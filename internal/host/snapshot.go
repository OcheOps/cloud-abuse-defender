// Package host collects read-only process and network snapshots from a Linux
// host and scores processes for cryptomining indicators.
//
// Collection only reads /proc; it never signals, stops or changes a process.
// Command lines can contain secrets, so values that look like passwords,
// tokens or keys are masked at collection time, before a snapshot is written
// anywhere.
package host

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrInvalid is wrapped by malformed snapshots and collection errors.
var ErrInvalid = errors.New("invalid host snapshot")

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat CPU times. It is 100 on
// every mainstream Linux architecture.
const clockTicks = 100

// Process is one running process.
type Process struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	UID  int    `json:"uid"`
	Name string `json:"name"`
	// Exe is the executable path; it ends in " (deleted)" when the file was
	// removed after the process started.
	Exe string `json:"exe,omitempty"`
	// Cmdline is the argument vector with secret-looking values masked.
	Cmdline []string `json:"cmdline,omitempty"`
	// CPUPercent is CPU use over the sampling interval, as a percentage of
	// one core (it can exceed 100 on multi-core hosts).
	CPUPercent float64 `json:"cpu_percent"`
}

// Connection is an outbound TCP connection owned by a process.
type Connection struct {
	PID        int    `json:"pid"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
}

// Snapshot is the state of one host at one time.
type Snapshot struct {
	Host          string       `json:"host"`
	CollectedAt   time.Time    `json:"collected_at"`
	SampleSeconds float64      `json:"sample_seconds"`
	Processes     []Process    `json:"processes"`
	Connections   []Connection `json:"connections,omitempty"`
}

// Load decodes and validates a snapshot. Unknown fields are rejected.
func Load(r io.Reader) (Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return Snapshot{}, fmt.Errorf("%w: unexpected data after JSON document", ErrInvalid)
	}
	if s.CollectedAt.IsZero() {
		return Snapshot{}, fmt.Errorf("%w: collected_at is required", ErrInvalid)
	}
	seen := map[int]bool{}
	for _, p := range s.Processes {
		if p.PID <= 0 || seen[p.PID] {
			return Snapshot{}, fmt.Errorf("%w: missing or duplicate pid %d", ErrInvalid, p.PID)
		}
		seen[p.PID] = true
		if p.CPUPercent < 0 {
			return Snapshot{}, fmt.Errorf("%w: pid %d has negative cpu_percent", ErrInvalid, p.PID)
		}
	}
	for _, c := range s.Connections {
		if c.RemotePort < 0 || c.RemotePort > 65535 {
			return Snapshot{}, fmt.Errorf("%w: invalid remote_port %d", ErrInvalid, c.RemotePort)
		}
	}
	return s, nil
}

var (
	secretKey  = regexp.MustCompile(`(?i)(pass(word|wd)?|token|secret|api[-_]?key|access[-_]?key|private[-_]?key|credential)s?$`)
	urlUserPwd = regexp.MustCompile(`(://[^/\s:@]+):[^/\s@]+@`)
)

const masked = "***"

// RedactCmdline masks values that look like secrets: "--password=x",
// "--token x", "-p x" after a password flag, and passwords in URLs.
func RedactCmdline(args []string) []string {
	out := make([]string, len(args))
	maskNext := false
	for i, a := range args {
		if maskNext {
			out[i], maskNext = masked, false
			continue
		}
		a = urlUserPwd.ReplaceAllString(a, "$1:"+masked+"@")
		if strings.HasPrefix(a, "-") {
			flag := strings.TrimLeft(a, "-")
			if k, _, ok := strings.Cut(flag, "="); ok {
				if secretKey.MatchString(k) {
					a = a[:strings.Index(a, "=")+1] + masked
				}
			} else if secretKey.MatchString(flag) || flag == "p" {
				maskNext = true
			}
		} else if k, _, ok := strings.Cut(a, "="); ok && secretKey.MatchString(k) {
			a = k + "=" + masked
		}
		out[i] = a
	}
	return out
}

// CollectOptions controls a /proc collection.
type CollectOptions struct {
	// ProcRoot is the proc filesystem to read; "/proc" if empty.
	ProcRoot string
	// Hostname is recorded in the snapshot.
	Hostname string
	// Now is the collection time.
	Now time.Time
	// Sample is the CPU sampling interval; zero records no CPU use.
	Sample time.Duration
	// Wait is called between the two CPU samples; time.Sleep(Sample) if nil.
	Wait func()
}

type procTimes map[int]uint64

// Collect reads processes and TCP connections from /proc. Processes that
// exit during collection, or cannot be read without privileges, are skipped
// or recorded with the fields that could be read.
func Collect(opt CollectOptions) (Snapshot, error) {
	root := opt.ProcRoot
	if root == "" {
		root = "/proc"
	}
	if opt.Now.IsZero() {
		return Snapshot{}, fmt.Errorf("%w: collection time is required", ErrInvalid)
	}
	if opt.Sample < 0 {
		return Snapshot{}, fmt.Errorf("%w: sample interval must not be negative", ErrInvalid)
	}
	pids, err := listPIDs(root)
	if err != nil {
		return Snapshot{}, err
	}

	var before procTimes
	if opt.Sample > 0 {
		before = readTimes(root, pids)
		if opt.Wait != nil {
			opt.Wait()
		} else {
			time.Sleep(opt.Sample)
		}
	}

	snap := Snapshot{Host: opt.Hostname, CollectedAt: opt.Now.UTC(), SampleSeconds: opt.Sample.Seconds()}
	for _, pid := range pids {
		p, ticks, ok := readProcess(root, pid)
		if !ok {
			continue
		}
		if opt.Sample > 0 {
			if prev, had := before[pid]; had && ticks >= prev {
				p.CPUPercent = float64(ticks-prev) / clockTicks / opt.Sample.Seconds() * 100
			}
		}
		snap.Processes = append(snap.Processes, p)
	}
	snap.Connections = readConnections(root, pids)
	return snap, nil
}

func listPIDs(root string) ([]int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 && e.IsDir() {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

// parseStat returns the ppid and utime+stime from /proc/<pid>/stat. The comm
// field may contain spaces and parentheses, so parsing starts after the last ')'.
func parseStat(raw []byte) (ppid int, ticks uint64, ok bool) {
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(string(raw[i+1:]))
	// f[0] is state (field 3); ppid is field 4, utime 14, stime 15.
	if len(f) < 13 {
		return 0, 0, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	ut, err2 := strconv.ParseUint(f[11], 10, 64)
	st, err3 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, false
	}
	return ppid, ut + st, true
}

func readTimes(root string, pids []int) procTimes {
	t := procTimes{}
	for _, pid := range pids {
		if raw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat")); err == nil {
			if _, ticks, ok := parseStat(raw); ok {
				t[pid] = ticks
			}
		}
	}
	return t
}

func readProcess(root string, pid int) (Process, uint64, bool) {
	dir := filepath.Join(root, strconv.Itoa(pid))
	raw, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Process{}, 0, false // exited
	}
	ppid, ticks, ok := parseStat(raw)
	if !ok {
		return Process{}, 0, false
	}
	p := Process{PID: pid, PPID: ppid, UID: -1}
	if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		p.Name = strings.TrimSpace(string(comm))
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe = exe
	}
	if cmd, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && len(cmd) > 0 {
		p.Cmdline = RedactCmdline(strings.Split(strings.TrimRight(string(cmd), "\x00"), "\x00"))
	}
	if status, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(status))
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) >= 2 && f[0] == "Uid:" {
				if uid, err := strconv.Atoi(f[1]); err == nil {
					p.UID = uid
				}
			}
		}
	}
	return p, ticks, true
}

var tcpStates = map[string]string{"01": "established", "02": "syn_sent"}

// readConnections maps sockets in /proc/net/tcp{,6} to their owning processes
// through /proc/<pid>/fd. Only outbound-looking states are kept.
func readConnections(root string, pids []int) []Connection {
	owner := map[string]int{}
	for _, pid := range pids {
		fdDir := filepath.Join(root, strconv.Itoa(pid), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				owner[link[len("socket:["):len(link)-1]] = pid
			}
		}
	}
	var conns []Connection
	for _, file := range []string{"tcp", "tcp6"} {
		raw, err := os.ReadFile(filepath.Join(root, "net", file))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Scan() // header
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 10 {
				continue
			}
			state, ok := tcpStates[f[3]]
			if !ok {
				continue
			}
			pid, ok := owner[f[9]]
			if !ok {
				continue
			}
			ip, port, ok := parseAddr(f[2])
			if !ok || ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			conns = append(conns, Connection{PID: pid, RemoteIP: ip.String(), RemotePort: port, State: state})
		}
	}
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].PID != conns[j].PID {
			return conns[i].PID < conns[j].PID
		}
		return conns[i].RemoteIP+strconv.Itoa(conns[i].RemotePort) < conns[j].RemoteIP+strconv.Itoa(conns[j].RemotePort)
	})
	return conns
}

// parseAddr decodes a /proc/net/tcp address: hex IP in host (little-endian)
// 32-bit words, then a hex port.
func parseAddr(s string) (net.IP, int, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	b, err := hex.DecodeString(ipHex)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, 0, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, int(port), true
}
