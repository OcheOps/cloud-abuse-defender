package host

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// WeightsVersion identifies the host scoring weights. Bump it whenever a
// weight or rule changes; TestWeightsVersion fails otherwise.
const WeightsVersion = "host-weights-2026-11-07.1"

// Indicator is a named, explainable host signal.
type Indicator string

const (
	MinerProcessName  Indicator = "miner_process_name"
	StratumURL        Indicator = "stratum_url"
	MinerArguments    Indicator = "miner_arguments"
	MiningPoolDomain  Indicator = "mining_pool_domain"
	MiningPoolPort    Indicator = "mining_pool_port"
	DeletedExecutable Indicator = "deleted_executable"
	TempDirExecutable Indicator = "temp_dir_executable"
	HighCPU           Indicator = "high_cpu"
)

const (
	// HighCPUThreshold is the CPU percentage (of one core) for high_cpu.
	HighCPUThreshold   = 90.0
	maxCmdlineInOutput = 512
)

// Weights is the evidence weight (0 < w < 1) of each indicator. Strong,
// mining-specific signals weigh most; generic ones (temp-dir binaries, CPU)
// weigh little because legitimate builds and jobs produce them too.
var Weights = map[Indicator]float64{
	StratumURL:        0.80,
	MinerProcessName:  0.70,
	MinerArguments:    0.50,
	MiningPoolDomain:  0.50,
	MiningPoolPort:    0.35,
	DeletedExecutable: 0.30,
	TempDirExecutable: 0.30,
	HighCPU:           0.15,
}

var minerNames = map[string]bool{
	"xmrig": true, "xmr-stak": true, "xmr-stak-rx": true, "minerd": true, "cpuminer": true,
	"cpuminer-multi": true, "ccminer": true, "ethminer": true, "nbminer": true, "t-rex": true,
	"lolminer": true, "phoenixminer": true, "nanominer": true, "srbminer-multi": true,
	"gminer": true, "teamredminer": true, "kdevtmpfsi": true, "kinsing": true, "xmrigminer": true,
}

var (
	stratumRe   = regexp.MustCompile(`(?i)stratum[0-9]?\+(tcp|ssl|tls)://`)
	minerFlagRe = regexp.MustCompile(`(?i)^--(donate-level|randomx[-\w]*|cpu-max-threads-hint|cpu-priority|nicehash|coin)(=|$)`)
	algoFlagRe  = regexp.MustCompile(`(?i)^(-a|--algo|--algorithm)(=|$)`)
	minerAlgos  = regexp.MustCompile(`(?i)^(rx/\w+|randomx|cn[/\w-]*|cryptonight[\w/-]*|kawpow|ethash|etchash|autolykos2?|argon2[\w/-]*|ghostrider|equihash[\w/-]*)$`)
	poolDomains = []string{
		"supportxmr.com", "minexmr.com", "nanopool.org", "2miners.com", "f2pool.com", "hashvault.pro",
		"moneroocean.stream", "c3pool.com", "herominers.com", "unmineable.com", "nicehash.com",
		"ethermine.org", "xmrpool.eu", "monerohash.com", "kryptex.network",
	}
	tempDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/"}
)

// PoolPorts are remote ports commonly used by mining pools.
var PoolPorts = map[int]bool{3333: true, 4444: true, 5555: true, 7777: true, 14433: true, 14444: true, 45560: true, 45700: true}

// Contributor is one piece of evidence for a finding.
type Contributor struct {
	Indicator Indicator `json:"indicator"`
	Weight    float64   `json:"weight"`
	Detail    string    `json:"detail"`
}

// Finding is a scored process.
type Finding struct {
	Host         string        `json:"host"`
	PID          int           `json:"pid"`
	PPID         int           `json:"ppid"`
	UID          int           `json:"uid"`
	Name         string        `json:"name"`
	Exe          string        `json:"exe,omitempty"`
	Cmdline      string        `json:"cmdline,omitempty"`
	CPUPercent   float64       `json:"cpu_percent"`
	Contributors []Contributor `json:"contributors"`
	Confidence   float64       `json:"confidence"`
}

func exeBase(exe string) string {
	return strings.ToLower(filepath.Base(strings.TrimSuffix(exe, " (deleted)")))
}

func joinCmdline(args []string) string {
	s := strings.Join(RedactCmdline(args), " ")
	if len(s) > maxCmdlineInOutput {
		s = s[:maxCmdlineInOutput] + "…"
	}
	return s
}

// Scan scores every process and returns those with at least one indicator,
// highest confidence first. Command lines are redacted again before output,
// in case the snapshot came from another collector.
func Scan(s Snapshot) []Finding {
	connsByPID := map[int][]Connection{}
	for _, c := range s.Connections {
		connsByPID[c.PID] = append(connsByPID[c.PID], c)
	}
	var out []Finding
	for _, p := range s.Processes {
		f := Finding{Host: s.Host, PID: p.PID, PPID: p.PPID, UID: p.UID, Name: p.Name, Exe: p.Exe,
			Cmdline: joinCmdline(p.Cmdline), CPUPercent: p.CPUPercent}
		add := func(ind Indicator, detail string) {
			f.Contributors = append(f.Contributors, Contributor{Indicator: ind, Weight: Weights[ind], Detail: detail})
		}

		if n := strings.ToLower(p.Name); minerNames[n] {
			add(MinerProcessName, "process name "+p.Name)
		} else if b := exeBase(p.Exe); p.Exe != "" && minerNames[b] {
			add(MinerProcessName, "executable "+b)
		}
		cmd := strings.Join(p.Cmdline, " ")
		if m := stratumRe.FindString(cmd); m != "" {
			add(StratumURL, "command line uses "+strings.ToLower(m))
		}
		if flag := minerFlag(p.Cmdline); flag != "" {
			add(MinerArguments, "miner option "+flag)
		}
		lower := strings.ToLower(cmd)
		for _, d := range poolDomains {
			if strings.Contains(lower, d) {
				add(MiningPoolDomain, "command line names pool "+d)
				break
			}
		}
		for _, c := range connsByPID[p.PID] {
			if PoolPorts[c.RemotePort] {
				add(MiningPoolPort, fmt.Sprintf("%s connection to %s:%d", c.State, c.RemoteIP, c.RemotePort))
				break
			}
		}
		if strings.HasSuffix(p.Exe, " (deleted)") {
			add(DeletedExecutable, "executable deleted from disk: "+strings.TrimSuffix(p.Exe, " (deleted)"))
		}
		for _, d := range tempDirs {
			if strings.HasPrefix(p.Exe, d) {
				add(TempDirExecutable, "runs from "+d)
				break
			}
		}
		if p.CPUPercent >= HighCPUThreshold {
			add(HighCPU, fmt.Sprintf("%.0f%% CPU", p.CPUPercent))
		}

		if len(f.Contributors) == 0 {
			continue
		}
		miss := 1.0
		for _, c := range f.Contributors {
			miss *= 1 - c.Weight
		}
		f.Confidence = math.Round((1-miss)*1000) / 10
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].PID < out[j].PID
	})
	return out
}

func minerFlag(args []string) string {
	for i, a := range args {
		if minerFlagRe.MatchString(a) {
			flag, _, _ := strings.Cut(a, "=")
			return flag
		}
		if algoFlagRe.MatchString(a) {
			flag, val, hasVal := strings.Cut(a, "=")
			if !hasVal && i+1 < len(args) {
				val = args[i+1]
			}
			if minerAlgos.MatchString(val) {
				return flag + " " + val
			}
		}
	}
	return ""
}
