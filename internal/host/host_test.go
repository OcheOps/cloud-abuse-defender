package host

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)

const alertThreshold = 50.0

func load(t *testing.T, name string) Snapshot {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fixtureScores is the tuning contract: the highest confidence each fixture
// must produce. Benign fixtures must stay below the default alert threshold.
var fixtureScores = map[string]float64{
	"benign_web_server":    0,
	"benign_ml_training":   15,
	"benign_go_build":      40.5,
	"attack_renamed_miner": 85.1,
	"attack_kinsing":       88.4,
	"attack_xmrig":         99.2,
}

func TestFixtureScores(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	if len(paths) != len(fixtureScores) {
		t.Fatalf("%d fixtures but %d expectations; every fixture needs an expected score", len(paths), len(fixtureScores))
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		t.Run(name, func(t *testing.T) {
			want, ok := fixtureScores[name]
			if !ok {
				t.Fatalf("no expected score for %s", name)
			}
			findings := Scan(load(t, name))
			top := 0.0
			if len(findings) > 0 {
				top = findings[0].Confidence
			}
			if top != want {
				t.Fatalf("top confidence %v, want %v; findings %+v", top, want, findings)
			}
			if strings.HasPrefix(name, "benign_") && top >= alertThreshold {
				t.Fatalf("benign fixture reaches the alert threshold: %v", top)
			}
			if strings.HasPrefix(name, "attack_") && top < alertThreshold {
				t.Fatalf("attack fixture below the alert threshold: %v", top)
			}
		})
	}
}

func TestXmrigFinding(t *testing.T) {
	f := Scan(load(t, "attack_xmrig"))[0]
	got := map[Indicator]bool{}
	for _, c := range f.Contributors {
		got[c.Indicator] = true
		if c.Detail == "" {
			t.Errorf("%s has no detail", c.Indicator)
		}
	}
	// It connects by IP, so mining_pool_domain is covered by attack_renamed_miner instead.
	for ind := range Weights {
		if !got[ind] && ind != MiningPoolDomain {
			t.Errorf("xmrig fixture should trigger %s", ind)
		}
	}
	if !strings.Contains(f.Cmdline, "-p ***") {
		t.Fatalf("pool password not masked: %q", f.Cmdline)
	}
}

func TestScanRedactsForeignSnapshots(t *testing.T) {
	s := load(t, "benign_web_server")
	s.Processes[len(s.Processes)-1].CPUPercent = 95 // force a finding for the node process
	for _, f := range Scan(s) {
		if strings.Contains(f.Cmdline, fakeSecret) {
			t.Fatalf("secret leaked into finding: %q", f.Cmdline)
		}
	}
}

func TestCmdlineTruncated(t *testing.T) {
	long := []string{"xmrig", strings.Repeat("a", 2000)}
	f := Scan(Snapshot{Processes: []Process{{PID: 1, Name: "xmrig", Cmdline: long}}})[0]
	if len(f.Cmdline) > maxCmdlineInOutput+len("…") {
		t.Fatalf("cmdline not truncated: %d", len(f.Cmdline))
	}
}

func TestMinerFlag(t *testing.T) {
	for args, want := range map[string]string{
		"xmrig --donate-level 1":   "--donate-level",
		"x --donate-level=5":       "--donate-level",
		"x -a rx/0":                "-a rx/0",
		"x --algo=kawpow":          "--algo kawpow",
		"x -a":                     "",
		"tar -a archive.tar.gz":    "",
		"curl --algorithm sha256":  "",
		"java -jar app.jar --coin": "--coin",
	} {
		if got := minerFlag(strings.Fields(args)); got != want {
			t.Errorf("minerFlag(%q) = %q, want %q", args, got, want)
		}
	}
}

// fakeSecret stands in for every secret in these tests. Inputs are built
// from it so the test source holds no secret-like literals for scanners to flag.
const fakeSecret = "not-a-real-secret"

func TestRedactCmdline(t *testing.T) {
	f := func(format string) string { return fmt.Sprintf(format, fakeSecret) }
	for in, want := range map[string]string{
		f("app --password=%s --user bob"):       "app --password=*** --user bob",
		f("app --token %s --verbose"):           "app --token *** --verbose",
		f("mysql -u root -p %s"):                "mysql -u root -p ***",
		f("app API_KEY=%s other=1"):             "app API_KEY=*** other=1",
		f("curl https://bob:%s@example.com/x"):  "curl https://bob:***@example.com/x",
		f("app --aws-secret-access-key=%s"):     "app --aws-secret-access-key=***",
		"app --keyboard-layout=us --name=keyed": "app --keyboard-layout=us --name=keyed",
		"app --private-key":                     "app --private-key",
	} {
		if strings.Contains(want, fakeSecret) {
			t.Fatalf("bad test case: %q", want)
		}
		if got := strings.Join(RedactCmdline(strings.Fields(in)), " "); got != want {
			t.Errorf("RedactCmdline(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAddr(t *testing.T) {
	for in, want := range map[string]string{
		"4D7100CB:0D05":                         "203.0.113.77:3333",
		"B80D0120000000000000000001000000:01BB": "2001:db8::1:443",
		"0000000000000000FFFF00004D7100CB:115C": "203.0.113.77:4444",
	} {
		ip, port, ok := parseAddr(in)
		if !ok || fmt.Sprintf("%s:%d", ip, port) != want {
			t.Errorf("parseAddr(%q) = %v:%d %v, want %s", in, ip, port, ok, want)
		}
	}
	for _, bad := range []string{"nocolon", "ZZ:0050", "0100007F:ZZZZ", "01007F:0050"} {
		if _, _, ok := parseAddr(bad); ok {
			t.Errorf("parseAddr(%q) should fail", bad)
		}
	}
}

func TestParseStat(t *testing.T) {
	ppid, ticks, ok := parseStat([]byte("4401 (evil) (name) R 1 4401 4401 0 -1 4194304 1 0 0 0 250 50 0 0 20 0 1 0 1 1 1"))
	if !ok || ppid != 1 || ticks != 300 {
		t.Fatalf("parseStat: ppid=%d ticks=%d ok=%v", ppid, ticks, ok)
	}
	for _, bad := range []string{"no paren", "1 (x) R 1 2", "1 (x) R a 2 3 4 5 6 7 8 9 10 11 12 13"} {
		if _, _, ok := parseStat([]byte(bad)); ok {
			t.Errorf("parseStat(%q) should fail", bad)
		}
	}
}

// fakeProc builds a minimal /proc tree.
type fakeProc struct {
	t    *testing.T
	root string
}

func (fp fakeProc) write(rel, content string) {
	fp.t.Helper()
	p := filepath.Join(fp.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		fp.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		fp.t.Fatal(err)
	}
}

func (fp fakeProc) link(rel, target string) {
	fp.t.Helper()
	p := filepath.Join(fp.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		fp.t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		fp.t.Fatal(err)
	}
}

func stat(pid, ppid int, comm string, ticks int) string {
	return fmt.Sprintf("%d (%s) S %d 1 1 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 1 1 1\n", pid, comm, ppid, ticks)
}

func TestCollect(t *testing.T) {
	fp := fakeProc{t, t.TempDir()}
	// A miner with a deleted binary, a pool connection and a password on its command line.
	fp.write("4401/stat", stat(4401, 1, "xmrig", 1000))
	fp.write("4401/comm", "xmrig\n")
	fp.write("4401/cmdline", "/tmp/.x/xmrig\x00-o\x00stratum+tcp://203.0.113.77:3333\x00-p\x00"+fakeSecret+"\x00")
	fp.write("4401/status", "Name:\txmrig\nUid:\t33\t33\t33\t33\n")
	fp.link("4401/exe", "/tmp/.x/xmrig (deleted)")
	fp.link("4401/fd/3", "socket:[777]")
	fp.link("4401/fd/4", "/dev/null")
	// A process we cannot inspect fully (no exe, cmdline or status).
	fp.write("12/stat", stat(12, 2, "kworker/0:1 (x)", 5))
	// A non-process directory and a malformed stat.
	fp.write("self-not-a-pid/stat", "x")
	fp.write("99/stat", "garbage")
	fp.write("net/tcp", strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 0F02000A:C350 4D7100CB:0D05 01 00000000:00000000 00:00000000 00000000    33        0 777 1",
		"   1: 0F02000A:C351 0100007F:1F90 01 00000000:00000000 00:00000000 00000000    33        0 778 1",
		"   2: 0F02000A:C352 4D7100CB:0050 0A 00000000:00000000 00:00000000 00000000    33        0 777 1",
		"   3: short line",
	}, "\n")+"\n")

	waited := false
	snap, err := Collect(CollectOptions{ProcRoot: fp.root, Hostname: "web-02", Now: t0, Sample: 2 * time.Second,
		Wait: func() {
			waited = true
			fp.write("4401/stat", stat(4401, 1, "xmrig", 1800)) // 800 ticks over 2s = 400% of a core
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !waited || snap.Host != "web-02" || !snap.CollectedAt.Equal(t0) || snap.SampleSeconds != 2 {
		t.Fatalf("unexpected snapshot header: %+v", snap)
	}
	if len(snap.Processes) != 2 {
		t.Fatalf("want 2 readable processes, got %+v", snap.Processes)
	}
	k, m := snap.Processes[0], snap.Processes[1]
	if k.PID != 12 || k.UID != -1 || k.Name != "" || k.Exe != "" {
		t.Fatalf("partially readable process: %+v", k)
	}
	want := Process{PID: 4401, PPID: 1, UID: 33, Name: "xmrig", Exe: "/tmp/.x/xmrig (deleted)",
		Cmdline: []string{"/tmp/.x/xmrig", "-o", "stratum+tcp://203.0.113.77:3333", "-p", "***"}, CPUPercent: 400}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("miner process:\n got %+v\nwant %+v", m, want)
	}
	if !reflect.DeepEqual(snap.Connections, []Connection{{PID: 4401, RemoteIP: "203.0.113.77", RemotePort: 3333, State: "established"}}) {
		t.Fatalf("connections: %+v (loopback, listening and unowned sockets must be skipped)", snap.Connections)
	}
	if fs := Scan(snap); len(fs) == 0 || fs[0].Confidence < 90 {
		t.Fatalf("collected miner must score high: %+v", fs)
	}
}

func TestCollectWithoutSample(t *testing.T) {
	fp := fakeProc{t, t.TempDir()}
	fp.write("7/stat", stat(7, 1, "sleep", 10))
	snap, err := Collect(CollectOptions{ProcRoot: fp.root, Now: t0})
	if err != nil || len(snap.Processes) != 1 || snap.Processes[0].CPUPercent != 0 {
		t.Fatalf("unsampled collection: %+v %v", snap, err)
	}
}

func TestCollectErrors(t *testing.T) {
	if _, err := Collect(CollectOptions{ProcRoot: t.TempDir()}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing time: %v", err)
	}
	if _, err := Collect(CollectOptions{ProcRoot: t.TempDir(), Now: t0, Sample: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative sample: %v", err)
	}
	if _, err := Collect(CollectOptions{ProcRoot: filepath.Join(t.TempDir(), "missing"), Now: t0}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing proc root: %v", err)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":          `nope`,
		"no time":           `{"processes":[]}`,
		"unknown field":     `{"collected_at":"2026-11-07T10:00:00Z","x":1}`,
		"trailing":          `{"collected_at":"2026-11-07T10:00:00Z"} {}`,
		"duplicate pid":     `{"collected_at":"2026-11-07T10:00:00Z","processes":[{"pid":1},{"pid":1}]}`,
		"zero pid":          `{"collected_at":"2026-11-07T10:00:00Z","processes":[{"pid":0}]}`,
		"negative cpu":      `{"collected_at":"2026-11-07T10:00:00Z","processes":[{"pid":1,"cpu_percent":-1}]}`,
		"port out of range": `{"collected_at":"2026-11-07T10:00:00Z","connections":[{"pid":1,"remote_port":70000}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(doc)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

// Changing a weight or rule list without bumping WeightsVersion fails here.
var weightsFingerprints = map[string]string{
	"host-weights-2026-11-07.1": "c0566ff4f6a441f7",
}

func scoringFingerprint() string {
	var b strings.Builder
	inds := make([]string, 0, len(Weights))
	for ind := range Weights {
		inds = append(inds, string(ind))
	}
	sort.Strings(inds)
	for _, ind := range inds {
		fmt.Fprintf(&b, "w %s %v\n", ind, Weights[Indicator(ind)])
	}
	names := make([]string, 0, len(minerNames))
	for n := range minerNames {
		names = append(names, n)
	}
	sort.Strings(names)
	ports := make([]int, 0, len(PoolPorts))
	for p := range PoolPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	fmt.Fprintf(&b, "%v %v %v %v %s %s %s %v\n", names, ports, poolDomains, tempDirs,
		stratumRe, minerFlagRe, minerAlgos, HighCPUThreshold)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

func TestWeightsVersion(t *testing.T) {
	want, ok := weightsFingerprints[WeightsVersion]
	if !ok {
		t.Fatalf("WeightsVersion %q has no fingerprint entry", WeightsVersion)
	}
	if got := scoringFingerprint(); got != want {
		t.Fatalf("host scoring changed (fingerprint %s) but WeightsVersion is still %q; bump it and record the new fingerprint", got, WeightsVersion)
	}
}

func TestWeightsAreProbabilities(t *testing.T) {
	for ind, w := range Weights {
		if !(w > 0 && w < 1) {
			t.Errorf("%s weight %v out of range", ind, w)
		}
	}
}
