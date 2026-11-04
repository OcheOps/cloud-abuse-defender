package alert

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

func sample(conf float64, act policy.Action, first, last time.Duration) Alert {
	return Alert{
		Principal:  "arn:aws:iam::123456789012:user/x",
		First:      t0.Add(first),
		Last:       t0.Add(last),
		Confidence: conf,
		Decision:   &policy.Decision{Action: act},
	}
}

func TestCheckVerdicts(t *testing.T) {
	const window, suppress = time.Hour, 24 * time.Hour
	sentAt := t0.Add(10 * time.Minute)
	s := &State{Version: stateVersion}
	s.Record(sample(72, policy.Alert, 0, 10*time.Minute), window, sentAt)

	tests := []struct {
		name string
		a    Alert
		now  time.Time
		want Verdict
	}{
		{"same finding again", sample(72, policy.Alert, 0, 10*time.Minute), sentAt.Add(time.Hour), VerdictDuplicate},
		{"longer replay of same incident", sample(72, policy.Alert, -30*time.Minute, 40*time.Minute), sentAt.Add(time.Hour), VerdictDuplicate},
		{"lower confidence", sample(60, policy.Alert, 0, 10*time.Minute), sentAt.Add(time.Hour), VerdictDuplicate},
		{"confidence rose", sample(88, policy.Alert, 0, 20*time.Minute), sentAt.Add(time.Hour), VerdictEscalated},
		{"decision changed", sample(72, policy.RecommendContainment, 0, 10*time.Minute), sentAt.Add(time.Hour), VerdictEscalated},
		{"suppression expired", sample(72, policy.Alert, 0, 10*time.Minute), sentAt.Add(suppress), VerdictReminder},
		{"within window gap", sample(72, policy.Alert, 70*time.Minute, 80*time.Minute), sentAt.Add(time.Hour), VerdictDuplicate},
		{"separate incident later", sample(72, policy.Alert, 3*time.Hour, 4*time.Hour), sentAt.Add(time.Hour), VerdictNew},
		{"other principal", func() Alert { a := sample(72, policy.Alert, 0, 10*time.Minute); a.Principal = "other"; return a }(), sentAt, VerdictNew},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Check(tt.a, window, suppress, tt.now); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRecordMergesRange(t *testing.T) {
	s := &State{Version: stateVersion}
	s.Record(sample(50, policy.Alert, 0, 10*time.Minute), time.Hour, t0)
	s.Record(sample(80, policy.Alert, 5*time.Minute, 50*time.Minute), time.Hour, t0.Add(time.Hour))
	if len(s.Entries) != 1 {
		t.Fatalf("want one merged entry, got %+v", s.Entries)
	}
	e := s.Entries[0]
	if !e.First.Equal(t0) || !e.Last.Equal(t0.Add(50*time.Minute)) || e.Confidence != 80 || !e.SentAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("unexpected merge: %+v", e)
	}
	s.Record(sample(50, policy.Alert, 5*time.Hour, 6*time.Hour), time.Hour, t0)
	if len(s.Entries) != 2 {
		t.Fatalf("separate incident must add an entry: %+v", s.Entries)
	}
}

func TestNilDecisionAction(t *testing.T) {
	s := &State{Version: stateVersion}
	a := sample(40, "", 0, time.Minute)
	a.Decision = nil
	s.Record(a, time.Hour, t0)
	if got := s.Check(a, time.Hour, 24*time.Hour, t0.Add(time.Minute)); got != VerdictDuplicate {
		t.Fatalf("got %s", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := LoadState(path)
	if err != nil || len(s.Entries) != 0 {
		t.Fatalf("missing file must load empty: %v %+v", err, s)
	}
	s.Record(sample(72, policy.Alert, 0, time.Minute), time.Hour, t0)
	old := sample(90, policy.Alert, 0, time.Minute)
	old.Principal = "old"
	s.Record(old, time.Hour, t0.Add(-31*24*time.Hour))
	if err := s.Save(path, t0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", info.Mode().Perm())
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Principal != sample(0, "", 0, 0).Principal {
		t.Fatalf("expired entry not pruned or entry lost: %+v", got.Entries)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".cad-alert-state-*")); len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestSaveEmptyWritesArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := (&State{}).Save(path, t0); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "{\n  \"version\": 1,\n  \"entries\": []\n}\n" {
		t.Fatalf("unexpected file: %q", raw)
	}
}

func TestLoadStateRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not json":      "nope",
		"wrong version": `{"version":2,"entries":[]}`,
		"unknown field": `{"version":1,"entries":[],"x":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadState(path); !errors.Is(err, ErrState) {
				t.Fatalf("want ErrState, got %v", err)
			}
		})
	}
	if _, err := LoadState(dir); !errors.Is(err, ErrState) {
		t.Fatalf("directory must be rejected, got %v", err)
	}
}

func TestSaveFailsInMissingDir(t *testing.T) {
	if err := (&State{}).Save(filepath.Join(t.TempDir(), "missing", "state.json"), t0); !errors.Is(err, ErrState) {
		t.Fatalf("want ErrState, got %v", err)
	}
}
