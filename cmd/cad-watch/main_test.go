package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func ev(id string, at time.Time) string {
	return fmt.Sprintf(`{"eventID":%q,"eventTime":%q,"eventSource":"ec2.amazonaws.com","eventName":"X"}`, id, at.Format(time.RFC3339))
}

type scripted struct {
	events []string
	err    error
}

type detectCall struct {
	args   []string
	events string
}

// harness scripts a sequence of polls, advancing a fake clock by the wait
// interval, and records every fetch window and detector run.
type harness struct {
	polls   []scripted
	windows [][2]time.Time
	calls   []detectCall
	clock   time.Time
	fail    error // detector error
	stderr  bytes.Buffer
}

func (h *harness) deps() deps {
	i := 0
	return deps{
		fetch: func(_ context.Context, _ string, start, end time.Time) ([]byte, int, error) {
			h.windows = append(h.windows, [2]time.Time{start, end})
			p := h.polls[i]
			i++
			if p.err != nil {
				return nil, 0, p.err
			}
			return []byte(`{"Records":[` + strings.Join(p.events, ",") + `]}`), len(p.events), nil
		},
		detect: func(_ context.Context, _ string, args []string, _, _ io.Writer) error {
			raw, err := os.ReadFile(args[2])
			if err != nil {
				return err
			}
			info, _ := os.Stat(args[2])
			if info.Mode().Perm() != 0o600 {
				return fmt.Errorf("event file mode %v", info.Mode().Perm())
			}
			h.calls = append(h.calls, detectCall{args: append([]string(nil), args...), events: string(raw)})
			return h.fail
		},
		now: func() time.Time { return h.clock },
		wait: func(_ context.Context, d time.Duration) bool {
			h.clock = h.clock.Add(d)
			return i < len(h.polls)
		},
	}
}

func (h *harness) run(args ...string) int {
	if h.clock.IsZero() {
		h.clock = t0
	}
	return run(context.Background(), append([]string{"-region", "us-east-1"}, args...), io.Discard, &h.stderr, h.deps())
}

func TestEventsCorrelateAcrossPolls(t *testing.T) {
	h := &harness{polls: []scripted{
		{events: []string{ev("a", t0.Add(-10*time.Minute))}},
		{events: []string{ev("a", t0.Add(-10*time.Minute)), ev("b", t0.Add(2*time.Minute))}}, // overlap returns "a" again
		{}, // nothing new: buffered events are still scored
	}}
	if code := h.run(); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if len(h.calls) != 3 {
		t.Fatalf("want 3 detector runs, got %d", len(h.calls))
	}
	if strings.Contains(h.calls[0].events, `"b"`) || strings.Count(h.calls[1].events, `"eventID":"a"`) != 1 || !strings.Contains(h.calls[1].events, `"b"`) {
		t.Fatalf("second run must see both events once: %s", h.calls[1].events)
	}
	if !strings.Contains(h.calls[2].events, `"a"`) {
		t.Fatalf("buffered events must be re-scored: %s", h.calls[2].events)
	}
	// The temporary event file is removed after each run.
	if _, err := os.Stat(h.calls[0].args[2]); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind: %v", err)
	}
}

func TestEventsExpireFromBuffer(t *testing.T) {
	h := &harness{polls: []scripted{{events: []string{ev("old", t0)}}, {}, {}}}
	if code := h.run("-interval", "30m", "-lookback", "15m", "-correlate", "45m"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	// Polls at +0, +30m and +60m; "old" is outside the 45m horizon by the third.
	if len(h.calls) != 2 {
		t.Fatalf("want 2 detector runs before the event expires, got %d", len(h.calls))
	}
}

func TestFailedPollIsBackfilled(t *testing.T) {
	h := &harness{polls: []scripted{{}, {err: errors.New("throttled")}, {err: errors.New("throttled")}, {}}}
	if code := h.run("-interval", "10m", "-lookback", "15m"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "CloudTrail polling failed: throttled") {
		t.Fatalf("failure not logged: %s", h.stderr.String())
	}
	// Polls at +0, +10, +20 (failed), +30. The last one must reach back to
	// the last good poll (+0) minus the lookback, not just 15 minutes.
	last := h.windows[3]
	if !last[0].Equal(t0.Add(-15*time.Minute)) || !last[1].Equal(t0.Add(30*time.Minute)) {
		t.Fatalf("backfill window: %v to %v", last[0], last[1])
	}
	if first := h.windows[0]; !first[0].Equal(t0.Add(-15 * time.Minute)) {
		t.Fatalf("first window: %v", first[0])
	}
}

func TestBackfillIsCappedAtCorrelateHorizon(t *testing.T) {
	polls := []scripted{{}}
	for i := 0; i < 20; i++ {
		polls = append(polls, scripted{err: errors.New("down")})
	}
	polls = append(polls, scripted{})
	h := &harness{polls: polls}
	h.run("-interval", "10m", "-lookback", "15m", "-correlate", "1h")
	last := h.windows[len(h.windows)-1]
	if got := last[1].Sub(last[0]); got != time.Hour {
		t.Fatalf("backfill must stop at the correlate horizon, got %s", got)
	}
}

func TestPassThroughFlags(t *testing.T) {
	h := &harness{polls: []scripted{{events: []string{ev("a", t0)}}}}
	code := h.run("-once", "-notify", "slack", "-alert-state", "s.json", "-evidence-log", "e.jsonl", "-usage", "u.json", "-pricing", "p.json",
		"-ec2-pricing", "ec2.json", "-suppressions", "sup.json", "-config", "c.json", "-allow-containment", "-approvals-required", "3", "-require-signed-approvals")
	if code != 0 {
		t.Fatal(h.stderr.String())
	}
	args := h.calls[0].args
	want := []string{"-alert-state", "s.json", "-notify", "slack", "-evidence-log", "e.jsonl", "-usage", "u.json", "-pricing", "p.json",
		"-ec2-pricing", "ec2.json", "-suppressions", "sup.json", "-config", "c.json", "-allow-containment", "-approvals-required", "3", "-require-signed-approvals"}
	if args[0] != "detect" || args[1] != "-file" || !reflect.DeepEqual(args[3:], want) {
		t.Fatalf("detector args: %v", args)
	}
	plain := &harness{polls: []scripted{{events: []string{ev("a", t0)}}}}
	plain.run("-once")
	if len(plain.calls[0].args) != 3 {
		t.Fatalf("no flags must pass nothing through: %v", plain.calls[0].args)
	}
}

func TestOnceExitCodes(t *testing.T) {
	if h := (&harness{polls: []scripted{{}}}); h.run("-once") != 0 || len(h.calls) != 0 {
		t.Fatal("an empty poll is a success with no detector run")
	}
	if h := (&harness{polls: []scripted{{err: errors.New("denied")}}}); h.run("-once") != 1 {
		t.Fatal("a failed fetch must exit 1")
	}
	h := &harness{polls: []scripted{{events: []string{ev("a", t0)}}}, fail: errors.New("exit status 1")}
	if h.run("-once") != 1 || !strings.Contains(h.stderr.String(), "detector failed") {
		t.Fatalf("a failed detector must exit 1: %s", h.stderr.String())
	}
	bad := &harness{polls: []scripted{{events: []string{`{"eventName":"no id"}`}}}}
	if bad.run("-once") != 1 || !strings.Contains(bad.stderr.String(), "rejected") {
		t.Fatalf("malformed events must fail the poll: %s", bad.stderr.String())
	}
}

func TestFlagValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no region":            {[]string{}, "-region is required"},
		"short interval":       {[]string{"-region", "r", "-interval", "10s"}, "at least 1m"},
		"short lookback":       {[]string{"-region", "r", "-lookback", "10s"}, "at least 1m"},
		"correlate too short":  {[]string{"-region", "r", "-correlate", "5m"}, "at least -lookback"},
		"bad notify":           {[]string{"-region", "r", "-notify", "email"}, "slack or webhook"},
		"notify without state": {[]string{"-region", "r", "-notify", "slack"}, "requires -alert-state"},
		"usage alone":          {[]string{"-region", "r", "-usage", "u.json"}, "used together"},
		"negative approvals":   {[]string{"-region", "r", "-approvals-required", "-1"}, "must not be negative"},
		"extra args":           {[]string{"-region", "r", "extra"}, "unexpected arguments"},
		"unknown flag":         {[]string{"-nope"}, "flag provided but not defined"},
	} {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			d := deps{fetch: func(context.Context, string, time.Time, time.Time) ([]byte, int, error) {
				t.Fatal("must not poll with invalid flags")
				return nil, 0, nil
			}}
			if code := run(context.Background(), tc.args, io.Discard, &stderr, d); code != 2 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr.String(), tc.want)
			}
		})
	}
}

func TestStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := realDeps()
	d.fetch = func(context.Context, string, time.Time, time.Time) ([]byte, int, error) {
		cancel() // a stop signal arrives during the first poll
		return []byte(`{"Records":[]}`), 0, nil
	}
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-region", "r"}, io.Discard, io.Discard, d) }()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop after its context ended")
	}
}
