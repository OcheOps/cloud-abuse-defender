package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

var now = time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC)

const (
	exampleUsage   = "../../examples/usage.example.json"
	examplePricing = "../../examples/pricing.example.json"
)

func TestRunDefaultsAlertOnly(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut, now); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	var d policy.Decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if d.Action != policy.Alert || d.EligibleForContainment || d.ProjectedCostUSD != 600 {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestRunAllowContainment(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-allow-containment"}, &out, &errOut, now); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	var d policy.Decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Action != policy.RecommendContainment || !d.EligibleForContainment {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestRunErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"invalid input", []string{"-confidence", "101"}, "threat_confidence"},
		{"zero gates", []string{"-threshold", "0"}, "threshold_usd"},
		{"unknown flag", []string{"-nope"}, "flag provided but not defined"},
		{"positional args", []string{"extra"}, "unexpected arguments"},
		{"usage without pricing", []string{"-usage", exampleUsage}, "must be used together"},
		{"pricing without usage", []string{"-pricing", examplePricing}, "must be used together"},
		{"rate with usage", []string{"-usage", exampleUsage, "-pricing", examplePricing, "-hourly-rate", "5"}, "cannot be combined"},
		{"missing usage file", []string{"-usage", "nope.json", "-pricing", examplePricing}, "nope.json"},
		{"invalid usage file", []string{"-usage", examplePricing, "-pricing", examplePricing}, "invalid cost input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, &out, &errOut, now); code != 2 {
				t.Fatalf("exit %d, want 2", code)
			}
			if out.Len() != 0 {
				t.Fatalf("unexpected stdout: %s", out.String())
			}
			if !strings.Contains(errOut.String(), tt.wantErr) {
				t.Fatalf("stderr %q missing %q", errOut.String(), tt.wantErr)
			}
		})
	}
}

func runUsage(t *testing.T, extra ...string) estimateOutput {
	t.Helper()
	var out, errOut bytes.Buffer
	args := append([]string{"-usage", exampleUsage, "-pricing", examplePricing}, extra...)
	if code := run(args, &out, &errOut, now); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	var got estimateOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	return got
}

func TestRunUsageDerivesRate(t *testing.T) {
	got := runUsage(t, "-allow-containment")
	if got.Estimate.HourlyCostUSD != 56 || got.Estimate.PricingVersion != "example-2026-11" {
		t.Fatalf("unexpected estimate: %+v", got.Estimate)
	}
	if got.Decision.ProjectedCostUSD != 56*24 || got.Decision.Action != policy.RecommendContainment {
		t.Fatalf("unexpected decision: %+v", got.Decision)
	}
}

func TestRunUsageStalePricingDegrades(t *testing.T) {
	got := runUsage(t, "-allow-containment", "-max-pricing-age", "1h")
	if got.Decision.Action != policy.Alert || got.Decision.Reason != policy.ReasonDegradedForecast {
		t.Fatalf("stale pricing must degrade to alert-only: %+v", got.Decision)
	}
	if len(got.Decision.ForecastWarnings) != 1 || len(got.Estimate.Warnings) != 1 {
		t.Fatalf("warnings not reported: %+v", got)
	}
}

func TestRunUsageUnpricedModelDegrades(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage.json")
	doc := `{"region":"us-east-1","window_start":"2026-11-04T10:00:00Z","window_end":"2026-11-04T11:00:00Z",
		"models":[{"model_id":"unknown.model","input_tokens":999999999,"output_tokens":0}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"-usage", path, "-pricing", examplePricing, "-allow-containment"}, &out, &errOut, now); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut.String())
	}
	var got estimateOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision.Action != policy.Alert || got.Decision.Reason != policy.ReasonDegradedForecast {
		t.Fatalf("unpriced usage must degrade to alert-only: %+v", got.Decision)
	}
}

const incidentLog = "../../internal/cloudtrail/testdata/incident.json"

func runCT(t *testing.T, args ...string) (cloudTrailOutput, int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"cloudtrail"}, args...), &out, &errOut, now)
	var got cloudTrailOutput
	if code == 0 {
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("invalid JSON %q: %v", out.String(), err)
		}
	} else if out.Len() != 0 {
		t.Fatalf("unexpected stdout on failure: %s", out.String())
	}
	return got, code, errOut.String()
}

func TestRunCloudTrail(t *testing.T) {
	got, code, stderr := runCT(t, "-file", incidentLog)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(got.Events) != 10 || got.Summary.Events != 10 || got.Summary.WithIndicators != 7 {
		t.Fatalf("unexpected output: %d events, summary %+v", len(got.Events), got.Summary)
	}
}

func TestRunCloudTrailOnlyIndicators(t *testing.T) {
	got, code, stderr := runCT(t, "-file", incidentLog, "-only-indicators")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(got.Events) != 7 || got.Summary.Events != 10 {
		t.Fatalf("got %d events, summary %+v", len(got.Events), got.Summary)
	}
	for _, ev := range got.Events {
		if len(ev.Indicators) == 0 {
			t.Fatalf("event without indicators printed: %+v", ev)
		}
	}
}

func TestRunCloudTrailErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"nope":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"missing file flag": {nil, "-file is required"},
		"unknown flag":      {[]string{"-nope"}, "flag provided but not defined"},
		"positional args":   {[]string{"-file", incidentLog, "extra"}, "unexpected arguments"},
		"missing file":      {[]string{"-file", "nope.json"}, "nope.json"},
		"invalid log":       {[]string{"-file", bad}, "invalid cloudtrail input"},
	} {
		t.Run(name, func(t *testing.T) {
			_, code, stderr := runCT(t, tc.args...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, tc.want)
			}
		})
	}
}

func runDetectCmd(t *testing.T, args ...string) (detectOutput, int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"detect"}, args...), &out, &errOut, now)
	var got detectOutput
	if code == 0 {
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("invalid JSON %q: %v", out.String(), err)
		}
	} else if out.Len() != 0 {
		t.Fatalf("unexpected stdout on failure: %s", out.String())
	}
	return got, code, errOut.String()
}

func TestRunDetectFindingsOnly(t *testing.T) {
	got, code, stderr := runDetectCmd(t, "-file", incidentLog)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(got.Findings) != 2 || got.Findings[0].Confidence != 98.6 || got.Estimate != nil {
		t.Fatalf("unexpected output: %+v", got)
	}
	for _, f := range got.Findings {
		if f.Decision != nil {
			t.Fatalf("no decision expected without a cost source: %+v", f)
		}
	}
}

func TestRunDetectWithUsagePipeline(t *testing.T) {
	got, code, stderr := runDetectCmd(t, "-file", incidentLog, "-usage", exampleUsage, "-pricing", examplePricing, "-allow-containment")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if got.Estimate == nil || got.Estimate.HourlyCostUSD != 56 {
		t.Fatalf("missing estimate: %+v", got.Estimate)
	}
	top, root := got.Findings[0], got.Findings[1]
	if top.Decision == nil || top.Decision.Action != policy.RecommendContainment {
		t.Fatalf("top finding should be eligible: %+v", top.Decision)
	}
	if root.Decision == nil || root.Decision.Reason != policy.ReasonLowConfidence {
		t.Fatalf("root finding (36%%) must stay alert-only: %+v", root.Decision)
	}
}

func TestRunDetectExplicitRate(t *testing.T) {
	got, code, stderr := runDetectCmd(t, "-file", incidentLog, "-hourly-rate", "1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	d := got.Findings[0].Decision
	if d == nil || d.Action != policy.Alert || d.Reason != policy.ReasonBelowThreshold {
		t.Fatalf("$24 projected must stay below threshold: %+v", d)
	}
}

func TestRunDetectWindowSplits(t *testing.T) {
	got, code, stderr := runDetectCmd(t, "-file", incidentLog, "-window", "30s")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(got.Findings) <= 2 {
		t.Fatalf("a 30s window should split the minute-spaced incident, got %d findings", len(got.Findings))
	}
}

func TestRunDetectErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"nope":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"missing file flag": {nil, "-file is required"},
		"positional args":   {[]string{"-file", incidentLog, "x"}, "unexpected arguments"},
		"negative window":   {[]string{"-file", incidentLog, "-window", "-1s"}, "window must not be negative"},
		"usage alone":       {[]string{"-file", incidentLog, "-usage", exampleUsage}, "must be used together"},
		"rate and usage":    {[]string{"-file", incidentLog, "-usage", exampleUsage, "-pricing", examplePricing, "-hourly-rate", "3"}, "cannot be combined"},
		"invalid log":       {[]string{"-file", bad}, "invalid cloudtrail input"},
		"invalid policy":    {[]string{"-file", incidentLog, "-hourly-rate", "5", "-threshold", "0"}, "threshold_usd"},
		"bad usage file":    {[]string{"-file", incidentLog, "-usage", "nope.json", "-pricing", examplePricing}, "nope.json"},
		"unknown flag":      {[]string{"-confidence", "90"}, "flag provided but not defined"},
	} {
		t.Run(name, func(t *testing.T) {
			_, code, stderr := runDetectCmd(t, tc.args...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, tc.want)
			}
		})
	}
}

func TestRunDetectNotifyDryRun(t *testing.T) {
	t.Setenv(webhookEnv, "")
	got, code, stderr := runDetectCmd(t, "-file", incidentLog, "-notify", "slack", "-notify-dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(got.Notifications) != 2 {
		t.Fatalf("want 2 notifications, got %+v", got.Notifications)
	}
	top, root := got.Notifications[0], got.Notifications[1]
	if top.Status != "dry_run" || !json.Valid(top.Payload) || !strings.Contains(string(top.Payload), "98.6% confidence") {
		t.Fatalf("unexpected top notification: %+v", top)
	}
	if root.Status != "skipped_below_threshold" || root.Payload != nil {
		t.Fatalf("36%% finding must be skipped at the default threshold: %+v", root)
	}
}

func TestRunDetectNotifySends(t *testing.T) {
	var bodies [][]byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, b)
	}))
	defer srv.Close()
	old := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = old })
	t.Setenv(webhookEnv, srv.URL+"/hook")

	got, code, stderr := runDetectCmd(t, "-file", incidentLog, "-notify", "webhook", "-notify-min-confidence", "0",
		"-usage", exampleUsage, "-pricing", examplePricing)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(bodies) != 2 || got.Notifications[0].Status != "sent" || got.Notifications[1].Status != "sent" {
		t.Fatalf("want 2 sent alerts, got %d bodies, %+v", len(bodies), got.Notifications)
	}
	if !strings.Contains(string(bodies[0]), `"schema":"cad.alert.v1"`) || !strings.Contains(string(bodies[0]), `"pricing_version":"example-2026-11"`) {
		t.Fatalf("unexpected webhook body: %s", bodies[0])
	}
}

func TestRunDetectNotifyFailureStillPrintsFindings(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	old := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = old })
	t.Setenv(webhookEnv, srv.URL+"/services/SECRETTOKEN")

	var out, errOut bytes.Buffer
	code := run([]string{"detect", "-file", incidentLog, "-notify", "slack"}, &out, &errOut, now)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	var got detectOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("findings must still be printed: %v", err)
	}
	if len(got.Findings) != 2 || got.Notifications[0].Status != "failed" || !strings.Contains(got.Notifications[0].Error, "HTTP 403") {
		t.Fatalf("unexpected output: %+v", got.Notifications)
	}
	if strings.Contains(out.String()+errOut.String(), "SECRETTOKEN") {
		t.Fatal("webhook URL leaked into output")
	}
}

func TestRunDetectNotifyErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		env  string
		args []string
		want string
	}{
		"no url":            {"", []string{"-notify", "slack"}, "requires $" + webhookEnv},
		"http url":          {"http://hooks.example.com/SECRETTOKEN", []string{"-notify", "slack"}, "must use https"},
		"bad format":        {"", []string{"-notify", "email"}, "unknown format"},
		"dry run alone":     {"", []string{"-notify-dry-run"}, "require -notify"},
		"threshold alone":   {"", []string{"-notify-min-confidence", "10"}, "require -notify"},
		"threshold too big": {"", []string{"-notify", "slack", "-notify-dry-run", "-notify-min-confidence", "101"}, "between 0 and 100"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(webhookEnv, tc.env)
			_, code, stderr := runDetectCmd(t, append([]string{"-file", incidentLog}, tc.args...)...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, tc.want)
			}
			if strings.Contains(stderr, "SECRETTOKEN") {
				t.Fatal("webhook URL leaked into stderr")
			}
		})
	}
}
