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

	"github.com/OcheOps/cloud-abuse-defender/internal/alert"
	"github.com/OcheOps/cloud-abuse-defender/internal/cloudwatch"
	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
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

// hookServer counts deliveries and fails them while fail is set.
func hookServer(t *testing.T, fail *bool) (*int, func()) {
	t.Helper()
	count := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *fail {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		count++
	}))
	old := httpClient
	httpClient = srv.Client()
	t.Setenv(webhookEnv, srv.URL+"/hook")
	return &count, func() { httpClient = old; srv.Close() }
}

func TestRunDetectDedupe(t *testing.T) {
	fail := false
	sent, done := hookServer(t, &fail)
	defer done()
	state := filepath.Join(t.TempDir(), "state.json")
	base := []string{"-file", incidentLog, "-notify", "webhook", "-alert-state", state}

	first, code, stderr := runDetectCmd(t, base...)
	if code != 0 || *sent != 1 || first.Notifications[0].Status != "sent" || first.Notifications[0].Verdict != alert.VerdictNew {
		t.Fatalf("first run: exit %d sent %d %+v %s", code, *sent, first.Notifications, stderr)
	}

	second, code, _ := runDetectCmd(t, base...)
	if code != 0 || *sent != 1 || second.Notifications[0].Status != "suppressed_duplicate" {
		t.Fatalf("second run must suppress: sent %d %+v", *sent, second.Notifications)
	}

	// A decision now exists (alert-only -> containment eligible): escalate.
	third, code, _ := runDetectCmd(t, append(base, "-usage", exampleUsage, "-pricing", examplePricing, "-allow-containment")...)
	if code != 0 || *sent != 2 || third.Notifications[0].Verdict != alert.VerdictEscalated {
		t.Fatalf("decision change must escalate: sent %d %+v", *sent, third.Notifications)
	}

	// A zero suppression period turns unchanged alerts into reminders.
	fourth, code, _ := runDetectCmd(t, append(base, "-usage", exampleUsage, "-pricing", examplePricing, "-allow-containment", "-alert-suppress-for", "0s")...)
	if code != 0 || *sent != 3 || fourth.Notifications[0].Verdict != alert.VerdictReminder {
		t.Fatalf("expired suppression must remind: sent %d %+v", *sent, fourth.Notifications)
	}
}

func TestRunDetectDedupeDryRunAndFailuresDoNotRecord(t *testing.T) {
	fail := true
	sent, done := hookServer(t, &fail)
	defer done()
	state := filepath.Join(t.TempDir(), "state.json")
	base := []string{"-file", incidentLog, "-notify", "webhook", "-alert-state", state}

	if _, code, _ := runDetectCmd(t, append(base, "-notify-dry-run")...); code != 0 {
		t.Fatalf("dry run exit %d", code)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("dry run must not write state: %v", err)
	}

	var out, errOut bytes.Buffer
	if code := run(append([]string{"detect"}, base...), &out, &errOut, now); code != 1 {
		t.Fatalf("failed send exit %d, want 1", code)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("failed send must not be recorded: %v", err)
	}

	fail = false
	got, code, _ := runDetectCmd(t, base...)
	if code != 0 || *sent != 1 || got.Notifications[0].Verdict != alert.VerdictNew {
		t.Fatalf("alert must be retried after a failure: sent %d %+v", *sent, got.Notifications)
	}
}

func TestRunDetectDedupeErrors(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(webhookEnv, "")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"state without notify":    {[]string{"-alert-state", corrupt}, "require -notify"},
		"suppress without notify": {[]string{"-alert-suppress-for", "1h"}, "require -notify"},
		"suppress without state":  {[]string{"-notify", "slack", "-notify-dry-run", "-alert-suppress-for", "1h"}, "requires -alert-state"},
		"negative suppress":       {[]string{"-notify", "slack", "-notify-dry-run", "-alert-state", corrupt, "-alert-suppress-for", "-1h"}, "must not be negative"},
		"corrupt state":           {[]string{"-notify", "slack", "-notify-dry-run", "-alert-state", corrupt}, "invalid alert state"},
	} {
		t.Run(name, func(t *testing.T) {
			_, code, stderr := runDetectCmd(t, append([]string{"-file", incidentLog}, tc.args...)...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, tc.want)
			}
		})
	}
}

const (
	metricResults = "../../internal/cloudwatch/testdata/get-metric-data.json"
	listMetrics   = "../../internal/cloudwatch/testdata/list-metrics.json"
)

func runCmd(t *testing.T, args ...string) (string, int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut, now)
	if code != 0 && out.Len() != 0 {
		t.Fatalf("unexpected stdout on failure: %s", out.String())
	}
	return out.String(), code, errOut.String()
}

func TestRunBedrockQueries(t *testing.T) {
	for name, args := range map[string][]string{
		"models flag":  {"-models", "example.text-model-small,example.text-model-large"},
		"list metrics": {"-list-metrics", listMetrics},
	} {
		t.Run(name, func(t *testing.T) {
			out, code, stderr := runCmd(t, append([]string{"bedrock-queries"}, args...)...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			var q []cloudwatch.Query
			if err := json.Unmarshal([]byte(out), &q); err != nil {
				t.Fatal(err)
			}
			if len(q) != 4 || q[0].Label != "cad:InputTokenCount:example.text-model-large" || q[0].MetricStat.Period != 300 {
				t.Fatalf("unexpected queries: %+v", q)
			}
		})
	}
}

func TestRunBedrockUsageFeedsPipeline(t *testing.T) {
	out, code, stderr := runCmd(t, "bedrock-usage", "-results", metricResults, "-region", "us-east-1",
		"-start", "2026-11-04T10:00:00Z", "-end", "2026-11-04T10:30:00Z")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	u, err := cost.LoadUsage(strings.NewReader(out))
	if err != nil {
		t.Fatalf("output is not a valid usage file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "usage.json")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runUsageFile(t, path)
	if len(u.Models) != 2 || got.Estimate.HourlyCostUSD != 56 {
		t.Fatalf("converted usage must price like the example: %+v", got.Estimate)
	}
}

func runUsageFile(t *testing.T, usagePath string) estimateOutput {
	t.Helper()
	out, code, stderr := runCmd(t, "-usage", usagePath, "-pricing", examplePricing)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var got estimateOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRunBedrockErrors(t *testing.T) {
	usage := func(extra ...string) []string {
		return append([]string{"bedrock-usage", "-results", metricResults, "-region", "us-east-1"}, extra...)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"queries no source":    {[]string{"bedrock-queries"}, "exactly one of"},
		"queries both sources": {[]string{"bedrock-queries", "-models", "a", "-list-metrics", listMetrics}, "exactly one of"},
		"queries bad period":   {[]string{"bedrock-queries", "-models", "a", "-period", "90"}, "multiple of 60"},
		"queries missing file": {[]string{"bedrock-queries", "-list-metrics", "nope.json"}, "nope.json"},
		"queries extra args":   {[]string{"bedrock-queries", "-models", "a", "x"}, "unexpected arguments"},
		"usage missing flags":  {[]string{"bedrock-usage", "-results", metricResults}, "are required"},
		"usage bad start":      {usage("-start", "yesterday", "-end", "2026-11-04T10:30:00Z"), "-start"},
		"usage bad end":        {usage("-start", "2026-11-04T10:00:00Z", "-end", "later"), "-end"},
		"usage wrong window":   {usage("-start", "2026-11-04T10:10:00Z", "-end", "2026-11-04T10:30:00Z"), "outside the window"},
		"usage missing file":   {[]string{"bedrock-usage", "-results", "nope.json", "-region", "r", "-start", "2026-11-04T10:00:00Z", "-end", "2026-11-04T10:30:00Z"}, "nope.json"},
		"usage extra args":     {append(usage("-start", "2026-11-04T10:00:00Z", "-end", "2026-11-04T10:30:00Z"), "x"), "unexpected arguments"},
	} {
		t.Run(name, func(t *testing.T) {
			_, code, stderr := runCmd(t, tc.args...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, tc.want)
			}
		})
	}
}

func TestRunDetectEvidenceLog(t *testing.T) {
	fail := false
	sent, done := hookServer(t, &fail)
	defer done()
	logPath := filepath.Join(t.TempDir(), "evidence.jsonl")

	got, code, stderr := runDetectCmd(t, "-file", incidentLog, "-evidence-log", logPath,
		"-usage", exampleUsage, "-pricing", examplePricing, "-notify", "webhook")
	if code != 0 || *sent != 1 {
		t.Fatalf("exit %d sent %d: %s", code, *sent, stderr)
	}
	// 2 finding records + 1 notification (the 36%% finding is skipped, not delivered).
	if got.EvidenceHead == nil || got.EvidenceHead.Records != 3 {
		t.Fatalf("unexpected evidence head: %+v", got.EvidenceHead)
	}
	if got.Findings[0].IncidentID == "" || got.Findings[0].IncidentID == got.Findings[1].IncidentID {
		t.Fatalf("incident IDs missing or not distinct: %+v", got.Findings)
	}

	var recs []evidence.Record
	raw, _ := os.ReadFile(logPath)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r evidence.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if recs[0].Kind != "finding" || recs[2].Kind != "notification" || recs[0].IncidentID != got.Findings[0].IncidentID {
		t.Fatalf("unexpected records: %+v", recs)
	}
	var fe findingEvidence
	if err := json.Unmarshal(recs[0].Data, &fe); err != nil {
		t.Fatal(err)
	}
	if fe.PolicyVersion != policy.Version || fe.WeightsVersion != detect.WeightsVersion || fe.PricingVersion != "example-2026-11" ||
		fe.Decision == nil || len(fe.Finding.Contributors) == 0 {
		t.Fatalf("finding record incomplete: %+v", fe)
	}
	var ne notificationEvidence
	if err := json.Unmarshal(recs[2].Data, &ne); err != nil {
		t.Fatal(err)
	}
	if ne.Status != "sent" || ne.FindingRecord != recs[0].Hash {
		t.Fatalf("notification record not linked to its finding: %+v", ne)
	}
	if strings.Contains(string(raw), "/hook") {
		t.Fatal("webhook URL leaked into the evidence log")
	}

	// A second run appends to the same chain.
	again, code, _ := runDetectCmd(t, "-file", incidentLog, "-evidence-log", logPath)
	if code != 0 || again.EvidenceHead.Records != 5 {
		t.Fatalf("second run must append: %+v", again.EvidenceHead)
	}

	out, code, stderr := runCmd(t, "evidence-verify", "-file", logPath, "-expect-record", recs[0].Hash)
	if code != 0 || !strings.Contains(out, again.EvidenceHead.Hash) {
		t.Fatalf("verify: exit %d %s %s", code, out, stderr)
	}
}

func TestRunDetectEvidenceAlertCarriesHash(t *testing.T) {
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { body, _ = io.ReadAll(r.Body) }))
	defer srv.Close()
	old := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = old })
	t.Setenv(webhookEnv, srv.URL+"/hook")
	logPath := filepath.Join(t.TempDir(), "evidence.jsonl")

	if _, code, stderr := runDetectCmd(t, "-file", incidentLog, "-evidence-log", logPath, "-notify", "webhook"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var a alert.Alert
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatal(err)
	}
	if a.EvidenceHash == "" || a.IncidentID == "" {
		t.Fatalf("alert missing evidence hash or incident ID: %+v", a)
	}
	if out, code, stderr := runCmd(t, "evidence-verify", "-file", logPath, "-expect-record", a.EvidenceHash); code != 0 {
		t.Fatalf("alert hash must be in the log: %d %s %s", code, out, stderr)
	}
}

func TestRunEvidenceVerifyFailures(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "evidence.jsonl")
	if _, code, _ := runDetectCmd(t, "-file", incidentLog, "-evidence-log", logPath); code != 0 {
		t.Fatal("setup failed")
	}
	raw, _ := os.ReadFile(logPath)
	tampered := filepath.Join(t.TempDir(), "tampered.jsonl")
	os.WriteFile(tampered, []byte(strings.Replace(string(raw), "ci-deploy", "ci-deplox", 1)), 0o600)

	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no file flag":                {[]string{"evidence-verify"}, 2, "-file is required"},
		"extra args":                  {[]string{"evidence-verify", "-file", logPath, "x"}, 2, "unexpected arguments"},
		"missing log":                 {[]string{"evidence-verify", "-file", logPath + ".nope"}, 1, "does not exist"},
		"tampered log":                {[]string{"evidence-verify", "-file", tampered}, 1, "hash mismatch"},
		"unknown record":              {[]string{"evidence-verify", "-file", logPath, "-expect-record", "deadbeef"}, 1, "has no record deadbeef"},
		"detect refuses tampered log": {[]string{"detect", "-file", incidentLog, "-evidence-log", tampered}, 2, "hash mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			_, code, stderr := runCmd(t, tc.args...)
			if code != tc.code || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d (want %d), stderr %q, want %q", code, tc.code, stderr, tc.want)
			}
		})
	}
}
