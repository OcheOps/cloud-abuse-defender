package main

import (
	"bytes"
	"encoding/json"
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
