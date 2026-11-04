package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

func TestRunDefaultsAlertOnly(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 0 {
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
	if code := run([]string{"-allow-containment"}, &out, &errOut); code != 0 {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, &out, &errOut); code != 2 {
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
