package detect

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cloudtrail"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func ev(id string, offset time.Duration, principal string, inds ...cloudtrail.Indicator) cloudtrail.Event {
	return cloudtrail.Event{
		EventID:      id,
		Time:         t0.Add(offset),
		PrincipalARN: principal,
		AccountID:    "123456789012",
		SourceIP:     "203.0.113.50",
		Region:       "us-east-1",
		Indicators:   inds,
	}
}

func contributor(f Finding, name string) (Contributor, bool) {
	for _, c := range f.Contributors {
		if c.Name == name {
			return c, true
		}
	}
	return Contributor{}, false
}

func TestWeightsAreProbabilities(t *testing.T) {
	for ind, w := range IndicatorWeights {
		if !(w > 0 && w < 1) {
			t.Errorf("weight for %s = %v, want 0 < w < 1", ind, w)
		}
	}
	for _, r := range ChainRules {
		if !(r.Weight > 0 && r.Weight < 1) || len(r.AllOf) < 2 {
			t.Errorf("chain rule %s: weight %v, %d groups", r.Name, r.Weight, len(r.AllOf))
		}
	}
	if !(enumerationBurstWeight > 0 && enumerationBurstWeight < 1) {
		t.Error("enumeration burst weight out of range")
	}
}

// Every indicator the adapter can emit must have a weight, or it would be silently ignored.
func TestEveryIndicatorWeighted(t *testing.T) {
	for _, ind := range []cloudtrail.Indicator{
		cloudtrail.GPUInstanceLaunch, cloudtrail.BulkInstanceLaunch, cloudtrail.QuotaIncreaseRequest,
		cloudtrail.MonitoringTampering, cloudtrail.BedrockLoggingDisabled, cloudtrail.BedrockModelAccessChange,
		cloudtrail.CredentialCreation, cloudtrail.AccessDenied, cloudtrail.RootActivity,
	} {
		if _, ok := IndicatorWeights[ind]; !ok {
			t.Errorf("indicator %s has no weight", ind)
		}
	}
}

func TestIncidentFixture(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "cloudtrail", "testdata", "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := cloudtrail.Replay(f)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Detect(events, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(findings), findings)
	}
	top, root := findings[0], findings[1]
	if top.Principal != "arn:aws:iam::123456789012:user/ci-deploy" || top.Confidence != 98.6 || top.EventCount != 6 {
		t.Fatalf("unexpected top finding: principal=%s confidence=%v events=%d", top.Principal, top.Confidence, top.EventCount)
	}
	for _, chain := range []string{"cryptojacking_chain", "llmjacking_chain", "evasion_with_resource_abuse"} {
		if _, ok := contributor(top, chain); !ok {
			t.Errorf("top finding missing %s", chain)
		}
	}
	if len(top.Regions) != 2 {
		t.Errorf("want both regions in top finding, got %v", top.Regions)
	}
	if root.Principal != "arn:aws:iam::123456789012:root" || root.Confidence != 36 {
		t.Fatalf("unexpected root finding: %+v", root)
	}
}

func TestScoring(t *testing.T) {
	tests := []struct {
		name   string
		events []cloudtrail.Event
		want   float64
	}{
		{"single weak signal", []cloudtrail.Event{ev("1", 0, "p", cloudtrail.AccessDenied)}, 10},
		{"repeats do not stack", []cloudtrail.Event{
			ev("1", 0, "p", cloudtrail.AccessDenied), ev("2", time.Minute, "p", cloudtrail.AccessDenied),
		}, 10},
		{"enumeration burst", []cloudtrail.Event{
			ev("1", 0, "p", cloudtrail.AccessDenied), ev("2", 1, "p", cloudtrail.AccessDenied), ev("3", 2, "p", cloudtrail.AccessDenied),
			ev("4", 3, "p", cloudtrail.AccessDenied), ev("5", 4, "p", cloudtrail.AccessDenied),
		}, 32.5}, // 1 - 0.9*0.75
		{"cryptojacking chain", []cloudtrail.Event{
			ev("1", 0, "p", cloudtrail.QuotaIncreaseRequest), ev("2", time.Minute, "p", cloudtrail.GPUInstanceLaunch),
		}, 72}, // 1 - 0.8*0.7*0.5
		{"llmjacking chain", []cloudtrail.Event{
			ev("1", 0, "p", cloudtrail.BedrockLoggingDisabled), ev("2", time.Minute, "p", cloudtrail.BedrockModelAccessChange),
		}, 77.5}, // 1 - 0.6*0.75*0.5; must not also match evasion_with_resource_abuse
		{"evasion with abuse", []cloudtrail.Event{
			ev("1", 0, "p", cloudtrail.MonitoringTampering), ev("2", time.Minute, "p", cloudtrail.BedrockModelAccessChange),
		}, 75.3}, // 1 - 0.55*0.75*0.6
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Detect(tt.events, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Confidence != tt.want {
				t.Fatalf("got %+v, want one finding at %v", got, tt.want)
			}
		})
	}
}

func TestWindowSplitsFindings(t *testing.T) {
	events := []cloudtrail.Event{
		ev("1", 0, "p", cloudtrail.QuotaIncreaseRequest),
		ev("2", 3*time.Hour, "p", cloudtrail.GPUInstanceLaunch),
	}
	split, err := Detect(events, Options{Window: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(split) != 2 {
		t.Fatalf("want 2 findings with 1h window, got %d", len(split))
	}
	if _, ok := contributor(split[0], "cryptojacking_chain"); ok {
		t.Fatal("chain must not span separate findings")
	}
	joined, err := Detect(events, Options{Window: 4 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(joined) != 1 || joined[0].Confidence != 72 {
		t.Fatalf("want one 72%% finding with 4h window, got %+v", joined)
	}
}

func TestPrincipalsAreSeparate(t *testing.T) {
	events := []cloudtrail.Event{
		ev("1", 0, "alice", cloudtrail.QuotaIncreaseRequest),
		ev("2", time.Minute, "bob", cloudtrail.GPUInstanceLaunch),
	}
	got, err := Detect(events, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Principal != "bob" || got[1].Principal != "alice" {
		t.Fatalf("want bob (30) then alice (20), got %+v", got)
	}
}

func TestPrincipalFallbacks(t *testing.T) {
	keyed := ev("1", 0, "", cloudtrail.AccessDenied)
	keyed.AccessKeyID = "AKIA****MPLE"
	anon := ev("2", 0, "", cloudtrail.AccessDenied)
	got, err := Detect([]cloudtrail.Event{keyed, anon}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Principal != "access-key:AKIA****MPLE" || got[1].Principal != "unknown" {
		t.Fatalf("unexpected principals: %+v", got)
	}
}

func TestIgnoresEventsWithoutIndicatorsAndOrder(t *testing.T) {
	events := []cloudtrail.Event{
		ev("3", 2*time.Minute, "p", cloudtrail.GPUInstanceLaunch),
		ev("noise", time.Minute, "p"),
		ev("1", 0, "p", cloudtrail.QuotaIncreaseRequest),
	}
	got, err := Detect(events, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EventCount != 2 || !got[0].First.Equal(t0) || got[0].Last != t0.Add(2*time.Minute) {
		t.Fatalf("unexpected finding: %+v", got)
	}
	c, _ := contributor(got[0], "cryptojacking_chain")
	if len(c.EventIDs) != 2 || c.EventIDs[0] != "1" || c.EventIDs[1] != "3" {
		t.Fatalf("chain evidence = %v", c.EventIDs)
	}
}

func TestEmptyAndInvalid(t *testing.T) {
	if got, err := Detect(nil, Options{}); err != nil || len(got) != 0 {
		t.Fatalf("empty input: %v, %v", got, err)
	}
	if got, err := Detect([]cloudtrail.Event{ev("1", 0, "p")}, Options{}); err != nil || len(got) != 0 {
		t.Fatalf("no indicators: %v, %v", got, err)
	}
	if _, err := Detect(nil, Options{Window: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestUnknownIndicatorIgnored(t *testing.T) {
	got, err := Detect([]cloudtrail.Event{ev("1", 0, "p", "future_indicator")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Confidence != 0 || len(got[0].Contributors) != 0 {
		t.Fatalf("unweighted indicator must contribute nothing: %+v", got)
	}
}
