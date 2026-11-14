package detect

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

// weightsFingerprints maps each WeightsVersion to a hash of the scoring
// configuration it names. Changing a weight without bumping WeightsVersion
// fails here; after bumping, add the new version's fingerprint.
var weightsFingerprints = map[string]string{
	"weights-2026-11-04.1": "0b7867d0fa0cfb0a",
	"weights-2026-11-13.1": "c5257c657adcbd0e",
}

func scoringFingerprint() string {
	var b strings.Builder
	inds := make([]string, 0, len(IndicatorWeights))
	for ind := range IndicatorWeights {
		inds = append(inds, string(ind))
	}
	sort.Strings(inds)
	for _, ind := range inds {
		fmt.Fprintf(&b, "w %s %v\n", ind, IndicatorWeights[cloudtrail.Indicator(ind)])
	}
	for _, r := range ChainRules {
		fmt.Fprintf(&b, "c %s %v %v\n", r.Name, r.Weight, r.AllOf)
	}
	fmt.Fprintf(&b, "k %d %d %v %v %v\n", EnumerationBurstThreshold, MultiRegionGPUThreshold, enumerationBurstWeight, multiRegionGPUWeight, DefaultWindow)
	fmt.Fprintf(&b, "l %v\n", createdIdentityWeight)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

func TestWeightsVersion(t *testing.T) {
	want, ok := weightsFingerprints[WeightsVersion]
	if !ok {
		t.Fatalf("WeightsVersion %q has no fingerprint entry", WeightsVersion)
	}
	if got := scoringFingerprint(); got != want {
		t.Fatalf("scoring configuration changed (fingerprint %s) but WeightsVersion is still %q; bump it and record the new fingerprint", got, WeightsVersion)
	}
}

func TestIncidentID(t *testing.T) {
	f := Finding{Principal: "arn:aws:iam::123456789012:user/a", First: t0}
	id := f.IncidentID()
	if len(id) != len("inc_")+16 || !strings.HasPrefix(id, "inc_") {
		t.Fatalf("unexpected id %q", id)
	}
	g := f
	g.First = t0.In(time.FixedZone("x", 3600))
	if g.IncidentID() != id {
		t.Fatal("incident ID must not depend on time zone")
	}
	g.First = t0.Add(time.Second)
	if g.IncidentID() == id {
		t.Fatal("different first event must give a different ID")
	}
	g = f
	g.Principal = "other"
	if g.IncidentID() == id {
		t.Fatal("different principal must give a different ID")
	}
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
	for name, w := range map[string]float64{"enumeration_burst": enumerationBurstWeight, "multi_region_gpu_launch": multiRegionGPUWeight} {
		if !(w > 0 && w < 1) {
			t.Errorf("%s weight %v out of range", name, w)
		}
	}
}

// Every indicator the adapter can emit must have a weight, or it would be silently ignored.
func TestEveryIndicatorWeighted(t *testing.T) {
	for _, ind := range []cloudtrail.Indicator{
		cloudtrail.GPUInstanceLaunch, cloudtrail.BulkInstanceLaunch, cloudtrail.QuotaIncreaseRequest,
		cloudtrail.MonitoringTampering, cloudtrail.BedrockLoggingDisabled, cloudtrail.BedrockModelAccessChange,
		cloudtrail.CredentialCreation, cloudtrail.AccessDenied, cloudtrail.RootActivity,
		cloudtrail.AlternateComputeLaunch, cloudtrail.PrivilegeEscalation,
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
		}, 50.5}, // 1 - 0.9*0.55
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

func TestMultiRegionGPULaunch(t *testing.T) {
	gpu := func(id, region string) cloudtrail.Event {
		e := ev(id, 0, "p", cloudtrail.GPUInstanceLaunch)
		e.Region = region
		return e
	}
	two, err := Detect([]cloudtrail.Event{gpu("1", "us-east-1"), gpu("2", "us-west-2"), gpu("3", "us-west-2")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := contributor(two[0], "multi_region_gpu_launch"); ok || two[0].Confidence != 30 {
		t.Fatalf("two regions must not trigger the rule: %+v", two[0])
	}
	three, err := Detect([]cloudtrail.Event{gpu("1", "us-east-1"), gpu("2", "us-west-2"), gpu("3", "eu-west-1")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := contributor(three[0], "multi_region_gpu_launch")
	if !ok || len(c.EventIDs) != 3 || three[0].Confidence != 58 { // 1 - 0.7*0.6
		t.Fatalf("three regions must trigger the rule: %+v", three[0])
	}
}

// Thresholds the bands are measured against: the CLI defaults for
// -notify-min-confidence and -min-confidence.
const (
	alertThreshold       = 50.0
	containmentThreshold = 85.0
)

type band string

const (
	bandNone        band = "no finding"
	bandBelowAlert  band = "below alert threshold"
	bandAlertOnly   band = "alert only"
	bandContainable band = "containment eligible"
)

func bandOf(confidence float64) band {
	switch {
	case confidence >= containmentThreshold:
		return bandContainable
	case confidence >= alertThreshold:
		return bandAlertOnly
	default:
		return bandBelowAlert
	}
}

// fixtureBands is the tuning contract: the band of each replay fixture's
// highest-confidence finding. Every fixture must be listed. When changing
// weights, run this test; a band change must be a deliberate decision,
// documented in the README's tuning table.
var fixtureBands = map[string]band{
	// Benign activity must not reach the alert threshold...
	"benign_ci_deploy":            bandNone,
	"benign_ml_single_gpu":        bandBelowAlert,
	"benign_admin_onboarding":     bandBelowAlert,
	"benign_trail_maintenance":    bandBelowAlert,
	"benign_autoscaling_scaleout": bandBelowAlert,
	// ...except a large GPU job right after a quota increase, which is
	// indistinguishable from mining in CloudTrail alone. It alerts so a
	// human can confirm, but must never be containment eligible.
	"benign_gpu_training_job": bandAlertOnly,

	// Attacks must at least alert.
	"incident":                   bandContainable,
	"attack_llmjacking":          bandContainable,
	"attack_cryptojacking_quiet": bandContainable,
	// A stolen key creates an admin user and switches to it. Only linking the
	// two identities gets this past the containment threshold.
	"attack_identity_pivot": bandContainable,
	// Probing alone is suspicious but has no resource abuse yet.
	"attack_key_enumeration": bandAlertOnly,
}

func TestFixtureBands(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "cloudtrail", "testdata", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	seen := map[string]bool{}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			want, ok := fixtureBands[name]
			if !ok {
				t.Fatalf("fixture %s has no expected band; add it to fixtureBands", name)
			}
			f, err := os.Open(path)
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
			got := bandNone
			if len(findings) > 0 {
				got = bandOf(findings[0].Confidence) // findings are sorted, highest first
			}
			if got != want {
				top := "none"
				if len(findings) > 0 {
					top = fmt.Sprintf("%.1f (%s)", findings[0].Confidence, findings[0].Principal)
				}
				t.Fatalf("band %q, want %q; top finding %s", got, want, top)
			}
			if strings.HasPrefix(name, "benign_") {
				for _, f := range findings {
					if f.Confidence >= containmentThreshold {
						t.Fatalf("benign finding is containment eligible: %.1f %s", f.Confidence, f.Principal)
					}
				}
			}
		})
	}
	for name := range fixtureBands {
		if !seen[name] {
			t.Errorf("fixtureBands lists %s but testdata has no such fixture", name)
		}
	}
}

func replayFixture(t *testing.T, name string) []cloudtrail.Event {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "cloudtrail", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := cloudtrail.Replay(f)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestIdentityPivotIsOneFinding(t *testing.T) {
	events := replayFixture(t, "attack_identity_pivot")
	findings, err := Detect(events, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want one linked finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Principal != "arn:aws:iam::123456789012:user/support-tool" || f.Confidence != 96 {
		t.Fatalf("unexpected finding: %s %v", f.Principal, f.Confidence)
	}
	if !reflect.DeepEqual(f.LinkedPrincipals, []string{"arn:aws:iam::123456789012:user/svc-metrics"}) {
		t.Fatalf("linked principals: %v", f.LinkedPrincipals)
	}
	for _, name := range []string{"created_identity_activity", "privilege_escalation_with_new_credentials", "evasion_with_resource_abuse"} {
		if _, ok := contributor(f, name); !ok {
			t.Errorf("missing %s", name)
		}
	}
	// The denied RunInstances call is not counted as a launch.
	if !reflect.DeepEqual(f.Launches, []Launch{{Region: "us-east-1", InstanceType: "g5.xlarge", Count: 4}}) {
		t.Fatalf("launches: %+v", f.Launches)
	}

	// Without the creation events the two identities stay separate and
	// neither reaches the containment threshold.
	var unlinked []cloudtrail.Event
	for _, ev := range events {
		ev.TargetUser = ""
		unlinked = append(unlinked, ev)
	}
	split, _ := Detect(unlinked, Options{})
	if len(split) != 2 || split[0].Confidence >= containmentThreshold {
		t.Fatalf("unlinked control: %d findings, top %v", len(split), split[0].Confidence)
	}
}

func TestIdentityLinkRules(t *testing.T) {
	mk := func(id string, off time.Duration, who, target, errCode string, inds ...cloudtrail.Indicator) cloudtrail.Event {
		e := ev(id, off, "arn:aws:iam::123456789012:user/"+who, inds...)
		e.Service, e.Action, e.TargetUser, e.ErrorCode = "iam", "CreateAccessKey", target, errCode
		return e
	}
	act := func(id string, off time.Duration, who string) cloudtrail.Event {
		return ev(id, off, "arn:aws:iam::123456789012:user/"+who, cloudtrail.GPUInstanceLaunch)
	}
	count := func(events ...cloudtrail.Event) int {
		fs, err := Detect(events, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return len(fs)
	}
	if n := count(mk("1", 0, "a", "b", "", cloudtrail.CredentialCreation), act("2", time.Minute, "b")); n != 1 {
		t.Errorf("created identity must join its creator: %d findings", n)
	}
	if n := count(mk("1", time.Minute, "a", "b", "", cloudtrail.CredentialCreation), act("2", 0, "b")); n != 2 {
		t.Errorf("activity before the creation must not be linked: %d findings", n)
	}
	if n := count(mk("1", 0, "a", "b", "AccessDenied", cloudtrail.CredentialCreation), act("2", time.Minute, "b")); n != 2 {
		t.Errorf("a failed creation must not link: %d findings", n)
	}
	if n := count(mk("1", 0, "a", "a", "", cloudtrail.CredentialCreation)); n != 1 {
		t.Errorf("a key for oneself is not a link: %d findings", n)
	}
	// A creates B, B creates C: all three roll up to A; a cycle terminates.
	if n := count(mk("1", 0, "a", "b", "", cloudtrail.CredentialCreation), mk("2", time.Minute, "b", "c", "", cloudtrail.CredentialCreation),
		act("3", 2*time.Minute, "c"), mk("4", 3*time.Minute, "c", "a", "", cloudtrail.CredentialCreation)); n != 1 {
		t.Errorf("chained creations must roll up: %d findings", n)
	}
}

func TestSuppressions(t *testing.T) {
	rules := `{"version":"s1","rules":[{"principal":"arn:aws:iam::*:user/ml-*","indicators":["gpu_instance_launch","quota_increase_request"],"reason":"ML platform trains on GPUs","expires":"2027-01-01T00:00:00Z"}]}`
	s, err := LoadSuppressions(strings.NewReader(rules))
	if err != nil {
		t.Fatal(err)
	}
	events := replayFixture(t, "benign_gpu_training_job")
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	kept, hits, expired := s.Apply(events, now)
	if expired != 0 || len(hits) != 2 || hits[0].Indicator != cloudtrail.GPUInstanceLaunch || hits[0].Reason == "" || hits[1].Events != 1 {
		t.Fatalf("hits %+v expired %d", hits, expired)
	}
	if fs, _ := Detect(kept, Options{}); len(fs) != 0 {
		t.Fatalf("suppressed training job must produce no finding: %+v", fs)
	}
	if len(events[0].Indicators) == 0 {
		t.Fatal("Apply must not modify its input")
	}
	// The same rule must not hide an attacker using a different principal...
	attack := replayFixture(t, "attack_cryptojacking_quiet")
	if kept, hits, _ := s.Apply(attack, now); len(hits) != 0 || !reflect.DeepEqual(kept, attack) {
		t.Fatalf("rule matched the wrong principal: %+v", hits)
	}
	// ...and stops applying once expired.
	if _, hits, expired := s.Apply(events, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); len(hits) != 0 || expired != 1 {
		t.Fatalf("expired rule still applied: %+v %d", hits, expired)
	}
}

func TestLoadSuppressionsRejects(t *testing.T) {
	rule := func(body string) string { return `{"version":"s1","rules":[` + body + `]}` }
	for name, doc := range map[string]string{
		"not json":       `nope`,
		"no version":     `{"rules":[]}`,
		"unknown field":  `{"version":"s","rules":[],"x":1}`,
		"trailing":       `{"version":"s","rules":[]} {}`,
		"bare wildcard":  rule(`{"principal":"**","indicators":["access_denied"],"reason":"r","expires":"2027-01-01T00:00:00Z"}`),
		"no indicators":  rule(`{"principal":"arn:x","indicators":[],"reason":"r","expires":"2027-01-01T00:00:00Z"}`),
		"no reason":      rule(`{"principal":"arn:x","indicators":["access_denied"],"reason":" ","expires":"2027-01-01T00:00:00Z"}`),
		"no expiry":      rule(`{"principal":"arn:x","indicators":["access_denied"],"reason":"r"}`),
		"unknown":        rule(`{"principal":"arn:x","indicators":["nope"],"reason":"r","expires":"2027-01-01T00:00:00Z"}`),
		"evasion signal": rule(`{"principal":"arn:x","indicators":["monitoring_tampering"],"reason":"r","expires":"2027-01-01T00:00:00Z"}`),
		"bedrock logs":   rule(`{"principal":"arn:x","indicators":["bedrock_logging_disabled"],"reason":"r","expires":"2027-01-01T00:00:00Z"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadSuppressions(strings.NewReader(doc)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestWildcardMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"abc", "abc", true}, {"abc", "abcd", false}, {"a*", "abc", true}, {"*c", "abc", true},
		{"a*c", "abc", true}, {"a*c", "ab", false}, {"arn:*:user/ml-*", "arn:aws:iam::1:user/ml-x", true},
		{"arn:*:user/ml-*", "arn:aws:iam::1:role/ml-x", false}, {"a*b*c", "a-b-b-c", true}, {"a*bc", "abcabd", false},
	} {
		if got := wildcardMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("wildcardMatch(%q, %q) = %v", tc.pattern, tc.s, got)
		}
	}
}
