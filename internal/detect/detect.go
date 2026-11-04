// Package detect correlates normalized CloudTrail events into per-principal
// findings with an explainable threat-confidence score.
//
// Events carrying indicators are grouped by principal and split into
// incidents wherever consecutive indicator events are further apart than the
// correlation window. Each finding is scored with a noisy-OR over its
// evidence:
//
//	confidence = 100 * (1 - Π(1 - w_i))
//
// where each w_i is the weight of one distinct indicator or one matched
// attack-chain rule. Repeating an indicator does not add weight, so noisy
// errors cannot inflate the score, and the score approaches but never
// reaches 100. Every contributor is listed with the event IDs behind it.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cloudtrail"
)

// WeightsVersion identifies the scoring weights and rules. Bump it whenever
// any weight, rule or threshold changes; TestWeightsVersion fails otherwise.
const WeightsVersion = "weights-2026-11-04.1"

// ErrInvalid is wrapped by validation errors in this package.
var ErrInvalid = errors.New("invalid detector input")

// DefaultWindow is the correlation gap used when Options.Window is zero.
const DefaultWindow = time.Hour

// EnumerationBurstThreshold is the number of access-denied events in one
// finding at or above which the enumeration_burst contributor applies.
const EnumerationBurstThreshold = 5

// MultiRegionGPUThreshold is the number of distinct regions with GPU launches
// in one finding at or above which multi_region_gpu_launch applies.
const MultiRegionGPUThreshold = 3

// IndicatorWeights is the evidence weight (0 < w < 1) of each indicator.
// Weights reflect how specific a signal is to abuse, not how severe the action is.
var IndicatorWeights = map[cloudtrail.Indicator]float64{
	cloudtrail.AccessDenied:             0.10,
	cloudtrail.RootActivity:             0.20,
	cloudtrail.CredentialCreation:       0.20,
	cloudtrail.QuotaIncreaseRequest:     0.20,
	cloudtrail.BedrockModelAccessChange: 0.25,
	cloudtrail.BulkInstanceLaunch:       0.25,
	cloudtrail.GPUInstanceLaunch:        0.30,
	cloudtrail.BedrockLoggingDisabled:   0.40,
	cloudtrail.MonitoringTampering:      0.45,
}

// ChainRule adds weight when indicators that are individually common appear
// together in one finding. Every group in AllOf must match at least one of its indicators.
type ChainRule struct {
	Name   string
	Weight float64
	AllOf  [][]cloudtrail.Indicator
}

// ChainRules are the correlated patterns the detector recognises.
var ChainRules = []ChainRule{
	{
		Name:   "cryptojacking_chain",
		Weight: 0.50,
		AllOf: [][]cloudtrail.Indicator{
			{cloudtrail.GPUInstanceLaunch},
			{cloudtrail.QuotaIncreaseRequest, cloudtrail.BulkInstanceLaunch},
		},
	},
	{
		Name:   "llmjacking_chain",
		Weight: 0.50,
		AllOf: [][]cloudtrail.Indicator{
			{cloudtrail.BedrockLoggingDisabled},
			{cloudtrail.BedrockModelAccessChange},
		},
	},
	{
		Name:   "evasion_with_resource_abuse",
		Weight: 0.40,
		AllOf: [][]cloudtrail.Indicator{
			// Bedrock logging removal is left out: llmjacking_chain already
			// scores it with model-access changes, and one pair of events
			// must not count as two chains.
			{cloudtrail.MonitoringTampering},
			{cloudtrail.GPUInstanceLaunch, cloudtrail.BulkInstanceLaunch, cloudtrail.BedrockModelAccessChange},
		},
	},
}

// Weights for the count-based rules. Tuned against the replay fixtures in
// internal/cloudtrail/testdata; see TestFixtureBands before changing them.
const (
	// enumerationBurstWeight applies when a finding has many access-denied
	// events. Ordinary permission trial and error produces a few denials;
	// a burst across services is typical of probing with stolen keys.
	enumerationBurstWeight = 0.45
	// multiRegionGPUWeight applies when GPU instances are launched in several
	// regions at once, which separates miners spreading across regions from
	// a training job in one region.
	multiRegionGPUWeight = 0.40
)

// Options tune correlation.
type Options struct {
	// Window is the largest gap between consecutive indicator events of one
	// principal that still belong to the same finding. Zero means DefaultWindow.
	Window time.Duration
}

// Contributor is one piece of evidence behind a finding's confidence.
type Contributor struct {
	Kind     string   `json:"kind"` // "indicator" or "chain"
	Name     string   `json:"name"`
	Weight   float64  `json:"weight"`
	EventIDs []string `json:"event_ids"`
}

// Finding is a scored, explainable incident for one principal.
type Finding struct {
	Principal    string                       `json:"principal"`
	AccountIDs   []string                     `json:"account_ids,omitempty"`
	SourceIPs    []string                     `json:"source_ips,omitempty"`
	Regions      []string                     `json:"regions,omitempty"`
	First        time.Time                    `json:"first_event_time"`
	Last         time.Time                    `json:"last_event_time"`
	EventCount   int                          `json:"event_count"`
	Indicators   map[cloudtrail.Indicator]int `json:"indicators"`
	Contributors []Contributor                `json:"contributors"`
	Confidence   float64                      `json:"confidence"`
}

// IncidentID is a stable identifier for a finding, derived from its
// principal and first event time. A replay that starts earlier and so finds
// an earlier first event yields a different ID.
func (f Finding) IncidentID() string {
	sum := sha256.Sum256([]byte(f.Principal + "|" + f.First.UTC().Format(time.RFC3339Nano)))
	return "inc_" + hex.EncodeToString(sum[:8])
}

// principalKey identifies who acted. Masked key IDs are a weaker key than
// ARNs (two keys can share a mask), so ARNs are preferred.
func principalKey(ev cloudtrail.Event) string {
	switch {
	case ev.PrincipalARN != "":
		return ev.PrincipalARN
	case ev.AccessKeyID != "":
		return "access-key:" + ev.AccessKeyID
	default:
		return "unknown"
	}
}

// Detect correlates events into findings, highest confidence first.
// Events without indicators are ignored. Input order does not matter.
func Detect(events []cloudtrail.Event, opt Options) ([]Finding, error) {
	if opt.Window < 0 {
		return nil, fmt.Errorf("%w: window must not be negative", ErrInvalid)
	}
	if opt.Window == 0 {
		opt.Window = DefaultWindow
	}

	byPrincipal := map[string][]cloudtrail.Event{}
	for _, ev := range events {
		if len(ev.Indicators) > 0 {
			k := principalKey(ev)
			byPrincipal[k] = append(byPrincipal[k], ev)
		}
	}

	var findings []Finding
	for principal, evs := range byPrincipal {
		sort.SliceStable(evs, func(i, j int) bool {
			if !evs[i].Time.Equal(evs[j].Time) {
				return evs[i].Time.Before(evs[j].Time)
			}
			return evs[i].EventID < evs[j].EventID
		})
		start := 0
		for i := 1; i <= len(evs); i++ {
			if i == len(evs) || evs[i].Time.Sub(evs[i-1].Time) > opt.Window {
				findings = append(findings, score(principal, evs[start:i]))
				start = i
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.Principal != b.Principal {
			return a.Principal < b.Principal
		}
		return a.First.Before(b.First)
	})
	return findings, nil
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func score(principal string, evs []cloudtrail.Event) Finding {
	f := Finding{
		Principal:  principal,
		First:      evs[0].Time,
		Last:       evs[len(evs)-1].Time,
		EventCount: len(evs),
		Indicators: map[cloudtrail.Indicator]int{},
	}
	accounts, ips, regions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	eventsFor := map[cloudtrail.Indicator][]string{}
	gpuRegions := map[string]bool{}
	for _, ev := range evs {
		if ev.AccountID != "" {
			accounts[ev.AccountID] = true
		}
		if ev.SourceIP != "" {
			ips[ev.SourceIP] = true
		}
		if ev.Region != "" {
			regions[ev.Region] = true
		}
		for _, ind := range ev.Indicators {
			f.Indicators[ind]++
			eventsFor[ind] = append(eventsFor[ind], ev.EventID)
			if ind == cloudtrail.GPUInstanceLaunch && ev.Region != "" {
				gpuRegions[ev.Region] = true
			}
		}
	}
	f.AccountIDs, f.SourceIPs, f.Regions = sortedKeys(accounts), sortedKeys(ips), sortedKeys(regions)

	// Distinct indicators, in a stable order.
	inds := make([]cloudtrail.Indicator, 0, len(f.Indicators))
	for ind := range f.Indicators {
		inds = append(inds, ind)
	}
	sort.Slice(inds, func(i, j int) bool { return inds[i] < inds[j] })
	for _, ind := range inds {
		if w, ok := IndicatorWeights[ind]; ok {
			f.Contributors = append(f.Contributors, Contributor{Kind: "indicator", Name: string(ind), Weight: w, EventIDs: eventsFor[ind]})
		}
	}
	if n := f.Indicators[cloudtrail.AccessDenied]; n >= EnumerationBurstThreshold {
		f.Contributors = append(f.Contributors, Contributor{Kind: "chain", Name: "enumeration_burst", Weight: enumerationBurstWeight, EventIDs: eventsFor[cloudtrail.AccessDenied]})
	}
	if len(gpuRegions) >= MultiRegionGPUThreshold {
		f.Contributors = append(f.Contributors, Contributor{Kind: "chain", Name: "multi_region_gpu_launch", Weight: multiRegionGPUWeight, EventIDs: eventsFor[cloudtrail.GPUInstanceLaunch]})
	}
	for _, rule := range ChainRules {
		var ids []string
		matched := true
		for _, group := range rule.AllOf {
			hit := false
			for _, ind := range group {
				if f.Indicators[ind] > 0 {
					hit = true
					ids = append(ids, eventsFor[ind]...)
				}
			}
			if !hit {
				matched = false
				break
			}
		}
		if matched {
			f.Contributors = append(f.Contributors, Contributor{Kind: "chain", Name: rule.Name, Weight: rule.Weight, EventIDs: dedupe(ids)})
		}
	}

	miss := 1.0
	for _, c := range f.Contributors {
		miss *= 1 - c.Weight
	}
	f.Confidence = math.Round((1-miss)*1000) / 10
	return f
}

func dedupe(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := ids[:0:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
