// Package policy evaluates cost-aware response decisions without external side effects.
package policy

import (
	"errors"
	"fmt"
	"math"
)

// Action is the response the policy recommends.
type Action string

const (
	Alert                Action = "alert"
	RecommendContainment Action = "recommend_containment"
)

// Input holds the forecast and confidence values the policy is evaluated against.
//
// MinConfidence and ThresholdUSD must be greater than zero. A zero gate would
// let any signal pass, which would violate the two-signal requirement.
type Input struct {
	HourlyCostUSD    float64 `json:"hourly_cost_usd"`
	HorizonHours     float64 `json:"horizon_hours"`
	ThresholdUSD     float64 `json:"threshold_usd"`
	ThreatConfidence float64 `json:"threat_confidence"`
	MinConfidence    float64 `json:"min_confidence"`
	AllowContainment bool    `json:"allow_containment"`
	// ForecastWarnings lists reasons the cost forecast may be wrong (stale
	// pricing, unpriced models, short observation window). Any entry forces
	// alert-only, because an unreliable forecast must not justify containment.
	ForecastWarnings []string `json:"forecast_warnings,omitempty"`
}

// Decision is the result of evaluating an Input.
type Decision struct {
	Action           Action  `json:"action"`
	ProjectedCostUSD float64 `json:"projected_cost_usd"`
	Reason           string  `json:"reason"`
	// EligibleForContainment indicates policy eligibility only; there is no executor in the MVP.
	EligibleForContainment bool `json:"eligible_for_containment"`
	// ForecastWarnings echoes the input warnings so the decision is self-explanatory.
	ForecastWarnings []string `json:"forecast_warnings,omitempty"`
}

// ErrInvalidInput is wrapped by every validation error returned by Evaluate.
var ErrInvalidInput = errors.New("invalid policy input")

// Reasons reported in Decision.Reason.
const (
	ReasonLowConfidence       = "threat confidence below policy minimum"
	ReasonDegradedForecast    = "cost forecast is unreliable; alert-only until forecast warnings are resolved"
	ReasonBelowThreshold      = "projected cost below policy threshold"
	ReasonContainmentDisabled = "containment disabled; alert-only mode"
	ReasonEligible            = "confidence and projected cost meet or exceed policy limits; operator-approved containment required"
)

const maxConfidence = 100

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func validate(in Input) error {
	checks := []struct {
		name string
		v    float64
		ok   func(float64) bool
		want string
	}{
		{"hourly_cost_usd", in.HourlyCostUSD, func(v float64) bool { return v >= 0 }, ">= 0"},
		{"horizon_hours", in.HorizonHours, func(v float64) bool { return v >= 0 }, ">= 0"},
		{"threshold_usd", in.ThresholdUSD, func(v float64) bool { return v > 0 }, "> 0"},
		{"threat_confidence", in.ThreatConfidence, func(v float64) bool { return v >= 0 && v <= maxConfidence }, "between 0 and 100"},
		{"min_confidence", in.MinConfidence, func(v float64) bool { return v > 0 && v <= maxConfidence }, "greater than 0 and at most 100"},
	}
	for _, c := range checks {
		if !finite(c.v) || !c.ok(c.v) {
			return fmt.Errorf("%w: %s must be finite and %s, got %v", ErrInvalidInput, c.name, c.want, c.v)
		}
	}
	return nil
}

// Evaluate uses a simple fixed-rate forecast for simulation purposes.
// It cannot assess whether activity is malicious or stop infrastructure.
func Evaluate(in Input) (Decision, error) {
	if err := validate(in); err != nil {
		return Decision{}, err
	}
	projected := in.HourlyCostUSD * in.HorizonHours
	if !finite(projected) {
		return Decision{}, fmt.Errorf("%w: projected cost overflow", ErrInvalidInput)
	}
	decision := Decision{Action: Alert, ProjectedCostUSD: projected, ForecastWarnings: in.ForecastWarnings}
	switch {
	case in.ThreatConfidence < in.MinConfidence:
		decision.Reason = ReasonLowConfidence
	case len(in.ForecastWarnings) > 0:
		decision.Reason = ReasonDegradedForecast
	case projected < in.ThresholdUSD:
		decision.Reason = ReasonBelowThreshold
	case !in.AllowContainment:
		decision.Reason = ReasonContainmentDisabled
	default:
		decision.Action = RecommendContainment
		decision.EligibleForContainment = true
		decision.Reason = ReasonEligible
	}
	return decision, nil
}
