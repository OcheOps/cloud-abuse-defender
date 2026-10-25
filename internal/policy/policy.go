// Package policy evaluates cost-aware response decisions without external side effects.
package policy

import (
 "errors"
 "math"
)

type Action string

const (
 Alert Action = "alert"
 RecommendContainment Action = "recommend_containment"
)

type Input struct {
 HourlyCostUSD float64 `json:"hourly_cost_usd"`
 HorizonHours float64 `json:"horizon_hours"`
 ThresholdUSD float64 `json:"threshold_usd"`
 ThreatConfidence float64 `json:"threat_confidence"`
 MinConfidence float64 `json:"min_confidence"`
 AllowContainment bool `json:"allow_containment"`
}

type Decision struct {
 Action Action `json:"action"`
 ProjectedCostUSD float64 `json:"projected_cost_usd"`
 Reason string `json:"reason"`
 // Approved indicates policy eligibility only; there is no executor in the MVP.
 EligibleForContainment bool `json:"eligible_for_containment"`
}

func finiteNonnegative(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }

// Evaluate uses a simple fixed-rate forecast for simulation purposes.
// It cannot assess whether activity is malicious or stop infrastructure.
func Evaluate(in Input) (Decision, error) {
 if !finiteNonnegative(in.HourlyCostUSD) || !finiteNonnegative(in.HorizonHours) || !finiteNonnegative(in.ThresholdUSD) ||
    math.IsNaN(in.ThreatConfidence) || math.IsInf(in.ThreatConfidence, 0) ||
    math.IsNaN(in.MinConfidence) || math.IsInf(in.MinConfidence, 0) ||
    in.ThreatConfidence < 0 || in.ThreatConfidence > 100 || in.MinConfidence < 0 || in.MinConfidence > 100 {
   return Decision{}, errors.New("invalid forecast or confidence parameters")
 }
 projected := in.HourlyCostUSD * in.HorizonHours
 if math.IsInf(projected, 0) || math.IsNaN(projected) { return Decision{}, errors.New("projected cost overflow") }
 decision := Decision{Action: Alert, ProjectedCostUSD: projected}
 if in.ThreatConfidence < in.MinConfidence {
   decision.Reason = "threat confidence below policy minimum"
 } else if projected < in.ThresholdUSD {
   decision.Reason = "projected cost below policy threshold"
 } else if !in.AllowContainment {
   decision.Reason = "containment disabled; alert-only mode"
 } else {
   decision.Action = RecommendContainment
   decision.EligibleForContainment = true
   decision.Reason = "confidence and projected cost exceed policy limits; operator-approved containment required"
 }
 return decision, nil
}
