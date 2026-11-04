package policy

import (
	"errors"
	"math"
	"testing"
)

func valid() Input {
	return Input{HourlyCostUSD: 25, HorizonHours: 24, ThresholdUSD: 100, ThreatConfidence: 90, MinConfidence: 85}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Input)
		want      Action
		eligible  bool
		reason    string
		projected float64
	}{
		{"default alerts", func(in *Input) {}, Alert, false, ReasonContainmentDisabled, 600},
		{"high confidence with opt in", func(in *Input) { in.AllowContainment = true }, RecommendContainment, true, ReasonEligible, 600},
		{"low confidence", func(in *Input) { in.ThreatConfidence = 70; in.AllowContainment = true }, Alert, false, ReasonLowConfidence, 600},
		{"low spend", func(in *Input) { in.HourlyCostUSD = 1; in.ThreatConfidence = 99; in.AllowContainment = true }, Alert, false, ReasonBelowThreshold, 24},
		{"threshold and confidence boundary", func(in *Input) {
			in.HourlyCostUSD, in.HorizonHours, in.ThreatConfidence, in.AllowContainment = 5, 20, 85, true
		}, RecommendContainment, true, ReasonEligible, 100},
		{"zero spend", func(in *Input) { in.HourlyCostUSD = 0; in.AllowContainment = true }, Alert, false, ReasonBelowThreshold, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid()
			tt.mutate(&in)
			got, err := Evaluate(in)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != tt.want || got.EligibleForContainment != tt.eligible || got.Reason != tt.reason || got.ProjectedCostUSD != tt.projected {
				t.Fatalf("got %+v, want action=%s eligible=%v reason=%q projected=%v", got, tt.want, tt.eligible, tt.reason, tt.projected)
			}
		})
	}
}

func TestRejectInvalid(t *testing.T) {
	nan, inf := math.NaN(), math.Inf(1)
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{"negative hourly", func(in *Input) { in.HourlyCostUSD = -1 }},
		{"NaN hourly", func(in *Input) { in.HourlyCostUSD = nan }},
		{"Inf hourly", func(in *Input) { in.HourlyCostUSD = inf }},
		{"negative horizon", func(in *Input) { in.HorizonHours = -1 }},
		{"NaN horizon", func(in *Input) { in.HorizonHours = nan }},
		{"zero threshold", func(in *Input) { in.ThresholdUSD = 0 }},
		{"negative threshold", func(in *Input) { in.ThresholdUSD = -1 }},
		{"NaN threshold", func(in *Input) { in.ThresholdUSD = nan }},
		{"confidence above 100", func(in *Input) { in.ThreatConfidence = 101 }},
		{"negative confidence", func(in *Input) { in.ThreatConfidence = -1 }},
		{"NaN confidence", func(in *Input) { in.ThreatConfidence = nan }},
		{"Inf confidence", func(in *Input) { in.ThreatConfidence = inf }},
		{"-Inf confidence", func(in *Input) { in.ThreatConfidence = math.Inf(-1) }},
		{"zero min confidence", func(in *Input) { in.MinConfidence = 0 }},
		{"negative min confidence", func(in *Input) { in.MinConfidence = -1 }},
		{"min confidence above 100", func(in *Input) { in.MinConfidence = 101 }},
		{"Inf min confidence", func(in *Input) { in.MinConfidence = inf }},
		{"projected overflow", func(in *Input) { in.HourlyCostUSD, in.HorizonHours = math.MaxFloat64, 2 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid()
			tt.mutate(&in)
			if _, err := Evaluate(in); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("want ErrInvalidInput for %+v, got %v", in, err)
			}
		})
	}
}

// The zero value must never yield a containment recommendation.
func TestZeroValueRejected(t *testing.T) {
	if d, err := Evaluate(Input{AllowContainment: true}); err == nil {
		t.Fatalf("zero-value input accepted: %+v", d)
	}
}
