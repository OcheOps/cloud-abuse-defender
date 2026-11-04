// Package cost estimates on-demand AWS Bedrock spend from observed token usage
// and a versioned pricing table. It performs no network calls: pricing and
// usage are supplied by the caller (for example, exported CloudWatch
// InputTokenCount/OutputTokenCount metrics per ModelId).
//
// Estimates are projections, not billed amounts. Provisioned throughput,
// batch discounts, private pricing and other billing adjustments are not modelled.
package cost

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"
)

// ErrInvalid is wrapped by every validation error in this package.
var ErrInvalid = errors.New("invalid cost input")

const tokensPerMillion = 1_000_000

// ModelRate is the on-demand price of one model, in USD per million tokens.
type ModelRate struct {
	InputPerMillionUSD  float64 `json:"input_per_million_tokens_usd"`
	OutputPerMillionUSD float64 `json:"output_per_million_tokens_usd"`
}

// PricingTable is a versioned set of model rates for one provider and region.
type PricingTable struct {
	Version       string               `json:"version"`
	Provider      string               `json:"provider"`
	Region        string               `json:"region"`
	Currency      string               `json:"currency"`
	EffectiveDate time.Time            `json:"effective_date"`
	Source        string               `json:"source"`
	Models        map[string]ModelRate `json:"models"`
}

// ModelUsage is the token count observed for one model during the window.
type ModelUsage struct {
	ModelID      string `json:"model_id"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
}

// Usage is token consumption observed in one region over a time window.
type Usage struct {
	Region      string       `json:"region"`
	WindowStart time.Time    `json:"window_start"`
	WindowEnd   time.Time    `json:"window_end"`
	Models      []ModelUsage `json:"models"`
}

// Options control when an estimate is flagged as unreliable.
type Options struct {
	// Now is the evaluation time used for pricing-age checks. Required.
	Now time.Time
	// MaxPricingAge flags pricing tables older than this. Zero disables the check.
	MaxPricingAge time.Duration
	// MinWindow flags observation windows shorter than this, since
	// extrapolating a short burst to an hourly rate is unreliable. Zero disables the check.
	MinWindow time.Duration
}

// ModelCost is the per-model breakdown of an estimate.
type ModelCost struct {
	ModelID      string  `json:"model_id"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	Priced       bool    `json:"priced"`
}

// Estimate is the result of pricing observed usage.
//
// Any entry in Warnings means the estimate may be wrong (usually low) and
// callers should degrade to alert-only.
type Estimate struct {
	PricingVersion  string      `json:"pricing_version"`
	Region          string      `json:"region"`
	WindowStart     time.Time   `json:"window_start"`
	WindowEnd       time.Time   `json:"window_end"`
	WindowHours     float64     `json:"window_hours"`
	ObservedCostUSD float64     `json:"observed_cost_usd"`
	HourlyCostUSD   float64     `json:"hourly_cost_usd"`
	Models          []ModelCost `json:"models"`
	Warnings        []string    `json:"warnings,omitempty"`
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func validRate(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }

// Validate checks that the table is internally consistent.
func (p PricingTable) Validate() error {
	switch {
	case p.Version == "":
		return invalid("pricing version is required")
	case p.Provider != "aws-bedrock":
		return invalid("unsupported pricing provider %q (want \"aws-bedrock\")", p.Provider)
	case p.Region == "":
		return invalid("pricing region is required")
	case p.Currency != "USD":
		return invalid("unsupported currency %q (want \"USD\")", p.Currency)
	case p.EffectiveDate.IsZero():
		return invalid("pricing effective_date is required")
	case len(p.Models) == 0:
		return invalid("pricing table has no models")
	}
	for id, r := range p.Models {
		if id == "" {
			return invalid("pricing table has an empty model id")
		}
		if !validRate(r.InputPerMillionUSD) || !validRate(r.OutputPerMillionUSD) {
			return invalid("model %q has a negative or non-finite rate", id)
		}
	}
	return nil
}

// Validate checks that the usage window and counts are well formed.
func (u Usage) Validate() error {
	switch {
	case u.Region == "":
		return invalid("usage region is required")
	case u.WindowStart.IsZero() || u.WindowEnd.IsZero():
		return invalid("usage window_start and window_end are required")
	case !u.WindowEnd.After(u.WindowStart):
		return invalid("usage window_end must be after window_start")
	}
	seen := make(map[string]bool, len(u.Models))
	for _, m := range u.Models {
		if m.ModelID == "" {
			return invalid("usage entry has an empty model_id")
		}
		if seen[m.ModelID] {
			return invalid("duplicate usage entry for model %q", m.ModelID)
		}
		seen[m.ModelID] = true
		if m.InputTokens < 0 || m.OutputTokens < 0 {
			return invalid("model %q has negative token counts", m.ModelID)
		}
	}
	return nil
}

// EstimateBedrock prices the observed usage and extrapolates an hourly rate.
func EstimateBedrock(u Usage, p PricingTable, opt Options) (Estimate, error) {
	if err := p.Validate(); err != nil {
		return Estimate{}, err
	}
	if err := u.Validate(); err != nil {
		return Estimate{}, err
	}
	if opt.Now.IsZero() {
		return Estimate{}, invalid("options.Now is required")
	}
	if opt.MaxPricingAge < 0 || opt.MinWindow < 0 {
		return Estimate{}, invalid("options durations must not be negative")
	}
	if u.Region != p.Region {
		return Estimate{}, invalid("usage region %q does not match pricing region %q", u.Region, p.Region)
	}

	window := u.WindowEnd.Sub(u.WindowStart)
	est := Estimate{
		PricingVersion: p.Version,
		Region:         u.Region,
		WindowStart:    u.WindowStart,
		WindowEnd:      u.WindowEnd,
		WindowHours:    window.Hours(),
		Models:         make([]ModelCost, 0, len(u.Models)),
	}

	if opt.MaxPricingAge > 0 && opt.Now.Sub(p.EffectiveDate) > opt.MaxPricingAge {
		est.Warnings = append(est.Warnings, fmt.Sprintf("pricing %q is older than %s", p.Version, opt.MaxPricingAge))
	}
	if p.EffectiveDate.After(opt.Now) {
		est.Warnings = append(est.Warnings, fmt.Sprintf("pricing %q is not effective until %s", p.Version, p.EffectiveDate.Format(time.RFC3339)))
	}
	if opt.MinWindow > 0 && window < opt.MinWindow {
		est.Warnings = append(est.Warnings, fmt.Sprintf("observation window %s is shorter than %s; hourly extrapolation is unreliable", window, opt.MinWindow))
	}

	for _, m := range u.Models {
		mc := ModelCost{ModelID: m.ModelID, InputTokens: m.InputTokens, OutputTokens: m.OutputTokens}
		if r, ok := p.Models[m.ModelID]; ok {
			mc.Priced = true
			mc.CostUSD = float64(m.InputTokens)/tokensPerMillion*r.InputPerMillionUSD +
				float64(m.OutputTokens)/tokensPerMillion*r.OutputPerMillionUSD
		} else if m.InputTokens > 0 || m.OutputTokens > 0 {
			est.Warnings = append(est.Warnings, fmt.Sprintf("no price for model %q in pricing %q; its cost is excluded", m.ModelID, p.Version))
		}
		est.ObservedCostUSD += mc.CostUSD
		est.Models = append(est.Models, mc)
	}
	sort.Slice(est.Models, func(i, j int) bool { return est.Models[i].ModelID < est.Models[j].ModelID })

	est.HourlyCostUSD = est.ObservedCostUSD / est.WindowHours
	if math.IsInf(est.HourlyCostUSD, 0) || math.IsNaN(est.HourlyCostUSD) {
		return Estimate{}, invalid("hourly cost overflow")
	}
	return est, nil
}

func decodeStrict(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return invalid("unexpected data after JSON document")
	}
	return nil
}

// LoadPricing decodes and validates a pricing table. Unknown fields are rejected.
func LoadPricing(r io.Reader) (PricingTable, error) {
	var p PricingTable
	if err := decodeStrict(r, &p); err != nil {
		return PricingTable{}, err
	}
	return p, p.Validate()
}

// LoadUsage decodes and validates a usage observation. Unknown fields are rejected.
func LoadUsage(r io.Reader) (Usage, error) {
	var u Usage
	if err := decodeStrict(r, &u); err != nil {
		return Usage{}, err
	}
	return u, u.Validate()
}
