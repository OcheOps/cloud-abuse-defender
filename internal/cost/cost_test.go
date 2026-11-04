package cost

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	t0  = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	now = t0.Add(time.Hour)
)

func table() PricingTable {
	return PricingTable{
		Version:       "test-v1",
		Provider:      "aws-bedrock",
		Region:        "us-east-1",
		Currency:      "USD",
		EffectiveDate: t0.Add(-24 * time.Hour),
		Models: map[string]ModelRate{
			"large": {InputPerMillionUSD: 3, OutputPerMillionUSD: 15},
			"small": {InputPerMillionUSD: 0.25, OutputPerMillionUSD: 1.25},
		},
	}
}

func usage() Usage {
	return Usage{
		Region:      "us-east-1",
		WindowStart: t0,
		WindowEnd:   t0.Add(30 * time.Minute),
		Models: []ModelUsage{
			{ModelID: "small", InputTokens: 2_000_000, OutputTokens: 400_000},
			{ModelID: "large", InputTokens: 4_000_000, OutputTokens: 1_000_000},
		},
	}
}

func opts() Options {
	return Options{Now: now, MaxPricingAge: 30 * 24 * time.Hour, MinWindow: 15 * time.Minute}
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestEstimateBedrock(t *testing.T) {
	est, err := EstimateBedrock(usage(), table(), opts())
	if err != nil {
		t.Fatal(err)
	}
	if !approx(est.ObservedCostUSD, 28) || !approx(est.HourlyCostUSD, 56) || !approx(est.WindowHours, 0.5) {
		t.Fatalf("observed=%v hourly=%v hours=%v", est.ObservedCostUSD, est.HourlyCostUSD, est.WindowHours)
	}
	if len(est.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", est.Warnings)
	}
	if est.PricingVersion != "test-v1" {
		t.Fatalf("pricing version not recorded: %q", est.PricingVersion)
	}
	if len(est.Models) != 2 || est.Models[0].ModelID != "large" || !approx(est.Models[0].CostUSD, 27) || !approx(est.Models[1].CostUSD, 1) {
		t.Fatalf("unexpected breakdown (want sorted by id): %+v", est.Models)
	}
}

func TestEstimateWarnings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Usage, *PricingTable, *Options)
		want   string
	}{
		{"unpriced model", func(u *Usage, _ *PricingTable, _ *Options) {
			u.Models = append(u.Models, ModelUsage{ModelID: "mystery", InputTokens: 1})
		}, `no price for model "mystery"`},
		{"stale pricing", func(_ *Usage, p *PricingTable, _ *Options) {
			p.EffectiveDate = now.Add(-31 * 24 * time.Hour)
		}, "older than"},
		{"future pricing", func(_ *Usage, p *PricingTable, _ *Options) {
			p.EffectiveDate = now.Add(time.Hour)
		}, "not effective until"},
		{"short window", func(u *Usage, _ *PricingTable, _ *Options) {
			u.WindowEnd = u.WindowStart.Add(time.Minute)
		}, "shorter than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, p, o := usage(), table(), opts()
			tt.mutate(&u, &p, &o)
			est, err := EstimateBedrock(u, p, o)
			if err != nil {
				t.Fatal(err)
			}
			if len(est.Warnings) != 1 || !strings.Contains(est.Warnings[0], tt.want) {
				t.Fatalf("warnings %v, want one containing %q", est.Warnings, tt.want)
			}
		})
	}
}

func TestUnpricedZeroUsageIsNotAWarning(t *testing.T) {
	u := usage()
	u.Models = append(u.Models, ModelUsage{ModelID: "idle"})
	est, err := EstimateBedrock(u, table(), opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(est.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", est.Warnings)
	}
}

func TestChecksDisabledByZeroOptions(t *testing.T) {
	u, p := usage(), table()
	p.EffectiveDate = now.Add(-365 * 24 * time.Hour)
	u.WindowEnd = u.WindowStart.Add(time.Second)
	est, err := EstimateBedrock(u, p, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(est.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", est.Warnings)
	}
}

func TestEstimateRejectsInvalid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Usage, *PricingTable, *Options)
	}{
		{"no version", func(_ *Usage, p *PricingTable, _ *Options) { p.Version = "" }},
		{"wrong provider", func(_ *Usage, p *PricingTable, _ *Options) { p.Provider = "other" }},
		{"no pricing region", func(_ *Usage, p *PricingTable, _ *Options) { p.Region = "" }},
		{"non-USD", func(_ *Usage, p *PricingTable, _ *Options) { p.Currency = "EUR" }},
		{"no effective date", func(_ *Usage, p *PricingTable, _ *Options) { p.EffectiveDate = time.Time{} }},
		{"no models", func(_ *Usage, p *PricingTable, _ *Options) { p.Models = nil }},
		{"empty model id", func(_ *Usage, p *PricingTable, _ *Options) { p.Models[""] = ModelRate{} }},
		{"negative rate", func(_ *Usage, p *PricingTable, _ *Options) { p.Models["large"] = ModelRate{InputPerMillionUSD: -1} }},
		{"NaN rate", func(_ *Usage, p *PricingTable, _ *Options) {
			p.Models["large"] = ModelRate{OutputPerMillionUSD: math.NaN()}
		}},
		{"no usage region", func(u *Usage, _ *PricingTable, _ *Options) { u.Region = "" }},
		{"region mismatch", func(u *Usage, _ *PricingTable, _ *Options) { u.Region = "eu-west-1" }},
		{"no window", func(u *Usage, _ *PricingTable, _ *Options) { u.WindowStart = time.Time{} }},
		{"empty window", func(u *Usage, _ *PricingTable, _ *Options) { u.WindowEnd = u.WindowStart }},
		{"reversed window", func(u *Usage, _ *PricingTable, _ *Options) { u.WindowEnd = u.WindowStart.Add(-time.Minute) }},
		{"empty usage model id", func(u *Usage, _ *PricingTable, _ *Options) { u.Models[0].ModelID = "" }},
		{"duplicate usage model", func(u *Usage, _ *PricingTable, _ *Options) { u.Models[1].ModelID = u.Models[0].ModelID }},
		{"negative tokens", func(u *Usage, _ *PricingTable, _ *Options) { u.Models[0].OutputTokens = -1 }},
		{"no now", func(_ *Usage, _ *PricingTable, o *Options) { o.Now = time.Time{} }},
		{"negative max age", func(_ *Usage, _ *PricingTable, o *Options) { o.MaxPricingAge = -1 }},
		{"negative min window", func(_ *Usage, _ *PricingTable, o *Options) { o.MinWindow = -1 }},
		{"hourly overflow", func(u *Usage, p *PricingTable, _ *Options) {
			p.Models["large"] = ModelRate{InputPerMillionUSD: math.MaxFloat64}
			u.WindowEnd = u.WindowStart.Add(time.Nanosecond)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, p, o := usage(), table(), opts()
			tt.mutate(&u, &p, &o)
			if _, err := EstimateBedrock(u, p, o); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field": `{"version":"v","provider":"aws-bedrock","region":"r","currency":"USD","effective_date":"2026-01-01T00:00:00Z","models":{"m":{}},"surprise":1}`,
		"trailing data": `{"version":"v","provider":"aws-bedrock","region":"r","currency":"USD","effective_date":"2026-01-01T00:00:00Z","models":{"m":{}}} {}`,
		"not json":      `nope`,
		"invalid table": `{"version":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPricing(strings.NewReader(doc)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
	if _, err := LoadUsage(strings.NewReader(`{"region":"r","extra":true}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("usage: want ErrInvalid, got %v", err)
	}
}

// The shipped examples must stay valid and produce the documented result.
func TestExampleFiles(t *testing.T) {
	open := func(name string) *os.File {
		f, err := os.Open(filepath.Join("..", "..", "examples", name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	p, err := LoadPricing(open("pricing.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Version, "example-") || !strings.Contains(p.Source, "ILLUSTRATIVE") {
		t.Fatalf("example pricing must be clearly marked as illustrative: %+v", p)
	}
	u, err := LoadUsage(open("usage.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	est, err := EstimateBedrock(u, p, Options{Now: u.WindowEnd})
	if err != nil {
		t.Fatal(err)
	}
	if !approx(est.HourlyCostUSD, 56) || len(est.Warnings) != 0 {
		t.Fatalf("unexpected example estimate: %+v", est)
	}
}
