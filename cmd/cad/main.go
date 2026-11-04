// Command cad runs a local policy simulation and prints the decision as JSON.
// It never calls cloud APIs or changes infrastructure.
//
// The hourly spend comes either from -hourly-rate, or from a Bedrock usage
// observation priced with a versioned table (-usage and -pricing).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}

// estimateOutput is printed when the rate is derived from usage, so the
// decision is reported together with the forecast and pricing version behind it.
type estimateOutput struct {
	Estimate cost.Estimate   `json:"estimate"`
	Decision policy.Decision `json:"decision"`
}

func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hourly := fs.Float64("hourly-rate", 25, "estimated unauthorized spend per hour in USD (ignored with -usage)")
	horizon := fs.Float64("hours", 24, "forecast horizon in hours")
	threshold := fs.Float64("threshold", 100, "forecast USD threshold (must be > 0)")
	confidence := fs.Float64("confidence", 90, "threat confidence between 0 and 100")
	minimum := fs.Float64("min-confidence", 85, "minimum confidence for recommendation (greater than 0, at most 100)")
	allow := fs.Bool("allow-containment", false, "enable containment recommendation (never executes)")
	usagePath := fs.String("usage", "", "Bedrock usage observation JSON; derives the hourly rate (requires -pricing)")
	pricingPath := fs.String("pricing", "", "versioned Bedrock pricing table JSON (requires -usage)")
	maxAge := fs.Duration("max-pricing-age", 30*24*time.Hour, "warn and degrade to alert-only when pricing is older than this (0 disables)")
	minWindow := fs.Duration("min-window", 15*time.Minute, "warn and degrade to alert-only when the usage window is shorter than this (0 disables)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	in := policy.Input{
		HourlyCostUSD:    *hourly,
		HorizonHours:     *horizon,
		ThresholdUSD:     *threshold,
		ThreatConfidence: *confidence,
		MinConfidence:    *minimum,
		AllowContainment: *allow,
	}

	var est *cost.Estimate
	switch {
	case *usagePath == "" && *pricingPath == "":
	case *usagePath == "" || *pricingPath == "":
		fmt.Fprintln(stderr, "-usage and -pricing must be used together")
		return 2
	case set["hourly-rate"]:
		fmt.Fprintln(stderr, "-hourly-rate cannot be combined with -usage; the rate is derived from usage")
		return 2
	default:
		e, err := estimateFromFiles(*usagePath, *pricingPath, cost.Options{Now: now, MaxPricingAge: *maxAge, MinWindow: *minWindow})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		est = &e
		in.HourlyCostUSD = e.HourlyCostUSD
		in.ForecastWarnings = e.Warnings
	}

	decision, err := policy.Evaluate(in)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var out any = decision
	if est != nil {
		out = estimateOutput{Estimate: *est, Decision: decision}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func estimateFromFiles(usagePath, pricingPath string, opt cost.Options) (cost.Estimate, error) {
	u, err := loadFile(usagePath, cost.LoadUsage)
	if err != nil {
		return cost.Estimate{}, err
	}
	p, err := loadFile(pricingPath, cost.LoadPricing)
	if err != nil {
		return cost.Estimate{}, err
	}
	return cost.EstimateBedrock(u, p, opt)
}

func loadFile[T any](path string, load func(io.Reader) (T, error)) (T, error) {
	var zero T
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	v, err := load(f)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}
