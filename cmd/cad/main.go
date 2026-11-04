// Command cad runs local, offline simulations and prints JSON. It never calls
// cloud APIs or changes infrastructure.
//
//	cad [flags]                      evaluate the policy for one confidence and spend rate
//	cad cloudtrail -file <log>       replay a CloudTrail log into redacted events with indicators
//	cad detect -file <log> [flags]   correlate a CloudTrail log into scored findings and,
//	                                 given a cost source, a policy decision per finding
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

	"github.com/OcheOps/cloud-abuse-defender/internal/cloudtrail"
	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}

func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	if len(args) > 0 {
		switch args[0] {
		case "cloudtrail":
			return runCloudTrail(args[1:], stdout, stderr)
		case "detect":
			return runDetect(args[1:], stdout, stderr, now)
		}
	}
	return runPolicy(args, stdout, stderr, now)
}

// usageError reports a command-line problem; callers exit with status 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) (set map[string]bool, ok bool) {
	if err := fs.Parse(args); err != nil {
		return nil, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return nil, false
	}
	set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set, true
}

// costFlags are the policy and spend-rate flags shared by the policy and detect commands.
type costFlags struct {
	hourly, horizon, threshold, minimum *float64
	allow                               *bool
	usagePath, pricingPath              *string
	maxAge, minWindow                   *time.Duration
}

func registerCostFlags(fs *flag.FlagSet) *costFlags {
	return &costFlags{
		hourly:      fs.Float64("hourly-rate", 25, "estimated unauthorized spend per hour in USD (cannot be combined with -usage)"),
		horizon:     fs.Float64("hours", 24, "forecast horizon in hours"),
		threshold:   fs.Float64("threshold", 100, "forecast USD threshold (must be > 0)"),
		minimum:     fs.Float64("min-confidence", 85, "minimum confidence for recommendation (greater than 0, at most 100)"),
		allow:       fs.Bool("allow-containment", false, "enable containment recommendation (never executes)"),
		usagePath:   fs.String("usage", "", "Bedrock usage observation JSON; derives the hourly rate (requires -pricing)"),
		pricingPath: fs.String("pricing", "", "versioned Bedrock pricing table JSON (requires -usage)"),
		maxAge:      fs.Duration("max-pricing-age", 30*24*time.Hour, "warn and degrade to alert-only when pricing is older than this (0 disables)"),
		minWindow:   fs.Duration("min-window", 15*time.Minute, "warn and degrade to alert-only when the usage window is shorter than this (0 disables)"),
	}
}

// resolve builds a policy input (without ThreatConfidence) and, when -usage
// and -pricing are given, the cost estimate the rate came from.
func (c *costFlags) resolve(set map[string]bool, now time.Time) (policy.Input, *cost.Estimate, error) {
	in := policy.Input{
		HourlyCostUSD:    *c.hourly,
		HorizonHours:     *c.horizon,
		ThresholdUSD:     *c.threshold,
		MinConfidence:    *c.minimum,
		AllowContainment: *c.allow,
	}
	switch {
	case *c.usagePath == "" && *c.pricingPath == "":
		return in, nil, nil
	case *c.usagePath == "" || *c.pricingPath == "":
		return in, nil, usageError{"-usage and -pricing must be used together"}
	case set["hourly-rate"]:
		return in, nil, usageError{"-hourly-rate cannot be combined with -usage; the rate is derived from usage"}
	}
	est, err := estimateFromFiles(*c.usagePath, *c.pricingPath, cost.Options{Now: now, MaxPricingAge: *c.maxAge, MinWindow: *c.minWindow})
	if err != nil {
		return in, nil, err
	}
	in.HourlyCostUSD = est.HourlyCostUSD
	in.ForecastWarnings = est.Warnings
	return in, &est, nil
}

// estimateOutput is printed when the rate is derived from usage, so the
// decision is reported together with the forecast and pricing version behind it.
type estimateOutput struct {
	Estimate cost.Estimate   `json:"estimate"`
	Decision policy.Decision `json:"decision"`
}

func runPolicy(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := registerCostFlags(fs)
	confidence := fs.Float64("confidence", 90, "threat confidence between 0 and 100")
	set, ok := parseFlags(fs, args, stderr)
	if !ok {
		return 2
	}
	in, est, err := cf.resolve(set, now)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	in.ThreatConfidence = *confidence
	decision, err := policy.Evaluate(in)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if est != nil {
		return encode(stdout, stderr, estimateOutput{Estimate: *est, Decision: decision})
	}
	return encode(stdout, stderr, decision)
}

type cloudTrailOutput struct {
	Events  []cloudtrail.Event `json:"events"`
	Summary cloudtrail.Summary `json:"summary"`
}

func runCloudTrail(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cad cloudtrail", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("file", "", "CloudTrail log file (S3 delivery format, .json or .json.gz); required")
	onlyIndicators := fs.Bool("only-indicators", false, "print only events that carry at least one indicator (summary still counts all events)")
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-file is required")
		return 2
	}
	events, err := loadFile(*path, cloudtrail.Replay)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	out := cloudTrailOutput{Events: events, Summary: cloudtrail.Summarize(events)}
	if *onlyIndicators {
		out.Events = out.Events[:0:0]
		for _, ev := range events {
			if len(ev.Indicators) > 0 {
				out.Events = append(out.Events, ev)
			}
		}
	}
	return encode(stdout, stderr, out)
}

type detectedFinding struct {
	detect.Finding
	// Decision is present only when a cost source was given.
	Decision *policy.Decision `json:"decision,omitempty"`
}

type detectOutput struct {
	Findings []detectedFinding `json:"findings"`
	Estimate *cost.Estimate    `json:"estimate,omitempty"`
}

func runDetect(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad detect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("file", "", "CloudTrail log file (S3 delivery format, .json or .json.gz); required")
	window := fs.Duration("window", detect.DefaultWindow, "largest gap between a principal's indicator events within one finding")
	cf := registerCostFlags(fs)
	set, ok := parseFlags(fs, args, stderr)
	if !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-file is required")
		return 2
	}
	in, est, err := cf.resolve(set, now)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Decisions need a real spend figure: the -hourly-rate default is a
	// simulation placeholder, so it is only used when given explicitly.
	decide := est != nil || set["hourly-rate"]

	events, err := loadFile(*path, cloudtrail.Replay)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	findings, err := detect.Detect(events, detect.Options{Window: *window})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	out := detectOutput{Findings: make([]detectedFinding, 0, len(findings)), Estimate: est}
	for _, f := range findings {
		df := detectedFinding{Finding: f}
		if decide {
			fin := in
			fin.ThreatConfidence = f.Confidence
			d, err := policy.Evaluate(fin)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			df.Decision = &d
		}
		out.Findings = append(out.Findings, df)
	}
	return encode(stdout, stderr, out)
}

func encode(stdout, stderr io.Writer, v any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
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
