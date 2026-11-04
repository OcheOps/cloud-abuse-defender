// Command cad runs a local policy simulation and prints the decision as JSON.
// It never calls cloud APIs or changes infrastructure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cad", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hourly := fs.Float64("hourly-rate", 25, "estimated unauthorized spend per hour in USD")
	horizon := fs.Float64("hours", 24, "forecast horizon in hours")
	threshold := fs.Float64("threshold", 100, "forecast USD threshold (must be > 0)")
	confidence := fs.Float64("confidence", 90, "threat confidence between 0 and 100")
	minimum := fs.Float64("min-confidence", 85, "minimum confidence for recommendation (greater than 0, at most 100)")
	allow := fs.Bool("allow-containment", false, "enable containment recommendation (never executes)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	}
	decision, err := policy.Evaluate(policy.Input{
		HourlyCostUSD:    *hourly,
		HorizonHours:     *horizon,
		ThresholdUSD:     *threshold,
		ThreatConfidence: *confidence,
		MinConfidence:    *minimum,
		AllowContainment: *allow,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(decision); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
