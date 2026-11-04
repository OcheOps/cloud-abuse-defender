// Command cad runs local, offline simulations and prints JSON. It never calls
// cloud APIs or changes infrastructure.
//
//	cad [flags]                      evaluate the policy for one confidence and spend rate
//	cad cloudtrail -file <log>       replay a CloudTrail log into redacted events with indicators
//	cad detect -file <log> [flags]   correlate a CloudTrail log into scored findings and,
//	                                 given a cost source, a policy decision per finding;
//	                                 -notify slack|webhook sends alerts to $CAD_WEBHOOK_URL
//	cad bedrock-queries -models a,b  write CloudWatch queries for Bedrock token metrics
//	cad bedrock-usage -results <f>   convert "aws cloudwatch get-metric-data" output to a usage file
//	cad evidence-verify -file <log>  verify a tamper-evident evidence log
//	cad approvals -evidence-log <f>  show each incident's containment approval state
//	cad approve|reject|revoke ...    record an operator decision (never executes anything)
//
// The hourly spend comes either from -hourly-rate, or from a Bedrock usage
// observation priced with a versioned table (-usage and -pricing).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/alert"
	"github.com/OcheOps/cloud-abuse-defender/internal/cloudtrail"
	"github.com/OcheOps/cloud-abuse-defender/internal/cloudwatch"
	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
	"github.com/OcheOps/cloud-abuse-defender/internal/incident"
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
		case "bedrock-queries":
			return runBedrockQueries(args[1:], stdout, stderr)
		case "bedrock-usage":
			return runBedrockUsage(args[1:], stdout, stderr)
		case "evidence-verify":
			return runEvidenceVerify(args[1:], stdout, stderr)
		case "approvals":
			return runApprovals(args[1:], stdout, stderr, now)
		case "approve", "reject", "revoke":
			return runDecision(args[0], args[1:], stdout, stderr, now)
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
	IncidentID string `json:"incident_id"`
	detect.Finding
	// Decision is present only when a cost source was given.
	Decision *policy.Decision `json:"decision,omitempty"`
}

// webhookEnv names the environment variable holding the webhook URL. The URL
// is a secret, so it is never accepted as a flag (flags leak into shell
// history and process listings) and never printed.
const webhookEnv = "CAD_WEBHOOK_URL"

// httpClient is used for alert delivery; tests replace it.
var httpClient = &http.Client{Timeout: 10 * time.Second}

type notification struct {
	Principal string    `json:"principal"`
	First     time.Time `json:"first_event_time"`
	// Status is "sent", "failed", "dry_run", "skipped_below_threshold" or
	// "suppressed_duplicate".
	Status string `json:"status"`
	// Verdict is the de-duplication verdict ("new", "escalated", "reminder",
	// "duplicate") when -alert-state is set.
	Verdict alert.Verdict   `json:"verdict,omitempty"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type detectOutput struct {
	Findings      []detectedFinding `json:"findings"`
	Estimate      *cost.Estimate    `json:"estimate,omitempty"`
	Notifications []notification    `json:"notifications,omitempty"`
	// EvidenceHead is the end of the evidence chain after this run.
	EvidenceHead *evidence.Head `json:"evidence_head,omitempty"`
}

func runDetect(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad detect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("file", "", "CloudTrail log file (S3 delivery format, .json or .json.gz); required")
	window := fs.Duration("window", detect.DefaultWindow, "largest gap between a principal's indicator events within one finding")
	notify := fs.String("notify", "", `send alerts as "slack" or "webhook" to $`+webhookEnv)
	notifyMin := fs.Float64("notify-min-confidence", 50, "only alert on findings at or above this confidence")
	dryRun := fs.Bool("notify-dry-run", false, "render alert payloads into the output instead of sending them")
	statePath := fs.String("alert-state", "", "state file of delivered alerts; enables de-duplication (created if missing, never written on dry runs)")
	suppressFor := fs.Duration("alert-suppress-for", 24*time.Hour, "with -alert-state, re-send an unchanged alert only after this long")
	evidencePath := fs.String("evidence-log", "", "append a tamper-evident record of each finding and delivered alert to this file")
	cf := registerCostFlags(fs)
	set, ok := parseFlags(fs, args, stderr)
	if !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-file is required")
		return 2
	}
	var sender *alert.Sender
	switch {
	case *notify == "" && (*dryRun || set["notify-min-confidence"] || *statePath != "" || set["alert-suppress-for"]):
		fmt.Fprintln(stderr, "-notify-dry-run, -notify-min-confidence, -alert-state and -alert-suppress-for require -notify")
		return 2
	case set["alert-suppress-for"] && *statePath == "":
		fmt.Fprintln(stderr, "-alert-suppress-for requires -alert-state")
		return 2
	case *suppressFor < 0:
		fmt.Fprintln(stderr, "-alert-suppress-for must not be negative")
		return 2
	case *notify != "":
		format, err := alert.ParseFormat(*notify)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if *notifyMin < 0 || *notifyMin > 100 {
			fmt.Fprintln(stderr, "-notify-min-confidence must be between 0 and 100")
			return 2
		}
		sender = &alert.Sender{Format: format, Client: httpClient}
		if !*dryRun {
			sender.URL = os.Getenv(webhookEnv)
			if sender.URL == "" {
				fmt.Fprintf(stderr, "-notify requires $%s (or use -notify-dry-run)\n", webhookEnv)
				return 2
			}
			if err := sender.Validate(); err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
		}
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
		df.IncidentID = f.IncidentID()
		out.Findings = append(out.Findings, df)
	}

	// Evidence is written before any alert goes out, so every alert can
	// point at the record that explains it.
	var evLog *evidence.Log
	recordHash := make([]string, len(out.Findings))
	if *evidencePath != "" {
		if evLog, err = evidence.Open(*evidencePath); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer evLog.Close()
		for i, df := range out.Findings {
			ev := incident.FindingData{Finding: df.Finding, Decision: df.Decision, PolicyVersion: policy.Version, WeightsVersion: detect.WeightsVersion}
			if est != nil {
				ev.PricingVersion, ev.HourlyCostUSD, ev.ForecastWarnings = est.PricingVersion, est.HourlyCostUSD, est.Warnings
			}
			rec, err := evLog.Append(incident.KindFinding, df.IncidentID, ev, now)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			recordHash[i] = rec.Hash
		}
	}

	var state *alert.State
	if sender != nil && *statePath != "" {
		if state, err = alert.LoadState(*statePath); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	code := 0
	stateChanged := false
	if sender != nil {
		for i, df := range out.Findings {
			n := notification{Principal: df.Principal, First: df.First}
			a := alert.FromFinding(df.Finding, df.Decision, est, now)
			a.EvidenceHash = recordHash[i]
			if state != nil && df.Confidence >= *notifyMin {
				n.Verdict = state.Check(a, *window, *suppressFor, now)
				if n.Verdict == alert.VerdictEscalated || n.Verdict == alert.VerdictReminder {
					a.Update = string(n.Verdict)
				}
			}
			switch {
			case df.Confidence < *notifyMin:
				n.Status = "skipped_below_threshold"
			case n.Verdict == alert.VerdictDuplicate:
				n.Status = "suppressed_duplicate"
			case *dryRun:
				payload, err := alert.Render(sender.Format, a)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				n.Status, n.Payload = "dry_run", payload
			default:
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				err := sender.Send(ctx, a)
				cancel()
				if err != nil {
					n.Status, n.Error = "failed", err.Error()
					code = 1
				} else {
					n.Status = "sent"
					// Only delivered alerts are recorded, so a failed send is retried next run.
					if state != nil {
						state.Record(a, *window, now)
						stateChanged = true
					}
				}
			}
			out.Notifications = append(out.Notifications, n)
			// Dry runs and skipped findings deliver nothing, so there is nothing to record.
			if evLog != nil && (n.Status == "sent" || n.Status == "failed" || n.Status == "suppressed_duplicate") {
				ne := incident.NotificationData{Format: sender.Format, Status: n.Status, Verdict: n.Verdict, Error: n.Error, FindingRecord: recordHash[i]}
				if _, err := evLog.Append(incident.KindNotification, df.IncidentID, ne, now); err != nil {
					fmt.Fprintln(stderr, err)
					code = 1
				}
			}
		}
	}
	if evLog != nil {
		head := evLog.Head()
		out.EvidenceHead = &head
	}
	if stateChanged {
		if err := state.Save(*statePath, now); err != nil {
			fmt.Fprintln(stderr, err)
			code = 1
		}
	}
	// Findings are always printed; a failed delivery is reported in the
	// output and the exit status rather than hiding the detection result.
	if c := encode(stdout, stderr, out); c != 0 {
		return c
	}
	if code != 0 {
		fmt.Fprintln(stderr, "one or more alerts could not be delivered")
	}
	return code
}

func runApprovals(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad approvals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("evidence-log", "", "evidence log written by 'cad detect -evidence-log'; required")
	id := fs.String("incident", "", "show only this incident")
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-evidence-log is required")
		return 2
	}
	records, _, err := evidence.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *id != "" {
		s, err := incident.StatusOf(records, *id, now)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return encode(stdout, stderr, s)
	}
	all, err := incident.Summarize(records, now)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return encode(stdout, stderr, all)
}

// localAccount is the OS account running the command, recorded next to the
// self-declared operator name.
var localAccount = func() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

type decisionOutput struct {
	Record evidence.Record `json:"record"`
	Status incident.Status `json:"status"`
}

// runDecision records an approval, rejection or revocation. Nothing is executed.
func runDecision(kind string, args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad "+kind, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("evidence-log", "", "evidence log written by 'cad detect -evidence-log'; required")
	id := fs.String("incident", "", "incident ID; required")
	operator := fs.String("operator", "", "name of the operator making the decision; required")
	reason := fs.String("reason", "", "why; required")
	var principal, action *string
	var ttl *time.Duration
	if kind == "approve" {
		principal = fs.String("principal", "", "the incident's principal ARN, typed out to confirm the target; required")
		action = fs.String("action", "", "reversible action to authorise: deactivate-access-keys or attach-deny-all-policy; required")
		ttl = fs.Duration("expires", 0, "how long the approval stays valid (at most 24h); required")
	}
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *path == "" || *id == "" {
		fmt.Fprintln(stderr, "-evidence-log and -incident are required")
		return 2
	}
	records, head, err := evidence.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	d := incident.Decider{Operator: *operator, RecordedBy: localAccount(), Reason: *reason}

	var recordKind string
	var data any
	switch kind {
	case "approve":
		act, perr := incident.ParseAction(*action)
		if perr != nil {
			fmt.Fprintln(stderr, perr)
			return 2
		}
		recordKind = incident.KindApproval
		data, err = incident.Approve(records, incident.ApproveRequest{Decider: d, IncidentID: *id, Principal: *principal, Action: act, TTL: *ttl}, now)
	case "reject":
		recordKind = incident.KindRejection
		data, err = incident.Reject(records, *id, d, now)
	default:
		recordKind = incident.KindRevocation
		data, err = incident.Revoke(records, *id, d, now)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	log, err := evidence.Open(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer log.Close()
	// The decision was validated against the log as read above; refuse if
	// another writer appended in between.
	if log.Head() != head {
		fmt.Fprintln(stderr, "evidence log changed while the decision was being checked; run the command again")
		return 1
	}
	rec, err := log.Append(recordKind, *id, data, now)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	status, err := incident.StatusOf(append(records, rec), *id, now)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return encode(stdout, stderr, decisionOutput{Record: rec, Status: status})
}

func runEvidenceVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cad evidence-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("file", "", "evidence log written by -evidence-log; required")
	expect := fs.String("expect-record", "", "record hash kept outside the log (for example an alert's evidence_hash); fails if it is not in the chain")
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-file is required")
		return 2
	}
	head, found, err := evidence.VerifyFileContains(*path, *expect)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *expect != "" && !found {
		fmt.Fprintf(stderr, "log verifies but has no record %s (it was truncated past that record or rebuilt)\n", *expect)
		return 1
	}
	return encode(stdout, stderr, head)
}

func runBedrockQueries(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cad bedrock-queries", flag.ContinueOnError)
	fs.SetOutput(stderr)
	models := fs.String("models", "", "comma-separated Bedrock model IDs")
	listMetrics := fs.String("list-metrics", "", `output of "aws cloudwatch list-metrics --namespace AWS/Bedrock" to take model IDs from`)
	period := fs.Int("period", cloudwatch.DefaultPeriod, "aggregation period in seconds (multiple of 60)")
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	var ids []string
	switch {
	case (*models == "") == (*listMetrics == ""):
		fmt.Fprintln(stderr, "give exactly one of -models or -list-metrics")
		return 2
	case *models != "":
		ids = strings.Split(*models, ",")
	default:
		var err error
		if ids, err = loadFile(*listMetrics, cloudwatch.ModelsFromListMetrics); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	queries, err := cloudwatch.BuildQueries(ids, *period)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return encode(stdout, stderr, queries)
}

func runBedrockUsage(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cad bedrock-usage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	results := fs.String("results", "", `output of "aws cloudwatch get-metric-data" run with queries from "cad bedrock-queries"; required`)
	region := fs.String("region", "", "AWS region the metrics were read from; required")
	startStr := fs.String("start", "", "the --start-time given to the AWS CLI (RFC 3339); required")
	endStr := fs.String("end", "", "the --end-time given to the AWS CLI (RFC 3339); required")
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *results == "" || *region == "" || *startStr == "" || *endStr == "" {
		fmt.Fprintln(stderr, "-results, -region, -start and -end are required")
		return 2
	}
	start, err := time.Parse(time.RFC3339, *startStr)
	if err != nil {
		fmt.Fprintf(stderr, "-start: %v\n", err)
		return 2
	}
	end, err := time.Parse(time.RFC3339, *endStr)
	if err != nil {
		fmt.Fprintf(stderr, "-end: %v\n", err)
		return 2
	}
	usage, err := loadFile(*results, func(r io.Reader) (cost.Usage, error) {
		return cloudwatch.UsageFromResults(r, *region, start, end)
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return encode(stdout, stderr, usage)
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
