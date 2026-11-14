package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/alert"
	"github.com/OcheOps/cloud-abuse-defender/internal/cloudtrail"
	"github.com/OcheOps/cloud-abuse-defender/internal/cost"
	"github.com/OcheOps/cloud-abuse-defender/internal/detect"
	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
	"github.com/OcheOps/cloud-abuse-defender/internal/incident"
	"github.com/OcheOps/cloud-abuse-defender/internal/policy"
)

type detectedFinding struct {
	IncidentID string `json:"incident_id"`
	detect.Finding
	// Decision is present only when a cost source was given.
	Decision *policy.Decision `json:"decision,omitempty"`
	// EC2Estimate prices the finding's instance launches, with -ec2-pricing.
	EC2Estimate *cost.EC2Estimate `json:"ec2_estimate,omitempty"`
	// HourlyCostUSD is the total hourly rate the decision used.
	HourlyCostUSD float64 `json:"hourly_cost_usd,omitempty"`
	// EvidenceRecord is the hash of this finding's record in the evidence log.
	EvidenceRecord string `json:"evidence_record,omitempty"`
}

type detectOutput struct {
	Findings []detectedFinding `json:"findings"`
	Estimate *cost.Estimate    `json:"estimate,omitempty"`
	// Suppressed lists what the suppression file removed before scoring.
	Suppressed    []detect.SuppressionHit `json:"suppressed,omitempty"`
	Notifications []notification          `json:"notifications,omitempty"`
	// EvidenceHead is the end of the evidence chain after this run.
	EvidenceHead *evidence.Head `json:"evidence_head,omitempty"`
}

func runDetect(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad detect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("file", "", "CloudTrail log file (S3 delivery format, .json or .json.gz); required")
	window := fs.Duration("window", detect.DefaultWindow, "largest gap between a principal's indicator events within one finding")
	nf := registerNotifyFlags(fs)
	evidencePath := fs.String("evidence-log", "", "append a tamper-evident record of each new or changed finding and each delivered alert to this file")
	approvalsRequired := fs.Int("approvals-required", incident.DefaultRequiredApprovals, "distinct operators who must approve containment for findings recorded in this run (1-5)")
	requireSigned := fs.Bool("require-signed-approvals", false, "approvals for findings recorded in this run only count when signed by a trusted operator key")
	ec2PricingPath := fs.String("ec2-pricing", "", "versioned EC2 pricing table JSON; prices each finding's instance launches")
	suppressionsPath := fs.String("suppressions", "", "suppression rules JSON: named indicators to ignore for named principals")
	cf := registerCostFlags(fs)
	addConfigFlag(fs)
	set, ok := parseFlags(fs, args, stderr)
	if !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-file is required")
		return 2
	}
	sender, err := nf.sender(set)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	switch {
	case (set["approvals-required"] || *requireSigned) && *evidencePath == "":
		fmt.Fprintln(stderr, "-approvals-required and -require-signed-approvals require -evidence-log")
		return 2
	case *approvalsRequired < 1 || *approvalsRequired > incident.MaxRequiredApprovals:
		fmt.Fprintf(stderr, "-approvals-required must be between 1 and %d\n", incident.MaxRequiredApprovals)
		return 2
	}
	in, est, err := cf.resolve(set, now)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var ec2 *cost.EC2PricingTable
	if *ec2PricingPath != "" {
		table, err := loadFile(*ec2PricingPath, cost.LoadEC2Pricing)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		ec2 = &table
	}
	// Decisions need a real spend figure. The -hourly-rate default is a
	// simulation placeholder, so it counts only when given explicitly.
	baseHourly := 0.0
	if est != nil || set["hourly-rate"] {
		baseHourly = in.HourlyCostUSD
	}
	decide := est != nil || set["hourly-rate"] || ec2 != nil

	events, err := loadFile(*path, cloudtrail.Replay)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	out := detectOutput{Estimate: est}
	suppressionsVersion := ""
	if *suppressionsPath != "" {
		rules, err := loadFile(*suppressionsPath, detect.LoadSuppressions)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		var expired int
		events, out.Suppressed, expired = rules.Apply(events, now)
		suppressionsVersion = rules.Version
		if expired > 0 {
			fmt.Fprintf(stderr, "warning: %d suppression rule(s) in %s have expired and were not applied\n", expired, *suppressionsPath)
		}
	}
	findings, err := detect.Detect(events, detect.Options{Window: *window})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	out.Findings = make([]detectedFinding, 0, len(findings))
	for _, f := range findings {
		df := detectedFinding{Finding: f, IncidentID: f.IncidentID()}
		if decide {
			fin := in
			fin.ThreatConfidence = f.Confidence
			fin.HourlyCostUSD = baseHourly
			fin.ForecastWarnings = append([]string(nil), in.ForecastWarnings...)
			if ec2 != nil && len(f.Launches) > 0 {
				launches := make([]cost.InstanceLaunch, len(f.Launches))
				for i, l := range f.Launches {
					launches[i] = cost.InstanceLaunch{Region: l.Region, InstanceType: l.InstanceType, Count: l.Count}
				}
				e, err := cost.EstimateEC2(launches, *ec2, cost.Options{Now: now, MaxPricingAge: *cf.maxAge})
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 2
				}
				df.EC2Estimate = &e
				fin.HourlyCostUSD += e.HourlyCostUSD
				fin.ForecastWarnings = append(fin.ForecastWarnings, e.Warnings...)
			}
			d, err := policy.Evaluate(fin)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			df.Decision, df.HourlyCostUSD = &d, fin.HourlyCostUSD
		}
		out.Findings = append(out.Findings, df)
	}

	// Evidence is written before any alert goes out, so every alert can
	// point at the record that explains it.
	var evLog *evidence.Log
	if *evidencePath != "" {
		if evLog, err = evidence.Open(*evidencePath); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer evLog.Close()
		last, err := lastFindingRecords(*evidencePath, incident.KindFinding)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		for i := range out.Findings {
			df := &out.Findings[i]
			ev := incident.FindingData{Finding: df.Finding, Decision: df.Decision, PolicyVersion: policy.Version, WeightsVersion: detect.WeightsVersion,
				ApprovalsRequired: *approvalsRequired, RequireSignedApprovals: *requireSigned, SuppressionsVersion: suppressionsVersion,
				HourlyCostUSD: df.HourlyCostUSD}
			if est != nil {
				ev.PricingVersion = est.PricingVersion
			}
			if df.EC2Estimate != nil {
				ev.EC2PricingVersion = df.EC2Estimate.PricingVersion
			}
			if df.Decision != nil {
				ev.ForecastWarnings = df.Decision.ForecastWarnings
			}
			raw, err := json.Marshal(ev)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			// A repeated run over the same events (a polling watcher, for
			// example) must not re-record an identical finding: a new record
			// would reset any approvals made on the earlier one.
			if prev, seen := last[df.IncidentID]; seen && bytes.Equal(prev.Data, raw) {
				df.EvidenceRecord = prev.Hash
				continue
			}
			rec, err := evLog.Append(incident.KindFinding, df.IncidentID, ev, now)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			df.EvidenceRecord = rec.Hash
		}
	}

	code := 0
	if sender != nil {
		d, err := newDeliverer(nf, sender, evLog, *window, now)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		items := make([]alertItem, len(out.Findings))
		for i, df := range out.Findings {
			a := alert.FromFinding(df.Finding, df.Decision, est, now)
			if df.EC2Estimate != nil {
				versions := []string{df.EC2Estimate.PricingVersion}
				if a.PricingVersion != "" {
					versions = []string{a.PricingVersion, df.EC2Estimate.PricingVersion}
				}
				a.PricingVersion, a.HourlyCostUSD = strings.Join(versions, " + "), df.HourlyCostUSD
			}
			items[i] = alertItem{alert: a, confidence: df.Confidence, findingRecord: df.EvidenceRecord}
		}
		if out.Notifications, code, err = d.run(items, stderr); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := d.save(); err != nil {
			fmt.Fprintln(stderr, err)
			code = 1
		}
	}
	if evLog != nil {
		head := evLog.Head()
		out.EvidenceHead = &head
	}
	// Findings are always printed; a failed delivery is reported in the
	// output and the exit status rather than hiding the detection result.
	if c := encode(stdout, stderr, out); c != 0 {
		return c
	}
	if code != 0 {
		fmt.Fprintln(stderr, "one or more alerts could not be delivered or recorded")
	}
	return code
}
