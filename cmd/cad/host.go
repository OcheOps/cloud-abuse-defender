package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/alert"
	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
	"github.com/OcheOps/cloud-abuse-defender/internal/host"
)

// hostname is recorded in snapshots; tests replace it.
var hostname = os.Hostname

func runHostSnapshot(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad host-snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sample := fs.Duration("sample", 2*time.Second, "CPU sampling interval (0 records no CPU use)")
	procRoot := fs.String("proc", "/proc", "proc filesystem to read")
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	name, _ := hostname()
	snap, err := host.Collect(host.CollectOptions{ProcRoot: *procRoot, Hostname: name, Now: now, Sample: *sample})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return encode(stdout, stderr, snap)
}

// kindHostFinding is the evidence record kind for a scored host process.
const kindHostFinding = "host_finding"

// hostAlertWindow is how far apart two snapshots can be for alerts about the
// same process to count as one incident.
const hostAlertWindow = 24 * time.Hour

type hostFindingEvidence struct {
	Finding        host.Finding `json:"finding"`
	CollectedAt    time.Time    `json:"collected_at"`
	WeightsVersion string       `json:"weights_version"`
}

type hostScanFinding struct {
	IncidentID string `json:"incident_id"`
	host.Finding
	EvidenceRecord string `json:"evidence_record,omitempty"`
}

type hostScanOutput struct {
	Host           string            `json:"host"`
	CollectedAt    time.Time         `json:"collected_at"`
	WeightsVersion string            `json:"weights_version"`
	Findings       []hostScanFinding `json:"findings"`
	Notifications  []notification    `json:"notifications,omitempty"`
	EvidenceHead   *evidence.Head    `json:"evidence_head,omitempty"`
}

func runHostScan(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad host-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("file", "", "snapshot from 'cad host-snapshot'; required")
	minConf := fs.Float64("min-confidence", 0, "only report findings at or above this confidence")
	nf := registerNotifyFlags(fs)
	evidencePath := fs.String("evidence-log", "", "append a tamper-evident record of each reported finding and each delivered alert to this file")
	addConfigFlag(fs)
	set, ok := parseFlags(fs, args, stderr)
	if !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-file is required")
		return 2
	}
	if *minConf < 0 || *minConf > 100 {
		fmt.Fprintln(stderr, "-min-confidence must be between 0 and 100")
		return 2
	}
	sender, err := nf.sender(set)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	snap, err := loadFile(*path, host.Load)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	out := hostScanOutput{Host: snap.Host, CollectedAt: snap.CollectedAt, WeightsVersion: host.WeightsVersion, Findings: []hostScanFinding{}}
	for _, f := range host.Scan(snap) {
		if f.Confidence >= *minConf {
			out.Findings = append(out.Findings, hostScanFinding{IncidentID: f.IncidentID(), Finding: f})
		}
	}

	var evLog *evidence.Log
	if *evidencePath != "" {
		if evLog, err = evidence.Open(*evidencePath); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer evLog.Close()
		for i := range out.Findings {
			hf := &out.Findings[i]
			rec, err := evLog.Append(kindHostFinding, hf.IncidentID, hostFindingEvidence{Finding: hf.Finding, CollectedAt: snap.CollectedAt, WeightsVersion: host.WeightsVersion}, now)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			hf.EvidenceRecord = rec.Hash
		}
	}

	code := 0
	if sender != nil {
		d, err := newDeliverer(nf, sender, evLog, hostAlertWindow, now)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		items := make([]alertItem, len(out.Findings))
		for i, hf := range out.Findings {
			items[i] = alertItem{alert: alert.FromHost(hf.Finding, snap.CollectedAt, now), confidence: hf.Confidence, findingRecord: hf.EvidenceRecord}
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
	if c := encode(stdout, stderr, out); c != 0 {
		return c
	}
	if code != 0 {
		fmt.Fprintln(stderr, "one or more alerts could not be delivered or recorded")
	}
	return code
}
