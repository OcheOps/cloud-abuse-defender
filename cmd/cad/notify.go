package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/alert"
	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
	"github.com/OcheOps/cloud-abuse-defender/internal/incident"
)

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

// notifyFlags are the alerting flags shared by detect and host-scan.
type notifyFlags struct {
	format      *string
	min         *float64
	dryRun      *bool
	statePath   *string
	suppressFor *time.Duration
}

func registerNotifyFlags(fs *flag.FlagSet) *notifyFlags {
	return &notifyFlags{
		format:      fs.String("notify", "", `send alerts as "slack" or "webhook" to $`+webhookEnv),
		min:         fs.Float64("notify-min-confidence", 50, "only alert on findings at or above this confidence"),
		dryRun:      fs.Bool("notify-dry-run", false, "render alert payloads into the output instead of sending them"),
		statePath:   fs.String("alert-state", "", "state file of delivered alerts; enables de-duplication (created if missing, never written on dry runs)"),
		suppressFor: fs.Duration("alert-suppress-for", 24*time.Hour, "with -alert-state, re-send an unchanged alert only after this long"),
	}
}

// sender validates the flags and returns nil when alerting is off.
func (nf *notifyFlags) sender(set map[string]bool) (*alert.Sender, error) {
	switch {
	case *nf.format == "" && (*nf.dryRun || set["notify-min-confidence"] || *nf.statePath != "" || set["alert-suppress-for"]):
		return nil, usageError{"-notify-dry-run, -notify-min-confidence, -alert-state and -alert-suppress-for require -notify"}
	case set["alert-suppress-for"] && *nf.statePath == "":
		return nil, usageError{"-alert-suppress-for requires -alert-state"}
	case *nf.suppressFor < 0:
		return nil, usageError{"-alert-suppress-for must not be negative"}
	case *nf.format == "":
		return nil, nil
	}
	format, err := alert.ParseFormat(*nf.format)
	if err != nil {
		return nil, err
	}
	if *nf.min < 0 || *nf.min > 100 {
		return nil, usageError{"-notify-min-confidence must be between 0 and 100"}
	}
	s := &alert.Sender{Format: format, Client: httpClient}
	if !*nf.dryRun {
		s.URL = os.Getenv(webhookEnv)
		if s.URL == "" {
			return nil, usageError{fmt.Sprintf("-notify requires $%s (or use -notify-dry-run)", webhookEnv)}
		}
		if err := s.Validate(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// alertItem is one finding ready to be alerted on.
type alertItem struct {
	alert      alert.Alert
	confidence float64
	// findingRecord is the hash of the evidence record behind the alert, if any.
	findingRecord string
}

// deliverer sends alerts, applying the threshold and de-duplication, and
// records each delivery attempt in the evidence log.
type deliverer struct {
	nf     *notifyFlags
	sender *alert.Sender
	state  *alert.State
	evLog  *evidence.Log
	// window is how close in time two alerts for one principal must be to
	// count as the same incident.
	window       time.Duration
	now          time.Time
	stateChanged bool
}

func newDeliverer(nf *notifyFlags, sender *alert.Sender, evLog *evidence.Log, window time.Duration, now time.Time) (*deliverer, error) {
	d := &deliverer{nf: nf, sender: sender, evLog: evLog, window: window, now: now}
	if *nf.statePath != "" {
		var err error
		if d.state, err = alert.LoadState(*nf.statePath); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// run delivers the items. code is 1 when a delivery or record failed; err is
// set only when nothing further should be attempted.
func (d *deliverer) run(items []alertItem, stderr io.Writer) (notes []notification, code int, err error) {
	for _, it := range items {
		a := it.alert
		a.EvidenceHash = it.findingRecord
		n := notification{Principal: a.Principal, First: a.First}
		if d.state != nil && it.confidence >= *d.nf.min {
			n.Verdict = d.state.Check(a, d.window, *d.nf.suppressFor, d.now)
			if n.Verdict == alert.VerdictEscalated || n.Verdict == alert.VerdictReminder {
				a.Update = string(n.Verdict)
			}
		}
		switch {
		case it.confidence < *d.nf.min:
			n.Status = "skipped_below_threshold"
		case n.Verdict == alert.VerdictDuplicate:
			n.Status = "suppressed_duplicate"
		case *d.nf.dryRun:
			payload, rerr := alert.Render(d.sender.Format, a)
			if rerr != nil {
				return notes, 1, rerr
			}
			n.Status, n.Payload = "dry_run", payload
		default:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			serr := d.sender.Send(ctx, a)
			cancel()
			if serr != nil {
				n.Status, n.Error = "failed", serr.Error()
				code = 1
			} else {
				n.Status = "sent"
				// Only delivered alerts are recorded, so a failed send is retried next run.
				if d.state != nil {
					d.state.Record(a, d.window, d.now)
					d.stateChanged = true
				}
			}
		}
		notes = append(notes, n)
		// Dry runs and skipped findings deliver nothing, so there is nothing to record.
		if d.evLog != nil && (n.Status == "sent" || n.Status == "failed" || n.Status == "suppressed_duplicate") {
			ne := incident.NotificationData{Format: d.sender.Format, Status: n.Status, Verdict: n.Verdict, Error: n.Error, FindingRecord: it.findingRecord}
			if _, aerr := d.evLog.Append(incident.KindNotification, a.IncidentID, ne, d.now); aerr != nil {
				fmt.Fprintln(stderr, aerr)
				code = 1
			}
		}
	}
	return notes, code, nil
}

// save writes the de-duplication state if any alert was delivered.
func (d *deliverer) save() error {
	if !d.stateChanged {
		return nil
	}
	return d.state.Save(*d.nf.statePath, d.now)
}

// lastFindingRecords maps each incident to its most recent record of the
// given kind, so an unchanged finding is not recorded again.
func lastFindingRecords(path, kind string) (map[string]evidence.Record, error) {
	records, _, err := evidence.ReadFile(path)
	if err != nil {
		return nil, err
	}
	last := map[string]evidence.Record{}
	for _, rec := range records {
		if rec.Kind == kind {
			last[rec.IncidentID] = rec
		}
	}
	return last, nil
}
