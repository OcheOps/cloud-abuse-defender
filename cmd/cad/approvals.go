package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/evidence"
	"github.com/OcheOps/cloud-abuse-defender/internal/incident"
)

const operatorsHelp = "trusted operators file (names and public keys); needed for incidents that require signed approvals"

// reviewer loads the trusted operators file, if one was given.
func reviewer(operatorsPath string) (incident.Reviewer, error) {
	if operatorsPath == "" {
		return incident.Reviewer{}, nil
	}
	ops, err := loadFile(operatorsPath, incident.LoadOperators)
	return incident.Reviewer{Operators: ops}, err
}

func runApprovals(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("cad approvals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("evidence-log", "", "evidence log written by 'cad detect -evidence-log'; required")
	id := fs.String("incident", "", "show only this incident")
	operatorsPath := fs.String("operators", "", operatorsHelp)
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-evidence-log is required")
		return 2
	}
	rv, err := reviewer(*operatorsPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	records, _, err := evidence.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *id != "" {
		s, err := rv.StatusOf(records, *id, now)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return encode(stdout, stderr, s)
	}
	all, err := rv.Summarize(records, now)
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
	operator := fs.String("operator", "", "name of the operator making the decision; required unless -key is given")
	reason := fs.String("reason", "", "why; required")
	operatorsPath := fs.String("operators", "", operatorsHelp)
	var principal, action, keyPath *string
	var ttl *time.Duration
	if kind == "approve" {
		principal = fs.String("principal", "", "the incident's principal ARN, typed out to confirm the target; required")
		action = fs.String("action", "", "reversible action to authorise: deactivate-access-keys or attach-deny-all-policy; required")
		ttl = fs.Duration("expires", 0, "how long the approval stays valid (at most 24h); required")
		keyPath = fs.String("key", "", "operator's private key file from 'cad keygen'; signs the approval")
	}
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *path == "" || *id == "" {
		fmt.Fprintln(stderr, "-evidence-log and -incident are required")
		return 2
	}
	rv, err := reviewer(*operatorsPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var signer ed25519.PrivateKey
	if keyPath != nil && *keyPath != "" {
		var keyOperator string
		f, err := os.Open(*keyPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		keyOperator, signer, err = incident.LoadKey(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", *keyPath, err)
			return 2
		}
		if *operator != "" && *operator != keyOperator {
			fmt.Fprintf(stderr, "-operator %q does not match the key's operator %q\n", *operator, keyOperator)
			return 2
		}
		*operator = keyOperator
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
		data, err = rv.Approve(records, incident.ApproveRequest{Decider: d, IncidentID: *id, Principal: *principal, Action: act, TTL: *ttl, Signer: signer}, now)
	case "reject":
		recordKind = incident.KindRejection
		data, err = rv.Reject(records, *id, d, now)
	default:
		recordKind = incident.KindRevocation
		data, err = rv.Revoke(records, *id, d, now)
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
	status, err := rv.StatusOf(append(records, rec), *id, now)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return encode(stdout, stderr, decisionOutput{Record: rec, Status: status})
}

// runKeygen creates an operator signing key. The private key goes to a new
// owner-only file and is never printed; the public entry goes to stdout.
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cad keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	operator := fs.String("operator", "", "operator name the key belongs to; required")
	out := fs.String("out", "", "file to write the private key to; must not exist; required")
	if _, ok := parseFlags(fs, args, stderr); !ok {
		return 2
	}
	if *operator == "" || *out == "" {
		fmt.Fprintln(stderr, "-operator and -out are required")
		return 2
	}
	key, entry, err := incident.GenerateKey(*operator)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	raw, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// O_EXCL: never overwrite an existing key.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	_, werr := f.Write(append(raw, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintln(stderr, werr)
		return 1
	}
	return encode(stdout, stderr, entry)
}
