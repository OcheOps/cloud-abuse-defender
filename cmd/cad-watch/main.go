// cad-watch polls read-only AWS CloudTrail management events and invokes
// the offline cad detector. It cannot modify cloud resources.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/awswatch"
)

func main() {
	// SIGTERM is what systemd, Docker and Kubernetes send to stop a process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, realDeps()))
}

// deps are the watcher's side effects, replaced in tests.
type deps struct {
	// fetch returns CloudTrail events in [start, end) as a Records envelope.
	fetch func(ctx context.Context, region string, start, end time.Time) ([]byte, int, error)
	// detect runs "cad detect" with the given arguments.
	detect func(ctx context.Context, cad string, args []string, stdout, stderr io.Writer) error
	now    func() time.Time
	// wait blocks for d and reports false if ctx ended first.
	wait func(ctx context.Context, d time.Duration) bool
}

func realDeps() deps {
	return deps{
		fetch: func(ctx context.Context, region string, start, end time.Time) ([]byte, int, error) {
			fetchCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			return awswatch.Fetch(fetchCtx, awswatch.CLI, region, start, end)
		},
		detect: func(ctx context.Context, cad string, args []string, stdout, stderr io.Writer) error {
			cmd := exec.CommandContext(ctx, cad, args...)
			cmd.Stdout, cmd.Stderr = stdout, stderr
			return cmd.Run()
		},
		now: time.Now,
		wait: func(ctx context.Context, d time.Duration) bool {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-timer.C:
				return true
			}
		},
	}
}

// maxBufferedEvents bounds memory use between polls.
const maxBufferedEvents = 50000

func run(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("cad-watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	region := fs.String("region", "", "AWS region (required)")
	interval := fs.Duration("interval", 5*time.Minute, "poll interval (min 1m)")
	lookback := fs.Duration("lookback", 15*time.Minute, "how far back each poll reads (min 1m); after failed polls the gap is read again")
	correlate := fs.Duration("correlate", 2*time.Hour, "how long events are kept in memory so activity spanning several polls is scored together (at least -lookback)")
	once := fs.Bool("once", false, "perform one read and exit")
	cad := fs.String("cad", "cad", "path to cad detector executable")
	// The remaining flags are passed through to "cad detect".
	state := fs.String("alert-state", "", "alert de-duplication file; required with -notify")
	notify := fs.String("notify", "", "notification format: slack or webhook")
	evidenceLog := fs.String("evidence-log", "", "tamper-evident evidence log to append findings and alerts to")
	usage := fs.String("usage", "", "Bedrock usage file (with -pricing)")
	pricing := fs.String("pricing", "", "Bedrock pricing table (with -usage)")
	ec2Pricing := fs.String("ec2-pricing", "", "EC2 pricing table; prices each finding's instance launches")
	suppressions := fs.String("suppressions", "", "suppression rules file")
	allow := fs.Bool("allow-containment", false, "let the policy recommend containment (never executes)")
	approvals := fs.Int("approvals-required", 0, "distinct operators who must approve containment (0 keeps the detector's default)")
	signed := fs.Bool("require-signed-approvals", false, "approvals only count when signed by a trusted operator key")
	config := fs.String("config", "", "JSON config file for cad detect; covers any detector flag not listed here")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case fs.NArg() != 0:
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	case *region == "":
		fmt.Fprintln(stderr, "-region is required")
		return 2
	case *interval < time.Minute || *lookback < time.Minute:
		fmt.Fprintln(stderr, "-interval and -lookback must be at least 1m")
		return 2
	case *correlate < *lookback:
		fmt.Fprintln(stderr, "-correlate must be at least -lookback")
		return 2
	case *notify != "" && *notify != "slack" && *notify != "webhook":
		fmt.Fprintln(stderr, "-notify must be slack or webhook")
		return 2
	case *notify != "" && *state == "":
		// Every poll re-scores the events still in memory; without a state
		// file the same alert would be sent on every poll.
		fmt.Fprintln(stderr, "-notify requires -alert-state, so repeated polls do not re-send the same alert")
		return 2
	case (*usage == "") != (*pricing == ""):
		fmt.Fprintln(stderr, "-usage and -pricing must be used together")
		return 2
	case *approvals < 0:
		fmt.Fprintln(stderr, "-approvals-required must not be negative")
		return 2
	}
	var passthrough []string
	add := func(name, value string) {
		if value != "" {
			passthrough = append(passthrough, name, value)
		}
	}
	add("-alert-state", *state)
	add("-notify", *notify)
	add("-evidence-log", *evidenceLog)
	add("-usage", *usage)
	add("-pricing", *pricing)
	add("-ec2-pricing", *ec2Pricing)
	add("-suppressions", *suppressions)
	add("-config", *config)
	if *allow {
		passthrough = append(passthrough, "-allow-containment")
	}
	if *approvals > 0 {
		passthrough = append(passthrough, "-approvals-required", strconv.Itoa(*approvals))
	}
	if *signed {
		passthrough = append(passthrough, "-require-signed-approvals")
	}

	buffer, err := awswatch.NewBuffer(*correlate, maxBufferedEvents)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var lastSuccess time.Time
	for {
		now := d.now().UTC()
		start := now.Add(-*lookback)
		// After failed polls, read again from the last good poll (with the
		// usual overlap) so the gap is not lost, up to what the buffer keeps.
		if !lastSuccess.IsZero() && lastSuccess.Add(-*lookback).Before(start) {
			start = lastSuccess.Add(-*lookback)
		}
		if floor := now.Add(-*correlate); start.Before(floor) {
			start = floor
		}
		failed := poll(ctx, d, buffer, *region, *cad, start, now, passthrough, stdout, stderr)
		if !failed {
			lastSuccess = now
		}
		if *once {
			if failed {
				return 1
			}
			return 0
		}
		if !d.wait(ctx, *interval) {
			return 0
		}
	}
}

// poll reads one window, merges it into the buffer and runs the detector
// over everything still buffered. It reports whether anything failed.
func poll(ctx context.Context, d deps, buffer *awswatch.Buffer, region, cad string, start, end time.Time, passthrough []string, stdout, stderr io.Writer) (failed bool) {
	data, _, err := d.fetch(ctx, region, start, end)
	if err != nil {
		fmt.Fprintf(stderr, "CloudTrail polling failed: %v\n", err)
		return true
	}
	if _, err := buffer.Add(data); err != nil {
		fmt.Fprintf(stderr, "CloudTrail events rejected: %v\n", err)
		return true
	}
	payload, n, err := buffer.Payload(end)
	if err != nil {
		fmt.Fprintf(stderr, "event buffer: %v\n", err)
		return true
	}
	if n == 0 {
		return false
	}
	// CreateTemp makes the file readable by its owner only.
	f, err := os.CreateTemp("", "cad-cloudtrail-*.json")
	if err != nil {
		fmt.Fprintf(stderr, "temporary file: %v\n", err)
		return true
	}
	path := f.Name()
	defer os.Remove(path)
	_, err = f.Write(payload)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintf(stderr, "write temporary event file: %v\n", err)
		return true
	}
	if err := d.detect(ctx, cad, append([]string{"detect", "-file", path}, passthrough...), stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "detector failed: %v\n", err)
		return true
	}
	return false
}
