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
	"time"

	"github.com/OcheOps/cloud-abuse-defender/internal/awswatch"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("cad-watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	region := fs.String("region", "", "AWS region (required)")
	interval := fs.Duration("interval", 5*time.Minute, "poll interval (min 1m)")
	lookback := fs.Duration("lookback", 15*time.Minute, "event lookback window (min 1m)")
	once := fs.Bool("once", false, "perform one read and exit")
	cad := fs.String("cad", "cad", "path to cad detector executable")
	state := fs.String("alert-state", "", "optional alert deduplication file")
	notify := fs.String("notify", "", "optional notification format: slack or webhook")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *region == "" || *interval < time.Minute || *lookback < time.Minute || (*notify != "" && *notify != "slack" && *notify != "webhook") {
		fmt.Fprintln(stderr, "-region required; -interval/-lookback >=1m; -notify slack|webhook")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	for {
		now := time.Now().UTC()
		fetchCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		data, n, err := awswatch.Fetch(fetchCtx, awswatch.CLI, *region, now.Add(-*lookback), now)
		cancel()
		failed := false
		if err != nil {
			fmt.Fprintf(stderr, "CloudTrail polling failed: %v\n", err)
			failed = true
		} else if n > 0 {
			f, e := os.CreateTemp("", "cad-cloudtrail-*.json")
			if e != nil {
				fmt.Fprintf(stderr, "temporary file: %v\n", e)
				failed = true
			} else {
				path := f.Name()
				_, e = f.Write(data)
				if closeErr := f.Close(); e == nil {
					e = closeErr
				}
				if e != nil {
					fmt.Fprintf(stderr, "write temporary event file: %v\n", e)
					failed = true
				} else {
					detectArgs := []string{"detect", "-file", path}
					if *state != "" {
						detectArgs = append(detectArgs, "-alert-state", *state)
					}
					if *notify != "" {
						detectArgs = append(detectArgs, "-notify", *notify)
					}
					cmd := exec.CommandContext(ctx, *cad, detectArgs...)
					cmd.Stdout = os.Stdout
					cmd.Stderr = stderr
					if e := cmd.Run(); e != nil {
						fmt.Fprintf(stderr, "detector failed: %v\n", e)
						failed = true
					}
				}
				os.Remove(path)
			}
		}
		if *once {
			if failed {
				return 1
			}
			return 0
		}
		timer := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}
