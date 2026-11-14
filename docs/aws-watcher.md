# Read-only CloudTrail polling

`cad-watch` is a separate Go binary that periodically calls the AWS CLI
`cloudtrail lookup-events` API, converts returned events into the CloudTrail
`Records` envelope, and invokes the existing `cad detect` command. It never
changes anything in AWS.

## Build

```sh
make build
aws sts get-caller-identity
./bin/cad-watch -once -region us-east-1 -cad ./bin/cad
```

Continuous mode (polls every five minutes):

```sh
CAD_WEBHOOK_URL='https://hooks.slack.com/services/...' ./bin/cad-watch -region us-east-1 -cad ./bin/cad \
  -interval 5m -lookback 15m -correlate 2h \
  -notify slack -alert-state ./alerts-state.json \
  -evidence-log ./cad-evidence.jsonl \
  -ec2-pricing ./ec2-pricing.json -allow-containment
```

Use a persistent, access-controlled directory for the state and evidence
files. Run only one watcher per state file and evidence log.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-region` | required | AWS region to poll |
| `-interval` | 5m | time between polls (at least 1m) |
| `-lookback` | 15m | how far back each poll reads, overlapping the previous one |
| `-correlate` | 2h | how long events stay in memory, so activity spanning several polls is scored as one finding |
| `-once` | off | poll once and exit; exit status 1 if the poll or the detector failed |
| `-cad` | `cad` | path to the detector binary |

These are passed through to `cad detect`: `-notify`, `-alert-state`,
`-evidence-log`, `-usage`, `-pricing`, `-ec2-pricing`, `-suppressions`,
`-allow-containment`, `-approvals-required`, `-require-signed-approvals` and
`-config`. Any other detector setting (`-window`, `-threshold`,
`-notify-min-confidence`, ...) goes in the `-config` file.

`-notify` requires `-alert-state`: every poll re-scores the events still in
memory, so without de-duplication the same alert would be sent on every poll.

## How polling works

- Each poll reads the last `-lookback` and merges the events into an
  in-memory buffer keyed by event ID, so overlapping polls don't duplicate
  events. The detector runs over the whole buffer.
- Events older than `-correlate` are dropped. The buffer holds at most
  50,000 events, keeping the newest.
- After failed polls, the next successful one reads from the last good poll
  (minus the lookback), up to the `-correlate` horizon, so a short outage
  doesn't leave a gap.
- A finding that hasn't changed since the last poll isn't recorded again in
  the evidence log, so approvals made on it stay valid.
- SIGINT and SIGTERM stop the watcher cleanly. The buffer is in memory only:
  after a restart it refills from the first lookback window.

## Least-privilege permissions

Use a dedicated AWS CLI profile or a role with only the permissions below
for the polled region:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["cloudtrail:LookupEvents"],
    "Resource": "*"
  }]
}
```

The AWS CLI handles credentials externally. No credentials are stored by
Cloud Abuse Defender, and subprocesses are invoked without a shell.

## Important limitations

- **Management events only**: `LookupEvents` doesn't provide Bedrock
  invocation or token counts. Bedrock spend still needs the CloudWatch
  metrics workflow in the README; the watcher prices EC2 launches only.
- CloudTrail delivery is not instantaneous (typically a few minutes); the
  overlapping lookback helps but does not guarantee zero gaps.
- **Single region**: start a separate process for each region, each with
  its own alert-state file. They can't correlate with each other.
- An outage longer than `-correlate` is not backfilled.
- `LookupEvents` is rate-limited by AWS; keep `-interval` at a few minutes.
- Temporary event files are readable by their owner only and are removed
  after each detector run; treat process output and alerts as sensitive.
- Start in alert-only mode and validate detector scoring on your
  environment before using findings for response decisions.
