# Experimental read-only CloudTrail polling

`cad-watch` is a separate Go binary that periodically calls the AWS CLI
`cloudtrail lookup-events` API, converts returned events into the CloudTrail
`Records` envelope, and invokes the existing `cad detect` command.

## Build

```sh
go build -o bin/cad ./cmd/cad
go build -o bin/cad-watch ./cmd/cad-watch
aws sts get-caller-identity
./bin/cad-watch -once -region us-east-1 -cad ./bin/cad
```

Continuous mode (polls every five minutes):

```sh
./bin/cad-watch -region us-east-1 -cad ./bin/cad \
  -interval 5m -lookback 15m
```

Add `-notify slack -alert-state ./alerts-state.json` and set
`CAD_WEBHOOK_URL` in the environment to use the detector's existing Slack
alerting. Use a persistent, access-controlled directory for the state file.
Run only one watcher per state file. A watcher does **not** execute containment.

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
  invocation/token counts. This feature cannot detect all LLMjacking or forecast
  live Bedrock spend by itself; a separate near-real-time metrics adapter is
  still required.
- CloudTrail delivery is not instantaneous; an overlapping polling window
  helps but does not guarantee zero gaps.
- This initial version is **single-region**; start separate processes for
  additional regions, each with its own alert-state file.
- Cross-poll correlation isn't implemented: each polling batch is evaluated
  independently. Overlapping events can produce repeat findings.
- A failed lookup is logged and retried on the next interval, but the watcher
  doesn't checkpoint or backfill missed history automatically.
- Temporary events files have OS-private permissions and are removed after
  detection; treat process output and alerts as security-sensitive.
- Start in alert-only mode and validate detector scoring on your environment
  before using findings for response decisions.
