# Cloud Abuse Defender

Open-source, cost-aware cloud threat detection and incident response.

> **Status:** early prototype. Not production-ready. It reads logs and metrics and sends alerts; it has no ability to change or terminate cloud resources. The only AWS access is the optional read-only `cad-watch` poller, through your own AWS CLI.

## Why

Stolen cloud credentials and cryptojacking can turn a security incident into a huge bill. Cloud Abuse Defender aims to correlate suspicious activity with **estimated future financial exposure**, alert operators first, and make containment an explicit, auditable policy decision.

## Principles

- **Alert first**: observability and notifications are the default.
- **Containment is opt-in**: financial risk alone must never terminate a workload.
- **Two signals**: require both sufficient security confidence and projected loss.
- **Least disruptive response**: prefer reversible, scoped controls over deleting infrastructure.
- **Explainable decisions**: record why a decision was reached, inputs and policy version.
- **No secrets**: read-only integration privileges wherever possible; never store cloud keys.
- **Conservative forecasts**: cloud billing has latency; projected costs are estimates.

## Architecture

See [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).

Initial components:
1. Telemetry adapters: **AWS CloudTrail log replay, live CloudTrail polling (`cad-watch`), Bedrock CloudWatch metrics conversion and Linux host snapshots (implemented)**; Kubernetes events planned.
2. **Detector (implemented)**: correlates CloudTrail indicators per principal into scored, explainable findings, following identities an attacker creates, with reviewed suppression rules for known workloads. Anomaly baselines are planned.
3. **Policy engine (implemented)**: pure Go spending projection + risk gate.
   **Cost estimators (implemented)**: price Bedrock token usage and EC2 instance launches with versioned pricing tables, and flag unreliable forecasts.
4. Response orchestration: **Slack/webhook alerts and the operator approval workflow with optional signed approvals (implemented)**; executing reversible scoped containment is planned and disabled by design.
5. **Evidence store (implemented)**: tamper-evident, hash-chained incident records with the policy and weight versions behind each decision.

## Install

Requires Go 1.22+. There are no dependencies outside the standard library.

```sh
make build          # writes bin/cad and bin/cad-watch
./bin/cad help      # lists every command
```

Tagged releases publish Linux and macOS binaries with checksums on the GitHub releases page. A `Dockerfile` builds an image containing only the offline `cad` analyser:

```sh
docker build -t cad .
docker run --rm -v "$PWD:/data:ro" cad detect -file /data/trail.json.gz
```

Any command that takes many flags can read them from a JSON file with `-config`, for example `{"notify": "slack", "ec2-pricing": "ec2-pricing.json", "window": "2h"}`. Flags on the command line win, and an unknown name in the file is an error, so a typo can't silently leave a setting at its default.

## Try the policy engine

```sh
go test ./...
go run ./cmd/cad -hourly-rate 25 -hours 24 -threshold 100 -confidence 90
```

This is a **simulation**, not a live billing feed. It prints a JSON decision and never calls cloud APIs or terminates anything. Default response mode is alert-only; `-allow-containment` opts into a *recommendation* only, not execution. `-threshold` and `-min-confidence` must be greater than zero, so neither gate can be disabled by accident.

### Estimate the rate from Bedrock usage

Instead of supplying `-hourly-rate` by hand, give the CLI a token-usage observation and a versioned pricing table:

```sh
go run ./cmd/cad -usage examples/usage.example.json -pricing examples/pricing.example.json -allow-containment
```

The output contains the `estimate` (per-model cost, observed cost, hourly rate and `pricing_version`) and the `decision`. The prices in `examples/pricing.example.json` are **illustrative placeholders**: replace them with current rates for your region from AWS before relying on the result.

The forecast is flagged as unreliable, and the decision drops to **alert-only**, when:
- the pricing table is older than `-max-pricing-age` (default 30 days) or not yet in effect,
- usage includes a model with no price in the table, or
- the observation window is shorter than `-min-window` (default 15 minutes).

#### Build the usage file from CloudWatch

`cad` never calls AWS or touches credentials. Instead, it writes the queries, you fetch the metrics with your own AWS CLI, and `cad` converts the result:

```sh
# 1. Find the models with token metrics (or skip and pass -models a,b directly)
aws cloudwatch list-metrics --namespace AWS/Bedrock --metric-name InputTokenCount --region us-east-1 > list-metrics.json
go run ./cmd/cad bedrock-queries -list-metrics list-metrics.json > queries.json

# 2. Fetch input/output token sums for the window
aws cloudwatch get-metric-data --metric-data-queries file://queries.json \
  --start-time 2026-11-04T10:00:00Z --end-time 2026-11-04T10:30:00Z --region us-east-1 > results.json

# 3. Convert, using the same region and times
go run ./cmd/cad bedrock-usage -results results.json -region us-east-1 \
  -start 2026-11-04T10:00:00Z -end 2026-11-04T10:30:00Z > usage.json
```

`usage.json` then goes to `-usage` as above. The AWS identity only needs this read-only policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": ["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"], "Resource": "*" }]
}
```

The conversion refuses to guess:
- it rejects results whose `StatusCode` isn't `Complete`, because partial data would understate spend;
- it rejects datapoints outside `-start`/`-end`, which catches times that don't match the AWS CLI call;
- it rejects series it didn't label, since each query's `Label` (`cad:<metric>:<model>`) is how it knows which model a series belongs to.

Paginated output with repeated series is summed. One query file covers up to 250 models.

Usage in one region can't be priced with another region's table. Only on-demand token pricing is modelled; provisioned throughput, batch discounts and private pricing are not.

### Price EC2 launches

Cryptojacking costs instance-hours, not tokens. Give the detector a versioned EC2 price table and each finding gets its own forecast from the instances it launched:

```sh
go run ./cmd/cad detect -file internal/cloudtrail/testdata/attack_cryptojacking_quiet.json \
  -ec2-pricing examples/ec2-pricing.example.json -allow-containment
```

On that fixture the 30 GPU instances across three regions come to $145/hour, $3,480 over 24 hours. As with Bedrock, the prices in `examples/ec2-pricing.example.json` are **illustrative placeholders** to replace with your own on-demand rates.

- Only successful `RunInstances` calls inside the finding are priced; denied launches are not.
- The estimate assumes every launched instance keeps running, so it is a ceiling. Instances that were later stopped still count. Spot, Savings Plans, storage and data transfer aren't modelled, and neither are ECS, Batch or SageMaker launches.
- An instance type or region missing from the table, or a table older than `-max-pricing-age`, makes the decision **alert-only**.
- With `-usage`/`-pricing` as well, the Bedrock and EC2 rates are added together.

### Replay a CloudTrail log

```sh
go run ./cmd/cad cloudtrail -file internal/cloudtrail/testdata/incident.json -only-indicators
```

This reads a CloudTrail log file in the S3 delivery format (`{"Records": [...]}`, `.json` or `.json.gz`) **offline**. It makes no AWS calls. Each record becomes a minimal event: raw request and response payloads are dropped and access key IDs are masked (`AKIA************MPLE`). Events are tagged with explainable indicators:

| Indicator | Trigger |
|---|---|
| `gpu_instance_launch` | `ec2:RunInstances` for an accelerated family (`p`, `g`, `inf`, `trn`, `dl`) |
| `bulk_instance_launch` | one `RunInstances` call requesting 10 or more instances |
| `quota_increase_request` | `servicequotas:RequestServiceQuotaIncrease` |
| `monitoring_tampering` | CloudTrail `StopLogging`/`DeleteTrail`/`UpdateTrail`/`PutEventSelectors`, GuardDuty `DeleteDetector`/`UpdateDetector` |
| `bedrock_logging_disabled` | `bedrock:DeleteModelInvocationLoggingConfiguration` |
| `bedrock_model_access_change` | Bedrock model-access requests (`PutUseCaseForModelAccess`, `CreateFoundationModelAgreement`, `PutFoundationModelEntitlement`) |
| `credential_creation` | IAM `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile` |
| `access_denied` | `AccessDenied`, `AccessDeniedException` or `UnauthorizedOperation` errors |
| `root_activity` | calls made directly by the root user |
| `alternate_compute_launch` | compute started through ECS (`RunTask`, `CreateService`), Batch, SageMaker or Lambda instead of EC2 |
| `privilege_escalation` | `AdministratorAccess` attached to a user, role or group |

SageMaker notebook and training-job GPU types (`ml.p…`, `ml.g…`) also count as `gpu_instance_launch`. For credential-creating IAM calls the target user name is kept, so the detector can follow identities an attacker creates.

Indicators are signals for a future detector to weigh, not verdicts: each one alone is often legitimate. Replay fixtures live in `internal/cloudtrail/testdata/`. Each `*.json` log has a `.golden` file holding the expected output; after an intended change, regenerate them with `go test ./internal/cloudtrail -update`.

### Detect and decide end to end

```sh
go run ./cmd/cad detect -file internal/cloudtrail/testdata/incident.json \
  -usage examples/usage.example.json -pricing examples/pricing.example.json -allow-containment
```

`cad detect` groups a CloudTrail log's indicator events by principal, starting a new finding wherever a principal goes quiet for longer than `-window` (default 1h). Each finding gets a confidence from a noisy-OR over its evidence, `100 × (1 − Π(1 − wᵢ))`:

- each **distinct** indicator adds its weight once, so repeating it doesn't stack (weights are in `internal/detect`);
- attack chains add weight when signals appear together: `cryptojacking_chain` (GPU launch + quota increase or bulk launch), `llmjacking_chain` (Bedrock logging removed + model-access change) and `evasion_with_resource_abuse` (CloudTrail/GuardDuty tampering + GPU, bulk or Bedrock activity);
- `enumeration_burst` applies at 5 or more access-denied events, and `multi_region_gpu_launch` when GPU instances are launched in 3 or more regions;
- `privilege_escalation_with_new_credentials` applies when an administrator policy is attached and credentials are created;
- `created_identity_activity` applies when a finding includes activity by an identity the principal created (see below).

**Created identities are followed.** Attackers often create a fresh IAM user, or a new access key for an existing one, and switch to it, which would split their activity into two weak findings. When a principal successfully creates a user or issues credentials for one, that user's later activity is counted in the creator's finding and listed under `linked_principals`. On the `attack_identity_pivot` fixture this turns two findings of 68.8 and 80.4, both below the containment threshold, into one of 96.0.

Every contributor is listed with its weight and the event IDs behind it. With a cost source (`-usage`/`-pricing`, or an explicit `-hourly-rate`), each finding also gets a policy `decision`; without one, only findings are printed. On the sample incident the `ci-deploy` user scores 98.6 and is eligible for containment, while the separate root activity scores 36 and stays alert-only.

#### Tuning fixtures

The weights are tuned against synthetic replay fixtures in `internal/cloudtrail/testdata/`, scored at the default thresholds: alert at 50, containment eligible at 85.

| Fixture | Scenario | Score | Band |
|---|---|---|---|
| `benign_ci_deploy` | CI role deploys a stack and two `m6i` instances | none | no finding |
| `benign_autoscaling_scaleout` | Auto Scaling launches 12 instances, twice | 25.0 | below alert |
| `benign_ml_single_gpu` | researcher starts one `g5.xlarge` | 30.0 | below alert |
| `benign_admin_onboarding` | admin creates a user and login, hits 2 denials, raises a vCPU quota | 42.4 | below alert |
| `benign_trail_maintenance` | security engineer changes trail event selectors | 45.0 | below alert |
| `benign_gpu_training_job` | quota increase, then 4 × `p4d.24xlarge` in one region | 72.0 | **alert only** |
| `attack_key_enumeration` | old key probes 8 services, all denied | 50.5 | alert only |
| `attack_cryptojacking_quiet` | quota increase, 30 GPU instances across 3 regions, no evasion | 87.4 | containment eligible |
| `attack_llmjacking` | probing, Bedrock logging deleted, model access requested | 88.9 | containment eligible |
| `attack_identity_pivot` | stolen key creates an admin user, which stops logging and launches ECS tasks and GPUs | 96.0 | containment eligible |
| `incident` | combined LLMjacking + cryptojacking + `StopLogging` | 98.6 | containment eligible |

Known limits:
- **A real GPU training job looks like the start of mining.** In CloudTrail alone it scores 72 and alerts. That's deliberate: a human confirms, and it can never reach containment. Mining across 3 or more regions is what pushes the attack fixture past 85.
- **Change to a trail's configuration scores 45**, just under the alert threshold. Alerting on every trail edit would be noisy, but tampering together with resource abuse is still caught by `evasion_with_resource_abuse`.
- The fixtures are synthetic. Add replays of your own normal activity before relying on the scores.

`TestFixtureBands` in `internal/detect` fails if any fixture changes band or has no expected band, so weight changes have to be deliberate. To add a fixture, put the log in `testdata/`, give it a band in `fixtureBands`, and run `go test ./internal/cloudtrail -update` to create its golden file.

#### Suppress known workloads

A legitimate workload that keeps triggering the same indicators, like the GPU training job above, can be suppressed with a reviewed rule file:

```json
{
  "version": "2026-11-13",
  "rules": [{
    "principal": "arn:aws:iam::123456789012:user/ml-platform",
    "indicators": ["gpu_instance_launch", "quota_increase_request"],
    "reason": "ML platform trains on GPUs; reviewed by security 2026-11-13",
    "expires": "2027-02-01T00:00:00Z"
  }]
}
```

```sh
go run ./cmd/cad detect -file trail.json.gz -suppressions suppressions.json
```

Rules are narrow on purpose, because a suppressed principal is exactly what an attacker who compromises it would hide behind:
- each rule must list its indicators, give a reason and have an expiry; expired rules stop applying and are reported;
- `principal` may use `*`, but not on its own;
- `monitoring_tampering` and `bedrock_logging_disabled` can never be suppressed;
- everything removed is listed under `suppressed` in the output, and the rule file's version is stored in the evidence record.

### Send alerts

Preview the payloads without sending anything:

```sh
go run ./cmd/cad detect -file internal/cloudtrail/testdata/incident.json -notify slack -notify-dry-run
```

To deliver, put the webhook URL in `CAD_WEBHOOK_URL` and choose a format:

```sh
CAD_WEBHOOK_URL='https://hooks.slack.com/services/...' go run ./cmd/cad detect -file trail.json.gz -notify slack
```

- `-notify slack` posts a Slack incoming-webhook message; `-notify webhook` posts the generic JSON schema `cad.alert.v1`.
- Only findings at or above `-notify-min-confidence` (default 50) are sent; the rest are listed as `skipped_below_threshold`.
- The URL is read **only** from the environment, because flags end up in shell history and process lists. It must be `https`, and it is never printed, including in error messages.
- Alerts include the principal, accounts, regions, time range, confidence, evidence names and weights, and the policy decision. Source IPs, user agents, access key IDs and event IDs stay out of third-party chat tools.
- 429 and 5xx responses are retried up to 3 times with backoff; other errors fail immediately.
- If any delivery fails, findings are still printed, each notification's status is in the output, and the command exits 1.

Alerts are informational: every message says no action has been taken and containment needs operator approval.

#### De-duplication

Add `-alert-state <file>` so repeated runs over the same or overlapping logs don't re-send alerts:

```sh
CAD_WEBHOOK_URL='https://hooks.slack.com/services/...' go run ./cmd/cad detect -file trail.json.gz -notify slack -alert-state cad-alert-state.json
```

A finding matches an earlier alert when it's the same principal and the time ranges overlap or are within `-window` of each other, so a longer replay of the same incident still matches. Each matching finding gets a `verdict`:

| Verdict | When | Result |
|---|---|---|
| `new` | no earlier alert covers it | sent |
| `escalated` | confidence rose, or the policy decision changed | sent, titled "Escalated:" |
| `reminder` | unchanged, but the last send is older than `-alert-suppress-for` (default 24h) | sent, titled "Reminder:" |
| `duplicate` | unchanged and recent | not sent (`suppressed_duplicate`) |

Only delivered alerts are recorded, so a failed send is retried on the next run, and dry runs never write the file. The file is written atomically with `0600` permissions, keeps 30 days of history, and contains principal ARNs, so treat it as sensitive. A corrupt state file stops the run instead of being silently reset. It assumes one writer at a time: two runs sharing a file at once may both send.

### Keep an evidence log

```sh
go run ./cmd/cad detect -file trail.json.gz -usage usage.json -pricing pricing.json \
  -notify slack -alert-state cad-alert-state.json -evidence-log cad-evidence.jsonl
go run ./cmd/cad evidence-verify -file cad-evidence.jsonl
```

`-evidence-log` appends one JSON line per finding, and one per delivery attempt (sent, failed or suppressed; dry runs and skipped findings aren't recorded). Finding records hold everything needed to explain the decision later:
- the full finding, including contributors and event IDs;
- the policy decision, pricing version, hourly rate and forecast warnings;
- `policy_version` and `weights_version`.

Each record includes the SHA-256 hash of the record before it, so editing, deleting, inserting or reordering any record breaks the chain at that point. Verification also requires every line to be byte-for-byte what was written, so even a change that keeps a record's meaning, such as altered whitespace, is caught. `cad detect` won't append to a log that fails verification, and it doesn't re-record a finding that hasn't changed since the last run, so running it repeatedly over the same events doesn't reset approvals.

The chain is tamper-evident, not tamper-proof: anyone who can write the file could rebuild it from scratch or drop the newest records. To catch that, every alert carries its `incident_id` and the `evidence_hash` of the record behind it, which puts a copy of the chain's state in Slack or your webhook receiver. Check a hash you kept with:

```sh
go run ./cmd/cad evidence-verify -file cad-evidence.jsonl -expect-record <evidence_hash>
```

The log contains principal ARNs, source IPs and event IDs, is written `0600`, and assumes one writer at a time.

### Approve or reject containment

Approvals are **recorded decisions, not actions**: nothing in this project executes containment. They live in the evidence log, so every decision is part of the verified chain.

```sh
# Run detection with a cost source and -allow-containment so eligible findings are marked
go run ./cmd/cad detect -file trail.json.gz -usage usage.json -pricing pricing.json -allow-containment -evidence-log cad-evidence.jsonl

go run ./cmd/cad approvals -evidence-log cad-evidence.jsonl
go run ./cmd/cad approve -evidence-log cad-evidence.jsonl -incident inc_... \
  -principal arn:aws:iam::123456789012:user/ci-deploy -action deactivate-access-keys \
  -expires 4h -operator alice -reason "confirmed stolen key, owner unreachable"
go run ./cmd/cad revoke -evidence-log cad-evidence.jsonl -incident inc_... -operator alice -reason "key rotated by owner"
go run ./cmd/cad reject -evidence-log cad-evidence.jsonl -incident inc_... -operator alice -reason "scheduled load test"
```

Rules enforced:
- Only a finding the policy marked **containment eligible** can be approved or rejected; approval is never inferred from a score.
- `-principal` must repeat the incident's principal exactly, so a mistyped incident ID can't approve the wrong target.
- Only reversible actions scoped to that principal are offered: `deactivate-access-keys` and `attach-deny-all-policy`.
- Every decision needs an operator name and a reason, and approvals expire after `-expires`, at most 24h.
- **Two-person rule:** an incident is `approved` only once enough *distinct* operators have approved the same action on the same finding; until then it is `partially_approved`. The number needed is fixed in the finding record at detection time with `cad detect -approvals-required` (default 2, range 1–5), so approvers can't lower it. A second approval is refused if it uses an operator name already in the round, or comes from an OS account already in the round.
- The quorum expires with its **earliest** approval. An approval that arrives after that starts a fresh round rather than completing the old one.
- **One operator can stop it:** any single operator can reject a pending or partially approved incident, or revoke an approval round, complete or not.
- Decisions bind to one finding record. If a later run records a newer finding for the incident, it returns to `pending` for a fresh decision.
- A complete approval can't be approved again or rejected; revoke it first.
- Decisions are refused on a log that fails verification, or one that changed while the decision was being checked.

`cad approvals` reports each incident as `not_eligible`, `pending`, `partially_approved`, `approved`, `rejected`, `expired` or `revoked`, with the required count and the approvals so far.

By default identity is **not authenticated**: `operator` is what was typed, and `recorded_by` is the local OS account that ran the command. The distinct-account check stops one person approving twice from the same login, but someone with two accounts, or write access to the log, could still satisfy the quorum alone. `-approvals-required 1` turns the two-person rule off for single-operator teams; that choice is recorded in each finding.

#### Signed approvals

To make operator identity real, give each operator an Ed25519 key and require signatures:

```sh
# Each operator, once. The private key goes to a new owner-only file and is never printed.
go run ./cmd/cad keygen -operator alice -out alice.key > alice.pub.json

# Collect the printed entries into operators.json: {"operators": [{"name": "alice", "public_key": "..."}, ...]}

# Require signatures for findings recorded from now on
go run ./cmd/cad detect -file trail.json.gz -ec2-pricing ec2-pricing.json -allow-containment \
  -evidence-log cad-evidence.jsonl -require-signed-approvals

go run ./cmd/cad approve -evidence-log cad-evidence.jsonl -incident inc_... -principal arn:... \
  -action deactivate-access-keys -expires 4h -reason "confirmed stolen key" \
  -key alice.key -operators operators.json
go run ./cmd/cad approvals -evidence-log cad-evidence.jsonl -operators operators.json
```

- Like the quorum, the requirement is fixed in the finding record at detection time, so approvers can't turn it off.
- An approval counts only if its signature verifies against the trusted key for the operator it names. The signature covers the action, principal, finding record, expiry, operator and reason, so none of them can be changed afterwards.
- Unsigned, forged, reused or altered approvals are ignored and reported as `unverified_approvals`. Without `-operators`, nothing verifies and the incident stays `pending`.
- Rejecting and revoking never need a key: stopping stays easy.

Protect `operators.json` like the approvals themselves: whoever can edit it decides who is trusted. Keep it somewhere the people running `cad approve` can't write, such as a repository with required reviews.

### Scan a Linux host for cryptominers

```sh
go run ./cmd/cad host-snapshot > snapshot.json     # run on the host; root sees every process
go run ./cmd/cad host-scan -file snapshot.json -min-confidence 50
```

`host-snapshot` only **reads** `/proc`. It records each process's name, executable, command line, owner and CPU use over a 2-second sample (`-sample`), plus outbound TCP connections from `/proc/net/tcp{,6}`. It never signals or changes a process. Values that look like secrets (`--password=…`, `--token x`, `-p x`, `API_KEY=…`, `user:pass@` in URLs) are masked before the snapshot is written. Run it as root to see every process; without root, other users' executables and connections are left out.

`host-scan` scores each process with the same noisy-OR method as the CloudTrail detector:

| Indicator | Weight | Trigger |
|---|---|---|
| `stratum_url` | 0.80 | `stratum+tcp://` or `stratum+ssl://` on the command line |
| `miner_process_name` | 0.70 | known miner names (xmrig, kdevtmpfsi, kinsing, t-rex, lolminer, …) |
| `miner_arguments` | 0.50 | `--donate-level`, `--randomx…`, `--cpu-max-threads-hint`, or `-a`/`--algo` with a mining algorithm |
| `mining_pool_domain` | 0.50 | well-known pool domains on the command line |
| `mining_pool_port` | 0.35 | a connection to a common pool port (3333, 4444, 5555, 7777, 14433, 14444, …) |
| `deleted_executable` | 0.30 | the binary was deleted after starting |
| `temp_dir_executable` | 0.30 | runs from `/tmp`, `/dev/shm` or `/var/tmp` |
| `high_cpu` | 0.15 | 90% or more of one core |

Tuning fixtures in `internal/host/testdata/`:

| Fixture | Top score |
|---|---|
| `benign_web_server` (nginx, postgres, node) | no finding |
| `benign_ml_training` (python at 780% CPU) | 15.0 |
| `benign_go_build` (test binary from `/tmp` at high CPU) | 40.5 |
| `attack_renamed_miner` (`/dev/shm/.kworkerds` to supportxmr) | 85.1 |
| `attack_kinsing` (`kdevtmpfsi` in `/tmp` to port 4444) | 88.4 |
| `attack_xmrig` (deleted `/tmp/.x/xmrig`, stratum to port 3333) | 99.2 |

Generic signals are weighted low on purpose: builds run from `/tmp` and package upgrades leave deleted binaries running, so neither alone reaches the alert threshold of 50. A test locks the scores, and another fails if the weights change without bumping `host.WeightsVersion`. `host-scan` takes the same `-notify`, `-alert-state` and `-evidence-log` flags as `detect`. Host alerts carry the host, process name, PID and indicator names; the command line and executable path stay in the scan output and evidence log.

### Watch CloudTrail continuously

`cad-watch` polls CloudTrail through the AWS CLI with a read-only `cloudtrail:LookupEvents` permission and runs the detector on what it finds:

```sh
CAD_WEBHOOK_URL='https://hooks.slack.com/services/...' ./bin/cad-watch -region us-east-1 -cad ./bin/cad \
  -notify slack -alert-state cad-alert-state.json -evidence-log cad-evidence.jsonl \
  -ec2-pricing ec2-pricing.json -allow-containment
```

It keeps recent events in memory (`-correlate`, default 2h) so activity that spans several polls is scored together, reads the gap again after failed polls, and stops cleanly on SIGTERM. It never changes anything in AWS. See [docs/aws-watcher.md](docs/aws-watcher.md) for the IAM policy and limits.

## Roadmap

- [x] Initial Go module and tested policy evaluator
- [x] Safe CLI simulation
- [x] AWS Bedrock token-cost estimation and pricing-version tracking
- [x] Bedrock CloudWatch token metrics to usage conversion (via the AWS CLI; no direct API client)
- [x] CloudTrail adapter with event replay tests, and live polling with `cad-watch` (S3/EventBridge ingestion still planned)
- [x] Indicator correlation and confidence scoring (CloudTrail), following created identities, with suppression rules
- [x] EC2 launch cost forecasting
- [x] Slack/webhook alert integration with de-duplication
- [x] Host runtime cryptojacking indicators (Linux `/proc` snapshots) with alerts and evidence records
- [ ] Kubernetes integration
- [x] Auditable approval workflow: two-person rule and signed approvals
- [x] Releases: tagged binaries, Dockerfile, fuzzing and vulnerability checks in CI
- [ ] Containment execution (deliberately not built; approvals are records only)
- [ ] Azure and GCP integrations

## Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Reports of security issues should be handled privately. This project is licensed under [Apache 2.0](LICENSE).
