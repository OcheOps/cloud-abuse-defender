# Cloud Abuse Defender

Open-source, cost-aware cloud threat detection and incident response.

> **Status:** early prototype. Not production-ready. No cloud API integrations or automatic resource termination are implemented yet.

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
1. Telemetry adapters: **AWS CloudTrail log replay (implemented, offline)**; Bedrock metrics ingestion, host agent and Kubernetes events planned.
2. **Detector (implemented)**: correlates CloudTrail indicators per principal into scored, explainable findings. Anomaly baselines and host cryptominer indicators are planned.
3. **Policy engine (implemented)**: pure Go spending projection + risk gate.
   **Bedrock cost estimator (implemented)**: prices observed token usage with a versioned pricing table and flags unreliable forecasts.
4. Response orchestration: **Slack/webhook alerts (implemented)**; approval workflows and reversible scoped containment planned.
5. Evidence store (planned): immutable incident records with sensitive fields redacted.

## Try the policy engine

Requires Go 1.22+.

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

Usage in one region can't be priced with another region's table. Only on-demand token pricing is modelled; provisioned throughput, batch discounts and private pricing are not.

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

Indicators are signals for a future detector to weigh, not verdicts: each one alone is often legitimate. Replay fixtures live in `internal/cloudtrail/testdata/`. Each `*.json` log has a `.golden` file holding the expected output; after an intended change, regenerate them with `go test ./internal/cloudtrail -update`.

### Detect and decide end to end

```sh
go run ./cmd/cad detect -file internal/cloudtrail/testdata/incident.json \
  -usage examples/usage.example.json -pricing examples/pricing.example.json -allow-containment
```

`cad detect` groups a CloudTrail log's indicator events by principal, starting a new finding wherever a principal goes quiet for longer than `-window` (default 1h). Each finding gets a confidence from a noisy-OR over its evidence, `100 × (1 − Π(1 − wᵢ))`:

- each **distinct** indicator adds its weight once, so repeating it doesn't stack (weights are in `internal/detect`);
- attack chains add weight when signals appear together: `cryptojacking_chain` (GPU launch + quota increase or bulk launch), `llmjacking_chain` (Bedrock logging removed + model-access change) and `evasion_with_resource_abuse` (CloudTrail/GuardDuty tampering + GPU, bulk or Bedrock activity);
- `enumeration_burst` applies at 5 or more access-denied events.

Every contributor is listed with its weight and the event IDs behind it. With a cost source (`-usage`/`-pricing`, or an explicit `-hourly-rate`), each finding also gets a policy `decision`; without one, only findings are printed. On the sample incident the `ci-deploy` user scores 98.6 and is eligible for containment, while the separate root activity scores 36 and stays alert-only.

The weights are starting estimates, not tuned on real incidents: review them against your own environment before relying on the scores.

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

Alerts are informational: every message says no action has been taken and containment needs operator approval. There is no de-duplication yet, so replaying the same log sends the same alerts again.

## Roadmap

- [x] Initial Go module and tested policy evaluator
- [x] Safe CLI simulation
- [x] AWS Bedrock token-cost estimation and pricing-version tracking (offline; CloudWatch metrics ingestion still planned)
- [x] CloudTrail adapter with event replay tests (offline log files; S3/EventBridge ingestion still planned)
- [x] Indicator correlation and confidence scoring (CloudTrail)
- [x] Slack/webhook alert integration (no de-duplication yet)
- [ ] Host runtime cryptojacking indicators
- [ ] Kubernetes integration
- [ ] Auditable approval and containment orchestration
- [ ] Azure and GCP integrations

## Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Reports of security issues should be handled privately. This project is licensed under [Apache 2.0](LICENSE).
