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
1. Telemetry adapters (planned): AWS CloudTrail and Bedrock metrics, host agent, Kubernetes events.
2. Normalizer and detector (planned): event aggregation, anomaly detection, cryptominer indicators.
3. **Policy engine (implemented)**: pure Go spending projection + risk gate.
4. Response orchestration (planned): notifications, approval workflows, reversible scoped containment.
5. Evidence store (planned): immutable incident records with sensitive fields redacted.

## Try the policy engine

Requires Go 1.22+.

```sh
go test ./...
go run ./cmd/cad -hourly-rate 25 -hours 24 -threshold 100 -confidence 90
```

This is a **simulation**, not a live billing feed. It prints a JSON decision and never calls cloud APIs or terminates anything. Default response mode is alert-only; `-allow-containment` opts into a *recommendation* only, not execution.

## Roadmap

- [x] Initial Go module and tested policy evaluator
- [x] Safe CLI simulation
- [ ] AWS Bedrock token-cost estimation and pricing-version tracking
- [ ] CloudTrail adapter with event replay tests
- [ ] Slack/webhook alert integration
- [ ] Host runtime cryptojacking indicators
- [ ] Kubernetes integration
- [ ] Auditable approval and containment orchestration
- [ ] Azure and GCP integrations

## Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Reports of security issues should be handled privately. This project is licensed under [Apache 2.0](LICENSE).
