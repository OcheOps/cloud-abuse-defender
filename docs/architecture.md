# Architecture (proposed)

```text
Cloud/host/Kubernetes signals
            |
        adapters
            |
   normalized events
            |
  detector + correlation
            |
  usage/cost estimator ---> versioned pricing data
            |
    policy evaluator
            |
  audit / notification
            |
   human approval gate
            |
scoped response executor (future, disabled by default)
```

## Separation of concerns
- Adapters are read-only and minimize permissions.
- Detectors produce independently explainable confidence scores.
- Forecasts include time window, source, pricing version and uncertainty.
- The policy engine only makes recommendations; no production APIs are reachable from its package.
- Approval and execution are separate services. Approval cannot be inferred from a model score or spending threshold alone.
- Every attempted action needs an incident ID, narrowly scoped target, operator identity, expiry, and audit record.

## CloudTrail adapter
`internal/cloudtrail` parses CloudTrail log files (S3 delivery format, optionally gzipped, capped at 256 MiB decoded) without calling AWS. Records are normalized into minimal events: raw `requestParameters`/`responseElements` are never carried forward, only fields an indicator needs (such as instance type and count) are extracted, access key IDs are masked and user agents are truncated. Indicators are static, named rules so every tag can be explained; correlation and confidence scoring belong to the detector stage. Replay tests compare normalized output for fixture logs with checked-in golden files.

## CloudWatch metrics
`internal/cloudwatch` generates GetMetricData queries for Bedrock `InputTokenCount`/`OutputTokenCount` (Sum, per `ModelId`) and converts the AWS CLI's results into a `cost.Usage`. Fetching stays with the operator's AWS CLI and credentials, so this project still holds no cloud keys. The model ID travels in each query's label, results must be `Complete` and inside the requested window, and anything ambiguous is rejected rather than estimated.

## Host snapshots
`internal/host` reads `/proc` (processes, CPU over a sample, owned TCP connections) without changing anything, masks secret-looking command-line values at collection time, and scores processes with weighted miner indicators. It shares the detector's noisy-OR scoring and version-fingerprint discipline but is a separate stage for now: host findings are not yet fed into alerts or the evidence log.

## Detector
`internal/detect` groups indicator events by principal (ARN, else masked access key) and splits them into findings at gaps longer than the correlation window. Confidence is a noisy-OR over distinct indicator weights plus attack-chain rules, so the score is bounded below 100, repeating a signal can't inflate it, and every point traces to named contributors and event IDs. The detector supplies `ThreatConfidence` to the policy engine; it never decides on containment itself.

## Evidence store
`internal/evidence` is an append-only JSON-lines log where each record carries the SHA-256 hash of the one before it. Detection writes a record per finding before any alert goes out, so each alert can carry the hash of the record that explains it; delivery attempts are recorded after. Records carry `policy.Version` and `detect.WeightsVersion`, and a test fails if scoring weights change without a version bump. Approval and containment, when built, should append to this same chain.

## Approval workflow
`internal/incident` derives each incident's state from the evidence log and validates operator decisions before they're appended as `approval`, `rejection` or `revocation` records. An approval names one reversible action, the finding's principal, the finding record it was made on, the operator and an expiry of at most 24h. Containment is approved only when a quorum of distinct operators (two by default, fixed in the finding record at detection time) approves the same action within the earliest approver's expiry; any single operator can reject or revoke. Nothing executes approvals; a future executor must check for an active approval in a verified log, act only on that principal and action before the expiry, and record the outcome in the same chain.

## Cost forecasting
The policy engine projects `hourly_rate * forecast_hours`. The hourly rate can be supplied directly, or derived by `internal/cost` from observed Bedrock input/output token counts and a versioned, region-specific pricing table (USD per million tokens). The estimate records the pricing version it used, and any forecast warning (stale or not-yet-effective pricing, unpriced models, a too-short observation window) forces the policy decision to alert-only. Real AWS Bedrock forecasting should derive usage from observed request/token metrics and model-specific rates, account for provisioned throughput and discounts, and clearly distinguish billed costs from estimates. Cloud billing data can be delayed.

## Failure behavior
Missing telemetry, stale rates, incomplete attribution, or conflicting signals should degrade to alert-only. Production workloads need allowlists, cooldowns, blast-radius limits and reversible containment.
