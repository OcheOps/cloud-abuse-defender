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

## Cost forecasting
The policy engine projects `hourly_rate * forecast_hours`. The hourly rate can be supplied directly, or derived by `internal/cost` from observed Bedrock input/output token counts and a versioned, region-specific pricing table (USD per million tokens). The estimate records the pricing version it used, and any forecast warning (stale or not-yet-effective pricing, unpriced models, a too-short observation window) forces the policy decision to alert-only. Real AWS Bedrock forecasting should derive usage from observed request/token metrics and model-specific rates, account for provisioned throughput and discounts, and clearly distinguish billed costs from estimates. Cloud billing data can be delayed.

## Failure behavior
Missing telemetry, stale rates, incomplete attribution, or conflicting signals should degrade to alert-only. Production workloads need allowlists, cooldowns, blast-radius limits and reversible containment.
