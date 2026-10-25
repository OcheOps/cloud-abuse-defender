# Threat model

## In scope
Unauthorized cryptomining, stolen API credentials, anomalous model inference consumption, and abuse of cloud compute.

## Trust boundaries
Agents/telemetry -> ingestion -> policy engine -> incident store -> response orchestrator -> privileged cloud/Kubernetes APIs.

## Key threats
- Attacker spoofs high-cost signals to shut down legitimate workloads.
- Compromised collector injects incidents or exfiltrates credentials.
- Sensitive process arguments contain tokens or secrets.
- Delayed billing leads to inaccurate loss forecasts.
- Automated response causes larger damage than the incident itself.

## Required protections before live execution
- Read-only collectors, mTLS/signatures for telemetry, RBAC, tamper-evident audit logging.
- Minimize/redact secrets and short retention of sensitive evidence.
- Require corroborating security indicators, not spending alone.
- Human approval by default; explicit policy-scoped opt-in for any automatic action.
- Rate limits, dry-run testing, rollback plan and protected critical-resource exclusions.
- Never retaliate against third-party systems or attempt to seize attacker funds.
