# Changelog

Notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## Unreleased

### Added
- **EC2 cost forecasting**: `cad detect -ec2-pricing` prices each finding's successful `RunInstances` launches from a versioned table; unpriced or stale prices degrade the decision to alert-only.
- **Created identities are followed**: activity by an IAM user is counted under the principal that created it or issued its credentials (`linked_principals`, `created_identity_activity`).
- **New indicators**: `alternate_compute_launch` (ECS, Batch, SageMaker, Lambda) and `privilege_escalation` (`AdministratorAccess` attached); SageMaker GPU types count as GPU launches. New chain `privilege_escalation_with_new_credentials`.
- **Suppression rules**: `cad detect -suppressions`, with a required reason and expiry per rule. Evasion indicators cannot be suppressed.
- **Signed approvals**: `cad keygen`, `cad approve -key`, `-operators`, and `cad detect -require-signed-approvals` (Ed25519).
- **Host findings** can send alerts and write evidence records (`cad host-scan -notify`, `-evidence-log`), and get incident IDs.
- **Linux host scanning**: `cad host-snapshot` and `cad host-scan`.
- **`cad-watch` hardening**: cross-poll event buffer (`-correlate`), backfill after failed polls, SIGTERM handling, and pass-through of evidence, cost, suppression and approval flags.
- `cad help`, `cad version`, `cad policy`, and `-config` JSON files.
- Makefile, Dockerfile, release workflow for tagged binaries, Dependabot, and CI jobs for fuzzing and `govulncheck`.
- Fuzz tests for every parser that reads untrusted input.

### Changed
- Detector weights version is now `weights-2026-11-13.1`.
- `cad detect` no longer re-records a finding that is unchanged since the previous run, so repeated runs don't reset approvals.
- `cad-watch -notify` now requires `-alert-state`.
- An unknown first argument is an error (`unknown command`) instead of being treated as a policy flag.
- Alerts carry a `source` field (`cloudtrail` or `host`).

### Fixed
- Evidence verification now requires each line to be byte-identical to what was written. Previously an edit that kept a record's decoded values, such as changing a JSON key's letter case, was not detected. Found by fuzzing.
