# External Security Review Checklist

This checklist addresses production-readiness issue #5.

## Scope package for reviewers

Provide:

- architecture overview and trust boundaries
- threat model assumptions
- resolver protocol and policy docs
- token/delegation design
- audit log integrity design
- incident response runbook

## Required review areas

1. Cryptography usage and token verification
2. Secret material handling at rest/in transit
3. 2FA flow integrity and replay resistance
4. Policy bypass opportunities
5. Concurrency/race risks in audit/state paths
6. Build/release supply-chain controls

## Test evidence to include

- CI passing runs
- hardware gate output (`artifacts/hardware/release-gates.json`)
- negative-path tests for deny/fail-closed behavior

## Acceptance criteria

- no unresolved critical/high findings
- medium findings triaged with owners and deadlines
- remediation PRs merged for accepted blockers

## Deliverables

- security review report
- remediation plan
- sign-off decision for production rollout
