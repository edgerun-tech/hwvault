# Proof of Work & Production Readiness Evidence

Generated: 2026-03-04T04:37:49Z

## What was delivered

- Hardware trust-root policy in resolver (TPM/YubiKey)
- Delegation with short-lived, one-time tokens
- Token claim binding to caller identity (agent/session/audience)
- Replay protection and expiry checks
- Hash-chained audit events
- Optional fingerprint confirmation for sensitive IDs
- Optional second-factor command hook for sensitive IDs
- Non-hardware TTL clamp defaults
- CI + secret scanning + branch protections

## Local gate evidence

- Resolver tests executed: `cargo test --bin openclaw-hwvault-resolver`
- Hardware gate harness: `make test-hardware-gates`
- Latest gate artifact path (local): `artifacts/hardware/release-gates.json`

## Repo hardening evidence

Branch protections and workflow states were queried via GitHub API/CLI.

- hwvault protection snapshot: `/tmp/hwvault.protection.json`
- hwvault-extension protection snapshot: `/tmp/hwvault-extension.protection.json`
- hwvault-android protection snapshot: `/tmp/hwvault-android.protection.json`
- hwvault-ios protection snapshot: `/tmp/hwvault-ios.protection.json`

- hwvault runs snapshot: `/tmp/hwvault.runs.json`
- hwvault-extension runs snapshot: `/tmp/hwvault-extension.runs.json`
- hwvault-android runs snapshot: `/tmp/hwvault-android.runs.json`
- hwvault-ios runs snapshot: `/tmp/hwvault-ios.runs.json`

## Public repos

- https://github.com/edgerun-tech/hwvault
- https://github.com/edgerun-tech/hwvault-extension
- https://github.com/edgerun-tech/hwvault-android
- https://github.com/edgerun-tech/hwvault-ios

## Remaining strict-production blockers

- Dedicated second-device approval backend service (replace generic command hook)
- Signed release artifacts + reproducible build docs
- Incident response runbook
- External independent security review
