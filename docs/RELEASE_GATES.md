# Release Gates (OpenClaw + HWVault)

This document defines **hard release blockers** for hardware-backed OpenClaw secret integration.

## Required gates

1. Merge-clean contribution path to OpenClaw main
2. Hardware trust root present (TPM + YubiKey)
3. Delegation model uses short-lived credentials
4. Auditable secret access decisions (no secret material in logs)
5. Real-hardware test pass before release

## Hardware gate harness

Run:

```bash
make test-hardware-gates
```

This executes `scripts/hardware/test_release_gates.sh` and writes:

- `artifacts/hardware/release-gates.json`

The harness is fail-closed: non-zero exit if any required gate fails.

## Current state

The harness currently validates:

- local tooling presence
- TPM device presence
- YubiKey/smartcard detection
- resolver roundtrip against real `hwvault`

It intentionally fails for not-yet-implemented gates:

- short-lived delegated tokens
- signed/tamper-evident audit trail

Those two failures are release blockers by design until implemented.
