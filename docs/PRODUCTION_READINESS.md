# Production Readiness Checklist

This checklist must pass before declaring production readiness.

## Required

- [x] License/NOTICE/CREDITS present
- [x] CI workflow enabled
- [x] Secret scanning workflow enabled
- [x] Hardware release-gate harness present
- [x] Trust-root policy enforcement (TPM/YubiKey)
- [x] Delegation TTL + one-time token behavior
- [x] Claim binding (agent/session/audience)
- [x] Audit chain output
- [x] Optional presence checks (fingerprint)
- [x] Optional second-factor hook

## Pending for strict production default

- [ ] independent external security review (see `docs/EXTERNAL_SECURITY_REVIEW.md`)
- [x] concrete second-device approval backend (beyond local command hook)
- [x] signed/reproducible release artifact baseline docs + CI artifact workflow (see `docs/RELEASE_SIGNING.md` and `.github/workflows/release-artifacts.yml`)
- [x] incident response runbook (see `docs/INCIDENT_RESPONSE.md`)
