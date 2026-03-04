# Incident Response Runbook

This runbook addresses production-readiness issue #4.

## Trigger conditions

Open an incident immediately if any of these occur:

- suspected secret disclosure
- suspicious/unauthorized secret resolution events
- signing key compromise suspicion
- repeated 2FA bypass or policy bypass signals

## Severity levels

- **SEV-1**: active compromise likely / confirmed
- **SEV-2**: high-confidence suspicious behavior
- **SEV-3**: low-confidence anomaly needing investigation

## Immediate actions (first 15 minutes)

1. Freeze changes to `main` and releases.
2. Revoke/rotate affected credentials.
3. Disable impacted resolver paths/policies if needed.
4. Preserve logs/audit artifacts.
5. Assign incident commander and recorder.

## Containment

- Rotate:
  - 2FA backend bearer/token material
  - any compromised secret IDs
  - delegation signing key material
- Force expiration of outstanding delegation tokens.
- Restrict policy to minimum safe allowlist.

## Eradication & recovery

- patch root cause
- validate via tests + targeted manual checks
- re-enable services in stages
- monitor for recurrence

## Communication

- maintain internal timeline (UTC)
- notify affected users/maintainers as appropriate
- publish postmortem summary for significant incidents

## Post-incident checklist

- [ ] root cause identified
- [ ] all affected credentials rotated
- [ ] controls/tests added to prevent recurrence
- [ ] runbook updated with lessons learned
