# hwvault

Hardware-rooted secret resolver and delegation runtime for OpenClaw integrations.

Initial scope in this repository:

- `openclaw-hwvault-resolver` binary
- trust-root policy (TPM/YubiKey)
- short-lived delegation tokens (bound claims)
- presence + second-factor hooks
- hardware release-gate harness

See `docs/OPENCLAW.md` for configuration details.

Production/security docs:

- `docs/PRODUCTION_READINESS.md`
- `docs/RELEASE_SIGNING.md`
- `docs/INCIDENT_RESPONSE.md`
- `docs/EXTERNAL_SECURITY_REVIEW.md`

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

## Credits

Originally created by Ken (Sylchi). See `CREDITS.md`.
