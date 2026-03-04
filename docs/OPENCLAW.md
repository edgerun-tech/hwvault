# OpenClaw Integration

`hwvault` can be used as a SecretRef `exec` provider backend for OpenClaw.

## Resolver binary

This repo provides:

- `openclaw-hwvault-resolver`

The resolver reads OpenClaw's exec-provider request JSON from stdin and prints JSON to stdout.

### Request format

```json
{ "protocolVersion": 1, "provider": "hwvault", "ids": ["openai-api-key"] }
```

### Response format

```json
{ "protocolVersion": 1, "values": { "openai-api-key": "sk-..." } }
```

or with per-id errors:

```json
{
  "protocolVersion": 1,
  "values": {},
  "errors": {
    "openai-api-key": { "message": "not found" }
  }
}
```

## Build

```bash
cargo build --release --bin openclaw-hwvault-resolver
```

Install/copy binary to a stable absolute path, for example:

```bash
install -m 0755 target/release/openclaw-hwvault-resolver /usr/local/bin/openclaw-hwvault-resolver
```

## OpenClaw config example

```json5
{
  secrets: {
    providers: {
      hwvault: {
        source: "exec",
        command: "/usr/local/bin/openclaw-hwvault-resolver",
        passEnv: ["PATH", "HOME"],
        jsonOnly: true,
      },
    },
    defaults: {
      exec: "hwvault",
    },
  },
}
```

Use SecretRef values:

```json5
{ source: "exec", provider: "hwvault", id: "openai-api-key" }
```

## Delegation + audit commands

Resolver also supports local delegation primitives:

```bash
openclaw-hwvault-resolver delegate-issue <id> [ttlSeconds]
openclaw-hwvault-resolver delegate-redeem <token>
```

Properties:

- one-time token redemption
- short TTL expiry
- token claim binding (`agentId`, `sessionKey`, `audience`)
- id allowlist policy via `HWVAULT_POLICY_PATH` (default: `~/.config/hwvault/openclaw-policy.json`)
- hash-chained audit log in `~/.local/share/hwvault/openclaw-audit.jsonl`
- no plaintext secret storage in delegation state (secret is resolved at redeem time)
- non-hardware hosts automatically clamp delegation TTL to `nonHardwareMaxTtlSeconds` (default: 30s)
- delegation signing key prefers Linux kernel keyring (`keyctl`) before disk fallback

Policy file example:

```json
{
  "acceptedRoots": ["tpm", "yubikey"],
  "allowedIds": ["openai-api-key", "anthropic-api-key"],
  "requiredRootsById": {
    "anthropic-api-key": ["tpm"]
  }
}
```

Behavior:

- Resolver requires at least one accepted hardware root to be present.
- Per-id root constraints (`requiredRootsById`) override global `acceptedRoots`.
- Optional env override: `HWVAULT_TRUST_ROOTS=tpm,yubikey`.
- Sensitive ids can require explicit presence confirmation (fingerprint) using:
  - `presenceMethod`: `fingerprint`
  - `requirePresenceForIds`: `["secret-id"]`
- Optional override command for presence checks:
  - `HWVAULT_PRESENCE_CMD="..."`
- Sensitive ids can also require a second factor from another device:
  - `secondFactorMethod`: `http` (recommended)
  - `secondFactorHttpUrl`: `https://2fa.example.com`
  - `secondFactorTimeoutSeconds`: `90`
  - `requireSecondFactorForIds`: `["secret-id"]`

HTTP backend contract:

- Resolver `POST`s approval request to: `POST {baseUrl}/v1/approvals`
- Resolver polls status at: `GET {baseUrl}/v1/approvals/{requestId}`
- Auth via env: `HWVAULT_SECOND_FACTOR_HTTP_BEARER`
- `https://` is required by default for `secondFactorHttpUrl`
  - opt-out only with `allowInsecureSecondFactorHttp: true`
  - or env `HWVAULT_ALLOW_INSECURE_SECOND_FACTOR_HTTP=1`

Status response must contain:

- `{ "status": "pending" | "approved" | "denied" }`

Demo backend reference:

- `scripts/hardware/hwvault-2fa-http-backend.example.py`

Alternative local hook method still supported:

- `secondFactorMethod`: `command`
- `secondFactorCommand`: `/usr/local/bin/hwvault-second-factor-approve`

`secondFactorCommand` receives env vars:

- `HWVAULT_2FA_ACTION` (`resolve` / `delegate-issue` / `delegate-redeem`)
- `HWVAULT_2FA_SECRET_ID`

Exit code `0` means approved; non-zero denies the action.

See also: `docs/examples/openclaw-policy.json`

## Notes

- Resolver uses `hwvault get <id>` and returns the `Pass:` field.
- Override `hwvault` binary path with `HWVAULT_BIN=/absolute/path/to/hwvault`.
- Keep resolver and hwvault binaries root-owned and non-writable by other users.
