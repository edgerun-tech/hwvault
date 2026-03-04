#!/usr/bin/env bash
set -euo pipefail

# Hardware release-gate harness for hwvault + OpenClaw integration.
# Fails closed: any unmet required gate exits non-zero.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${HWVAULT_HW_REPORT_DIR:-$ROOT_DIR/artifacts/hardware}"
mkdir -p "$REPORT_DIR"
REPORT_JSON="$REPORT_DIR/release-gates.json"

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

FAIL_COUNT=0
PASS_COUNT=0

declare -a RESULTS

record() {
  local gate="$1" status="$2" detail="$3"
  RESULTS+=("{\"gate\":\"$gate\",\"status\":\"$status\",\"detail\":\"${detail//\"/\\\"}\"}")
  if [[ "$status" == "pass" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  echo "[$status] $gate - $detail"
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

gate_tooling() {
  if has_cmd hwvault && has_cmd openclaw-hwvault-resolver; then
    record tooling pass "required binaries found"
  else
    record tooling fail "missing hwvault and/or openclaw-hwvault-resolver in PATH"
  fi
}

gate_tpm_trust_root() {
  if [[ -e /dev/tpmrm0 || -e /dev/tpm0 ]]; then
    record tpm_trust_root pass "TPM device node present"
  else
    record tpm_trust_root fail "TPM device missing"
  fi
}

gate_yubikey_presence() {
  if has_cmd ykman; then
    if ykman list 2>/dev/null | grep -qi yubikey; then
      record yubikey_presence pass "YubiKey detected via ykman"
      return
    fi
    record yubikey_presence fail "ykman installed but no YubiKey detected"
    return
  fi

  if has_cmd gpg && gpg --card-status >/dev/null 2>&1; then
    record yubikey_presence pass "smartcard detected via gpg --card-status"
  else
    record yubikey_presence fail "no ykman and no smartcard via gpg"
  fi
}

gate_trust_root_policy() {
  local p
  p="$(mktemp)"
  cat >"$p" <<'JSON'
{"acceptedRoots":["nonexistent-root"]}
JSON
  local resp
  resp="$(printf '{"protocolVersion":1,"provider":"hwvault","ids":["anything"]}' | HWVAULT_POLICY_PATH="$p" openclaw-hwvault-resolver 2>/dev/null || true)"
  rm -f "$p"
  if printf '%s' "$resp" | grep -q 'no accepted hardware trust root available'; then
    record trust_root_policy pass "resolver denies when required trust root unavailable"
  else
    record trust_root_policy fail "resolver did not enforce trust-root policy"
  fi
}

gate_resolver_roundtrip() {
  local test_name="openclaw-hwgate-$(date +%s)"
  if ! hwvault unlock >/dev/null 2>&1; then
    record resolver_roundtrip fail "hwvault unlock failed"
    return
  fi
  if ! hwvault store "$test_name" gate-user gate-secret >/dev/null 2>&1; then
    record resolver_roundtrip fail "failed to store test secret"
    return
  fi

  local req resp
  req="{\"protocolVersion\":1,\"provider\":\"hwvault\",\"ids\":[\"$test_name\",\"missing-secret\"]}"
  if ! resp="$(printf '%s' "$req" | openclaw-hwvault-resolver 2>/dev/null)"; then
    record resolver_roundtrip fail "resolver execution failed"
    return
  fi

  if printf '%s' "$resp" | grep -q '"gate-secret"' && printf '%s' "$resp" | grep -q '"missing-secret"'; then
    record resolver_roundtrip pass "resolver returned value + per-id error"
  else
    record resolver_roundtrip fail "unexpected resolver response"
  fi
}

gate_delegation_short_ttl() {
  local id="openclaw-ttl-$(date +%s)"
  hwvault unlock >/dev/null 2>&1 || true
  hwvault store "$id" gate-user ttl-secret >/dev/null 2>&1 || {
    record delegation_short_ttl fail "failed to store ttl test secret"
    return
  }

  local issue_json token
  if ! issue_json="$(OPENCLAW_AGENT_ID=agent-main OPENCLAW_SESSION_KEY=session-main OPENCLAW_DELEGATION_AUDIENCE=openclaw openclaw-hwvault-resolver delegate-issue "$id" 2 2>/dev/null)"; then
    record delegation_short_ttl fail "delegate-issue failed"
    return
  fi
  token="$(printf '%s' "$issue_json" | jq -r '.token // empty')"
  if [[ -z "$token" ]]; then
    record delegation_short_ttl fail "delegate-issue returned no token"
    return
  fi

  if ! OPENCLAW_AGENT_ID=agent-main OPENCLAW_SESSION_KEY=session-main OPENCLAW_DELEGATION_AUDIENCE=openclaw openclaw-hwvault-resolver delegate-redeem "$token" >/dev/null 2>&1; then
    record delegation_short_ttl fail "token redeem failed before expiry"
    return
  fi

  # one-time use enforcement
  if OPENCLAW_AGENT_ID=agent-main OPENCLAW_SESSION_KEY=session-main OPENCLAW_DELEGATION_AUDIENCE=openclaw openclaw-hwvault-resolver delegate-redeem "$token" >/dev/null 2>&1; then
    record delegation_short_ttl fail "token reused successfully (must be one-time)"
    return
  fi

  # expiry enforcement
  issue_json="$(OPENCLAW_AGENT_ID=agent-main OPENCLAW_SESSION_KEY=session-main OPENCLAW_DELEGATION_AUDIENCE=openclaw openclaw-hwvault-resolver delegate-issue "$id" 1 2>/dev/null || true)"
  token="$(printf '%s' "$issue_json" | jq -r '.token // empty')"
  [[ -n "$token" ]] || {
    record delegation_short_ttl fail "second delegate-issue failed"
    return
  }
  sleep 2
  if OPENCLAW_AGENT_ID=agent-main OPENCLAW_SESSION_KEY=session-main OPENCLAW_DELEGATION_AUDIENCE=openclaw openclaw-hwvault-resolver delegate-redeem "$token" >/dev/null 2>&1; then
    record delegation_short_ttl fail "expired token still redeemable"
    return
  fi

  record delegation_short_ttl pass "short-lived one-time tokens enforced"
}

gate_non_hw_short_ttl_default() {
  local id="openclaw-nonhw-$(date +%s)"
  hwvault unlock >/dev/null 2>&1 || true
  hwvault store "$id" gate-user nonhw-secret >/dev/null 2>&1 || {
    record non_hw_short_ttl fail "failed to store non-hw ttl test secret"
    return
  }

  local issue_json ttl
  issue_json="$(HWVAULT_SIMULATE_NO_HW_ROOT=1 OPENCLAW_AGENT_ID=agent-main OPENCLAW_SESSION_KEY=session-main OPENCLAW_DELEGATION_AUDIENCE=openclaw openclaw-hwvault-resolver delegate-issue "$id" 999 2>/dev/null || true)"
  ttl="$(printf '%s' "$issue_json" | jq -r '.ttlSeconds // empty')"
  if [[ -z "$ttl" ]]; then
    record non_hw_short_ttl fail "delegate-issue in simulated non-hw mode failed"
    return
  fi
  if (( ttl <= 30 )); then
    record non_hw_short_ttl pass "non-hw ttl clamped to short value ($ttl)s"
  else
    record non_hw_short_ttl fail "non-hw ttl not clamped ($ttl)s"
  fi
}

gate_auditability() {
  local audit_file="$HOME/.local/share/hwvault/openclaw-audit.jsonl"
  local chain_file="$HOME/.local/share/hwvault/openclaw-audit.chain"

  if [[ ! -s "$audit_file" || ! -s "$chain_file" ]]; then
    record auditability fail "audit artifacts missing"
    return
  fi

  local bad
  bad="$(tail -n 20 "$audit_file" | jq -r 'select(.hash == null or .prevHash == null) | .ts' | head -n 1 || true)"
  if [[ -n "$bad" ]]; then
    record auditability fail "audit entries missing hash chain fields"
    return
  fi

  # crude secret leakage check
  if tail -n 20 "$audit_file" | grep -q "ttl-secret"; then
    record auditability fail "audit log appears to contain secret material"
    return
  fi

  record auditability pass "hash-chained audit events present and redacted"
}

generate_report() {
  local status="pass"
  if (( FAIL_COUNT > 0 )); then
    status="fail"
  fi

  {
    echo "{"
    echo "  \"generatedAt\": \"$(now_iso)\"," 
    echo "  \"status\": \"$status\"," 
    echo "  \"passCount\": $PASS_COUNT," 
    echo "  \"failCount\": $FAIL_COUNT," 
    echo "  \"results\": ["
    local i
    for i in "${!RESULTS[@]}"; do
      printf '    %s' "${RESULTS[$i]}"
      if (( i < ${#RESULTS[@]} - 1 )); then
        echo ","
      else
        echo
      fi
    done
    echo "  ]"
    echo "}"
  } >"$REPORT_JSON"

  echo "Report: $REPORT_JSON"
}

main() {
  gate_tooling
  gate_tpm_trust_root
  gate_yubikey_presence
  gate_trust_root_policy
  gate_resolver_roundtrip
  gate_delegation_short_ttl
  gate_non_hw_short_ttl_default
  gate_auditability
  generate_report

  if (( FAIL_COUNT > 0 )); then
    exit 1
  fi
}

main "$@"
