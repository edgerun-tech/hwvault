use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolverRequest {
    protocol_version: u32,
    provider: String,
    ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolverResponse {
    protocol_version: u32,
    values: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    errors: BTreeMap<String, ResolverError>,
}

#[derive(Debug, Serialize)]
struct ResolverError {
    message: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Policy {
    #[serde(default)]
    allowed_ids: Vec<String>,
    #[serde(default)]
    accepted_roots: Vec<String>,
    #[serde(default)]
    required_roots_by_id: BTreeMap<String, Vec<String>>,
    /// Secret ids that require explicit user-presence confirmation.
    #[serde(default)]
    require_presence_for_ids: Vec<String>,
    /// Presence method. Currently: "fingerprint"
    #[serde(default)]
    presence_method: Option<String>,
    /// Secret ids that require a second factor approval from another device.
    #[serde(default)]
    require_second_factor_for_ids: Vec<String>,
    /// Second-factor method. Currently: "command"
    #[serde(default)]
    second_factor_method: Option<String>,
    /// Legacy single-string command executed for second-factor approval. Exit 0 => approved.
    #[serde(default)]
    second_factor_command: Option<String>,
    /// Structured second-factor command binary path (preferred over `second_factor_command`).
    #[serde(default)]
    second_factor_command_bin: Option<String>,
    /// Structured second-factor command args.
    #[serde(default)]
    second_factor_command_args: Vec<String>,
    /// Base URL for HTTP second-factor backend (e.g. https://2fa.example.com).
    #[serde(default)]
    second_factor_http_url: Option<String>,
    /// Poll timeout for HTTP second-factor backend.
    #[serde(default)]
    second_factor_timeout_seconds: Option<u64>,
    /// Allow insecure (non-HTTPS) second-factor HTTP backend URL.
    #[serde(default)]
    allow_insecure_second_factor_http: bool,
    /// Require poll response metadata to bind to original request/action/secret.
    #[serde(default = "default_true")]
    strict_second_factor_binding: bool,
    /// Default TTL when a hardware trust root is present.
    #[serde(default)]
    default_ttl_seconds: Option<u64>,
    /// Max/default TTL when no hardware trust root exists.
    #[serde(default)]
    non_hardware_max_ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEvent<'a> {
    ts: u64,
    action: &'a str,
    id: &'a str,
    decision: &'a str,
    detail: &'a str,
    prev_hash: String,
    hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DelegationClaims {
    jti: String,
    id: String,
    agent_id: String,
    session_key: String,
    audience: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DelegationState {
    used_jti: BTreeMap<String, u64>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn state_dir() -> PathBuf {
    if let Ok(path) = std::env::var("HWVAULT_STATE_DIR") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/share/hwvault")
}

fn policy_path() -> PathBuf {
    if let Ok(path) = std::env::var("HWVAULT_POLICY_PATH") {
        return PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".config/hwvault/openclaw-policy.json")
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("failed creating state dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms).map_err(|e| format!("failed setting dir perms: {e}"))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    fs::write(path, content).map_err(|e| format!("write failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| format!("failed setting file perms: {e}"))?;
    }
    Ok(())
}

fn load_policy(path: &Path) -> Policy {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => Policy::default(),
    }
}

fn is_id_allowed(policy: &Policy, id: &str) -> bool {
    policy.allowed_ids.is_empty() || policy.allowed_ids.iter().any(|v| v == id)
}

fn has_tpm_root() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

fn has_yubikey_root() -> bool {
    if let Ok(out) = Command::new("ykman").arg("list").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if s.contains("yubikey") {
                return true;
            }
        }
    }
    if let Ok(out) = Command::new("gpg").arg("--card-status").output() {
        return out.status.success();
    }
    false
}

fn effective_roots(policy: &Policy) -> Vec<String> {
    if let Ok(from_env) = std::env::var("HWVAULT_TRUST_ROOTS") {
        let roots: Vec<String> = from_env
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if !roots.is_empty() {
            return roots;
        }
    }
    if policy.accepted_roots.is_empty() {
        vec!["tpm".to_string(), "yubikey".to_string()]
    } else {
        policy.accepted_roots.clone()
    }
}

fn any_hardware_root_available() -> bool {
    has_tpm_root() || has_yubikey_root()
}

fn resolve_root_type(policy: &Policy, id: Option<&str>) -> Result<String, String> {
    let mut candidates = effective_roots(policy);
    if let Some(secret_id) = id {
        if let Some(required) = policy.required_roots_by_id.get(secret_id) {
            candidates = required.clone();
        }
    }

    for root in candidates {
        match root.as_str() {
            "tpm" if has_tpm_root() => return Ok("tpm".to_string()),
            "yubikey" if has_yubikey_root() => return Ok("yubikey".to_string()),
            _ => {}
        }
    }

    Err("no accepted hardware trust root available".to_string())
}

fn parse_pass_field(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("Pass: ").map(ToString::to_string))
}

fn resolve_secret(hwvault_bin: &str, id: &str) -> Result<String, String> {
    let output = Command::new(hwvault_bin)
        .arg("get")
        .arg(id)
        .output()
        .map_err(|e| format!("failed to run hwvault: {e}"))?;

    if !output.status.success() {
        return Err("hwvault get failed".to_string());
    }

    let stdout = String::from_utf8(output.stdout).map_err(|_| "non-utf8 response".to_string())?;
    parse_pass_field(&stdout).ok_or_else(|| "entry missing Pass field".to_string())
}

fn requires_presence(policy: &Policy, id: &str) -> bool {
    policy.require_presence_for_ids.iter().any(|v| v == id)
}

fn run_fingerprint_confirmation() -> Result<(), String> {
    if let Ok(cmdline) = std::env::var("HWVAULT_PRESENCE_CMD") {
        let mut parts = cmdline.split_whitespace();
        let Some(bin) = parts.next() else {
            return Err("HWVAULT_PRESENCE_CMD is empty".to_string());
        };
        let args: Vec<String> = parts.map(|s| s.to_string()).collect();
        let status = Command::new(bin)
            .args(args)
            .status()
            .map_err(|e| format!("presence command failed to start: {e}"))?;
        if status.success() {
            return Ok(());
        }
        return Err("presence command failed".to_string());
    }

    // Default Linux fingerprint path
    let status = Command::new("timeout")
        .args(["15s", "fprintd-verify"])
        .status()
        .map_err(|e| format!("fingerprint verify command failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("fingerprint confirmation failed".to_string())
    }
}

fn enforce_presence(policy: &Policy, id: &str) -> Result<(), String> {
    if !requires_presence(policy, id) {
        return Ok(());
    }
    let method = policy
        .presence_method
        .as_deref()
        .unwrap_or("fingerprint")
        .to_lowercase();
    match method.as_str() {
        "fingerprint" => run_fingerprint_confirmation(),
        _ => Err(format!("unsupported presence method: {method}")),
    }
}

fn requires_second_factor(policy: &Policy, id: &str) -> bool {
    policy
        .require_second_factor_for_ids
        .iter()
        .any(|v| v == id)
}

fn run_second_factor_command(policy: &Policy, action: &str, id: &str) -> Result<(), String> {
    let (bin, args) = if let Some(bin) = policy.second_factor_command_bin.as_ref() {
        (bin.clone(), policy.second_factor_command_args.clone())
    } else {
        // Backward-compatible fallback for existing single-string command config.
        let cmdline = if let Some(v) = policy.second_factor_command.as_ref() {
            v.clone()
        } else if let Ok(v) = std::env::var("HWVAULT_SECOND_FACTOR_CMD") {
            v
        } else {
            return Err("second_factor_command not configured".to_string());
        };
        let mut parts = cmdline.split_whitespace();
        let Some(bin) = parts.next() else {
            return Err("second_factor_command is empty".to_string());
        };
        let args: Vec<String> = parts.map(|s| s.to_string()).collect();
        (bin.to_string(), args)
    };

    let status = Command::new(bin)
        .args(args)
        .env("HWVAULT_2FA_ACTION", action)
        .env("HWVAULT_2FA_SECRET_ID", id)
        .status()
        .map_err(|e| format!("second-factor command failed to start: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("second-factor command denied or failed".to_string())
    }
}

fn run_second_factor_http(policy: &Policy, action: &str, id: &str) -> Result<(), String> {
    let base = policy
        .second_factor_http_url
        .clone()
        .or_else(|| std::env::var("HWVAULT_SECOND_FACTOR_HTTP_URL").ok())
        .ok_or_else(|| "second_factor_http_url not configured".to_string())?;

    let allow_insecure = policy.allow_insecure_second_factor_http
        || std::env::var("HWVAULT_ALLOW_INSECURE_SECOND_FACTOR_HTTP")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    if !allow_insecure && !base.to_lowercase().starts_with("https://") {
        return Err("second-factor HTTP backend must use https".to_string());
    }

    let bearer = std::env::var("HWVAULT_SECOND_FACTOR_HTTP_BEARER")
        .map_err(|_| "HWVAULT_SECOND_FACTOR_HTTP_BEARER not configured".to_string())?;

    let timeout_seconds = policy.second_factor_timeout_seconds.unwrap_or(90).clamp(5, 300);
    let request_id = random_id();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client build failed: {e}"))?;

    let create_url = format!("{}/v1/approvals", base.trim_end_matches('/'));
    let payload = serde_json::json!({
        "requestId": request_id,
        "action": action,
        "secretId": id,
        "ts": now_unix(),
    });

    let create_resp = client
        .post(create_url)
        .bearer_auth(&bearer)
        .json(&payload)
        .send()
        .map_err(|e| format!("second-factor create request failed: {e}"))?;

    if !create_resp.status().is_success() {
        return Err(format!(
            "second-factor create request rejected ({})",
            create_resp.status()
        ));
    }

    let poll_url = format!(
        "{}/v1/approvals/{}",
        base.trim_end_matches('/'),
        request_id
    );
    let started = now_unix();
    loop {
        if now_unix().saturating_sub(started) > timeout_seconds {
            return Err("second-factor approval timed out".to_string());
        }
        let poll_resp = client
            .get(&poll_url)
            .bearer_auth(&bearer)
            .send()
            .map_err(|e| format!("second-factor poll failed: {e}"))?;
        if !poll_resp.status().is_success() {
            return Err(format!("second-factor poll rejected ({})", poll_resp.status()));
        }
        let body: serde_json::Value = poll_resp
            .json()
            .map_err(|e| format!("second-factor poll decode failed: {e}"))?;

        let strict_binding = policy.strict_second_factor_binding
            && !std::env::var("HWVAULT_DISABLE_STRICT_2FA_BINDING")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
        if strict_binding {
            let rid_ok = body
                .get("requestId")
                .and_then(|v| v.as_str())
                .map(|v| v == request_id)
                .unwrap_or(false);
            let action_ok = body
                .get("action")
                .and_then(|v| v.as_str())
                .map(|v| v == action)
                .unwrap_or(false);
            let secret_ok = body
                .get("secretId")
                .and_then(|v| v.as_str())
                .map(|v| v == id)
                .unwrap_or(false);
            if !(rid_ok && action_ok && secret_ok) {
                return Err("second-factor poll binding mismatch".to_string());
            }
        }

        match body
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("pending")
        {
            "approved" => return Ok(()),
            "denied" => return Err("second-factor denied".to_string()),
            _ => sleep(Duration::from_secs(2)),
        }
    }
}

fn enforce_second_factor(policy: &Policy, action: &str, id: &str) -> Result<(), String> {
    if !requires_second_factor(policy, id) {
        return Ok(());
    }
    let method = policy
        .second_factor_method
        .as_deref()
        .unwrap_or("command")
        .to_lowercase();
    match method.as_str() {
        "command" => run_second_factor_command(policy, action, id),
        "http" => run_second_factor_http(policy, action, id),
        _ => Err(format!("unsupported second-factor method: {method}")),
    }
}

fn validate_id(id: &str) -> Result<(), String> {
    let ok = id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':'));
    if !ok || id.is_empty() || id.len() > 255 {
        return Err("invalid id format".to_string());
    }
    Ok(())
}

fn chain_hash(prev_hash: &str, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

fn append_audit(action: &str, id: &str, decision: &str, detail: &str) {
    let dir = state_dir();
    if ensure_private_dir(&dir).is_err() {
        return;
    }
    let lock_path = dir.join("openclaw-audit.lock");
    let chain_path = dir.join("openclaw-audit.chain");
    let log_path = dir.join("openclaw-audit.jsonl");

    // Coarse process lock via lock-file create_new; fail closed after bounded retries.
    let mut lock_acquired = false;
    for _ in 0..50 {
        match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_path)
        {
            Ok(_) => {
                lock_acquired = true;
                break;
            }
            Err(_) => sleep(Duration::from_millis(20)),
        }
    }
    if !lock_acquired {
        return;
    }

    let prev = fs::read_to_string(&chain_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "GENESIS".to_string());

    let payload = format!("{}|{}|{}|{}|{}", now_unix(), action, id, decision, detail);
    let hash = chain_hash(&prev, &payload);

    let event = AuditEvent {
        ts: now_unix(),
        action,
        id,
        decision,
        detail,
        prev_hash: prev,
        hash: hash.clone(),
    };

    if let Ok(line) = serde_json::to_string(&event) {
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(f, "{line}");
        }
        let _ = write_private_file(&chain_path, hash.as_bytes());
    }

    let _ = fs::remove_file(lock_path);
}

fn signing_key_path() -> PathBuf {
    state_dir().join("openclaw-delegation.key")
}

fn kernel_keyring_read(key_name: &str) -> Option<String> {
    let out = Command::new("keyctl")
        .args(["pipe", key_name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let t = s.trim().to_string();
    if t.is_empty() { None } else { Some(t) }
}

fn kernel_keyring_write(key_name: &str, value: &str) -> Result<(), String> {
    let status = Command::new("keyctl")
        .args(["padd", "user", key_name, "@s"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut c| {
            if let Some(mut stdin) = c.stdin.take() {
                use std::io::Write as _;
                let _ = stdin.write_all(value.as_bytes());
            }
            c.wait()
        })
        .map_err(|e| format!("keyctl write failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("keyctl write failed".to_string())
    }
}

fn load_or_create_signing_key() -> Result<String, String> {
    let key_name = "hwvault:openclaw:delegation-signing";
    if let Some(v) = kernel_keyring_read(key_name) {
        return Ok(v);
    }

    let path = signing_key_path();
    if let Ok(existing) = fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            let _ = kernel_keyring_write(key_name, &trimmed);
            return Ok(trimmed);
        }
    }

    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| format!("random failed: {e}"))?;
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);

    // Prefer kernel keyring. If unavailable, persist to disk as fallback.
    if kernel_keyring_write(key_name, &key).is_ok() {
        return Ok(key);
    }

    write_private_file(&path, key.as_bytes()).map_err(|e| format!("key write failed: {e}"))?;
    Ok(key)
}

fn sign_payload(signing_key: &str, payload_b64: &str) -> Result<String, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes())
        .map_err(|e| format!("hmac init failed: {e}"))?;
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig))
}

fn encode_token(claims: &DelegationClaims, signing_key: &str) -> Result<String, String> {
    let payload = serde_json::to_vec(claims).map_err(|e| format!("claims encode failed: {e}"))?;
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    let sig = sign_payload(signing_key, &payload_b64)?;
    Ok(format!("ocst.{payload_b64}.{sig}"))
}

fn decode_and_verify_token(token: &str, signing_key: &str) -> Result<DelegationClaims, String> {
    let mut parts = token.split('.');
    let Some(prefix) = parts.next() else {
        return Err("invalid token format".to_string());
    };
    let Some(payload_b64) = parts.next() else {
        return Err("invalid token format".to_string());
    };
    let Some(sig_b64) = parts.next() else {
        return Err("invalid token format".to_string());
    };
    if parts.next().is_some() || prefix != "ocst" {
        return Err("invalid token format".to_string());
    }

    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "invalid token signature".to_string())?;

    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes())
        .map_err(|e| format!("hmac init failed: {e}"))?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| "invalid token signature".to_string())?;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "invalid token payload".to_string())?;
    serde_json::from_slice(&payload).map_err(|e| format!("invalid token claims: {e}"))
}

fn delegation_state_path() -> PathBuf {
    state_dir().join("openclaw-delegation-state.json")
}

fn load_delegation_state() -> DelegationState {
    let p = delegation_state_path();
    match fs::read_to_string(p) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => DelegationState::default(),
    }
}

fn save_delegation_state(state: &DelegationState) -> Result<(), String> {
    let p = delegation_state_path();
    let body = serde_json::to_vec_pretty(state).map_err(|e| format!("state encode failed: {e}"))?;
    write_private_file(&p, &body).map_err(|e| format!("state write failed: {e}"))
}

fn random_id() -> String {
    let mut buf = [0u8; 18];
    let _ = getrandom::fill(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn compute_ttl(policy: &Policy, requested: Option<u64>) -> u64 {
    let simulate_no_hw = std::env::var("HWVAULT_SIMULATE_NO_HW_ROOT")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let has_hw = !simulate_no_hw && any_hardware_root_available();

    if has_hw {
        let default_ttl = policy.default_ttl_seconds.unwrap_or(120);
        requested.unwrap_or(default_ttl).clamp(1, 600)
    } else {
        let non_hw_max = policy.non_hardware_max_ttl_seconds.unwrap_or(30);
        requested.unwrap_or(non_hw_max).clamp(1, non_hw_max.max(1))
    }
}

fn cmd_delegate_issue(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: delegate-issue <id> [ttlSeconds]".to_string());
    }
    let id = &args[0];
    validate_id(id)?;

    let policy = load_policy(&policy_path());
    if !is_id_allowed(&policy, id) {
        append_audit("delegate-issue", id, "deny", "id not in allowlist");
        return Err("id not allowed by policy".to_string());
    }
    let root_type = resolve_root_type(&policy, Some(id))
        .map_err(|e| {
            append_audit("delegate-issue", id, "deny", &e);
            e
        })?;
    enforce_presence(&policy, id).map_err(|e| {
        append_audit("delegate-issue", id, "deny", &format!("presence check failed: {e}"));
        e
    })?;
    enforce_second_factor(&policy, "delegate-issue", id).map_err(|e| {
        append_audit("delegate-issue", id, "deny", &format!("second-factor failed: {e}"));
        e
    })?;

    // Ensure id exists now; redeem will re-resolve from hwvault to avoid plaintext-at-rest.
    let hwvault_bin = std::env::var("HWVAULT_BIN").unwrap_or_else(|_| "hwvault".to_string());
    let _ = resolve_secret(&hwvault_bin, id)?;

    let requested_ttl = args
        .get(1)
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            std::env::var("HWVAULT_DELEGATE_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
        });
    let ttl = compute_ttl(&policy, requested_ttl);

    let agent_id = std::env::var("OPENCLAW_AGENT_ID").unwrap_or_else(|_| "unknown-agent".to_string());
    let session_key = std::env::var("OPENCLAW_SESSION_KEY").unwrap_or_else(|_| "unknown-session".to_string());
    let audience = std::env::var("OPENCLAW_DELEGATION_AUDIENCE").unwrap_or_else(|_| "openclaw".to_string());

    let issued_at = now_unix();
    let claims = DelegationClaims {
        jti: random_id(),
        id: id.to_string(),
        agent_id,
        session_key,
        audience,
        issued_at,
        expires_at: issued_at.saturating_add(ttl),
    };

    let signing_key = load_or_create_signing_key()?;
    let token = encode_token(&claims, &signing_key)?;

    append_audit(
        "delegate-issue",
        id,
        "allow",
        &format!("issued token ttl={ttl}s root={root_type}"),
    );

    let out = serde_json::json!({
        "token": token,
        "id": claims.id,
        "agentId": claims.agent_id,
        "sessionKey": claims.session_key,
        "audience": claims.audience,
        "ttlSeconds": ttl,
        "expiresAt": claims.expires_at,
    });
    serde_json::to_writer(std::io::stdout(), &out).map_err(|e| format!("json write failed: {e}"))?;
    Ok(())
}

fn cmd_delegate_redeem(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: delegate-redeem <token>".to_string());
    }
    let token = &args[0];

    let signing_key = load_or_create_signing_key()?;
    let claims = decode_and_verify_token(token, &signing_key)?;

    let now = now_unix();
    if claims.expires_at <= now {
        append_audit("delegate-redeem", &claims.id, "deny", "expired token");
        return Err("token expired".to_string());
    }

    let req_agent = std::env::var("OPENCLAW_AGENT_ID").unwrap_or_else(|_| "unknown-agent".to_string());
    let req_session =
        std::env::var("OPENCLAW_SESSION_KEY").unwrap_or_else(|_| "unknown-session".to_string());
    let req_aud = std::env::var("OPENCLAW_DELEGATION_AUDIENCE").unwrap_or_else(|_| "openclaw".to_string());

    if claims.agent_id != req_agent || claims.session_key != req_session || claims.audience != req_aud {
        append_audit(
            "delegate-redeem",
            &claims.id,
            "deny",
            "claim binding mismatch",
        );
        return Err("token claim binding mismatch".to_string());
    }

    let mut state = load_delegation_state();
    state.used_jti.retain(|_, exp| *exp > now);
    if state.used_jti.contains_key(&claims.jti) {
        append_audit("delegate-redeem", &claims.id, "deny", "replay detected");
        return Err("token already used".to_string());
    }
    state.used_jti.insert(claims.jti.clone(), claims.expires_at);
    save_delegation_state(&state)?;

    let policy = load_policy(&policy_path());
    if !is_id_allowed(&policy, &claims.id) {
        append_audit("delegate-redeem", &claims.id, "deny", "id not in allowlist");
        return Err("id not allowed by policy".to_string());
    }
    let root_type = resolve_root_type(&policy, Some(&claims.id))
        .map_err(|e| {
            append_audit("delegate-redeem", &claims.id, "deny", &e);
            e
        })?;
    enforce_presence(&policy, &claims.id).map_err(|e| {
        append_audit(
            "delegate-redeem",
            &claims.id,
            "deny",
            &format!("presence check failed: {e}"),
        );
        e
    })?;
    enforce_second_factor(&policy, "delegate-redeem", &claims.id).map_err(|e| {
        append_audit(
            "delegate-redeem",
            &claims.id,
            "deny",
            &format!("second-factor failed: {e}"),
        );
        e
    })?;

    let hwvault_bin = std::env::var("HWVAULT_BIN").unwrap_or_else(|_| "hwvault".to_string());
    let secret = resolve_secret(&hwvault_bin, &claims.id)?;

    append_audit(
        "delegate-redeem",
        &claims.id,
        "allow",
        &format!("redeemed once root={root_type}"),
    );
    let out = serde_json::json!({"id": claims.id, "secret": secret});
    serde_json::to_writer(std::io::stdout(), &out).map_err(|e| format!("json write failed: {e}"))?;
    Ok(())
}

fn run_resolver() -> Result<(), String> {
    let mut stdin_buf = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin_buf)
        .map_err(|e| format!("failed to read stdin: {e}"))?;

    let req: ResolverRequest =
        serde_json::from_str(&stdin_buf).map_err(|e| format!("invalid request JSON: {e}"))?;

    if req.protocol_version != 1 {
        return Err(format!("unsupported protocolVersion: {}", req.protocol_version));
    }
    if req.provider.trim().is_empty() {
        return Err("provider must be non-empty".to_string());
    }

    let policy = load_policy(&policy_path());
    let hwvault_bin = std::env::var("HWVAULT_BIN").unwrap_or_else(|_| "hwvault".to_string());

    let mut values = BTreeMap::new();
    let mut errors = BTreeMap::new();

    for id in req.ids {
        if let Err(msg) = validate_id(&id) {
            append_audit("resolve", &id, "deny", &msg);
            errors.insert(id, ResolverError { message: msg });
            continue;
        }
        if !is_id_allowed(&policy, &id) {
            append_audit("resolve", &id, "deny", "id not in allowlist");
            errors.insert(
                id,
                ResolverError {
                    message: "id not allowed by policy".to_string(),
                },
            );
            continue;
        }

        let root_type = match resolve_root_type(&policy, Some(&id)) {
            Ok(root) => root,
            Err(message) => {
                append_audit("resolve", &id, "deny", &message);
                errors.insert(id, ResolverError { message });
                continue;
            }
        };

        if let Err(message) = enforce_presence(&policy, &id) {
            append_audit("resolve", &id, "deny", &format!("presence check failed: {message}"));
            errors.insert(id, ResolverError { message });
            continue;
        }
        if let Err(message) = enforce_second_factor(&policy, "resolve", &id) {
            append_audit("resolve", &id, "deny", &format!("second-factor failed: {message}"));
            errors.insert(id, ResolverError { message });
            continue;
        }

        match resolve_secret(&hwvault_bin, &id) {
            Ok(secret) => {
                append_audit("resolve", &id, "allow", &format!("resolved root={root_type}"));
                values.insert(id, secret);
            }
            Err(message) => {
                append_audit("resolve", &id, "deny", &message);
                errors.insert(id, ResolverError { message });
            }
        }
    }

    let resp = ResolverResponse {
        protocol_version: 1,
        values,
        errors,
    };
    serde_json::to_writer(std::io::stdout(), &resp)
        .map_err(|e| format!("failed to write response JSON: {e}"))?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = if args.is_empty() {
        run_resolver()
    } else if args[0] == "delegate-issue" {
        cmd_delegate_issue(&args[1..])
    } else if args[0] == "delegate-redeem" {
        cmd_delegate_redeem(&args[1..])
    } else {
        Err("unknown command".to_string())
    };

    if let Err(err) = res {
        let _ = writeln!(std::io::stderr(), "{err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pass_field_works() {
        let sample = "ID: x\nName: demo\nUser: u\nPass: secret123\n";
        assert_eq!(parse_pass_field(sample).as_deref(), Some("secret123"));
    }

    #[test]
    fn parse_pass_field_missing() {
        let sample = "ID: x\nName: demo\n";
        assert_eq!(parse_pass_field(sample), None);
    }

    #[test]
    fn id_validation() {
        assert!(validate_id("openai-api-key").is_ok());
        assert!(validate_id("providers/openai:api.key_1").is_ok());
        assert!(validate_id("bad id with spaces").is_err());
    }

    #[test]
    fn policy_allows_all_when_empty() {
        let p = Policy::default();
        assert!(is_id_allowed(&p, "abc"));
    }
}
