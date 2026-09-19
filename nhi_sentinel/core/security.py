"""Cryptographic helpers: canonical JSON, SHA-256 digests, HMAC signatures (DC15, EX05, SC15)."""
from __future__ import annotations

import hashlib
import hmac
import json

from ..config import get_settings


def canonical_json(obj) -> str:
    """Deterministic serialization used for digests and signatures (EX05 canonicalization)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_of(obj) -> str:
    return sha256_hex(canonical_json(obj))


def hmac_obj(obj, key: str | None = None) -> str:
    secret = (key or get_settings().signing_secret).encode("utf-8")
    return hmac.new(secret, canonical_json(obj).encode("utf-8"), hashlib.sha256).hexdigest()


def sign_artifact(content, redaction_version: str = "1.0") -> tuple[str, str]:
    """DC15: sha256 over canonical content + keyed signature. Returns (sha256, signature)."""
    content_hash = digest_of(content)
    sig = hmac_obj({"content_sha256": content_hash, "redaction_version": redaction_version})
    return content_hash, sig


def verify_artifact(content, sha256: str, signature: str, redaction_version: str = "1.0") -> bool:
    expected_hash = digest_of(content)
    if not hmac.compare_digest(expected_hash, sha256):
        return False
    expected_sig = hmac_obj({"content_sha256": expected_hash, "redaction_version": redaction_version})
    return hmac.compare_digest(expected_sig, signature)


def hash_password(password: str) -> str:
    salt = "nhi-sentinel-static-dev-salt"  # demo only; production uses per-user KDF salt
    return sha256_hex(f"{salt}:{password}")


def verify_password(password: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), password_hash)


def new_token() -> str:
    import secrets
    return secrets.token_urlsafe(32)


# --- SC11 secret minimization -------------------------------------------------
SECRET_FIELD_HINTS = ("secret", "password", "token_value", "private_key", "api_key", "credential_value")
SECRET_PATTERN = __import__("re").compile(
    r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.eyJ)"
)


def redact_dict(obj: dict) -> tuple[dict, int]:
    """Deep-copy redaction of secret-bearing fields; returns (redacted, removed_count).
    Original values never persist (SC11); collectors run this before durable ingest (AR08)."""
    removed = 0

    def _walk(o):
        nonlocal removed
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if any(h in str(k).lower() for h in SECRET_FIELD_HINTS) and isinstance(v, str) and v:
                    out[k] = "[REDACTED]"
                    removed += 1
                else:
                    out[k] = _walk(v)
            return out
        if isinstance(o, list):
            return [_walk(i) for i in o]
        return o

    return _walk(obj), removed


def fingerprint_secret(value: str, tenant_id: str) -> str:
    """DC07: keyed HMAC fingerprint bound to tenant; not recoverable, comparable within tenant (KEY-005)."""
    import hmac as _hmac
    secret = get_settings().signing_secret.encode()
    return _hmac.new(secret, f"{tenant_id}:{value}".encode(), hashlib.sha256).hexdigest()[:40]
