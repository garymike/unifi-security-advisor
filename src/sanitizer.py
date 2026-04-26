"""
Shared sanitization module.

Imported by src/unifi_audit.py (live API audit) and src/parser.py (Phase 4
backup parser). This is the single source of truth for SECRET_FIELD_NAMES,
_fingerprint(), and sanitize().

Security contract (per docs/05-credential-handling.md, C-cred-005):
- Any value under a SECRET_FIELD_NAMES key is replaced with a non-reversible
  fingerprint dict (length + sha256 prefix + character-class hints) BEFORE
  any data crosses a trust boundary (disk write, log line, network send).
- Sanitization is idempotent: sanitize(sanitize(x)) == sanitize(x).
- The redact_pii flag is opt-in; by default PII (hostnames, names, notes)
  passes through unchanged. Backup mode (parser.py) sets redact_pii=True
  when producing fixtures intended for sharing.
"""
from __future__ import annotations

import hashlib
from typing import Any

# Union of historical sets in src/unifi_audit.py:183-188 and src/parser.py:103-116,
# expanded with camelCase variants seen in the UniFi Network Integration v1 API.
# Source: 01-RESEARCH.md Pitfall 4; codebase grep verified union.
SECRET_FIELD_NAMES: frozenset[str] = frozenset({
    # snake_case (classic API + backup BSON)
    "x_passphrase",
    "x_passphrase_rollover",
    "x_radius_secret",
    "x_shared_secret",
    "x_ssh_password",
    "x_iapp_key",
    "password",
    "x_auth_key",
    "auth_key",
    "private_key",
    "api_key",
    "token",
    "passphrase",
    "psk",
    "pre_shared_key",
    "wpa_psk",
    # camelCase (Integration v1 API)
    "preSharedKey",
    "presharedKey",
    "privateKey",
    "sharedSecret",
    "radiusSecret",
    "sshPassword",
    "authKey",
    "iappKey",
    "apiKey",
    "wifiPassword",
})


def _fingerprint(value: Any) -> dict[str, Any]:
    """Return a non-reversible fingerprint for a secret value.

    For string values, returns length + 12-char sha256 prefix + character-class
    hints. For non-strings, returns a redaction marker.
    """
    if not isinstance(value, str):
        return {"type": type(value).__name__, "redacted": True}
    return {
        "length": len(value),
        "fingerprint": hashlib.sha256(value.encode()).hexdigest()[:12],
        "has_symbols": any(not c.isalnum() for c in value),
        "has_digits": any(c.isdigit() for c in value),
        "has_mixed_case": (
            any(c.isupper() for c in value) and any(c.islower() for c in value)
        ),
    }


def sanitize(obj: Any, redact_pii: bool = False) -> Any:
    """Recursively sanitize a JSON-shaped value.

    Args:
        obj: Any JSON-decodable Python value (dict / list / scalar).
        redact_pii: If True, also replace hostname/name/note string values with
            a length-only marker. Default False.

    Returns:
        A new value with the same structure where every key in SECRET_FIELD_NAMES
        has its value replaced by _fingerprint(value), and (if redact_pii=True)
        PII fields are length-redacted.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in SECRET_FIELD_NAMES:
                out[k] = _fingerprint(v) if isinstance(v, str) else {"redacted": True}
            elif redact_pii and k in {"hostname", "note", "name"} and isinstance(v, str):
                out[k] = f"<redacted:{len(v)} chars>"
            else:
                out[k] = sanitize(v, redact_pii)
        return out
    if isinstance(obj, list):
        return [sanitize(i, redact_pii) for i in obj]
    return obj
