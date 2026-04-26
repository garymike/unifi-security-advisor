"""Fixture-commit safety gate (T-1-03 mitigation).

Plan 08 commits samples/fixtures/api_dump_home_office.json. Before that commit
lands, this test must pass — meaning the file (a) exists, (b) contains only
fingerprint dicts under SECRET_FIELD_NAMES keys, never raw strings, and (c)
is below the 200 KB review-friendliness threshold from D-08.

Pre-Plan 08: this test SKIPS cleanly. After Plan 08: the test gates the commit.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sanitizer import SECRET_FIELD_NAMES

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_FIXTURE = REPO_ROOT / "samples" / "fixtures" / "api_dump_home_office.json"
MAX_FIXTURE_BYTES = 200 * 1024  # 200 KB per D-08


def _walk(obj, path=""):
    """Yield (path, key, value) for every (key, value) in any nested dict."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else k
            yield (new_path, k, v)
            yield from _walk(v, new_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _walk(item, f"{path}[{i}]")


def test_canonical_fixture_exists_or_skip():
    if not CANONICAL_FIXTURE.exists():
        pytest.skip(
            f"Canonical fixture not yet committed: {CANONICAL_FIXTURE}. "
            "This is expected pre-Plan 08."
        )


def test_canonical_fixture_under_size_budget():
    if not CANONICAL_FIXTURE.exists():
        pytest.skip("Fixture not committed yet.")
    size = CANONICAL_FIXTURE.stat().st_size
    assert size < MAX_FIXTURE_BYTES, (
        f"Fixture is {size} bytes (>{MAX_FIXTURE_BYTES} budget per D-08). "
        "Trim it or split into multiple smaller fixtures."
    )


def test_canonical_fixture_no_raw_secrets():
    """Every value under a SECRET_FIELD_NAMES key must be a fingerprint dict, never a raw string."""
    if not CANONICAL_FIXTURE.exists():
        pytest.skip("Fixture not committed yet.")
    data = json.loads(CANONICAL_FIXTURE.read_text())
    leaks = []
    for path, key, value in _walk(data):
        if key in SECRET_FIELD_NAMES:
            if isinstance(value, str):
                leaks.append((path, value[:20]))
            elif isinstance(value, dict):
                # Must look like a fingerprint dict
                if not ({"length", "fingerprint"}.issubset(value.keys()) or value.get("redacted") is True):
                    leaks.append((path, f"unrecognized dict shape: {sorted(value.keys())}"))
    assert not leaks, (
        "Canonical fixture has raw secrets under SECRET_FIELD_NAMES keys:\n"
        + "\n".join(f"  {p}: {v}" for p, v in leaks)
    )


def test_canonical_fixture_is_valid_json():
    if not CANONICAL_FIXTURE.exists():
        pytest.skip("Fixture not committed yet.")
    # Will raise json.JSONDecodeError if invalid
    data = json.loads(CANONICAL_FIXTURE.read_text())
    assert isinstance(data, dict), "Top-level fixture must be a dict (collect_all() output shape)"
    assert "_endpoints_probed" in data, "Fixture missing collect_all metadata key"


def test_canonical_fixture_has_no_obvious_high_entropy_strings_under_pii_keys():
    """Soft check: warn if a 'name', 'hostname', 'note' field contains a string
    that looks like a passphrase (>16 chars, mixed case + digits + symbols)."""
    if not CANONICAL_FIXTURE.exists():
        pytest.skip("Fixture not committed yet.")
    data = json.loads(CANONICAL_FIXTURE.read_text())
    PII_KEYS = {"name", "hostname", "note", "description"}
    suspicious = []
    for path, key, value in _walk(data):
        if key in PII_KEYS and isinstance(value, str) and len(value) > 16:
            has_upper = any(c.isupper() for c in value)
            has_lower = any(c.islower() for c in value)
            has_digit = any(c.isdigit() for c in value)
            has_sym = any(not c.isalnum() and not c.isspace() for c in value)
            if has_upper and has_lower and has_digit and has_sym:
                suspicious.append((path, value[:20] + "..."))
    if suspicious:
        # Soft fail: print a warning but don't block. The anonymizer in Plan 02/08
        # is responsible for catching these intentionally.
        import warnings
        warnings.warn(
            "Suspicious high-entropy strings under PII-class keys (review fixture):\n"
            + "\n".join(f"  {p}: {v}" for p, v in suspicious),
            stacklevel=1,
        )
