"""Sanitizer unit + property tests.

Mitigates T-1-01 (sanitization bypass on a new field name) by:
1. Tagged-secret round-trip across the full SECRET_FIELD_NAMES set
2. Property-based fuzz with hypothesis on dict shapes
3. Explicit camelCase coverage (the leak vector that motivated D-09)
"""
from __future__ import annotations

import json

import pytest
from hypothesis import given, settings, strategies as st

from sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize


# --- Tagged-secret round-trip (T-1-01 primary mitigation) -------------------

def test_tagged_secret_never_leaks_via_sanitize(tagged_secret_blob):
    TAG, blob = tagged_secret_blob
    result = sanitize(blob)
    serialized = json.dumps(result)
    assert TAG not in serialized, (
        f"Tagged secret leaked under one of: "
        f"{[k for k, v in result.items() if isinstance(v, str) and TAG in v]}"
    )


def test_tagged_secret_never_leaks_under_nested_dict(tagged_secret_blob):
    TAG, blob = tagged_secret_blob
    nested = {"site_x": {"wlans": {"data": [blob]}}}
    result = sanitize(nested)
    assert TAG not in json.dumps(result)


def test_tagged_secret_never_leaks_under_list_of_lists(tagged_secret_blob):
    TAG, blob = tagged_secret_blob
    nested = [[blob], [blob]]
    result = sanitize(nested)
    assert TAG not in json.dumps(result)


# --- Camel-case coverage (the regression D-09 was extracted to prevent) -----

CAMEL_CASE_SECRETS = [
    "preSharedKey", "presharedKey", "sharedSecret", "radiusSecret",
    "sshPassword", "authKey", "iappKey", "privateKey", "apiKey", "wifiPassword",
]


@pytest.mark.parametrize("key", CAMEL_CASE_SECRETS)
def test_camelcase_secret_field_redacted(key):
    val = "MyVeryRealSecretValue1234"
    out = sanitize({key: val})
    assert isinstance(out[key], dict), f"{key} returned a {type(out[key])}, expected dict fingerprint"
    assert "length" in out[key] or "redacted" in out[key]
    assert out[key].get("length") == len(val) or out[key].get("redacted") is True
    assert val not in json.dumps(out)


SNAKE_CASE_SECRETS = [
    "x_passphrase", "x_radius_secret", "x_shared_secret", "x_ssh_password",
    "x_iapp_key", "password", "x_auth_key", "auth_key", "private_key",
    "api_key", "token", "passphrase", "psk", "pre_shared_key", "wpa_psk",
]


@pytest.mark.parametrize("key", SNAKE_CASE_SECRETS)
def test_snake_case_secret_field_redacted(key):
    val = "MyVeryRealSecretValue1234"
    out = sanitize({key: val})
    assert isinstance(out[key], dict)
    assert val not in json.dumps(out)


# --- PII flag behaviour ------------------------------------------------------

def test_redact_pii_off_by_default():
    out = sanitize({"name": "Alice", "hostname": "alice.lan", "note": "hi"})
    assert out == {"name": "Alice", "hostname": "alice.lan", "note": "hi"}


def test_redact_pii_on_replaces_strings():
    out = sanitize({"name": "Alice", "hostname": "alice.lan"}, redact_pii=True)
    assert out["name"] == "<redacted:5 chars>"
    assert out["hostname"] == "<redacted:9 chars>"


def test_redact_pii_does_not_touch_non_strings():
    out = sanitize({"name": 42}, redact_pii=True)
    assert out == {"name": 42}


# --- Edge cases --------------------------------------------------------------

def test_non_string_secret_marked_redacted():
    out = sanitize({"password": 12345})
    assert isinstance(out["password"], dict)
    assert out["password"].get("redacted") is True


def test_none_secret_marked_redacted():
    out = sanitize({"password": None})
    assert isinstance(out["password"], dict)
    assert out["password"].get("redacted") is True


def test_empty_dict():
    assert sanitize({}) == {}


def test_empty_list():
    assert sanitize([]) == []


def test_scalar_passes_through():
    assert sanitize("hello") == "hello"
    assert sanitize(42) == 42
    assert sanitize(None) is None


def test_nested_secret_at_depth():
    out = sanitize({"a": {"b": {"c": {"x_passphrase": "deep_secret"}}}})
    assert "deep_secret" not in json.dumps(out)
    assert isinstance(out["a"]["b"]["c"]["x_passphrase"], dict)


def test_list_of_dicts_with_secrets():
    out = sanitize([{"x_passphrase": "s1"}, {"x_passphrase": "s2"}])
    assert "s1" not in json.dumps(out)
    assert "s2" not in json.dumps(out)


# --- Fingerprint properties --------------------------------------------------

def test_fingerprint_deterministic():
    assert _fingerprint("hello") == _fingerprint("hello")


def test_fingerprint_different_for_different_inputs():
    a = _fingerprint("hello")
    b = _fingerprint("world")
    assert a["fingerprint"] != b["fingerprint"]


def test_fingerprint_non_reversible():
    fp = _fingerprint("MySecretPassword123!")
    serialized = json.dumps(fp)
    assert "MySecretPassword123!" not in serialized
    assert len(fp["fingerprint"]) == 12  # only sha256 prefix


def test_fingerprint_character_class_hints():
    fp = _fingerprint("aB3!")
    assert fp["has_mixed_case"] is True
    assert fp["has_digits"] is True
    assert fp["has_symbols"] is True


# --- Property tests (hypothesis) --------------------------------------------

@given(st.dictionaries(
    st.text(min_size=1, max_size=30),
    st.one_of(st.text(), st.integers(), st.none(), st.booleans()),
    min_size=0,
    max_size=20,
))
@settings(max_examples=200, deadline=None)
def test_sanitize_is_idempotent(input_dict):
    once = sanitize(input_dict)
    twice = sanitize(once)
    assert once == twice


@given(st.fixed_dictionaries({
    k: st.text(min_size=1, max_size=200)
    for k in list(sorted(SECRET_FIELD_NAMES))[:8]
}))
@settings(max_examples=200, deadline=None)
def test_sanitize_never_leaks_known_secret_fields(secret_dict):
    result = sanitize(secret_dict)
    for key in secret_dict:
        if key in SECRET_FIELD_NAMES:
            val = result[key]
            assert isinstance(val, dict), f"Key {key!r} returned non-dict {type(val).__name__}"


def test_secret_field_names_includes_camelcase():
    """Regression: D-09 expansion must include camelCase variants."""
    must_have = {"preSharedKey", "sharedSecret", "radiusSecret", "sshPassword"}
    missing = must_have - SECRET_FIELD_NAMES
    assert not missing, f"SECRET_FIELD_NAMES missing camelCase variants: {missing}"


# --- Coverage gap completions (Acceptance Bar condition 8: >= 95%) -----------

def test_fingerprint_non_string_returns_redacted_type_marker():
    """Line 64: _fingerprint() with a non-string input returns type+redacted marker."""
    result = _fingerprint(99)
    assert result == {"type": "int", "redacted": True}

    result_none = _fingerprint(None)
    assert result_none == {"type": "NoneType", "redacted": True}

    result_list = _fingerprint([1, 2])
    assert result_list == {"type": "list", "redacted": True}


def test_sanitize_idempotency_dict_passthrough():
    """Line 98: a value under a secret key that is already a dict passes through unchanged.

    This is the idempotency guarantee: sanitize(sanitize(x)) == sanitize(x).
    When a secret field's value is already a fingerprint dict, it is not re-fingerprinted.
    """
    already_sanitized = {
        "x_passphrase": {
            "length": 16,
            "fingerprint": "abc123def456",
            "has_symbols": True,
            "has_digits": True,
            "has_mixed_case": True,
        }
    }
    result = sanitize(already_sanitized)
    # Must pass through unchanged (idempotent)
    assert result["x_passphrase"] == already_sanitized["x_passphrase"]
    # And sanitize(sanitize(x)) == sanitize(x)
    assert sanitize(result) == result
