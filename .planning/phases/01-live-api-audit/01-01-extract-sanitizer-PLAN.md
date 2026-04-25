---
phase: 01-live-api-audit
plan: 01
type: execute
wave: 0
depends_on: []
files_modified:
  - src/sanitizer.py
  - src/unifi_audit.py
  - src/parser.py
  - pyproject.toml
  - requirements-dev.txt
  - tests/__init__.py
  - tests/conftest.py
  - tests/test_sanitizer.py
  - tests/test_fixture_safety.py
  - tests/fixtures/.gitignore
  - samples/fixtures/.gitkeep
autonomous: true
requirements:
  - REQ-validation-sanitization-coverage
  - REQ-test-fixtures
requirements_addressed:
  - REQ-validation-sanitization-coverage
  - REQ-test-fixtures
threat_refs: [T-1-01, T-1-03]
tags: [python, security, sanitization, pytest, scaffold]

must_haves:
  truths:
    - "src/sanitizer.py exports SECRET_FIELD_NAMES, _fingerprint, sanitize"
    - "src/unifi_audit.py imports sanitize from sanitizer (no local definitions)"
    - "src/parser.py imports sanitize from sanitizer (no local definitions)"
    - "Sanitizer SECRET_FIELD_NAMES contains both snake_case and camelCase variants"
    - "pytest is configured and tests/ directory runs"
    - "test_sanitizer.py tagged-secret round-trip test passes"
    - "test_fixture_safety.py refuses to pass if a committed fixture contains a raw secret"
  artifacts:
    - path: "src/sanitizer.py"
      provides: "Shared sanitization module"
      exports: ["SECRET_FIELD_NAMES", "_fingerprint", "sanitize"]
      min_lines: 60
    - path: "tests/conftest.py"
      provides: "Shared pytest fixtures"
      exports: ["synthetic_api_dump", "tagged_secret_blob"]
    - path: "tests/test_sanitizer.py"
      provides: "Sanitizer unit + property tests"
      contains: "test_tagged_secret"
    - path: "tests/test_fixture_safety.py"
      provides: "Pre-commit gate scanning fixtures for raw secrets"
    - path: "pyproject.toml"
      provides: "[tool.pytest.ini_options] section"
    - path: "requirements-dev.txt"
      provides: "pytest, pytest-cov, hypothesis pins"
  key_links:
    - from: "src/unifi_audit.py"
      to: "src/sanitizer.py"
      via: "from sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize"
      pattern: "from sanitizer import"
    - from: "src/parser.py"
      to: "src/sanitizer.py"
      via: "from sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize"
      pattern: "from sanitizer import"
    - from: "tests/test_sanitizer.py"
      to: "src/sanitizer.py"
      via: "import sanitizer"
      pattern: "import sanitizer|from sanitizer"
---

<objective>
Eliminate the duplicate sanitization implementations (CONCERNS.md DRY violation) by extracting a single shared module `src/sanitizer.py`, expanding `SECRET_FIELD_NAMES` to include camelCase variants used by the Integration v1 API, and standing up the pytest infrastructure that all subsequent Phase 1 plans rely on. This is Wave 0 — every other plan in this phase depends on the import path being stable and on tests existing to verify the work.

Purpose: Closes the highest-risk leak path (T-1-01 sanitization bypass on a camelCase field, T-1-03 fixture commit leak) before any new code is written that touches the sanitization surface. Ships the test scaffold so later plans can add assertions immediately.

Output:
- `src/sanitizer.py` — canonical sanitizer with snake_case + camelCase secret field names
- `src/unifi_audit.py` — imports replaced; local definitions removed
- `src/parser.py` — imports replaced; local definitions removed
- `tests/` directory with conftest.py, test_sanitizer.py (tagged-secret + property tests), test_fixture_safety.py (the gate that will block Plan 08 from committing an unsafe fixture)
- `pyproject.toml` with `[tool.pytest.ini_options]`
- `requirements-dev.txt` with `pytest`, `pytest-cov`, `hypothesis` pinned
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/STATE.md
@.planning/phases/01-live-api-audit/01-CONTEXT.md
@.planning/phases/01-live-api-audit/01-RESEARCH.md
@.planning/phases/01-live-api-audit/01-VALIDATION.md
@.planning/codebase/CONCERNS.md
@.planning/codebase/TESTING.md
@CLAUDE.md
@DECISIONS.md

<interfaces>
<!-- Existing definitions in the two files being deduplicated. Both are byte-for-byte
     equivalent for the SECRET_FIELD_NAMES set (parser has 12 entries; unifi_audit
     has 20). The new sanitizer.py is the union plus camelCase variants. -->

From src/unifi_audit.py (lines 183-216) — to be REMOVED in this plan:
```python
SECRET_FIELD_NAMES = {
    "x_passphrase", "x_passphrase_rollover", "x_radius_secret", "x_shared_secret",
    "x_ssh_password", "x_iapp_key", "password", "x_auth_key", "auth_key",
    "private_key", "api_key", "token", "passphrase", "preSharedKey", "presharedKey",
    "psk", "pre_shared_key", "privateKey", "wpa_psk",
}

def _fingerprint(value: Any) -> dict[str, Any]: ...   # 191-202
def sanitize(obj: Any) -> Any: ...                    # 205-216
```

From src/parser.py (lines 103-148) — to be REMOVED in this plan:
```python
SECRET_FIELD_NAMES = {
    "x_passphrase", "x_passphrase_rollover", "x_radius_secret", "x_shared_secret",
    "x_ssh_password", "x_iapp_key", "password", "x_auth_key", "auth_key",
    "private_key", "api_key", "token",
}
def _fingerprint(value: str) -> dict[str, Any]: ...   # 119-131
def sanitize(obj: Any, redact_pii: bool = False) -> Any: ...  # 134-148  (note: takes redact_pii)
```

Note: parser.sanitize accepts an optional `redact_pii: bool = False` parameter that the audit script does not use. The new sanitizer.py preserves this parameter — calls from unifi_audit.py omit it (defaults to False), calls from parser.py pass it through.
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Create src/sanitizer.py with union secret-field set + camelCase variants</name>
  <files>src/sanitizer.py</files>
  <read_first>
    - src/unifi_audit.py (lines 183-216) — current definitions
    - src/parser.py (lines 103-148) — current definitions including redact_pii
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (Pattern 1 §"Sanitizer Extraction (D-09)" and Pitfall 4 §"Sanitizer Misses New Secret Field Names")
    - CLAUDE.md (Constraint 3: All outputs are sanitized)
    - docs/05-credential-handling.md (authoritative source for sanitization contract)
  </read_first>
  <behavior>
    - sanitize({"x_passphrase": "MySecretPSK1234"}) returns {"x_passphrase": {"length": 15, "fingerprint": <12-char hex>, ...}} — no raw string
    - sanitize({"preSharedKey": "MySecretPSK1234"}) returns the same fingerprint shape (camelCase variant covered)
    - sanitize({"sharedSecret": "RadiusSecret999"}) returns fingerprint shape (new camelCase secret)
    - sanitize({"name": "Living Room"}, redact_pii=False) returns {"name": "Living Room"} (PII pass-through unless flag set)
    - sanitize({"name": "Living Room"}, redact_pii=True) returns {"name": "<redacted:11 chars>"}
    - sanitize(sanitize(x)) == sanitize(x) for any input (idempotent)
    - sanitize on non-string secret value returns {"redacted": True} or {"type": <type-name>, "redacted": True}
    - _fingerprint returns dict with keys: length, fingerprint, has_symbols, has_digits, has_mixed_case
  </behavior>
  <action>
Create the file at `src/sanitizer.py` with the exact content below. The SECRET_FIELD_NAMES set is the UNION of the current two implementations PLUS the camelCase variants identified in RESEARCH.md Pitfall 4 (per T-1-01 mitigation). Use `frozenset` (immutable, satisfies "no new entries silently appended at runtime"). Include `from __future__ import annotations`. Type hints on every function. Docstrings on the module and on every public function.

```python
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
```

Do NOT add any other public functions. Do NOT remove the `redact_pii` parameter — `parser.py` consumers (Phase 4) need it.
  </action>
  <verify>
    <automated>python -c "from src.sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize; assert 'preSharedKey' in SECRET_FIELD_NAMES; assert 'sharedSecret' in SECRET_FIELD_NAMES; assert sanitize({'preSharedKey':'abc12345'})['preSharedKey']['length']==8; print('OK')"</automated>
  </verify>
  <acceptance_criteria>
    - File `src/sanitizer.py` exists
    - `grep -c "preSharedKey" src/sanitizer.py` returns ≥ 1
    - `grep -c "sharedSecret" src/sanitizer.py` returns ≥ 1
    - `grep -c "x_passphrase" src/sanitizer.py` returns ≥ 1 (back-compat preserved)
    - `grep -c "redact_pii" src/sanitizer.py` returns ≥ 2 (parameter present and used)
    - Python statement `from src.sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize` succeeds
    - `sanitize({'preSharedKey':'MySecret1234567'})['preSharedKey']` is a dict containing key `length` with value 15
  </acceptance_criteria>
  <done>src/sanitizer.py exports SECRET_FIELD_NAMES (frozenset, ≥26 entries including camelCase), _fingerprint, sanitize. Idempotent. redact_pii param preserved.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Replace local sanitization in unifi_audit.py and parser.py with imports</name>
  <files>src/unifi_audit.py, src/parser.py</files>
  <read_first>
    - src/sanitizer.py (just created in Task 1)
    - src/unifi_audit.py (lines 178-216, plus all call sites of `sanitize` and `SECRET_FIELD_NAMES`)
    - src/parser.py (lines 96-148, plus all call sites)
  </read_first>
  <behavior>
    - After this change, `python -c "import src.unifi_audit"` succeeds with no NameError
    - `grep -n "^SECRET_FIELD_NAMES" src/unifi_audit.py` returns zero matches (definition removed)
    - `grep -n "^def _fingerprint" src/unifi_audit.py` returns zero matches
    - `grep -n "^def sanitize" src/unifi_audit.py` returns zero matches
    - Same three checks for src/parser.py return zero
    - `grep -n "from sanitizer import" src/unifi_audit.py` returns ≥ 1 match
    - `grep -n "from sanitizer import" src/parser.py` returns ≥ 1 match
    - parser.py call site `sanitize(obj, redact_pii=True)` still works (the param is in the imported function)
  </behavior>
  <action>
In `src/unifi_audit.py`:

1. Add an import. The existing imports use bare module names (e.g., `import hashlib`). Since `src/` is the package root and modules are run as scripts, use a try/except import pattern that works both as `python src/unifi_audit.py` (script) and `python -m src.unifi_audit` (module):

```python
try:
    from sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize  # script mode
except ImportError:
    from src.sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize  # package mode
```

Place this import block immediately after the third-party imports (after the `requests` block ending around line 60).

2. Delete lines 183-216 from `src/unifi_audit.py` (the `SECRET_FIELD_NAMES = {...}` set, the `_fingerprint` function, and the `sanitize` function). Keep the surrounding section header comments intact, but remove the bodies.

3. Verify all internal references still resolve. Search for `SECRET_FIELD_NAMES`, `_fingerprint`, and `sanitize` — they should now resolve to the imported names. The call site at line 652 (`clean = sanitize(raw)`) needs no change.

In `src/parser.py`:

1. Add the same try/except import block after the third-party imports (Crypto.Cipher.AES / pymongo).

2. Delete lines 103-148 (the `SECRET_FIELD_NAMES = {...}` set, `_fingerprint`, and `sanitize` function). Keep the section comment "# 2. SANITIZATION" but remove the body.

3. Confirm any internal call to `sanitize(obj, redact_pii=True)` in parser.py still works — the imported function accepts the `redact_pii` kwarg.

Do NOT modify the `Finding` dataclass in either file. Do NOT change any function signature. Do NOT change `findings_enhanced.py` (D-01 keeps it untouched).
  </action>
  <verify>
    <automated>python -c "import sys; sys.path.insert(0, 'src'); import unifi_audit; assert 'preSharedKey' in unifi_audit.SECRET_FIELD_NAMES; assert callable(unifi_audit.sanitize); print('unifi_audit OK'); import parser; assert 'preSharedKey' in parser.SECRET_FIELD_NAMES; assert callable(parser.sanitize); s = parser.sanitize({'name': 'A'}, redact_pii=True); assert s == {'name': '<redacted:1 chars>'}; print('parser OK')"</automated>
  </verify>
  <acceptance_criteria>
    - `grep -E "^SECRET_FIELD_NAMES\\s*=" src/unifi_audit.py` returns zero matches
    - `grep -E "^def _fingerprint" src/unifi_audit.py` returns zero matches
    - `grep -E "^def sanitize" src/unifi_audit.py` returns zero matches
    - `grep -E "^SECRET_FIELD_NAMES\\s*=" src/parser.py` returns zero matches
    - `grep -E "^def _fingerprint" src/parser.py` returns zero matches
    - `grep -E "^def sanitize" src/parser.py` returns zero matches
    - `grep "from sanitizer import" src/unifi_audit.py` returns ≥ 1 match
    - `grep "from sanitizer import" src/parser.py` returns ≥ 1 match
    - `python -c "import sys; sys.path.insert(0,'src'); import unifi_audit, parser; print('OK')"` exits 0
    - parser.sanitize({'name':'A'}, redact_pii=True) returns {'name': '<redacted:1 chars>'}
  </acceptance_criteria>
  <done>Both files import sanitizer; no duplicate definitions; existing call sites still resolve; redact_pii kwarg path preserved in parser.py.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: pytest scaffold (pyproject.toml, requirements-dev.txt, tests/conftest.py, .gitignore for tests/fixtures)</name>
  <files>pyproject.toml, requirements-dev.txt, tests/__init__.py, tests/conftest.py, tests/fixtures/.gitignore, samples/fixtures/.gitkeep</files>
  <read_first>
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"pytest Infrastructure Patterns", §"conftest.py — Canonical Fixture Loader")
    - .planning/phases/01-live-api-audit/01-VALIDATION.md (§"Wave 0 Requirements")
    - CLAUDE.md (Code conventions: pytest is dev-only)
  </read_first>
  <behavior>
    - `pytest --version` reports a 9.x version
    - `pytest -q tests/` discovers and exits 0 (no tests yet, or only the ones from Task 4 if run after)
    - `tests/fixtures/` is gitignored except for the .gitignore itself
    - `samples/fixtures/` directory exists and is committable (placeholder .gitkeep present)
    - `synthetic_api_dump` fixture is importable from conftest
  </behavior>
  <action>
1. Create `pyproject.toml` at the repo root with this content (only the pytest section; this project does not use a build backend yet, so do NOT add `[build-system]` or `[project]`):

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short --strict-markers"
pythonpath = ["src"]
markers = [
    "manual: marks tests that require human action (real network, real backup file)",
]
```

The `pythonpath = ["src"]` line is critical — it lets test files write `from sanitizer import sanitize` instead of `from src.sanitizer import sanitize`.

2. Create `requirements-dev.txt` at the repo root:

```
# Phase 1 dev dependencies — pytest is dev-only per CLAUDE.md C-code-001
# Runtime deps stay stdlib + requests + pycryptodome + pymongo only.
pytest>=9.0,<10
pytest-cov>=5.0
hypothesis>=6.100
```

3. Create `tests/__init__.py` (empty file — makes tests/ importable for some test runners; harmless if pytest doesn't need it).

4. Create `tests/conftest.py`:

```python
"""Shared pytest fixtures for Phase 1 tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_FIXTURE = REPO_ROOT / "samples" / "fixtures" / "api_dump_home_office.json"
TESTS_FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def canonical_api_dump() -> dict:
    """Load the committed canonical fixture if it exists; skip the test otherwise.

    Plan 08 commits this file. Tests that depend on it before Plan 08 lands
    will skip cleanly, not fail.
    """
    if not CANONICAL_FIXTURE.exists():
        pytest.skip(f"Canonical fixture not yet captured: {CANONICAL_FIXTURE}")
    return json.loads(CANONICAL_FIXTURE.read_text())


@pytest.fixture
def synthetic_api_dump() -> dict:
    """Minimal synthetic API dump shaped like collect_all() output post-sanitize.

    No real data. Safe for unit tests that need a non-empty pipeline input.
    """
    return {
        "_endpoints_probed": [{"name": "sites", "status": 200}],
        "_errors": [],
        "_site_count": 1,
        "site_default": {
            "_meta": {"id": "default", "name": "test-site"},
            "devices": {
                "data": [
                    {
                        "macAddress": "02:00:00:00:00:01",
                        "ipAddress": "192.0.2.10",
                        "model": "U6-Pro",
                        "name": "ap-0",
                        "type": "uap",
                        "state": "connected",
                        "sshEnabled": False,
                        "version": "7.0.66",
                    }
                ],
                "totalCount": 1,
            },
            "wlans": {
                "data": [
                    {
                        "name": "test-ssid",
                        "enabled": True,
                        "security": "wpapsk",
                        "wpa_mode": "wpa2",
                        "x_passphrase": {"length": 18, "fingerprint": "abc123def456",
                                          "has_symbols": True, "has_digits": True,
                                          "has_mixed_case": True},
                        "pmf_mode": "disabled",
                    }
                ],
                "totalCount": 1,
            },
            "networks": {
                "data": [{"name": "main", "purpose": "corporate", "vlan": 1}],
                "totalCount": 1,
            },
            "port_forwards": {"data": [], "totalCount": 0},
            "vpn_configs": {"data": [], "totalCount": 0},
            "firewall_policies": {"data": [], "totalCount": 0},
            "firewall_zones": {"data": [], "totalCount": 0},
            "traffic_routes": {"data": [], "totalCount": 0},
            "clients": {"data": [], "totalCount": 0},
        },
    }


@pytest.fixture
def tagged_secret_blob() -> tuple[str, dict]:
    """Return (TAG, dict) where dict has the tag string injected under each
    SECRET_FIELD_NAMES key. Used for round-trip leak detection in test_sanitizer."""
    TAG = "UNIQUE_SECRET_TAG_7f3a9b2c_DO_NOT_COMMIT"
    # Import lazily so tests can use this fixture even before Task 1's import path is hot
    import sys
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from sanitizer import SECRET_FIELD_NAMES
    blob = {k: TAG for k in sorted(SECRET_FIELD_NAMES)}
    return TAG, blob
```

5. Create `tests/fixtures/.gitignore`:

```
# Real captured fixtures stay local (per D-08).
# Only samples/fixtures/api_dump_home_office.json is committed (in Plan 08).
*
!.gitignore
```

6. Create `samples/fixtures/.gitkeep` (empty file). This makes the directory committable now; the actual `api_dump_home_office.json` lands in Plan 08.

Verify with `pytest -q tests/` — should exit 0 with "no tests ran" or with whatever later tasks add.
  </action>
  <verify>
    <automated>python -c "import subprocess, sys; r = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '-q', 'tests/'], capture_output=True, text=True); assert r.returncode == 0 or 'no tests ran' in r.stdout + r.stderr, r.stdout + r.stderr; print('pytest discovers tests/ OK')"</automated>
  </verify>
  <acceptance_criteria>
    - `pyproject.toml` exists and contains literal string `[tool.pytest.ini_options]`
    - `pyproject.toml` contains `pythonpath = ["src"]`
    - `requirements-dev.txt` exists and contains `pytest`, `pytest-cov`, `hypothesis`
    - `tests/__init__.py` exists (may be empty)
    - `tests/conftest.py` exists and contains `def synthetic_api_dump`
    - `tests/conftest.py` contains `def canonical_api_dump`
    - `tests/conftest.py` contains `def tagged_secret_blob`
    - `tests/fixtures/.gitignore` exists and contains `*` and `!.gitignore`
    - `samples/fixtures/.gitkeep` exists
    - `python -m pytest --collect-only -q tests/` exits 0
  </acceptance_criteria>
  <done>pytest infrastructure present; tests/ discoverable; conftest provides synthetic_api_dump, canonical_api_dump (skip-safe), tagged_secret_blob; tests/fixtures gitignored; samples/fixtures committable directory exists.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 4: tests/test_sanitizer.py — tagged-secret round-trip + property tests + idempotence</name>
  <files>tests/test_sanitizer.py</files>
  <read_first>
    - src/sanitizer.py (Task 1 output)
    - tests/conftest.py (Task 3 output — uses synthetic_api_dump and tagged_secret_blob)
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Property-Based Test for Sanitizer (hypothesis)" and §"Tagged-Secret Round-Trip Test")
  </read_first>
  <behavior>
    - test_tagged_secret_never_leaks: inject TAG into every SECRET_FIELD_NAMES key, sanitize, assert TAG appears nowhere in the JSON-serialized output
    - test_sanitize_is_idempotent: hypothesis-generated dicts → sanitize(sanitize(x)) == sanitize(x)
    - test_camelcase_secrets_redacted: parametrized over preSharedKey, sharedSecret, radiusSecret, sshPassword, authKey, privateKey, apiKey — each value becomes a fingerprint dict, not a raw string
    - test_snake_case_secrets_redacted: same for x_passphrase, x_radius_secret, x_shared_secret, x_ssh_password, password, etc.
    - test_redact_pii_off_by_default: sanitize({"name": "Alice"}) == {"name": "Alice"} (PII pass-through)
    - test_redact_pii_on_replaces_pii: sanitize({"name": "Alice"}, redact_pii=True) == {"name": "<redacted:5 chars>"}
    - test_non_string_secret_marked_redacted: sanitize({"password": 12345}) == {"password": {"redacted": True}} or {"password": {"type": "int", "redacted": True}}
    - test_nested_secrets: sanitize({"a": {"b": {"x_passphrase": "secret"}}}) — nested secret is fingerprinted
    - test_lists_recurse: sanitize([{"x_passphrase": "s1"}, {"x_passphrase": "s2"}]) — both fingerprinted
    - test_fingerprint_deterministic: same input → same fingerprint
    - test_fingerprint_non_reversible: sha256 prefix only, no plaintext
    - All tests pass; coverage on src/sanitizer.py ≥ 95%
  </behavior>
  <action>
Create `tests/test_sanitizer.py` with the content below. Use `hypothesis` for the property tests (already in requirements-dev.txt; install with `pip install -r requirements-dev.txt`). If hypothesis is not installed in the executor's environment, install it before running tests: `pip install hypothesis pytest-cov`.

```python
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
```

After writing the file, run:

```bash
pip install -r requirements-dev.txt
pytest -q tests/test_sanitizer.py --cov=src/sanitizer --cov-report=term-missing
```

Confirm coverage on `src/sanitizer.py` is ≥ 95%.
  </action>
  <verify>
    <automated>pip install -q -r requirements-dev.txt && pytest -q tests/test_sanitizer.py --cov=src/sanitizer --cov-report=term-missing --cov-fail-under=95</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_sanitizer.py` exists
    - `pytest -q tests/test_sanitizer.py` exits 0 (all tests pass)
    - `pytest --cov=src/sanitizer --cov-report=term-missing tests/test_sanitizer.py --cov-fail-under=95` exits 0
    - `grep -c "test_tagged_secret" tests/test_sanitizer.py` returns ≥ 1
    - `grep -c "test_camelcase_secret_field_redacted" tests/test_sanitizer.py` returns ≥ 1
    - `grep -c "@given" tests/test_sanitizer.py` returns ≥ 2 (hypothesis property tests present)
    - `grep -c "test_secret_field_names_includes_camelcase" tests/test_sanitizer.py` returns ≥ 1
  </acceptance_criteria>
  <done>Sanitizer test file exists; all tests pass; coverage ≥ 95% on src/sanitizer.py; tagged-secret round-trip + camelCase + idempotence + property tests all present.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 5: tests/test_fixture_safety.py — pre-commit gate for committed fixtures</name>
  <files>tests/test_fixture_safety.py</files>
  <read_first>
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Pitfall 5: Test Fixture Contains Real Credentials After Sanitization Bug")
    - .planning/phases/01-live-api-audit/01-CONTEXT.md (D-08 fixture spec)
    - tests/conftest.py (CANONICAL_FIXTURE path)
  </read_first>
  <behavior>
    - When `samples/fixtures/api_dump_home_office.json` does not exist (pre-Plan 08): test SKIPS, does not fail
    - When fixture exists with only fingerprint dicts (no raw strings under SECRET_FIELD_NAMES keys): test PASSES
    - When fixture exists and contains a raw string under any SECRET_FIELD_NAMES key: test FAILS with a clear error pointing to the offending key path
    - When fixture exists and contains a string that looks like a high-entropy secret (length > 16, mixed case + digits + symbols, NOT under a known field) under a `note`/`name`/`description` key: test WARNS (uses pytest.warns) but does not fail (PII redaction is opt-in)
    - File size check: fixture must be < 200 KB per D-08
  </behavior>
  <action>
Create `tests/test_fixture_safety.py`:

```python
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
```

This test file is the mitigation for T-1-03. Plan 08 must run `pytest tests/test_fixture_safety.py` and have it pass before committing the fixture.
  </action>
  <verify>
    <automated>pytest -q tests/test_fixture_safety.py</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_fixture_safety.py` exists
    - `pytest -q tests/test_fixture_safety.py` exits 0 (tests skip cleanly because the fixture does not exist yet)
    - `grep -c "SECRET_FIELD_NAMES" tests/test_fixture_safety.py` returns ≥ 1
    - `grep -c "MAX_FIXTURE_BYTES" tests/test_fixture_safety.py` returns ≥ 1
    - `grep -c "test_canonical_fixture_no_raw_secrets" tests/test_fixture_safety.py` returns ≥ 1
    - When invoked with a fixture missing: ALL tests skip; exit 0
    - The test file imports SECRET_FIELD_NAMES from sanitizer (not redefined)
  </acceptance_criteria>
  <done>Pre-commit fixture-safety gate file exists; tests skip cleanly when fixture absent; will fail loudly if Plan 08 commits an unsafe fixture.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Process → disk | Sanitized JSON is written to disk. Anything past this point is at user's discretion to share. |
| Process → log file | Audit log writes endpoint URLs and status codes. Must NOT contain the API key or response body content. |
| Tests → committed fixture | Anything in samples/fixtures/ becomes part of the public git history forever. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-1-01 | Information Disclosure | src/sanitizer.py SECRET_FIELD_NAMES coverage | mitigate | Union of snake_case + camelCase variants in frozenset; tagged-secret round-trip in test_sanitizer; hypothesis property tests prove no raw string survives any known-secret key |
| T-1-03 | Information Disclosure | samples/fixtures/api_dump_home_office.json | mitigate | tests/test_fixture_safety.py walks the JSON and fails loudly if any raw string exists under a SECRET_FIELD_NAMES key. This test is in Wave 0 so Plan 08 cannot commit a fixture that fails it. |
</threat_model>

<verification>
After all tasks complete in this plan:

```bash
# All sanitizer tests pass with high coverage
pytest -q tests/test_sanitizer.py --cov=src/sanitizer --cov-report=term-missing --cov-fail-under=95

# Fixture safety gate is green (skips cleanly pre-Plan 08)
pytest -q tests/test_fixture_safety.py

# Existing modules still import cleanly
python -c "import sys; sys.path.insert(0, 'src'); import unifi_audit, parser; print('OK')"

# DRY violation eliminated — only one definition exists
grep -c "^SECRET_FIELD_NAMES" src/sanitizer.py    # expect 1
grep -c "^SECRET_FIELD_NAMES" src/unifi_audit.py  # expect 0
grep -c "^SECRET_FIELD_NAMES" src/parser.py       # expect 0
```
</verification>

<success_criteria>
- src/sanitizer.py exists with frozenset SECRET_FIELD_NAMES of ≥ 26 entries (snake_case + camelCase)
- src/unifi_audit.py and src/parser.py import from sanitizer; local definitions removed
- pyproject.toml configures pytest with `pythonpath = ["src"]`
- requirements-dev.txt pins pytest, pytest-cov, hypothesis
- tests/conftest.py exposes synthetic_api_dump, canonical_api_dump (skip-safe), tagged_secret_blob
- tests/test_sanitizer.py: tagged-secret round-trip + property + camelCase + idempotence tests; coverage on src/sanitizer.py ≥ 95%
- tests/test_fixture_safety.py: gate that fails if a committed fixture has raw secrets under a known-secret key
- tests/fixtures/.gitignore prevents accidental commits of user-captured dumps
- samples/fixtures/.gitkeep makes the directory committable now
- T-1-01 mitigated by sanitizer + tests; T-1-03 mitigated by fixture safety gate
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-01-SUMMARY.md` with:
- Files created and line counts
- SECRET_FIELD_NAMES count delta (12 + 20 → 26+)
- pytest version and coverage result
- Confirmation that DRY violation is closed (zero definitions outside sanitizer.py)
- Any deviations from the plan and rationale
</output>
