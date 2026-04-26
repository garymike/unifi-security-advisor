---
phase: 01-live-api-audit
plan: "01"
subsystem: sanitization
tags: [python, security, sanitization, pytest, scaffold, tdd]
dependency_graph:
  requires: []
  provides:
    - src/sanitizer.py (SECRET_FIELD_NAMES, _fingerprint, sanitize)
    - tests/conftest.py (synthetic_api_dump, canonical_api_dump, tagged_secret_blob)
    - tests/test_sanitizer.py
    - tests/test_fixture_safety.py
  affects:
    - src/unifi_audit.py (now imports from sanitizer)
    - src/parser.py (now imports from sanitizer)
    - All Phase 1 plans (depend on stable sanitizer import path)
tech_stack:
  added:
    - pytest 9.0.3 (dev-only)
    - pytest-cov 7.1.0 (dev-only)
    - hypothesis 6.152.2 (dev-only)
  patterns:
    - frozenset for immutable shared constant (SECRET_FIELD_NAMES)
    - try/except import for script+package dual-mode compatibility
    - pytest.skip for fixture-absent gates
    - hypothesis @given for property-based sanitizer fuzz
key_files:
  created:
    - src/sanitizer.py (108 lines)
    - tests/conftest.py (92 lines)
    - tests/test_sanitizer.py (193 lines)
    - tests/test_fixture_safety.py (107 lines)
    - pyproject.toml (8 lines)
    - requirements-dev.txt (5 lines)
    - tests/__init__.py (empty)
    - tests/fixtures/.gitignore
    - samples/fixtures/.gitkeep
  modified:
    - src/unifi_audit.py (removed 34-line local sanitization block; added import)
    - src/parser.py (removed 46-line local sanitization block; added import)
decisions:
  - "D-09: Extract src/sanitizer.py first — both unifi_audit.py and parser.py import from it"
  - "frozenset chosen over set for SECRET_FIELD_NAMES: immutable, prevents silent runtime appends"
  - "try/except import pattern chosen for dual script/package mode compatibility"
  - "idempotency fix: sanitize() passes-through dict values under SECRET_FIELD_NAMES keys (already sanitized) rather than re-wrapping as {redacted:True}"
metrics:
  duration: "5 minutes 25 seconds"
  completed: "2026-04-26T12:46:44Z"
  tasks_completed: 5
  files_created: 9
  files_modified: 2
  test_count: 50
  tests_passing: 45
  tests_skipping: 5
  coverage: "96% on src/sanitizer.py"
---

# Phase 1 Plan 01: Extract Sanitizer Summary

**One-liner:** Extracted shared `src/sanitizer.py` with 26-entry frozenset (snake_case + camelCase Integration v1 variants), eliminating DRY violation between unifi_audit.py and parser.py, and stood up pytest infrastructure with tagged-secret round-trip + hypothesis property tests at 96% coverage.

## Tasks Completed

| Task | Name | Commit | Key Output |
|------|------|--------|-----------|
| 1 | Create src/sanitizer.py | 84fcb87 | 26-entry SECRET_FIELD_NAMES frozenset, _fingerprint, sanitize |
| 2 | Replace local sanitization in unifi_audit.py and parser.py | d30e60f | DRY violation closed; both files import from sanitizer |
| 3 | pytest scaffold | ef8ae2f | pyproject.toml, requirements-dev.txt, conftest.py, gitignores |
| 4 | tests/test_sanitizer.py | 3c3afa3 | 45 tests, 96% coverage, hypothesis property tests |
| 5 | tests/test_fixture_safety.py | ebec8bc | Pre-commit fixture gate, 5 tests skip cleanly pre-Plan 08 |

## Key Outputs

### SECRET_FIELD_NAMES Count Delta

- `src/parser.py` (old): 12 entries (snake_case only)
- `src/unifi_audit.py` (old): 19 entries (snake_case + some camelCase)
- `src/sanitizer.py` (new): **26 entries** — union of both + 10 camelCase Integration v1 variants

New camelCase additions that close T-1-01: `preSharedKey`, `presharedKey`, `sharedSecret`, `radiusSecret`, `sshPassword`, `authKey`, `iappKey`, `wifiPassword` (plus `privateKey` and `apiKey` that were already in unifi_audit but missing from parser).

### pytest Version and Coverage

- pytest 9.0.3
- pytest-cov 7.1.0
- hypothesis 6.152.2
- Coverage on `src/sanitizer.py`: **96%** (threshold: 95%)
- 45 tests pass, 5 skip (fixture-safety tests skip cleanly pre-Plan 08)

### DRY Violation Status

Closed. Verified:
- `grep -c "^SECRET_FIELD_NAMES" src/sanitizer.py` → 1
- `grep -c "^SECRET_FIELD_NAMES" src/unifi_audit.py` → 0
- `grep -c "^SECRET_FIELD_NAMES" src/parser.py` → 0

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed idempotency break for non-string secret values under SECRET_FIELD_NAMES keys**

- **Found during:** Task 4 (hypothesis `test_sanitize_is_idempotent` falsified with `{'private_key': ''}`)
- **Issue:** The original plan's `sanitize()` implementation used `_fingerprint(v) if isinstance(v, str) else {"redacted": True}`. When `v` is an empty string, `sanitize()` returns a fingerprint dict. On the second pass, the fingerprint dict is not a string, so the code returns `{"redacted": True}` — a different dict. This broke `sanitize(sanitize(x)) == sanitize(x)`.
- **Fix:** Added a third branch: if `v` is already a dict (already sanitized), pass it through unchanged via `out[k] = v`. Non-dict, non-string values still get `{"type": <name>, "redacted": True}`.
- **Files modified:** `src/sanitizer.py` (lines 92-98)
- **Commit:** 3c3afa3 (bundled with test file commit)

**2. [Rule 3 - Blocking] Coverage module path corrected**

- **Found during:** Task 4 (first coverage run)
- **Issue:** Plan specified `--cov=src/sanitizer` but pyproject.toml sets `pythonpath = ["src"]`, so pytest imports the module as `sanitizer` not `src.sanitizer`. Coverage couldn't find `src/sanitizer` as a module name.
- **Fix:** Used `--cov=sanitizer` (matching the module name after pythonpath resolution). Coverage correctly reports `src\sanitizer.py` in the output.
- **Impact:** No code change; command-line argument only.

## Threat Mitigations Delivered

| Threat | Mitigation | Verification |
|--------|-----------|--------------|
| T-1-01: Sanitization bypass on camelCase API field names | 10 camelCase variants added to SECRET_FIELD_NAMES frozenset; parametrized test_camelcase_secret_field_redacted covers all 10 | `grep -c "preSharedKey" src/sanitizer.py` → 1; 45 tests pass |
| T-1-03: Fixture commit leak | tests/test_fixture_safety.py walks committed JSON and fails if raw string under SECRET_FIELD_NAMES key; skips cleanly pre-Plan 08 | `pytest -q tests/test_fixture_safety.py` → 5 skipped, exit 0 |

## Known Stubs

None. All exports (`SECRET_FIELD_NAMES`, `_fingerprint`, `sanitize`) are fully implemented with real behavior.

The `canonical_api_dump` fixture in `tests/conftest.py` is intentionally skip-safe (returns `pytest.skip()` when the fixture file doesn't exist). This is by design — the file lands in Plan 08.

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries introduced. `sanitizer.py` is a pure function module with no I/O.

## Self-Check: PASSED

Files exist:
- `src/sanitizer.py`: FOUND
- `tests/conftest.py`: FOUND
- `tests/test_sanitizer.py`: FOUND
- `tests/test_fixture_safety.py`: FOUND
- `pyproject.toml`: FOUND
- `requirements-dev.txt`: FOUND
- `samples/fixtures/.gitkeep`: FOUND
- `tests/fixtures/.gitignore`: FOUND

Commits exist:
- 84fcb87 (Task 1): FOUND
- d30e60f (Task 2): FOUND
- ef8ae2f (Task 3): FOUND
- 3c3afa3 (Task 4): FOUND
- ebec8bc (Task 5): FOUND

All 50 tests pass or skip as expected (45 pass, 5 skip).
