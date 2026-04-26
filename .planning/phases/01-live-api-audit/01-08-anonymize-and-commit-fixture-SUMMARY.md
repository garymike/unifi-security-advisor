---
phase: 01-live-api-audit
plan: "08"
subsystem: test-fixtures
tags: [fixture, anonymization, security, sanitization, regression]
dependency_graph:
  requires: [01-07-real-network-validation]
  provides: [samples/fixtures/api_dump_home_office.json, tools/anonymize_fixture.py]
  affects: [tests/test_pipeline_smoke.py, tests/test_sanitizer.py, tests/conftest.py]
tech_stack:
  added: []
  patterns:
    - Deterministic MAC anonymization via sha256 seeding with locally-administered bit set (0x02)
    - RFC 5737 documentation-range IP replacement (192.0.2.x)
    - Counter-keyed device-class-preserving name anonymization (ap-N, switch-N, gateway-N)
    - Layered defense: sanitizer (secrets) + anonymizer (PII) + static safety gate (tests)
key_files:
  created:
    - tools/anonymize_fixture.py
    - samples/fixtures/api_dump_home_office.json
    - .planning/phases/01-live-api-audit/01-08-anonymize-and-commit-fixture-SUMMARY.md
  modified:
    - tests/test_pipeline_smoke.py
    - tests/test_sanitizer.py
decisions:
  - "D-08 LOCKED: canonical fixture committed at samples/fixtures/api_dump_home_office.json; tests/fixtures/raw_sanitized.json gitignored permanently"
  - "Sanitizer coverage gap closed at lines 64 and 98 via explicit tests for _fingerprint(non-string) and idempotency dict passthrough"
  - "Canonical fixture uses site key site_00000000-0000-0000-0000-000000000001 (not site_default) — analyze() handles both shapes"
metrics:
  duration_seconds: ~1800
  completed: "2026-04-26T15:47:58Z"
  tasks_completed: 3
  files_modified: 5
---

# Phase 1 Plan 8: Anonymize and Commit Canonical Fixture — Summary

**One-liner:** Deterministic PII anonymization script committed alongside a 15,012-byte canonical fixture that activates all previously-skipped real-data smoke tests and closes REQ-test-fixtures with sanitizer.py at 100% coverage.

---

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create tools/anonymize_fixture.py | b4e6930, fb903dc | tools/anonymize_fixture.py |
| 2 | Checkpoint: review anonymized output | (checkpoint — user approved) | samples/fixtures/api_dump_home_office.json |
| 3 | Stage fixture + smoke test + coverage | 62e0389, 84a069a | samples/fixtures/api_dump_home_office.json, tests/test_pipeline_smoke.py, tests/test_sanitizer.py |

---

## What Was Built

### tools/anonymize_fixture.py (289 lines)

One-shot idempotent anonymization script. Reads `tests/fixtures/raw_sanitized.json` (gitignored real-network capture from Plan 07) and writes `samples/fixtures/api_dump_home_office.json` (committed canonical fixture). Anonymization strategy:

- **MAC addresses** → locally-administered fake (0x02 bit set, sha256-seeded from original) e.g. `02:a4:9c:...`
- **IPv4 addresses** → RFC 5737 documentation range `192.0.2.x` (last octet preserved for intra-fixture traceability)
- **Device names** → device-class-preserving counters (ap-N for UAP/U6/U7; switch-N for USW; gateway-N for UDM/USG)
- **Hostnames** → `host-N.local`
- **Site names** → `test-site-home-office`
- **Serial numbers** → `SIM-{n:05d}`

Idempotency guaranteed by counter dicts keyed on original value (same input → same output on every run).

### samples/fixtures/api_dump_home_office.json (15,012 bytes)

Committed canonical fixture produced from a real UniFi controller (Network Application ≥9.3.43, home-office deployment). Structure mirrors `collect_all()` output with:

- Site key: `site_00000000-0000-0000-0000-000000000001`
- Endpoints returning HTTP 200: `info`, `sites`, `devices`, `clients`, `networks`
- Endpoints returning HTTP 404: `wlans`, `firewall_policies`, `firewall_zones`, `port_forwards`, `vpn_configs`, `traffic_routes`
- Produces 15 findings when run through `analyze()`: MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001 (always-top unknowns) + SEG-001, CORR-KEYS-001, BAK-001, FW-VER-*, CORR-PIVOT-001, FW-CONTENT-001, FW-AUTO-001, RF-ROGUE-001, FW-GEO-IN, FW-GEO-OUT, LOG-FWD-001, META-COVERAGE

All 5 fixture-safety gate tests pass (no raw secrets, RFC 5737 IPs, locally-administered MACs, under 200 KB, valid JSON).

### test_canonical_fixture_pipeline_smoke (added to tests/test_pipeline_smoke.py)

Runs `analyze()` against the real-data fixture. Asserts:
- ≥ 4 findings returned
- All finding shapes valid (severity in VALID_SEVERITIES, status in VALID_STATUSES)
- MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001 all present
- `findings[0].id` is an always-top finding (ordering invariant)

### Sanitizer coverage tests (added to tests/test_sanitizer.py)

Two new tests to close the 92% → 100% coverage gap on `src/sanitizer.py`:
- `test_fingerprint_non_string_returns_redacted_type_marker` — covers line 64 (`_fingerprint()` with int/None/list inputs)
- `test_sanitize_idempotency_dict_passthrough` — covers line 98 (already-sanitized dict value passes through unchanged)

---

## Test Results

**Final suite:** 202 passed, 0 skipped, 0 failed

**Previously-skipped tests now active:** The `canonical_api_dump` fixture in `conftest.py` was wired to `pytest.skip()` when `samples/fixtures/api_dump_home_office.json` did not exist. With the file now committed, all tests using it activate cleanly. No previously-skipped tests failed when activated.

**Sanitizer coverage:** 100% (25/25 statements; was 92% before this plan, missing lines 64 and 98)

---

## Acceptance Bar Status (from 01-VALIDATION.md)

| # | Condition | Status |
|---|-----------|--------|
| 1 | `unifi_audit.py` runs end-to-end against ≥1 real UniFi network without raising | PASS (Plan 07) |
| 2 | Captured `raw_sanitized.json` survives tagged-secret round-trip | PASS (Plan 06 + fixture-safety gate) |
| 3 | `pytest -q tests/` passes against canonical fixture | **PASS (this plan — 202/202)** |
| 4 | Smoke test asserts all 12 modules produce findings with data to fire | PASS (Plan 06 + this plan's canonical-fixture smoke) |
| 5 | Always-top produces 3 unknown findings + correct ordering | PASS (Plan 04, asserted by smoke test) |
| 6 | ≥1 compound finding fires on constructed test case | PASS (Plan 03) |
| 7 | `src/sanitizer.py` exports SECRET_FIELD_NAMES, sanitize(), _fingerprint; imported by both modules | PASS (Plan 01) |
| 8 | Coverage on `src/sanitizer.py` ≥ 95% | **PASS — 100% (this plan)** |

**All 8 conditions met. Phase 1 acceptance bar fully satisfied.**

---

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Coverage] Sanitizer coverage 92% → 100% (below Acceptance Bar condition 8)**

- **Found during:** Task 3 — running `pytest --cov=sanitizer`
- **Issue:** Coverage was 92% (23/25 statements). Lines 64 and 98 in `src/sanitizer.py` were not exercised by existing tests. Line 64 is `_fingerprint()` called directly with a non-string (the existing non-string tests call `sanitize()` which bypasses `_fingerprint()` entirely via the `else` branch at line 100). Line 98 is the idempotency passthrough for already-fingerprinted dict values.
- **Fix:** Added `test_fingerprint_non_string_returns_redacted_type_marker` and `test_sanitize_idempotency_dict_passthrough` to `tests/test_sanitizer.py`. Both are correctness tests, not coverage padding — they assert semantic behavior of the security-critical sanitization path.
- **Files modified:** `tests/test_sanitizer.py`
- **Commit:** 84a069a

---

## Known Stubs

None. The canonical fixture activates real findings from the pipeline; no placeholder data flows to any output.

---

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries introduced. The fixture file itself is the threat surface addressed by T-1-03 — mitigated by the layered defense (sanitizer + anonymizer + fixture-safety gate).

---

## Phase 1 Completion

**Plans complete: 8/8**

REQ-test-fixtures is now closed. The last open Phase 1 requirement (`REQ-validation-cloud-mode`) was explicitly deferred to Phase 3 in REQUIREMENTS.md and VALIDATION.md — it requires a unified API key with Cloud Connector (April 2026 unified key) and is outside Phase 1 scope.

Phase 1 (Live API Audit) is complete. All 8 plans executed; all 8 acceptance bar conditions satisfied; 202 tests pass with 0 skips.

---

## Self-Check

### Files created/modified exist:

- samples/fixtures/api_dump_home_office.json: FOUND
- tools/anonymize_fixture.py: FOUND
- tests/test_pipeline_smoke.py: FOUND (contains test_canonical_fixture_pipeline_smoke)
- tests/test_sanitizer.py: FOUND (contains coverage gap tests)

### Commits exist:

- b4e6930: FOUND (feat: create tools/anonymize_fixture.py)
- fb903dc: FOUND (fix: refine anonymize_fixture.py)
- 62e0389: FOUND (feat: commit anonymized canonical fixture)
- 84a069a: FOUND (feat: add canonical-fixture smoke test and fill sanitizer coverage gaps)

## Self-Check: PASSED
