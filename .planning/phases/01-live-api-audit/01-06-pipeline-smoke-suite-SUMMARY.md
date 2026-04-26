---
phase: 01-live-api-audit
plan: 06
subsystem: testing
tags: [python, pytest, smoke, regression, coverage, static-analysis, security]

# Dependency graph
requires:
  - phase: 01-live-api-audit plan 05
    provides: profile_weights.py + analyze() ranking + all prior test infrastructure

provides:
  - tests/test_pipeline_smoke.py: end-to-end pipeline smoke suite (15 tests)
  - tests/test_no_credential_leak.py: static T-1-02 guard across all src/*.py (34 tests)
  - Adapter bug fix: build_parser_collections() now populates "setting" list for _get_setting()

affects:
  - plan 07 (real-network validation — smoke suite exercises all code paths)
  - plan 08 (canonical fixture — 5 skipped tests will unlock automatically)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Static source-text scan via re.compile() + pytest.mark.parametrize for per-file security assertions"
    - "Tagged-secret round-trip test: inject known value -> sanitize -> analyze -> render -> grep all disk artifacts"
    - "Adapter _get_setting compatibility: 'setting' list with {key: proto_name, ...} entries bridges Integration v1 VPN shape to parser.py interface"

key-files:
  created:
    - tests/test_pipeline_smoke.py
    - tests/test_no_credential_leak.py
  modified:
    - src/api_to_collections.py

key-decisions:
  - "adapter _get_setting fix: build_parser_collections now emits a 'setting' list so parser.py _get_setting() can locate VPN protocol dicts; previously find_remote_access (enhanced) silently missed VPN-PPTP-001 because _get_setting iterated a non-existent 'setting' key"
  - "coverage invocation: --cov=sanitizer (not --cov=src/sanitizer) matches the module name as imported from sys.path; 96% achieved"
  - "write_text encoding='utf-8' required on Windows due to arrow characters in render_report output"

patterns-established:
  - "Per-file parametrized static scans: _existing_files() filters OWNED_SRC to avoid failures on optional modules"
  - "Fixture augmentation pattern: fixture_firing_all_modules extends synthetic_api_dump to trigger all module paths"
  - "404 graceful-skip test: mock must return a site list so site-scoped calls fire and produce 404 entries in _endpoints_probed"

requirements-completed:
  - REQ-phase1-live-api-audit
  - REQ-validation-network-version-compat
  - REQ-validation-ssl-self-signed
  - REQ-validation-sanitization-coverage
  - REQ-finding-module-segmentation
  - REQ-finding-module-wifi
  - REQ-finding-module-firewall
  - REQ-finding-module-remote-access
  - REQ-finding-module-devices
  - REQ-finding-module-api-coverage-meta

# Metrics
duration: 5min
completed: 2026-04-26
---

# Phase 01 Plan 06: Pipeline Smoke Suite Summary

**pytest smoke suite locking Phase 1 acceptance bar via tagged-secret round-trip, 404 graceful-skip, SSL-default assertions, static credential-leak guard, and adapter _get_setting bug fix enabling VPN-PPTP-001 detection**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-04-26T13:16:23Z
- **Completed:** 2026-04-26T13:21:10Z
- **Tasks:** 3 (2 with new code, 1 verification-only)
- **Files modified:** 3 (2 created, 1 modified)

## Accomplishments

- Added `tests/test_pipeline_smoke.py` with 15 tests covering the full analyze() pipeline, 404 graceful skip (REQ-validation-network-version-compat), SSL defaults (REQ-validation-ssl-self-signed), tagged-secret round-trip sanitization (REQ-validation-sanitization-coverage), always-top ordering, and 3 unknown always-top findings
- Added `tests/test_no_credential_leak.py` with 34 parametrized static-analysis tests scanning all owned src/*.py files — no logger/print of response.text, api_key, or full cfg dict; regression detector for the safe_msg scrub pattern
- Fixed adapter bug: `build_parser_collections()` now emits a `"setting"` list compatible with `parser.py _get_setting()`; VPN-PPTP-001 (always-top finding) was silently missing from all prior test runs
- Full suite: 173 tests passing, 5 skipped (canonical fixture, unlocks in Plan 08); `src/sanitizer.py` coverage 96% (acceptance bar #8: >= 95%)

## Task Commits

1. **Task 1: test_pipeline_smoke.py + adapter bug fix** - `2025941` (feat)
2. **Task 2: test_no_credential_leak.py** - `9bde066` (feat)
3. **Task 3: Verification gate** - (no commit; verification-only task)

**Plan metadata:** (this SUMMARY commit)

## Files Created/Modified

- `tests/test_pipeline_smoke.py` - 15-test smoke suite covering end-to-end pipeline, 404 graceful skip, SSL defaults, tagged-secret round-trip, always-top ordering, 3 unknowns gate
- `tests/test_no_credential_leak.py` - 34-test static guard for T-1-02: no response.text logging, no api_key printing, no full cfg logging; regression detector for existing safe_msg scrub
- `src/api_to_collections.py` - Added "setting" list population so parser.py's `_get_setting()` can locate VPN protocol dicts by key name

## Decisions Made

- Adapter "setting" list fix (Rule 1 Bug): `_get_setting(colls, key)` in parser.py iterates `colls["setting"]` looking for `{"key": key, ...}` entries. The adapter was emitting VPN settings only as direct top-level keys (e.g., `colls["vpn_pptp"]`), which `_get_setting` never checked. Fix adds a `"setting"` list with all VPN protocol dicts tagged with their `"key"` field — backward-compat direct keys are preserved alongside.
- Windows `write_text` needs `encoding="utf-8"` because `render_report` output contains Unicode arrow characters that the default cp1252 codec cannot encode.
- Coverage invocation requires `--cov=sanitizer` (module import name) not `--cov=src/sanitizer` (path notation) when the src/ directory is on sys.path.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Adapter _get_setting() integration: VPN-PPTP-001 never fired**
- **Found during:** Task 1 (test_pipeline_smoke.py) — test_pptp_finding_is_first_when_present failed
- **Issue:** `build_parser_collections()` emitted `colls["vpn_pptp"] = {"type": "pptp", "enabled": True}` but `parser.py _get_setting(colls, "vpn_pptp")` iterates `colls["setting"]` (a list) looking for `{"key": "vpn_pptp", ...}`. No "setting" list existed, so `_get_setting` always returned `None`, and `find_remote_access` (enhanced) never triggered VPN-PPTP-001 — the most critical always-top finding.
- **Fix:** Added `"setting"` list construction in `build_parser_collections()`. Each VPN protocol dict and stub-setting entry is wrapped with its `"key"` field and appended to the list. Direct top-level keys preserved for backward-compat.
- **Files modified:** `src/api_to_collections.py`
- **Verification:** `find_remote_access(colls)` now returns `['VPN-PPTP-001', 'VPN-MISSING-001']` as expected; all 15 smoke tests pass
- **Committed in:** `2025941` (part of Task 1 commit)

**2. [Rule 3 - Blocking] test_404_graceful_skip mock needed a real site list**
- **Found during:** Task 1 — mock returning `{"data": []}` for /sites produced no site-scoped calls, so no 404s appeared in `_endpoints_probed`
- **Fix:** Mock now returns `{"data": [{"id": "default", "name": "test-site"}]}` for /sites so site-scoped calls fire and hit the 404-return path
- **Files modified:** `tests/test_pipeline_smoke.py`
- **Verification:** `statuses` list now contains 404; test passes
- **Committed in:** `2025941` (part of Task 1 commit)

**3. [Rule 3 - Blocking] write_text UnicodeEncodeError on Windows**
- **Found during:** Task 1 — `test_tagged_secret_does_not_appear_in_any_pipeline_output` failed with cp1252 codec error on arrow character in report
- **Fix:** Added `encoding="utf-8"` to `report_path.write_text(report, encoding="utf-8")`
- **Files modified:** `tests/test_pipeline_smoke.py`
- **Verification:** Test passes on Windows Python 3.14
- **Committed in:** `2025941` (part of Task 1 commit)

---

**Total deviations:** 3 auto-fixed (1 Rule 1 bug, 2 Rule 3 blocking)
**Impact on plan:** All fixes necessary for correctness and test completeness. The adapter bug fix is particularly important — VPN-PPTP-001 (always-top critical finding) was silently absent from all prior enhanced-module runs.

## Issues Encountered

- Windows-specific: default `write_text` encoding fails on Unicode characters produced by `render_report`; requires explicit `encoding="utf-8"`.

## Acceptance Bar Status

| Condition | Status |
|-----------|--------|
| 3. pytest -q tests/ passes | PASS (173 passed, 5 skipped) |
| 4. All 12 modules execute gate | PASS (test_all_12_modules_produce_findings asserts >= 5 sections) |
| 5. 3 unknown always-top findings + ordering | PASS (test_three_unknown_always_top_emitted + test_pptp_finding_is_first_when_present) |
| 8. sanitizer.py coverage >= 95% | PASS (96%) |
| REQ-validation-network-version-compat | PASS (test_404_graceful_skip, test_404_does_not_raise_in_collect_all) |
| REQ-validation-ssl-self-signed | PASS (test_ssl_default_local_is_false, test_ssl_default_cloud_is_true, 2 explicit override tests) |
| REQ-validation-sanitization-coverage | PASS (test_tagged_secret_does_not_appear_in_any_pipeline_output) |
| T-1-02 mitigation | PASS (test_no_credential_leak.py: 34 static guards across all src/*.py) |

## Known Stubs

None introduced in this plan. The 5 skipped tests in `test_fixture_safety.py` depend on the canonical fixture committed in Plan 08 — they will unlock automatically once `samples/fixtures/api_dump_home_office.json` exists.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. This plan adds test files and a bug fix to the adapter only.

## Next Phase Readiness

- Plan 07 (real-network validation) can now run `pytest -q tests/` as a pre-flight check
- Plan 08 (canonical fixture commit) will unlock 5 currently-skipped tests automatically
- All Phase 1 code-quality acceptance bar items (3, 4, 5, 8) are now test-enforced
- VPN-PPTP-001 detection is now verified end-to-end through the adapter

---
*Phase: 01-live-api-audit*
*Completed: 2026-04-26*
