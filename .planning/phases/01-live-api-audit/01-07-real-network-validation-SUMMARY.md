---
phase: 01-live-api-audit
plan: "07"
subsystem: validation
tags: [unifi, integration-api, real-network, adapter, fixtures, validation, divergent-shapes]

# Dependency graph
requires:
  - phase: 01-live-api-audit (plans 01-06)
    provides: Full audit pipeline with sanitizer, adapter, correlations, float-top, profile weights, smoke suite

provides:
  - Real authenticated run outcome documented (Network 10.3.55, Cloud Gateway Fiber + U7 Pro)
  - tests/fixtures/captured_real_network_run.md with A1-A8 fully resolved (VERIFIED / DIVERGENT / UNKNOWN-404 / UNKNOWN-not-present)
  - src/api_to_collections.py: all [UNKNOWN 2026-04-26] tags replaced with specific, evidence-backed annotations
  - _network_to_classic fixed to derive purpose from metadata.origin (USER_DEFINED -> corporate)
  - firmwareVersion lookup order corrected (Integration v1 field tried first)
  - 4 new tests covering DIVERGENT cases and VERIFIED fields
  - REQ-validation-real-network confirmed (authenticated run, 15 findings)
  - REQ-validation-api-response-shapes confirmed for 200 endpoints; 404 endpoints documented

affects:
  - 01-08 (anonymized fixture plan, if planned — remaining UNKNOWNs are 404-endpoint-gated)
  - any plan that reads adapter field-path annotations

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "[VERIFIED date] annotation: field name + type confirmed from live API response"
    - "[DIVERGENT date] annotation: real shape differs from assumption; code fixed"
    - "[UNKNOWN -- 404 on this controller version] annotation: endpoint not available at Network 10.3.55"
    - "[UNKNOWN -- not present in observed data] annotation: endpoint 200 but field absent from this hardware"
    - "metadata.origin-based purpose derivation: USER_DEFINED -> 'corporate' for SEG-001 compatibility"

key-files:
  created: []
  modified:
    - src/api_to_collections.py (all [UNKNOWN 2026-04-26] tags replaced with specific annotations; _network_to_classic fixed for Integration v1 purpose derivation; firmwareVersion order fixed)
    - tests/test_adapter.py (4 new tests for DIVERGENT cases and VERIFIED fields; 14 tests total)
    - tests/fixtures/captured_real_network_run.md (gitignored; rewritten with real observations, PII abstracted, A1-A8 fully resolved)

key-decisions:
  - "features field is an array of strings not dicts on Network 10.3.55; isinstance(feat, dict) guard in _extract_ssh_state prevents crash; no code logic change needed beyond clarifying the annotation"
  - "Integration v1 has no purpose field on network objects; metadata.origin drives purpose derivation (USER_DEFINED -> corporate) so SEG-001 detection works via adapter path"
  - "firmwareVersion (camelCase) confirmed as Integration v1 field name; lookup order fixed to try firmwareVersion before version fallback"
  - "6 endpoints return 404 on Network 10.3.55 (wlans, firewall-policies, firewall-zones, port-forwards, vpn-configs, traffic-routes); tagged UNKNOWN-404, not DIVERGENT"
  - "SEG-001 false-positive in _find_segmentation (raw path) is a known gap: _find_segmentation reads clean dict directly and looks for purpose field which doesn't exist in Integration v1; documented as deferred item"

patterns-established:
  - "Two-tier UNKNOWN distinction: 404-gated (endpoint absent) vs not-present (endpoint 200 but field missing from this hardware/firmware)"
  - "DIVERGENT with safe no-op: features-as-strings case where existing guard makes the wrong-shape harmless"

requirements-completed:
  - REQ-validation-real-network
  - REQ-validation-api-response-shapes
  - REQ-validation-network-version-compat
  - REQ-validation-ssl-self-signed

# Metrics
duration: 35min (iteration 1: 15min; iteration 2: 20min)
completed: 2026-04-26
---

# Phase 1 Plan 07: Real-Network Validation Summary (Iteration 2)

**Successful authenticated run against Network 10.3.55 (Cloud Gateway Fiber + U7 Pro): all [UNKNOWN 2026-04-26] adapter tags resolved to specific evidence-backed annotations; two DIVERGENT shapes found and fixed; 4 new tests added; 177 passed, 5 skipped**

## Performance

- **Duration:** ~35 min total (iteration 1: ~15 min; iteration 2: ~20 min)
- **Completed:** 2026-04-26
- **Tasks:** 3 of 3 (Task 1 was human-action checkpoint; Tasks 2-3 executed in two continuation passes)
- **Files modified:** 3 (api_to_collections.py, tests/test_adapter.py committed; captured_real_network_run.md gitignored)

## Accomplishments

- Ran a successful authenticated audit against a real UniFi controller (Network 10.3.55, Cloud Gateway Fiber gateway + U7 Pro AP, 1 site "Default", 2 networks, 2 devices, 30 clients)
- Resolved all 22 `[UNKNOWN 2026-04-26]` tags in `src/api_to_collections.py` to specific, evidence-backed annotations
- Identified and fixed 2 DIVERGENT shapes with covering tests
- Confirmed 3 field paths as VERIFIED (data wrapper key, firmwareVersion, vlanId)
- 4 new tests in `tests/test_adapter.py`; full suite 177 passed, 5 skipped — zero regressions
- Copied `audit_output/raw_sanitized.json` to `tests/fixtures/` for local test use (gitignored per D-08)
- Rewrote `tests/fixtures/captured_real_network_run.md` with real observations, PII abstracted

## Task Commits

1. **Task 1: User ran unifi_audit.py against real controller** — Human-action checkpoint (no commit; user output in audit_output/)
2. **Task 2 (iteration 1): Document observed shapes (all UNKNOWN)** — `766ce79` (previous iteration; gitignored fixture)
3. **Task 3 (iteration 1): Patch [ASSUMED] → [UNKNOWN]** — `766ce79` (fix)
4. **Task 2+3 (iteration 2): Re-resolve annotations + fix DIVERGENT + new tests** — `3cc74f8` (fix)
5. **Plan metadata (iteration 2):** this commit (docs)

## Files Created/Modified

- `tests/fixtures/captured_real_network_run.md` — Gitignored. Rewritten with real observations: A1-A8 fully resolved, PII (MAC/IP/hostname/device-name) abstracted, pagination observations, DIVERGENT analysis, acceptance bar sign-off
- `src/api_to_collections.py` — All `[UNKNOWN 2026-04-26]` tags replaced with specific annotations; `_network_to_classic` fixed to derive purpose from `metadata.origin`; `firmwareVersion` lookup order corrected; module docstring updated with annotation legend
- `tests/test_adapter.py` — 4 new tests: `test_features_as_strings_does_not_crash_ssh_detection`, `test_firmwareversion_camelcase_verified`, `test_network_purpose_derived_from_metadata_origin_user_defined`, `test_network_vlanid_camelcase_verified`
- `tests/fixtures/raw_sanitized.json` — Gitignored. Copied from audit_output/ for local test use

## Decisions Made

- **Two-tier UNKNOWN distinction:** `[UNKNOWN — 404 on this controller version]` for paths blocked by missing endpoints vs `[UNKNOWN — not present in observed data]` for paths where the endpoint returned 200 but the specific field was absent from the observed objects (e.g., sshEnabled on Cloud Gateway Fiber and U7 Pro)
- **features DIVERGENT treated as safe no-op:** The `isinstance(feat, dict)` guard already makes the wrong shape harmless. Annotated as DIVERGENT, retained for forward-compat, no code logic change needed
- **purpose derivation from metadata.origin:** `USER_DEFINED` → `"corporate"` so that SEG-001 detection (which filters `purpose in ("corporate", "guest", "vlan-only")`) correctly counts user-created networks via the adapter path
- **SEG-001 raw-path gap documented as deferred:** `_find_segmentation` in `unifi_audit.py` reads the raw `clean` dict directly and looks for `purpose` which doesn't exist in Integration v1 responses. This is why SEG-001 fires with `network_count: 0` in the real run even though there are 2 networks. Fixing the raw path is a follow-on item.

## Deviations from Plan

### DIVERGENT Shape 1: features field is array of strings not dicts

**Found during:** Task 2 (reading raw_sanitized.json)
**Issue:** `_extract_ssh_state` assumed `features` might be `[{"name": "ssh", "enabled": true}, ...]`. Real shape is `["switching"]` / `["accessPoint"]` (string array).
**Fix:** The `isinstance(feat, dict)` guard already prevented crash/false-positive. Updated annotation to `[DIVERGENT 2026-04-26]`, added `test_features_as_strings_does_not_crash_ssh_detection`.
**Files modified:** `src/api_to_collections.py`, `tests/test_adapter.py`
**Commit:** `3cc74f8`

### DIVERGENT Shape 2: Network purpose field absent; metadata.origin is the discriminator

**Found during:** Task 2 (reading raw_sanitized.json)
**Issue:** `_network_to_classic` assumed a `purpose` field (`"corporate"` / `"guest"` / `"vlan-only"`). Integration v1 has no `purpose` field. Instead: `metadata.origin` is `"USER_DEFINED"` or `"SYSTEM_DEFINED"`, and `default` is a boolean. Without this fix, `build_parser_collections` produces networks with `purpose: ""`, causing SEG-001 via the adapter path to always count 0 user-defined networks.
**Fix:** Added purpose derivation logic in `_network_to_classic`: `USER_DEFINED` → `"corporate"`, `SYSTEM_DEFINED` + `default==True` → `"system_default"`, `SYSTEM_DEFINED` + `default==False` → `"system_defined"`. Classic-API fallback retained for backup-mode compat.
**Tests added:** `test_network_purpose_derived_from_metadata_origin_user_defined`, `test_network_vlanid_camelcase_verified`
**Files modified:** `src/api_to_collections.py`, `tests/test_adapter.py`
**Commit:** `3cc74f8`

## A1-A8 Assumption Resolution Summary

| Assumption | Status | Notes |
|-----------|--------|-------|
| A1 — SSH state field (sshEnabled / ssh_enabled / features[]) | UNKNOWN (not present) + DIVERGENT | sshEnabled/ssh_enabled not seen; features are strings not dicts; guard safe |
| A2 — radio_table field (radioTable / radio_table) | UNKNOWN — not present in observed data | U7 Pro has interfaces:["radios"] but no radioTable in Integration v1 |
| A3 — Settings not in Integration v1 (auto_update etc.) | Confirmed absent at 10.3.55 | Stubs are correct |
| A4 — WLAN field names (security / wpaMode / pmfMode) | UNKNOWN — 404 on this controller version | /wlans returns 404 at Network 10.3.55 |
| A5 — Network purpose values (corporate / guest / vlan-only) | DIVERGENT 2026-04-26 | No purpose field; metadata.origin used instead; code fixed |
| A6 — Firmware version field (firmwareVersion) | VERIFIED 2026-04-26 | Both devices have firmwareVersion; lookup order corrected |
| A7 — Port-forward enabled flag | UNKNOWN — 404 on this controller version | /port-forwards returns 404 at Network 10.3.55 |
| A8 — VPN protocol field (type / protocol) | UNKNOWN — 404 on this controller version | /vpn-configs returns 404 at Network 10.3.55 |

## Adapter Annotation Counts

- **Before Plan 07:** 20+ `[ASSUMED]` occurrences
- **After Plan 07 (iteration 1):** 0 `[ASSUMED]`; 29 `[UNKNOWN 2026-04-26]` (generic)
- **After Plan 07 (iteration 2):** 0 `[UNKNOWN 2026-04-26]` (generic); replaced with:
  - `[VERIFIED 2026-04-26]`: 3
  - `[DIVERGENT 2026-04-26]`: 2 (features format; network purpose)
  - `[UNKNOWN — 404 on this controller version]`: 11
  - `[UNKNOWN — not present in observed data]`: 4
  - Confirmed absent (prose, no tag needed): 7 (settings stubs)

## Findings Produced (from real authenticated run — 15 total)

| Section | Count | IDs |
|---------|-------|-----|
| Admin (always-top unknowns) | 3 | MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001 |
| Segmentation | 1 | SEG-001-`<site-uuid>` (false-positive via raw path — see deferred) |
| Firewall | 3 | FW-CONTENT-001, FW-GEO-IN, FW-GEO-OUT |
| Firmware | 2 | FW-VER-`<MAC>` (Cloud Gateway Fiber on major version behind), FW-AUTO-001 |
| Wireless tuning | 1 | RF-ROGUE-001 |
| Logging | 1 | LOG-FWD-001 |
| Backup | 1 | BAK-001 |
| Risk correlation | 2 | CORR-KEYS-001, CORR-PIVOT-001 |
| Audit scope | 1 | META-COVERAGE (6 endpoints 404) |
| **Total** | **15** | |

## Validation REQ Status

| REQ | Status | Evidence |
|-----|--------|----------|
| REQ-validation-real-network | CONFIRMED | Authenticated run against 192.168.1.1 (Network 10.3.55); 15 findings produced |
| REQ-validation-api-response-shapes | CONFIRMED (partial) | 200 endpoints: shapes documented and annotations resolved; 404 endpoints: documented as version-gated |
| REQ-validation-network-version-compat | CONFIRMED | Both graceful-401 path (iteration 1) and 404-on-endpoint path (iteration 2) confirmed |
| REQ-validation-ssl-self-signed | CONFIRMED | TLS with verify=False succeeded; real API data received |

## Known Stubs

None — all adapter outputs flow to real finding logic. The SEG-001 false-positive is a logic gap (raw-path purpose detection), not a stub.

## Deferred Items

1. **SEG-001 false-positive via raw path:** `_find_segmentation` in `unifi_audit.py` reads the raw `clean` dict directly and counts `purpose in ("corporate", "guest", "vlan-only")`. Integration v1 network objects have no `purpose` field, so it always counts 0 even when user-defined networks exist. The adapter fix resolves this for the findings_enhanced.py path but not the raw path in `unifi_audit.py`. Follow-on fix: have `_find_segmentation` use `metadata.origin` awareness or route through the adapter.

2. **Pagination not implemented:** Clients returned 25 of 30. Truncation WARN fires correctly; continuation is deferred per D-03.

3. **6 endpoints returning 404:** wlans, firewall-policies, firewall-zones, port-forwards, vpn-configs, traffic-routes — all absent on Network 10.3.55. Re-test on a newer version to resolve remaining `[UNKNOWN — 404]` tags.

## Self-Check

- [x] `src/api_to_collections.py` contains zero `[UNKNOWN 2026-04-26]` (generic) tags
- [x] All DIVERGENT cases have covering tests
- [x] `tests/fixtures/captured_real_network_run.md` rewritten with real observations
- [x] `pytest -q tests/` — 177 passed, 5 skipped, 0 failed
- [x] No PII (MAC/IP/hostname/device-name) in any committed file
- [x] `3cc74f8` fix commit exists

## Self-Check: PASSED

---
*Phase: 01-live-api-audit*
*Completed: 2026-04-26 (iteration 2)*
