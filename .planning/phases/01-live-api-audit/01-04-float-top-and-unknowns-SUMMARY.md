---
phase: 01-live-api-audit
plan: 04
subsystem: api
tags: [python, ranking, always-top, unknown-findings, findings-pipeline]

# Dependency graph
requires:
  - phase: 01-live-api-audit/plan-03
    provides: _correlate_findings() pass wired into analyze(); findings_correlations.py with 3 compound rules

provides:
  - ALWAYS_TOP_FINDING_IDS frozenset (6 canonical prefixes) in src/unifi_audit.py
  - _emit_unknown_always_top() emitting 3 status=unknown Findings for API-undetectable risks (D-03)
  - _apply_float_top() reorder pass (D-02) — always-top findings surface first regardless of score
  - analyze() flow extended: baseline -> enhanced -> emit_unknowns -> correlate -> sort -> apply_float_top
  - T-1-06 regression guard test (test_pipeline_first_findings_are_always_top)
  - D-10 confirmed: unknowns render inline via render_report(), no separate Limitations section

affects:
  - Phase 2 wizard (intent_question fields on 3 unknown Findings become wizard inputs)
  - Profile-aware scoring (Plan 01-05 — apply_float_top runs after scoring sort, overrides it)
  - Report rendering (all 6 always-top IDs appear at top of report.md)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Always-float-to-top via ALWAYS_TOP_FINDING_IDS frozenset + _apply_float_top() — startswith prefix match handles per-site suffixes (e.g. SEG-001-default)"
    - "Unknown Findings pattern (D-03/D-10): emit status=unknown with intent_question populated, render inline through existing render_report() loop"
    - "emit_unknowns BEFORE correlate — ensures keys-to-kingdom rule can see MFA-UNKNOWN-001 in findings list"

key-files:
  created:
    - tests/test_float_top.py — 20 tests: constant integrity, unknowns emission, ordering, idempotence, T-1-06 regression, D-10 inline rendering
    - tests/_smoke_float_top.py — smoke verification script for CI/verify step
  modified:
    - src/unifi_audit.py — ALWAYS_TOP_FINDING_IDS constant, _emit_unknown_always_top(), _apply_float_top(), analyze() updated

key-decisions:
  - "ALWAYS_TOP_FINDING_IDS uses frozenset (immutable, membership test O(1)); match is startswith to handle per-site suffix variants"
  - "_emit_unknown_always_top() called BEFORE _correlate_findings() so keys-to-kingdom rule can inspect MFA-UNKNOWN-001 in the findings list"
  - "_apply_float_top() runs AFTER severity sort — overrides score-based ordering as required by D-02"
  - "D-10: no separate Limitations section — unknown Findings render through the same render_report() for loop"

patterns-established:
  - "Pattern: always-top override via startswith prefix match against frozenset constant — idempotent, handles per-site suffix"
  - "Pattern: emit API-undetectable risks as status=unknown Findings with intent_question for Phase 2 handoff (not free-text limitations prose)"

requirements-completed:
  - REQ-always-float-to-top-overrides

# Metrics
duration: 3min
completed: 2026-04-26
---

# Phase 01 Plan 04: Float-Top and Unknowns Summary

**Always-float-to-top override (ALWAYS_TOP_FINDING_IDS frozenset, _apply_float_top) and 3 honest unknown Findings for API-undetectable risks (MFA, default creds, WAN mgmt), wired into analyze() with T-1-06 regression guard and 20 new tests**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-04-26T13:06:27Z
- **Completed:** 2026-04-26T13:09:29Z
- **Tasks:** 2
- **Files modified:** 3 (1 modified, 2 created)

## Accomplishments

- Added `ALWAYS_TOP_FINDING_IDS` frozenset (6 prefixes: VPN-PPTP-001, SEG-001, FW-EOL-001, MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001) to `src/unifi_audit.py` as a module-level constant
- Added `_emit_unknown_always_top()` emitting 3 status=unknown Findings (MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001), each with `intent_question` populated for Phase 2 wizard handoff (D-03)
- Added `_apply_float_top()` reorder pass using startswith-prefix matching, idempotent, preserving relative order within top and rest groups (D-02)
- Updated `analyze()` flow: baseline -> enhanced -> emit_unknowns -> correlate -> sort -> apply_float_top
- Created `tests/test_float_top.py` with 20 tests including T-1-06 regression guard (`test_pipeline_first_findings_are_always_top`) and D-10 inline render confirmation (`test_pipeline_unknowns_render_inline`)
- Full test suite: 102 passed, 5 skipped (canonical fixture tests — expected until Plan 08)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add ALWAYS_TOP_FINDING_IDS, _emit_unknown_always_top, _apply_float_top to unifi_audit.py** - `021e738` (feat)
2. **Task 2: tests/test_float_top.py — ordering, unknowns emission, regression check** - `f9977b0` (test)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified

- `src/unifi_audit.py` — Added ALWAYS_TOP_FINDING_IDS constant (~18 lines), _emit_unknown_always_top() (~40 lines), _apply_float_top() (~12 lines), updated analyze() wiring (+8 lines net)
- `tests/test_float_top.py` — 20 tests covering all aspects of float-top and unknowns emission (186 lines)
- `tests/_smoke_float_top.py` — Standalone smoke verification script for Task 1 verify step (32 lines)

## Decisions Made

- `_emit_unknown_always_top()` is called BEFORE `_correlate_findings()` in `analyze()` so the keys-to-kingdom correlation rule (`CORR-KEYS-001`) can see `MFA-UNKNOWN-001` in the findings list — test `test_pipeline_correlation_sees_mfa_unknown` validates this ordering
- `_apply_float_top()` runs AFTER the severity sort (not before), so the sort cannot re-shuffle always-top findings back behind scored ones
- `ALWAYS_TOP_FINDING_IDS` uses startswith prefix matching (not exact ID equality) so per-site suffix variants like `SEG-001-default` and `SEG-001-prod` both float correctly
- `frozenset` (not `list` or `set`) for the constant — immutable, O(1) membership test, signals intent that this set is locked by C-finding-002

## Deviations from Plan

None — plan executed exactly as written.

The smoke script (`tests/_smoke_float_top.py`) was created as part of Task 1 (before Task 2) since Task 1's verify step requires it. This is consistent with the plan's intent — Task 2's action block describes creating it, and Task 1's verify step uses it.

## Issues Encountered

None.

## Known Stubs

None — all 3 unknown Findings have real `current_state`, `recommendation`, and `intent_question` text. No placeholder values.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The only new code paths are in-process ranking and Finding construction — no new trust boundary surface.

T-1-06 (Tampering — always-top sort regression) is mitigated by `test_pipeline_first_findings_are_always_top`, which asserts that the first N findings in `analyze()` output (where N = count of always-top findings present) all match ALWAYS_TOP_FINDING_IDS prefixes.

## Next Phase Readiness

- Plan 01-05 (profile-aware scoring weights) can proceed — `_apply_float_top()` runs after the severity sort and will override any weight-adjusted ordering for the 6 always-top IDs
- Phase 2 wizard: `intent_question` fields on MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001 are ready for wizard input binding
- All 102 tests passing; no blockers

---
*Phase: 01-live-api-audit*
*Completed: 2026-04-26*
