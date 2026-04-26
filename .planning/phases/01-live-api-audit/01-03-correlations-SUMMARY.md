---
phase: 01-live-api-audit
plan: 03
subsystem: api
tags: [python, correlation, compound-findings, security-audit]

# Dependency graph
requires:
  - phase: 01-live-api-audit
    plan: 02
    provides: "analyze() pipeline with 12 modules + adapter; Finding dataclass"

provides:
  - "src/findings_correlations.py: 3 compound-finding rules + CORRELATION_RULES registry"
  - "_correlate_findings() pass in analyze() between enhanced modules and final sort"
  - "15 correlation tests; REQ-cross-answer-tension-detection closed"

affects:
  - "01-live-api-audit plan 04 (always-float-to-top — shares analyze() pipeline)"
  - "01-live-api-audit plan 05 (profile-aware scoring — same findings list post-correlation)"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Compound-finding correlation: pure functions over list[Finding]; one rule per risk pattern"
    - "Lazy import inside rule body to avoid circular import (findings_correlations imports Finding from unifi_audit)"
    - "Try/except per rule in _correlate_findings so a single rule failure never aborts the audit"
    - "CORRELATION_RULES list registry: new rules registered by appending to the list"

key-files:
  created:
    - src/findings_correlations.py
    - tests/test_correlations.py
    - tests/_smoke_correlate.py
  modified:
    - src/unifi_audit.py

key-decisions:
  - "D-003 LOCKED: correlation rules as plain Python functions (not a YAML rules engine) per plan"
  - "D-04: rules in findings_correlations.py; lazy Finding import avoids circular dependency"
  - "Correlation pass position: AFTER enhanced modules, BEFORE severity sort — consistent with D-02"
  - "Three trigger conditions (Phase 1 conservative): FW-*+VPN-MISSING, MFA-*+remote, SEG-001"

patterns-established:
  - "Rule signature: (findings: list, profile: str) -> Finding | None — uniform for all rules"
  - "_has_finding_id(findings, prefix) helper for prefix-based ID matching"
  - "CORR- prefix for all compound finding IDs; section='Risk correlation'"

requirements-completed:
  - REQ-cross-answer-tension-detection

# Metrics
duration: 3min
completed: 2026-04-26
---

# Phase 1 Plan 03: Correlations Summary

**Cross-answer tension detection pass: 3 compound CORR-* rules (priority mismatch, keys-to-kingdom, pivot path) wired into analyze() as pure Python functions via findings_correlations.py, closing REQ-cross-answer-tension-detection**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-04-26T13:00:00Z
- **Completed:** 2026-04-26T13:03:11Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Created `src/findings_correlations.py` with 3 compound rules + CORRELATION_RULES registry (176 lines)
- Added `_correlate_findings()` helper and wired into `analyze()` between enhanced modules and sort
- 15 correlation tests all pass; end-to-end test confirms CORR-PIVOT-001 fires on synthetic fixture
- Full test suite: 82 passed, 5 skipped (skips are canonical-fixture tests, expected until Plan 08)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create src/findings_correlations.py** - `e70fef1` (feat)
2. **Task 2: Wire _correlate_findings() into analyze()** - `27bcf5a` (feat)
3. **Task 3: tests/test_correlations.py** - `7c75e7b` (test)

## Files Created/Modified

- `src/findings_correlations.py` (176 lines, NEW) — 3 compound rules + _has_finding_id/_get_finding helpers + CORRELATION_RULES registry
- `src/unifi_audit.py` (770 lines, modified) — CORRELATION_RULES import added; _correlate_findings() function added above analyze(); correlation pass wired in analyze() body
- `tests/test_correlations.py` (160 lines, NEW) — 15 tests covering positive/negative cases, registry integrity, end-to-end pipeline, and failure isolation
- `tests/_smoke_correlate.py` (20 lines, NEW) — standalone smoke script for Task 2 verify step

## Decisions Made

- Lazy `from unifi_audit import Finding` import inside each rule body — avoids circular import since `unifi_audit` imports `findings_correlations` at module level (D-04 implementation note honored)
- Phase 1 conservative trigger for `correlate_priority_mismatch`: fires on FW-* + VPN-MISSING (not on downtime-sensitivity data unavailable from API alone)
- `correlate_keys_to_kingdom` trigger accepts either VPN-MISSING or FW-* as the remote-exposure signal — either path is sufficient
- `test_correlation_failure_does_not_abort` uses monkeypatch + importlib.reload to test isolation; reload needed because CORRELATION_RULES is imported at module level in unifi_audit

## Deviations from Plan

None — plan executed exactly as written. The verbatim Pattern 3 implementation from RESEARCH.md was used for the rule bodies.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Correlation pass is in place; Plan 04 (always-float-to-top) can now add MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001 unknown Findings and the _apply_float_top() pass after _correlate_findings()
- Plan 05 (profile-aware scoring weights) reads the final sorted findings list; correlation findings have section="Risk correlation" and will receive the weight for that section
- REQ-cross-answer-tension-detection closed

---
*Phase: 01-live-api-audit*
*Completed: 2026-04-26*
