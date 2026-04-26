---
phase: 01-live-api-audit
plan: 05
subsystem: api
tags: [python, ranking, profiles, scoring, weights]

# Dependency graph
requires:
  - phase: 01-live-api-audit/plan-04
    provides: _apply_float_top() and ALWAYS_TOP_FINDING_IDS in unifi_audit.py

provides:
  - src/profile_weights.py — WEIGHTS dict (50 cells), get_weight, score_finding, KNOWN_PROFILES
  - Profile-weighted ranking in analyze() — (severity, -score_finding, section) sort key
  - UNIFI_PROFILE validation with fallback to home_office (load_config)
  - render_report() "Profile: <name> (manual)" label (D-06)
  - T-1-05 mitigation: always-top bypass via _apply_float_top running LAST
  - 22 new tests in tests/test_profile_weights.py

affects:
  - Phase 2 wizard (profile auto-detection replaces manual env var; D-06 deferred)
  - All report outputs (profile label now shows "(manual)" suffix)
  - analyze() ordering — same evidence produces different non-always-top ordering by profile

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Profile-aware scoring: (impact * get_weight(profile, section)) / effort_hours — sort secondary key in analyze()"
    - "T-1-05 mitigation: weight-cell coverage asserted by test; always-top bypass asserted by test (structural: _apply_float_top runs after sort)"
    - "UNIFI_PROFILE env var validation with KNOWN_PROFILES frozenset and graceful fallback"

key-files:
  created:
    - src/profile_weights.py — WEIGHTS (50 cells), DEFAULT_WEIGHT, get_weight, score_finding, KNOWN_PROFILES, IMPACT_SCORES, EFFORT_HOURS (174 lines)
    - tests/test_profile_weights.py — 22 tests: cell coverage, scoring math, always-top bypass, ranking end-to-end, render label, bogus profile fallback (230 lines)
    - tests/_smoke_profile_weights.py — standalone smoke script for Task 2 verify step
  modified:
    - src/unifi_audit.py — import score_finding + KNOWN_PROFILES; analyze() sort key updated; load_config() validates UNIFI_PROFILE; render_report() adds "(manual)" label

key-decisions:
  - "score_finding duck-typed (no hard Finding import in profile_weights.py) — keeps module standalone and testable without circular import risk"
  - "_apply_float_top() still runs LAST in analyze() — weight-based sort cannot demote always-top findings (T-1-05 structural guarantee)"
  - "Audit scope section (api_coverage meta finding) intentionally omitted from WEIGHTS table — falls back to DEFAULT_WEIGHT (1.0) for all profiles; informational regardless of context"
  - "Smoke script created as part of Task 2 commit (needed for verify step); test file is Task 3 commit"

patterns-established:
  - "Pattern: (profile, section) tuple keyed dict for per-operator scoring amplification/suppression"
  - "Pattern: KNOWN_PROFILES frozenset for env var validation with graceful fallback — no sys.exit, warning to stderr"

requirements-completed:
  - REQ-profile-aware-scoring-weights

# Metrics
duration: 194s
completed: 2026-04-26
---

# Phase 01 Plan 05: Profile Weights Summary

**Profile-aware scoring weights (D-05/D-06): WEIGHTS dict with 50 cells (5 profiles x 10 sections), score_finding helper, UNIFI_PROFILE validation, and "(manual)" report label — same evidence produces measurably different non-always-top ordering by operator profile**

## Performance

- **Duration:** ~194s (~3 min)
- **Started:** 2026-04-26T13:11:51Z
- **Completed:** 2026-04-26T13:15:05Z
- **Tasks:** 3
- **Files created/modified:** 4 (2 created, 1 created smoke, 1 modified)

## Accomplishments

- Created `src/profile_weights.py` with 50-cell WEIGHTS dict (5 profiles x 10 sections), `get_weight`, `score_finding`, `KNOWN_PROFILES`, `IMPACT_SCORES`, `EFFORT_HOURS`
- Updated `analyze()` sort key to `(severity, -score_finding(f, profile), section)` — profile-weighted secondary ranking within each severity tier; `_apply_float_top` still runs last (T-1-05 bypass preserved)
- Updated `load_config()` to validate `UNIFI_PROFILE` against `KNOWN_PROFILES`; unknown values fall back to `home_office` with a stderr warning (no crash)
- Updated `render_report()` to show `**Profile:** home_office (manual)` with D-06 explanatory sub-line
- Created `tests/test_profile_weights.py` with 22 tests covering: 50-cell coverage assertion (T-1-05), score math, missing-attr fallback, always-top bypass (manual + end-to-end across all 5 profiles), end-to-end ranking diff between home/regulated_hipaa, render label, bogus profile fallback
- Full test suite: 124 passed, 5 skipped (canonical fixture tests — expected until Plan 08)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create src/profile_weights.py** — `afe8e06` (feat)
2. **Task 2: Integrate profile weights into analyze() + render_report** — `cc5fb07` (feat)
3. **Task 3: tests/test_profile_weights.py** — `ccc1242` (test)

## Files Created/Modified

- `src/profile_weights.py` — 50-cell WEIGHTS table, helpers, KNOWN_PROFILES (174 lines)
- `tests/test_profile_weights.py` — 22 tests; covers T-1-05 invariants (230 lines)
- `tests/_smoke_profile_weights.py` — standalone smoke script (31 lines)
- `src/unifi_audit.py` — import block (+5 lines), load_config validation (+9 lines), analyze() sort key (+5 lines net), render_report header (+2 lines net)

## WEIGHTS cell count

50 explicit cells. Sections covered: Segmentation, Wi-Fi, Firewall, Remote access, Admin, Wireless tuning, Firmware, Logging, Backup, Risk correlation. The Audit scope meta-section intentionally falls back to DEFAULT_WEIGHT (1.0) for all profiles.

## Test count and pass status

- `pytest -q tests/test_profile_weights.py`: **22 passed**
- `pytest -q tests/`: **124 passed, 5 skipped** (no regressions)

## Decisions Made

- `score_finding` is duck-typed — accepts any object with `.impact`, `.effort`, `.section` — no hard `Finding` import in `profile_weights.py`, which keeps the module standalone without circular import risk
- `_apply_float_top()` remains the last step in `analyze()` — this is the structural guarantee for T-1-05: weight-based sort cannot demote always-top findings regardless of what multipliers are in WEIGHTS
- `Audit scope` section (api_coverage meta finding) intentionally omitted from the explicit WEIGHTS table — it is informational regardless of operator context, so DEFAULT_WEIGHT (1.0) is correct for all profiles
- `KNOWN_PROFILES` validation in `load_config()` uses `sys.stderr.write` (not `logging`) so the warning appears before the logger is configured

## Deviations from Plan

None — plan executed exactly as written.

The smoke script (`tests/_smoke_profile_weights.py`) was created as part of Task 2's commit (before Task 3) since Task 2's verify step requires it. This matches the plan's intent — Task 3's action block describes creating it, but Task 2's verify step uses it.

## Known Stubs

None — all 50 weight cells have real float values derived from the RESEARCH.md weight table. No placeholder values.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced. All new code paths are in-process (ranking arithmetic, env var string comparison). No new trust boundary surface.

T-1-05 (Tampering — weight-cell coverage + always-top ordering) is mitigated by:
- `test_weights_cover_all_profile_section_cells` — asserts every (profile, section) cell is present; a missing cell would be caught here, not silently default to 1.0 in production
- `test_always_top_bypasses_weights` — manual reproduction of analyze() sort + _apply_float_top; asserts PPTP with worst possible score still floats first
- `test_always_top_set_is_first_under_every_profile` — end-to-end across all 5 profiles via analyze()

## Next Phase Readiness

- Plan 01-06 (validation / reporting) can proceed — profile-aware scoring is fully wired; render_report now shows the profile label
- Phase 2 wizard: `UNIFI_PROFILE` manual mechanism will be replaced by auto-detection; D-06 is explicitly deferred; the "(manual)" suffix in the report signals this to users
- All 124 tests passing; no blockers

---
*Phase: 01-live-api-audit*
*Completed: 2026-04-26*

## Self-Check: PASSED

Files verified:
- FOUND: src/profile_weights.py
- FOUND: tests/test_profile_weights.py
- FOUND: tests/_smoke_profile_weights.py
- FOUND: src/unifi_audit.py (modified)

Commits verified:
- FOUND: afe8e06 (feat: profile_weights.py)
- FOUND: cc5fb07 (feat: integrate weights into unifi_audit.py)
- FOUND: ccc1242 (test: test_profile_weights.py)
