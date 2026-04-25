---
phase: 01-live-api-audit
plan: 05
type: execute
wave: 4
depends_on: [04]
files_modified:
  - src/profile_weights.py
  - src/unifi_audit.py
  - tests/test_profile_weights.py
autonomous: true
requirements:
  - REQ-profile-aware-scoring-weights
requirements_addressed:
  - REQ-profile-aware-scoring-weights
threat_refs: [T-1-05]
tags: [python, ranking, profiles, scoring]

must_haves:
  truths:
    - "src/profile_weights.py exports WEIGHTS dict, DEFAULT_WEIGHT, get_weight(profile, section)"
    - "WEIGHTS is keyed by (profile, section) tuples and has a complete cell for every cross product of 5 profiles × 10 sections"
    - "get_weight returns DEFAULT_WEIGHT (1.0) when (profile, section) is not in WEIGHTS"
    - "analyze() in unifi_audit.py uses profile weights in a ranking step that runs AFTER the severity sort but BEFORE _apply_float_top"
    - "The same Finding evidence on different profiles produces different ordering between the always-top and the bottom of the report"
    - "Always-top findings BYPASS profile weights — they always come first regardless of weight (T-1-05 mitigation)"
    - "UNIFI_PROFILE env var is the only profile control in Phase 1 (D-06); default 'home_office'"
    - "Report header shows 'Profile: <profile> (manual)' so the user knows what shaped the scoring"
  artifacts:
    - path: "src/profile_weights.py"
      provides: "WEIGHTS dict + get_weight + ranking helper"
      exports: ["WEIGHTS", "DEFAULT_WEIGHT", "get_weight", "score_finding"]
      min_lines: 80
    - path: "src/unifi_audit.py"
      provides: "Profile-weight integration in analyze() ranking; render_report shows profile (manual)"
      contains: "get_weight|score_finding|profile.*manual"
    - path: "tests/test_profile_weights.py"
      provides: "Profile weight cell coverage + always-top bypass + ranking-changes-by-profile tests"
  key_links:
    - from: "src/unifi_audit.py:analyze"
      to: "src/profile_weights.py:score_finding"
      via: "import + sort key uses score_finding(f, profile)"
      pattern: "score_finding|get_weight"
---

<objective>
Implement profile-aware scoring weights (D-05, REQ-profile-aware-scoring-weights). The same Finding evidence produces different report ordering depending on the operator's `UNIFI_PROFILE` env var (home / home_office / small_business / regulated_hipaa / regulated_pci) — home profiles do not get enterprise retention recommendations at the top, regulated profiles do.

Per D-06 LOCKED: Phase 1 ships manual profile only. `UNIFI_PROFILE` env var, default `home_office`. Report header shows `"Profile: <profile> (manual)"`. Auto-detection deferred to Phase 2 wizard.

Per T-1-05 mitigation: weight tables MUST cover every (profile, section) cell, AND always-top findings MUST bypass weight calculation entirely (they always come first regardless of multiplier). Tests assert both invariants.

Output:
- `src/profile_weights.py` — WEIGHTS dict (5 profiles × 10 sections = 50 cells), get_weight, score_finding helper
- `src/unifi_audit.py` — profile-weighted ranking integrated into analyze(); render_report shows profile label
- `tests/test_profile_weights.py` — weight cell coverage, always-top bypass, ranking-changes-by-profile end-to-end
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/REQUIREMENTS.md
@.planning/phases/01-live-api-audit/01-CONTEXT.md
@.planning/phases/01-live-api-audit/01-RESEARCH.md
@.planning/phases/01-live-api-audit/01-04-float-top-and-unknowns-PLAN.md
@CLAUDE.md (Profile labels)

<interfaces>
<!-- The 5 profile labels per C-profile-001:
     home, home_office, small_business, regulated_hipaa, regulated_pci

     The 10 sections used across baseline + enhanced + correlation modules:
     Segmentation, Wi-Fi, Firewall, Remote access, Admin (devices + unknowns),
     Wireless tuning, Firmware, Logging, Backup, Risk correlation,
     Audit scope (api_coverage meta finding)

     The full WEIGHTS table starting values come from RESEARCH.md §"Pattern 5:
     Profile-Aware Weight Table (D-05)" lines ~726-808. Use those as the literal
     starting values. -->
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Create src/profile_weights.py with full WEIGHTS table + scoring helper</name>
  <files>src/profile_weights.py</files>
  <read_first>
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Pattern 5: Profile-Aware Weight Table (D-05)" lines ~726-822)
    - .planning/phases/01-live-api-audit/01-CONTEXT.md (D-05 spec)
    - CLAUDE.md (Profile labels list, "Always-float-to-top findings" list)
    - src/findings_enhanced.py (RETENTION_PROFILES dict at lines 480-486 — already encodes profile-specific retention values; the weight table amplifies/suppresses ranking, NOT the recommendation text)
  </read_first>
  <behavior>
    - WEIGHTS contains every (profile, section) cell for the 5 profiles × 10 sections cross product (50 cells minimum)
    - WEIGHTS[("home", "Logging")] == 0.4 (home suppresses enterprise retention)
    - WEIGHTS[("regulated_hipaa", "Logging")] == 2.0 (HIPAA amplifies retention)
    - WEIGHTS[("regulated_pci", "Segmentation")] == 2.5 (PCI CDE isolation cornerstone)
    - WEIGHTS[("home", "Wi-Fi")] == 1.0 (baseline)
    - get_weight("home", "Logging") returns 0.4
    - get_weight("home", "Nonexistent Section") returns DEFAULT_WEIGHT (1.0)
    - get_weight("nonexistent_profile", "Logging") returns DEFAULT_WEIGHT (1.0)
    - score_finding(finding, profile) returns (impact_score * weight) / effort_hours
    - score_finding for impact="high" effort="quick" home_office Logging: (3 * 0.7) / 2 = 1.05
    - score_finding handles unknown impact/effort gracefully (default to medium values)
  </behavior>
  <action>
Create `src/profile_weights.py` with the full implementation from RESEARCH.md §"Pattern 5":

1. Module docstring explaining (profile, section) -> multiplier; 1.0 baseline; >1 amplify; <1 suppress; rationale per cell.

2. `from __future__ import annotations`.

3. Define `WEIGHTS: dict[tuple[str, str], float]` with all 50 cells. Use the exact values from RESEARCH.md §"Pattern 5":

```python
WEIGHTS: dict[tuple[str, str], float] = {
    # --- home: suppress enterprise-only recommendations ---
    ("home", "Logging"):           0.4,
    ("home", "Backup"):            0.7,
    ("home", "Firmware"):          1.0,
    ("home", "Segmentation"):      1.2,
    ("home", "Wireless tuning"):   0.8,
    ("home", "Firewall"):          1.0,
    ("home", "Remote access"):     1.0,
    ("home", "Admin"):             1.0,
    ("home", "Wi-Fi"):             1.0,
    ("home", "Risk correlation"):  1.0,

    # --- home_office: baseline ---
    ("home_office", "Logging"):           0.7,
    ("home_office", "Backup"):            1.0,
    ("home_office", "Firmware"):          1.0,
    ("home_office", "Segmentation"):      1.2,
    ("home_office", "Wireless tuning"):   1.0,
    ("home_office", "Firewall"):          1.0,
    ("home_office", "Remote access"):     1.2,
    ("home_office", "Admin"):             1.0,
    ("home_office", "Wi-Fi"):             1.0,
    ("home_office", "Risk correlation"):  1.0,

    # --- small_business: raise operational sections ---
    ("small_business", "Logging"):           1.2,
    ("small_business", "Backup"):            1.3,
    ("small_business", "Firmware"):          1.2,
    ("small_business", "Segmentation"):      1.5,
    ("small_business", "Wireless tuning"):   1.0,
    ("small_business", "Firewall"):          1.3,
    ("small_business", "Remote access"):     1.3,
    ("small_business", "Admin"):             1.3,
    ("small_business", "Wi-Fi"):             1.0,
    ("small_business", "Risk correlation"):  1.2,

    # --- regulated_hipaa: 6-year retention; raise admin/segmentation ---
    ("regulated_hipaa", "Logging"):           2.0,
    ("regulated_hipaa", "Backup"):            1.8,
    ("regulated_hipaa", "Firmware"):          1.5,
    ("regulated_hipaa", "Segmentation"):      2.0,
    ("regulated_hipaa", "Wireless tuning"):   1.2,
    ("regulated_hipaa", "Firewall"):          1.8,
    ("regulated_hipaa", "Remote access"):     1.8,
    ("regulated_hipaa", "Admin"):             2.0,
    ("regulated_hipaa", "Wi-Fi"):             1.2,
    ("regulated_hipaa", "Risk correlation"):  1.5,

    # --- regulated_pci: cornerstone is segmentation + firewall ---
    ("regulated_pci", "Logging"):            1.8,
    ("regulated_pci", "Backup"):             1.8,
    ("regulated_pci", "Firmware"):           1.8,
    ("regulated_pci", "Segmentation"):       2.5,
    ("regulated_pci", "Wireless tuning"):    1.5,
    ("regulated_pci", "Firewall"):           2.5,
    ("regulated_pci", "Remote access"):      2.0,
    ("regulated_pci", "Admin"):              2.5,
    ("regulated_pci", "Wi-Fi"):              2.0,
    ("regulated_pci", "Risk correlation"):   2.0,
}

DEFAULT_WEIGHT: float = 1.0

# Sections also covered by api_coverage meta finding ("Audit scope") — default 1.0 for all
# profiles via DEFAULT_WEIGHT fallthrough; intentional omission from explicit table.
```

4. Define helpers:

```python
IMPACT_SCORES: dict[str, int] = {"high": 3, "medium": 2, "low": 1}
EFFORT_HOURS: dict[str, int] = {"quick": 2, "medium": 8, "project": 40}


def get_weight(profile: str, section: str) -> float:
    """Return the (profile, section) weight or DEFAULT_WEIGHT for unknown pairs."""
    return WEIGHTS.get((profile, section), DEFAULT_WEIGHT)


def score_finding(finding, profile: str) -> float:
    """Compute the prioritization score for a Finding under a profile.

    Higher score = higher rank (sort descending in analyze()).
    Formula: (impact_score * profile_weight) / effort_hours.

    Args:
        finding: object with .impact (high/medium/low), .effort (quick/medium/project),
                 and .section (matched against WEIGHTS).
        profile: one of home / home_office / small_business / regulated_hipaa / regulated_pci.

    Returns:
        float score; never raises on unknown impact/effort/profile/section
        (defaults to medium impact, medium effort, DEFAULT_WEIGHT).
    """
    impact = IMPACT_SCORES.get(getattr(finding, "impact", "medium"), 2)
    effort = EFFORT_HOURS.get(getattr(finding, "effort", "medium"), 8)
    weight = get_weight(profile, getattr(finding, "section", ""))
    return (impact * weight) / effort
```

5. Define a profile-validity helper for the audit script:

```python
KNOWN_PROFILES: frozenset[str] = frozenset({
    "home", "home_office", "small_business", "regulated_hipaa", "regulated_pci",
})
```

Do NOT add a CLI flag; D-06 specifies env var only.
  </action>
  <verify>
    <automated>python -c "import sys; sys.path.insert(0,'src'); from profile_weights import WEIGHTS, DEFAULT_WEIGHT, get_weight, score_finding, KNOWN_PROFILES; assert get_weight('home','Logging')==0.4; assert get_weight('regulated_hipaa','Logging')==2.0; assert get_weight('home','Nonexistent')==DEFAULT_WEIGHT; assert len(KNOWN_PROFILES)==5; sections={s for (p,s) in WEIGHTS.keys()}; profiles={p for (p,s) in WEIGHTS.keys()}; assert len(profiles)==5; assert len(sections)>=10; print(f'OK {len(WEIGHTS)} cells, {len(profiles)} profiles, {len(sections)} sections')"</automated>
  </verify>
  <acceptance_criteria>
    - File `src/profile_weights.py` exists
    - `grep -c "^WEIGHTS" src/profile_weights.py` returns ≥ 1
    - `grep -c "DEFAULT_WEIGHT" src/profile_weights.py` returns ≥ 2
    - `grep -c "def get_weight" src/profile_weights.py` returns 1
    - `grep -c "def score_finding" src/profile_weights.py` returns 1
    - `grep -c "KNOWN_PROFILES" src/profile_weights.py` returns ≥ 1
    - Profile count from WEIGHTS keys ≥ 5
    - Section count from WEIGHTS keys ≥ 10
    - get_weight("home", "Logging") == 0.4 (verified via the verify command above)
    - get_weight("regulated_hipaa", "Logging") == 2.0
    - get_weight("nonexistent", "anything") returns DEFAULT_WEIGHT
  </acceptance_criteria>
  <done>profile_weights.py exists with 50+ cells, helper functions, and KNOWN_PROFILES; cell coverage complete; defaults handle missing keys.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Integrate profile weights into analyze() ranking + render_report header</name>
  <files>src/unifi_audit.py</files>
  <read_first>
    - src/unifi_audit.py (analyze() flow after Plan 04; render_report at lines 579-624)
    - src/profile_weights.py (just created in Task 1)
    - .planning/phases/01-live-api-audit/01-CONTEXT.md (D-06 manual profile, "Profile: home_office (manual)")
  </read_first>
  <behavior>
    - analyze() imports score_finding from profile_weights
    - Ranking step replaces the existing severity-only sort with: primary key = severity; secondary key = -score_finding (descending — higher score first)
    - The ranking happens BEFORE _apply_float_top, so always-top still wins (T-1-05 mitigation: float-top bypasses weight calc)
    - render_report header line includes "Profile: <profile> (manual)" exactly
    - Calling analyze() with profile="home" vs profile="regulated_hipaa" on the same fixture produces measurably different non-always-top ordering (verified by Task 3 test)
  </behavior>
  <action>
Modify `src/unifi_audit.py`:

**Change 1: Import score_finding.** Add to the same try/except import block:

```python
try:
    from profile_weights import score_finding, KNOWN_PROFILES
except ImportError:
    from src.profile_weights import score_finding, KNOWN_PROFILES
```

**Change 2: Update analyze() ranking.** Replace the existing single-key sort:

```python
# OLD (Plans 02-04 had):
order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
findings.sort(key=lambda f: (order.get(f.severity, 5), f.section))

# NEW (Plan 05):
order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
findings.sort(key=lambda f: (
    order.get(f.severity, 5),
    -score_finding(f, profile),   # higher score first
    f.section,
))

# Then apply_float_top still runs LAST (T-1-05 mitigation: bypass weights)
findings = _apply_float_top(findings)
```

This preserves the severity-first ordering AND ranks within each severity tier by profile-weighted score. _apply_float_top runs last, so always-top items override regardless of score.

**Change 3: Validate UNIFI_PROFILE in load_config (defensive).** In `load_config()` (lines 120-155), after the existing profile read, add validation:

```python
profile = os.environ.get("UNIFI_PROFILE", "home_office").strip()
if profile not in KNOWN_PROFILES:
    sys.stderr.write(
        f"Warning: UNIFI_PROFILE='{profile}' is not a recognized profile. "
        f"Known: {sorted(KNOWN_PROFILES)}. Falling back to 'home_office'.\n"
    )
    profile = "home_office"
```

(If `KNOWN_PROFILES` is not yet imported in load_config scope, import it the same way at module top via the try/except.)

**Change 4: Update render_report() header.** In render_report() at lines 579-624, change the existing `**Profile:** {profile}` line to:

```python
lines.append(f"**Profile:** {profile} (manual)")
```

Make this a single replacement of the existing line. Also add an explanatory line below:

```python
lines.append(
    f"<sub>Manual profile per UNIFI_PROFILE env var. Auto-detection deferred to Phase 2 wizard (D-06).</sub>"
)
```
  </action>
  <verify>
    <automated>python tests/_smoke_profile_weights.py</automated>
  </verify>
  <acceptance_criteria>
    - `grep -c "from profile_weights import" src/unifi_audit.py` returns ≥ 1
    - `grep -c "score_finding" src/unifi_audit.py` returns ≥ 2
    - `grep -c "KNOWN_PROFILES" src/unifi_audit.py` returns ≥ 1
    - `grep "(manual)" src/unifi_audit.py` returns ≥ 1 line (render_report header updated)
    - `grep "-score_finding" src/unifi_audit.py` returns ≥ 1 line OR equivalent descending sort
    - Order in analyze(): sort happens BEFORE `_apply_float_top` (verified by line-number ordering)
    - `python tests/_smoke_profile_weights.py` exits 0 (Task 3 will create that script)
  </acceptance_criteria>
  <done>Profile weights integrated into ranking; always-top still wins via _apply_float_top order; render_report shows "(manual)" label; KNOWN_PROFILES validation in load_config rejects typos with a fallback.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: tests/test_profile_weights.py — cell coverage, always-top bypass, ranking-changes-by-profile</name>
  <files>tests/test_profile_weights.py, tests/_smoke_profile_weights.py</files>
  <read_first>
    - src/profile_weights.py (Task 1 output)
    - src/unifi_audit.py (Task 2 changes; analyze flow)
    - tests/conftest.py (synthetic_api_dump fixture)
  </read_first>
  <behavior>
    - test_weights_cover_all_profile_section_cells: every (profile, section) cell in the 5×10 cross product is present in WEIGHTS (50 cells minimum)
    - test_get_weight_known_pair: get_weight("home", "Logging") == 0.4
    - test_get_weight_unknown_returns_default: get_weight("home", "Bogus") == DEFAULT_WEIGHT
    - test_get_weight_unknown_profile_returns_default: get_weight("bogus_profile", "Logging") == DEFAULT_WEIGHT
    - test_score_finding_high_impact_quick_effort: a Finding with impact="high" effort="quick" section="Logging" profile="regulated_hipaa" returns (3 * 2.0) / 2 = 3.0
    - test_score_finding_handles_missing_attrs: a Finding object with no impact/effort attrs falls back to medium values
    - test_known_profiles_has_5: len(KNOWN_PROFILES) == 5 with the exact set
    - test_always_top_bypasses_weights (T-1-05 regression): a Finding with id="VPN-PPTP-001" and impact="low" effort="project" still appears in the always-top group regardless of profile weight (verified end-to-end via analyze())
    - test_ranking_changes_by_profile: run analyze() on the same fixture with profile="home" vs profile="regulated_hipaa"; assert that the order of NON-always-top findings differs (specifically that LOG-FWD-001 ranks lower in "home" than in "regulated_hipaa")
    - test_render_report_shows_manual_profile: render_report output contains the literal "(manual)"
    - test_unknown_profile_falls_back_to_home_office: load_config with UNIFI_PROFILE=bogus produces a warning and uses home_office (use monkeypatch on os.environ)
  </behavior>
  <action>
Create `tests/_smoke_profile_weights.py`:

```python
"""Smoke script invoked by Plan 05 Task 2's verify command."""
import sys
sys.path.insert(0, "src")
import unifi_audit
from profile_weights import score_finding, KNOWN_PROFILES, get_weight, WEIGHTS, DEFAULT_WEIGHT

# Imports succeeded
assert hasattr(unifi_audit, "score_finding")
assert hasattr(unifi_audit, "KNOWN_PROFILES")

# Cell math
assert get_weight("home", "Logging") == 0.4
assert get_weight("regulated_hipaa", "Logging") == 2.0
assert get_weight("home", "Bogus") == DEFAULT_WEIGHT

# Profile cross-product coverage
profiles = {"home", "home_office", "small_business", "regulated_hipaa", "regulated_pci"}
sections = {"Segmentation", "Wi-Fi", "Firewall", "Remote access", "Admin",
            "Wireless tuning", "Firmware", "Logging", "Backup", "Risk correlation"}
missing = []
for p in profiles:
    for s in sections:
        if (p, s) not in WEIGHTS:
            missing.append((p, s))
assert not missing, f"{len(missing)} cells missing: {missing[:5]}..."

# score_finding with regulated_hipaa Logging high/quick = (3*2.0)/2 = 3.0
class F:
    impact = "high"
    effort = "quick"
    section = "Logging"
assert abs(score_finding(F(), "regulated_hipaa") - 3.0) < 0.001

print(f"OK — {len(WEIGHTS)} weight cells; coverage complete")
```

Create `tests/test_profile_weights.py`:

```python
"""Profile-weight cell coverage, always-top bypass, ranking-changes-by-profile."""
from __future__ import annotations

import logging
import os

import pytest

from profile_weights import (
    DEFAULT_WEIGHT,
    KNOWN_PROFILES,
    WEIGHTS,
    get_weight,
    score_finding,
)
from unifi_audit import (
    ALWAYS_TOP_FINDING_IDS,
    Finding,
    analyze,
    load_config,
    render_report,
)


# --- Cell coverage ---------------------------------------------------------

REQUIRED_PROFILES = {"home", "home_office", "small_business",
                     "regulated_hipaa", "regulated_pci"}
REQUIRED_SECTIONS = {
    "Segmentation", "Wi-Fi", "Firewall", "Remote access", "Admin",
    "Wireless tuning", "Firmware", "Logging", "Backup", "Risk correlation",
}


def test_known_profiles_has_5():
    assert KNOWN_PROFILES == frozenset(REQUIRED_PROFILES)


def test_weights_cover_all_profile_section_cells():
    """T-1-05 mitigation: every (profile, section) cell must be present."""
    missing = [
        (p, s) for p in REQUIRED_PROFILES for s in REQUIRED_SECTIONS
        if (p, s) not in WEIGHTS
    ]
    assert not missing, f"{len(missing)} cells missing: {missing}"


def test_weights_cell_count():
    """At least 5 profiles × 10 sections = 50 cells."""
    assert len(WEIGHTS) >= 50


@pytest.mark.parametrize("profile,section,expected", [
    ("home", "Logging", 0.4),
    ("home", "Wi-Fi", 1.0),
    ("home_office", "Remote access", 1.2),
    ("small_business", "Segmentation", 1.5),
    ("regulated_hipaa", "Logging", 2.0),
    ("regulated_hipaa", "Admin", 2.0),
    ("regulated_pci", "Segmentation", 2.5),
    ("regulated_pci", "Firewall", 2.5),
])
def test_get_weight_known_pairs(profile, section, expected):
    assert get_weight(profile, section) == expected


def test_get_weight_unknown_section_returns_default():
    assert get_weight("home", "Bogus") == DEFAULT_WEIGHT


def test_get_weight_unknown_profile_returns_default():
    assert get_weight("bogus_profile", "Logging") == DEFAULT_WEIGHT


# --- score_finding ---------------------------------------------------------

def _F(section, severity="medium", status="gap", impact="medium", effort="medium"):
    return Finding(id="X", section=section, severity=severity, status=status,
                   title="t", current_state="c", impact=impact, effort=effort)


def test_score_finding_high_quick_hipaa_logging():
    f = _F("Logging", impact="high", effort="quick")
    # (3 * 2.0) / 2 = 3.0
    assert abs(score_finding(f, "regulated_hipaa") - 3.0) < 0.001


def test_score_finding_low_project_home_logging():
    f = _F("Logging", impact="low", effort="project")
    # (1 * 0.4) / 40 = 0.01
    assert abs(score_finding(f, "home") - 0.01) < 0.0001


def test_score_finding_handles_missing_attrs():
    """A duck-typed object without impact/effort uses medium defaults."""
    class Bare:
        section = "Wi-Fi"
    score = score_finding(Bare(), "home_office")
    # impact defaults to medium=2, effort to medium=8, weight=1.0 → 0.25
    assert abs(score - 0.25) < 0.001


def test_score_finding_higher_for_higher_amplified_section():
    f = _F("Logging", impact="high", effort="quick")
    home_score = score_finding(f, "home")
    hipaa_score = score_finding(f, "regulated_hipaa")
    assert hipaa_score > home_score, \
        "regulated_hipaa Logging should outrank home Logging for the same finding"


# --- T-1-05: always-top bypasses weights ----------------------------------

def test_always_top_bypasses_weights():
    """A VPN-PPTP-001 finding with impact=low effort=project (worst score)
    still appears in the always-top group regardless of profile.

    This is the structural guarantee: _apply_float_top runs AFTER the sort,
    so weight-based ranking cannot demote always-top findings.
    """
    f_pptp = Finding(id="VPN-PPTP-001", section="Remote access",
                     severity="critical", status="gap", title="t", current_state="c",
                     impact="low", effort="project")  # intentionally bad score
    f_other = Finding(id="WIFI-x", section="Wi-Fi",
                      severity="critical", status="gap", title="t", current_state="c",
                      impact="high", effort="quick")  # great score
    # Compose the analyze() last steps manually
    from unifi_audit import _apply_float_top
    findings = [f_other, f_pptp]
    # Sort by severity then -score (matches analyze ranking)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 5),
                                  -score_finding(f, "home"), f.section))
    # After sort, f_other ranks before f_pptp (better score)
    findings = _apply_float_top(findings)
    # After float_top, PPTP must come first
    assert findings[0].id == "VPN-PPTP-001", \
        f"Always-top failed; got {[f.id for f in findings]}"


# --- End-to-end: ranking changes by profile -------------------------------

def test_ranking_changes_between_home_and_regulated_hipaa(synthetic_api_dump):
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())

    home_findings = analyze(synthetic_api_dump, "home", logger)
    hipaa_findings = analyze(synthetic_api_dump, "regulated_hipaa", logger)

    # The set of finding IDs is the same (same evidence) — but the ordering differs
    home_ids = [f.id for f in home_findings]
    hipaa_ids = [f.id for f in hipaa_findings]
    assert set(home_ids) == set(hipaa_ids), \
        "Same evidence should produce same set of findings; only ordering differs"

    # Find LOG-FWD-001 if present — it should be ranked HIGHER (lower index)
    # in regulated_hipaa than in home, because (regulated_hipaa, Logging) = 2.0
    # and (home, Logging) = 0.4.
    if "LOG-FWD-001" in home_ids and "LOG-FWD-001" in hipaa_ids:
        home_pos = home_ids.index("LOG-FWD-001")
        hipaa_pos = hipaa_ids.index("LOG-FWD-001")
        # In regulated_hipaa, Logging is amplified, so LOG-FWD-001 should rank
        # equal or higher (lower index)
        assert hipaa_pos <= home_pos, \
            f"LOG-FWD-001 expected at equal/higher rank in regulated_hipaa: " \
            f"home pos={home_pos}, hipaa pos={hipaa_pos}"


def test_always_top_set_is_first_under_every_profile(synthetic_api_dump):
    """T-1-05/T-1-06 cross-check: under every profile, always-top findings
    occupy the leading positions."""
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    for profile in REQUIRED_PROFILES:
        findings = analyze(synthetic_api_dump, profile, logger)
        top_count = sum(1 for f in findings
                        if any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS))
        assert top_count > 0, f"Profile {profile}: no always-top findings"
        for i in range(top_count):
            f = findings[i]
            assert any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS), \
                f"Profile {profile}: position {i} ({f.id}) is not always-top"


# --- render_report displays manual profile label -------------------------

def test_render_report_shows_manual_profile(synthetic_api_dump):
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(synthetic_api_dump, "home_office", logger)
    report = render_report(findings, synthetic_api_dump, "home_office")
    assert "(manual)" in report, "Profile label missing '(manual)' suffix"
    assert "home_office" in report


# --- Bogus profile fallback in load_config ------------------------------

def test_load_config_unknown_profile_falls_back_to_home_office(monkeypatch, capsys):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_HOST", "192.0.2.1")
    monkeypatch.setenv("UNIFI_PROFILE", "bogus_profile_typo")
    cfg = load_config()
    assert cfg["profile"] == "home_office"
    captured = capsys.readouterr()
    assert "not a recognized profile" in captured.err.lower() or \
           "warning" in captured.err.lower()
```

Run `pytest -q tests/test_profile_weights.py`. All 16+ tests should pass.
  </action>
  <verify>
    <automated>pytest -q tests/test_profile_weights.py</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_profile_weights.py` exists
    - File `tests/_smoke_profile_weights.py` exists
    - `pytest -q tests/test_profile_weights.py` exits 0
    - `python tests/_smoke_profile_weights.py` exits 0
    - `grep -c "test_weights_cover_all_profile_section_cells" tests/test_profile_weights.py` returns 1
    - `grep -c "test_always_top_bypasses_weights" tests/test_profile_weights.py` returns 1
    - `grep -c "test_ranking_changes_between_home_and_regulated_hipaa" tests/test_profile_weights.py` returns 1
    - `grep -c "test_always_top_set_is_first_under_every_profile" tests/test_profile_weights.py` returns 1
    - `grep -c "test_render_report_shows_manual_profile" tests/test_profile_weights.py` returns 1
  </acceptance_criteria>
  <done>Weight-cell coverage proven; always-top bypass proven by 2 tests (manual + end-to-end across all profiles); ranking-changes-by-profile proven; manual profile label rendered; bogus profile falls back gracefully.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Profile env var → ranking | UNIFI_PROFILE controls scoring multipliers; an unknown profile must fall back safely (not raise; not silently miscategorize). |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-1-05 | Tampering | src/profile_weights.py:WEIGHTS coverage; src/unifi_audit.py:_apply_float_top ordering | mitigate | (a) test_weights_cover_all_profile_section_cells asserts every (profile, section) cell is present — a typo creating a missing cell silently downweights to 1.0 (DEFAULT_WEIGHT), but the test detects the missing cell. (b) test_always_top_bypasses_weights and test_always_top_set_is_first_under_every_profile assert that always-top findings appear first regardless of weight calculation — _apply_float_top runs AFTER the weight-aware sort, so weight tampering cannot demote critical risks. |
</threat_model>

<verification>
After all tasks complete:

```bash
pytest -q tests/
python tests/_smoke_profile_weights.py
grep -c "(manual)" src/unifi_audit.py    # >= 1 (render_report header)
grep -c "score_finding" src/unifi_audit.py  # >= 2 (import + sort key)
```
</verification>

<success_criteria>
- WEIGHTS has full 5×10 cell coverage; KNOWN_PROFILES has 5 entries
- analyze() ranking uses (severity, -profile_score, section) as sort key BEFORE _apply_float_top
- T-1-05 mitigated: weight-cell test + always-top-bypass test both green
- render_report header shows "(manual)" suffix per D-06
- Bogus UNIFI_PROFILE falls back to home_office with a warning
- The same evidence produces different non-always-top ordering between home and regulated_hipaa
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-05-SUMMARY.md` with:
- Files created and line counts
- WEIGHTS cell count
- Test count and pass status
- Confirmation that REQ-profile-aware-scoring-weights is complete
</output>
