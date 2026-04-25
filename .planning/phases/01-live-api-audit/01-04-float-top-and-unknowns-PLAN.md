---
phase: 01-live-api-audit
plan: 04
type: execute
wave: 3
depends_on: [03]
files_modified:
  - src/unifi_audit.py
  - tests/test_float_top.py
autonomous: true
requirements:
  - REQ-always-float-to-top-overrides
requirements_addressed:
  - REQ-always-float-to-top-overrides
threat_refs: [T-1-06]
tags: [python, ranking, always-top, unknown-findings]

must_haves:
  truths:
    - "src/unifi_audit.py defines ALWAYS_TOP_FINDING_IDS as a frozenset constant"
    - "ALWAYS_TOP_FINDING_IDS contains: VPN-PPTP-001, SEG-001, FW-EOL-001, MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001"
    - "_emit_unknown_always_top() returns 3 Findings (MFA, default creds, WAN mgmt) with status='unknown'"
    - "Each unknown Finding has current_state stating cannot be determined via API alone, intent_question populated, recommendation present (D-03/D-10)"
    - "_apply_float_top(findings) re-sorts so any finding whose id starts with an ALWAYS_TOP_FINDING_IDS prefix appears before any other finding"
    - "analyze() flow: baseline -> enhanced -> emit 3 unknowns -> correlate -> apply_float_top -> sort"
    - "After analyze() runs on a fixture firing PPTP and SEG-001, findings[0..N] include the always-top set BEFORE any scored finding"
    - "The 3 unknown findings render through render_report() inline (D-10), not in a separate Limitations section"
  artifacts:
    - path: "src/unifi_audit.py"
      provides: "ALWAYS_TOP_FINDING_IDS, _emit_unknown_always_top, _apply_float_top integrated into analyze()"
      contains: "ALWAYS_TOP_FINDING_IDS|_emit_unknown_always_top|_apply_float_top|MFA-UNKNOWN-001|CRED-DEFAULT-001|WAN-MGMT-001"
    - path: "tests/test_float_top.py"
      provides: "Always-top ordering + 3 unknown findings emission tests"
  key_links:
    - from: "src/unifi_audit.py:analyze"
      to: "src/unifi_audit.py:_apply_float_top"
      via: "function call after correlate, before final sort"
      pattern: "_apply_float_top|ALWAYS_TOP_FINDING_IDS"
    - from: "src/unifi_audit.py:analyze"
      to: "src/unifi_audit.py:_emit_unknown_always_top"
      via: "function call before correlate (so MFA-UNKNOWN-001 is in the list when keys-to-kingdom rule checks)"
      pattern: "_emit_unknown_always_top"
---

<objective>
Implement the always-float-to-top override (D-02 part 2, REQ-always-float-to-top-overrides) AND the 3 honest unknown Findings for the API-undetectable always-top risks (D-03, D-10). After this plan, the report opens with the 6 always-top findings (3 detectable: VPN-PPTP-001, SEG-001, FW-EOL-001; 3 unknown: MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001) before any scored finding, regardless of severity calculation.

Per D-03 and D-10: API-undetectable always-top risks become `status="unknown"` Findings with `intent_question` populated, rendered inline through the existing `render_report()` path — no separate "Limitations" section.

Per T-1-06 mitigation: a regression test asserts that the always-top set is positioned at the front of the findings list whenever any always-top finding is present.

Output:
- `src/unifi_audit.py` extended with: ALWAYS_TOP_FINDING_IDS constant, _emit_unknown_always_top() helper, _apply_float_top() reorder pass, integrated into analyze()
- `tests/test_float_top.py` — ordering and emission tests including the T-1-06 regression check
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/01-live-api-audit/01-CONTEXT.md
@.planning/phases/01-live-api-audit/01-RESEARCH.md
@.planning/phases/01-live-api-audit/01-03-correlations-PLAN.md
@CLAUDE.md (Always-float-to-top findings list)

<interfaces>
<!-- The 6 always-top findings per CLAUDE.md "Always-float-to-top findings" + D-02:
1. No MFA on any admin account                    → MFA-UNKNOWN-001 (unknown, API can't detect)
2. Management plane reachable from WAN             → WAN-MGMT-001 (unknown, API can't detect)
3. Flat network with mixed device classes          → SEG-001 (detected by baseline)
4. Default credentials anywhere                    → CRED-DEFAULT-001 (unknown, API can't detect)
5. Firmware >2 majors behind with known advisories → FW-EOL-001 (detected by enhanced)
6. PPTP or any deprecated-crypto VPN enabled        → VPN-PPTP-001 (detected by enhanced) -->

The render_report() function at src/unifi_audit.py:579-624 iterates `for f in findings:` —
the 3 unknown findings render through the same loop (D-10, no special-case Limitations section).

Plan 03's analyze() flow ends with:
1. baseline modules
2. enhanced modules
3. _correlate_findings()
4. final sort

Plan 04 inserts BETWEEN steps 2 and 3:
2.5. _emit_unknown_always_top() → adds 3 Findings (MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001) BEFORE correlate so the keys-to-kingdom rule can see MFA-UNKNOWN-001
And adds AFTER step 4:
5. _apply_float_top() → reorders so always-top findings come first

The full analyze() flow becomes:
baseline → enhanced → emit_unknowns → correlate → sort → apply_float_top → return
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Add ALWAYS_TOP_FINDING_IDS, _emit_unknown_always_top, _apply_float_top to unifi_audit.py</name>
  <files>src/unifi_audit.py</files>
  <read_first>
    - src/unifi_audit.py (the analyze() body modified by Plans 02 and 03; the Finding dataclass)
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Pattern 4: `_apply_float_top()` — Always-Top Override (D-02)" and §"Three `unknown` Findings to emit")
    - .planning/phases/01-live-api-audit/01-CONTEXT.md (D-03 unknown finding spec)
    - CLAUDE.md (Always-float-to-top findings list — 6 items)
  </read_first>
  <behavior>
    - ALWAYS_TOP_FINDING_IDS is a frozenset containing exactly: "VPN-PPTP-001", "SEG-001", "FW-EOL-001", "MFA-UNKNOWN-001", "CRED-DEFAULT-001", "WAN-MGMT-001"
    - _emit_unknown_always_top() returns a list of exactly 3 Finding objects with ids MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001
    - Each unknown Finding has status="unknown", intent_question populated, current_state mentioning "cannot be determined via Network Integration API alone", recommendation populated
    - _apply_float_top reorders findings so any finding whose id startswith any string in ALWAYS_TOP_FINDING_IDS appears at the top, preserving relative order within the top group and within the rest group
    - _apply_float_top([]) returns []
    - _apply_float_top([f]) where f.id starts with "FW-EOL-001-..." returns [f]
    - Idempotent: _apply_float_top(_apply_float_top(x)) == _apply_float_top(x)
    - analyze() now: baseline → enhanced → emit_unknowns → correlate → sort → apply_float_top → return
  </behavior>
  <action>
Modify `src/unifi_audit.py`:

**Change 1: Add the constant.** Near the top of the file with other module-level constants (e.g., right after `SITE_SCOPED_LOCAL` block around line 86), add:

```python
# Always-float-to-top finding IDs (D-02, C-finding-002, REQ-always-float-to-top-overrides).
# Any finding whose id startswith one of these strings is reordered to the top of the
# report regardless of its severity/effort/profile-weight score.
#
# - VPN-PPTP-001:      PPTP enabled (cryptographically broken); detected by enhanced module
# - SEG-001:           Flat network with no segmentation; detected by baseline module
# - FW-EOL-001:        Firmware on EOL hardware; detected by enhanced module
# - MFA-UNKNOWN-001:   API cannot detect MFA state — emit unknown Finding (D-03)
# - CRED-DEFAULT-001:  API cannot detect default credentials — emit unknown Finding (D-03)
# - WAN-MGMT-001:      API cannot detect WAN-reachable management — emit unknown Finding (D-03)
ALWAYS_TOP_FINDING_IDS: frozenset[str] = frozenset({
    "VPN-PPTP-001",
    "SEG-001",
    "FW-EOL-001",
    "MFA-UNKNOWN-001",
    "CRED-DEFAULT-001",
    "WAN-MGMT-001",
})
```

**Change 2: Add _emit_unknown_always_top.** Above analyze(), add (verbatim from RESEARCH.md §"Three `unknown` Findings to emit" with text fields preserved):

```python
def _emit_unknown_always_top() -> list[Finding]:
    """Emit 3 always-top Findings for risks the Network Integration API cannot detect.

    Per D-03 / D-10: render inline through render_report() like any other Finding.
    The intent_question field becomes the Phase 2 wizard input.
    """
    return [
        Finding(
            id="MFA-UNKNOWN-001",
            section="Admin",
            severity="high",
            status="unknown",
            title="Admin account MFA status cannot be determined from API",
            current_state="Cannot be determined via Network Integration API alone.",
            recommendation="Verify in Ubiquiti account settings that MFA is enabled on all admin accounts.",
            intent_question="Is MFA enabled on all accounts with admin access to this controller?",
            maps_to={"cis_v8": "6.3", "nist_csf": "PR.AC-7"},
            effort="quick",
            impact="high",
        ),
        Finding(
            id="CRED-DEFAULT-001",
            section="Admin",
            severity="high",
            status="unknown",
            title="Default credential state cannot be verified from API",
            current_state="Cannot be determined via Network Integration API alone.",
            recommendation="Verify that no device uses factory-default credentials.",
            intent_question="Have you changed factory-default credentials on all UniFi devices and the controller?",
            maps_to={"cis_v8": "5.2"},
            effort="quick",
            impact="high",
        ),
        Finding(
            id="WAN-MGMT-001",
            section="Admin",
            severity="high",
            status="unknown",
            title="Management plane WAN reachability cannot be determined from API",
            current_state="Cannot be determined via Network Integration API alone.",
            recommendation="Confirm the UniFi controller UI is not accessible from the internet.",
            intent_question="Is the UniFi controller management interface reachable from the public internet?",
            maps_to={"cis_v8": "4.8", "nist_csf": "PR.AC-5"},
            effort="medium",
            impact="high",
        ),
    ]
```

**Change 3: Add _apply_float_top.** Above analyze() too:

```python
def _apply_float_top(findings: list[Finding]) -> list[Finding]:
    """Reorder findings so any always-top finding appears before any non-always-top.

    Preserves relative order within each group. Idempotent.
    Match is by `f.id.startswith(prefix)` against ALWAYS_TOP_FINDING_IDS — this
    handles the per-site suffix pattern (e.g., 'SEG-001-default' starts with 'SEG-001').
    """
    def is_top(f: Finding) -> bool:
        return any(f.id.startswith(prefix) for prefix in ALWAYS_TOP_FINDING_IDS)

    top = [f for f in findings if is_top(f)]
    rest = [f for f in findings if not is_top(f)]
    return top + rest
```

**Change 4: Update analyze().** Modify the analyze() body so the flow is:

```python
def analyze(clean: dict, profile: str, logger: logging.Logger) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Baseline modules (unchanged from Plan 02)
    baseline_modules = [...]
    for name, fn in baseline_modules:
        try:
            findings.extend(fn(clean, profile))
        except Exception as e:
            logger.warning(f"Module {name} failed: {e}")

    # 2. Enhanced modules via adapter (unchanged from Plan 02)
    try:
        colls = build_parser_collections(clean)
    except Exception as e:
        logger.warning(f"Adapter build_parser_collections failed: {e}")
        colls = {}
    enhanced_modules = [...]
    for name, fn in enhanced_modules:
        try:
            findings.extend(fn())
        except Exception as e:
            logger.warning(f"Enhanced module {name} failed: {e}")

    # 3. Emit 3 unknown always-top Findings (NEW in Plan 04)
    findings.extend(_emit_unknown_always_top())

    # 4. Correlation pass (from Plan 03 — sees the unknowns now, so keys-to-kingdom can fire)
    findings.extend(_correlate_findings(findings, profile, logger))

    # 5. Sort by severity (existing)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 5), f.section))

    # 6. Apply always-top override LAST (NEW in Plan 04 — overrides severity sort)
    findings = _apply_float_top(findings)

    return findings
```

The order — emit_unknowns BEFORE correlate, apply_float_top LAST — is required because:
- emit before correlate: lets keys-to-kingdom see MFA-UNKNOWN-001
- apply_float_top last: overrides the severity sort, otherwise the sort would re-shuffle them
  </action>
  <verify>
    <automated>python tests/_smoke_float_top.py</automated>
  </verify>
  <acceptance_criteria>
    - `grep -c "ALWAYS_TOP_FINDING_IDS" src/unifi_audit.py` returns ≥ 3 (definition + at least 2 references)
    - `grep -c "MFA-UNKNOWN-001" src/unifi_audit.py` returns ≥ 2
    - `grep -c "CRED-DEFAULT-001" src/unifi_audit.py` returns ≥ 2
    - `grep -c "WAN-MGMT-001" src/unifi_audit.py` returns ≥ 2
    - `grep -c "def _emit_unknown_always_top" src/unifi_audit.py` returns 1
    - `grep -c "def _apply_float_top" src/unifi_audit.py` returns 1
    - `grep -c "_apply_float_top(findings)" src/unifi_audit.py` returns ≥ 1 (invocation in analyze)
    - `grep -c "_emit_unknown_always_top()" src/unifi_audit.py` returns ≥ 1 (invocation in analyze)
    - `python tests/_smoke_float_top.py` exits 0 (Task 2 will create that script)
  </acceptance_criteria>
  <done>ALWAYS_TOP_FINDING_IDS frozenset defined with all 6 prefixes; _emit_unknown_always_top emits 3 unknowns with status='unknown' and populated intent_question; _apply_float_top reorders correctly; analyze flow updated to: baseline → enhanced → emit_unknowns → correlate → sort → float_top.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: tests/test_float_top.py — ordering, unknowns emission, regression check</name>
  <files>tests/test_float_top.py, tests/_smoke_float_top.py</files>
  <read_first>
    - src/unifi_audit.py (Task 1 changes)
    - tests/conftest.py (synthetic_api_dump)
  </read_first>
  <behavior>
    - test_always_top_constant_has_six_ids: ALWAYS_TOP_FINDING_IDS has 6 elements, exact set match
    - test_emit_unknown_always_top_returns_three: _emit_unknown_always_top() returns list of 3 Findings
    - test_unknown_findings_have_status_unknown: all 3 have status="unknown"
    - test_unknown_findings_have_intent_question: all 3 have intent_question populated (truthy string)
    - test_unknown_findings_ids_in_always_top: each of the 3 ids is in ALWAYS_TOP_FINDING_IDS
    - test_apply_float_top_empty: _apply_float_top([]) == []
    - test_apply_float_top_no_top_findings: with [F("WIFI-1"), F("LOG-1")] returns same order
    - test_apply_float_top_seg001_floats: with [F("WIFI-1"), F("SEG-001-default")] returns SEG first
    - test_apply_float_top_pptp_floats: with [F("RF-1"), F("VPN-PPTP-001-x")] returns PPTP first
    - test_apply_float_top_preserves_relative_order: with [F("a"), F("SEG-001"), F("b"), F("VPN-PPTP-001"), F("c")] returns [F("SEG-001"), F("VPN-PPTP-001"), F("a"), F("b"), F("c")]
    - test_apply_float_top_idempotent: _apply_float_top(_apply_float_top(x)) == _apply_float_top(x)
    - test_pipeline_first_n_are_always_top (T-1-06 regression): run analyze() against synthetic_api_dump; the first M findings (where M = number of always-top findings present) all have ids that match ALWAYS_TOP_FINDING_IDS prefixes
    - test_pipeline_emits_three_unknowns: analyze() output contains MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001
    - test_pipeline_unknowns_render_inline: render_report contains each of the 3 ids exactly once in the markdown body
  </behavior>
  <action>
Create `tests/_smoke_float_top.py`:

```python
"""Smoke script invoked by Plan 04 Task 1's verify command."""
import sys
import logging
sys.path.insert(0, "src")
import unifi_audit

# Constant exists with 6 entries
assert isinstance(unifi_audit.ALWAYS_TOP_FINDING_IDS, frozenset)
expected = {"VPN-PPTP-001", "SEG-001", "FW-EOL-001",
            "MFA-UNKNOWN-001", "CRED-DEFAULT-001", "WAN-MGMT-001"}
assert unifi_audit.ALWAYS_TOP_FINDING_IDS == expected, \
    f"ALWAYS_TOP_FINDING_IDS mismatch: {unifi_audit.ALWAYS_TOP_FINDING_IDS}"

# 3 unknowns
unknowns = unifi_audit._emit_unknown_always_top()
assert len(unknowns) == 3
assert {u.id for u in unknowns} == {"MFA-UNKNOWN-001", "CRED-DEFAULT-001", "WAN-MGMT-001"}
assert all(u.status == "unknown" for u in unknowns)
assert all(u.intent_question for u in unknowns)

# _apply_float_top
F = unifi_audit.Finding
sample = [
    F(id="WIFI-x", section="W", severity="low", status="gap", title="t", current_state="c"),
    F(id="SEG-001-default", section="S", severity="high", status="gap", title="t", current_state="c"),
    F(id="LOG-1", section="L", severity="info", status="gap", title="t", current_state="c"),
    F(id="VPN-PPTP-001", section="R", severity="critical", status="gap", title="t", current_state="c"),
]
reordered = unifi_audit._apply_float_top(sample)
assert reordered[0].id == "SEG-001-default", f"first: {reordered[0].id}"
assert reordered[1].id == "VPN-PPTP-001", f"second: {reordered[1].id}"
print("OK — float_top smoke")
```

Create `tests/test_float_top.py`:

```python
"""Always-top override + unknown findings emission (D-02, D-03, REQ-always-float-to-top-overrides)."""
from __future__ import annotations

import logging

import pytest

from unifi_audit import (
    ALWAYS_TOP_FINDING_IDS,
    Finding,
    _apply_float_top,
    _emit_unknown_always_top,
    analyze,
    render_report,
)


def _F(fid, severity="medium"):
    return Finding(id=fid, section="X", severity=severity, status="gap",
                   title=fid, current_state=".")


# --- ALWAYS_TOP_FINDING_IDS constant ---------------------------------------

def test_always_top_constant_has_six_ids():
    assert ALWAYS_TOP_FINDING_IDS == frozenset({
        "VPN-PPTP-001", "SEG-001", "FW-EOL-001",
        "MFA-UNKNOWN-001", "CRED-DEFAULT-001", "WAN-MGMT-001",
    })


def test_always_top_constant_is_frozen():
    assert isinstance(ALWAYS_TOP_FINDING_IDS, frozenset)


# --- _emit_unknown_always_top ----------------------------------------------

def test_emit_unknown_always_top_returns_three():
    out = _emit_unknown_always_top()
    assert len(out) == 3


def test_emit_unknown_always_top_ids():
    ids = {f.id for f in _emit_unknown_always_top()}
    assert ids == {"MFA-UNKNOWN-001", "CRED-DEFAULT-001", "WAN-MGMT-001"}


def test_emit_unknown_findings_status_is_unknown():
    for f in _emit_unknown_always_top():
        assert f.status == "unknown"


def test_emit_unknown_findings_have_intent_question():
    for f in _emit_unknown_always_top():
        assert f.intent_question, f"{f.id} missing intent_question"
        assert isinstance(f.intent_question, str)
        assert len(f.intent_question) > 10


def test_emit_unknown_findings_have_recommendation():
    for f in _emit_unknown_always_top():
        assert f.recommendation, f"{f.id} missing recommendation"


def test_emit_unknown_findings_ids_are_in_always_top():
    for f in _emit_unknown_always_top():
        assert any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS)


def test_emit_unknown_findings_current_state_says_api_cannot_detect():
    for f in _emit_unknown_always_top():
        assert "cannot be determined" in f.current_state.lower() or \
               "network integration api" in f.current_state.lower()


# --- _apply_float_top ------------------------------------------------------

def test_apply_float_top_empty():
    assert _apply_float_top([]) == []


def test_apply_float_top_no_top_findings_preserves_order():
    findings = [_F("WIFI-1"), _F("LOG-1"), _F("RF-1")]
    out = _apply_float_top(findings)
    assert [f.id for f in out] == ["WIFI-1", "LOG-1", "RF-1"]


def test_apply_float_top_seg001_floats_to_front():
    findings = [_F("WIFI-1"), _F("SEG-001-default")]
    out = _apply_float_top(findings)
    assert out[0].id == "SEG-001-default"


def test_apply_float_top_pptp_floats():
    findings = [_F("RF-1"), _F("VPN-PPTP-001"), _F("LOG-1")]
    out = _apply_float_top(findings)
    assert out[0].id == "VPN-PPTP-001"


def test_apply_float_top_preserves_relative_order_within_groups():
    findings = [_F("a"), _F("SEG-001-x"), _F("b"), _F("VPN-PPTP-001"), _F("c")]
    out = _apply_float_top(findings)
    ids = [f.id for f in out]
    # Top group: SEG-001-x then VPN-PPTP-001 (input order preserved)
    assert ids[0] == "SEG-001-x"
    assert ids[1] == "VPN-PPTP-001"
    # Rest group: a, b, c (input order preserved)
    assert ids[2:] == ["a", "b", "c"]


def test_apply_float_top_idempotent():
    findings = [_F("WIFI-1"), _F("SEG-001"), _F("VPN-PPTP-001")]
    once = _apply_float_top(findings)
    twice = _apply_float_top(once)
    assert [f.id for f in once] == [f.id for f in twice]


def test_apply_float_top_handles_per_site_suffix():
    """SEG-001-default and SEG-001-prod both should float."""
    findings = [_F("WIFI-1"), _F("SEG-001-default"), _F("SEG-001-prod")]
    out = _apply_float_top(findings)
    assert out[0].id.startswith("SEG-001")
    assert out[1].id.startswith("SEG-001")


# --- End-to-end (T-1-06 regression mitigation) ----------------------------

def test_pipeline_emits_three_unknowns(synthetic_api_dump):
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(synthetic_api_dump, "home_office", logger)
    ids = {f.id for f in findings}
    assert "MFA-UNKNOWN-001" in ids
    assert "CRED-DEFAULT-001" in ids
    assert "WAN-MGMT-001" in ids


def test_pipeline_first_findings_are_always_top(synthetic_api_dump):
    """T-1-06: regression test that always-top finding IDs appear at the front."""
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(synthetic_api_dump, "home_office", logger)
    # Count always-top in the result
    top_count = sum(1 for f in findings
                    if any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS))
    assert top_count > 0, "Expected at least 1 always-top finding (3 unknowns at minimum)"
    # First top_count entries must all be always-top
    for i in range(top_count):
        f = findings[i]
        assert any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS), \
            f"Position {i}: {f.id} is not always-top, but always-top items follow it"


def test_pipeline_unknowns_render_inline(synthetic_api_dump):
    """D-10: unknowns render via the same render_report path, not a separate section."""
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(synthetic_api_dump, "home_office", logger)
    report = render_report(findings, synthetic_api_dump, "home_office")
    assert "MFA-UNKNOWN-001" in report
    assert "CRED-DEFAULT-001" in report
    assert "WAN-MGMT-001" in report
    # No separate Limitations section header
    assert "## Limitations" not in report


def test_pipeline_correlation_sees_mfa_unknown(synthetic_api_dump):
    """Plan 03's keys-to-kingdom rule should fire when MFA-UNKNOWN-001 + remote exposed.

    The synthetic fixture has port-forwards empty by default, so VPN-MISSING does not fire.
    Add a port-forward to trigger the keys-to-kingdom path.
    """
    synthetic_api_dump["site_default"]["port_forwards"]["data"] = [
        {"enabled": True, "name": "test-fwd"}
    ]
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(synthetic_api_dump, "home_office", logger)
    ids = [f.id for f in findings]
    # Either CORR-KEYS-001 fires, or at minimum MFA-UNKNOWN-001 is present and
    # VPN-MISSING-* is also present
    has_keys = any("CORR-KEYS-001" in i for i in ids)
    has_mfa = any("MFA-UNKNOWN-001" in i for i in ids)
    has_remote_exposure = any(i.startswith("VPN-MISSING") or i.startswith("FW-") for i in ids)
    assert has_keys or (has_mfa and has_remote_exposure), \
        f"Neither keys-to-kingdom fired nor preconditions present: {ids}"
```

Run `pytest -q tests/test_float_top.py`. All 18+ tests should pass.
  </action>
  <verify>
    <automated>pytest -q tests/test_float_top.py</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_float_top.py` exists
    - File `tests/_smoke_float_top.py` exists
    - `pytest -q tests/test_float_top.py` exits 0
    - `python tests/_smoke_float_top.py` exits 0
    - `grep -c "test_pipeline_first_findings_are_always_top" tests/test_float_top.py` returns 1 (T-1-06 regression)
    - `grep -c "test_pipeline_emits_three_unknowns" tests/test_float_top.py` returns 1
    - `grep -c "test_pipeline_unknowns_render_inline" tests/test_float_top.py` returns 1
    - `grep -c "test_apply_float_top_idempotent" tests/test_float_top.py` returns 1
    - `grep -c "test_emit_unknown_findings_status_is_unknown" tests/test_float_top.py` returns 1
  </acceptance_criteria>
  <done>Float-top tests cover constant integrity, unknowns emission, ordering, idempotence, and end-to-end pipeline. T-1-06 regression check is in place — any future change that re-orders findings such that always-top no longer floats will fail this test.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Findings list → ranking | _apply_float_top reorders the findings list in-place semantically; render_report consumes the reordered list. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-1-06 | Tampering | src/unifi_audit.py:_apply_float_top + analyze() | mitigate | Regression test `test_pipeline_first_findings_are_always_top` asserts that the first N entries of the analyze() output (where N = count of always-top findings present) are all always-top IDs. Any future code change that breaks this ordering will fail the test. |
</threat_model>

<verification>
After all tasks complete:

```bash
# All tests pass
pytest -q tests/

# Smoke
python tests/_smoke_float_top.py

# Confirm wiring
grep -A1 "_emit_unknown_always_top()" src/unifi_audit.py
grep -A1 "_apply_float_top" src/unifi_audit.py
```
</verification>

<success_criteria>
- ALWAYS_TOP_FINDING_IDS = frozenset of exactly the 6 documented prefixes
- _emit_unknown_always_top() returns 3 status="unknown" Findings with intent_question populated
- _apply_float_top() reorders correctly, preserves relative order, idempotent
- analyze() flow: baseline → enhanced → emit_unknowns → correlate → sort → float_top
- T-1-06 regression test (test_pipeline_first_findings_are_always_top) is the structural guard
- D-10 confirmed: unknowns render inline through render_report (no separate Limitations section)
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-04-SUMMARY.md` with:
- Files modified and line counts
- Confirmation of the 6 always-top IDs and 3 unknowns
- Test count and pass status
- Any deviations and rationale
</output>
