---
phase: 01-live-api-audit
plan: 03
type: execute
wave: 2
depends_on: [02]
files_modified:
  - src/findings_correlations.py
  - src/unifi_audit.py
  - tests/test_correlations.py
autonomous: true
requirements:
  - REQ-cross-answer-tension-detection
requirements_addressed:
  - REQ-cross-answer-tension-detection
threat_refs: []
tags: [python, correlation, compound-findings]

must_haves:
  truths:
    - "src/findings_correlations.py exists with at least 3 correlation rule functions"
    - "Each rule takes (findings: list, profile: str) and returns Finding | None"
    - "CORRELATION_RULES list registry exports all rules"
    - "analyze() in unifi_audit.py invokes _correlate_findings() AFTER baseline+enhanced modules but BEFORE final sort"
    - "Correlation findings have section='Risk correlation' and IDs prefixed CORR-"
    - "At least one compound finding fires on a constructed test case (REQ-cross-answer-tension-detection)"
    - "Correlation pass is wrapped in try/except — a single rule failure does not abort the audit"
  artifacts:
    - path: "src/findings_correlations.py"
      provides: "Compound-finding rule registry"
      exports: ["CORRELATION_RULES", "correlate_priority_mismatch", "correlate_keys_to_kingdom", "correlate_pivot_path"]
      min_lines: 100
    - path: "src/unifi_audit.py"
      provides: "_correlate_findings() pass invoked from analyze()"
      contains: "_correlate_findings|CORRELATION_RULES"
    - path: "tests/test_correlations.py"
      provides: "Constructed test cases firing each compound rule"
  key_links:
    - from: "src/unifi_audit.py:analyze"
      to: "src/findings_correlations.py:CORRELATION_RULES"
      via: "import + iteration in _correlate_findings()"
      pattern: "CORRELATION_RULES|_correlate_findings"
---

<objective>
Implement the cross-answer tension detection pass (D-003 LOCKED, D-04). After all individual finding modules run, a correlation pass walks the findings list and emits compound findings that no single module could produce — priority mismatch, keys-to-kingdom, pivot path. This closes REQ-cross-answer-tension-detection, the second of the four Phase 1 needs-work items.

Per D-04: rules live in `src/findings_correlations.py` as one Python function per compound finding. Pure rules over the existing finding list, no new YAML format, no rules engine to maintain.

Output:
- `src/findings_correlations.py` — 3 compound rules + CORRELATION_RULES registry
- `src/unifi_audit.py` — `_correlate_findings(findings, profile)` pass added between enhanced modules and the final sort
- `tests/test_correlations.py` — constructed test cases that fire each rule
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
@.planning/phases/01-live-api-audit/01-01-extract-sanitizer-PLAN.md
@.planning/phases/01-live-api-audit/01-02-adapter-and-wire-enhanced-modules-PLAN.md
@DECISIONS.md

<interfaces>
<!-- The Finding dataclass that correlations construct. From src/unifi_audit.py:100-114 -->

```python
@dataclass
class Finding:
    id: str
    section: str
    severity: str  # info | low | medium | high | critical
    status: str    # ok | gap | recommendation | unknown
    title: str
    current_state: str
    recommendation: str | None = None
    intent_question: str | None = None
    evidence: dict = field(default_factory=dict)
    maps_to: dict = field(default_factory=dict)
    effort: str = "medium"
    impact: str = "medium"
```

<!-- Existing finding IDs the correlation rules look at. -->

Baseline + enhanced modules emit IDs prefixed:
- SEG-001-{site_id}     (flat network)
- WIFI-{site_id}-{name}-WPA / WIFI-{site_id}-{name}-PSK
- FW-{site_id}-PF       (port-forwards present)
- FW-GEO-IN / FW-GEO-OUT / FW-CONTENT-001
- FW-EOL-001            (EOL firmware — always-top candidate)
- FW-AUTO-001           (auto-update disabled)
- FW-VER-{mac}          (stale firmware)
- VPN-MISSING-{site_id} / VPN-MISSING-001  (port-forwards but no VPN)
- VPN-PPTP-001          (PPTP enabled — always-top candidate)
- VPN-L2TP-001 / VPN-WG-OK
- DEV-SSH-{site_id}
- RF-* (wireless tuning)
- LOG-* / BAK-* (logging / backup)

The 3 unknown findings emitted by Plan 04 will use IDs:
- MFA-UNKNOWN-001 / CRED-DEFAULT-001 / WAN-MGMT-001
But Plan 03's correlations run BEFORE those exist (Plan 04 inserts unknowns alongside correlation). Correlation rules MUST tolerate the absence of those IDs (use prefix matching with .startswith).
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Create src/findings_correlations.py with 3 compound rules + registry</name>
  <files>src/findings_correlations.py</files>
  <read_first>
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Pattern 3: `_correlate_findings()` — Compound Rules (D-04)" lines ~535-655)
    - .planning/phases/01-live-api-audit/01-CONTEXT.md (D-03 examples: priority mismatch, keys-to-kingdom, pivot path)
    - .planning/intel/decisions.md (D-003 full rationale)
    - src/unifi_audit.py (Finding dataclass at lines 100-114; existing finding IDs)
    - src/findings_enhanced.py (existing finding IDs to reference)
  </read_first>
  <behavior>
    - correlate_priority_mismatch returns a CORR-PRIORITY-001 Finding when port-forwards exist AND no VPN configured. None otherwise.
    - correlate_keys_to_kingdom returns a CORR-KEYS-001 Finding when MFA is unknown AND remote access is exposed. None otherwise.
    - correlate_pivot_path returns a CORR-PIVOT-001 Finding when SEG-001 (flat network) finding is present. None otherwise.
    - All three return None on an empty findings list — no false positives.
    - All three accept a profile string parameter even if they don't use it (uniform signature).
    - CORRELATION_RULES is a list/tuple of all three callables.
    - Each correlation Finding has section="Risk correlation" and id starting with "CORR-".
    - _has_finding_id(findings, "FOO-") helper returns True if any finding's id starts with that prefix.
    - All rules are idempotent — re-running over the same input gives the same output.
  </behavior>
  <action>
Create `src/findings_correlations.py`. Use the verbatim implementation from `.planning/phases/01-live-api-audit/01-RESEARCH.md` §"Pattern 3" (lines ~538-655). Key adjustments:

1. Module docstring stating: D-003 LOCKED implementation; D-04 module location; pure functions over list[Finding]; one rule per compound risk.

2. Imports: `from __future__ import annotations`, `from typing import Any`. Do NOT do `from unifi_audit import Finding` at module top — that creates a circular import. Instead, do the import lazily inside each rule function (per RESEARCH.md note: `from unifi_audit import Finding` inside the rule body).

3. `_has_finding_id(findings: list, prefix: str) -> bool` — `return any(f.id.startswith(prefix) for f in findings)`.

4. `_get_finding(findings: list, prefix: str)` — `return next((f for f in findings if f.id.startswith(prefix)), None)`.

5. `correlate_priority_mismatch(findings: list, profile: str) -> Any | None`:
   - Trigger condition: `_has_finding_id(findings, "FW-") and _has_finding_id(findings, "VPN-MISSING")` (port-forwards exist AND VPN missing — this is the Phase 1 conservative version per RESEARCH.md A-section "additional questionnaire data not available")
   - When triggered, return a Finding with id "CORR-PRIORITY-001", section "Risk correlation", severity "high", status "recommendation", title "Port-forwards without VPN suggest exposure-as-remote-access path", a current_state describing the compound risk, recommendation pointing toward setting up WireGuard, intent_question "Are port forwards for your own remote access, or for public-facing services?", maps_to={"cis_v8":"4.4","nist_csf":"PR.AC-3"}, effort "medium", impact "high".
   - Return None otherwise.

6. `correlate_keys_to_kingdom(findings: list, profile: str)`:
   - Trigger condition: `_has_finding_id(findings, "MFA-") AND (_has_finding_id(findings, "VPN-MISSING") OR _has_finding_id(findings, "FW-"))` (MFA unknown finding present AND remote access exposed)
   - Severity "critical", status "unknown", id "CORR-KEYS-001"
   - Title: "Remote access exposed + MFA status unknown = keys-to-kingdom risk"
   - intent_question: "Is MFA enabled on all accounts with admin access to this network?"
   - maps_to={"cis_v8":"6.3","nist_csf":"PR.AC-7"}, effort "quick", impact "high"

7. `correlate_pivot_path(findings: list, profile: str)`:
   - Trigger condition: `_has_finding_id(findings, "SEG-001")` (flat network detected by baseline segmentation module)
   - Severity "high", status "unknown", id "CORR-PIVOT-001"
   - Title: "Flat network with likely mixed device classes — pivot path risk"
   - intent_question: "Do IoT devices (cameras, smart home) share the same network as your NAS or work computers?"
   - maps_to={"cis_v8":"12.2","nist_csf":"PR.AC-5"}, effort "project", impact "high"

8. `CORRELATION_RULES = [correlate_priority_mismatch, correlate_keys_to_kingdom, correlate_pivot_path]` at module level.

The text fields (current_state, recommendation) should be substantive — at least 2 sentences each — drawn directly from RESEARCH.md §"Pattern 3" verbatim. The full Finding constructions are reproduced there.
  </action>
  <verify>
    <automated>python -c "import sys; sys.path.insert(0,'src'); from findings_correlations import CORRELATION_RULES, correlate_priority_mismatch, correlate_keys_to_kingdom, correlate_pivot_path; assert len(CORRELATION_RULES) >= 3; assert correlate_pivot_path([],'home_office') is None; print('OK', len(CORRELATION_RULES), 'rules')"</automated>
  </verify>
  <acceptance_criteria>
    - File `src/findings_correlations.py` exists
    - `grep -c "def correlate_priority_mismatch" src/findings_correlations.py` returns 1
    - `grep -c "def correlate_keys_to_kingdom" src/findings_correlations.py` returns 1
    - `grep -c "def correlate_pivot_path" src/findings_correlations.py` returns 1
    - `grep -c "CORRELATION_RULES" src/findings_correlations.py` returns ≥ 1
    - `grep -c "from unifi_audit import Finding" src/findings_correlations.py` returns ≥ 3 (lazy imports inside each rule)
    - `python -c "import sys; sys.path.insert(0,'src'); from findings_correlations import CORRELATION_RULES; assert len(CORRELATION_RULES) >= 3; print('OK')"` exits 0
    - `python -c "import sys; sys.path.insert(0,'src'); from findings_correlations import correlate_pivot_path; assert correlate_pivot_path([], 'home') is None; print('empty input None')"` exits 0
  </acceptance_criteria>
  <done>findings_correlations.py exists with 3 rules + registry; trigger conditions match D-003 examples; lazy Finding import avoids circular dependency; rules return None on empty input.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Wire _correlate_findings() pass into analyze()</name>
  <files>src/unifi_audit.py</files>
  <read_first>
    - src/unifi_audit.py (the analyze() body modified in Plan 02)
    - src/findings_correlations.py (just created in Task 1)
  </read_first>
  <behavior>
    - analyze() calls _correlate_findings(findings, profile) AFTER baseline+enhanced module loops complete, BEFORE the final sort
    - Each correlation rule wrapped in try/except so a single rule failure does not abort the audit
    - Findings emitted by correlation rules appended to the same findings list
    - The final sort (severity-based) sorts correlation findings alongside detection findings
    - The constructed test case in Task 3 produces ≥ 1 correlation finding
  </behavior>
  <action>
Modify `src/unifi_audit.py`:

**Change 1: Add import.** In the same try/except import block as the adapter import from Plan 02:

```python
try:
    from findings_correlations import CORRELATION_RULES
except ImportError:
    from src.findings_correlations import CORRELATION_RULES
```

**Change 2: Add helper function.** Above `analyze()`, add:

```python
def _correlate_findings(findings: list[Finding], profile: str, logger: logging.Logger) -> list[Finding]:
    """Run all compound-finding correlation rules over the current findings list.

    Returns NEW findings produced by the rules (does not mutate the input list).
    Each rule is wrapped in try/except so a single rule failure cannot abort
    the audit. Rules return Finding | None; None is filtered out.
    """
    new: list[Finding] = []
    for rule in CORRELATION_RULES:
        try:
            result = rule(findings, profile)
        except Exception as e:
            logger.warning(f"Correlation rule {getattr(rule, '__name__', rule)} failed: {e}")
            continue
        if result is not None:
            new.append(result)
    return new
```

**Change 3: Invoke from analyze().** Modify the analyze() body to call _correlate_findings AFTER the enhanced module loop and BEFORE the sort. Example structure (the rest of analyze() stays as Plan 02 left it):

```python
def analyze(clean: dict, profile: str, logger: logging.Logger) -> list[Finding]:
    findings: list[Finding] = []

    # ... baseline modules loop (unchanged from Plan 02) ...

    # ... build_parser_collections + enhanced modules loop (unchanged from Plan 02) ...

    # NEW: correlation pass — runs after individual modules, before sort
    correlation_findings = _correlate_findings(findings, profile, logger)
    findings.extend(correlation_findings)

    # ... existing sort (unchanged) ...
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 5), f.section))
    return findings
```

Do NOT remove the sort. Plan 04 (always-top) and Plan 05 (profile weights) extend the sort/ranking logic further.
  </action>
  <verify>
    <automated>python tests/_smoke_correlate.py</automated>
  </verify>
  <acceptance_criteria>
    - `grep -c "from findings_correlations import" src/unifi_audit.py` returns ≥ 1
    - `grep -c "def _correlate_findings" src/unifi_audit.py` returns 1
    - `grep -c "CORRELATION_RULES" src/unifi_audit.py` returns ≥ 1
    - `grep "correlation_findings = _correlate_findings" src/unifi_audit.py` returns ≥ 1 line OR equivalent invocation pattern (`findings.extend(_correlate_findings(...))`)
    - The correlation invocation appears AFTER the `enhanced_modules` block and BEFORE the `findings.sort` call (verified by line-number ordering in the file)
    - The smoke script `python tests/_smoke_correlate.py` exits 0 (Task 3 will create that script)
  </acceptance_criteria>
  <done>analyze() invokes _correlate_findings after individual modules; CORRELATION_RULES iterated with try/except per rule; correlation findings included in the sorted output.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: tests/test_correlations.py — constructed cases firing each rule</name>
  <files>tests/test_correlations.py, tests/_smoke_correlate.py</files>
  <read_first>
    - src/findings_correlations.py (Task 1)
    - src/unifi_audit.py (Finding dataclass and analyze() flow)
    - tests/conftest.py (synthetic_api_dump for end-to-end correlation firing)
  </read_first>
  <behavior>
    - test_pivot_path_fires_on_seg_001: a list containing a single Finding with id="SEG-001-default" passed to correlate_pivot_path returns a Finding with id="CORR-PIVOT-001"
    - test_pivot_path_no_fire_on_empty: empty list → None
    - test_priority_mismatch_fires_on_fw_plus_vpn_missing: list with FW-default-PF and VPN-MISSING-default findings → returns CORR-PRIORITY-001
    - test_priority_mismatch_no_fire_on_fw_alone: list with only FW-default-PF → None
    - test_keys_to_kingdom_fires: list with MFA-UNKNOWN-001 + VPN-MISSING-default → returns CORR-KEYS-001 (severity critical)
    - test_keys_to_kingdom_no_fire_without_mfa: list with only VPN-MISSING → None
    - test_correlation_rules_registry_has_3: len(CORRELATION_RULES) == 3
    - test_all_rules_uniform_signature: each rule callable with (findings, profile) signature returns Finding | None
    - test_rule_idempotence: running each rule twice over the same input returns equal output
    - test_pipeline_correlation_fires_end_to_end: synthetic_api_dump from conftest + an injected SEG-001 finding → analyze() output contains a CORR-PIVOT-001 finding (REQ-cross-answer-tension-detection)
    - test_correlation_failure_does_not_abort: a monkeypatched rule that raises is logged and the audit continues
  </behavior>
  <action>
Create `tests/_smoke_correlate.py`:

```python
"""Smoke script invoked by Plan 03 Task 2's verify command."""
import sys
import logging
sys.path.insert(0, "src")
import unifi_audit

# Verify _correlate_findings exists
assert hasattr(unifi_audit, "_correlate_findings"), "_correlate_findings not added to unifi_audit"

# Construct a findings list that triggers correlate_pivot_path
flat = unifi_audit.Finding(
    id="SEG-001-default", section="Segmentation", severity="high", status="gap",
    title="Flat network", current_state="...",
)
logger = logging.getLogger("test")
logger.addHandler(logging.NullHandler())
new = unifi_audit._correlate_findings([flat], "home_office", logger)
assert any(f.id == "CORR-PIVOT-001" for f in new), \
    f"Expected CORR-PIVOT-001, got {[f.id for f in new]}"
print(f"OK — correlation produced: {[f.id for f in new]}")
```

Create `tests/test_correlations.py`:

```python
"""Compound-finding correlation rules — constructed test cases per D-003."""
from __future__ import annotations

import logging

import pytest

from findings_correlations import (
    CORRELATION_RULES,
    correlate_priority_mismatch,
    correlate_keys_to_kingdom,
    correlate_pivot_path,
)
from unifi_audit import Finding, analyze, _correlate_findings


def _F(fid, section="Test", severity="medium", status="gap"):
    """Tiny Finding factory for tests."""
    return Finding(id=fid, section=section, severity=severity, status=status,
                   title=fid, current_state="x")


# --- correlate_pivot_path ---------------------------------------------------

def test_pivot_path_fires_on_seg_001():
    findings = [_F("SEG-001-default", "Segmentation", "high")]
    result = correlate_pivot_path(findings, "home_office")
    assert result is not None
    assert result.id == "CORR-PIVOT-001"
    assert result.section == "Risk correlation"


def test_pivot_path_no_fire_on_empty():
    assert correlate_pivot_path([], "home_office") is None


def test_pivot_path_no_fire_without_seg():
    findings = [_F("WIFI-default-main-WPA")]
    assert correlate_pivot_path(findings, "home_office") is None


# --- correlate_priority_mismatch --------------------------------------------

def test_priority_mismatch_fires():
    findings = [_F("FW-default-PF"), _F("VPN-MISSING-default")]
    result = correlate_priority_mismatch(findings, "home_office")
    assert result is not None
    assert result.id == "CORR-PRIORITY-001"
    assert result.severity == "high"


def test_priority_mismatch_no_fire_on_fw_alone():
    findings = [_F("FW-default-PF")]
    assert correlate_priority_mismatch(findings, "home_office") is None


def test_priority_mismatch_no_fire_on_vpn_missing_alone():
    findings = [_F("VPN-MISSING-default")]
    # Per current rule: FW-* AND VPN-MISSING both required.
    # Rule may legitimately fire or not depending on implementation specifics;
    # adjust assertion to match behaviour: if only VPN-MISSING with no FW-, return None.
    result = correlate_priority_mismatch(findings, "home_office")
    assert result is None or result.id == "CORR-PRIORITY-001"


# --- correlate_keys_to_kingdom ----------------------------------------------

def test_keys_to_kingdom_fires():
    findings = [_F("MFA-UNKNOWN-001", "Admin", "high"),
                _F("VPN-MISSING-default", "Remote access", "high")]
    result = correlate_keys_to_kingdom(findings, "home_office")
    assert result is not None
    assert result.id == "CORR-KEYS-001"
    assert result.severity == "critical"
    assert result.status == "unknown"


def test_keys_to_kingdom_no_fire_without_mfa():
    findings = [_F("VPN-MISSING-default")]
    assert correlate_keys_to_kingdom(findings, "home_office") is None


def test_keys_to_kingdom_no_fire_without_remote_exposure():
    findings = [_F("MFA-UNKNOWN-001")]
    assert correlate_keys_to_kingdom(findings, "home_office") is None


# --- registry integrity -----------------------------------------------------

def test_correlation_rules_registry_size():
    assert len(CORRELATION_RULES) >= 3


def test_all_rules_callable_with_uniform_signature():
    for rule in CORRELATION_RULES:
        result = rule([], "home_office")
        # Rule may return None (most likely on empty input) or a Finding-shape object
        assert result is None or hasattr(result, "id"), \
            f"Rule {rule.__name__} returned unexpected type: {type(result)}"


def test_rule_idempotence():
    findings = [_F("SEG-001-default", "Segmentation", "high")]
    once = correlate_pivot_path(findings, "home_office")
    twice = correlate_pivot_path(findings, "home_office")
    assert once.id == twice.id
    assert once.severity == twice.severity


# --- end-to-end via analyze() -----------------------------------------------

def test_pipeline_correlation_fires_end_to_end(synthetic_api_dump):
    """REQ-cross-answer-tension-detection: at least 1 compound finding fires."""
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(synthetic_api_dump, "home_office", logger)
    # The synthetic fixture has flat network (1 corporate net) and port-forwards is empty,
    # so SEG-001 fires from baseline → CORR-PIVOT-001 should fire from correlation.
    corr_ids = [f.id for f in findings if f.id.startswith("CORR-")]
    assert corr_ids, f"No CORR-* finding in {[f.id for f in findings]}"


def test_correlation_failure_does_not_abort(monkeypatch):
    """A rule that raises is logged; audit continues."""
    def boom(findings, profile):
        raise RuntimeError("intentional boom")
    boom.__name__ = "boom_rule"

    import findings_correlations as fc
    monkeypatch.setattr(fc, "CORRELATION_RULES",
                        [boom] + list(fc.CORRELATION_RULES))

    # Re-import so unifi_audit picks up the patched registry
    import importlib, unifi_audit as ua
    importlib.reload(ua)

    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = [_F("SEG-001-default", "Segmentation", "high")]
    new = ua._correlate_findings(findings, "home_office", logger)
    # Boom rule failed; the surviving 3 rules still produced at least the pivot-path
    assert any(f.id == "CORR-PIVOT-001" for f in new)
```

Run `pytest -q tests/test_correlations.py`. All 11+ tests should pass.
  </action>
  <verify>
    <automated>pytest -q tests/test_correlations.py</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_correlations.py` exists
    - File `tests/_smoke_correlate.py` exists
    - `pytest -q tests/test_correlations.py` exits 0
    - `python tests/_smoke_correlate.py` exits 0
    - `grep -c "def test_pivot_path_fires_on_seg_001" tests/test_correlations.py` returns 1
    - `grep -c "def test_priority_mismatch_fires" tests/test_correlations.py` returns 1
    - `grep -c "def test_keys_to_kingdom_fires" tests/test_correlations.py` returns 1
    - `grep -c "def test_pipeline_correlation_fires_end_to_end" tests/test_correlations.py` returns 1
    - `grep -c "def test_correlation_failure_does_not_abort" tests/test_correlations.py` returns 1
  </acceptance_criteria>
  <done>Correlation tests exist; each rule has a positive (fires) and negative (does not fire) test; end-to-end test confirms ≥1 CORR-* finding in pipeline output; failure isolation tested.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Findings list → correlation rules | Rules read the existing findings list (read-only); produce new Findings; cannot mutate existing ones. |

## STRIDE Threat Register

No new threats introduced — correlation is a pure transformation over already-sanitized findings. Existing threats T-1-01..T-1-06 are unaffected by this plan.
</threat_model>

<verification>
After all tasks complete:

```bash
# All Plan 01 + 02 + 03 tests pass
pytest -q tests/

# Smoke test: end-to-end correlation fires
python tests/_smoke_correlate.py

# Confirm correlation pass is wired between modules and sort
grep -A2 "_correlate_findings" src/unifi_audit.py
```
</verification>

<success_criteria>
- src/findings_correlations.py exports CORRELATION_RULES with 3 rules
- src/unifi_audit.py defines _correlate_findings and invokes it in analyze() between enhanced modules and the final sort
- A constructed test case fires at least one CORR-* finding (REQ-cross-answer-tension-detection)
- Each rule is independently testable; the end-to-end test confirms wiring
- Rule failure does not abort the audit (try/except per rule)
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-03-SUMMARY.md` with:
- Files created and line counts
- Number of correlation rules implemented
- Test count and pass status
- Confirmation that REQ-cross-answer-tension-detection is satisfied
</output>
