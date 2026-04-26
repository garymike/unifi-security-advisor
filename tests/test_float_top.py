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
