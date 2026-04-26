"""Compound-finding correlation rules — constructed test cases per D-003.

REQ-cross-answer-tension-detection: verifies that the _correlate_findings() pass
produces at least one compound CORR-* finding when trigger conditions are met.
"""
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
    # Rule requires BOTH FW-* AND VPN-MISSING-* to fire.
    # With only VPN-MISSING and no FW- prefix, rule must return None.
    findings = [_F("VPN-MISSING-default")]
    result = correlate_priority_mismatch(findings, "home_office")
    assert result is None


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


def test_keys_to_kingdom_fires_with_fw_exposure():
    """keys-to-kingdom also fires when FW-* (port-forwards) are present."""
    findings = [_F("MFA-UNKNOWN-001", "Admin", "high"),
                _F("FW-default-PF", "Firewall", "info")]
    result = correlate_keys_to_kingdom(findings, "home_office")
    assert result is not None
    assert result.id == "CORR-KEYS-001"


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
    assert once is not None and twice is not None
    assert once.id == twice.id
    assert once.severity == twice.severity


# --- end-to-end via analyze() -----------------------------------------------

def test_pipeline_correlation_fires_end_to_end(synthetic_api_dump):
    """REQ-cross-answer-tension-detection: at least 1 compound finding fires.

    The synthetic fixture has a flat network (1 corporate net) and no port-forwards,
    so SEG-001 fires from the baseline segmentation module, which triggers
    CORR-PIVOT-001 from the correlation pass.
    """
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(synthetic_api_dump, "home_office", logger)
    corr_ids = [f.id for f in findings if f.id.startswith("CORR-")]
    assert corr_ids, f"No CORR-* finding in {[f.id for f in findings]}"


def test_correlation_failure_does_not_abort(monkeypatch):
    """A rule that raises is logged; the audit continues and surviving rules run."""
    def boom(findings, profile):
        raise RuntimeError("intentional boom")
    boom.__name__ = "boom_rule"

    import findings_correlations as fc
    original_rules = list(fc.CORRELATION_RULES)
    monkeypatch.setattr(fc, "CORRELATION_RULES", [boom] + original_rules)

    # Re-import so unifi_audit picks up the patched registry
    import importlib
    import unifi_audit as ua
    importlib.reload(ua)

    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = [_F("SEG-001-default", "Segmentation", "high")]
    new = ua._correlate_findings(findings, "home_office", logger)
    # boom rule failed; the surviving rules still produce the pivot-path finding
    assert any(f.id == "CORR-PIVOT-001" for f in new), \
        f"Expected CORR-PIVOT-001 from surviving rules; got {[f.id for f in new]}"
