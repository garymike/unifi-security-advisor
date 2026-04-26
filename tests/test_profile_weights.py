"""Profile-weight cell coverage, always-top bypass, ranking-changes-by-profile.

Tests for Plan 01-05 (REQ-profile-aware-scoring-weights, T-1-05 mitigation).
"""
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


# ---------------------------------------------------------------------------
# Cell coverage
# ---------------------------------------------------------------------------

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
    """At least 5 profiles x 10 sections = 50 cells."""
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


# ---------------------------------------------------------------------------
# score_finding
# ---------------------------------------------------------------------------

def _F(section, severity="medium", status="gap", impact="medium", effort="medium"):
    """Helper: construct a minimal Finding for scoring tests."""
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
    # impact defaults to medium=2, effort to medium=8, weight=1.0 -> 0.25
    assert abs(score - 0.25) < 0.001


def test_score_finding_higher_for_higher_amplified_section():
    f = _F("Logging", impact="high", effort="quick")
    home_score = score_finding(f, "home")
    hipaa_score = score_finding(f, "regulated_hipaa")
    assert hipaa_score > home_score, \
        "regulated_hipaa Logging should outrank home Logging for the same finding"


# ---------------------------------------------------------------------------
# T-1-05: always-top bypasses weights
# ---------------------------------------------------------------------------

def test_always_top_bypasses_weights():
    """A VPN-PPTP-001 finding with impact=low effort=project (worst score)
    still appears in the always-top group regardless of profile weight.

    This is the structural guarantee: _apply_float_top runs AFTER the sort,
    so weight-based ranking cannot demote always-top findings.
    """
    f_pptp = Finding(id="VPN-PPTP-001", section="Remote access",
                     severity="critical", status="gap", title="t", current_state="c",
                     impact="low", effort="project")   # intentionally bad score
    f_other = Finding(id="WIFI-x", section="Wi-Fi",
                      severity="critical", status="gap", title="t", current_state="c",
                      impact="high", effort="quick")   # great score

    # Reproduce the analyze() ranking + float-top steps manually
    from unifi_audit import _apply_float_top
    findings = [f_other, f_pptp]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (
        order.get(f.severity, 5),
        -score_finding(f, "home"),
        f.section,
    ))
    # After sort, f_other ranks before f_pptp (better score)
    findings = _apply_float_top(findings)
    # After float_top, PPTP must come first
    assert findings[0].id == "VPN-PPTP-001", \
        f"Always-top failed; got {[f.id for f in findings]}"


# ---------------------------------------------------------------------------
# End-to-end: ranking changes by profile
# ---------------------------------------------------------------------------

def test_ranking_changes_between_home_and_regulated_hipaa(synthetic_api_dump):
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())

    home_findings = analyze(synthetic_api_dump, "home", logger)
    hipaa_findings = analyze(synthetic_api_dump, "regulated_hipaa", logger)

    # Same evidence -> same set of finding IDs; only ordering differs
    home_ids = [f.id for f in home_findings]
    hipaa_ids = [f.id for f in hipaa_findings]
    assert set(home_ids) == set(hipaa_ids), \
        "Same evidence should produce same set of findings; only ordering differs"

    # LOG-FWD-001 should rank equal or higher (lower index) under regulated_hipaa
    # because (regulated_hipaa, Logging) = 2.0 vs (home, Logging) = 0.4
    if "LOG-FWD-001" in home_ids and "LOG-FWD-001" in hipaa_ids:
        home_pos = home_ids.index("LOG-FWD-001")
        hipaa_pos = hipaa_ids.index("LOG-FWD-001")
        assert hipaa_pos <= home_pos, (
            f"LOG-FWD-001 expected at equal/higher rank in regulated_hipaa: "
            f"home pos={home_pos}, hipaa pos={hipaa_pos}"
        )


def test_always_top_set_is_first_under_every_profile(synthetic_api_dump):
    """T-1-05/T-1-06 cross-check: under every profile, always-top findings
    occupy the leading positions."""
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())

    for profile in REQUIRED_PROFILES:
        findings = analyze(synthetic_api_dump, profile, logger)
        top_count = sum(
            1 for f in findings
            if any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS)
        )
        assert top_count > 0, f"Profile {profile}: no always-top findings"
        for i in range(top_count):
            f = findings[i]
            assert any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS), (
                f"Profile {profile}: position {i} ({f.id}) is not always-top"
            )


# ---------------------------------------------------------------------------
# render_report: manual profile label
# ---------------------------------------------------------------------------

def test_render_report_shows_manual_profile(synthetic_api_dump):
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())

    findings = analyze(synthetic_api_dump, "home_office", logger)
    report = render_report(findings, synthetic_api_dump, "home_office")
    assert "(manual)" in report, "Profile label missing '(manual)' suffix"
    assert "home_office" in report


# ---------------------------------------------------------------------------
# Bogus profile fallback in load_config
# ---------------------------------------------------------------------------

def test_load_config_unknown_profile_falls_back_to_home_office(monkeypatch, capsys):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_HOST", "192.0.2.1")
    monkeypatch.setenv("UNIFI_PROFILE", "bogus_profile_typo")
    cfg = load_config()
    assert cfg["profile"] == "home_office"
    captured = capsys.readouterr()
    assert (
        "not a recognized profile" in captured.err.lower()
        or "warning" in captured.err.lower()
    )
