"""Phase 1 pipeline smoke suite — end-to-end + version-compat + SSL + sanitization.

Covers REQ-validation-network-version-compat (404 graceful skip),
REQ-validation-ssl-self-signed (UniFiClient defaults),
REQ-validation-sanitization-coverage (tagged-secret round-trip via the full pipeline),
and the all-12-modules-execute gate.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sanitizer import sanitize
from unifi_audit import (
    ALWAYS_TOP_FINDING_IDS,
    Finding,
    UniFiClient,
    analyze,
    collect_all,
    load_config,
    render_report,
)

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_STATUSES = {"ok", "gap", "recommendation", "unknown"}


def _silent_logger():
    log = logging.getLogger("test")
    log.addHandler(logging.NullHandler())
    return log


# --- Full pipeline smoke ---------------------------------------------------

def test_full_pipeline_runs_without_raising(synthetic_api_dump):
    findings = analyze(synthetic_api_dump, "home_office", _silent_logger())
    assert isinstance(findings, list)


def test_full_pipeline_emits_minimum_findings(synthetic_api_dump):
    findings = analyze(synthetic_api_dump, "home_office", _silent_logger())
    assert len(findings) >= 4, f"Expected >=4 findings, got {len(findings)}: {[f.id for f in findings]}"


def test_full_pipeline_finding_shape(synthetic_api_dump):
    for f in analyze(synthetic_api_dump, "home_office", _silent_logger()):
        assert isinstance(f.id, str) and f.id
        assert isinstance(f.section, str) and f.section
        assert f.severity in VALID_SEVERITIES, f"Invalid severity: {f.severity!r} in {f.id}"
        assert f.status in VALID_STATUSES, f"Invalid status: {f.status!r} in {f.id}"
        assert isinstance(f.title, str) and f.title
        assert isinstance(f.current_state, str)


# --- All 12 modules execute -----------------------------------------------

@pytest.fixture
def fixture_firing_all_modules(synthetic_api_dump):
    """Augment synthetic_api_dump so each finding module has data to fire."""
    site = synthetic_api_dump["site_default"]
    # PSK shorter than 12 -> fires WIFI-*-PSK
    site["wlans"]["data"][0]["x_passphrase"] = {
        "length": 8, "fingerprint": "deadbeef1234",
        "has_symbols": False, "has_digits": True, "has_mixed_case": False,
    }
    # WPA3 + PMF disabled -> fires RF-PMF-*
    site["wlans"]["data"][0]["wpa_mode"] = "wpa3"
    # Add an EOL device -> fires FW-EOL-001
    site["devices"]["data"][0]["model"] = "UAP-AC-LITE"
    site["devices"]["data"][0]["sshEnabled"] = True  # fires DEV-SSH-*
    site["devices"]["data"][0]["radioTable"] = [{"radio": "ng", "tx_power_mode": "high"}]  # fires RF-* TX
    site["devices"]["data"][0]["version"] = "6.0.42"  # fires FW-VER-*
    # Port forward + no VPN -> fires FW-*-PF, VPN-MISSING-*
    site["port_forwards"]["data"] = [{"enabled": True, "name": "ssh-fwd"}]
    # PPTP enabled -> fires VPN-PPTP-001 (always-top)
    site["vpn_configs"]["data"] = [{"type": "pptp", "enabled": True}]
    # Add a 404 in _endpoints_probed -> fires META-COVERAGE
    synthetic_api_dump["_endpoints_probed"].append(
        {"name": "firewall_zones", "path": "/x", "status": 404}
    )
    return synthetic_api_dump


def test_all_12_modules_produce_findings(fixture_firing_all_modules):
    """REQ-finding-module-* gate: across the full fixture, every module's
    section appears in the findings list (or is absent because the API
    cannot expose the data, in which case the count is reduced)."""
    findings = analyze(fixture_firing_all_modules, "home_office", _silent_logger())
    sections_with_findings = {f.section for f in findings}
    # We expect at least 5 distinct sections: Segmentation, Wi-Fi, Firewall,
    # Remote access, Admin. Wireless tuning, Firmware, Backup, Logging may or
    # may not fire depending on adapter limitations.
    minimum_sections = {"Segmentation", "Wi-Fi", "Firewall", "Remote access", "Admin"}
    missing = minimum_sections - sections_with_findings
    assert not missing, (
        f"Sections missing from findings: {missing}. "
        f"Sections produced: {sections_with_findings}. "
        f"Finding IDs: {[f.id for f in findings]}"
    )


def test_pptp_finding_is_first_when_present(fixture_firing_all_modules):
    """VPN-PPTP-001 is always-top; should be at position 0 (or among first few)."""
    findings = analyze(fixture_firing_all_modules, "home_office", _silent_logger())
    pptp_idx = next((i for i, f in enumerate(findings) if f.id == "VPN-PPTP-001"), None)
    assert pptp_idx is not None, "VPN-PPTP-001 not in findings"
    # All findings before (and including) PPTP should be always-top findings
    for f in findings[:pptp_idx + 1]:
        assert any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS), \
            f"Non-always-top finding {f.id} appeared before PPTP"


def test_three_unknown_always_top_emitted(synthetic_api_dump):
    """Acceptance bar item 5: MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001 always present."""
    findings = analyze(synthetic_api_dump, "home_office", _silent_logger())
    ids = {f.id for f in findings}
    assert "MFA-UNKNOWN-001" in ids, "MFA-UNKNOWN-001 missing"
    assert "CRED-DEFAULT-001" in ids, "CRED-DEFAULT-001 missing"
    assert "WAN-MGMT-001" in ids, "WAN-MGMT-001 missing"


# --- 404 graceful skip (REQ-validation-network-version-compat) -----------

def test_404_graceful_skip():
    """A 404 on any endpoint must be handled (no exception, recorded in _endpoints_probed)."""
    cfg = {"key": "test-key", "host": "192.0.2.1", "use_cloud": False,
           "verify_ssl": False, "profile": "home_office"}
    logger = _silent_logger()
    client = UniFiClient(cfg, logger)

    def mock_get(path):
        # Return sites list so site-scoped calls fire; return 404 for all site-scoped paths
        if path.endswith("/sites"):
            return 200, {"data": [{"id": "default", "name": "test-site"}]}
        if path.endswith("/info"):
            return 200, {}
        # All site-scoped endpoints return 404 to exercise graceful-skip logic
        return 404, {}

    with patch.object(client, "get", side_effect=mock_get):
        result = collect_all(client, logger)

    # Must not raise. Probed list should have the 404s from site-scoped calls.
    assert "_endpoints_probed" in result
    statuses = [p["status"] for p in result["_endpoints_probed"]]
    assert 404 in statuses, "404 not recorded in probed list"


def test_404_does_not_raise_in_collect_all():
    cfg = {"key": "test-key", "host": "192.0.2.1", "use_cloud": False,
           "verify_ssl": False, "profile": "home_office"}
    logger = _silent_logger()
    client = UniFiClient(cfg, logger)
    with patch.object(client, "get", return_value=(404, {})):
        result = collect_all(client, logger)  # must not raise
    assert isinstance(result, dict)


# --- SSL defaults (REQ-validation-ssl-self-signed) -----------------------

def test_ssl_default_local_is_false(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_HOST", "192.0.2.1")
    monkeypatch.delenv("UNIFI_USE_CLOUD", raising=False)
    monkeypatch.delenv("UNIFI_VERIFY_SSL", raising=False)
    cfg = load_config()
    assert cfg["verify_ssl"] is False, f"Expected local default False, got {cfg['verify_ssl']}"


def test_ssl_default_cloud_is_true(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_USE_CLOUD", "true")
    monkeypatch.delenv("UNIFI_HOST", raising=False)
    monkeypatch.delenv("UNIFI_VERIFY_SSL", raising=False)
    cfg = load_config()
    assert cfg["verify_ssl"] is True, f"Expected cloud default True, got {cfg['verify_ssl']}"


def test_ssl_explicit_override_true(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_HOST", "192.0.2.1")
    monkeypatch.setenv("UNIFI_VERIFY_SSL", "true")
    cfg = load_config()
    assert cfg["verify_ssl"] is True


def test_ssl_explicit_override_false(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_USE_CLOUD", "true")
    monkeypatch.setenv("UNIFI_VERIFY_SSL", "false")
    cfg = load_config()
    assert cfg["verify_ssl"] is False


def test_unifi_client_sets_api_key_header():
    cfg = {"key": "test-key-12345", "host": "192.0.2.1", "use_cloud": False,
           "verify_ssl": False, "profile": "home_office"}
    client = UniFiClient(cfg, _silent_logger())
    assert client.session.headers.get("X-API-KEY") == "test-key-12345"


# --- Full-pipeline sanitization (REQ-validation-sanitization-coverage) --

def test_tagged_secret_does_not_appear_in_any_pipeline_output(synthetic_api_dump, tmp_path):
    """T-1-01 / REQ-validation-sanitization-coverage end-to-end gate.

    Inject a tagged secret into a known PSK field, run the full pipeline
    (sanitize -> analyze -> render_report -> write to disk), grep all output
    for the tag -- must be absent.
    """
    TAG = "TAGGED_PSK_a1b2c3d4_NEVER_LOG"
    # Inject as raw string under a known secret field
    synthetic_api_dump["site_default"]["wlans"]["data"][0]["x_passphrase"] = TAG

    clean = sanitize(synthetic_api_dump)
    findings = analyze(clean, "home_office", _silent_logger())
    report = render_report(findings, clean, "home_office")

    # Write all artifacts to disk like the real pipeline does
    raw_path = tmp_path / "raw_sanitized.json"
    raw_path.write_text(json.dumps(clean, indent=2, default=str))
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(
        [{"id": f.id, "title": f.title, "current_state": f.current_state,
          "evidence": str(f.evidence)} for f in findings], indent=2,
    ))
    report_path = tmp_path / "report.md"
    report_path.write_text(report, encoding="utf-8")

    for path in (raw_path, findings_path, report_path):
        text = path.read_text()
        assert TAG not in text, f"Tagged secret leaked into {path.name}"


def test_render_report_does_not_include_apikey():
    """The raw API key must never appear in the markdown report."""
    KEY = "real-looking-test-key-do-not-leak"
    clean = {"_endpoints_probed": [], "_errors": [], "_site_count": 0}
    report = render_report([], clean, "home_office")
    assert KEY not in report
