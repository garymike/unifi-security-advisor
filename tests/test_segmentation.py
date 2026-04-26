"""SEG-001 segmentation finding — Integration v1 + parser-shape coverage.

Regression for the bug where `_find_segmentation` only recognized parser-shape
`purpose` fields and silently counted 0 user-defined networks on Integration v1
API responses (which use `metadata.origin` instead of `purpose`).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from unifi_audit import (
    Finding,
    _find_segmentation,
    _is_user_defined_network,
    analyze,
)

_TEST_LOGGER = logging.getLogger("test_segmentation")


# ---------------------------------------------------------------------------
# _is_user_defined_network — unit tests for the shared helper
# ---------------------------------------------------------------------------

def test_helper_integration_v1_user_defined():
    """Integration v1: metadata.origin == USER_DEFINED -> user network."""
    assert _is_user_defined_network({"metadata": {"origin": "USER_DEFINED"}})


def test_helper_integration_v1_system_defined():
    """Integration v1: metadata.origin == SYSTEM_DEFINED -> not a user network."""
    assert not _is_user_defined_network({"metadata": {"origin": "SYSTEM_DEFINED"}})


def test_helper_parser_shape_corporate():
    """Parser/backup shape: purpose=corporate -> user network."""
    assert _is_user_defined_network({"purpose": "corporate"})


def test_helper_parser_shape_guest():
    """Parser/backup shape: purpose=guest -> user network."""
    assert _is_user_defined_network({"purpose": "guest"})


def test_helper_parser_shape_vlan_only():
    """Parser/backup shape: purpose=vlan-only -> user network."""
    assert _is_user_defined_network({"purpose": "vlan-only"})


def test_helper_empty_dict():
    """Empty dict (no purpose, no metadata) -> not a user network; no crash."""
    assert not _is_user_defined_network({})


def test_helper_missing_metadata_key():
    """purpose absent and metadata absent -> False without raising KeyError."""
    assert not _is_user_defined_network({"name": "anything", "vlan": 1})


def test_helper_metadata_is_none():
    """metadata=None must not raise (the `or {}` guard handles it)."""
    assert not _is_user_defined_network({"metadata": None})


def test_helper_unrelated_purpose_value():
    """Unrelated purpose values (e.g., wan) -> not a user network."""
    assert not _is_user_defined_network({"purpose": "wan"})


def test_helper_purpose_takes_precedence_over_metadata():
    """If both shapes present and purpose matches, return True without checking metadata."""
    n = {"purpose": "corporate", "metadata": {"origin": "SYSTEM_DEFINED"}}
    assert _is_user_defined_network(n) is True


# ---------------------------------------------------------------------------
# _find_segmentation — module-level tests for both data shapes
# ---------------------------------------------------------------------------

def _site(networks: list[dict]) -> dict:
    """Wrap a list of network dicts in the per-site clean-dict shape."""
    return {
        "site_default": {
            "networks": {"data": networks, "totalCount": len(networks)},
        }
    }


def _seg_findings(clean: dict) -> list[Finding]:
    return _find_segmentation(clean, profile="home_office")


def test_seg001_integration_v1_one_user_defined_network_fires_with_count_1():
    """Bug regression: with 1 SYSTEM + 1 USER_DEFINED, SEG-001 fires AND
    evidence.network_count is 1 (not 0). Pre-fix it was 0 because the
    raw-path filter never matched any Integration v1 network."""
    clean = _site([
        {"name": "Default", "metadata": {"origin": "SYSTEM_DEFINED"}, "default": True},
        {"name": "IoT", "metadata": {"origin": "USER_DEFINED"}, "default": False},
    ])
    findings = _seg_findings(clean)
    assert len(findings) == 1
    assert findings[0].id == "SEG-001-default"
    # The crucial assertion: count is 1, not 0. Pre-fix this was 0.
    assert findings[0].evidence == {"network_count": 1}


def test_seg001_integration_v1_two_user_defined_networks_does_not_fire():
    """With 2 user-defined VLANs (genuine segmentation), SEG-001 must NOT fire."""
    clean = _site([
        {"name": "Default", "metadata": {"origin": "SYSTEM_DEFINED"}, "default": True},
        {"name": "IoT", "metadata": {"origin": "USER_DEFINED"}, "default": False},
        {"name": "Work", "metadata": {"origin": "USER_DEFINED"}, "default": False},
    ])
    assert _seg_findings(clean) == []


def test_seg001_parser_shape_two_corporate_networks_does_not_fire():
    """Parser/backup shape: 2 user networks -> SEG-001 must NOT fire."""
    clean = _site([
        {"name": "main", "purpose": "corporate", "vlan": 1},
        {"name": "iot", "purpose": "vlan-only", "vlan": 30},
    ])
    assert _seg_findings(clean) == []


def test_seg001_parser_shape_only_default_fires():
    """Parser shape: only a default LAN with no purpose -> flat -> SEG-001 fires."""
    clean = _site([{"name": "main"}])  # no purpose, no metadata
    findings = _seg_findings(clean)
    assert len(findings) == 1
    assert findings[0].evidence == {"network_count": 0}


def test_seg001_mixed_shape_counts_both():
    """Mixed-shape data: one Integration v1 USER_DEFINED + one parser corporate
    -> 2 user networks -> SEG-001 does NOT fire."""
    clean = _site([
        {"name": "Default", "metadata": {"origin": "SYSTEM_DEFINED"}},
        {"name": "Backup-mode IoT", "purpose": "vlan-only"},  # parser shape
        {"name": "API IoT", "metadata": {"origin": "USER_DEFINED"}},  # Integration v1
    ])
    assert _seg_findings(clean) == []


def test_seg001_genuinely_flat_integration_v1_fires():
    """Only system_defined networks -> truly flat -> SEG-001 fires."""
    clean = _site([
        {"name": "Default", "metadata": {"origin": "SYSTEM_DEFINED"}, "default": True},
    ])
    findings = _seg_findings(clean)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].evidence == {"network_count": 0}


# ---------------------------------------------------------------------------
# Captured-fixture regression: real Integration v1 response shape
# ---------------------------------------------------------------------------

CAPTURED_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "raw_sanitized.json"
)


def test_captured_fixture_seg001_evidence_uses_real_network_count():
    """Regression for the bug: against the user's real Integration v1 capture,
    SEG-001 evidence must show the actual count of user-defined networks
    (>= 1 if any USER_DEFINED network is present), not the broken 0 from
    the pre-fix raw-path filter.

    Skipped if the fixture file does not exist (it's gitignored — only
    present on machines that ran the audit and copied the output)."""
    if not CAPTURED_FIXTURE.exists():
        import pytest
        pytest.skip(f"Captured fixture not present: {CAPTURED_FIXTURE}")

    data = json.loads(CAPTURED_FIXTURE.read_text())

    # Count USER_DEFINED networks across all sites in the captured data.
    user_defined_count = 0
    for key, val in data.items():
        if not (key.startswith("site_") and isinstance(val, dict)):
            continue
        nets_blob = val.get("networks") or {}
        nets = nets_blob.get("data") if isinstance(nets_blob, dict) else nets_blob
        if not isinstance(nets, list):
            continue
        for n in nets:
            if isinstance(n, dict) and _is_user_defined_network(n):
                user_defined_count += 1

    findings = analyze(data, profile="home_office", logger=_TEST_LOGGER)
    seg_findings = [f for f in findings if f.id.startswith("SEG-001")]

    if user_defined_count > 1:
        # Genuinely segmented -> SEG-001 must NOT fire
        assert seg_findings == [], (
            f"SEG-001 fired with {user_defined_count} user-defined networks present"
        )
    else:
        # Genuinely flat (<=1 user-defined) -> SEG-001 must fire AND evidence
        # must reflect the real count, not 0 (which was the bug).
        assert len(seg_findings) >= 1, "SEG-001 did not fire on a flat network"
        assert seg_findings[0].evidence["network_count"] == user_defined_count, (
            "Pre-fix bug regression: evidence.network_count must equal the "
            "actual user-defined network count, not 0."
        )
