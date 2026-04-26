"""Shared pytest fixtures for Phase 1 tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_FIXTURE = REPO_ROOT / "samples" / "fixtures" / "api_dump_home_office.json"
TESTS_FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def canonical_api_dump() -> dict:
    """Load the committed canonical fixture if it exists; skip the test otherwise.

    Plan 08 commits this file. Tests that depend on it before Plan 08 lands
    will skip cleanly, not fail.
    """
    if not CANONICAL_FIXTURE.exists():
        pytest.skip(f"Canonical fixture not yet captured: {CANONICAL_FIXTURE}")
    return json.loads(CANONICAL_FIXTURE.read_text())


@pytest.fixture
def synthetic_api_dump() -> dict:
    """Minimal synthetic API dump shaped like collect_all() output post-sanitize.

    No real data. Safe for unit tests that need a non-empty pipeline input.
    """
    return {
        "_endpoints_probed": [{"name": "sites", "status": 200}],
        "_errors": [],
        "_site_count": 1,
        "site_default": {
            "_meta": {"id": "default", "name": "test-site"},
            "devices": {
                "data": [
                    {
                        "macAddress": "02:00:00:00:00:01",
                        "ipAddress": "192.0.2.10",
                        "model": "U6-Pro",
                        "name": "ap-0",
                        "type": "uap",
                        "state": "connected",
                        "sshEnabled": False,
                        "version": "7.0.66",
                    }
                ],
                "totalCount": 1,
            },
            "wlans": {
                "data": [
                    {
                        "name": "test-ssid",
                        "enabled": True,
                        "security": "wpapsk",
                        "wpa_mode": "wpa2",
                        "x_passphrase": {"length": 18, "fingerprint": "abc123def456",
                                          "has_symbols": True, "has_digits": True,
                                          "has_mixed_case": True},
                        "pmf_mode": "disabled",
                    }
                ],
                "totalCount": 1,
            },
            "networks": {
                "data": [{"name": "main", "purpose": "corporate", "vlan": 1}],
                "totalCount": 1,
            },
            "port_forwards": {"data": [], "totalCount": 0},
            "vpn_configs": {"data": [], "totalCount": 0},
            "firewall_policies": {"data": [], "totalCount": 0},
            "firewall_zones": {"data": [], "totalCount": 0},
            "traffic_routes": {"data": [], "totalCount": 0},
            "clients": {"data": [], "totalCount": 0},
        },
    }


@pytest.fixture
def tagged_secret_blob() -> tuple[str, dict]:
    """Return (TAG, dict) where dict has the tag string injected under each
    SECRET_FIELD_NAMES key. Used for round-trip leak detection in test_sanitizer."""
    TAG = "UNIQUE_SECRET_TAG_7f3a9b2c_DO_NOT_COMMIT"
    # Import lazily so tests can use this fixture even before Task 1's import path is hot
    import sys
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from sanitizer import SECRET_FIELD_NAMES
    blob = {k: TAG for k in sorted(SECRET_FIELD_NAMES)}
    return TAG, blob
