"""Adapter (build_parser_collections) coverage."""
from __future__ import annotations

import logging

import pytest

from api_to_collections import build_parser_collections


def test_empty_input_returns_all_required_keys():
    r = build_parser_collections({})
    required = {
        "device", "wlanconf", "networkconf", "portforward", "firewallrule",
        "firewallgroup", "user", "vpn_pptp", "vpn_l2tp", "vpn_wireguard",
        "vpn_openvpn", "auto_update", "auto_backup", "mgmt", "dpi",
        "rogueap", "dns_filtering",
    }
    assert required.issubset(r.keys()), f"missing keys: {required - set(r.keys())}"


def test_single_site_device_camelcase_mapped():
    r = build_parser_collections({
        "site_a": {
            "devices": {"data": [{
                "macAddress": "aa:bb:cc:dd:ee:ff",
                "ipAddress": "192.0.2.10",
                "firmwareVersion": "7.0.66",
                "model": "u6-pro",
                "name": "ap0",
                "type": "uap",
                "sshEnabled": True,
                "radioTable": [{"radio": "ng"}],
            }]},
        }
    })
    assert len(r["device"]) == 1
    d = r["device"][0]
    assert d["mac"] == "aa:bb:cc:dd:ee:ff"
    assert d["ip"] == "192.0.2.10"
    assert d["version"] == "7.0.66"
    assert d["model"] == "U6-PRO"  # uppercased for EOL_MODELS lookup
    assert d["ssh_enabled"] is True
    assert d["radio_table"] == [{"radio": "ng"}]


def test_features_array_ssh_detection():
    r = build_parser_collections({
        "site_a": {
            "devices": {"data": [{
                "macAddress": "02:00:00:00:00:01", "model": "U6", "name": "ap",
                "features": [{"name": "ssh", "enabled": True}],
            }]},
        }
    })
    assert r["device"][0]["ssh_enabled"] is True


def test_multi_site_aggregates():
    r = build_parser_collections({
        "site_a": {
            "devices": {"data": [{"macAddress": "aa", "model": "U6", "name": "a"},
                                 {"macAddress": "bb", "model": "U6", "name": "b"}]},
        },
        "site_b": {
            "devices": {"data": [{"macAddress": "cc", "model": "U6", "name": "c"},
                                 {"macAddress": "dd", "model": "U6", "name": "d"}]},
        },
    })
    assert len(r["device"]) == 4
    macs = {d["mac"] for d in r["device"]}
    assert macs == {"aa", "bb", "cc", "dd"}


def test_vpn_protocol_routing_wireguard():
    r = build_parser_collections({
        "site_a": {
            "vpn_configs": {"data": [{"type": "wireguard", "enabled": True}]},
        }
    })
    assert r["vpn_wireguard"]["enabled"] is True
    assert r["vpn_pptp"] == {}
    assert r["vpn_l2tp"] == {}


def test_vpn_protocol_routing_pptp_critical():
    """Setup for VPN-PPTP-001 always-top finding (Plan 04)."""
    r = build_parser_collections({
        "site_a": {
            "vpn_configs": {"data": [{"type": "pptp", "enabled": True}]},
        }
    })
    assert r["vpn_pptp"]["enabled"] is True


def test_unknown_shape_emits_warning(caplog):
    caplog.set_level(logging.WARNING, logger="unifi_audit.adapter")
    r = build_parser_collections({
        "site_a": {
            "devices": {"foobar": "not a list"},  # unknown wrapper
        }
    })
    assert r["device"] == []
    assert any("unknown response shape" in rec.message.lower() or "keys present" in rec.message.lower()
               for rec in caplog.records), \
        f"No unknown-shape warning emitted; records: {[r.message for r in caplog.records]}"


def test_pagination_truncation_warns(caplog):
    caplog.set_level(logging.WARNING, logger="unifi_audit.adapter")
    r = build_parser_collections({
        "site_a": {
            "devices": {"data": [{"macAddress": "aa", "model": "U6", "name": "a"}],
                        "count": 1, "totalCount": 100},
        }
    })
    assert any("pagination truncation" in rec.message.lower() for rec in caplog.records), \
        f"No pagination warning emitted; records: {[r.message for r in caplog.records]}"


def test_x_passphrase_preserves_fingerprint_dict():
    fingerprint = {"length": 20, "fingerprint": "abc123def456"}
    r = build_parser_collections({
        "site_a": {
            "wlans": {"data": [{"name": "ssid", "enabled": True, "x_passphrase": fingerprint}]},
        }
    })
    assert r["wlanconf"][0]["x_passphrase"] == fingerprint


def test_pre_shared_key_fallback_to_x_passphrase():
    fingerprint = {"length": 18, "fingerprint": "xyz"}
    r = build_parser_collections({
        "site_a": {
            "wlans": {"data": [{"name": "ssid", "enabled": True, "preSharedKey": fingerprint}]},
        }
    })
    assert r["wlanconf"][0]["x_passphrase"] == fingerprint


# ---------------------------------------------------------------------------
# DIVERGENT shape tests (2026-04-26 real-network run — Network 10.3.55)
# ---------------------------------------------------------------------------

def test_features_as_strings_does_not_crash_ssh_detection():
    """[DIVERGENT 2026-04-26] features is an array of strings on 10.3.55.

    Real observed shape: {"features": ["switching"]} or {"features": ["accessPoint"]}.
    The isinstance(feat, dict) guard in _extract_ssh_state must prevent a crash
    and must return False (no ssh capability observed via string features).
    """
    r = build_parser_collections({
        "site_a": {
            "devices": {"data": [
                {
                    "macAddress": "***REMOVED***",
                    "model": "UCG Fiber",
                    "name": "Cloud Gateway Fiber",
                    "features": ["switching"],         # string array — DIVERGENT shape
                    "firmwareVersion": "5.0.16",
                },
                {
                    "macAddress": "a8:9c:6c:6a:41:a4",
                    "model": "U7 Pro",
                    "name": "U7 Pro",
                    "features": ["accessPoint"],       # string array — DIVERGENT shape
                    "firmwareVersion": "8.5.21",
                },
            ]},
        }
    })
    assert len(r["device"]) == 2
    # String features must not set ssh_enabled = True
    assert r["device"][0]["ssh_enabled"] is False
    assert r["device"][1]["ssh_enabled"] is False


def test_firmwareversion_camelcase_verified():
    """[VERIFIED 2026-04-26] firmwareVersion is the correct Integration v1 field name."""
    r = build_parser_collections({
        "site_a": {
            "devices": {"data": [{
                "macAddress": "aa:bb:cc:dd:ee:ff",
                "model": "U7 Pro",
                "name": "ap",
                "firmwareVersion": "8.5.21",
            }]},
        }
    })
    assert r["device"][0]["version"] == "8.5.21"


def test_network_purpose_derived_from_metadata_origin_user_defined():
    """[DIVERGENT 2026-04-26] Integration v1 has no 'purpose' field.

    Real observed shape uses metadata.origin = USER_DEFINED or SYSTEM_DEFINED.
    _network_to_classic must map USER_DEFINED → purpose = 'corporate' so that
    SEG-001 detection (which filters on purpose == 'corporate') works correctly.
    """
    r = build_parser_collections({
        "site_a": {
            "networks": {"data": [
                {
                    "management": "GATEWAY",
                    "id": "655847bb-d750-4d39-897f-be0bf654d7d0",
                    "name": "Primary",
                    "enabled": True,
                    "vlanId": 1,
                    "metadata": {"origin": "SYSTEM_DEFINED", "configurable": True},
                    "default": True,
                },
                {
                    "management": "GATEWAY",
                    "id": "25236f8a-eefc-404f-866d-0d305f56bb09",
                    "name": "IoT",
                    "enabled": True,
                    "vlanId": 2,
                    "metadata": {"origin": "USER_DEFINED"},
                    "default": False,
                },
            ]},
        }
    })
    nets = r["networkconf"]
    assert len(nets) == 2

    # SYSTEM_DEFINED default network → purpose = "system_default"
    primary = next(n for n in nets if n["name"] == "Primary")
    assert primary["purpose"] == "system_default"
    assert primary["vlan"] == 1

    # USER_DEFINED network → purpose = "corporate" (so SEG-001 counts it)
    iot = next(n for n in nets if n["name"] == "IoT")
    assert iot["purpose"] == "corporate"
    assert iot["vlan"] == 2


def test_network_vlanid_camelcase_verified():
    """[VERIFIED 2026-04-26] vlanId is the correct Integration v1 field name."""
    r = build_parser_collections({
        "site_a": {
            "networks": {"data": [{
                "name": "LAN",
                "vlanId": 10,
                "metadata": {"origin": "USER_DEFINED"},
                "default": False,
            }]},
        }
    })
    assert r["networkconf"][0]["vlan"] == 10
