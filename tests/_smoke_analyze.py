"""Smoke script invoked by Plan 02 Task 2's verify command."""
import sys
import logging
sys.path.insert(0, "src")
import unifi_audit

assert hasattr(unifi_audit, "find_wireless_tuning"), "find_wireless_tuning not imported"
assert hasattr(unifi_audit, "find_firmware"), "find_firmware not imported"
assert hasattr(unifi_audit, "build_parser_collections"), "adapter not imported"

synthetic = {
    "_endpoints_probed": [{"name": "sites", "status": 200}],
    "_errors": [],
    "_site_count": 1,
    "site_a": {
        "_meta": {"id": "a", "name": "test"},
        "devices": {"data": [{"macAddress": "02:00:00:00:00:01",
                              "model": "UAP-AC-LITE",  # an EOL model
                              "name": "ap0", "type": "uap",
                              "sshEnabled": True, "version": "6.0.42",
                              "radioTable": [{"radio": "ng", "tx_power_mode": "high"}]}],
                    "totalCount": 1},
        "wlans": {"data": [{"name": "main", "enabled": True,
                            "wpa_mode": "wpa3", "pmf_mode": "disabled"}],
                  "totalCount": 1},
        "networks": {"data": [{"name": "lan", "purpose": "corporate", "vlan": 1}],
                     "totalCount": 1},
        "port_forwards": {"data": [{"enabled": True, "name": "ssh-fwd"}],
                          "totalCount": 1},
        "vpn_configs": {"data": [], "totalCount": 0},
        "firewall_policies": {"data": [], "totalCount": 0},
    }
}

logger = logging.getLogger("test")
logger.addHandler(logging.NullHandler())
findings = unifi_audit.analyze(synthetic, "home_office", logger)

assert len(findings) >= 4, f"Expected >=4 findings, got {len(findings)}: {[f.id for f in findings]}"

ids = [f.id for f in findings]
# At least one enhanced module must have fired (FW-EOL-001 from EOL UAP-AC-LITE; or VPN-MISSING-001 from port-forward without VPN; or RF-* from high TX power; or BAK-001 from no auto-backup)
assert any(i.startswith(("FW-EOL", "RF-", "BAK-", "LOG-", "VPN-MISSING", "VPN-PPTP")) for i in ids), \
    f"No enhanced finding fired in {ids}"
print(f"OK — {len(findings)} findings: {ids}")
