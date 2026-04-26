"""Smoke script invoked by Plan 02 Task 1's verify command."""
import sys
sys.path.insert(0, "src")
from api_to_collections import build_parser_collections

# Empty input
r = build_parser_collections({})
required_keys = {"device", "wlanconf", "networkconf", "portforward", "firewallrule",
                 "firewallgroup", "user", "vpn_pptp", "vpn_l2tp", "vpn_wireguard",
                 "vpn_openvpn", "auto_update", "auto_backup", "mgmt", "dpi",
                 "rogueap", "dns_filtering"}
missing = required_keys - set(r.keys())
assert not missing, f"build_parser_collections({{}}) missing keys: {missing}"

# Single site, single device
r = build_parser_collections({
    "site_a": {
        "devices": {"data": [{"macAddress": "aa:bb:cc:dd:ee:ff", "model": "u6-pro",
                              "name": "ap0", "type": "uap", "sshEnabled": True}]},
        "wlans": {"data": []},
        "networks": {"data": []},
    }
})
assert len(r["device"]) == 1
assert r["device"][0]["mac"] == "aa:bb:cc:dd:ee:ff"
assert r["device"][0]["model"] == "U6-PRO", f"model not uppercased: {r['device'][0]['model']}"
assert r["device"][0]["ssh_enabled"] is True
assert r["auto_update"] == {}
print("OK — adapter smoke passed")
