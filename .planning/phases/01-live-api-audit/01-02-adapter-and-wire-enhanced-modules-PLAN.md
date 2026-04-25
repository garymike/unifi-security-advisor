---
phase: 01-live-api-audit
plan: 02
type: execute
wave: 1
depends_on: [01]
files_modified:
  - src/api_to_collections.py
  - src/unifi_audit.py
  - tests/test_extract_helpers.py
  - tests/test_adapter.py
autonomous: true
requirements:
  - REQ-wire-enhanced-modules-into-audit-script
  - REQ-finding-module-wireless-tuning
  - REQ-finding-module-firewall-threats
  - REQ-finding-module-firmware
  - REQ-finding-module-logging
  - REQ-finding-module-backup
  - REQ-validation-api-response-shapes
requirements_addressed:
  - REQ-wire-enhanced-modules-into-audit-script
  - REQ-finding-module-wireless-tuning
  - REQ-finding-module-firewall-threats
  - REQ-finding-module-firmware
  - REQ-finding-module-logging
  - REQ-finding-module-backup
  - REQ-validation-api-response-shapes
threat_refs: [T-1-04]
tags: [python, adapter, integration, api]

must_haves:
  truths:
    - "src/api_to_collections.py exports build_parser_collections(clean: dict) -> dict"
    - "build_parser_collections returns a dict with keys: device, wlanconf, networkconf, portforward, firewallrule, firewallgroup, plus settings sub-keys"
    - "analyze() in unifi_audit.py calls build_parser_collections and feeds the result to the 6 enhanced modules"
    - "All 6 enhanced modules are registered in the analyze() modules list"
    - "_extract_list logs a WARNING with response keys when no fallback matches (was: silent return None)"
    - "Each enhanced module is wrapped in try/except — failure of one does not abort the audit"
    - "When the adapter encounters an unknown response shape it logs a WARN line listing the keys it saw (T-1-04 mitigation)"
  artifacts:
    - path: "src/api_to_collections.py"
      provides: "API-camelCase to parser-snake_case translation layer"
      exports: ["build_parser_collections"]
      min_lines: 100
    - path: "src/unifi_audit.py"
      provides: "Extended analyze() with adapter + 6 enhanced modules wired"
      contains: "build_parser_collections|find_wireless_tuning|find_firewall_threats|find_firmware|find_logging|find_backup_config"
    - path: "tests/test_extract_helpers.py"
      provides: "_extract_list and _extract_sites shape variant coverage"
    - path: "tests/test_adapter.py"
      provides: "Adapter unit tests on synthetic API shapes"
  key_links:
    - from: "src/unifi_audit.py:analyze"
      to: "src/api_to_collections.py:build_parser_collections"
      via: "import + call before enhanced modules run"
      pattern: "build_parser_collections"
    - from: "src/unifi_audit.py:analyze"
      to: "src/findings_enhanced.py:find_wireless_tuning"
      via: "import + register in modules list"
      pattern: "find_wireless_tuning"
    - from: "src/unifi_audit.py:analyze"
      to: "src/findings_enhanced.py:find_firmware"
      via: "import + register in modules list"
      pattern: "find_firmware"
---

<objective>
Build the API-to-collections adapter (D-01) so the 6 enhanced finding modules in `src/findings_enhanced.py` can run unmodified against the Integration v1 API response. Wire those 6 modules into `analyze()`'s modules list. Enhance `_extract_list()` to log a warning when it encounters an unknown response shape (T-1-04 mitigation, REQ-validation-api-response-shapes).

After this plan: `unifi_audit.py` runs all 12 finding modules (6 baseline + 6 enhanced) end-to-end against the synthetic fixture without raising. Real-network coverage extends from ~50% to ~100% of implemented finding logic.

Purpose: Closes the most critical Phase 1 gap per CONCERNS.md. Per D-01, `findings_enhanced.py` source stays untouched — all data-shape translation lives in the new adapter module.

Output:
- `src/api_to_collections.py` — adapter (~100-150 LOC, pure function, no I/O)
- `src/unifi_audit.py` — `analyze()` extended; modules list now has 12 entries; `_extract_list` warns on unknown shapes
- `tests/test_extract_helpers.py` — `_extract_list` / `_extract_sites` against {data:[]}, [...], {items:[]}, {results:[]}, unknown shapes
- `tests/test_adapter.py` — adapter against synthetic API shapes
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
@.planning/codebase/CONCERNS.md
@.planning/codebase/ARCHITECTURE.md
@CLAUDE.md

<interfaces>
<!-- These are the EXACT module signatures the adapter must feed. From src/findings_enhanced.py.
     Do NOT modify these — D-01 keeps findings_enhanced.py source untouched. -->

From src/findings_enhanced.py:
```python
def find_wireless_tuning(colls: dict) -> list  # uses _get_collection(colls, "device") and _get_setting(colls, "rogueap")
def find_remote_access(colls: dict) -> list    # uses _get_setting(colls, "vpn_pptp"|"vpn_l2tp"|"vpn_wireguard"|"vpn_openvpn"); _get_collection(colls, "portforward")
def find_firewall_threats(colls: dict) -> list  # uses _get_collection(colls, "firewallrule"|"firewallgroup"); _get_setting(colls, "dns_filtering"|"content_filtering")
def find_firmware(colls: dict) -> list          # uses _get_collection(colls, "device"); _get_setting(colls, "auto_update")
def find_logging(colls: dict, profile: str = "home_office") -> list  # uses _get_setting(colls, "mgmt"|"dpi")
def find_backup_config(colls: dict) -> list    # uses _get_setting(colls, "auto_backup")
```

From src/parser.py (the helpers the enhanced modules import):
```python
def _get_collection(colls: dict, name: str) -> list  # returns colls.get(name, [])
def _get_setting(colls: dict, name: str) -> dict | None  # walks colls.setting nested dict
```

The enhanced modules read colls with these collection keys: device, wlanconf, networkconf,
portforward, firewallrule, firewallgroup, user. Plus settings paths: vpn_pptp, vpn_l2tp,
vpn_wireguard, vpn_openvpn, rogueap, dns_filtering, content_filtering, mgmt, dpi,
auto_update, auto_backup.

The existing analyze() at src/unifi_audit.py:355-375 has 6 baseline modules registered.
The existing _extract_list at src/unifi_audit.py:562-572 silently returns None on unknown shapes.
The existing _extract_sites at src/unifi_audit.py:340-348 handles "data"/"sites"/"items" keys.
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Create src/api_to_collections.py with build_parser_collections</name>
  <files>src/api_to_collections.py</files>
  <read_first>
    - src/findings_enhanced.py (full file — every _get_collection/_get_setting call site dictates a key the adapter must produce)
    - src/parser.py (lines 178-260 — the parser-shape examples for `find_segmentation`)
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (Pattern 2 §"API-to-Collections Adapter (D-01)" lines ~387-530)
    - src/unifi_audit.py (SITE_SCOPED_LOCAL endpoints lines 76-86)
  </read_first>
  <behavior>
    - build_parser_collections({}) returns a dict with all expected keys present (empty values)
    - With one site containing one device {macAddress, model, name, type, sshEnabled}, returns colls with device[0].mac, device[0].ssh_enabled, device[0].model uppercased
    - Multi-site: aggregates devices/wlans/networks across both sites into single lists
    - Unknown shape (devices is None or unexpected dict): logs WARN, returns empty list, does not raise
    - VPN config protocol routing: vpn_configs entry with type="wireguard" enabled=true populates vpn_wireguard.enabled = True
    - radio_table is preserved on devices (camelCase radioTable accepted)
    - sshEnabled / ssh_enabled / features[name=ssh].enabled all map to ssh_enabled bool
    - x_passphrase preserves whatever shape the sanitizer left (likely a fingerprint dict)
  </behavior>
  <action>
Create `src/api_to_collections.py`. This is a pure transformation module — no I/O, no mutation of input. Every `[ASSUMED]` field comment is preserved verbatim from RESEARCH.md so Plan 07's real-network run can convert them to `[VERIFIED]`.

The full module structure (copy verbatim into the file):

1. Module docstring stating: shared adapter D-01; pure transformation; no I/O; T-1-04 mitigation by logging unknown shapes.

2. `from __future__ import annotations`, `import logging`, `from typing import Any`. Module-level `logger = logging.getLogger("unifi_audit.adapter")`.

3. `_unwrap(response: Any, *, endpoint_name: str = "<unknown>") -> list[dict]`:
   - None → []
   - list → filter to dict items
   - dict with keys "data" / "items" / "results" containing list → return that list filtered to dicts
   - dict with `count` and `totalCount` ints where `count < totalCount` → log WARN about pagination truncation, then continue
   - any other dict → log WARN with sorted observed keys (T-1-04), return []
   - anything else → []

4. `_extract_ssh_state(device: dict) -> bool`:
   - if `sshEnabled` in device → bool of that
   - elif `ssh_enabled` → bool of that
   - else iterate `device.get("features", []) or []`, look for entry with `name == "ssh"` and return `bool(feat.get("enabled", False))`
   - default False
   - Comment: `[ASSUMED]` field path; validate in Plan 07.

5. `_device_to_classic(d: dict) -> dict`:
   - mac ← d.get("macAddress", d.get("mac", ""))
   - ip ← d.get("ipAddress", d.get("ip", ""))
   - model ← d.get("model","").upper() if string else d.get("model","")  [findings_enhanced.find_firmware compares against upper-case EOL_MODELS]
   - name ← d.get("name","")
   - type ← d.get("type", d.get("deviceType",""))
   - state ← d.get("state","")
   - ssh_enabled ← _extract_ssh_state(d)
   - radio_table ← d.get("radioTable", d.get("radio_table", [])) or []
   - version ← d.get("version", d.get("firmwareVersion",""))
   - Then preserve all other keys via `for k,v in d.items(): if k not in out: out[k]=v` (no information loss)

6. `_wlan_to_classic(w: dict) -> dict`:
   - name ← w.get("name","")
   - enabled ← w.get("enabled", True)
   - security ← w.get("security") or w.get("securityProtocol") or ""
   - wpa_mode ← w.get("wpaMode") or w.get("wpa_mode") or ""
   - x_passphrase ← w.get("x_passphrase", w.get("preSharedKey", w.get("psk", {})))
   - pmf_mode ← w.get("pmfMode", w.get("pmf_mode", "disabled"))
   - Preserve all other keys
   - Comment: `[ASSUMED]` WLAN field names; validate in Plan 07.

7. `_network_to_classic(n: dict) -> dict`:
   - name ← n.get("name","")
   - purpose ← n.get("purpose", n.get("type",""))
   - vlan ← n.get("vlanId", n.get("vlan", None))
   - Preserve all other keys

8. `_route_vpn_configs(vpn_configs: list[dict]) -> dict[str, dict]`:
   - Returns {"vpn_pptp": {}, "vpn_l2tp": {}, "vpn_wireguard": {}, "vpn_openvpn": {}}
   - For each config, extract `proto = (v.get("type") or v.get("protocol") or "").lower()` and `enabled = bool(v.get("enabled", False))`
   - Map proto → key with: pptp→vpn_pptp, l2tp→vpn_l2tp, l2tp-ipsec→vpn_l2tp, wireguard→vpn_wireguard, openvpn→vpn_openvpn
   - OR-aggregate: `routed[key]["enabled"] = routed[key].get("enabled", False) or enabled`

9. `build_parser_collections(clean: dict) -> dict`:
   - Iterate `clean.items()`; for each key starting with "site_" with dict value, accumulate devices/wlans/networks/port_forwards/firewall_policies/firewall_zones/vpn_configs/clients via `_unwrap` + the appropriate _X_to_classic mapper
   - vpn_settings = _route_vpn_configs(vpn_configs)
   - user collection: for each client, if it has a `radio` or `radioBand` field, copy through; otherwise pass through unchanged
   - Return dict with these keys (all must be present):
     - Collections: `device`, `wlanconf`, `networkconf`, `portforward`, `firewallrule`, `firewallgroup`, `user`
     - VPN settings: `vpn_pptp`, `vpn_l2tp`, `vpn_wireguard`, `vpn_openvpn` (each from _route_vpn_configs)
     - Empty settings dicts (Integration v1 API does not expose per RESEARCH.md A3): `auto_update`, `auto_backup`, `mgmt`, `dpi`, `rogueap`, `dns_filtering`, `content_filtering`
     - Debugging: `_vpn_configs_raw` containing the unrouted vpn_configs list

The full reference implementation is documented verbatim in `.planning/phases/01-live-api-audit/01-RESEARCH.md` §"Pattern 2: API-to-Collections Adapter (D-01)" lines ~390-530. Use that as the literal implementation source.
  </action>
  <verify>
    <automated>python tests/_smoke_adapter.py</automated>
  </verify>
  <acceptance_criteria>
    - File `src/api_to_collections.py` exists
    - `grep -c "def build_parser_collections" src/api_to_collections.py` returns 1
    - `grep -c "def _device_to_classic" src/api_to_collections.py` returns 1
    - `grep -c "def _wlan_to_classic" src/api_to_collections.py` returns 1
    - `grep -c "def _route_vpn_configs" src/api_to_collections.py` returns 1
    - `grep -c "logger.warning" src/api_to_collections.py` returns ≥ 2 (T-1-04 mitigation present)
    - All keys present in `build_parser_collections({})` return value: device, wlanconf, networkconf, portforward, firewallrule, firewallgroup, user, vpn_pptp, vpn_l2tp, vpn_wireguard, vpn_openvpn, auto_update, auto_backup, mgmt, dpi, rogueap, dns_filtering (verified via the test in Task 3)
  </acceptance_criteria>
  <done>Adapter module exists; build_parser_collections accepts sanitized API output and returns parser-shape dict with all keys enhanced modules need; unknown shapes log a WARN; pagination truncation logs WARN; no I/O side effects.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Wire 6 enhanced modules into analyze() + log warning in _extract_list</name>
  <files>src/unifi_audit.py</files>
  <read_first>
    - src/unifi_audit.py (lines 355-375 for the modules list, lines 562-572 for _extract_list)
    - src/findings_enhanced.py (signatures of all 6 enhanced functions)
    - src/api_to_collections.py (just created in Task 1)
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Pattern 2" and §"_extract_list() Enhancement Needed")
  </read_first>
  <behavior>
    - analyze() runs all 12 modules: 6 baseline + 6 enhanced (find_wireless_tuning, find_firewall_threats, find_remote_access from enhanced, find_firmware, find_logging, find_backup_config)
    - Enhanced modules receive the adapter output, not the raw clean dict
    - find_logging is called with the profile parameter (its second positional arg)
    - Each enhanced module wrapped in try/except — failure of one logs warning, audit continues
    - findings_enhanced.find_remote_access has the SAME function name as the local _find_remote_access — wire under a different name in the modules list (e.g., "remote_access_enhanced") to avoid collision
    - _extract_list now logs a WARN when no key matches in a non-empty dict (REQ-validation-api-response-shapes)
    - _extract_list still returns None for None input so existing call sites keep working
  </behavior>
  <action>
Modify `src/unifi_audit.py` in three places:

**Change 1: Add imports.** After the existing import block and the sanitizer import added in Plan 01, add the adapter and enhanced module imports. Use the same try/except pattern Plan 01 established. Import `find_remote_access` from findings_enhanced as `find_remote_access_enhanced` (alias) to avoid collision with the existing local `_find_remote_access`.

The imports to add (at the same location as the sanitizer import from Plan 01):

```python
try:
    from api_to_collections import build_parser_collections
    from findings_enhanced import (
        find_wireless_tuning,
        find_firewall_threats,
        find_remote_access as find_remote_access_enhanced,
        find_firmware,
        find_logging,
        find_backup_config,
    )
except ImportError:
    from src.api_to_collections import build_parser_collections
    from src.findings_enhanced import (
        find_wireless_tuning,
        find_firewall_threats,
        find_remote_access as find_remote_access_enhanced,
        find_firmware,
        find_logging,
        find_backup_config,
    )
```

**Change 2: Extend analyze().** Replace the existing `analyze()` body (lines 355-375 ish) so the modules list runs in two passes: baseline (reads `clean` directly) then enhanced (reads `colls` from `build_parser_collections(clean)`). The enhanced pass calls `find_logging(colls, profile)` (not `find_logging(colls)`). Wrap the `build_parser_collections` call in try/except so an adapter failure does not abort the audit — log the warning and proceed with `colls = {}`. Wrap each enhanced module call in try/except.

Reference structure:

```python
def analyze(clean: dict, profile: str, logger: logging.Logger) -> list[Finding]:
    findings: list[Finding] = []

    baseline_modules = [
        ("segmentation", _find_segmentation),
        ("wifi", _find_wifi),
        ("firewall", _find_firewall),
        ("remote_access", _find_remote_access),
        ("devices", _find_devices),
        ("api_coverage", _find_api_coverage),
    ]
    for name, fn in baseline_modules:
        try:
            findings.extend(fn(clean, profile))
        except Exception as e:
            logger.warning(f"Module {name} failed: {e}")

    try:
        colls = build_parser_collections(clean)
    except Exception as e:
        logger.warning(f"Adapter build_parser_collections failed: {e}")
        colls = {}

    enhanced_modules = [
        ("wireless_tuning", lambda: find_wireless_tuning(colls)),
        ("firewall_threats", lambda: find_firewall_threats(colls)),
        ("remote_access_enhanced", lambda: find_remote_access_enhanced(colls)),
        ("firmware", lambda: find_firmware(colls)),
        ("logging", lambda: find_logging(colls, profile)),
        ("backup_config", lambda: find_backup_config(colls)),
    ]
    for name, fn in enhanced_modules:
        try:
            findings.extend(fn())
        except Exception as e:
            logger.warning(f"Enhanced module {name} failed: {e}")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 5), f.section))
    return findings
```

**Change 3: Add WARN log to _extract_list.** Locate the existing `_extract_list` (around line 562). Add a module-level logger if one is not already in scope: `_logger = logging.getLogger("unifi_audit")`. Modify `_extract_list` so that when the input is a non-empty dict and no recognized list key matches, it logs `_logger.warning("_extract_list: no recognized list key in response. Keys present: %s. Returning None.", sorted(data.keys()))` BEFORE returning None.

Do NOT change any baseline finding module signature. Do NOT modify findings_enhanced.py.
  </action>
  <verify>
    <automated>python tests/_smoke_analyze.py</automated>
  </verify>
  <acceptance_criteria>
    - `grep -c "from findings_enhanced import" src/unifi_audit.py` returns ≥ 1
    - `grep -c "build_parser_collections" src/unifi_audit.py` returns ≥ 2 (import + call)
    - `grep -c "find_wireless_tuning" src/unifi_audit.py` returns ≥ 2
    - `grep -c "find_firmware" src/unifi_audit.py` returns ≥ 2
    - `grep -c "find_logging" src/unifi_audit.py` returns ≥ 2
    - `grep -c "find_backup_config" src/unifi_audit.py` returns ≥ 2
    - `grep -c "find_remote_access_enhanced" src/unifi_audit.py` returns ≥ 2
    - `grep -B1 -A2 "_extract_list" src/unifi_audit.py` output contains the literal string `Keys present:` (warn message present)
    - `python -c "import sys; sys.path.insert(0,'src'); import unifi_audit; assert hasattr(unifi_audit, 'find_firmware') and hasattr(unifi_audit, 'build_parser_collections'); print('OK')"` exits 0
  </acceptance_criteria>
  <done>analyze() runs 12 modules; enhanced modules fed via adapter; _extract_list warns on unknown shape; one-module failure does not abort audit; collision between baseline _find_remote_access and enhanced find_remote_access resolved via alias.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: tests/test_extract_helpers.py + tests/test_adapter.py</name>
  <files>tests/test_extract_helpers.py, tests/test_adapter.py, tests/_smoke_adapter.py, tests/_smoke_analyze.py</files>
  <read_first>
    - src/unifi_audit.py (the modified _extract_list and _extract_sites)
    - src/api_to_collections.py (Task 1 output)
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"_extract_list() Enhancement Needed", §"Pattern 2")
    - tests/conftest.py (synthetic_api_dump fixture from Plan 01)
  </read_first>
  <behavior>
    - test_extract_list_data_envelope: {"data": [{"a":1}]} returns [{"a":1}]
    - test_extract_list_items_envelope: {"items": [{"a":1}]} returns [{"a":1}]
    - test_extract_list_results_envelope: {"results": [{"a":1}]} returns [{"a":1}]
    - test_extract_list_bare_list: [{"a":1}] returns the list
    - test_extract_list_none_returns_none: None returns None
    - test_extract_list_unknown_shape_warns: {"foobar": [{"a":1}]} returns None AND emits a WARN log line containing "Keys present"
    - test_extract_sites_handles_data_sites_items: parametrized over the 3 known wrappers
    - test_adapter_empty_input_safe: build_parser_collections({}) returns dict with all required keys, all empty
    - test_adapter_single_site_devices: one device shows up under colls["device"] with mac, model uppercased, ssh_enabled detected
    - test_adapter_multi_site_aggregates: two sites each with 2 devices → colls["device"] has 4 entries
    - test_adapter_vpn_protocol_routing: vpn_configs with type="wireguard" enabled=True → colls["vpn_wireguard"]["enabled"] is True
    - test_adapter_unknown_shape_logs_warn: passing devices = {"foo": "bar"} (no recognized list key) emits WARN log line
    - test_adapter_pagination_warns: passing {"data": [], "count": 5, "totalCount": 100} emits a WARN log line about truncation
    - test_adapter_camelcase_to_snake_case: device with macAddress, ipAddress, firmwareVersion, radioTable → colls["device"][0] has mac, ip, version, radio_table
    - test_adapter_features_array_ssh_detection: device with no top-level sshEnabled but features=[{"name":"ssh","enabled":True}] → ssh_enabled True
    - The two _smoke_*.py files are tiny scripts used by Task 1/2 verify commands — they do the analyze()/build_parser_collections smoke and exit 0
  </behavior>
  <action>
Create `tests/_smoke_adapter.py` (used by Task 1 verify):

```python
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
```

Create `tests/_smoke_analyze.py` (used by Task 2 verify):

```python
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

assert len(findings) >= 4, f"Expected ≥4 findings, got {len(findings)}: {[f.id for f in findings]}"

ids = [f.id for f in findings]
# At least one enhanced module must have fired (FW-EOL-001 from EOL UAP-AC-LITE; or VPN-MISSING-001 from port-forward without VPN; or RF-* from high TX power; or BAK-001 from no auto-backup)
assert any(i.startswith(("FW-EOL", "RF-", "BAK-", "LOG-", "VPN-MISSING", "VPN-PPTP")) for i in ids), \
    f"No enhanced finding fired in {ids}"
print(f"OK — {len(findings)} findings: {ids}")
```

Create `tests/test_extract_helpers.py`:

```python
"""_extract_list and _extract_sites shape-variant coverage."""
from __future__ import annotations

import logging

import pytest

from unifi_audit import _extract_list, _extract_sites


@pytest.mark.parametrize("envelope_key", ["data", "items", "results"])
def test_extract_list_handles_known_envelopes(envelope_key):
    response = {envelope_key: [{"a": 1}, {"b": 2}]}
    assert _extract_list(response) == [{"a": 1}, {"b": 2}]


def test_extract_list_bare_list():
    assert _extract_list([{"a": 1}]) == [{"a": 1}]


def test_extract_list_none_returns_none():
    assert _extract_list(None) is None


def test_extract_list_unknown_shape_logs_warning(caplog):
    caplog.set_level(logging.WARNING, logger="unifi_audit")
    result = _extract_list({"foobar": [{"a": 1}]})
    assert result is None
    assert any("Keys present" in rec.message for rec in caplog.records), \
        f"No 'Keys present' warning emitted; records: {[r.message for r in caplog.records]}"


def test_extract_list_empty_dict_no_warning(caplog):
    caplog.set_level(logging.WARNING, logger="unifi_audit")
    result = _extract_list({})
    assert result is None
    # Empty dict should not emit a warning (no keys to report)
    assert not any("Keys present" in rec.message for rec in caplog.records)


@pytest.mark.parametrize("envelope_key", ["data", "sites", "items"])
def test_extract_sites_handles_known_envelopes(envelope_key):
    response = {envelope_key: [{"id": "s1"}, {"id": "s2"}]}
    assert _extract_sites(response) == [{"id": "s1"}, {"id": "s2"}]


def test_extract_sites_bare_list():
    assert _extract_sites([{"id": "s1"}]) == [{"id": "s1"}]


def test_extract_sites_unknown_returns_empty():
    assert _extract_sites({"foobar": []}) == []
    assert _extract_sites(None) == []
    assert _extract_sites("not a dict") == []
```

Create `tests/test_adapter.py`:

```python
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
```

Run `pytest -q tests/` to confirm all new tests plus the Plan 01 sanitizer tests pass.
  </action>
  <verify>
    <automated>pytest -q tests/test_extract_helpers.py tests/test_adapter.py</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_extract_helpers.py` exists
    - File `tests/test_adapter.py` exists
    - File `tests/_smoke_adapter.py` exists
    - File `tests/_smoke_analyze.py` exists
    - `pytest -q tests/test_extract_helpers.py` exits 0
    - `pytest -q tests/test_adapter.py` exits 0
    - `python tests/_smoke_adapter.py` exits 0
    - `python tests/_smoke_analyze.py` exits 0 (after Task 2 lands)
    - `grep -c "test_unknown_shape_emits_warning" tests/test_adapter.py` returns ≥ 1
    - `grep -c "test_pagination_truncation_warns" tests/test_adapter.py` returns ≥ 1
    - `grep -c "test_extract_list_unknown_shape_logs_warning" tests/test_extract_helpers.py` returns ≥ 1
    - `grep -c "test_vpn_protocol_routing_wireguard" tests/test_adapter.py` returns ≥ 1
    - `grep -c "test_features_array_ssh_detection" tests/test_adapter.py` returns ≥ 1
  </acceptance_criteria>
  <done>Adapter and extract-helper test files exist; all tests pass; T-1-04 mitigation verified by warning-emission tests; smoke scripts ready for Tasks 1 and 2 verify commands.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| API response → adapter | Sanitized API response crosses into the adapter. The adapter must not assume any specific shape; unknown shapes are surfaced via WARN logs. |
| Adapter → enhanced modules | Parser-shape colls dict crosses into findings_enhanced.py. The contract is documented in the dict keys; enhanced modules tolerate empty collections. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-1-04 | Tampering / Information Disclosure | src/api_to_collections.py:_unwrap, src/unifi_audit.py:_extract_list | mitigate | Both functions log a WARN with the observed keys when an unknown shape is encountered; tests assert the warnings fire (test_unknown_shape_emits_warning, test_extract_list_unknown_shape_logs_warning). Audit continues with empty collection — affected enhanced module produces no findings, which is correct degraded behaviour per D-03. |
</threat_model>

<verification>
After all tasks complete:

```bash
# All Plan 01 + Plan 02 tests pass
pytest -q tests/

# Smoke scripts exit 0
python tests/_smoke_adapter.py
python tests/_smoke_analyze.py

# 12 finding modules execute end-to-end
python -c "import sys; sys.path.insert(0,'src'); import unifi_audit; print('OK' if hasattr(unifi_audit, 'find_firmware') and hasattr(unifi_audit, 'build_parser_collections') else 'MISSING')"
```
</verification>

<success_criteria>
- src/api_to_collections.py exists with build_parser_collections, _unwrap, _device_to_classic, _wlan_to_classic, _network_to_classic, _route_vpn_configs
- src/unifi_audit.py imports the 6 enhanced modules and the adapter
- analyze() runs all 12 modules; one-module failure does not abort
- _extract_list logs WARN on unknown response shape
- tests/test_adapter.py: 10+ tests, including unknown-shape warning and pagination warning
- tests/test_extract_helpers.py: 8+ tests covering all known envelopes + unknown
- T-1-04 mitigated by adapter + _extract_list warning surfaces, asserted by tests
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-02-SUMMARY.md` with:
- Files created and line counts
- Module count delta in analyze() (6 → 12)
- Test count and pass status
- Any [ASSUMED] field paths noted as candidates for Plan 07 verification
</output>
