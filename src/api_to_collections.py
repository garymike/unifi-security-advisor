"""
Translate Integration v1 API responses into parser-shaped collection dicts.

This is the adapter described in decision D-01. It is the ONLY place that knows
about both the camelCase Integration v1 API shape and the snake_case parser-shape
that findings_enhanced.py modules expect.

Design properties:
  - Pure transformation: no I/O, no mutation of input, no network access.
  - Field annotations updated 2026-04-26 from a successful real-network run
    (UniFi Network 10.3.55, Cloud Gateway Fiber + U7 Pro, single site).
    Tags:
      [VERIFIED 2026-04-26]  — field name + type confirmed from live API response
      [DIVERGENT 2026-04-26] — real shape differs from assumption; code fixed accordingly
      [UNKNOWN — 404 on this controller version] — endpoint returned 404 on 10.3.55;
           field paths cannot be observed until a newer controller version is used
      [UNKNOWN — not present in observed data] — endpoint returned 200 but this
           particular field did not appear in any object from the real run
  - T-1-04 mitigation: unknown response shapes emit a logger.warning() with the
    observed keys so silently-dropped data is surfaced in the audit log.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("unifi_audit.adapter")


# =============================================================================
# RESPONSE SHAPE UNWRAPPER (T-1-04 mitigation)
# =============================================================================

def _unwrap(response: Any, *, endpoint_name: str = "<unknown>") -> list[dict]:
    """Extract a list of dicts from a paginated Integration v1 API response.

    Handles the following shapes:
      - None                    → []
      - list                    → filter to dict items, return
      - {"data": [...], ...}    → use the "data" list  [VERIFIED 2026-04-26]
      - {"items": [...], ...}   → use the "items" list
      - {"results": [...], ...} → use the "results" list
      - other dict              → log WARN with observed keys (T-1-04), return []
      - anything else           → []

    Pagination: if count < totalCount, logs a WARN about possible data truncation
    (Integration v1 returns paginated results; we don't yet implement continuation).

    Observed 2026-04-26: all 200 endpoints (devices, clients, networks, sites) use
    {"data": [...], "offset": int, "limit": int, "count": int, "totalCount": int}.
    The "data" key path is [VERIFIED 2026-04-26].

    Args:
        response: Raw response value from a site-scoped endpoint.
        endpoint_name: Human-readable label for warning messages.

    Returns:
        List of dicts extracted from the response.
    """
    if response is None:
        return []

    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]

    if isinstance(response, dict):
        # Check for pagination truncation before extracting the list
        count = response.get("count")
        total_count = response.get("totalCount")
        if (
            isinstance(count, int)
            and isinstance(total_count, int)
            and count < total_count
        ):
            logger.warning(
                "_unwrap[%s]: pagination truncation detected — received %d of %d items. "
                "Some data may be missing from the audit. "
                "Keys present: %s",
                endpoint_name, count, total_count, sorted(response.keys()),
            )

        for key in ("data", "items", "results"):
            if key in response and isinstance(response[key], list):
                return [item for item in response[key] if isinstance(item, dict)]

        # No recognized list key found in a non-empty dict
        if response:
            logger.warning(
                "_unwrap[%s]: unknown response shape — no recognized list key found. "
                "Keys present: %s. Returning empty list (T-1-04 mitigation).",
                endpoint_name, sorted(response.keys()),
            )
        return []

    return []


# =============================================================================
# SSH STATE EXTRACTOR
# =============================================================================

def _extract_ssh_state(device: dict) -> bool:
    """Extract SSH enabled state from an Integration v1 device object.

    Observed 2026-04-26 (Network 10.3.55): neither 'sshEnabled' nor 'ssh_enabled'
    appeared on the two observed devices (Cloud Gateway Fiber, U7 Pro).
    The 'features' field IS present but contains a list of STRINGS (e.g. ["switching"],
    ["accessPoint"]), NOT a list of dicts with name/enabled keys.
    [DIVERGENT 2026-04-26] — features format: array of strings, not array of dicts.

    The dict-guard in the features loop (`isinstance(feat, dict)`) prevents a
    crash or false positive. The loop simply never matches on string values,
    returning False safely. No code logic change needed; the guard is correct.

    Field resolution:
      - 'sshEnabled' top-level bool: [UNKNOWN — not present in observed data]
      - 'ssh_enabled' snake_case: [UNKNOWN — not present in observed data]
      - features[].name == 'ssh': [DIVERGENT — features are strings, not dicts;
            dict guard makes this path safe but never fires on 10.3.55 data]

    Args:
        device: Raw device dict from Integration v1 API.

    Returns:
        True if SSH is enabled on the device, False otherwise.
    """
    # [UNKNOWN — not present in observed data] sshEnabled not seen on 10.3.55
    if "sshEnabled" in device:
        return bool(device["sshEnabled"])
    # Classic API / older firmware fallback
    if "ssh_enabled" in device:
        return bool(device["ssh_enabled"])
    # [DIVERGENT 2026-04-26] features are strings on 10.3.55 (e.g. "switching",
    # "accessPoint"). The isinstance(feat, dict) guard makes this safe — it never
    # matches string items. Retained for forward-compat if future firmware adds
    # a structured features format.
    for feat in device.get("features", []) or []:
        if isinstance(feat, dict) and feat.get("name") == "ssh":
            return bool(feat.get("enabled", False))
    return False


# =============================================================================
# PER-OBJECT MAPPERS (camelCase → snake_case)
# =============================================================================

def _device_to_classic(d: dict) -> dict:
    """Map an Integration v1 device object to classic parser collection shape.

    Key field mappings (camelCase Integration v1 → snake_case classic):
      macAddress      → mac       [VERIFIED 2026-04-26]
      ipAddress       → ip        [VERIFIED 2026-04-26]
      model           → model     [VERIFIED 2026-04-26] (uppercased for EOL_MODELS)
      firmwareVersion → version   [VERIFIED 2026-04-26] — field name confirmed
      name            → name      [VERIFIED 2026-04-26]
      state           → state     [VERIFIED 2026-04-26] (value: "ONLINE")
      features        → (ssh detection only) [DIVERGENT 2026-04-26] — array of
                        strings not dicts; see _extract_ssh_state
      radioTable      → radio_table [UNKNOWN — not present in observed data]
                        (U7 Pro uses 'interfaces: ["radios"]' but no radioTable key
                        in the Integration v1 response at 10.3.55)
      sshEnabled      → ssh_enabled [UNKNOWN — not present in observed data]

    All original keys are also preserved (pass-through) so callers inspecting
    the raw shape can still access them.
    """
    model_raw = d.get("model", "")
    model_upper = model_raw.upper() if isinstance(model_raw, str) else model_raw

    out: dict[str, Any] = {
        "mac": d.get("macAddress", d.get("mac", "")),
        "ip": d.get("ipAddress", d.get("ip", "")),
        # Uppercased: find_firmware compares against EOL_MODELS keys (all upper)
        "model": model_upper,
        "name": d.get("name", ""),
        "type": d.get("type", d.get("deviceType", "")),
        "state": d.get("state", ""),
        "ssh_enabled": _extract_ssh_state(d),
        # [UNKNOWN — not present in observed data] radioTable not seen on 10.3.55;
        # U7 Pro has 'interfaces: ["radios"]' but no radioTable in Integration v1.
        # Dual-fallback retained for forward-compat.
        "radio_table": d.get("radioTable", d.get("radio_table", [])) or [],
        # [VERIFIED 2026-04-26] firmwareVersion confirmed on both observed devices.
        # 'version' fallback retained for classic-API compat.
        "version": d.get("firmwareVersion", d.get("version", "")),
    }
    # Preserve all other keys (no information loss)
    for k, v in d.items():
        if k not in out:
            out[k] = v
    return out


def _wlan_to_classic(w: dict) -> dict:
    """Map an Integration v1 WLAN object to classic wlanconf collection shape.

    [UNKNOWN — 404 on this controller version] — /wlans returned 404 on Network
    10.3.55. No WLAN objects were observed. All field-path assumptions remain
    unconfirmed. The dual-fallback (camelCase first, snake_case second) is retained
    for when the endpoint becomes available on a newer controller version.

    Field assumptions (unresolvable until /wlans returns 200):
      securityProtocol / security — [UNKNOWN — 404 on this controller version]
      wpaMode / wpa_mode          — [UNKNOWN — 404 on this controller version]
      pmfMode / pmf_mode          — [UNKNOWN — 404 on this controller version]
      preSharedKey / psk          — [UNKNOWN — 404 on this controller version]

    Passphrase handling: by the time the adapter sees the response, sanitize()
    has already replaced the raw PSK with a fingerprint dict. We preserve
    whatever shape the sanitizer left.
    """
    out: dict[str, Any] = {
        "name": w.get("name", ""),
        "enabled": w.get("enabled", True),
        # [UNKNOWN — 404 on this controller version] Integration v1 may use
        # securityProtocol vs. classic security — not resolvable at 10.3.55
        "security": w.get("security") or w.get("securityProtocol") or "",
        # [UNKNOWN — 404 on this controller version] wpaMode (camelCase) vs wpa_mode
        "wpa_mode": w.get("wpaMode") or w.get("wpa_mode") or "",
        # Sanitizer has already fingerprinted the raw value; preserve as-is
        # [UNKNOWN — 404 on this controller version] preSharedKey / psk field names
        "x_passphrase": w.get("x_passphrase", w.get("preSharedKey", w.get("psk", {}))),
        # [UNKNOWN — 404 on this controller version] pmfMode (camelCase) vs pmf_mode
        "pmf_mode": w.get("pmfMode") or w.get("pmf_mode") or "disabled",
    }
    # Preserve all other keys
    for k, v in w.items():
        if k not in out:
            out[k] = v
    return out


def _network_to_classic(n: dict) -> dict:
    """Map an Integration v1 network object to classic networkconf collection shape.

    Observed 2026-04-26 (Network 10.3.55) — real network object shape:
      {
        "management": "GATEWAY",         [VERIFIED 2026-04-26]
        "id": "<uuid>",                  [VERIFIED 2026-04-26]
        "name": "Primary" | "IoT",       [VERIFIED 2026-04-26]
        "enabled": true,                 [VERIFIED 2026-04-26]
        "vlanId": 1 | 2,                 [VERIFIED 2026-04-26]
        "metadata": {
            "origin": "SYSTEM_DEFINED" | "USER_DEFINED",  [VERIFIED 2026-04-26]
            "configurable": true         (only on SYSTEM_DEFINED)
        },
        "default": true | false          [VERIFIED 2026-04-26]
      }

    [DIVERGENT 2026-04-26] 'purpose' field: Classic API uses purpose = "corporate" |
    "guest" | "vlan-only". Integration v1 does NOT have a 'purpose' field at all.
    Instead it has 'metadata.origin' ("SYSTEM_DEFINED" | "USER_DEFINED") and 'default'
    (bool). Fix: derive 'purpose' from metadata.origin so findings that filter on
    purpose == "corporate" / "guest" correctly identify user-defined networks.

    Mapping applied:
      metadata.origin == USER_DEFINED  →  purpose = "corporate"  (user-created LAN)
      metadata.origin == SYSTEM_DEFINED and default == True  →  purpose = "system_default"
      metadata.origin == SYSTEM_DEFINED and default == False →  purpose = "system_defined"
      fallback (no metadata)  →  purpose = "" (same as before)

    Note: 'vlanId' confirmed as camelCase [VERIFIED 2026-04-26]; 'vlan' is the classic
    snake_case name used by parser.py.
    """
    metadata = n.get("metadata") or {}
    origin = metadata.get("origin", "")

    # [DIVERGENT 2026-04-26] Derive purpose from metadata.origin (Integration v1)
    # since the classic 'purpose' field is absent.
    # Mirrors src/unifi_audit.py:_is_user_defined_network -- keep in sync.
    if origin == "USER_DEFINED":
        derived_purpose = "corporate"  # treat user-defined as a LAN segment
    elif origin == "SYSTEM_DEFINED":
        derived_purpose = "system_default" if n.get("default") else "system_defined"
    else:
        # Fallback: try classic API fields in case this is parsed from a backup file
        derived_purpose = n.get("purpose") or n.get("type") or ""

    out: dict[str, Any] = {
        "name": n.get("name", ""),
        # [DIVERGENT 2026-04-26] purpose derived from metadata.origin (see docstring)
        "purpose": derived_purpose,
        # [VERIFIED 2026-04-26] vlanId is the correct camelCase field in Integration v1
        "vlan": n.get("vlanId", n.get("vlan", None)),
    }
    # Preserve all other keys
    for k, v in n.items():
        if k not in out:
            out[k] = v
    return out


# =============================================================================
# VPN PROTOCOL ROUTER
# =============================================================================

def _route_vpn_configs(vpn_configs: list[dict]) -> dict[str, dict]:
    """Route vpn_configs entries to per-protocol setting dicts.

    Integration v1 exposes VPN as a list of configs with a 'type' or 'protocol'
    field. findings_enhanced.find_remote_access reads per-protocol setting dicts
    (vpn_pptp, vpn_l2tp, vpn_wireguard, vpn_openvpn). This function bridges
    the two shapes.

    [UNKNOWN — 404 on this controller version] — /vpn-configs returned 404 on
    Network 10.3.55. No VPN config objects were observed. 'type' / 'protocol'
    field names and protocol string values remain unconfirmed until the endpoint
    is available on a newer controller version.

    Multiple configs of the same protocol: OR-aggregate the enabled flag so that
    if any instance is enabled, the protocol shows as enabled.

    Known limitation (WR-04): when multiple configs share the same protocol key
    (e.g. two WireGuard tunnels), the last config's non-enabled fields overwrite
    the first config's fields. Only the enabled flag is correctly merged via OR.
    In Phase 1 this is acceptable because all finding modules only inspect the
    enabled flag. If a future finding module reads port, peers, or endpoint
    fields, it will silently see only the last config's values. At that point,
    replace the routed[key] = dict(config) overwrite with a proper merge strategy
    (e.g. keep first config's fields, OR the enabled flag from all configs).
    """
    routed: dict[str, dict] = {
        "vpn_pptp": {},
        "vpn_l2tp": {},
        "vpn_wireguard": {},
        "vpn_openvpn": {},
    }
    # [UNKNOWN — 404 on this controller version] Protocol name → setting key mapping;
    # values not confirmed from live API (endpoint returned 404 at Network 10.3.55)
    proto_map = {
        "pptp": "vpn_pptp",
        "l2tp": "vpn_l2tp",
        "l2tp-ipsec": "vpn_l2tp",
        "l2tpipsec": "vpn_l2tp",
        "wireguard": "vpn_wireguard",
        "openvpn": "vpn_openvpn",
    }
    for config in vpn_configs:
        # [UNKNOWN — 404 on this controller version] 'type' or 'protocol' field name
        proto = (config.get("type") or config.get("protocol") or "").lower().strip()
        enabled = bool(config.get("enabled", False))
        key = proto_map.get(proto)
        if key:
            # OR-aggregate: if any instance is enabled, protocol is enabled
            existing_enabled = routed[key].get("enabled", False)
            routed[key] = dict(config)  # preserve all fields from the config
            routed[key]["enabled"] = existing_enabled or enabled
        # Unknown protocols are silently skipped (they appear in _vpn_configs_raw)
    return routed


# =============================================================================
# MAIN ADAPTER FUNCTION
# =============================================================================

def build_parser_collections(clean: dict) -> dict:
    """Translate a sanitized Integration v1 API response into parser collection shape.

    The output dict is keyed by the collection names that findings_enhanced.py
    modules read via _get_collection() and _get_setting(). This is the contract
    (D-01): findings_enhanced.py stays untouched; all data-shape translation
    lives here.

    Collection keys produced:
      device        — list of device dicts (camelCase mapped to snake_case)
      wlanconf      — list of WLAN dicts
      networkconf   — list of network dicts
      portforward   — list of port-forward dicts
      firewallrule  — list of firewall policy/rule dicts
      firewallgroup — list of firewall group dicts (may be empty; not exposed by v1)
      user          — list of client/user dicts

    Settings keys produced (Integration v1 may not expose these; defaults to {}):
      vpn_pptp, vpn_l2tp, vpn_wireguard, vpn_openvpn
        — routed from vpn_configs list via _route_vpn_configs()
      auto_update, auto_backup, mgmt, dpi, rogueap, dns_filtering, content_filtering
        — not exposed by Integration v1 API (confirmed absent at Network 10.3.55);
          empty dicts cause affected modules to emit "disabled/unknown" findings,
          which is correct degraded behaviour per D-03.

    Debug keys:
      _vpn_configs_raw — unrouted vpn_configs list for adapter refinement

    Args:
        clean: Sanitized API response dict from collect_all() → sanitize().
               Expected to contain site_* keys with per-endpoint dicts.

    Returns:
        Parser-shaped collections dict. All keys listed above are always present.
    """
    devices: list[dict] = []
    wlans: list[dict] = []
    networks: list[dict] = []
    port_forwards: list[dict] = []
    firewall_policies: list[dict] = []
    firewall_zones: list[dict] = []
    vpn_configs: list[dict] = []
    clients: list[dict] = []

    for site_key, site_val in clean.items():
        if not site_key.startswith("site_") or not isinstance(site_val, dict):
            continue

        devices.extend(
            _device_to_classic(d)
            for d in _unwrap(site_val.get("devices"), endpoint_name=f"{site_key}/devices")
        )
        wlans.extend(
            _wlan_to_classic(w)
            for w in _unwrap(site_val.get("wlans"), endpoint_name=f"{site_key}/wlans")
        )
        networks.extend(
            _network_to_classic(n)
            for n in _unwrap(site_val.get("networks"), endpoint_name=f"{site_key}/networks")
        )
        port_forwards.extend(
            _unwrap(site_val.get("port_forwards"), endpoint_name=f"{site_key}/port_forwards")
        )
        firewall_policies.extend(
            _unwrap(site_val.get("firewall_policies"), endpoint_name=f"{site_key}/firewall_policies")
        )
        firewall_zones.extend(
            _unwrap(site_val.get("firewall_zones"), endpoint_name=f"{site_key}/firewall_zones")
        )
        vpn_configs.extend(
            _unwrap(site_val.get("vpn_configs"), endpoint_name=f"{site_key}/vpn_configs")
        )
        # Clients / users
        raw_clients = _unwrap(site_val.get("clients"), endpoint_name=f"{site_key}/clients")
        clients.extend(raw_clients)

    # Route VPN configs to per-protocol dicts
    vpn_settings = _route_vpn_configs(vpn_configs)

    # Build the "setting" list that parser.py's _get_setting() iterates.
    # _get_setting(colls, key) searches for {"key": key, ...} entries in colls["setting"].
    # Each VPN protocol dict and stub-setting dict is wrapped with its "key" so that
    # findings_enhanced modules can retrieve them via _get_setting().
    # Bug fix (Rule 1): original adapter exposed VPN settings only as direct dict keys;
    # _get_setting() could not find them because it iterates colls["setting"], not colls itself.
    _stub_settings = {
        "auto_update": {},
        "auto_backup": {},
        "mgmt": {},
        "dpi": {},
        "rogueap": {},
        "dns_filtering": {},
        "content_filtering": {},
    }
    setting_list: list[dict] = []
    # Add VPN protocol settings
    for proto_key, proto_val in vpn_settings.items():
        entry = dict(proto_val)
        entry["key"] = proto_key
        setting_list.append(entry)
    # Add stub settings (empty dicts become {"key": "..."} entries)
    for stub_key in _stub_settings:
        setting_list.append({"key": stub_key})

    return {
        # Collections
        "device": devices,
        "wlanconf": wlans,
        "networkconf": networks,
        "portforward": port_forwards,
        "firewallrule": firewall_policies,
        # [UNKNOWN — 404 on this controller version] firewall-zones returned 404 at
        # Network 10.3.55. Mapped here as firewallgroup for backward compat with
        # findings that read firewallgroup; will be empty until endpoint is available.
        "firewallgroup": firewall_zones,
        "user": clients,

        # "setting" list: required by parser.py's _get_setting() interface.
        # Contains VPN protocol dicts and stub-settings, each tagged with "key".
        "setting": setting_list,

        # VPN settings also exposed as direct keys for backward-compat with any
        # caller that reads colls["vpn_pptp"] directly (e.g. test assertions).
        "vpn_pptp": vpn_settings["vpn_pptp"],
        "vpn_l2tp": vpn_settings["vpn_l2tp"],
        "vpn_wireguard": vpn_settings["vpn_wireguard"],
        "vpn_openvpn": vpn_settings["vpn_openvpn"],

        # Settings NOT exposed by Integration v1 API (confirmed absent at 10.3.55).
        # Empty dicts -> modules emit "disabled/unknown" findings (correct per D-03).
        "auto_update": {},     # not in Integration v1 API (confirmed 2026-04-26)
        "auto_backup": {},     # not in Integration v1 API (confirmed 2026-04-26)
        "mgmt": {},            # not in Integration v1 API (confirmed 2026-04-26)
        "dpi": {},             # not in Integration v1 API (confirmed 2026-04-26)
        "rogueap": {},         # not in Integration v1 API (confirmed 2026-04-26)
        "dns_filtering": {},   # not in Integration v1 API (confirmed 2026-04-26)
        "content_filtering": {},  # not in Integration v1 API (confirmed 2026-04-26)

        # Debug: preserved for adapter refinement
        "_vpn_configs_raw": vpn_configs,
    }
