"""
Translate Integration v1 API responses into parser-shaped collection dicts.

This is the adapter described in decision D-01. It is the ONLY place that knows
about both the camelCase Integration v1 API shape and the snake_case parser-shape
that findings_enhanced.py modules expect.

Design properties:
  - Pure transformation: no I/O, no mutation of input, no network access.
  - Fields marked [UNKNOWN] were not observable in Plan 07 (HTTP 401 auth failure;
    all Integration v1 endpoints unreachable). Plan 08 will resolve them to
    [VERIFIED] or [DIVERGENT] once a valid API key is used.
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
      - {"data": [...], ...}    → use the "data" list
      - {"items": [...], ...}   → use the "items" list
      - {"results": [...], ...} → use the "results" list
      - other dict              → log WARN with observed keys (T-1-04), return []
      - anything else           → []

    Pagination: if count < totalCount, logs a WARN about possible data truncation
    (Integration v1 returns paginated results; we don't yet implement continuation).

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

    [UNKNOWN 2026-04-26] field paths — Plan 07 run returned HTTP 401 on all endpoints;
    no real device objects were observed. Field paths remain unconfirmed.
    Plan 08 will resolve these to [VERIFIED] or [DIVERGENT]:
      - Top-level 'sshEnabled' (likely Integration v1 field name)
      - Top-level 'ssh_enabled' (classic API field name, may appear in older firmware)
      - features array entry with name=='ssh' and enabled==True (capability flags pattern)
    See: tests/fixtures/captured_real_network_run.md A1.

    Args:
        device: Raw device dict from Integration v1 API.

    Returns:
        True if SSH is enabled on the device, False otherwise.
    """
    # [UNKNOWN 2026-04-26] Integration v1 may use sshEnabled (camelCase) — not confirmed
    if "sshEnabled" in device:
        return bool(device["sshEnabled"])
    # Classic API / older firmware fallback
    if "ssh_enabled" in device:
        return bool(device["ssh_enabled"])
    # [UNKNOWN 2026-04-26] features array pattern: [{name: "ssh", enabled: true}, ...]
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
      macAddress    → mac
      ipAddress     → ip
      model         → model (uppercased: EOL_MODELS uses upper keys)
      firmwareVersion → version
      radioTable    → radio_table
      sshEnabled    → ssh_enabled (via _extract_ssh_state)

    [UNKNOWN 2026-04-26] radioTable field name — Plan 07 returned HTTP 401; not confirmed.
    [UNKNOWN 2026-04-26] firmwareVersion field name — Plan 07 returned HTTP 401; not confirmed.
    Plan 08 will resolve these to [VERIFIED] or [DIVERGENT].
    See: tests/fixtures/captured_real_network_run.md A2, A6.

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
        # [UNKNOWN 2026-04-26] radioTable field name; not confirmed (auth failure in Plan 07)
        "radio_table": d.get("radioTable", d.get("radio_table", [])) or [],
        # [UNKNOWN 2026-04-26] firmwareVersion field name; not confirmed (auth failure in Plan 07)
        "version": d.get("version", d.get("firmwareVersion", "")),
    }
    # Preserve all other keys (no information loss)
    for k, v in d.items():
        if k not in out:
            out[k] = v
    return out


def _wlan_to_classic(w: dict) -> dict:
    """Map an Integration v1 WLAN object to classic wlanconf collection shape.

    [UNKNOWN 2026-04-26] field names — Plan 07 returned HTTP 401; no WLAN objects
    were observed. Plan 08 will resolve these to [VERIFIED] or [DIVERGENT]:
      securityProtocol, wpaMode, pmfMode, preSharedKey, psk
    See: tests/fixtures/captured_real_network_run.md A4.

    Passphrase handling: by the time the adapter sees the response, sanitize()
    has already replaced the raw PSK with a fingerprint dict. We preserve
    whatever shape the sanitizer left.
    """
    out: dict[str, Any] = {
        "name": w.get("name", ""),
        "enabled": w.get("enabled", True),
        # [UNKNOWN 2026-04-26] Integration v1 may use securityProtocol vs. classic security
        "security": w.get("security") or w.get("securityProtocol") or "",
        # [UNKNOWN 2026-04-26] wpaMode (camelCase) vs. wpa_mode (snake_case)
        "wpa_mode": w.get("wpaMode") or w.get("wpa_mode") or "",
        # Sanitizer has already fingerprinted the raw value; preserve as-is
        # [UNKNOWN 2026-04-26] preSharedKey / psk as Integration v1 field names
        "x_passphrase": w.get("x_passphrase", w.get("preSharedKey", w.get("psk", {}))),
        # [UNKNOWN 2026-04-26] pmfMode (camelCase) vs. pmf_mode (snake_case)
        "pmf_mode": w.get("pmfMode") or w.get("pmf_mode") or "disabled",
    }
    # Preserve all other keys
    for k, v in w.items():
        if k not in out:
            out[k] = v
    return out


def _network_to_classic(n: dict) -> dict:
    """Map an Integration v1 network object to classic networkconf collection shape.

    [UNKNOWN 2026-04-26] field names — Plan 07 returned HTTP 401; no network objects
    were observed. Plan 08 will resolve these to [VERIFIED] or [DIVERGENT]:
      vlanId (Integration v1) vs. vlan (classic)
    See: tests/fixtures/captured_real_network_run.md A5.
    """
    out: dict[str, Any] = {
        "name": n.get("name", ""),
        # [UNKNOWN 2026-04-26] purpose vs. type field name; not confirmed (auth failure in Plan 07)
        "purpose": n.get("purpose") or n.get("type") or "",
        # [UNKNOWN 2026-04-26] vlanId (Integration v1) vs. vlan (classic); not confirmed
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

    [UNKNOWN 2026-04-26] 'type' / 'protocol' field names — Plan 07 returned HTTP 401;
    no VPN config objects were observed. Plan 08 will resolve to [VERIFIED] or [DIVERGENT].
    [UNKNOWN 2026-04-26] Protocol string values (pptp, l2tp, l2tp-ipsec, wireguard, openvpn).
    See: tests/fixtures/captured_real_network_run.md A8.

    Multiple configs of the same protocol: OR-aggregate the enabled flag so that
    if any instance is enabled, the protocol shows as enabled.
    """
    routed: dict[str, dict] = {
        "vpn_pptp": {},
        "vpn_l2tp": {},
        "vpn_wireguard": {},
        "vpn_openvpn": {},
    }
    # [UNKNOWN 2026-04-26] Protocol name → setting key mapping; values not confirmed from live API
    proto_map = {
        "pptp": "vpn_pptp",
        "l2tp": "vpn_l2tp",
        "l2tp-ipsec": "vpn_l2tp",
        "l2tpipsec": "vpn_l2tp",
        "wireguard": "vpn_wireguard",
        "openvpn": "vpn_openvpn",
    }
    for config in vpn_configs:
        # [UNKNOWN 2026-04-26] 'type' or 'protocol' field name; not confirmed from live API
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
        — [UNKNOWN 2026-04-26: not verifiable from Plan 07 (HTTP 401); Plan 08 will confirm]
        — empty dicts cause affected modules to emit "disabled/unknown" findings,
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
        # [UNKNOWN 2026-04-26] firewallgroup not separately exposed in Integration v1 API;
        # Plan 07 returned HTTP 401 — cannot confirm. Plan 08 will verify.
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

        # Settings exposure by Integration v1 API — not verifiable (Plan 07 HTTP 401).
        # Empty dicts -> modules emit "disabled/unknown" findings (correct per D-03).
        # Plan 08 will confirm whether any of these are actually exposed.
        "auto_update": {},     # [UNKNOWN 2026-04-26: not verifiable from Plan 07]
        "auto_backup": {},     # [UNKNOWN 2026-04-26: not verifiable from Plan 07]
        "mgmt": {},            # [UNKNOWN 2026-04-26: not verifiable from Plan 07]
        "dpi": {},             # [UNKNOWN 2026-04-26: not verifiable from Plan 07]
        "rogueap": {},         # [UNKNOWN 2026-04-26: not verifiable from Plan 07]
        "dns_filtering": {},   # [UNKNOWN 2026-04-26: not verifiable from Plan 07]
        "content_filtering": {},  # [UNKNOWN 2026-04-26: not verifiable from Plan 07]

        # Debug: preserved for adapter refinement in Plan 07
        "_vpn_configs_raw": vpn_configs,
    }
