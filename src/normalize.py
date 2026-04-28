from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

_EXPECTED_COLLECTIONS = frozenset({
    "devices", "clients", "wlans", "networks", "port_forwards",
    "vpn_configs", "firewall_policies", "firewall_zones", "traffic_routes",
})


@dataclass
class NormalizedSite:
    site_id: str
    site_name: str
    devices: list[dict] = field(default_factory=list)
    clients: list[dict] = field(default_factory=list)
    wlans: list[dict] = field(default_factory=list)
    networks: list[dict] = field(default_factory=list)
    port_forwards: list[dict] = field(default_factory=list)
    vpn_configs: list[dict] = field(default_factory=list)
    firewall_policies: list[dict] = field(default_factory=list)
    firewall_zones: list[dict] = field(default_factory=list)
    traffic_routes: list[dict] = field(default_factory=list)
    settings: dict = field(default_factory=dict)  # empty in API mode; populated by backup parser
    profile: str = "home_office"
    api_gaps: list[str] = field(default_factory=list)


def _extract_list(data: Any) -> list:
    """Normalise varying API response shapes to a plain list."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "items", "results"):
            if key in data and isinstance(data[key], list):
                return data[key]
    return []


def normalize_api(clean: dict, profile: str) -> list[NormalizedSite]:
    """Convert collect_all() output to one NormalizedSite per site."""
    sites = []
    for key, val in clean.items():
        if not key.startswith("site_") or not isinstance(val, dict):
            continue
        site_id = key[5:]
        meta = val.get("_meta", {})
        site_name = meta.get("desc") or meta.get("name") or site_id
        api_gaps = sorted(name for name in _EXPECTED_COLLECTIONS if name not in val)
        sites.append(NormalizedSite(
            site_id=site_id,
            site_name=site_name,
            devices=_extract_list(val.get("devices")),
            clients=_extract_list(val.get("clients")),
            wlans=_extract_list(val.get("wlans")),
            networks=_extract_list(val.get("networks")),
            port_forwards=_extract_list(val.get("port_forwards")),
            vpn_configs=_extract_list(val.get("vpn_configs")),
            firewall_policies=_extract_list(val.get("firewall_policies")),
            firewall_zones=_extract_list(val.get("firewall_zones")),
            traffic_routes=_extract_list(val.get("traffic_routes")),
            settings={},
            profile=profile,
            api_gaps=api_gaps,
        ))
    return sites
