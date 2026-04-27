# Phase 1 Finalization Design

**Date:** 2026-04-27  
**Status:** Approved  
**Scope:** Normalized data layer, wiring all enhanced findings, always-float-to-top logic, profile-aware scoring weights

---

## Problem

`findings_enhanced.py` was written against the backup-parser format (`_get_collection(colls, ...)`, `_get_setting(colls, ...)`). The live API audit in `unifi_audit.py` uses a different site-scoped shape. They are not compatible. Wiring them requires a common normalized format both can produce and all finding modules can consume.

---

## Decisions

- **Common normalized layer (Option A):** A single `normalize.py` module maps API responses to `NormalizedSite`. Phase 4 backup mode will add a `normalize_backup()` function. Finding modules become data-source agnostic.
- **Tension detection deferred:** Cross-answer compound findings are out of scope for this phase.
- **Float-to-top and profile scoring included:** Both are structurally simple and needed for correct report ordering.

---

## Architecture

```
raw API response  ──► normalize_api()  ──► [NormalizedSite, ...]  ──► findings modules
                                                                    ──► analyze()
backup colls dict ──► normalize_backup() (Phase 4)
```

All finding modules accept a `NormalizedSite`. Neither `parser.py` nor API-specific dict shapes appear in any finding module.

---

## New Files

### `src/models.py`

Extracts `Finding` out of `unifi_audit.py` so both `unifi_audit.py` and `findings_enhanced.py` can import it without a circular dependency.

```python
@dataclass
class Finding:
    id: str
    section: str
    severity: str   # info | low | medium | high | critical
    status: str     # ok | gap | recommendation | unknown
    title: str
    current_state: str
    recommendation: str | None = None
    intent_question: str | None = None
    evidence: dict = field(default_factory=dict)
    maps_to: dict = field(default_factory=dict)
    effort: str = "medium"
    impact: str = "medium"
```

`unifi_audit.py` and `findings_enhanced.py` both import `Finding` from `models`.

### `src/normalize.py`

```python
@dataclass
class NormalizedSite:
    site_id: str
    site_name: str
    # API-backed collections
    devices: list[dict]
    clients: list[dict]
    wlans: list[dict]
    networks: list[dict]
    port_forwards: list[dict]
    vpn_configs: list[dict]
    firewall_policies: list[dict]
    firewall_zones: list[dict]
    traffic_routes: list[dict]
    profile: str          # home | home_office | small_business | regulated_hipaa | regulated_pci
    api_gaps: list[str]   # endpoint names that 404'd for this site

def normalize_api(clean: dict, profile: str) -> list[NormalizedSite]:
    """Map collect_all() output to NormalizedSite list. One per site."""
    ...
```

`normalize_api` iterates `_all_sites(clean)`, calls `_extract_list()` on each collection key, and returns one `NormalizedSite` per site. All field extraction uses the existing `_extract_list` helper.

### Settings fields not exposed by the live API

Several findings in `findings_enhanced.py` rely on `_get_setting(colls, ...)` to read settings that exist in backup files but have no corresponding endpoint in the Network Integration API (e.g. `auto_update`, `dns_filtering`, `rogueap`, `mgmt`, `dpi`, `auto_backup`).

**Rule:** If a setting is not available via the API, the finding module must:
1. Check the relevant `NormalizedSite` collection field (e.g., device-level `auto_update` may appear in device objects)
2. If genuinely absent, emit a `status="unknown"` finding with a note that the check requires backup-file mode, **not** a false `ok` or false `gap`
3. Add the missing setting name to `api_gaps` at normalize time

This ensures the API-mode audit is honest about its coverage limits rather than silently skipping checks.

---

## Changes to `findings_enhanced.py`

- Remove all `from parser import Finding, _get_collection, _get_setting`
- Each function signature changes from `fn(colls: dict)` to `fn(site: NormalizedSite)`
- Replace `_get_collection(colls, "wlanconf")` → `site.wlans`
- Replace `_get_collection(colls, "device")` → `site.devices`
- Replace `_get_collection(colls, "portforward")` → `site.port_forwards`
- Replace `_get_setting(colls, ...)` → access via relevant collection or a `site.settings` helper if needed
- `Finding` imported from `models` (see `src/models.py` above)

---

## Changes to `unifi_audit.py`

### Normalization step in `main()`

```python
# After sanitize(), before analyze():
from normalize import normalize_api
sites = normalize_api(clean, cfg["profile"])
findings = analyze(sites, cfg["profile"], logger)
```

### Extended `analyze()` module list

```python
from findings_enhanced import (
    find_wireless_tuning, find_remote_access as find_remote_access_enhanced,
    find_firewall_threats, find_firmware, find_logging, find_backup_config,
)

modules = [
    ("segmentation",        _find_segmentation),
    ("wifi",                _find_wifi),
    ("firewall",            _find_firewall),
    ("remote_access",       find_remote_access_enhanced),  # supersedes inline _find_remote_access; covers PPTP, L2TP, WireGuard
    ("devices",             _find_devices),
    ("wireless_tuning",     find_wireless_tuning),
    ("firewall_threats",    find_firewall_threats),
    ("firmware",            find_firmware),
    ("logging",             find_logging),
    ("backup",              find_backup_config),
]
# api_coverage runs on raw clean dict — stays separate, called after the per-site loop
# _find_remote_access (inline) is removed; find_remote_access_enhanced is its full replacement
```

Each module is called once per `NormalizedSite`. Results aggregated across all sites before sorting.

---

## Always-Float-to-Top Logic

Applied in `analyze()` after all findings collected, before severity sort.

```python
ALWAYS_TOP_PREDICATES = [
    lambda f: f.id.startswith("MFA-"),
    lambda f: f.id == "SEG-MGMT-WAN",
    lambda f: f.id.startswith("SEG-001"),
    lambda f: f.id.startswith("CRED-DEFAULT"),
    lambda f: f.id.startswith("FW-EOL") and f.severity == "high",
    lambda f: f.id == "VPN-PPTP-001",
]

def _is_float_top(f: Finding) -> bool:
    return any(pred(f) for pred in ALWAYS_TOP_PREDICATES)
```

Sort order: float-top findings first (preserving severity order among themselves), then remaining by severity.

---

## Profile-Aware Scoring

A post-analysis pass that adjusts `severity` and/or `impact` per finding ID for the current profile. Applied before sorting.

```python
PROFILE_OVERRIDES: dict[str, dict[str, dict]] = {
    "home": {
        "LOG-FWD-001":  {"severity": "low"},
        "LOG-PRIV-001": {"severity": "medium"},
    },
    "regulated_hipaa": {
        "LOG-FWD-001":  {"severity": "high"},
        "BAK-001":      {"severity": "critical"},
    },
    "regulated_pci": {
        "LOG-FWD-001":  {"severity": "high"},
        "FW-GEO-IN":    {"severity": "medium"},
    },
}
```

Findings not in the override table are unaffected. Override is a shallow mutation of `severity`/`impact` on the `Finding` dataclass before sorting.

---

## Out of Scope for This Phase

- Cross-answer tension detection (compound findings) — deferred to a later phase
- Backup-file normalization (`normalize_backup()`) — Phase 4
- New finding IDs for MFA, management-plane WAN exposure, default credentials — these are float-top predicates referencing IDs that don't exist yet; predicates are inert until the finding modules that emit them are added

---

## Files Changed

| File | Change |
|------|--------|
| `src/normalize.py` | New — `NormalizedSite` dataclass + `normalize_api()` |
| `src/findings_enhanced.py` | Port from `colls`-based to `NormalizedSite`-based |
| `src/unifi_audit.py` | Add normalization step, extend module list, add float-top + profile scoring in `analyze()` |
