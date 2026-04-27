# Phase 1 Finalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a normalized data layer so all finding modules are data-source agnostic, wire all enhanced findings into the live audit pipeline, and add float-to-top + profile-aware scoring.

**Architecture:** A new `src/models.py` holds the `Finding` dataclass. A new `src/normalize.py` converts raw API output into `NormalizedSite` objects. All finding modules in `findings_enhanced.py` are ported to accept `NormalizedSite`. `unifi_audit.py` calls `normalize_api()` then runs all modules.

**Tech Stack:** Python 3.9+, pytest, existing stdlib + requests

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/models.py` | Create | `Finding` dataclass — single source of truth |
| `src/normalize.py` | Create | `NormalizedSite` dataclass + `normalize_api()` + `_extract_list()` |
| `src/findings_enhanced.py` | Modify | Port all 6 modules from `colls`-based to `NormalizedSite`-based |
| `src/unifi_audit.py` | Modify | Import `Finding` from `models`, call `normalize_api()`, extend module list, add float-top + profile scoring, remove `_find_remote_access` (superseded) |
| `tests/__init__.py` | Create | Empty — makes `tests/` a package |
| `tests/test_models.py` | Create | `Finding` construction + defaults |
| `tests/test_normalize.py` | Create | `normalize_api()` and `_extract_list()` |
| `tests/test_findings_enhanced.py` | Create | Each ported finding module |
| `tests/test_analyze.py` | Create | Float-top ordering + profile override |

---

## Task 1: Test infrastructure + extract `Finding` to `src/models.py`

**Files:**
- Create: `src/models.py`
- Modify: `src/unifi_audit.py` (remove local `Finding`, import from `models`)
- Create: `tests/__init__.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Install pytest**

```bash
pip install pytest
```

- [ ] **Step 2: Write the failing test**

Create `tests/__init__.py` (empty file), then create `tests/test_models.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models import Finding

def test_finding_required_fields():
    f = Finding(
        id="TEST-001", section="Test", severity="high",
        status="gap", title="A finding", current_state="Something is wrong",
    )
    assert f.id == "TEST-001"
    assert f.severity == "high"

def test_finding_optional_defaults():
    f = Finding(
        id="TEST-002", section="Test", severity="low",
        status="ok", title="Fine", current_state="All good",
    )
    assert f.recommendation is None
    assert f.intent_question is None
    assert f.evidence == {}
    assert f.maps_to == {}
    assert f.effort == "medium"
    assert f.impact == "medium"
```

- [ ] **Step 3: Run test — expect ImportError (module doesn't exist yet)**

```bash
pytest tests/test_models.py -v
```

Expected: `ModuleNotFoundError: No module named 'models'`

- [ ] **Step 4: Create `src/models.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field


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

- [ ] **Step 5: Run test — expect PASS**

```bash
pytest tests/test_models.py -v
```

Expected: 2 passed

- [ ] **Step 6: Update `src/unifi_audit.py` — remove local `Finding`, import from `models`**

Remove the `@dataclass class Finding` block (lines ~100–113). Add at the top of the imports section:

```python
from models import Finding
```

- [ ] **Step 7: Smoke-check the import chain**

```bash
python -c "from unifi_audit import Finding; print('ok')"
```

Expected: `ok`

- [ ] **Step 8: Commit**

```bash
git add src/models.py src/unifi_audit.py tests/__init__.py tests/test_models.py
git commit -m "feat: extract Finding dataclass to src/models.py"
```

---

## Task 2: Create `src/normalize.py`

**Files:**
- Create: `src/normalize.py`
- Modify: `src/unifi_audit.py` (remove `_extract_list`, import from `normalize`)
- Create: `tests/test_normalize.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_normalize.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from normalize import normalize_api, NormalizedSite, _extract_list

CLEAN_ONE_SITE = {
    "_endpoints_probed": [], "_errors": [], "_site_count": 1,
    "site_default": {
        "_meta": {"desc": "Home", "name": "default"},
        "devices":          {"data": [{"mac": "aa:bb:cc", "type": "ugw"}]},
        "clients":          {"data": []},
        "wlans":            {"data": [{"name": "HomeNet", "enabled": True}]},
        "networks":         {"data": [{"name": "LAN", "purpose": "corporate"}]},
        "port_forwards":    {"data": []},
        "vpn_configs":      {"data": []},
        "firewall_policies":{"data": []},
        "firewall_zones":   {"data": []},
        "traffic_routes":   {"data": []},
    },
}

def test_returns_one_site():
    assert len(normalize_api(CLEAN_ONE_SITE, "home_office")) == 1

def test_site_id():
    assert normalize_api(CLEAN_ONE_SITE, "home_office")[0].site_id == "default"

def test_site_name_from_desc():
    assert normalize_api(CLEAN_ONE_SITE, "home_office")[0].site_name == "Home"

def test_wlans_unpacked():
    site = normalize_api(CLEAN_ONE_SITE, "home_office")[0]
    assert len(site.wlans) == 1
    assert site.wlans[0]["name"] == "HomeNet"

def test_devices_unpacked():
    site = normalize_api(CLEAN_ONE_SITE, "home_office")[0]
    assert site.devices[0]["mac"] == "aa:bb:cc"

def test_empty_input():
    assert normalize_api({}, "home") == []

def test_profile_set():
    site = normalize_api(CLEAN_ONE_SITE, "regulated_hipaa")[0]
    assert site.profile == "regulated_hipaa"

def test_api_gaps_tracks_missing_collections():
    clean = {"site_s1": {"_meta": {"name": "s1"}, "devices": {"data": []}}}
    site = normalize_api(clean, "home")[0]
    assert "wlans" in site.api_gaps
    assert "devices" not in site.api_gaps

def test_settings_empty_in_api_mode():
    site = normalize_api(CLEAN_ONE_SITE, "home")[0]
    assert site.settings == {}

def test_extract_list_data_key():
    assert _extract_list({"data": [1, 2]}) == [1, 2]

def test_extract_list_plain_list():
    assert _extract_list([1, 2]) == [1, 2]

def test_extract_list_none():
    assert _extract_list(None) == []

def test_extract_list_items_key():
    assert _extract_list({"items": ["a", "b"]}) == ["a", "b"]
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/test_normalize.py -v
```

Expected: `ModuleNotFoundError: No module named 'normalize'`

- [ ] **Step 3: Create `src/normalize.py`**

```python
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
```

- [ ] **Step 4: Run tests — expect all pass**

```bash
pytest tests/test_normalize.py -v
```

Expected: 12 passed

- [ ] **Step 5: Remove `_extract_list` from `unifi_audit.py`, import from `normalize`**

In `src/unifi_audit.py`, delete the `_extract_list` function (search for `def _extract_list`). Add to imports:

```python
from normalize import normalize_api, _extract_list
```

- [ ] **Step 6: Verify unifi_audit still imports cleanly**

```bash
python -c "import unifi_audit; print('ok')"
```

Expected: `ok`

- [ ] **Step 7: Commit**

```bash
git add src/normalize.py src/unifi_audit.py tests/test_normalize.py
git commit -m "feat: add NormalizedSite + normalize_api() in src/normalize.py"
```

---

## Task 3: Port `find_wireless_tuning` and `find_remote_access`

**Files:**
- Modify: `src/findings_enhanced.py`
- Create: `tests/test_findings_enhanced.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_findings_enhanced.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from normalize import NormalizedSite
from findings_enhanced import find_wireless_tuning, find_remote_access

def _site(**kwargs) -> NormalizedSite:
    """Build a minimal NormalizedSite for testing."""
    defaults = dict(
        site_id="test", site_name="Test",
        devices=[], clients=[], wlans=[], networks=[],
        port_forwards=[], vpn_configs=[], firewall_policies=[],
        firewall_zones=[], traffic_routes=[], settings={},
        profile="home_office", api_gaps=[],
    )
    defaults.update(kwargs)
    return NormalizedSite(**defaults)


# --- find_wireless_tuning ---

def test_high_tx_power_emits_finding():
    site = _site(devices=[{
        "type": "uap", "mac": "aa:bb:cc", "name": "AP1",
        "radio_table": [{"radio": "na", "tx_power_mode": "high"}],
    }])
    findings = find_wireless_tuning(site)
    ids = [f.id for f in findings]
    assert "RF-aa:bb:cc-na-TX" in ids

def test_auto_tx_power_no_finding():
    site = _site(devices=[{
        "type": "uap", "mac": "aa:bb:cc", "name": "AP1",
        "radio_table": [{"radio": "na", "tx_power_mode": "auto"}],
    }])
    findings = find_wireless_tuning(site)
    assert not any(f.id.endswith("-TX") for f in findings)

def test_24ghz_active_emits_finding():
    site = _site(
        devices=[{"type": "uap", "mac": "aa", "radio_table": [{"radio": "ng"}]}],
        clients=[{"radio": "ng"}, {"radio": "na"}],
    )
    ids = [f.id for f in find_wireless_tuning(site)]
    assert "RF-BAND-24GHZ" in ids

def test_rogueap_unknown_when_no_settings():
    site = _site()  # settings={}
    findings = find_wireless_tuning(site)
    rogue = [f for f in findings if f.id == "RF-ROGUE-001"]
    assert rogue
    assert rogue[0].status == "unknown"

def test_rogueap_gap_when_disabled_in_settings():
    site = _site(settings={"rogueap": {"report_rogue": False}})
    findings = find_wireless_tuning(site)
    rogue = [f for f in findings if f.id == "RF-ROGUE-001"]
    assert rogue
    assert rogue[0].status == "gap"

def test_wpa3_without_pmf_emits_finding():
    site = _site(wlans=[{
        "name": "Secure", "enabled": True,
        "wpa_mode": "wpa3", "pmf_mode": "disabled",
    }])
    ids = [f.id for f in find_wireless_tuning(site)]
    assert "RF-PMF-Secure" in ids

def test_wpa3_with_pmf_required_no_finding():
    site = _site(wlans=[{
        "name": "Secure", "enabled": True,
        "wpa_mode": "wpa3", "pmf_mode": "required",
    }])
    ids = [f.id for f in find_wireless_tuning(site)]
    assert "RF-PMF-Secure" not in ids


# --- find_remote_access ---

def test_pptp_vpn_emits_critical():
    site = _site(vpn_configs=[{"type": "pptp", "enabled": True}])
    findings = find_remote_access(site)
    pptp = [f for f in findings if f.id == "VPN-PPTP-001"]
    assert pptp
    assert pptp[0].severity == "critical"

def test_wireguard_emits_ok():
    site = _site(vpn_configs=[{"type": "wireguard", "enabled": True}])
    ids = {f.id: f for f in find_remote_access(site)}
    assert "VPN-WG-OK" in ids
    assert ids["VPN-WG-OK"].status == "ok"

def test_port_forwards_no_vpn_emits_high():
    site = _site(
        port_forwards=[{"enabled": True, "dst_port": "22"}],
        vpn_configs=[],
    )
    findings = find_remote_access(site)
    missing = [f for f in findings if f.id == "VPN-MISSING-001"]
    assert missing
    assert missing[0].severity == "high"

def test_port_forwards_with_wireguard_no_missing_vpn_finding():
    site = _site(
        port_forwards=[{"enabled": True, "dst_port": "80"}],
        vpn_configs=[{"type": "wireguard", "enabled": True}],
    )
    ids = [f.id for f in find_remote_access(site)]
    assert "VPN-MISSING-001" not in ids

def test_l2tp_only_emits_recommendation():
    site = _site(vpn_configs=[{"type": "l2tp", "enabled": True}])
    findings = find_remote_access(site)
    l2tp = [f for f in findings if f.id == "VPN-L2TP-001"]
    assert l2tp
    assert l2tp[0].severity == "medium"

def test_l2tp_plus_wireguard_no_l2tp_finding():
    site = _site(vpn_configs=[
        {"type": "l2tp", "enabled": True},
        {"type": "wireguard", "enabled": True},
    ])
    ids = [f.id for f in find_remote_access(site)]
    assert "VPN-L2TP-001" not in ids
```

- [ ] **Step 2: Run — expect failures (functions still use old signature)**

```bash
pytest tests/test_findings_enhanced.py -v
```

Expected: errors or failures on all tests

- [ ] **Step 3: Port `find_wireless_tuning` in `src/findings_enhanced.py`**

Replace the existing `find_wireless_tuning(colls: dict)` function with:

```python
def find_wireless_tuning(site) -> list:
    """Per-AP radio tuning: TX power, unused bands, rogue AP detection, PMF."""
    from models import Finding

    findings = []
    devices = [d for d in site.devices if d.get("type") == "uap"]

    for d in devices:
        ap_name = d.get("name") or d.get("mac", "unnamed")
        for r in d.get("radio_table", []):
            band = r.get("radio", "unknown")
            band_label = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}.get(band, band)
            if r.get("tx_power_mode") == "high":
                findings.append(Finding(
                    id=f"RF-{d.get('mac', 'x')}-{band}-TX",
                    section="Wireless tuning",
                    severity="low",
                    status="recommendation",
                    title=f"AP '{ap_name}' broadcasting at High power on {band_label}",
                    current_state=(
                        f"AP '{ap_name}' {band_label} radio is set to High TX power. "
                        "High power extends coverage past your physical space, inviting "
                        "opportunistic attacks from parking lots and drive-by reconnaissance."
                    ),
                    recommendation=(
                        "Set TX power to Auto or Medium for typical indoor use. "
                        "Exception: intentional outdoor or large-property coverage."
                    ),
                    intent_question="Is extended coverage deliberate (outdoor, large property)?",
                    maps_to={"cis_v8": "12.5", "nist_csf": "PR.PT-4"},
                    effort="quick",
                    impact="low",
                ))

    aps_with_24 = [
        d for d in devices
        if any(r.get("radio") == "ng" and not r.get("disabled") for r in d.get("radio_table", []))
    ]
    if aps_with_24:
        clients_on_24 = sum(1 for c in site.clients if c.get("radio") == "ng")
        total_wifi = sum(1 for c in site.clients if c.get("radio"))
        findings.append(Finding(
            id="RF-BAND-24GHZ",
            section="Wireless tuning",
            severity="info",
            status="recommendation",
            title="2.4 GHz radio active across AP(s)",
            current_state=(
                f"{len(aps_with_24)} AP(s) have 2.4 GHz enabled. "
                f"{clients_on_24} of {total_wifi} Wi-Fi clients are on 2.4 GHz."
            ),
            recommendation=(
                "Identify which devices need 2.4 GHz. If few do, disable it to shrink "
                "attack surface. If IoT requires it, isolate those on a dedicated VLAN."
            ),
            intent_question="Do you have devices that truly require 2.4 GHz?",
            maps_to={"cis_v8": "12.5"},
            effort="medium",
            impact="medium",
            evidence={"aps_24ghz": len(aps_with_24), "clients_24ghz": clients_on_24, "total_wifi": total_wifi},
        ))

    rogue_setting = site.settings.get("rogueap")
    if rogue_setting is None:
        findings.append(Finding(
            id="RF-ROGUE-001",
            section="Wireless tuning",
            severity="info",
            status="unknown",
            title="Rogue AP detection: cannot check via live API",
            current_state=(
                "Rogue AP detection state is not exposed by the Network Integration API. "
                "Use backup-file mode to audit this, or check Settings → WiFi → Advanced."
            ),
            recommendation="Enable Rogue AP Detection in Settings → WiFi → Advanced.",
            intent_question="Is rogue AP detection currently enabled?",
            maps_to={"cis_v8": "12.6", "nist_csf": "DE.CM-7"},
            effort="quick",
            impact="medium",
        ))
    elif not rogue_setting.get("report_rogue"):
        findings.append(Finding(
            id="RF-ROGUE-001",
            section="Wireless tuning",
            severity="medium",
            status="gap",
            title="Rogue AP detection not enabled",
            current_state=(
                "Rogue AP reporting is disabled. A fake version of your SSID "
                "would not be detected."
            ),
            recommendation="Enable Rogue AP Detection in Settings → WiFi → Advanced.",
            intent_question="Want rogue AP detection on? (no performance cost)",
            maps_to={"cis_v8": "12.6", "nist_csf": "DE.CM-7"},
            effort="quick",
            impact="medium",
        ))

    for w in site.wlans:
        if not w.get("enabled", True):
            continue
        name = w.get("name", "<unnamed>")
        wpa_mode = w.get("wpa_mode", "")
        pmf = w.get("pmf_mode", "disabled")
        if "wpa3" in wpa_mode.lower() and pmf == "disabled":
            findings.append(Finding(
                id=f"RF-PMF-{name}",
                section="Wireless tuning",
                severity="medium",
                status="gap",
                title=f"SSID '{name}' uses WPA3 but PMF is disabled",
                current_state=(
                    f"SSID '{name}' has WPA3 but PMF (802.11w) is off. "
                    "PMF is a WPA3 requirement that blocks deauth attacks."
                ),
                recommendation=f"Set PMF to Required on '{name}'.",
                intent_question=None,
                maps_to={"cis_v8": "12.5"},
                effort="quick",
                impact="medium",
            ))

    return findings
```

- [ ] **Step 4: Port `find_remote_access` in `src/findings_enhanced.py`**

Replace the existing `find_remote_access(colls: dict)` function with:

```python
def find_remote_access(site) -> list:
    """Remote access paths: PPTP, L2TP, WireGuard, OpenVPN, port-forward exposure."""
    from models import Finding

    findings = []
    vpn_by_type: dict[str, dict] = {}
    for v in site.vpn_configs:
        t = (v.get("type") or "").lower().replace("-", "_")
        if v.get("enabled", True):
            vpn_by_type[t] = v

    pptp = vpn_by_type.get("pptp")
    l2tp = vpn_by_type.get("l2tp") or vpn_by_type.get("l2tp_ipsec")
    wireguard = vpn_by_type.get("wireguard") or vpn_by_type.get("wg")
    openvpn = vpn_by_type.get("openvpn")

    if pptp:
        findings.append(Finding(
            id="VPN-PPTP-001",
            section="Remote access",
            severity="critical",
            status="gap",
            title="PPTP VPN enabled (broken protocol)",
            current_state=(
                "PPTP is enabled. MS-CHAPv2 is cryptographically broken; credentials "
                "and session traffic can be recovered by anyone on-path."
            ),
            recommendation=(
                "Disable PPTP immediately. Replace with WireGuard. "
                "Rotate all credentials ever used over PPTP."
            ),
            intent_question=None,
            maps_to={"cis_v8": "4.4", "nist_csf": "PR.AC-3"},
            effort="quick",
            impact="high",
        ))

    if l2tp and not (wireguard or openvpn):
        findings.append(Finding(
            id="VPN-L2TP-001",
            section="Remote access",
            severity="medium",
            status="recommendation",
            title="L2TP/IPsec is the only VPN (consider WireGuard)",
            current_state=(
                "L2TP/IPsec is the only VPN. It is often blocked by hotel/public Wi-Fi "
                "and slower than WireGuard."
            ),
            recommendation="Add WireGuard as the primary VPN.",
            intent_question="Do you have a client that specifically requires L2TP?",
            maps_to={"cis_v8": "4.4"},
            effort="medium",
            impact="medium",
        ))

    active_forwards = [p for p in site.port_forwards if p.get("enabled", True)]
    has_vpn = bool(wireguard or openvpn or l2tp)
    if active_forwards and not has_vpn:
        findings.append(Finding(
            id="VPN-MISSING-001",
            section="Remote access",
            severity="high",
            status="gap",
            title=f"{len(active_forwards)} services exposed to internet, no VPN configured",
            current_state=(
                f"{len(active_forwards)} port forwards expose internal services. "
                "No VPN is configured."
            ),
            recommendation="Set up WireGuard VPN, then remove port forwards used only for remote access.",
            intent_question="Are any port forwards for services that must be public-facing?",
            maps_to={"cis_v8": "4.4", "nist_csf": "PR.AC-3"},
            effort="medium",
            impact="high",
        ))

    if wireguard:
        findings.append(Finding(
            id="VPN-WG-OK",
            section="Remote access",
            severity="info",
            status="ok",
            title="WireGuard VPN configured",
            current_state="WireGuard VPN is enabled. This is the recommended remote access path.",
            recommendation=None,
            intent_question=None,
            maps_to={"cis_v8": "4.4"},
            effort="quick",
            impact="low",
        ))

    return findings
```

- [ ] **Step 5: Run tests — expect all pass**

```bash
pytest tests/test_findings_enhanced.py -v
```

Expected: all wireless_tuning and remote_access tests pass

- [ ] **Step 6: Commit**

```bash
git add src/findings_enhanced.py tests/test_findings_enhanced.py
git commit -m "feat: port find_wireless_tuning and find_remote_access to NormalizedSite"
```

---

## Task 4: Port `find_firewall_threats`, `find_firmware`, `find_logging`, `find_backup_config`

**Files:**
- Modify: `src/findings_enhanced.py`
- Modify: `tests/test_findings_enhanced.py`

- [ ] **Step 1: Add tests for the four remaining modules**

Append to `tests/test_findings_enhanced.py`:

```python
from findings_enhanced import find_firewall_threats, find_firmware, find_logging, find_backup_config

# --- find_firewall_threats ---

def test_no_geo_inbound_emits_recommendation():
    site = _site(firewall_policies=[])
    ids = [f.id for f in find_firewall_threats(site)]
    assert "FW-GEO-IN" in ids

def test_geo_inbound_policy_suppresses_finding():
    site = _site(firewall_policies=[{
        "enabled": True, "action": "drop",
        "source": {"geo": ["CN", "RU"]}, "direction": "WAN_IN",
    }])
    ids = [f.id for f in find_firewall_threats(site)]
    assert "FW-GEO-IN" not in ids

def test_dns_filtering_unknown_when_no_settings():
    site = _site()
    findings = find_firewall_threats(site)
    cf = [f for f in findings if f.id == "FW-CONTENT-001"]
    assert cf
    assert cf[0].status == "unknown"

def test_dns_filtering_gap_when_disabled():
    site = _site(settings={"dns_filtering": {"enabled": False}})
    findings = find_firewall_threats(site)
    cf = [f for f in findings if f.id == "FW-CONTENT-001"]
    assert cf
    assert cf[0].status == "recommendation"


# --- find_firmware ---

def test_eol_device_emits_high():
    site = _site(devices=[{"model": "UAP-AC-LITE", "name": "OldAP", "version": "5.43.0"}])
    findings = find_firmware(site)
    eol = [f for f in findings if f.id == "FW-EOL-001"]
    assert eol
    assert eol[0].severity == "high"

def test_stale_major_version_emits_finding():
    site = _site(devices=[{"model": "UDM", "name": "GW", "version": "6.5.55", "mac": "aa:bb"}])
    findings = find_firmware(site)
    stale = [f for f in findings if f.id.startswith("FW-VER-")]
    assert stale

def test_auto_update_unknown_when_no_settings():
    site = _site()
    findings = find_firmware(site)
    au = [f for f in findings if f.id == "FW-AUTO-001"]
    assert au
    assert au[0].status == "unknown"

def test_auto_update_gap_when_disabled():
    site = _site(settings={"auto_update": {"enabled": False}})
    findings = find_firmware(site)
    au = [f for f in findings if f.id == "FW-AUTO-001"]
    assert au
    assert au[0].status == "gap"


# --- find_logging ---

def test_syslog_unknown_when_no_settings():
    site = _site()
    findings = find_logging(site, "home_office")
    fwd = [f for f in findings if f.id == "LOG-FWD-001"]
    assert fwd
    assert fwd[0].status == "unknown"

def test_syslog_gap_when_not_configured():
    site = _site(settings={"mgmt": {"syslog_host": None}})
    findings = find_logging(site, "home_office")
    fwd = [f for f in findings if f.id == "LOG-FWD-001"]
    assert fwd
    assert fwd[0].status == "recommendation"


# --- find_backup_config ---

def test_backup_unknown_when_no_settings():
    site = _site()
    findings = find_backup_config(site)
    bak = [f for f in findings if f.id == "BAK-001"]
    assert bak
    assert bak[0].status == "unknown"

def test_backup_gap_when_disabled():
    site = _site(settings={"auto_backup": {"enabled": False}})
    findings = find_backup_config(site)
    bak = [f for f in findings if f.id == "BAK-001"]
    assert bak
    assert bak[0].status == "gap"

def test_backup_local_only_emits_destination_finding():
    site = _site(settings={"auto_backup": {"enabled": True, "destination": "local"}})
    findings = find_backup_config(site)
    ids = [f.id for f in findings]
    assert "BAK-002" in ids

def test_backup_schrodinger_always_emitted_when_enabled():
    site = _site(settings={"auto_backup": {"enabled": True, "destination": "cloud"}})
    ids = [f.id for f in find_backup_config(site)]
    assert "BAK-003" in ids
```

- [ ] **Step 2: Run — expect failures**

```bash
pytest tests/test_findings_enhanced.py -v -k "firewall_threats or firmware or logging or backup"
```

Expected: failures (functions still use old signatures)

- [ ] **Step 3: Port `find_firewall_threats` in `src/findings_enhanced.py`**

Replace the existing function:

```python
def find_firewall_threats(site) -> list:
    """Geo-IP blocking (both directions) and DNS content filtering."""
    from models import Finding

    findings = []

    def _has_geo_policy(direction_hint: str) -> bool:
        for p in site.firewall_policies:
            if not p.get("enabled", True):
                continue
            action = p.get("action", "")
            if action != "drop":
                continue
            src = p.get("source", {})
            if src.get("geo"):
                name = (p.get("name") or "").lower()
                d = p.get("direction", "").upper()
                if direction_hint in d or direction_hint in name:
                    return True
        return False

    if not _has_geo_policy("WAN_IN"):
        findings.append(Finding(
            id="FW-GEO-IN",
            section="Firewall",
            severity="low",
            status="recommendation",
            title="No Geo-IP blocking on inbound WAN",
            current_state="No policy found blocking inbound traffic from high-risk regions.",
            recommendation=(
                "Block inbound connections from countries you have no business receiving "
                "traffic from (e.g. CN, RU, KP, IR). Low false-positive rate for most users."
            ),
            intent_question="Do you expect inbound traffic from these regions?",
            maps_to={"cis_v8": "13.4"},
            effort="quick",
            impact="medium",
        ))

    if not _has_geo_policy("WAN_OUT"):
        findings.append(Finding(
            id="FW-GEO-OUT",
            section="Firewall",
            severity="low",
            status="recommendation",
            title="No Geo-IP blocking on outbound WAN (often overlooked)",
            current_state=(
                "No outbound Geo-IP policy found. A compromised device calling home "
                "to a C2 in a blocked region would succeed."
            ),
            recommendation="Apply outbound geo-blocking for the same regions you block inbound.",
            intent_question="Do any of your services legitimately talk to servers in high-risk regions?",
            maps_to={"cis_v8": "13.4"},
            effort="quick",
            impact="low",
        ))

    dns_filter = site.settings.get("dns_filtering")
    if dns_filter is None:
        findings.append(Finding(
            id="FW-CONTENT-001",
            section="Firewall",
            severity="info",
            status="unknown",
            title="Content filtering: cannot check via live API",
            current_state=(
                "DNS content filtering state is not exposed by the Network Integration API. "
                "Use backup-file mode to audit this, or check Settings → Security → Content Filtering."
            ),
            recommendation=(
                "Enable Content Filtering with the Security category at minimum. "
                "This blocks known-malicious domains for every device."
            ),
            intent_question="Is DNS content filtering currently enabled?",
            maps_to={"cis_v8": "9.3", "nist_csf": "PR.PT-4"},
            effort="quick",
            impact="medium",
        ))
    elif not dns_filter.get("enabled"):
        findings.append(Finding(
            id="FW-CONTENT-001",
            section="Firewall",
            severity="medium",
            status="recommendation",
            title="Content filtering not configured",
            current_state=(
                "DNS-based content filtering is off. No automatic blocking of malware "
                "domains or phishing sites at the DNS layer."
            ),
            recommendation=(
                "Enable Content Filtering with the Security category at minimum."
            ),
            intent_question="Should the network block known-malicious domains automatically?",
            maps_to={"cis_v8": "9.3", "nist_csf": "PR.PT-4"},
            effort="quick",
            impact="medium",
        ))

    return findings
```

- [ ] **Step 4: Port `find_firmware` in `src/findings_enhanced.py`**

Replace the existing function (keep `EOL_MODELS` dict unchanged):

```python
def find_firmware(site) -> list:
    """Firmware currency: auto-update, EOL hardware, stale major versions."""
    from models import Finding

    findings = []

    auto_update = site.settings.get("auto_update")
    if auto_update is None:
        findings.append(Finding(
            id="FW-AUTO-001",
            section="Firmware",
            severity="info",
            status="unknown",
            title="Auto-update setting: cannot check via live API",
            current_state=(
                "Auto-update state is not exposed by the Network Integration API. "
                "Use backup-file mode or check Settings → System → Updates."
            ),
            recommendation=(
                "Enable automatic firmware updates in a maintenance window (e.g. 03:00–05:00)."
            ),
            intent_question="Is automatic firmware update enabled?",
            maps_to={"cis_v8": "7.3", "nist_csf": "PR.IP-12"},
            effort="quick",
            impact="medium",
        ))
    elif not auto_update.get("enabled"):
        findings.append(Finding(
            id="FW-AUTO-001",
            section="Firmware",
            severity="medium",
            status="gap",
            title="Automatic firmware updates disabled",
            current_state="Devices do not auto-update firmware.",
            recommendation=(
                "Enable automatic firmware updates in a maintenance window (e.g. 03:00–05:00)."
            ),
            intent_question="Any reason to hold back updates (firmware quirk, testing)?",
            maps_to={"cis_v8": "7.3", "nist_csf": "PR.IP-12"},
            effort="quick",
            impact="medium",
        ))

    eol_devices = []
    for d in site.devices:
        model = d.get("model", "").upper()
        if model in EOL_MODELS:
            eol_devices.append({
                "name": d.get("name", d.get("mac")),
                "model": model,
                "status": EOL_MODELS[model]["status"],
                "eol_date": EOL_MODELS[model]["eol_date"],
            })

    eol_count = sum(1 for d in eol_devices if d["status"] == "eol")
    warning_count = sum(1 for d in eol_devices if d["status"] == "eol_warning")

    if eol_count:
        findings.append(Finding(
            id="FW-EOL-001",
            section="Firmware",
            severity="high",
            status="gap",
            title=f"{eol_count} device(s) past end-of-support",
            current_state=(
                f"{eol_count} device(s) are past Ubiquiti's end-of-support date "
                "and no longer receive security patches."
            ),
            recommendation=(
                "Plan replacement. Prioritise internet-facing devices first."
            ),
            intent_question="What is your replacement budget and timeline?",
            maps_to={"cis_v8": "7.3", "nist_csf": "PR.IP-12"},
            effort="project",
            impact="high",
            evidence={"devices": [d for d in eol_devices if d["status"] == "eol"]},
        ))

    if warning_count:
        findings.append(Finding(
            id="FW-EOL-002",
            section="Firmware",
            severity="medium",
            status="recommendation",
            title=f"{warning_count} device(s) approaching EOL",
            current_state=f"{warning_count} device(s) reach end-of-support within 12 months.",
            recommendation="Start planning replacements during your normal refresh cycle.",
            intent_question="Is hardware refresh on your roadmap?",
            maps_to={"cis_v8": "7.3"},
            effort="project",
            impact="medium",
            evidence={"devices": [d for d in eol_devices if d["status"] == "eol_warning"]},
        ))

    for d in site.devices:
        ver = d.get("version", "")
        if ver and "." in ver:
            try:
                major = int(ver.split(".")[0])
                if major < 7:
                    findings.append(Finding(
                        id=f"FW-VER-{d.get('mac', 'x')}",
                        section="Firmware",
                        severity="high",
                        status="gap",
                        title=f"Device '{d.get('name', d.get('mac'))}' on outdated major version",
                        current_state=f"Firmware {ver} is multiple major versions behind current.",
                        recommendation="Update to latest stable firmware in a maintenance window.",
                        intent_question=None,
                        maps_to={"cis_v8": "7.3"},
                        effort="quick",
                        impact="high",
                    ))
            except (ValueError, IndexError):
                pass

    return findings
```

- [ ] **Step 5: Port `find_logging` in `src/findings_enhanced.py`**

Replace the existing function (keep `RETENTION_PROFILES` dict unchanged):

```python
def find_logging(site, profile: str = "home_office") -> list:
    """Privacy-aware logging findings."""
    from models import Finding

    findings = []
    retention_profile = RETENTION_PROFILES.get(profile, RETENTION_PROFILES["home_office"])

    mgmt = site.settings.get("mgmt")
    if mgmt is None:
        findings.append(Finding(
            id="LOG-FWD-001",
            section="Logging",
            severity="info",
            status="unknown",
            title="Syslog setting: cannot check via live API",
            current_state=(
                "Syslog forwarding state is not exposed by the Network Integration API. "
                "Use backup-file mode or check Settings → System → Logging."
            ),
            recommendation=(
                f"For a {profile.replace('_', ' ')} profile, forward syslog to an "
                f"external destination. Retention target: {retention_profile['admin_days'][0]} days."
            ),
            intent_question="Is syslog forwarding to an external destination currently configured?",
            maps_to={"cis_v8": "8.2", "nist_csf": "DE.AE-3"},
            effort="medium",
            impact="medium",
        ))
    elif not (mgmt.get("syslog_host") or mgmt.get("advanced_feature_enabled")):
        findings.append(Finding(
            id="LOG-FWD-001",
            section="Logging",
            severity="low" if profile.startswith("home") else "medium",
            status="recommendation",
            title="Logs not forwarded to external destination",
            current_state="All logs live only on the gateway. Gateway loss = log loss.",
            recommendation=(
                f"Forward syslog to an external destination. "
                f"Retention target: {retention_profile['admin_days'][0]} days minimum."
            ),
            intent_question="Do you want to set up external log storage?",
            maps_to={"cis_v8": "8.2", "nist_csf": "DE.AE-3"},
            effort="medium",
            impact="medium",
        ))

    dpi = site.settings.get("dpi")
    if dpi and profile.startswith("home"):
        dpi_level = dpi.get("level", "disabled")
        if dpi_level in ("client", "fingerprint"):
            findings.append(Finding(
                id="LOG-PRIV-001",
                section="Logging",
                severity="low",
                status="recommendation",
                title="Client-level DPI logging may exceed household need",
                current_state=(
                    f"DPI is set to '{dpi_level}', retaining per-client, per-application "
                    "browsing metadata. For a home profile, this can be more detail than needed."
                ),
                recommendation=(
                    "Consider aggregate/protocol-only DPI for a home network."
                ),
                intent_question="Do you actively use the per-client DPI views?",
                maps_to={"nist_csf": "PR.DS-5"},
                effort="quick",
                impact="low",
            ))

    return findings
```

- [ ] **Step 6: Port `find_backup_config` in `src/findings_enhanced.py`**

Replace the existing function:

```python
def find_backup_config(site) -> list:
    """Backup: auto-backup state, destination diversity, tested-restore."""
    from models import Finding

    findings = []
    auto_backup = site.settings.get("auto_backup")

    if auto_backup is None:
        findings.append(Finding(
            id="BAK-001",
            section="Backup",
            severity="info",
            status="unknown",
            title="Backup setting: cannot check via live API",
            current_state=(
                "Auto-backup state is not exposed by the Network Integration API. "
                "Use backup-file mode or check Settings → System → Backup."
            ),
            recommendation="Enable daily automatic backups, retention at least 7 days.",
            intent_question="Is automatic backup currently enabled?",
            maps_to={"cis_v8": "11.2", "nist_csf": "PR.IP-4"},
            effort="quick",
            impact="high",
        ))
        return findings

    if not auto_backup.get("enabled"):
        findings.append(Finding(
            id="BAK-001",
            section="Backup",
            severity="high",
            status="gap",
            title="Automatic backups disabled",
            current_state="Controller config backups are not running automatically.",
            recommendation="Enable daily automatic backups, retention at least 7 days.",
            intent_question=None,
            maps_to={"cis_v8": "11.2", "nist_csf": "PR.IP-4"},
            effort="quick",
            impact="high",
        ))
        return findings

    if auto_backup.get("destination", "local") == "local":
        findings.append(Finding(
            id="BAK-002",
            section="Backup",
            severity="medium",
            status="gap",
            title="Backups stored only on the gateway itself",
            current_state=(
                "Auto-backups are saved only to the gateway. If the gateway is lost, "
                "the backups go with it."
            ),
            recommendation=(
                "Add an off-device destination: UniFi cloud backup, SMB share on a NAS, "
                "or periodic manual download. Rule of 3-2-1: 3 copies, 2 media, 1 offsite."
            ),
            intent_question="Which off-device option fits your setup best?",
            maps_to={"cis_v8": "11.3"},
            effort="medium",
            impact="medium",
        ))

    findings.append(Finding(
        id="BAK-003",
        section="Backup",
        severity="medium",
        status="unknown",
        title="Backup restore not verified (Schrödinger backup)",
        current_state=(
            "Backups are running. But without a tested restore, viability is unknown. "
            "A backup that has never been restored is only hypothetically useful."
        ),
        recommendation=(
            "Schedule a quarterly restore test. At minimum: decrypt and open the backup "
            "file with an offline tool once a year to confirm it is parseable."
        ),
        intent_question="Have you ever restored this backup, and when?",
        maps_to={"cis_v8": "11.5", "nist_csf": "PR.IP-4"},
        effort="medium",
        impact="high",
    ))

    return findings
```

- [ ] **Step 7: Remove dead imports from top of `findings_enhanced.py`**

Delete the first few lines of the file (the old comment and `from __future__` block only — keep the module docstring):

```python
"""
Enhanced findings modules addressing the 10-point coverage gaps.

All finding modules accept a NormalizedSite from src/normalize.py.
"""

from __future__ import annotations
from typing import Any
```

- [ ] **Step 8: Run all findings tests**

```bash
pytest tests/test_findings_enhanced.py -v
```

Expected: all tests pass

- [ ] **Step 9: Commit**

```bash
git add src/findings_enhanced.py tests/test_findings_enhanced.py
git commit -m "feat: port all findings_enhanced modules to NormalizedSite"
```

---

## Task 5: Wire enhanced modules into `unifi_audit.py`

**Files:**
- Modify: `src/unifi_audit.py`

- [ ] **Step 1: Add normalization call in `main()`**

In `src/unifi_audit.py`, after `clean = sanitize(raw)` and before the findings analysis, add:

```python
    from normalize import normalize_api
    logger.info("Normalizing collected data into site objects...")
    sites = normalize_api(clean, cfg["profile"])
    logger.info(f"  -> {len(sites)} site(s) normalized")
```

- [ ] **Step 2: Add import for enhanced findings at top of file**

After the existing imports, add:

```python
from findings_enhanced import (
    find_wireless_tuning,
    find_remote_access as find_remote_access_enhanced,
    find_firewall_threats,
    find_firmware,
    find_logging,
    find_backup_config,
)
```

- [ ] **Step 3: Refactor `analyze()` to accept `list[NormalizedSite]`**

Replace the `analyze` signature and modules list:

```python
def analyze(sites: list, profile: str, logger: logging.Logger) -> list[Finding]:
    """Run all findings modules across all normalized sites."""
    findings: list[Finding] = []
    modules = [
        ("segmentation",     _find_segmentation),
        ("wifi",             _find_wifi),
        ("firewall",         _find_firewall),
        ("remote_access",    find_remote_access_enhanced),
        ("devices",          _find_devices),
        ("wireless_tuning",  find_wireless_tuning),
        ("firewall_threats", find_firewall_threats),
        ("firmware",         find_firmware),
        ("logging",          lambda s, p: find_logging(s, p)),
        ("backup",           lambda s, p: find_backup_config(s)),
    ]
    for site in sites:
        for name, fn in modules:
            try:
                findings.extend(fn(site, profile))
            except Exception as e:
                logger.warning(f"Module {name} failed on site {site.site_id}: {e}")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 5), f.section))
    return findings
```

- [ ] **Step 4: Update inline finding functions to accept `(site, profile)` signature**

Each of `_find_segmentation`, `_find_wifi`, `_find_firewall`, `_find_remote_access` (which is now unused — delete it), and `_find_devices` currently takes `(clean: dict, profile: str)`. Change them to `(site, profile: str)` and update their internals to use `site.networks`, `site.wlans`, `site.port_forwards`, `site.vpn_configs`, `site.devices` instead of `_all_sites(clean)` + `_extract_list(site.get(...))`.

For `_find_segmentation`:
```python
def _find_segmentation(site, profile: str) -> list[Finding]:
    networks = site.networks
    user_nets = [n for n in networks if n.get("purpose") in ("corporate", "guest", "vlan-only")]
    if len(user_nets) <= 1:
        return [Finding(
            id=f"SEG-001-{site.site_id}",
            section="Segmentation",
            severity="high",
            status="gap",
            title="Flat network (no segmentation)",
            current_state=(
                f"Site '{site.site_name}' has {len(user_nets)} user-defined network(s). "
                "Devices share a broadcast domain; a compromise of any device can reach any other."
            ),
            recommendation=(
                "Create separate networks for main, IoT, guest, and management. "
                "Map SSIDs to appropriate VLANs. Enable Zone-Based Firewall rules."
            ),
            intent_question="Do you want to segment the network?",
            maps_to={"nist_csf": "PR.AC-5", "cis_v8": "12.2"},
            effort="project",
            impact="high",
            evidence={"network_count": len(user_nets)},
        )]
    return []
```

For `_find_wifi`:
```python
def _find_wifi(site, profile: str) -> list[Finding]:
    findings = []
    for w in site.wlans:
        if not w.get("enabled", True):
            continue
        name = w.get("name", "<unnamed>")
        security = (w.get("security") or w.get("securityProtocol") or "").lower()
        if "wpa2" in security and "wpa3" not in security:
            findings.append(Finding(
                id=f"WIFI-{site.site_id}-{name}-WPA",
                section="Wi-Fi",
                severity="low",
                status="recommendation",
                title=f"SSID '{name}' is WPA2-only",
                current_state=f"SSID '{name}' uses WPA2. WPA3 or mixed mode offers stronger protection.",
                recommendation="Switch to WPA2/WPA3 mixed mode, or WPA3-only if all clients support it.",
                intent_question=f"Do any clients on '{name}' require WPA2-only?",
                maps_to={"cis_v8": "12.5"},
                effort="quick",
                impact="low",
            ))
        psk = w.get("x_passphrase")
        if isinstance(psk, dict) and psk.get("length", 0) < 12:
            findings.append(Finding(
                id=f"WIFI-{site.site_id}-{name}-PSK",
                section="Wi-Fi",
                severity="high",
                status="gap",
                title=f"SSID '{name}' has a short passphrase",
                current_state=f"Passphrase is {psk.get('length')} characters. Short PSKs are vulnerable to offline attacks.",
                recommendation="Use a passphrase of at least 16 characters with mixed case, numbers, and symbols.",
                intent_question=None,
                maps_to={"cis_v8": "5.2"},
                effort="quick",
                impact="high",
            ))
    return findings
```

For `_find_firewall`:
```python
def _find_firewall(site, profile: str) -> list[Finding]:
    active = [p for p in site.port_forwards if p.get("enabled", True)]
    if active:
        return [Finding(
            id=f"FW-{site.site_id}-PF",
            section="Firewall",
            severity="info",
            status="recommendation",
            title=f"{len(active)} port forward(s) active",
            current_state=f"{len(active)} port forwards expose internal services.",
            recommendation="Review each. Prefer VPN for admin access; use source IP allowlists for public services.",
            intent_question="Want to review each port forward?",
            maps_to={"cis_v8": "4.4"},
            effort="medium",
            impact="high",
            evidence={"count": len(active)},
        )]
    return []
```

For `_find_devices`:
```python
def _find_devices(site, profile: str) -> list[Finding]:
    ssh_on = [d for d in site.devices if d.get("sshEnabled") or d.get("ssh_enabled")]
    if ssh_on:
        return [Finding(
            id=f"DEV-SSH-{site.site_id}",
            section="Admin",
            severity="medium",
            status="recommendation",
            title=f"SSH enabled on {len(ssh_on)} device(s)",
            current_state=f"SSH is enabled on {len(ssh_on)} device(s). This is a remote admin surface.",
            recommendation="Disable SSH unless actively used. If needed, key-based auth only, scoped to management VLAN.",
            intent_question="Do you use SSH to these devices?",
            maps_to={"cis_v8": "4.6"},
            effort="quick",
            impact="medium",
        )]
    return []
```

- [ ] **Step 5: Remove `_find_remote_access` (inline version) from `unifi_audit.py`**

Delete the `_find_remote_access` function — it is superseded by `find_remote_access_enhanced`.

- [ ] **Step 6: Update `main()` to pass `sites` to `analyze()`**

Change:
```python
    findings = analyze(clean, cfg["profile"], logger)
```
To:
```python
    findings = analyze(sites, cfg["profile"], logger)
```

- [ ] **Step 7: Remove now-unused helpers from `unifi_audit.py`**

Delete `_all_sites()` — it is no longer called anywhere.

- [ ] **Step 8: Smoke-test the full pipeline**

```bash
python -c "
import unifi_audit, json
# Simulate a minimal clean dict
clean = {'site_default': {'_meta': {'desc': 'Test'}, 'devices': {'data': []}, 'clients': {'data': []}, 'wlans': {'data': []}, 'networks': {'data': []}, 'port_forwards': {'data': []}, 'vpn_configs': {'data': []}, 'firewall_policies': {'data': []}, 'firewall_zones': {'data': []}, 'traffic_routes': {'data': []}}, '_endpoints_probed': [], '_errors': []}
from normalize import normalize_api
sites = normalize_api(clean, 'home_office')
import logging
logger = logging.getLogger('test')
logger.addHandler(logging.NullHandler())
findings = unifi_audit.analyze(sites, 'home_office', logger)
print(f'findings: {len(findings)}')
"
```

Expected: prints `findings: <N>` without error

- [ ] **Step 9: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all tests pass

- [ ] **Step 10: Commit**

```bash
git add src/unifi_audit.py
git commit -m "feat: wire all enhanced finding modules into analyze() pipeline"
```

---

## Task 6: Float-to-top sorting

**Files:**
- Modify: `src/unifi_audit.py`
- Create: `tests/test_analyze.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_analyze.py`:

```python
import sys, os, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models import Finding
import unifi_audit

_logger = logging.getLogger("test")
_logger.addHandler(logging.NullHandler())

def _make_finding(fid, severity="medium"):
    return Finding(
        id=fid, section="Test", severity=severity,
        status="gap", title=fid, current_state="x",
    )

def test_pptp_finding_floats_above_medium():
    pptp = _make_finding("VPN-PPTP-001", "critical")
    medium = _make_finding("SOME-OTHER-001", "medium")
    # Simulate what analyze() sort does
    findings = [medium, pptp]
    result = unifi_audit._sort_findings(findings)
    assert result[0].id == "VPN-PPTP-001"

def test_seg001_floats_above_low():
    seg = _make_finding("SEG-001-default", "high")
    low = _make_finding("WIFI-x-WPA", "low")
    findings = [low, seg]
    result = unifi_audit._sort_findings(findings)
    assert result[0].id == "SEG-001-default"

def test_non_float_top_sorted_by_severity():
    high = _make_finding("HIGH-001", "high")
    low = _make_finding("LOW-001", "low")
    medium = _make_finding("MED-001", "medium")
    result = unifi_audit._sort_findings([low, medium, high])
    assert [f.id for f in result] == ["HIGH-001", "MED-001", "LOW-001"]

def test_two_float_top_sorted_among_themselves():
    pptp = _make_finding("VPN-PPTP-001", "critical")
    seg = _make_finding("SEG-001-x", "high")
    low = _make_finding("LOW-001", "low")
    result = unifi_audit._sort_findings([low, seg, pptp])
    ids = [f.id for f in result]
    assert ids[0] == "VPN-PPTP-001"
    assert ids[1] == "SEG-001-x"
    assert ids[2] == "LOW-001"
```

- [ ] **Step 2: Run — expect AttributeError (`_sort_findings` doesn't exist)**

```bash
pytest tests/test_analyze.py -v
```

Expected: `AttributeError: module 'unifi_audit' has no attribute '_sort_findings'`

- [ ] **Step 3: Add `ALWAYS_TOP_PREDICATES` and `_sort_findings()` to `unifi_audit.py`**

Add after the `Finding` import, before `analyze()`:

```python
ALWAYS_TOP_PREDICATES = [
    lambda f: f.id.startswith("MFA-"),
    lambda f: f.id == "SEG-MGMT-WAN",
    lambda f: f.id.startswith("SEG-001"),
    lambda f: f.id.startswith("CRED-DEFAULT"),
    lambda f: f.id.startswith("FW-EOL") and f.severity == "high",
    lambda f: f.id == "VPN-PPTP-001",
]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _is_float_top(f: Finding) -> bool:
    return any(pred(f) for pred in ALWAYS_TOP_PREDICATES)


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """Float-top findings first (severity-ordered among themselves), then remainder by severity."""
    top = [f for f in findings if _is_float_top(f)]
    rest = [f for f in findings if not _is_float_top(f)]
    top.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))
    rest.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 5), f.section))
    return top + rest
```

- [ ] **Step 4: Replace the sort in `analyze()` with `_sort_findings()`**

In `analyze()`, replace:
```python
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 5), f.section))
    return findings
```
With:
```python
    return _sort_findings(findings)
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_analyze.py -v
```

Expected: all 4 tests pass

- [ ] **Step 6: Commit**

```bash
git add src/unifi_audit.py tests/test_analyze.py
git commit -m "feat: add always-float-to-top sorting for high-priority findings"
```

---

## Task 7: Profile-aware scoring overrides

**Files:**
- Modify: `src/unifi_audit.py`
- Modify: `tests/test_analyze.py`

- [ ] **Step 1: Add tests**

Append to `tests/test_analyze.py`:

```python
def test_home_profile_log_fwd_is_low():
    f = _make_finding("LOG-FWD-001", "medium")
    result = unifi_audit._apply_profile_overrides([f], "home")
    assert result[0].severity == "low"

def test_regulated_hipaa_log_fwd_is_high():
    f = _make_finding("LOG-FWD-001", "medium")
    result = unifi_audit._apply_profile_overrides([f], "regulated_hipaa")
    assert result[0].severity == "high"

def test_regulated_hipaa_bak001_is_critical():
    f = _make_finding("BAK-001", "high")
    result = unifi_audit._apply_profile_overrides([f], "regulated_hipaa")
    assert result[0].severity == "critical"

def test_unknown_finding_id_unchanged():
    f = _make_finding("SOME-UNKNOWN-999", "medium")
    result = unifi_audit._apply_profile_overrides([f], "regulated_hipaa")
    assert result[0].severity == "medium"

def test_unknown_profile_unchanged():
    f = _make_finding("LOG-FWD-001", "medium")
    result = unifi_audit._apply_profile_overrides([f], "nonexistent_profile")
    assert result[0].severity == "medium"
```

- [ ] **Step 2: Run — expect AttributeError**

```bash
pytest tests/test_analyze.py -v -k "profile"
```

Expected: `AttributeError: module 'unifi_audit' has no attribute '_apply_profile_overrides'`

- [ ] **Step 3: Add `PROFILE_OVERRIDES` and `_apply_profile_overrides()` to `unifi_audit.py`**

Add after `_sort_findings`:

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


def _apply_profile_overrides(findings: list[Finding], profile: str) -> list[Finding]:
    """Mutate severity/impact on findings that have a profile-specific override."""
    overrides = PROFILE_OVERRIDES.get(profile, {})
    for f in findings:
        if f.id in overrides:
            for attr, val in overrides[f.id].items():
                setattr(f, attr, val)
    return findings
```

- [ ] **Step 4: Wire `_apply_profile_overrides()` into `analyze()` before `_sort_findings()`**

In `analyze()`, replace:
```python
    return _sort_findings(findings)
```
With:
```python
    _apply_profile_overrides(findings, profile)
    return _sort_findings(findings)
```

- [ ] **Step 5: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all tests pass

- [ ] **Step 6: Final commit**

```bash
git add src/unifi_audit.py tests/test_analyze.py
git commit -m "feat: add profile-aware severity overrides (HIPAA, PCI, home)"
```
