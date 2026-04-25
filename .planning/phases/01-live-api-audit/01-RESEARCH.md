# Phase 1: Live API Audit - Research

**Researched:** 2026-04-25
**Domain:** UniFi Network Integration API v1 / Python audit pipeline / pytest
**Confidence:** MEDIUM (API field names not fully documentable without a live controller; all other areas HIGH)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** API-to-collections adapter approach. `analyze()` builds a parser-shaped dict from the API response and passes it to `findings_enhanced.py` modules **unmodified**. Adapter lives in `src/api_to_collections.py` (~50-100 LOC). `findings_enhanced.py` source is untouched.
- **D-02:** Two new `analyze()` passes after individual modules: `_correlate_findings(findings, profile) -> list[Finding]` and `_apply_float_top(findings) -> list[Finding]`.
- **D-03:** API-undetectable always-top findings (no MFA / default creds / WAN-reachable mgmt plane) become `status="unknown"` Findings with `intent_question` populated and `recommendation` pointing to the Phase 2 wizard.
- **D-04:** Compound correlation rules live in `src/findings_correlations.py`. One Python function per compound finding, returns `Finding | None`.
- **D-05:** `WEIGHTS` dict in `src/profile_weights.py`, keyed `(profile, section) -> multiplier`. Imported by `analyze()`.
- **D-06:** Manual profile only in Phase 1. `UNIFI_PROFILE` env var, default `home_office`. Report shows `"Profile: home_office (manual)"`.
- **D-07:** Manual real-network run captures fixtures; pytest suite targets highest-risk paths: `sanitize()`, `_extract_list()`, `_extract_sites()`, and a smoke test against the canonical fixture.
- **D-08:** Commit one anonymized canonical fixture to `samples/fixtures/api_dump_home_office.json`. User-supplied fixtures stay in `tests/fixtures/` (gitignored). Committed fixture must be sanitized + further anonymized (MAC, IP, hostname, serial, BSSID, site name) + < 200 KB.
- **D-09:** Extract `src/sanitizer.py` first (first task of Phase 1). Both `src/unifi_audit.py` and `src/parser.py` import from it.
- **D-10:** API-undetectable always-top findings render inline as regular Findings (not a separate "Limitations" section).

### Claude's Discretion

- Exact directory layout for `tests/` (e.g., `tests/unit/` vs flat `tests/`)
- Specific multipliers in the `WEIGHTS` dict (start with 1.0 baseline, lift cells where evidence supports)
- Adapter implementation style (function vs class — prefer what reads cleanly)
- Naming of the always-top constant list (e.g., `ALWAYS_TOP_FINDING_IDS`)
- Pytest configuration details (`pyproject.toml` vs `pytest.ini`)
- Whether to add a `--profile` CLI flag in addition to `UNIFI_PROFILE` env var

### Deferred Ideas (OUT OF SCOPE)

- Apply mode (Phase 6)
- Multi-site MSP aggregation (Phase 3)
- Backup-file mode work (Phase 4)
- Wizard / tier-aware rendering (Phase 2)
- Auto profile inference (Phase 2 wizard)
- Detection of MFA / default creds / WAN-reachable mgmt plane (Phase 2 questionnaire)
- CVE database integration (deferred; firmware finding ships with EOL list only)
- `UNIFI_USE_CLOUD=true` validation (Phase 3)
- Network request timeout configurable via env var (backlog)
- Schema-version response matrix full implementation (backlog)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-phase1-live-api-audit | End-to-end audit via Network Integration API with sanitized output | API shape research (Section: API Response Shapes), pipeline architecture |
| REQ-finding-module-segmentation | Flat-network detection (already wired; no Phase 1 work needed) | Existing pattern verified |
| REQ-finding-module-wifi | Security mode + PSK strength (already wired; no Phase 1 work needed) | Existing pattern verified |
| REQ-finding-module-firewall | Port forwards (already wired; no Phase 1 work needed) | Existing pattern verified |
| REQ-finding-module-remote-access | VPN protocol tiering (already wired; no Phase 1 work needed) | Existing pattern verified |
| REQ-finding-module-devices | SSH enablement (already wired; no Phase 1 work needed) | Existing pattern verified |
| REQ-finding-module-wireless-tuning | TX power, rogue AP, PMF, 2.4 GHz audit (implemented in `findings_enhanced.py`; needs wiring via adapter D-01) | Adapter key mapping table |
| REQ-finding-module-firewall-threats | Geo-IP, content filtering, safe-search (implemented; needs wiring) | Adapter key mapping table |
| REQ-finding-module-firmware | Auto-update toggle, EOL hardware, stale versions (implemented; needs wiring) | Adapter key mapping table |
| REQ-finding-module-logging | Privacy-aware retention by profile (implemented; needs wiring) | Adapter key mapping table; profile weight table |
| REQ-finding-module-backup | Destination diversity, tested-restore (implemented; needs wiring) | Adapter key mapping table |
| REQ-finding-module-api-coverage-meta | Meta-finding on endpoint failures (already wired) | Existing pattern verified |
| REQ-wire-enhanced-modules-into-audit-script | Wire 6 enhanced modules into `analyze()` via adapter | Adapter design (Section: Architecture Patterns) |
| REQ-cross-answer-tension-detection | Compound finding correlation pass | Correlation engine pattern (Section: Patterns) |
| REQ-profile-aware-scoring-weights | `WEIGHTS[(profile, section)]` table | Weight table recommendations (Section: Profile-Aware Scoring) |
| REQ-always-float-to-top-overrides | `_apply_float_top()` + 3 unknown Findings | Always-top pattern (Section: Architecture Patterns) |
| REQ-validation-real-network | Run against real UniFi network ≥ 9.3.43 | Environment availability; validation guide |
| REQ-validation-api-response-shapes | Diff actual shapes against assumed in `_extract_list` | API shape research; logging enhancement |
| REQ-validation-network-version-compat | Test ≥ 9.3.43 + graceful 404 handling | Existing 404-skip logic confirmed correct |
| REQ-validation-ssl-self-signed | Test SSL self-signed default for local mode | Existing `verify=False` default confirmed; unit-testable |
| REQ-validation-sanitization-coverage | Confirm sanitize() catches all secret fields in real responses | Sanitizer test surface; `hypothesis` pattern |
| REQ-test-fixtures | Anonymized API JSON dump committed; `tests/` directory | Fixture anonymization strategy; pytest layout |
</phase_requirements>

---

## Summary

Phase 1 finalization has five parallel workstreams: (1) sanitizer extraction to eliminate the DRY violation, (2) adapter construction to bridge API response shapes to the collection names `findings_enhanced.py` expects, (3) pipeline extension with the correlation pass and always-top override, (4) the profile-aware weight table, and (5) test infrastructure creation. These are ordered dependencies — sanitizer extraction must come first because the adapter and test suite both import from it.

The single highest-risk unknown is the exact field names returned by the UniFi Network Integration API v1 for endpoints beyond `/devices` and `/clients`. Community sources confirm the envelope structure (`{data: [...], offset, limit, totalCount}`) and that device-level fields use **camelCase** (`macAddress`, `ipAddress`, `model`, `state`). However, the classic-API field names used in `findings_enhanced.py` (e.g., `x_passphrase`, `radio_table`, `wpa_mode`, `ssh_enabled`) are from the **backup/classic API** shape, not the Integration v1 API shape. The adapter's primary job is exactly this mapping — and the canonical fixture from a real-network run will resolve the remaining unknowns.

The compound correlation engine, profile weight table, and pytest infrastructure are well-understood problems; the research below provides concrete starting values and patterns. Hypothesis property-testing is recommended as a dev-only dependency to prove the sanitizer never leaks raw secrets, at the cost of one additional dependency in `requirements-dev.txt`.

**Primary recommendation:** Build in this task order — sanitizer.py → adapter + fixture capture → tests → correlations + float-top → weights. Each step unblocks the next.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Credential loading | Local script / process boundary | — | API key must never leave user machine; env-var only |
| API data collection | Local script (collection layer) | UniFi controller (read-only) | One-way GET; no write endpoints |
| Sanitization | Local script (sanitization layer) | — | Happens before any data touches disk or analysis |
| Enhanced module execution | Local script (analysis layer) | — | Pure functions on sanitized dict |
| API-to-collections mapping | Local script (adapter module) | — | Translation layer only; no I/O |
| Compound correlation | Local script (analysis layer) | — | Pure Python rules on list[Finding] |
| Profile-aware scoring | Local script (analysis layer) | — | WEIGHTS dict + ranking formula |
| Always-top override | Local script (analysis layer) | — | Post-sort reorder pass |
| Report rendering | Local script (reporting layer) | — | Serializes sanitized findings only |
| Test fixtures | Development artifacts | — | Committed JSON only after anonymization pass |

---

## Standard Stack

### Core (Runtime)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Python | 3.9+ | Language (3.14.2 on this machine) | Locked by `C-code-001`; `from __future__ import annotations` already in all files |
| requests | 2.33.1 | HTTP client for UniFi API | `[VERIFIED: pip install]` Already in use in `unifi_audit.py` |
| hashlib | stdlib | SHA256 fingerprinting in `_fingerprint()` | No new dep; already used |
| dataclasses | stdlib | `Finding` dataclass schema | Already in use; schema locked `C-finding-001` |

### Dev-Only (Testing)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| pytest | 9.0.3 | Test runner | `[VERIFIED: pip install]` On machine already; primary test surface |
| pytest-cov | latest (≥5.0) | Coverage measurement | Add to `requirements-dev.txt`; not on machine yet |
| hypothesis | 6.x (latest stable) | Property-based testing for sanitizer | Dev-only; proves no raw secret survives; add to `requirements-dev.txt` |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| hypothesis | Manual parametrize edge cases | Manual tests miss the cases we don't think of; hypothesis finds them automatically. Worth adding as dev-only dep |
| pytest | unittest | pytest provides cleaner fixtures, parametrize, and conftest.py sharing — well worth it for this project |
| `samples/fixtures/` for canonical fixture | `tests/fixtures/` (gitignored) | Canonical fixture goes in `samples/fixtures/` (committed); user-captured fixtures go in `tests/fixtures/` (gitignored) per D-08 |

**Dev installation:**
```bash
pip install pytest pytest-cov hypothesis
# Or add to requirements-dev.txt:
# pytest>=9.0
# pytest-cov>=5.0
# hypothesis>=6.0
```

**Version verification:** `[VERIFIED: pip]` pytest 9.0.3 installed on machine. requests 2.33.1. hypothesis and pytest-cov need installation.

---

## API Response Shapes

### Confirmed Structure (HIGH confidence)

The UniFi Network Integration API v1 (`/proxy/network/integration/v1/`) uses a **paginated envelope** for list endpoints:

```json
{
  "data": [...],
  "offset": 0,
  "limit": 100,
  "count": 25,
  "totalCount": 25
}
```

**Sources:**
- `[CITED: github.com/tmcpro/unifi-network-api]` — "v1 Responses: Include pagination metadata (offset, limit, count, totalCount)"
- `[CITED: github.com/runZeroInc/runzero-custom-integrations]` — Code uses `response_json.get("data", [])` before iterating

**Critical implication for `_extract_list()`:** The current code already checks `data` as the first key — this is correct. The `offset`, `limit`, `totalCount` fields are pagination metadata, not data. For Phase 1 (single-site, modest device counts), pagination is unlikely to be hit, but the code should log a warning if `count < totalCount`.

### Device Object Fields (camelCase, HIGH confidence)

The Integration v1 API returns device objects with **camelCase** field names, unlike the classic API which uses snake_case:

```json
{
  "id": "...",
  "macAddress": "aa:bb:cc:dd:ee:ff",
  "ipAddress": "192.168.1.2",
  "name": "Living Room AP",
  "model": "U6-Pro",
  "state": "connected",
  "features": [...],
  "interfaces": [...]
}
```

`[CITED: github.com/runZeroInc/runzero-custom-integrations]` — Confirmed camelCase field names for the Integration v1 API.

**Critical implication:** `findings_enhanced.py` currently reads classic/backup-style snake_case fields from `parser.py` collection shapes (e.g., `d.get("ssh_enabled")`, `d.get("radio_table")`). The adapter (`api_to_collections.py`) must map:

| Integration v1 API (camelCase) | Parser/classic shape (snake_case) |
|--------------------------------|-----------------------------------|
| `macAddress` | `mac` |
| `ipAddress` | `ip` |
| `model` | `model` (same) |
| `name` | `name` (same) |
| `state` | `state` |
| SSH feature flag (unknown key) | `ssh_enabled` |
| Radio table (unknown structure) | `radio_table` |

**The adapter must be validated against a real API response.** The SSH and radio_table field names in the Integration v1 API are `[ASSUMED]` to be under `features` or a device-detail sub-resource — they may not be available at the list endpoint at all.

### WLAN, Network, Firewall, VPN Field Names (LOW confidence)

Ubiquiti's official Integration API documentation is not publicly accessible without a controller to navigate to `Settings > Control Plane > Integrations`. Community sources confirm these endpoints exist but do not document the field-level schemas:

- `/sites/{id}/wlans` — security mode, PSK, SSID name fields are `[ASSUMED]` to be different from classic `wlanconf` shape (`security`, `wpa_mode`, `x_passphrase`)
- `/sites/{id}/networks` — purpose field, VLAN ID are `[ASSUMED]` to map to classic `networkconf` shape
- `/sites/{id}/firewall-policies` — geo-IP, firewall rule fields are `[ASSUMED]`
- `/sites/{id}/vpn-configs` — VPN protocol type, enabled flag are `[ASSUMED]`
- `/sites/{id}/port-forwards` — enabled flag, protocol fields are `[ASSUMED]`

**Action required:** The canonical fixture capture (real-network run) is the only reliable way to discover these shapes. The adapter's `_COLLECTION_MAP` dict will contain LOW-confidence mappings until fixture verification.

### `_extract_list()` Enhancement Needed (MEDIUM confidence)

Current behavior: silently returns `None` when no key matches. Required behavior per CONCERNS.md Concern 5: log a warning with the actual response structure when no fallback matches.

```python
# Current (fragile):
return None

# Target (REQ-validation-api-response-shapes):
logger.warning(f"_extract_list: no matching key in response. Keys present: {list(data.keys())}")
return None
```

This enhancement is the mechanism that makes the canonical fixture useful — the warning output becomes the map of "what shape does this endpoint actually return?"

---

## Architecture Patterns

### System Architecture Diagram

```
[User env vars: UNIFI_API_KEY, UNIFI_HOST, UNIFI_PROFILE]
        |
        v
load_config() ──────────────────────────────────────────────
        |                                                   |
        v                                                   v
UniFiClient (session + X-API-KEY header)         profile string
        |
        v
collect_all()
  for each site endpoint (devices, wlans, networks, ...):
    GET /proxy/network/integration/v1/sites/{id}/{resource}
    response → {data: [...], offset, limit, totalCount}
        |
        v
raw dict {site_<id>: {devices: [...], wlans: [...], ...}, ...}
        |
        v
sanitize()  ◄── src/sanitizer.py (D-09)
  walk dict recursively
  SECRET_FIELD_NAMES match → _fingerprint()
  else → pass through
        |
        v
clean dict (PSKs, secrets → fingerprints)
        |
        ├── raw_sanitized.json (written to disk)
        |
        v
analyze(clean, profile, logger)
  |
  ├── build_parser_collections(clean) ◄── src/api_to_collections.py (D-01)
  |       Maps API camelCase keys → classic snake_case collection names
  |       Returns {device: [...], wlanconf: [...], networkconf: [...], ...}
  |
  ├── [existing modules] _find_segmentation, _find_wifi, _find_firewall,
  |                      _find_remote_access, _find_devices, _find_api_coverage
  |                      (consume clean dict directly — no adapter needed)
  |
  ├── [enhanced modules] find_wireless_tuning, find_firewall_threats,
  |                      find_remote_access (enhanced), find_firmware,
  |                      find_logging, find_backup_config
  |                      (consume parser-shaped colls dict via adapter)
  |
  ├── emit 3 unknown Findings (MFA, default creds, WAN mgmt plane)
  |
  ├── _correlate_findings(findings, profile) ◄── src/findings_correlations.py (D-04)
  |       priority mismatch, keys-to-kingdom, pivot path
  |
  └── _apply_float_top(findings) ◄── ALWAYS_TOP_FINDING_IDS constant
          PPTP/VPN, flat-network, EOL-firmware → top regardless of score
          3 unknown Findings → also floated to top
        |
        v
findings: list[Finding]  sorted by (always_top, severity×weight/effort)
        |
        ├── findings.json
        └── report.md  ◄── render_report() (unknown Findings render inline)
```

### Recommended Project Structure (new files in bold)

```
src/
  unifi_audit.py          # modified: import sanitizer; extend analyze()
  findings_enhanced.py    # untouched (D-01)
  parser.py               # modified: import sanitizer only
  sanitizer.py            # NEW: extracted shared module (D-09)
  api_to_collections.py   # NEW: adapter API→collections (D-01)
  findings_correlations.py # NEW: compound rules (D-04)
  profile_weights.py      # NEW: WEIGHTS dict (D-05)
  inspect_backup.py       # untouched

tests/
  conftest.py             # NEW: fixture loaders, shared helpers
  test_sanitizer.py       # NEW: 100% coverage of sanitize() + _fingerprint()
  test_extract_helpers.py # NEW: _extract_list / _extract_sites variants
  test_pipeline_smoke.py  # NEW: full pipeline against canonical fixture
  fixtures/               # gitignored - user-captured real API dumps
    .gitignore

samples/
  fixtures/
    api_dump_home_office.json  # NEW: committed canonical fixture (D-08)
  sample-report.md        # existing
  sample-gap-questions.md # existing

pyproject.toml            # NEW: [tool.pytest.ini_options] config
```

### Pattern 1: Sanitizer Extraction (D-09)

Extract and consolidate the two diverging `sanitize()` implementations into a single module. The `parser.py` version has an extra `redact_pii` flag — preserve it in the canonical implementation.

```python
# src/sanitizer.py
"""
Shared sanitization module. Imported by unifi_audit.py and parser.py.
Provides SECRET_FIELD_NAMES, _fingerprint(), sanitize().
"""
from __future__ import annotations
import hashlib
from typing import Any

# Union of both existing SECRET_FIELD_NAMES sets — parser.py had 12, unifi_audit.py had 20.
# Source: [VERIFIED: codebase grep unifi_audit.py:183-188, parser.py:103-116]
SECRET_FIELD_NAMES: frozenset[str] = frozenset({
    "x_passphrase", "x_passphrase_rollover", "x_radius_secret", "x_shared_secret",
    "x_ssh_password", "x_iapp_key", "password", "x_auth_key", "auth_key",
    "private_key", "api_key", "token", "passphrase", "preSharedKey", "presharedKey",
    "psk", "pre_shared_key", "privateKey", "wpa_psk",
})

def _fingerprint(value: Any) -> dict[str, Any]:
    """Non-reversible fingerprint for a secret value."""
    if not isinstance(value, str):
        return {"type": type(value).__name__, "redacted": True}
    return {
        "length": len(value),
        "fingerprint": hashlib.sha256(value.encode()).hexdigest()[:12],
        "has_symbols": any(not c.isalnum() for c in value),
        "has_digits": any(c.isdigit() for c in value),
        "has_mixed_case": (
            any(c.isupper() for c in value) and any(c.islower() for c in value)
        ),
    }

def sanitize(obj: Any, redact_pii: bool = False) -> Any:
    """Recursively sanitize. Always redacts secrets; optionally redacts PII hostnames/names."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in SECRET_FIELD_NAMES:
                out[k] = _fingerprint(v) if isinstance(v, str) else {"redacted": True}
            elif redact_pii and k in {"hostname", "note", "name"} and isinstance(v, str):
                out[k] = f"<redacted:{len(v)} chars>"
            else:
                out[k] = sanitize(v, redact_pii)
        return out
    if isinstance(obj, list):
        return [sanitize(i, redact_pii) for i in obj]
    return obj
```

**Replacement in `unifi_audit.py`:** Remove `SECRET_FIELD_NAMES`, `_fingerprint`, `sanitize` definitions; add `from sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize`.
**Replacement in `parser.py`:** Same import. Remove local definitions.

### Pattern 2: API-to-Collections Adapter (D-01)

The adapter's single responsibility: translate the Integration v1 API response shape (camelCase, paginated) into the parser-shape dict (snake_case, collection-keyed) that `findings_enhanced.py` expects.

```python
# src/api_to_collections.py
"""
Translate Integration v1 API responses into parser-shaped collection dicts.
This is the only place that knows about both shapes. findings_enhanced.py
modules receive the output of this module and require no modification.
"""
from __future__ import annotations
from typing import Any


def _unwrap(response: Any) -> list[dict]:
    """Extract the list from {data: [...]} envelope or bare list."""
    if isinstance(response, dict):
        return response.get("data", [])
    if isinstance(response, list):
        return response
    return []


def _device_to_classic(d: dict) -> dict:
    """Map an Integration v1 device object to classic collection shape."""
    # Integration v1 uses camelCase; classic uses snake_case.
    # [VERIFIED: github.com/runZeroInc/runzero-custom-integrations - camelCase confirmed]
    # [ASSUMED: ssh_enabled, radio_table fields - not confirmed from live API; must be
    #  validated against canonical fixture]
    out = {
        "mac": d.get("macAddress", d.get("mac", "")),
        "ip": d.get("ipAddress", d.get("ip", "")),
        "model": d.get("model", ""),
        "name": d.get("name", ""),
        "type": d.get("type", ""),
        "state": d.get("state", ""),
        # Features array may contain SSH state — check during fixture validation
        "ssh_enabled": _extract_ssh_state(d),
        # radio_table may be nested; check during fixture validation
        "radio_table": d.get("radioTable", d.get("radio_table", [])),
        "version": d.get("version", d.get("firmwareVersion", "")),
    }
    # Preserve all other fields for inspection
    out.update({k: v for k, v in d.items() if k not in out})
    return out


def _extract_ssh_state(device: dict) -> bool:
    """Extract SSH enabled state from Integration v1 device object.
    [ASSUMED: field path - validate against real fixture.]"""
    # Classic API: d.get("ssh_enabled")
    # Integration v1: may be in features[], config, or a top-level bool field
    if "sshEnabled" in device:
        return bool(device["sshEnabled"])
    if "ssh_enabled" in device:
        return bool(device["ssh_enabled"])
    # Check features array for SSH capability flag
    for feat in device.get("features", []):
        if isinstance(feat, dict) and feat.get("name") == "ssh":
            return bool(feat.get("enabled", False))
    return False


def _wlan_to_classic(w: dict) -> dict:
    """Map Integration v1 WLAN object to classic wlanconf shape.
    [ASSUMED: field mapping - validate against real fixture.]"""
    return {
        "name": w.get("name", ""),
        "enabled": w.get("enabled", True),
        # Classic uses 'security' + 'wpa_mode'; Integration v1 may differ
        "security": w.get("security", w.get("securityProtocol", "")),
        "wpa_mode": w.get("wpaMode", w.get("wpa_mode", "")),
        # PSK is a secret field — sanitizer will have fingerprinted it already
        "x_passphrase": w.get("x_passphrase", w.get("preSharedKey", w.get("psk", {}))),
        "pmf_mode": w.get("pmfMode", w.get("pmf_mode", "disabled")),
        **{k: v for k, v in w.items()},
    }


def _network_to_classic(n: dict) -> dict:
    """Map Integration v1 network object to classic networkconf shape.
    [ASSUMED: field mapping - validate against real fixture.]"""
    return {
        "name": n.get("name", ""),
        "purpose": n.get("purpose", n.get("type", "")),
        "vlan": n.get("vlanId", n.get("vlan", None)),
        **{k: v for k, v in n.items()},
    }


def build_parser_collections(clean: dict) -> dict:
    """Build a parser-shaped dict from the sanitized API response.

    Produces a dict keyed by classic collection names so findings_enhanced.py
    modules can be called without modification.

    Args:
        clean: sanitized API response from collect_all() → sanitize()

    Returns:
        dict with keys: device, wlanconf, networkconf, portforward,
        firewallrule, firewallgroup, setting (sub-keyed)
    """
    devices: list[dict] = []
    wlans: list[dict] = []
    networks: list[dict] = []
    port_forwards: list[dict] = []
    firewall_policies: list[dict] = []
    vpn_configs: list[dict] = []
    settings: dict[str, Any] = {}

    for key, val in clean.items():
        if not key.startswith("site_") or not isinstance(val, dict):
            continue
        devices.extend(_device_to_classic(d) for d in _unwrap(val.get("devices")))
        wlans.extend(_wlan_to_classic(w) for w in _unwrap(val.get("wlans")))
        networks.extend(_network_to_classic(n) for n in _unwrap(val.get("networks")))
        port_forwards.extend(_unwrap(val.get("port_forwards")))
        firewall_policies.extend(_unwrap(val.get("firewall_policies")))
        vpn_configs.extend(_unwrap(val.get("vpn_configs")))

    # findings_enhanced.py uses _get_setting(colls, "key") to retrieve settings.
    # Populate what we can from the API; remaining keys will return empty dicts.
    # [ASSUMED: settings field paths - validate against real fixture]
    return {
        "device": devices,
        "wlanconf": wlans,
        "networkconf": networks,
        "portforward": port_forwards,
        "firewallrule": firewall_policies,
        "firewallgroup": [],   # May not be exposed by Integration v1 API
        "vpn_pptp": {},        # [ASSUMED: check vpn_configs for protocol type]
        "vpn_l2tp": {},        # [ASSUMED]
        "vpn_wireguard": {},   # [ASSUMED]
        "auto_update": {},     # [ASSUMED: may not be in Integration v1 API]
        "auto_backup": {},     # [ASSUMED: may not be in Integration v1 API]
        "mgmt": {},            # [ASSUMED: may not be in Integration v1 API]
        "dpi": {},             # [ASSUMED: may not be in Integration v1 API]
        "rogueap": {},         # [ASSUMED: may not be in Integration v1 API]
        "dns_filtering": {},   # [ASSUMED: may not be in Integration v1 API]
        "_vpn_configs_raw": vpn_configs,  # Preserved for adapter refinement
    }
```

**Critical note:** Several setting-level fields (`auto_update`, `auto_backup`, `mgmt`, `dpi`, `rogueap`, `dns_filtering`) may not be exposed by the Integration v1 API at all. The affected enhanced modules (`find_firmware`, `find_backup_config`, `find_logging`, `find_wireless_tuning`, `find_firewall_threats`) will return empty findings for those checks until the fixture validation reveals whether these paths exist. This is acceptable per D-03's `status="unknown"` philosophy — but it means the test smoke check must explicitly test for "not empty" only on the paths we know fire.

### Pattern 3: `_correlate_findings()` — Compound Rules (D-04)

One function per compound finding; returns `Finding | None`. Consistent with `findings_enhanced.py` style.

```python
# src/findings_correlations.py
"""
Compound finding rules. Run after individual modules.
Each function takes (findings: list[Finding], profile: str) and returns Finding | None.
Source: D-003 (LOCKED); decision log .planning/intel/decisions.md
"""
from __future__ import annotations
from typing import Any


def _has_finding_id(findings: list, prefix: str) -> bool:
    """Check if any finding with given ID prefix exists."""
    return any(f.id.startswith(prefix) for f in findings)


def _get_finding(findings: list, prefix: str):
    """Return first finding whose ID starts with prefix, or None."""
    return next((f for f in findings if f.id.startswith(prefix)), None)


def correlate_priority_mismatch(findings: list, profile: str):
    """Compound: high downtime-sensitivity + no redundancy signalled by port-forwards."""
    # Fires if: no VPN configured (VPN-MISSING-*) and port-forwards exist (FW-*-PF)
    # [ASSUMED: additional questionnaire data about downtime-sensitivity not available
    #  from API alone — Phase 1 emits a conservative version]
    has_pf = _has_finding_id(findings, "FW-") and _has_finding_id(findings, "VPN-MISSING")
    if not has_pf:
        return None
    from unifi_audit import Finding
    return Finding(
        id="CORR-PRIORITY-001",
        section="Risk correlation",
        severity="high",
        status="recommendation",
        title="Port-forwards without VPN suggest exposure-as-remote-access path",
        current_state=(
            "Port forwards are active and no VPN is configured. If any forward is for "
            "your own remote access (not a public service), this exposes services "
            "unnecessarily. Combined with high network availability needs, this is a "
            "compounded risk."
        ),
        recommendation=(
            "Set up WireGuard VPN and replace remote-access port forwards. "
            "Reserve port forwards for services that must be publicly accessible."
        ),
        intent_question="Are port forwards for your own remote access, or for public-facing services?",
        maps_to={"cis_v8": "4.4", "nist_csf": "PR.AC-3"},
        effort="medium",
        impact="high",
    )


def correlate_keys_to_kingdom(findings: list, profile: str):
    """Compound: mobile remote management (port-forwards) + MFA unknown."""
    mfa_unknown = _has_finding_id(findings, "MFA-")
    remote_exposed = _has_finding_id(findings, "VPN-MISSING") or _has_finding_id(findings, "FW-")
    if not (mfa_unknown and remote_exposed):
        return None
    from unifi_audit import Finding
    return Finding(
        id="CORR-KEYS-001",
        section="Risk correlation",
        severity="critical",
        status="unknown",
        title="Remote access exposed + MFA status unknown = keys-to-kingdom risk",
        current_state=(
            "Services are reachable from the internet and admin MFA status cannot be "
            "confirmed from the API. If admin accounts lack MFA, an attacker who "
            "reaches a management interface has a path to full network control."
        ),
        recommendation=(
            "1. Confirm MFA is enabled on all admin accounts (see Ubiquiti account settings). "
            "2. If admin UIs are reachable from WAN, restrict to VPN-only. "
            "3. Enable MFA now if not already configured."
        ),
        intent_question="Is MFA enabled on all accounts with admin access to this network?",
        maps_to={"cis_v8": "6.3", "nist_csf": "PR.AC-7"},
        effort="quick",
        impact="high",
    )


def correlate_pivot_path(findings: list, profile: str):
    """Compound: flat network + IoT / NAS devices present = pivot risk."""
    flat_net = _has_finding_id(findings, "SEG-001")
    if not flat_net:
        return None
    from unifi_audit import Finding
    return Finding(
        id="CORR-PIVOT-001",
        section="Risk correlation",
        severity="high",
        status="unknown",
        title="Flat network with likely mixed device classes — pivot path risk",
        current_state=(
            "The network has no VLAN segmentation. If NAS devices, IoT devices, or "
            "work machines share the same broadcast domain, a compromised IoT device "
            "can reach your data directly."
        ),
        recommendation=(
            "Segment IoT, NAS/file-share, and work devices into separate VLANs with "
            "Zone-Based Firewall rules. IoT VLAN should not be able to reach NAS VLAN."
        ),
        intent_question="Do IoT devices (cameras, smart home) share the same network as your NAS or work computers?",
        maps_to={"cis_v8": "12.2", "nist_csf": "PR.AC-5"},
        effort="project",
        impact="high",
    )


# Registry: add new compound rules here
CORRELATION_RULES = [
    correlate_priority_mismatch,
    correlate_keys_to_kingdom,
    correlate_pivot_path,
]
```

### Pattern 4: `_apply_float_top()` — Always-Top Override (D-02)

```python
# In unifi_audit.py (or a sibling constant module)
ALWAYS_TOP_FINDING_IDS = frozenset({
    # API-detectable (wired or being wired):
    "VPN-PPTP-001",        # PPTP critical
    "SEG-001",             # Flat network (flat + mixed device classes)
    "FW-EOL-001",          # Firmware EOL (>2 majors behind with advisories)
    # API-undetectable (emit as unknown Finding, still floated to top):
    "MFA-UNKNOWN-001",     # No MFA detectable from API
    "CRED-DEFAULT-001",    # Default creds not detectable from API
    "WAN-MGMT-001",        # Management plane WAN reachability unknown
})

def _apply_float_top(findings: list[Finding]) -> list[Finding]:
    """Re-sort so always-top findings appear first regardless of score."""
    top = [f for f in findings if any(f.id.startswith(tid) for tid in ALWAYS_TOP_FINDING_IDS)]
    rest = [f for f in findings if f not in top]
    return top + rest
```

**Three `unknown` Findings to emit** (in `analyze()` before correlation pass):

```python
def _emit_unknown_always_top() -> list[Finding]:
    """Emit 3 always-top Findings for API-undetectable risks."""
    return [
        Finding(
            id="MFA-UNKNOWN-001",
            section="Admin",
            severity="high",
            status="unknown",
            title="Admin account MFA status cannot be determined from API",
            current_state="Cannot be determined via Network Integration API alone.",
            recommendation="Verify in Ubiquiti account settings that MFA is enabled on all admin accounts.",
            intent_question="Is MFA enabled on all accounts with admin access to this controller?",
            maps_to={"cis_v8": "6.3", "nist_csf": "PR.AC-7"},
            effort="quick",
            impact="high",
        ),
        Finding(
            id="CRED-DEFAULT-001",
            section="Admin",
            severity="high",
            status="unknown",
            title="Default credential state cannot be verified from API",
            current_state="Cannot be determined via Network Integration API alone.",
            recommendation="Verify that no device uses factory-default credentials.",
            intent_question="Have you changed factory-default credentials on all UniFi devices and the controller?",
            maps_to={"cis_v8": "5.2"},
            effort="quick",
            impact="high",
        ),
        Finding(
            id="WAN-MGMT-001",
            section="Admin",
            severity="high",
            status="unknown",
            title="Management plane WAN reachability cannot be determined from API",
            current_state="Cannot be determined via Network Integration API alone.",
            recommendation="Confirm the UniFi controller UI is not accessible from the internet.",
            intent_question="Is the UniFi controller management interface reachable from the public internet?",
            maps_to={"cis_v8": "4.8", "nist_csf": "PR.AC-5"},
            effort="medium",
            impact="high",
        ),
    ]
```

### Pattern 5: Profile-Aware Weight Table (D-05)

```python
# src/profile_weights.py
"""
Profile-aware scoring weights. Keyed (profile, section) -> float multiplier.
1.0 = neutral (no change). >1.0 = amplify. <1.0 = suppress.

Rationale for each non-1.0 value documented inline.
"""
from __future__ import annotations

# Sections align with QUESTIONNAIRE.md C-questionnaire-003 section structure.
# [CITED: .planning/PROJECT.md § Constraints C-questionnaire-003]
WEIGHTS: dict[tuple[str, str], float] = {
    # --- home profile: suppress enterprise-only recommendations ---
    ("home", "Logging"):          0.4,  # Long retention = overkill for home
    ("home", "Backup"):           0.7,  # Backup still matters, just less urgently
    ("home", "Firmware"):         1.0,  # Always important
    ("home", "Segmentation"):     1.2,  # IoT risk is high even at home
    ("home", "Wireless tuning"):  0.8,  # RF tuning less critical at home
    ("home", "Firewall"):         1.0,
    ("home", "Remote access"):    1.0,
    ("home", "Admin"):            1.0,
    ("home", "Wi-Fi"):            1.0,
    ("home", "Risk correlation"): 1.0,

    # --- home_office: baseline ---
    ("home_office", "Logging"):   0.7,  # Some retention recommended; not enterprise-grade
    ("home_office", "Backup"):    1.0,
    ("home_office", "Firmware"):  1.0,
    ("home_office", "Segmentation"): 1.2,
    ("home_office", "Wireless tuning"): 1.0,
    ("home_office", "Firewall"):  1.0,
    ("home_office", "Remote access"): 1.2,  # WFH = higher remote access risk
    ("home_office", "Admin"):     1.0,
    ("home_office", "Wi-Fi"):     1.0,
    ("home_office", "Risk correlation"): 1.0,

    # --- small_business: raise operational sections ---
    ("small_business", "Logging"):   1.2,
    ("small_business", "Backup"):    1.3,
    ("small_business", "Firmware"):  1.2,
    ("small_business", "Segmentation"): 1.5,
    ("small_business", "Wireless tuning"): 1.0,
    ("small_business", "Firewall"):  1.3,
    ("small_business", "Remote access"): 1.3,
    ("small_business", "Admin"):     1.3,
    ("small_business", "Wi-Fi"):     1.0,
    ("small_business", "Risk correlation"): 1.2,

    # --- regulated_hipaa: raise logging heavily (6-year retention); raise admin ---
    ("regulated_hipaa", "Logging"):      2.0,  # 6-year retention; not surfacing this is negligent
    ("regulated_hipaa", "Backup"):       1.8,
    ("regulated_hipaa", "Firmware"):     1.5,
    ("regulated_hipaa", "Segmentation"): 2.0,  # PHI isolation is a HIPAA requirement
    ("regulated_hipaa", "Wireless tuning"): 1.2,
    ("regulated_hipaa", "Firewall"):     1.8,
    ("regulated_hipaa", "Remote access"): 1.8,
    ("regulated_hipaa", "Admin"):        2.0,  # MFA, access control = HIPAA critical
    ("regulated_hipaa", "Wi-Fi"):        1.2,
    ("regulated_hipaa", "Risk correlation"): 1.5,

    # --- regulated_pci: raise all; extreme for firewall + segmentation ---
    ("regulated_pci", "Logging"):        1.8,  # 12-month retention (PCI DSS Req 10)
    ("regulated_pci", "Backup"):         1.8,
    ("regulated_pci", "Firmware"):       1.8,
    ("regulated_pci", "Segmentation"):   2.5,  # CDE isolation is PCI DSS cornerstone
    ("regulated_pci", "Wireless tuning"): 1.5,
    ("regulated_pci", "Firewall"):       2.5,  # PCI DSS Req 1 - firewall configuration
    ("regulated_pci", "Remote access"):  2.0,  # Req 8 - strong auth required
    ("regulated_pci", "Admin"):          2.5,  # Req 8 - unique IDs, MFA
    ("regulated_pci", "Wi-Fi"):          2.0,  # PCI DSS Req 4 - wireless security
    ("regulated_pci", "Risk correlation"): 2.0,
}

DEFAULT_WEIGHT = 1.0


def get_weight(profile: str, section: str) -> float:
    """Return the scoring weight for a (profile, section) pair."""
    return WEIGHTS.get((profile, section), DEFAULT_WEIGHT)
```

**Ranking formula** (to replace bare sort in `analyze()`):

```python
IMPACT_SCORES = {"high": 3, "medium": 2, "low": 1}
EFFORT_HOURS  = {"quick": 2, "medium": 8, "project": 40}

def _score(f: Finding, profile: str) -> float:
    impact = IMPACT_SCORES.get(f.impact, 1)
    effort = EFFORT_HOURS.get(f.effort, 8)
    weight = get_weight(profile, f.section)
    return (impact * weight) / effort
```

### Anti-Patterns to Avoid

- **Modifying `findings_enhanced.py`:** D-01 explicitly prohibits this. Any data shape translation belongs in the adapter only.
- **Importing `parser.Finding` from `findings_enhanced.py`:** The enhanced modules currently do `from parser import Finding`. After D-09, `parser.py`'s `Finding` class and `unifi_audit.py`'s `Finding` class are still separate dataclasses with identical fields. Phase 1 does NOT merge these — the adapter feeds `findings_enhanced.py` which uses `parser.Finding`. The adapter output feeds back into the `analyze()` findings list which uses `unifi_audit.Finding`. The planner must be careful that both `Finding` classes remain schema-compatible (`asdict()` output is the same shape). A cleaner fix (single `Finding` import from `sanitizer.py` or a `models.py`) is a future refactor.
- **Writing real API keys to any test fixture:** Tests must use synthetic keys (`X-API-KEY: test-only-not-real`).
- **Silent empty returns from `_extract_list()`:** Add warning logging when no key matches.
- **Assuming all enhanced modules fire on the canonical fixture:** Some modules check `_get_setting()` paths that may not exist in Integration v1 API responses. Tests must check "non-empty findings" only for paths we have evidence for.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SHA256 fingerprinting | Custom hash | `hashlib.sha256` (stdlib) | Already in use; cryptographically sound |
| Property-based sanitizer tests | Manual edge case lists | `hypothesis` | Finds cases you miss; handles arbitrary nesting |
| Test fixture loading | Custom loader | `pytest` conftest.py + `json.loads(Path.read_text())` | Standard pattern; no extra dep |
| Rules engine for compound findings | YAML DSL, external engine | Pure Python functions (D-04) | Simpler; testable; maintainable without new format |
| Profile weight system | ML model, inference engine | Dict lookup (D-05) | Auditable; type-checkable; no inference risk |
| HTTP mocking | Custom stub server | `monkeypatch` on `requests.Session.get` | Stdlib + pytest; no extra dep |

**Key insight:** For a security tool with a strict minimalism constraint (`C-code-001`), every new runtime dependency is a supply-chain risk. Hypothesis is acceptable as dev-only because it never ships with the tool.

---

## Fixture Anonymization Strategy (D-08)

The canonical fixture (`samples/fixtures/api_dump_home_office.json`) must be safe to commit. The sanitizer handles secrets; additional anonymization is needed for PII and identifying data.

### Fields Requiring Anonymization (beyond standard sanitizer)

| Field Category | Example Value | Replacement Strategy |
|----------------|--------------|----------------------|
| MAC addresses | `aa:bb:cc:dd:ee:ff` | Deterministic hash → `02:xx:xx:xx:xx:xx` (locally administered bit set = clearly fake). Use `hashlib.sha256(mac.encode()).hexdigest()[:10]` to seed |
| IP addresses | `192.168.1.100` | RFC 5737 documentation ranges: `192.0.2.x`, `198.51.100.x`, `203.0.113.x` |
| Hostnames | `johns-macbook.local` | Replace with `device-{n}.local` where n is a deterministic counter |
| Device names | `Living Room AP` | Replace with `ap-{n}`, `switch-{n}`, `gateway-{n}` |
| Site names | `My Home Network` | Replace with `test-site-home-office` |
| Serial numbers | `FXXXXXXXXXX` | Replace with `SIM-{index:05d}` |
| BSSIDs | Same as MAC above | Same deterministic approach |
| Client MAC addresses | `bb:cc:dd:ee:ff:00` | Same deterministic approach |

### Recommended Anonymization Script

```python
# tools/anonymize_fixture.py (not committed; run once then discard)
import json, hashlib, re
from pathlib import Path

def anon_mac(mac: str) -> str:
    """Deterministic fake MAC in locally-administered range."""
    h = hashlib.sha256(mac.encode()).hexdigest()
    octets = [h[i:i+2] for i in range(0, 10, 2)]
    # Set locally administered bit on first octet
    first = (int(octets[0], 16) | 0x02) & 0xFE
    return f"{first:02x}:{':'.join(octets[1:])}"

def anon_ip(ip: str) -> str:
    """Replace with RFC 5737 documentation range."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"192.0.2.{parts[-1]}"
    return ip

# Apply recursively to the raw_sanitized.json fixture
```

---

## Common Pitfalls

### Pitfall 1: Integration v1 API Does Not Expose All Classic API Fields

**What goes wrong:** The adapter maps `wlanconf.x_passphrase` but the Integration v1 API may not return the PSK field at all (only the fingerprint, if the sanitizer ran — or empty if the API doesn't expose it). Same for `radio_table`, settings-level fields (`auto_update`, `mgmt`, `rogueap`, etc.).

**Why it happens:** The Integration v1 API is a curated subset of the classic `/api/s/{site}/` API. It is designed for third-party integrations and intentionally omits some internal fields.

**How to avoid:** The adapter must default all missing fields to empty/neutral values (`{}`, `[]`, `False`). Enhanced modules that check `_get_setting()` will get empty dicts and simply produce no findings for those checks — which is correct behavior (return `[]`, not an exception).

**Warning signs:** Module produces zero findings for a section that should always have findings (e.g., `find_firmware` returns empty even when we know there are devices). Check if the adapter is returning empty for that collection.

### Pitfall 2: `findings_enhanced.py` Imports `from parser import Finding`

**What goes wrong:** When `findings_enhanced.py` is called from `analyze()` in `unifi_audit.py`, the `from parser import Finding` inside each function runs — importing `parser.py`'s `Finding` dataclass. Both `Finding` dataclasses have identical field definitions, so `asdict()` produces identical output. But they are separate types; `isinstance(f, unifi_audit.Finding)` will be `False` for enhanced findings.

**Why it happens:** Phase 1's D-01 decision is "don't modify `findings_enhanced.py`" — so we can't change the import.

**How to avoid:** In `analyze()`, treat the list as `list[Any]` when extending; the `render_report()` and `asdict()` calls are duck-typed. Add a comment documenting this is intentional technical debt resolved in a future shared-models refactor.

**Warning signs:** `isinstance` checks on findings produce unexpected `False`. Use duck-typing (check `hasattr(f, 'severity')`) rather than `isinstance` if needed.

### Pitfall 3: Pagination Truncation on Large Controllers

**What goes wrong:** The API returns the first 100 devices (or whatever the default `limit` is), but `totalCount` is 150. The audit misses 50 devices silently.

**Why it happens:** `collect_all()` makes one GET per endpoint and stores the response. No pagination loop exists.

**How to avoid:** Add pagination handling in `collect_all()` for the `totalCount > count` case. For Phase 1 (home/home_office scale), this is unlikely to fire, but add a warning log: `if data.get("totalCount", 0) > len(results): logger.warning("Pagination truncation: %d of %d items returned", len(results), data["totalCount"])`.

**Warning signs:** Device count in `raw_sanitized.json` seems lower than the controller UI shows.

### Pitfall 4: Sanitizer Misses New Secret Field Names from Integration v1 API

**What goes wrong:** The Integration v1 API may return secrets under field names not in the current `SECRET_FIELD_NAMES` set (e.g., `preSharedKey`, `sharedSecret`, `radiusSecret` in camelCase). The sanitizer matches by exact key name — new camelCase variants go through unredacted.

**Why it happens:** `SECRET_FIELD_NAMES` was built from classic API field names (all snake_case). The Integration v1 API uses camelCase.

**How to avoid:**
1. Add camelCase variants of all known secret fields to `SECRET_FIELD_NAMES` in `sanitizer.py`.
2. Property-test with `hypothesis` to detect any raw string surviving under a known-secret key.
3. After canonical fixture capture, grep the `raw_sanitized.json` for any value that looks like a PSK (length > 8, not a fingerprint dict).

**Current `SECRET_FIELD_NAMES` is missing camelCase variants.** The `sanitizer.py` extraction (D-09) should expand the set to include:

```python
# Add to SECRET_FIELD_NAMES:
"preSharedKey", "presharedKey", "sharedSecret", "radiusSecret",
"sshPassword", "authKey", "iappKey", "privateKey", "apiKey",
"wifPassword",  # observed in some Ubiquiti device configs
```

### Pitfall 5: Test Fixture Contains Real Credentials After Sanitization Bug

**What goes wrong:** If sanitization has a bug and a raw secret survives, committing the "sanitized" fixture leaks a real credential into git history — permanently.

**Why it happens:** Sanitization relies on exact field name matching; a new or differently-cased field escapes.

**How to avoid:**
1. Run `hypothesis` property test before committing any fixture: "feed a dict with known secret fields, assert no raw string survives."
2. Manual grep: `python3 -c "import json; d=json.loads(open('raw_sanitized.json').read()); print([k for k,v in d.items() if isinstance(v,str) and len(v)>8])"`
3. Add a pre-commit check that scans for high-entropy strings in JSON files in `samples/fixtures/`.

---

## pytest Infrastructure Patterns (D-07, D-08)

### pyproject.toml Configuration

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"
# Source: [CITED: docs.pytest.org/en/stable/reference/customize.html]
# Note: [tool.pytest] (native TOML) requires pytest 9.0+; machine has 9.0.3
# Either format works; ini_options is more portable if ever tested on older pytest
```

### conftest.py — Canonical Fixture Loader

```python
# tests/conftest.py
import json
from pathlib import Path
import pytest

CANONICAL_FIXTURE = Path(__file__).parent.parent / "samples/fixtures/api_dump_home_office.json"
TESTS_FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def canonical_api_dump() -> dict:
    """Load the committed canonical fixture. Session-scoped for speed."""
    return json.loads(CANONICAL_FIXTURE.read_text())


@pytest.fixture
def synthetic_api_dump() -> dict:
    """Minimal synthetic fixture for unit tests — no real data."""
    return {
        "_endpoints_probed": [{"name": "sites", "status": 200}],
        "_errors": [],
        "_site_count": 1,
        "site_default": {
            "_meta": {"id": "default", "name": "test-site"},
            "devices": {"data": [
                {"macAddress": "02:00:00:00:00:01", "model": "U6-Pro",
                 "name": "ap-0", "state": "connected", "sshEnabled": False}
            ], "totalCount": 1},
            "wlans": {"data": [
                {"name": "test-ssid", "enabled": True, "security": "wpapsk",
                 "wpa_mode": "wpa2", "x_passphrase": {"length": 12, "fingerprint": "abc123def456"}}
            ], "totalCount": 1},
            "networks": {"data": [
                {"name": "main", "purpose": "corporate", "vlan": 1}
            ], "totalCount": 1},
            "port_forwards": {"data": [], "totalCount": 0},
            "vpn_configs": {"data": [], "totalCount": 0},
            "firewall_policies": {"data": [], "totalCount": 0},
        },
    }
```

### Parametrizing Tests Across Multiple Fixture Files

```python
# tests/test_pipeline_smoke.py — parametrize over all fixtures in tests/fixtures/
import json
from pathlib import Path
import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"

def _fixture_files():
    """Discover all JSON fixture files in tests/fixtures/."""
    return list(FIXTURE_DIR.glob("*.json"))

@pytest.mark.parametrize("fixture_path", _fixture_files(), ids=lambda p: p.stem)
def test_pipeline_runs_without_error(fixture_path):
    data = json.loads(fixture_path.read_text())
    # Run pipeline and assert findings shape
    ...
```

### Property-Based Test for Sanitizer (hypothesis)

```python
# tests/test_sanitizer.py
from hypothesis import given, settings
import hypothesis.strategies as st
from sanitizer import sanitize, SECRET_FIELD_NAMES

# Strategy: build a dict where each secret key has an arbitrary string value
secret_key_strategy = st.sampled_from(sorted(SECRET_FIELD_NAMES))
secret_value_strategy = st.text(min_size=1, max_size=200)

@given(st.fixed_dictionaries({k: secret_value_strategy for k in sorted(SECRET_FIELD_NAMES)[:5]}))
@settings(max_examples=500)
def test_sanitize_never_leaks_secret_fields(secret_dict: dict):
    """No raw string should survive sanitize() under any SECRET_FIELD_NAME key."""
    result = sanitize(secret_dict)
    for key in SECRET_FIELD_NAMES:
        if key in result:
            val = result[key]
            # Value must be a fingerprint dict, not a raw string
            assert isinstance(val, dict), f"Key '{key}' leaked as non-dict: {type(val)}"
            assert "length" in val or "redacted" in val, f"Key '{key}' fingerprint missing: {val}"

@given(st.dictionaries(
    st.text(min_size=1, max_size=30),
    st.one_of(st.text(), st.integers(), st.none()),
    min_size=0, max_size=20,
))
def test_sanitize_is_idempotent(input_dict: dict):
    """sanitize(sanitize(x)) == sanitize(x) for any dict."""
    once = sanitize(input_dict)
    twice = sanitize(once)
    assert once == twice
```

### Tagged-Secret Round-Trip Test

```python
def test_tagged_secret_does_not_appear_in_any_output(tmp_path, synthetic_api_dump):
    """Feed a uniquely tagged secret through the full pipeline; grep all output for it."""
    TAGGED_SECRET = "UNIQUE_SECRET_TAG_7f3a9b2c_DO_NOT_COMMIT"
    # Inject into a known secret field
    synthetic_api_dump["site_default"]["wlans"]["data"][0]["x_passphrase"] = TAGGED_SECRET

    from unifi_audit import sanitize, analyze
    import logging, json
    logger = logging.getLogger("test")

    clean = sanitize(synthetic_api_dump)
    findings = analyze(clean, "home_office", logger)

    # Serialize everything to disk as the real pipeline does
    output_dir = tmp_path
    (output_dir / "raw_sanitized.json").write_text(json.dumps(clean))
    (output_dir / "findings.json").write_text(json.dumps(
        [dict(id=f.id, title=f.title, current_state=f.current_state,
              evidence=str(f.evidence)) for f in findings]
    ))

    # Grep all files for the tagged secret
    for f in output_dir.iterdir():
        content = f.read_text()
        assert TAGGED_SECRET not in content, f"Tagged secret leaked into {f.name}"
```

---

## Profile-Aware Scoring — Design Rationale

### Inspiration from CIS Benchmarks and lynis

OpenSCAP/CIS Benchmarks use **profile levels** (Level 1 = baseline, Level 2 = higher security) to selectively apply controls. `[CITED: open-scap.org/security-policies/choosing-policy/]`

lynis uses a **hardening index** (0-100) that accumulates points per check, with no profile-awareness. That approach is too blunt for this tool's audience spectrum (home users vs. regulated environments). `[ASSUMED: lynis score design - based on training knowledge]`

Our weight table approach is closer to the SCAP profile model but applied as a continuous multiplier rather than a binary include/exclude, which preserves all findings for all profiles (important for the user's education) while adjusting their ranking priority.

### Retention Policy Values in the Weight Table

The `find_logging` module in `findings_enhanced.py` already encodes profile-specific retention targets via `RETENTION_PROFILES`. The weight multipliers in `profile_weights.py` amplify or suppress the finding's ranking but do not change the retention recommendation text. The retention text is already correctly differentiated by profile inside the module.

| Profile | Traffic Log Target | Admin Log Target | HIPAA/PCI Rationale |
|---------|-------------------|-----------------|----------------------|
| home | 7-14 days | 30 days | Privacy > retention |
| home_office | 14-30 days | 90 days | Business use warrants some audit trail |
| small_business | 30-90 days | 365 days | Employee accountability |
| regulated_hipaa | 6 years both | 6 years both | HIPAA §164.312(b) — minimum 6 years |
| regulated_pci | 365 days | 365 days | PCI DSS Req 10.7 — minimum 12 months |

`[CITED: findings_enhanced.py:480-486]` — `RETENTION_PROFILES` dict already encodes these correctly.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Backup-file as Phase 1 deliverable | API-first; backup is Phase 4 specialist mode | July 2024 (MFA rollout + API key launch) | Phase 1 does not require AES-CBC key; works without admin MFA tradeoff |
| Classic cookie-session auth | X-API-KEY (Network Integration API) | July 2024 | Revocable; scoped; no MFA bypass required |
| Single unified API key (future) | Separate local + cloud keys | April 2026 unified key launch | Phase 1 uses local key; Phase 3 will validate unified key path |
| Secret field names (snake_case only) | Need camelCase variants too | Integration v1 API uses camelCase | Must expand `SECRET_FIELD_NAMES` in sanitizer.py |

**Deprecated / not to use:**
- Classic cookie auth (`/api/login`): requires MFA-less local admin. `D-007` LOCKED as anti-pattern.
- Hardcoded field names without camelCase variants: risk of leaked secrets from Integration v1 API responses.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | SSH state is accessible from Integration v1 devices endpoint (may be in `sshEnabled`, `features[]`, or a sub-resource) | API Response Shapes, Adapter Pattern | `find_devices` finds no SSH-enabled devices even when they exist; `DEV-SSH` findings missing |
| A2 | `radio_table` is accessible from Integration v1 devices endpoint (field name `radioTable` or nested) | Adapter Pattern | `find_wireless_tuning` TX-power and PMF checks produce no findings |
| A3 | Settings-level data (`auto_update`, `auto_backup`, `mgmt`, `rogueap`, `dns_filtering`) is NOT exposed by Integration v1 API | Adapter Pattern, Don't Hand-Roll | Several enhanced module checks produce no findings (acceptable per D-03); if actually available, we miss them |
| A4 | WLAN endpoint returns `security`, `wpaMode`/`wpa_mode`, `pmfMode` field names | Adapter Pattern | WPA/PMF findings from enhanced modules may fire incorrectly or not fire |
| A5 | Network endpoint returns a `purpose` field matching classic values (`corporate`, `guest`, `vlan-only`) | Adapter Pattern | Segmentation findings fire incorrectly or miss flat-network condition |
| A6 | Firmware `version` field name in Integration v1 API is `version` or `firmwareVersion` | Adapter Pattern | Firmware version checks in `find_firmware` miss stale firmware |
| A7 | Port-forward object from Integration v1 API has `enabled` boolean field | Adapter Pattern | `find_remote_access` (both modules) may miss active port forwards |
| A8 | VPN config type (PPTP, L2TP, WireGuard) is determinable from Integration v1 API's `vpn-configs` endpoint | Adapter Pattern | `VPN-PPTP-001` (always-top critical finding) may not fire; `find_remote_access` enhanced module misses VPN state |
| A9 | `hypothesis` 6.x `st.fixed_dictionaries` is the right strategy for sanitizer property testing | pytest Patterns | Tests pass but miss edge cases if strategy is too narrow; expand with `st.recursive` for nested structures |
| A10 | lynis uses non-profile-aware hardening index | Profile-Aware Scoring | Minor; weight table approach is independently sound regardless of lynis design |

**All A* claims**: resolve by running `unifi_audit.py` against a real controller (REQ-validation-real-network) and inspecting `raw_sanitized.json`. The adapter's `[ASSUMED]` comments convert to `[VERIFIED]` after that run.

---

## Open Questions

1. **SSH and radio_table availability in Integration v1 API**
   - What we know: Integration v1 confirms devices endpoint with `macAddress`, `model`, `state`, `features[]`
   - What's unclear: Whether `sshEnabled` is a top-level bool or nested in `features[]`; whether `radio_table` is accessible at all vs. requiring a per-device detail call
   - Recommendation: Add robust fallback in adapter; after fixture capture, check if these findings need a per-device detail endpoint call (`/sites/{id}/devices/{deviceId}`) as a second pass

2. **Settings-level data availability**
   - What we know: Community sources only document `/devices`, `/clients` as confirmed Integration v1 endpoints
   - What's unclear: Whether `/wlans`, `/networks`, `/firewall-policies`, `/vpn-configs`, `/port-forwards` are fully exposed in version 9.3.43+; whether any settings-level data (`auto_update`, `mgmt`, `rogueap`) is exposed at all
   - Recommendation: Plan for 50% of enhanced module checks to return no findings from the Integration v1 API; the remaining checks require backup-mode validation (Phase 4). Document this limitation in the Phase 1 report footer.

3. **`Finding` dataclass split between `unifi_audit.py` and `parser.py`**
   - What we know: Both dataclasses are schema-identical; `findings_enhanced.py` imports `parser.Finding`
   - What's unclear: Whether mixing them in the same `list[Finding]` causes any runtime issues with `asdict()` serialization
   - Recommendation: Duck-type all `findings.extend()` calls; add a test asserting that `asdict(enhanced_finding)` produces the same keys as `asdict(audit_finding)`

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.9+ | All modules | Yes | 3.14.2 | — |
| requests | `unifi_audit.py` | Yes | 2.33.1 | — |
| pytest | Test suite | Yes | 9.0.3 | — |
| hypothesis | Property tests for sanitizer | No | — | Parametrize manual edge cases; add hypothesis later |
| pytest-cov | Coverage measurement | No | — | Run tests without coverage; add later |
| pycryptodome | `parser.py` (Phase 4 only) | Unknown | — | Not needed for Phase 1 |
| pymongo | `parser.py` (Phase 4 only) | Unknown | — | Not needed for Phase 1 |
| Live UniFi controller ≥ 9.3.43 | REQ-validation-real-network | Unknown | — | No automated fallback; required for Phase 1 completion |

**Missing dependencies with no fallback:**
- Live UniFi controller (≥ 9.3.43) — required for real-network validation and canonical fixture capture. Phase 1 cannot be declared complete without it.

**Missing dependencies with fallback:**
- `hypothesis` — can install any time (`pip install hypothesis`); manual parametrized tests cover critical paths until then
- `pytest-cov` — optional for coverage measurement; not blocking

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 9.0.3 |
| Config file | `pyproject.toml` — `[tool.pytest.ini_options]` (see Wave 0 gap) |
| Quick run command | `pytest tests/ -v --tb=short` |
| Full suite command | `pytest tests/ -v --tb=short --cov=src --cov-report=term-missing` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-validation-sanitization-coverage | `sanitize()` never leaks raw secret values | unit + property | `pytest tests/test_sanitizer.py -x` | No — Wave 0 |
| REQ-validation-api-response-shapes | `_extract_list()` handles `{data:[]}`, `[]`, `{items:[]}`, unrecognized shapes with warning | unit | `pytest tests/test_extract_helpers.py -x` | No — Wave 0 |
| REQ-validation-ssl-self-signed | `UniFiClient` sets `verify=False` for local mode, `verify=True` for cloud | unit | `pytest tests/test_pipeline_smoke.py::test_ssl_defaults -x` | No — Wave 0 |
| REQ-validation-network-version-compat | 404 on any endpoint is gracefully skipped (no raise) | unit | `pytest tests/test_pipeline_smoke.py::test_404_graceful -x` | No — Wave 0 |
| REQ-always-float-to-top-overrides | 3 `unknown` Findings emitted; PPTP/EOL/flat-net float before scored findings | unit | `pytest tests/test_pipeline_smoke.py::test_float_top -x` | No — Wave 0 |
| REQ-cross-answer-tension-detection | At least 1 compound finding fires on a constructed test case | unit | `pytest tests/test_pipeline_smoke.py::test_correlation_fires -x` | No — Wave 0 |
| REQ-wire-enhanced-modules-into-audit-script | All 6 enhanced modules produce non-empty findings on canonical fixture (for the checks that the Integration v1 API exposes) | integration | `pytest tests/test_pipeline_smoke.py::test_enhanced_modules_wire -x` | No — Wave 0 |
| REQ-test-fixtures | Canonical fixture committed; synthetic fixture in conftest | N/A | `ls samples/fixtures/api_dump_home_office.json` | No — Wave 0 |
| REQ-validation-real-network | Full pipeline runs against real controller without exception | manual + smoke | `python3 src/unifi_audit.py` (manual; then `pytest` on output) | N/A — manual |

### Sampling Rate

- **Per task commit:** `pytest tests/ -v --tb=short -x` (fail-fast, < 30 seconds)
- **Per wave merge:** `pytest tests/ -v --tb=short --cov=src --cov-report=term-missing`
- **Phase gate:** Full suite green + manual real-network run documented before `/gsd-verify-work`

### Wave 0 Gaps (must create before implementation tests can run)

- [ ] `pyproject.toml` — `[tool.pytest.ini_options]` section
- [ ] `tests/` directory
- [ ] `tests/conftest.py` — canonical fixture loader + `synthetic_api_dump` fixture
- [ ] `tests/test_sanitizer.py` — 100% coverage of `sanitize()` + `_fingerprint()`
- [ ] `tests/test_extract_helpers.py` — `_extract_list()` and `_extract_sites()` shape variants
- [ ] `tests/test_pipeline_smoke.py` — float-top, 404 graceful, SSL defaults, correlation, tagged-secret leak
- [ ] `tests/fixtures/.gitignore` — exclude real API dumps
- [ ] `samples/fixtures/` directory — for committed canonical fixture
- [ ] Framework install: `pip install hypothesis pytest-cov` (if property tests wanted immediately)

**Phase gate acceptance criteria** (per CONTEXT.md D-07 §Validation acceptance bar):
1. `unifi_audit.py` runs end-to-end against ≥1 real UniFi network (≥9.3.43) without raising
2. `raw_sanitized.json` survives sanitize round-trip — tagged-secret test passes
3. pytest suite passes against canonical fixture
4. Smoke test asserts all 12 finding modules produce a list (empty-or-not is acceptable for API-limited modules)
5. Always-top override produces 3 `unknown` Findings + correctly orders detectable always-top findings ahead of scored ones
6. At least 1 compound finding fires on a constructed test case

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Credential loading is env-var only — no interactive auth flow in Phase 1 |
| V3 Session Management | Partial | `requests.Session` cleared after `collect_all()`; key not persisted |
| V4 Access Control | No | Read-only by design; no authorization decisions made |
| V5 Input Validation | Yes | Secret field name matching in sanitizer; `_extract_list()` defensive parsing |
| V6 Cryptography | Partial | SHA256 fingerprinting only; not encryption. Never hand-roll; `hashlib` is stdlib |
| V7 Error Handling | Yes | Exception messages scrubbed for key leakage (existing `safe_msg` pattern) |

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| API key in log output | Information Disclosure | Exception scrub: `str(e).replace(key, "<REDACTED>")` — already implemented |
| Raw PSK in sanitized fixture | Information Disclosure | Expand `SECRET_FIELD_NAMES` with camelCase; property-test with hypothesis |
| Test fixture leaks real credentials | Information Disclosure | Gitignore for `tests/fixtures/`; never commit real keys; tagged-secret test |
| Credential passed via CLI arg | Tampering | `load_config()` enforces env-var only; `sys.argv` never read for credentials |
| Pagination truncation (silent data loss) | Tampering/Info Disclosure | Log warning when `count < totalCount`; Phase 1 note in report |
| `findings_enhanced.py` exception leaks to log | Information Disclosure | Existing try/except in `analyze()` wraps each module; preserve this pattern |

---

## Sources

### Primary (HIGH confidence)

- `[VERIFIED: codebase]` `src/unifi_audit.py` (689 LOC) — actual implementation, line numbers verified by Read tool
- `[VERIFIED: codebase]` `src/findings_enhanced.py` (624 LOC) — module signatures and data model
- `[VERIFIED: codebase]` `src/parser.py` (562 LOC) — collection names used by enhanced modules
- `[VERIFIED: pip install]` pytest 9.0.3, requests 2.33.1 — installed on machine
- `[CITED: github.com/runZeroInc/runzero-custom-integrations]` — Integration v1 API uses camelCase; `{data:[]}` envelope confirmed by actual code inspection

### Secondary (MEDIUM confidence)

- `[CITED: github.com/tmcpro/unifi-network-api]` — Integration v1 pagination pattern (offset, limit, count, totalCount)
- `[CITED: docs.pytest.org/en/stable/reference/customize.html]` — pyproject.toml `[tool.pytest.ini_options]` configuration
- `[CITED: hypothesis.readthedocs.io]` — `st.fixed_dictionaries()` strategy for dict property testing
- `[CITED: .planning/codebase/TESTING.md]` — Recommended test surfaces and fixture spec
- `[CITED: .planning/codebase/CONCERNS.md]` — Confirmed concern list and severity ratings

### Tertiary (LOW confidence — flag for validation)

- `[ASSUMED]` WLAN, network, VPN, firewall, port-forward, and settings-level field names in Integration v1 API — not documented publicly; requires real controller run to verify
- `[ASSUMED]` SSH and radio_table field paths in Integration v1 device objects

---

## Metadata

**Confidence breakdown:**
- Sanitizer extraction (D-09): HIGH — both source implementations read directly from codebase
- Adapter design (D-01): MEDIUM — envelope structure confirmed; field-level mapping is ASSUMED pending fixture
- Compound rules (D-04): HIGH — pure Python; patterns from codebase
- Profile weights (D-05): MEDIUM — values are evidence-informed starting points; expect calibration after first real runs
- pytest patterns (D-07, D-08): HIGH — verified against installed pytest 9.0.3
- API response shapes: MEDIUM (envelope) / LOW (field names) — only real-network run resolves field-name uncertainty

**Research date:** 2026-04-25
**Valid until:** 2026-07-25 (90 days — stable API; update after Integration v1 API adds new endpoints or field names)
