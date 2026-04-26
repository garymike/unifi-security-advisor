#!/usr/bin/env python3
"""
Phase 1 fixture anonymization tool (D-08, REQ-test-fixtures).

Reads tests/fixtures/raw_sanitized.json (the user-captured real-network fixture
from Plan 07) and writes samples/fixtures/api_dump_home_office.json (the
committed-to-git canonical fixture).

Anonymization strategy (per RESEARCH.md §"Fixture Anonymization Strategy"):
- MAC addresses → locally-administered fake (02:xx:xx:xx:xx:xx; sha256-seeded)
- IPv4 addresses → RFC 5737 documentation range (192.0.2.X)
- Hostnames / device names → generic placeholders (ap-N, switch-N, etc.)
- Site names → test-site-home-office
- Serial numbers → SIM-{index:05d}
- Site UUIDs in keys → deterministic stable placeholder IDs

The sanitizer.py SECRET_FIELD_NAMES already replaces secrets with fingerprint
dicts; this script handles the additional PII layer.

Usage:
    python tools/anonymize_fixture.py
    # Reads:  tests/fixtures/raw_sanitized.json
    # Writes: samples/fixtures/api_dump_home_office.json

Run once (after Plan 07's real-network capture). Re-run if the captured
fixture changes (e.g., a new controller version).
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
INPUT = REPO_ROOT / "tests" / "fixtures" / "raw_sanitized.json"
OUTPUT = REPO_ROOT / "samples" / "fixtures" / "api_dump_home_office.json"

# Fields where the value is a MAC-shaped string
MAC_FIELDS = {"mac", "macAddress", "bssid", "bssId", "wanMac", "lanMac"}
# Fields where the value is an IP-shaped string
IP_FIELDS = {"ip", "ipAddress", "lanIp", "wanIp", "gatewayIp", "natIp", "ext_ip"}
# Fields where the value is a hostname
HOSTNAME_FIELDS = {"hostname"}
# Fields where the value is a device or client name (only anonymize in device/client contexts)
DEVICE_NAME_FIELDS = {"name", "deviceName", "displayName"}
# Generic name fields that NEVER get anonymized (functional labels, not PII)
PASSTHROUGH_NAME_FIELDS = {"siteName"}
# Fields where the value is a serial number
SERIAL_FIELDS = {"serial", "serialNumber", "deviceSerial"}
# Fields where the value is a site ID (UUID)
SITE_ID_FIELDS = {"id", "siteId"}
# Fields that are string paths/labels — pass through but scrub embedded UUIDs
UUID_SCRUB_FIELDS = {"path"}

# Parent-key contexts in which 'name' IS a device/client label → anonymize
_DEVICE_CLIENT_CONTEXTS = {"devices", "clients"}
# Parent-key contexts in which 'name' is a functional label → pass through
_PASSTHROUGH_CONTEXTS = {"_endpoints_probed", "networks", "sites", "_meta", "wlans",
                          "firewall_policies", "firewall_zones", "port_forwards",
                          "vpn_configs", "traffic_routes"}
# Patterns
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
# Full-string UUID match (anchored) — for field values that ARE a UUID
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Unanchored UUID search — for finding UUIDs embedded inside longer strings
UUID_SEARCH_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# Deterministic counters keyed by original value so the same source maps to the
# same anonymized output on every run (idempotence).
_COUNTERS: dict[str, dict[str, str]] = {
    "device": {},
    "host": {},
    "site": {},
    "serial": {},
    "site_id": {},
    "client": {},
}

# Stable fake UUIDs for site IDs (deterministic; locally harmless)
_FAKE_SITE_UUID_BASE = "00000000-0000-0000-0000-{n:012d}"


def _anon_mac(mac: str) -> str:
    """Deterministic fake MAC in locally-administered range.

    Set the locally-administered bit (0x02) on the first octet so analysts
    immediately recognize it as fake.
    """
    h = hashlib.sha256(mac.encode()).hexdigest()
    octets = [h[i : i + 2] for i in range(0, 12, 2)]
    first = (int(octets[0], 16) | 0x02) & 0xFE  # locally-administered, unicast
    rest = ":".join(octets[1:])
    return f"{first:02x}:{rest}"


def _anon_ipv4(ip: str) -> str:
    """RFC 5737 documentation range; preserve last octet for traceability within fixture."""
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    try:
        last = int(parts[3]) % 254 + 1
    except ValueError:
        last = 1
    return f"192.0.2.{last}"


def _anon_name(value: str, kind: str = "device") -> str:
    """Map name to a counter under its kind (device, host, site, serial, client)."""
    bucket = _COUNTERS.setdefault(kind, {})
    if value in bucket:
        return bucket[value]
    n = len(bucket) + 1
    if kind == "device":
        # Try to preserve device-class hint if recognizable
        v_low = value.lower()
        if any(w in v_low for w in ("ap", "u6", "uap", "u7")):
            new = f"ap-{n}"
        elif any(w in v_low for w in ("switch", "usw")):
            new = f"switch-{n}"
        elif any(w in v_low for w in ("gateway", "udm", "usg", "cgf", "ucg", "fiber", "cloud")):
            new = f"gateway-{n}"
        else:
            new = f"device-{n}"
    elif kind == "host":
        new = f"host-{n}.local"
    elif kind == "site":
        new = "test-site-home-office"
    elif kind == "serial":
        new = f"SIM-{n:05d}"
    elif kind == "client":
        new = f"client-{n}"
    else:
        new = f"anon-{n}"
    bucket[value] = new
    return new


def _anon_site_id(value: str) -> str:
    """Replace real site UUIDs with stable fake UUIDs."""
    bucket = _COUNTERS["site_id"]
    if value in bucket:
        return bucket[value]
    n = len(bucket) + 1
    new = _FAKE_SITE_UUID_BASE.format(n=n)
    bucket[value] = new
    return new


def _anon_key(key: str) -> str:
    """Anonymize dict keys that embed site UUIDs (e.g., 'site_<uuid>')."""
    # Key pattern: site_<uuid>
    m = re.match(r"^(site_)(.+)$", key)
    if m and UUID_RE.match(m.group(2)):
        return m.group(1) + _anon_site_id(m.group(2))
    # Endpoint probed path patterns: path contains /sites/<uuid>/
    return key


def _anon_path(path: str) -> str:
    """Anonymize site UUIDs embedded in API paths or label strings.

    Uses the unanchored UUID_SEARCH_RE so it replaces UUIDs that appear
    as substrings (e.g., 'devices@<uuid>', '/sites/<uuid>/devices').
    """
    def replace_uuid(m: re.Match) -> str:
        return _anon_site_id(m.group(0))

    return UUID_SEARCH_RE.sub(replace_uuid, path)


def _classify_name_field(key: str) -> str:
    """Determine anonymization kind for a name-class field."""
    key_low = key.lower()
    if key_low == "hostname":
        return "host"
    if key_low == "sitename":
        return "site"
    return "device"


def anonymize(obj: Any, _collection: str = "") -> Any:
    """Recursively anonymize a JSON-decoded value.

    Args:
        obj: The JSON-decoded value to anonymize.
        _collection: The nearest named collection ancestor key (e.g., 'devices',
            'clients', 'networks', 'sites', '_endpoints_probed').  This context
            drives whether a 'name' field is treated as PII (device/client label)
            or as a functional label that passes through unchanged.

    Returns:
        Anonymized copy with all PII replaced by deterministic fake values.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            anon_k = _anon_key(k)

            # Determine child collection context: use k if it is a known
            # collection name, otherwise inherit the current _collection.
            _all_known = _DEVICE_CLIENT_CONTEXTS | _PASSTHROUGH_CONTEXTS
            child_collection = k if k in _all_known else _collection

            if k in MAC_FIELDS and isinstance(v, str) and MAC_RE.match(v):
                out[anon_k] = _anon_mac(v)
            elif k in IP_FIELDS and isinstance(v, str) and IPV4_RE.match(v):
                out[anon_k] = _anon_ipv4(v)
            elif k in HOSTNAME_FIELDS and isinstance(v, str) and v:
                out[anon_k] = _anon_name(v, kind="host")
            elif k in DEVICE_NAME_FIELDS and isinstance(v, str) and v:
                # Only anonymize device/client 'name' fields when the nearest
                # collection ancestor is devices or clients.  In other contexts
                # (endpoint probe records, network labels, site labels, etc.)
                # the value is a functional label with no PII — pass through,
                # but still scrub any embedded UUIDs in the string value.
                if _collection in _DEVICE_CLIENT_CONTEXTS:
                    out[anon_k] = _anon_name(v, kind="device")
                elif _collection in _PASSTHROUGH_CONTEXTS:
                    # Pass through functional label but anonymize embedded UUIDs
                    out[anon_k] = _anon_path(v) if UUID_SEARCH_RE.search(v) else v
                else:
                    # Unknown context — be conservative and anonymize.
                    out[anon_k] = _anon_name(v, kind="device")
            elif k in UUID_SCRUB_FIELDS and isinstance(v, str) and v:
                # Path strings: pass through but replace any embedded UUIDs
                out[anon_k] = _anon_path(v) if UUID_SEARCH_RE.search(v) else v
            elif k in SERIAL_FIELDS and isinstance(v, str) and v:
                out[anon_k] = _anon_name(v, kind="serial")
            elif k == "id" and isinstance(v, str) and UUID_RE.match(v):
                # Anonymize UUIDs in 'id' fields (device IDs, client IDs, site IDs)
                out[anon_k] = _anon_site_id(v)
            elif k == "uplinkDeviceId" and isinstance(v, str) and UUID_RE.match(v):
                out[anon_k] = _anon_site_id(v)
            else:
                out[anon_k] = anonymize(v, _collection=child_collection)
        return out
    if isinstance(obj, list):
        return [anonymize(x, _collection=_collection) for x in obj]
    if isinstance(obj, str):
        # Catch BSSIDs / MACs that appear as values rather than under a known key
        if MAC_RE.match(obj):
            return _anon_mac(obj)
        # Catch UUIDs in _endpoints_probed paths and similar string values
        if UUID_SEARCH_RE.search(obj):
            return _anon_path(obj)
        # Catch raw IPv4s that slipped through (e.g., in string values in paths)
        if IPV4_RE.match(obj) and not obj.startswith("192.0.2."):
            return _anon_ipv4(obj)
    return obj


def main() -> int:
    """Run anonymization: read INPUT, write anonymized output to OUTPUT."""
    if not INPUT.exists():
        sys.stderr.write(
            f"Error: input fixture not found at {INPUT}.\n"
            "Run Plan 07 first to capture a real-network fixture.\n"
        )
        return 1

    raw = json.loads(INPUT.read_text())
    anonymized = anonymize(raw)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    # Pretty-print with 2 spaces, sort keys for diff stability
    OUTPUT.write_text(json.dumps(anonymized, indent=2, sort_keys=True))

    size = OUTPUT.stat().st_size
    print(f"Wrote {OUTPUT} ({size} bytes)")
    if size > 200 * 1024:
        sys.stderr.write(
            f"Warning: fixture is {size} bytes (>200 KB budget per D-08). "
            "Consider trimming or splitting.\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
