"""
Ubiquiti Security Advisor - Backup-File Parser (Phase 1)

Single-file skeleton showing the architecture. Splits into modules for the real build.
All processing is local; this module never opens a network connection.

Dependencies (minimal):
    pip install pycryptodome pymongo

Usage:
    python parser.py analyze path/to/backup.unf --out report.md

Tested against: placeholder (needs real backup fixtures for validation)
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Third-party. Imports deferred so --help works without them installed.
# from Crypto.Cipher import AES
# import bson


# =============================================================================
# 1. DECRYPTION
# =============================================================================
# The .unf format is AES-128-CBC with a static key and IV baked into the UniFi
# source. These keys are public and used by every open-source tool in this space.
# They're NOT a secret; they're an obfuscation layer.

UNF_KEY = bytes.fromhex("626379616e676b6d6c756f686d617273")  # "bcyangkmluohmars"
UNF_IV = bytes.fromhex("75626e74656e74657270726973656170")   # "ubntenterpriseap"


def decrypt_unf(unf_path: Path) -> bytes:
    """Decrypt a .unf backup and return the raw ZIP bytes."""
    from Crypto.Cipher import AES

    with open(unf_path, "rb") as f:
        ciphertext = f.read()

    cipher = AES.new(UNF_KEY, AES.MODE_CBC, UNF_IV)
    # UniFi doesn't pad in the standard way; -nopad in the reference openssl cmd.
    # Real implementation should handle possible trailing bytes gracefully.
    plaintext = cipher.decrypt(ciphertext)

    # The plaintext starts with a valid ZIP signature (PK\x03\x04).
    if plaintext[:4] != b"PK\x03\x04":
        raise ValueError(
            "Decrypted output doesn't start with ZIP signature. "
            "Possible: wrong file type, corrupted file, or new backup format."
        )

    return plaintext


def extract_collections(zip_bytes: bytes) -> dict[str, list[dict[str, Any]]]:
    """Extract the ZIP, gunzip db.gz, parse BSON, return a dict keyed by collection name."""
    import bson

    collections: dict[str, list[dict[str, Any]]] = {}

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        # Older backups: db.gz (single BSON dump with all collections inline)
        # Newer backups: dump/<db_name>/<collection>.bson files (mongodump style)
        names = z.namelist()

        if "db.gz" in names:
            with z.open("db.gz") as raw, gzip.open(raw) as gz:
                data = gz.read()
            # db.gz contains concatenated BSON documents; decode_all handles this.
            docs = bson.decode_all(data)
            # Each doc has its collection name in a convention that varies by version;
            # real implementation inspects structure to route to the right bucket.
            collections["_all"] = docs
        else:
            # mongodump-style: one file per collection
            for name in names:
                if name.endswith(".bson"):
                    collection_name = Path(name).stem
                    with z.open(name) as f:
                        collections[collection_name] = bson.decode_all(f.read())

    return collections


# =============================================================================
# 2. SANITIZATION
# =============================================================================
# Backup files contain WPA keys, RADIUS secrets, admin password hashes, etc.
# We redact/hash BEFORE any output leaves this module.

SECRET_FIELD_NAMES = {
    "x_passphrase",       # WPA PSK
    "x_passphrase_rollover",
    "x_radius_secret",
    "x_shared_secret",
    "x_ssh_password",
    "x_iapp_key",
    "password",           # admin accounts
    "x_auth_key",         # RADIUS
    "auth_key",
    "private_key",
    "api_key",
    "token",
}


def _fingerprint(value: str) -> dict[str, Any]:
    """Turn a secret string into a non-reversible fingerprint for analysis."""
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
    """Recursively sanitize. Always redacts secrets. Optionally redacts PII."""
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


# =============================================================================
# 3. FINDINGS MODEL
# =============================================================================

@dataclass
class Finding:
    id: str
    section: str
    severity: str               # info | low | medium | high | critical
    status: str                 # ok | gap | recommendation | unknown
    title: str
    current_state: str
    recommendation: str | None = None
    intent_question: str | None = None
    evidence: dict = field(default_factory=dict)
    maps_to: dict = field(default_factory=dict)
    effort: str = "medium"      # quick | medium | project
    impact: str = "medium"


# =============================================================================
# 4. FINDINGS MODULES (one per questionnaire section)
# =============================================================================
# Each module inspects the parsed collections and returns a list[Finding].
# Kept inline here; split into separate files in the real build.


def find_segmentation(colls: dict) -> list[Finding]:
    """Section 5: network segmentation state."""
    findings = []
    networks = _get_collection(colls, "networkconf")

    # Count non-default VLANs (default LAN usually has vlan=1 or no vlan tag)
    corporate_nets = [n for n in networks if n.get("purpose") == "corporate"]
    guest_nets = [n for n in networks if n.get("purpose") == "guest"]
    vlan_only = [n for n in networks if n.get("purpose") == "vlan-only"]
    total_user_nets = len(corporate_nets) + len(guest_nets) + len(vlan_only)

    if total_user_nets <= 1:
        findings.append(Finding(
            id="SEG-001",
            section="Segmentation",
            severity="high",
            status="gap",
            title="Flat network (no segmentation)",
            current_state=(
                f"The controller has {total_user_nets} user-defined network(s). "
                "All devices share a single broadcast domain and IP range, which "
                "means a compromise of any device can reach any other."
            ),
            recommendation=(
                "Create separate networks for: main/trusted, IoT, guest, and "
                "management. Map SSIDs to the appropriate VLANs. Enable Network "
                "Isolation or Zone-Based Firewall rules to block inter-VLAN traffic."
            ),
            intent_question=(
                "Do you want to segment the network into separate zones for "
                "trusted devices, IoT, and guests?"
            ),
            maps_to={"nist_csf": "PR.AC-5", "cis_v8": "12.2"},
            effort="project",
            impact="high",
            evidence={"network_count": total_user_nets, "purposes": {
                "corporate": len(corporate_nets),
                "guest": len(guest_nets),
                "vlan_only": len(vlan_only),
            }},
        ))

    # Check for a dedicated management network
    mgmt_candidates = [
        n for n in networks
        if "mgmt" in n.get("name", "").lower() or "admin" in n.get("name", "").lower()
    ]
    if not mgmt_candidates:
        findings.append(Finding(
            id="SEG-002",
            section="Segmentation",
            severity="medium",
            status="gap",
            title="No dedicated management network",
            current_state="No network named mgmt/admin detected. Controller and device admin interfaces are reachable from the main LAN.",
            recommendation="Create a management VLAN. Restrict admin UI access to that VLAN only.",
            intent_question="Is it acceptable that anyone on your main network can reach admin interfaces?",
            maps_to={"nist_csf": "PR.AC-5", "zt_tenet": "resource protection"},
            effort="medium",
            impact="medium",
        ))

    return findings


def find_admin(colls: dict) -> list[Finding]:
    """Section 4: admin and identity."""
    findings = []
    settings = _get_setting(colls, "super_identity") or {}
    mgmt = _get_setting(colls, "mgmt") or {}

    # SSH enablement on devices
    ssh_enabled_devices = [
        d for d in _get_collection(colls, "device")
        if d.get("ssh_enabled") is True
    ]
    if ssh_enabled_devices:
        findings.append(Finding(
            id="ADM-001",
            section="Admin",
            severity="medium",
            status="recommendation",
            title=f"SSH enabled on {len(ssh_enabled_devices)} device(s)",
            current_state=(
                f"SSH is enabled on {len(ssh_enabled_devices)} device(s). "
                "This is a remote admin surface that attackers target."
            ),
            recommendation=(
                "Disable SSH unless actively needed. If needed, ensure key-based "
                "auth only, unique password, and access restricted to the "
                "management VLAN."
            ),
            intent_question="Do you actively use SSH to any of these devices?",
            maps_to={"cis_v8": "4.6", "nist_csf": "PR.AC-4"},
            effort="quick",
            impact="medium",
            evidence={"device_count": len(ssh_enabled_devices)},
        ))

    # Admin accounts: infer from accounts collection
    admins = _get_collection(colls, "admin") or _get_collection(colls, "account")
    local_admins = [a for a in admins if not a.get("ubic_id")]
    if not local_admins:
        findings.append(Finding(
            id="ADM-002",
            section="Admin",
            severity="high",
            status="gap",
            title="No local break-glass admin detected",
            current_state=(
                "All admin accounts appear tied to Ubiquiti cloud SSO. If the "
                "cloud account is locked, compromised, or loses MFA access, "
                "there is no local recovery path."
            ),
            recommendation=(
                "Create a local admin account. Store its password in a password "
                "manager, offline. Never use it for daily login."
            ),
            intent_question="Do you want to add a local break-glass admin account?",
            maps_to={"cis_v8": "5.3", "nist_csf": "PR.AC-1"},
            effort="quick",
            impact="high",
        ))

    return findings


def find_firewall(colls: dict) -> list[Finding]:
    """Section 7: firewall and threat detection."""
    findings = []
    tm = _get_setting(colls, "threat_management") or {}
    mgmt = _get_setting(colls, "mgmt") or {}

    if not tm.get("enabled"):
        findings.append(Finding(
            id="FW-001",
            section="Firewall",
            severity="medium",
            status="gap",
            title="IDS/IPS is disabled",
            current_state="Threat management (IDS/IPS) is not enabled on this gateway.",
            recommendation=(
                "Enable IDS/IPS at the 'Security' or 'Balanced' level. Review "
                "categories to match your profile. Monitor alerts for 1-2 weeks "
                "then tune. Your gateway supports line-rate IDS/IPS with "
                "minimal performance impact."
            ),
            intent_question="Should IDS/IPS be turned on?",
            maps_to={"cis_v8": "13.3", "nist_csf": "DE.CM-1"},
            effort="quick",
            impact="medium",
        ))

    port_forwards = _get_collection(colls, "portforward")
    active_forwards = [p for p in port_forwards if p.get("enabled")]
    if active_forwards:
        findings.append(Finding(
            id="FW-002",
            section="Firewall",
            severity="info",
            status="recommendation",
            title=f"{len(active_forwards)} port forward(s) active",
            current_state=(
                f"{len(active_forwards)} port forwards are enabled, exposing "
                "internal services to the internet."
            ),
            recommendation=(
                "Review each forward. For each, confirm: the service is "
                "patched, reachable-only-by-needed-sources (allowlist), and "
                "not a management interface. Prefer VPN for admin access."
            ),
            intent_question="Want to review each port forward individually?",
            maps_to={"cis_v8": "4.4", "nist_csf": "PR.AC-5"},
            effort="medium",
            impact="high",
            evidence={"count": len(active_forwards)},
        ))

    if mgmt.get("upnp_enabled"):
        findings.append(Finding(
            id="FW-003",
            section="Firewall",
            severity="medium",
            status="recommendation",
            title="UPnP is enabled",
            current_state=(
                "UPnP lets applications open inbound ports automatically, "
                "without your approval or visibility."
            ),
            recommendation=(
                "Disable UPnP. Manually configure port forwards for specific "
                "games/apps that need them. Review regularly."
            ),
            intent_question="Do you need UPnP for a specific application (e.g., certain games)?",
            maps_to={"cis_v8": "4.4"},
            effort="quick",
            impact="medium",
        ))

    return findings


def find_wifi(colls: dict) -> list[Finding]:
    """Section 6: Wi-Fi."""
    findings = []
    wlans = _get_collection(colls, "wlanconf")

    for w in wlans:
        if not w.get("enabled"):
            continue
        name = w.get("name", "<unnamed>")
        security = w.get("security", "")
        wpa_mode = w.get("wpa_mode", "")
        if security == "wpapsk" and wpa_mode == "wpa2":
            findings.append(Finding(
                id=f"WIFI-{name}-001",
                section="Wi-Fi",
                severity="low",
                status="recommendation",
                title=f"SSID '{name}' is WPA2-only",
                current_state=f"SSID '{name}' uses WPA2-PSK only. WPA3 offers stronger protection against offline attacks.",
                recommendation=(
                    "Switch to WPA2/WPA3 mixed mode for compatibility, or "
                    "WPA3-only if all your clients support it. Keep WPA2 only "
                    "on IoT SSIDs where devices can't do WPA3."
                ),
                intent_question=f"Do any clients on '{name}' require WPA2-only?",
                maps_to={"cis_v8": "12.5"},
                effort="quick",
                impact="low",
            ))

        psk = w.get("x_passphrase", "")
        if isinstance(psk, str) and len(psk) < 12:
            findings.append(Finding(
                id=f"WIFI-{name}-002",
                section="Wi-Fi",
                severity="high",
                status="gap",
                title=f"SSID '{name}' has a short passphrase",
                current_state=f"SSID '{name}' passphrase is {len(psk)} characters. Short PSKs are vulnerable to offline dictionary attacks.",
                recommendation="Use a passphrase of at least 16 characters with mixed case, numbers, and symbols.",
                intent_question=f"Can you set a stronger passphrase on '{name}'?",
                maps_to={"cis_v8": "5.2"},
                effort="quick",
                impact="high",
            ))

    return findings


# Stubs for remaining sections. Real implementation fills these in.
def find_remote_access(colls: dict) -> list[Finding]: return []
def find_logging(colls: dict) -> list[Finding]: return []
def find_backup_config(colls: dict) -> list[Finding]: return []
def find_firmware(colls: dict) -> list[Finding]: return []


# =============================================================================
# 5. HELPERS
# =============================================================================

def _get_collection(colls: dict, name: str) -> list[dict]:
    """Return the named collection, handling both inline and per-file backup formats."""
    if name in colls:
        return colls[name]
    # Fallback: filter from _all if present
    if "_all" in colls:
        return [
            d for d in colls["_all"]
            if d.get("_type") == name or d.get("collection") == name
        ]
    return []


def _get_setting(colls: dict, key: str) -> dict | None:
    """Fetch a setting sub-document by key (settings collection is keyed by type)."""
    for s in _get_collection(colls, "setting"):
        if s.get("key") == key:
            return s
    return None


# =============================================================================
# 6. ORCHESTRATION
# =============================================================================

FINDING_MODULES = [
    find_admin,
    find_segmentation,
    find_firewall,
    find_wifi,
    find_remote_access,
    find_logging,
    find_backup_config,
    find_firmware,
]


def analyze(unf_path: Path, redact_pii: bool = False) -> dict:
    """Full analysis pipeline. Returns a dict with findings and metadata."""
    zip_bytes = decrypt_unf(unf_path)
    raw_collections = extract_collections(zip_bytes)
    clean = sanitize(raw_collections, redact_pii=redact_pii)

    all_findings: list[Finding] = []
    for module in FINDING_MODULES:
        try:
            all_findings.extend(module(clean))
        except Exception as e:
            # Don't let one module crash the whole analysis
            print(f"[warn] {module.__name__} failed: {e}", file=sys.stderr)

    # Sort: severity first (critical top), then section
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.section))

    return {
        "source": str(unf_path),
        "finding_count": len(all_findings),
        "by_severity": _count_by(all_findings, "severity"),
        "findings": [asdict(f) for f in all_findings],
    }


def _count_by(findings: list[Finding], attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        k = getattr(f, attr)
        out[k] = out.get(k, 0) + 1
    return out


def render_markdown(result: dict) -> str:
    """Turn the result dict into a readable markdown report."""
    lines = ["# UniFi Security Advisor Report", ""]
    lines.append(f"**Source:** `{result['source']}`  ")
    lines.append(f"**Findings:** {result['finding_count']}  ")
    lines.append(f"**Severity breakdown:** {result['by_severity']}")
    lines.append("")

    for f in result["findings"]:
        lines.append(f"## [{f['severity'].upper()}] {f['title']}")
        lines.append(f"*{f['section']} / {f['id']}*")
        lines.append("")
        lines.append(f"**Found:** {f['current_state']}")
        lines.append("")
        if f.get("recommendation"):
            lines.append(f"**Recommend:** {f['recommendation']}")
            lines.append("")
        if f.get("intent_question"):
            lines.append(f"**Confirm intent:** {f['intent_question']}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# =============================================================================
# 7. CLI
# =============================================================================

def main():
    p = argparse.ArgumentParser(prog="usa", description="UniFi Security Advisor")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="Analyze a .unf backup file")
    a.add_argument("path", type=Path)
    a.add_argument("--out", type=Path, default=Path("report.md"))
    a.add_argument("--json", type=Path, help="Also write JSON output")
    a.add_argument("--redact-pii", action="store_true")

    args = p.parse_args()
    if args.cmd == "analyze":
        result = analyze(args.path, redact_pii=args.redact_pii)
        args.out.write_text(render_markdown(result))
        print(f"Wrote {args.out} with {result['finding_count']} findings")
        if args.json:
            args.json.write_text(json.dumps(result, indent=2, default=str))
            print(f"Wrote {args.json}")


if __name__ == "__main__":
    main()
