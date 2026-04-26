#!/usr/bin/env python3
"""
Ubiquiti Security Advisor - Local Audit Script
================================================

Runs entirely on your machine. Your API key never leaves your environment.

SETUP
-----
    # 1. Install dependencies
    pip install requests

    # 2. Set environment variables (NEVER paste key as a CLI arg)
    export UNIFI_API_KEY='<your-key-here>'
    export UNIFI_HOST='192.168.1.1'        # your controller IP/hostname

    # 3. Run
    python3 unifi_audit.py

    # 4. Review outputs in ./audit_output/
    # 5. Revoke the API key in Site Manager

OUTPUTS
-------
    audit_output/
      raw_sanitized.json      # All API responses, secrets redacted
      findings.json           # Structured findings
      report.md               # Human-readable report
      audit.log               # Log of API calls made (no secrets)

SECURITY PROPERTIES
-------------------
- API key read only from environment variable UNIFI_API_KEY
- Never logged, never in output files, never in exception text
- Only transmitted to the UniFi controller itself (no telemetry, no cloud relay)
- Script makes only GET requests (read-only)
- PSKs, passwords, shared secrets are hashed to fingerprints before output
- SSL verification: on by default for Site Manager, off by default for local
  (UniFi uses self-signed certs locally; override with UNIFI_VERIFY_SSL=true)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import requests
    from requests.exceptions import RequestException
    from urllib3.exceptions import InsecureRequestWarning
except ImportError:
    sys.stderr.write("Missing dependency. Run: pip install requests\n")
    sys.exit(1)

try:
    from sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize  # script mode
except ImportError:
    from src.sanitizer import SECRET_FIELD_NAMES, _fingerprint, sanitize  # package mode

try:
    from profile_weights import score_finding, KNOWN_PROFILES  # script mode
except ImportError:
    from src.profile_weights import score_finding, KNOWN_PROFILES  # package mode

try:
    from api_to_collections import build_parser_collections  # script mode
    from findings_enhanced import (  # script mode
        find_wireless_tuning,
        find_firewall_threats,
        find_remote_access as find_remote_access_enhanced,
        find_firmware,
        find_logging,
        find_backup_config,
    )
    from findings_correlations import CORRELATION_RULES  # script mode
except ImportError:
    from src.api_to_collections import build_parser_collections  # package mode
    from src.findings_enhanced import (  # package mode
        find_wireless_tuning,
        find_firewall_threats,
        find_remote_access as find_remote_access_enhanced,
        find_firmware,
        find_logging,
        find_backup_config,
    )
    from src.findings_correlations import CORRELATION_RULES  # package mode


# =============================================================================
# CONFIGURATION
# =============================================================================

OUTPUT_DIR = Path("./audit_output")

# Candidate endpoints. Script probes each; gracefully skips any that 404.
# Written defensively because the Network Integration API schema is evolving.
ENDPOINTS_LOCAL = [
    ("info", "/proxy/network/integration/v1/info"),
    ("sites", "/proxy/network/integration/v1/sites"),
]

SITE_SCOPED_LOCAL = [
    ("devices", "/proxy/network/integration/v1/sites/{site_id}/devices"),
    ("clients", "/proxy/network/integration/v1/sites/{site_id}/clients"),
    ("wlans", "/proxy/network/integration/v1/sites/{site_id}/wlans"),
    ("firewall_policies", "/proxy/network/integration/v1/sites/{site_id}/firewall-policies"),
    ("firewall_zones", "/proxy/network/integration/v1/sites/{site_id}/firewall-zones"),
    ("port_forwards", "/proxy/network/integration/v1/sites/{site_id}/port-forwards"),
    ("vpn_configs", "/proxy/network/integration/v1/sites/{site_id}/vpn-configs"),
    ("networks", "/proxy/network/integration/v1/sites/{site_id}/networks"),
    ("traffic_routes", "/proxy/network/integration/v1/sites/{site_id}/traffic-routes"),
]

# Site Manager (cloud) endpoints, for when unified keys are used.
ENDPOINTS_CLOUD = [
    ("hosts", "https://api.ui.com/v1/hosts"),
    ("cloud_sites", "https://api.ui.com/v1/sites"),
    ("cloud_devices", "https://api.ui.com/v1/devices"),
]

# Always-float-to-top finding IDs (D-02, C-finding-002, REQ-always-float-to-top-overrides).
# Any finding whose id startswith one of these strings is reordered to the top of the
# report regardless of its severity/effort/profile-weight score.
#
# - VPN-PPTP-001:      PPTP enabled (cryptographically broken); detected by enhanced module
# - SEG-001:           Flat network with no segmentation; detected by baseline module
# - FW-EOL-001:        Firmware on EOL hardware; detected by enhanced module
# - MFA-UNKNOWN-001:   API cannot detect MFA state — emit unknown Finding (D-03)
# - CRED-DEFAULT-001:  API cannot detect default credentials — emit unknown Finding (D-03)
# - WAN-MGMT-001:      API cannot detect WAN-reachable management — emit unknown Finding (D-03)
ALWAYS_TOP_FINDING_IDS: frozenset = frozenset({
    "VPN-PPTP-001",
    "SEG-001",
    "FW-EOL-001",
    "MFA-UNKNOWN-001",
    "CRED-DEFAULT-001",
    "WAN-MGMT-001",
})


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class Finding:
    id: str
    section: str
    severity: str  # info | low | medium | high | critical
    status: str    # ok | gap | recommendation | unknown
    title: str
    current_state: str
    recommendation: str | None = None
    intent_question: str | None = None
    evidence: dict = field(default_factory=dict)
    maps_to: dict = field(default_factory=dict)
    effort: str = "medium"
    impact: str = "medium"


# =============================================================================
# CREDENTIAL LOADING
# =============================================================================

def load_config() -> dict:
    """Load config from environment only. Never from CLI args."""
    key = os.environ.get("UNIFI_API_KEY", "").strip()
    if not key:
        sys.stderr.write(
            "Error: UNIFI_API_KEY environment variable not set.\n"
            "Export your key with: export UNIFI_API_KEY='<key>'\n"
        )
        sys.exit(1)

    host = os.environ.get("UNIFI_HOST", "").strip()
    use_cloud = os.environ.get("UNIFI_USE_CLOUD", "").lower() in ("1", "true", "yes")
    if not host and not use_cloud:
        sys.stderr.write(
            "Error: UNIFI_HOST not set (and UNIFI_USE_CLOUD not enabled).\n"
            "For local auditing:  export UNIFI_HOST='192.168.1.1'\n"
            "For cloud auditing:  export UNIFI_USE_CLOUD=true\n"
        )
        sys.exit(1)

    verify_env = os.environ.get("UNIFI_VERIFY_SSL", "").lower()
    if verify_env in ("1", "true", "yes"):
        verify_ssl = True
    elif verify_env in ("0", "false", "no"):
        verify_ssl = False
    else:
        # Sensible default: verify cloud, skip for local self-signed
        verify_ssl = use_cloud

    profile = os.environ.get("UNIFI_PROFILE", "home_office").strip()
    if profile not in KNOWN_PROFILES:
        sys.stderr.write(
            f"Warning: UNIFI_PROFILE='{profile}' is not a recognized profile. "
            f"Known: {sorted(KNOWN_PROFILES)}. Falling back to 'home_office'.\n"
        )
        profile = "home_office"

    return {
        "key": key,
        "host": host,
        "use_cloud": use_cloud,
        "verify_ssl": verify_ssl,
        "profile": profile,
    }


# =============================================================================
# AUDIT-TRAIL LOGGING (no secrets in log)
# =============================================================================

def setup_logger(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("unifi_audit")
    logger.setLevel(logging.INFO)
    # Clean old handlers if re-run in same process
    for h in list(logger.handlers):
        logger.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


# =============================================================================
# SANITIZATION
# =============================================================================
# SECRET_FIELD_NAMES, _fingerprint, and sanitize are imported from src/sanitizer.py


# =============================================================================
# API CLIENT (read-only, no key leakage)
# =============================================================================

class UniFiClient:
    """Minimal read-only client. Key is held in memory only for the run."""

    def __init__(self, cfg: dict, logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        self.session = requests.Session()
        # X-API-KEY header, never logged
        self.session.headers.update({
            "X-API-KEY": cfg["key"],
            "Accept": "application/json",
        })
        self.session.verify = cfg["verify_ssl"]
        if not cfg["verify_ssl"]:
            # Only silence verification warning if user explicitly opted in
            # (or is using local self-signed, the default).
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _base_url(self) -> str:
        if self.cfg["use_cloud"]:
            return "https://api.ui.com"
        host = self.cfg["host"]
        if not host.startswith("http"):
            host = f"https://{host}"
        return host

    def get(self, path: str) -> tuple[int, Any]:
        """GET a path or absolute URL. Returns (status_code, json_or_text)."""
        url = path if path.startswith("http") else f"{self._base_url()}{path}"
        # Log URL but never the key
        self.logger.info(f"GET {url}")
        try:
            r = self.session.get(url, timeout=30)
        except RequestException as e:
            # Scrub exception text for anything that looks like the key
            safe_msg = str(e).replace(self.cfg["key"], "<REDACTED>")
            self.logger.error(f"Request failed: {safe_msg}")
            return 0, {"error": safe_msg}
        self.logger.info(f"  -> {r.status_code} ({len(r.content)} bytes)")
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {"non_json_response": r.text[:500]}

    def close(self):
        """Clear session state. Key is dropped when the process exits anyway."""
        self.session.close()


# =============================================================================
# COLLECTION PHASE: pull everything we can
# =============================================================================

def collect_all(client: UniFiClient, logger: logging.Logger) -> dict:
    """Enumerate sites, then pull per-site data. Gracefully skip 404s."""
    collected: dict[str, Any] = {"_endpoints_probed": [], "_errors": []}

    if client.cfg["use_cloud"]:
        # Site Manager / cloud path
        for name, url in ENDPOINTS_CLOUD:
            status, data = client.get(url)
            collected["_endpoints_probed"].append({"name": name, "url": url, "status": status})
            if status == 200:
                collected[name] = data
            elif status == 403:
                logger.warning(f"403 on {name}: key may lack scope for this endpoint")
                collected["_errors"].append({"endpoint": name, "status": 403, "hint": "insufficient scope"})
            elif status == 404:
                logger.info(f"404 on {name}: endpoint not present on this controller/version")
            else:
                collected["_errors"].append({"endpoint": name, "status": status})
    else:
        # Local Network Integration path
        for name, path in ENDPOINTS_LOCAL:
            status, data = client.get(path)
            collected["_endpoints_probed"].append({"name": name, "path": path, "status": status})
            if status == 200:
                collected[name] = data
            elif status == 404:
                logger.info(f"404 on {name}: endpoint not present (older Network version?)")
            elif status == 403:
                collected["_errors"].append({"endpoint": name, "status": 403, "hint": "key lacks scope"})
            else:
                collected["_errors"].append({"endpoint": name, "status": status})

        # Site-scoped: iterate sites
        site_list = _extract_sites(collected.get("sites", {}))
        collected["_site_count"] = len(site_list)
        for site in site_list:
            site_id = site.get("id") or site.get("_id") or site.get("name")
            if not site_id:
                continue
            site_key = f"site_{site_id}"
            collected[site_key] = {"_meta": site}
            for name, path_template in SITE_SCOPED_LOCAL:
                path = path_template.format(site_id=site_id)
                status, data = client.get(path)
                collected["_endpoints_probed"].append({
                    "name": f"{name}@{site_id}",
                    "path": path,
                    "status": status,
                })
                if status == 200:
                    collected[site_key][name] = data
                elif status == 404:
                    logger.info(f"404 on {name}@{site_id}")
                elif status == 403:
                    collected["_errors"].append({
                        "endpoint": f"{name}@{site_id}", "status": 403,
                        "hint": "key lacks scope"
                    })
                # Be gentle on the controller
                time.sleep(0.1)

    return collected


def _extract_sites(sites_response: Any) -> list[dict]:
    """Handle varying response shapes: {data:[...]}, [...], {sites:[...]}"""
    if isinstance(sites_response, dict):
        for key in ("data", "sites", "items"):
            if key in sites_response and isinstance(sites_response[key], list):
                return sites_response[key]
    if isinstance(sites_response, list):
        return sites_response
    return []


# =============================================================================
# FINDINGS PHASE: run analysis on sanitized data
# =============================================================================

def _emit_unknown_always_top() -> list[Finding]:
    """Emit 3 always-top Findings for risks the Network Integration API cannot detect.

    Per D-03 / D-10: render inline through render_report() like any other Finding.
    The intent_question field becomes the Phase 2 wizard input.
    """
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


def _apply_float_top(findings: list[Finding]) -> list[Finding]:
    """Reorder findings so any always-top finding appears before any non-always-top.

    Preserves relative order within each group. Idempotent.
    Match is by ``f.id.startswith(prefix)`` against ALWAYS_TOP_FINDING_IDS — this
    handles the per-site suffix pattern (e.g., 'SEG-001-default' starts with 'SEG-001').
    """
    def is_top(f: Finding) -> bool:
        return any(f.id.startswith(prefix) for prefix in ALWAYS_TOP_FINDING_IDS)

    top = [f for f in findings if is_top(f)]
    rest = [f for f in findings if not is_top(f)]
    return top + rest


def _correlate_findings(findings: list[Finding], profile: str, logger: logging.Logger) -> list[Finding]:
    """Run all compound-finding correlation rules over the current findings list.

    Returns NEW findings produced by the rules (does not mutate the input list).
    Each rule is wrapped in try/except so a single rule failure cannot abort
    the audit. Rules return Finding | None; None is filtered out.

    Args:
        findings: Current list of findings emitted by individual modules.
        profile: Audit profile string (e.g. ``"home_office"``).
        logger: Logger for warning on rule failure.

    Returns:
        List of new compound Finding objects (may be empty).
    """
    new: list[Finding] = []
    for rule in CORRELATION_RULES:
        try:
            result = rule(findings, profile)
        except Exception as e:
            logger.warning(f"Correlation rule {getattr(rule, '__name__', rule)} failed: {e}")
            continue
        if result is not None:
            new.append(result)
    return new


def analyze(clean: dict, profile: str, logger: logging.Logger) -> list[Finding]:
    """Run all 12 findings modules (6 baseline + 6 enhanced), then correlate.

    Each module is wrapped in try/except so one failure does not abort the audit.
    Enhanced modules receive the adapter output (parser-shape colls dict) rather
    than the raw clean dict. If the adapter itself fails, enhanced modules are
    skipped with a WARNING — the baseline modules still run.

    After individual modules complete, _correlate_findings() runs the compound
    rule pass (D-004) to detect cross-answer tensions. Correlation findings are
    appended before the final severity sort.
    """
    findings: list[Finding] = []

    # --- Baseline modules: operate directly on the sanitized API response ---
    baseline_modules = [
        ("segmentation", _find_segmentation),
        ("wifi", _find_wifi),
        ("firewall", _find_firewall),
        ("remote_access", _find_remote_access),
        ("devices", _find_devices),
        ("api_coverage", _find_api_coverage),  # meta-finding on what we could/couldn't see
    ]
    for name, fn in baseline_modules:
        try:
            findings.extend(fn(clean, profile))
        except Exception as e:
            logger.warning(f"Module {name} failed: {e}")

    # --- Adapter: translate API shape → parser collection shape ---
    try:
        colls = build_parser_collections(clean)
    except Exception as e:
        logger.warning(f"Adapter build_parser_collections failed: {e}. Enhanced modules skipped.")
        colls = {}

    # --- Enhanced modules: operate on parser-shape colls dict via findings_enhanced.py ---
    # find_remote_access_enhanced is an alias for findings_enhanced.find_remote_access,
    # aliased at import time to avoid collision with the baseline _find_remote_access.
    # find_logging takes a second positional arg (profile) unlike the other enhanced modules.
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

    # --- Emit 3 unknown always-top Findings (D-03) BEFORE correlation so
    # keys-to-kingdom rule can see MFA-UNKNOWN-001 in the findings list ---
    findings.extend(_emit_unknown_always_top())

    # --- Correlation pass: compound rules run after individual modules, before sort ---
    correlation_findings = _correlate_findings(findings, profile, logger)
    findings.extend(correlation_findings)

    # Sort by severity then profile-weighted score (descending) then section.
    # score_finding returns higher values for higher priority — negate for descending sort.
    # _apply_float_top runs LAST so always-top findings bypass weight calculation (T-1-05).
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (
        order.get(f.severity, 5),
        -score_finding(f, profile),   # higher score first (descending)
        f.section,
    ))

    # --- Apply always-top override LAST (D-02) — overrides severity sort ---
    findings = _apply_float_top(findings)

    return findings


def _all_sites(clean: dict) -> list[tuple[str, dict]]:
    """Yield (site_id, site_data) for each site found."""
    out = []
    for key, val in clean.items():
        if key.startswith("site_") and isinstance(val, dict):
            out.append((key[5:], val))
    return out


def _find_segmentation(clean: dict, profile: str) -> list[Finding]:
    findings = []
    for site_id, site in _all_sites(clean):
        networks = _extract_list(site.get("networks"))
        if networks is None:
            continue
        user_nets = [n for n in networks if n.get("purpose") in ("corporate", "guest", "vlan-only")]
        if len(user_nets) <= 1:
            findings.append(Finding(
                id=f"SEG-001-{site_id}",
                section="Segmentation",
                severity="high",
                status="gap",
                title="Flat network (no segmentation)",
                current_state=(
                    f"Site has {len(user_nets)} user-defined network(s). "
                    "Devices share a broadcast domain; a compromise of any "
                    "device can reach any other."
                ),
                recommendation=(
                    "Create separate networks for main, IoT, guest, and management. "
                    "Map SSIDs to the appropriate VLANs. Enable Network Isolation "
                    "and Zone-Based Firewall rules."
                ),
                intent_question="Do you want to segment the network?",
                maps_to={"nist_csf": "PR.AC-5", "cis_v8": "12.2"},
                effort="project",
                impact="high",
                evidence={"network_count": len(user_nets)},
            ))
    return findings


def _find_wifi(clean: dict, profile: str) -> list[Finding]:
    findings = []
    for site_id, site in _all_sites(clean):
        wlans = _extract_list(site.get("wlans"))
        if wlans is None:
            continue
        for w in wlans:
            if not w.get("enabled", True):
                continue
            name = w.get("name", "<unnamed>")
            security = (w.get("security") or w.get("securityProtocol") or "").lower()
            if "wpa2" in security and "wpa3" not in security:
                findings.append(Finding(
                    id=f"WIFI-{site_id}-{name}-WPA",
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
            # PSK strength (we only see the fingerprint now, not the value)
            psk = w.get("x_passphrase")
            if isinstance(psk, dict) and psk.get("length", 0) < 12:
                findings.append(Finding(
                    id=f"WIFI-{site_id}-{name}-PSK",
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


def _find_firewall(clean: dict, profile: str) -> list[Finding]:
    findings = []
    for site_id, site in _all_sites(clean):
        port_forwards = _extract_list(site.get("port_forwards"))
        if port_forwards:
            active = [p for p in port_forwards if p.get("enabled", True)]
            if active:
                findings.append(Finding(
                    id=f"FW-{site_id}-PF",
                    section="Firewall",
                    severity="info",
                    status="recommendation",
                    title=f"{len(active)} port forward(s) active",
                    current_state=f"{len(active)} port forwards expose internal services.",
                    recommendation="Review each forward. Prefer VPN for admin access; use source IP allowlists for public services.",
                    intent_question="Want to review each port forward?",
                    maps_to={"cis_v8": "4.4"},
                    effort="medium",
                    impact="high",
                    evidence={"count": len(active)},
                ))
    return findings


def _find_remote_access(clean: dict, profile: str) -> list[Finding]:
    findings = []
    for site_id, site in _all_sites(clean):
        vpn_configs = _extract_list(site.get("vpn_configs"))
        port_forwards = _extract_list(site.get("port_forwards")) or []
        has_vpn = bool(vpn_configs) and any(v.get("enabled", True) for v in vpn_configs)
        has_forwards = any(p.get("enabled", True) for p in port_forwards)
        if has_forwards and not has_vpn:
            findings.append(Finding(
                id=f"VPN-MISSING-{site_id}",
                section="Remote access",
                severity="high",
                status="gap",
                title="Port forwards active without a configured VPN",
                current_state="Services exposed to the internet, no VPN configured for private access.",
                recommendation="Set up WireGuard VPN; remove port forwards that exist only for your own remote access.",
                intent_question="Are port forwards for public services, or for your remote access?",
                maps_to={"cis_v8": "4.4"},
                effort="medium",
                impact="high",
            ))
    return findings


def _find_devices(clean: dict, profile: str) -> list[Finding]:
    findings = []
    for site_id, site in _all_sites(clean):
        devices = _extract_list(site.get("devices"))
        if not devices:
            continue
        ssh_on = [d for d in devices if d.get("sshEnabled") or d.get("ssh_enabled")]
        if ssh_on:
            findings.append(Finding(
                id=f"DEV-SSH-{site_id}",
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
            ))
    return findings


def _find_api_coverage(clean: dict, profile: str) -> list[Finding]:
    """Meta-finding: document what we couldn't audit due to API gaps."""
    probed = clean.get("_endpoints_probed", [])
    missing = [p for p in probed if p.get("status") in (404, 0)]
    if missing:
        return [Finding(
            id="META-COVERAGE",
            section="Audit scope",
            severity="info",
            status="unknown",
            title=f"{len(missing)} endpoint(s) not accessible; audit scope limited",
            current_state=(
                f"{len(missing)} API endpoints returned 404 or failed. "
                "This may be due to Network version (need 9.3.43+), API scope, "
                "or endpoints not yet in the official integration API."
            ),
            recommendation="Update UniFi Network to latest stable. For endpoints not yet in the official API, consider the backup-file mode as a complement.",
            intent_question=None,
            maps_to={},
            effort="quick",
            impact="low",
            evidence={"missing": [p.get("name") for p in missing]},
        )]
    return []


# Module-level logger for _extract_list and other module-level helpers.
# setup_logger() configures the named logger "unifi_audit" at runtime;
# this fallback logger is used when _extract_list is called before setup_logger().
_logger = logging.getLogger("unifi_audit")


def _extract_list(data: Any) -> list | None:
    """Handle varying response shapes for list endpoints.

    Returns None for None input (existing call-sites treat None as "not present").
    Returns the list for bare-list input.
    Returns the list from known envelope keys: data, items, results.
    Logs a WARNING when a non-empty dict has none of the recognized keys (T-1-04).
    """
    if data is None:
        return None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "items", "results"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # Non-empty dict with no recognized list key: surface via WARN (T-1-04 mitigation)
        if data:
            _logger.warning(
                "_extract_list: no recognized list key in response. "
                "Keys present: %s. Returning None.",
                sorted(data.keys()),
            )
    return None


# =============================================================================
# REPORT GENERATION
# =============================================================================

def render_report(findings: list[Finding], clean: dict, profile: str) -> str:
    lines = ["# UniFi Security Advisor - Live Audit Report", ""]
    lines.append(f"**Profile:** {profile} (manual)")
    lines.append(
        "<sub>Manual profile per UNIFI_PROFILE env var. "
        "Auto-detection deferred to Phase 2 wizard (D-06).</sub>"
    )
    lines.append(f"**Findings:** {len(findings)}  ")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append(f"**By severity:** {counts}")
    lines.append("")
    lines.append(f"**Endpoints probed:** {len(clean.get('_endpoints_probed', []))}  ")
    lines.append(f"**Endpoint errors:** {len(clean.get('_errors', []))}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for f in findings:
        lines.append(f"## [{f.severity.upper()}] {f.title}")
        lines.append(f"*{f.section} / {f.id}*")
        lines.append("")
        lines.append(f"**Current state:** {f.current_state}")
        lines.append("")
        if f.recommendation:
            lines.append(f"**Recommend:** {f.recommendation}")
            lines.append("")
        if f.intent_question:
            lines.append(f"**Confirm intent:** {f.intent_question}")
            lines.append("")
        if f.maps_to:
            lines.append(f"**Maps to:** {', '.join(f'{k}:{v}' for k,v in f.maps_to.items())}")
            lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## Notes on what's in this report")
    lines.append("")
    lines.append("- All secrets (PSKs, shared secrets, passwords) were replaced with length + sha256 fingerprints before any output was written.")
    lines.append("- No API key was included in any output file or log.")
    lines.append("- Only GET (read-only) requests were made.")
    lines.append("- Safe to share this report with an MSP, paste into chat for discussion, or archive.")
    lines.append("")
    lines.append("## Next steps")
    lines.append("")
    lines.append("1. **Revoke the API key** at unifi.ui.com → Site Manager → API Keys.")
    lines.append("2. Review this report and decide which findings to act on.")
    lines.append("3. If you want me (Claude) to help you prioritize or plan remediation, paste this report into a chat - it contains no secrets.")
    return "\n".join(lines)


# =============================================================================
# MAIN
# =============================================================================

def main():
    cfg = load_config()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger = setup_logger(OUTPUT_DIR / "audit.log")
    logger.info("=" * 60)
    logger.info("UniFi Security Advisor - starting audit")
    logger.info(f"Mode: {'cloud (Site Manager)' if cfg['use_cloud'] else 'local'}")
    if not cfg["use_cloud"]:
        logger.info(f"Host: {cfg['host']}")
    logger.info(f"SSL verify: {cfg['verify_ssl']}")
    logger.info(f"Profile: {cfg['profile']}")
    logger.info("=" * 60)

    client = UniFiClient(cfg, logger)
    try:
        raw = collect_all(client, logger)
    finally:
        client.close()

    # Sanitize BEFORE writing anything to disk
    logger.info("Sanitizing collected data...")
    clean = sanitize(raw)

    # Write sanitized raw dump for inspection
    raw_path = OUTPUT_DIR / "raw_sanitized.json"
    raw_path.write_text(json.dumps(clean, indent=2, default=str))
    logger.info(f"Wrote {raw_path}")

    # Run findings
    logger.info("Running findings analysis...")
    findings = analyze(clean, cfg["profile"], logger)

    findings_path = OUTPUT_DIR / "findings.json"
    findings_path.write_text(json.dumps([asdict(f) for f in findings], indent=2))
    logger.info(f"Wrote {findings_path} ({len(findings)} findings)")

    # Report
    report_path = OUTPUT_DIR / "report.md"
    report_path.write_text(render_report(findings, clean, cfg["profile"]))
    logger.info(f"Wrote {report_path}")

    logger.info("")
    logger.info("=" * 60)
    logger.info("Done.")
    logger.info("=" * 60)
    logger.info(f"Findings: {len(findings)}")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            logger.info(f"  {sev}: {count}")
    logger.info("")
    logger.info("NEXT STEPS")
    logger.info("  1. Review report.md")
    logger.info("  2. Revoke the API key in Site Manager")
    logger.info("  3. (Optional) Share report.md in chat to discuss remediation")


if __name__ == "__main__":
    main()
