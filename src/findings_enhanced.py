"""
Enhanced findings modules addressing the 10-point coverage gaps.

Drop-in replacement/addition for the stub modules in parser.py.
Imports and helpers assumed available from parser.py.
"""

from __future__ import annotations
from typing import Any
# from parser import Finding, _get_collection, _get_setting  # in real build


# =============================================================================
# NEW: Wireless tuning (Section 6.5)
# =============================================================================

def find_wireless_tuning(colls: dict) -> list:
    """Per-AP radio tuning: TX power, unused bands, rogue AP detection, fast roaming."""
    from parser import Finding, _get_collection, _get_setting

    findings = []
    devices = [d for d in _get_collection(colls, "device") if d.get("type") == "uap"]

    # --- TX power audit per AP per radio ---
    for d in devices:
        ap_name = d.get("name") or d.get("mac", "unnamed")
        for r in d.get("radio_table", []):
            band = r.get("radio", "unknown")  # ng | na | 6e
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
                        "opportunistic attacks from parking lots, neighboring units, and "
                        "drive-by reconnaissance."
                    ),
                    recommendation=(
                        "Set TX power to Auto (default) or Medium for typical indoor use. "
                        "Use WiFiman or a WiFi analyzer to confirm coverage does not bleed "
                        "meaningfully past your property line. Exception: intentional outdoor "
                        "or large-property coverage."
                    ),
                    intent_question="Is extended coverage deliberate (outdoor, large property, neighbor sharing)?",
                    maps_to={"cis_v8": "12.5", "nist_csf": "PR.PT-4"},
                    effort="quick",
                    impact="low",
                ))

    # --- 2.4 GHz radio audit ---
    aps_with_24 = [
        d for d in devices
        if any(r.get("radio") == "ng" and not r.get("disabled") for r in d.get("radio_table", []))
    ]
    if aps_with_24:
        # Count clients actually using 2.4 GHz at the time of backup
        clients = _get_collection(colls, "user")
        clients_on_24 = sum(1 for c in clients if c.get("radio") == "ng")
        total_wifi_clients = sum(1 for c in clients if c.get("radio"))

        findings.append(Finding(
            id="RF-BAND-24GHZ",
            section="Wireless tuning",
            severity="info",
            status="recommendation",
            title="2.4 GHz radio active across AP(s)",
            current_state=(
                f"{len(aps_with_24)} AP(s) have 2.4 GHz enabled. At last backup, "
                f"{clients_on_24} of {total_wifi_clients} Wi-Fi clients were using 2.4 GHz. "
                "2.4 GHz is the most crowded, most attacked, and oldest Wi-Fi band. "
                "It's also where most cheap IoT connects."
            ),
            recommendation=(
                "Identify which specific devices need 2.4 GHz. If few/none do, disable the "
                "2.4 GHz radio to shrink attack surface. If some IoT requires it, put those "
                "devices on a dedicated IoT SSID mapped to a restricted VLAN - then you can "
                "disable 2.4 GHz on the main SSID while keeping it for IoT only."
            ),
            intent_question="Do you have devices that truly require 2.4 GHz? Which ones?",
            maps_to={"cis_v8": "12.5"},
            effort="medium",
            impact="medium",
            evidence={"aps_24ghz": len(aps_with_24), "clients_24ghz": clients_on_24, "total_wifi": total_wifi_clients},
        ))

    # --- Rogue AP detection ---
    rogue_setting = _get_setting(colls, "rogueap") or {}
    if not rogue_setting.get("report_rogue"):
        findings.append(Finding(
            id="RF-ROGUE-001",
            section="Wireless tuning",
            severity="medium",
            status="gap",
            title="Rogue AP detection not enabled",
            current_state=(
                "Rogue AP reporting is disabled. If someone nearby sets up a fake version "
                "of your SSID to capture credentials (evil twin attack), your controller "
                "will not notice or alert."
            ),
            recommendation=(
                "Enable Rogue AP Detection in Settings > WiFi > Advanced. Review the "
                "neighboring APs list monthly. Investigate anything broadcasting your "
                "SSID names that isn't yours."
            ),
            intent_question="Want rogue AP detection on? (no performance cost)",
            maps_to={"cis_v8": "12.6", "nist_csf": "DE.CM-7"},
            effort="quick",
            impact="medium",
        ))

    # --- PMF (Protected Management Frames) audit on WPA3 SSIDs ---
    for w in _get_collection(colls, "wlanconf"):
        if not w.get("enabled"):
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
                    f"SSID '{name}' has WPA3 enabled but Protected Management Frames "
                    "(PMF / 802.11w) is off. PMF is a WPA3 requirement that protects "
                    "management frames from deauthentication and disassociation attacks."
                ),
                recommendation=f"Set PMF to Required on '{name}' (WPA3 mandates it).",
                intent_question=None,
                maps_to={"cis_v8": "12.5"},
                effort="quick",
                impact="medium",
            ))

    return findings


# =============================================================================
# ENHANCED: VPN and remote access (Section 8)
# =============================================================================

def find_remote_access(colls: dict) -> list:
    """Remote access paths with opinionated protocol preference."""
    from parser import Finding, _get_collection, _get_setting

    findings = []

    # Check for PPTP (cryptographically broken)
    pptp = _get_setting(colls, "vpn_pptp") or _get_setting(colls, "pptp_server")
    if pptp and pptp.get("enabled"):
        findings.append(Finding(
            id="VPN-PPTP-001",
            section="Remote access",
            severity="critical",
            status="gap",
            title="PPTP VPN enabled (broken protocol)",
            current_state=(
                "PPTP is enabled as a VPN server. PPTP's authentication (MS-CHAPv2) is "
                "cryptographically broken; credentials and session traffic can be recovered "
                "by anyone on the path between the user and the server."
            ),
            recommendation=(
                "Disable PPTP immediately. Replace with WireGuard (preferred) or OpenVPN. "
                "All credentials that have ever been used over PPTP should be considered "
                "potentially compromised and rotated."
            ),
            intent_question=None,
            maps_to={"cis_v8": "4.4", "nist_csf": "PR.AC-3"},
            effort="quick",
            impact="high",
        ))

    # L2TP/IPsec - discouraged but functional
    l2tp = _get_setting(colls, "vpn_l2tp") or _get_setting(colls, "l2tp_server")
    wireguard = _get_setting(colls, "vpn_wireguard") or _get_setting(colls, "wireguard")
    openvpn = _get_setting(colls, "vpn_openvpn") or _get_setting(colls, "openvpn_server")

    if l2tp and l2tp.get("enabled") and not (wireguard or openvpn):
        findings.append(Finding(
            id="VPN-L2TP-001",
            section="Remote access",
            severity="medium",
            status="recommendation",
            title="L2TP/IPsec is the only VPN (consider WireGuard)",
            current_state=(
                "L2TP/IPsec is enabled as the only VPN. L2TP/IPsec works but is legacy: "
                "often blocked by hotel/public Wi-Fi (UDP 500/4500/1701), slower, and "
                "more complex than WireGuard."
            ),
            recommendation=(
                "Keep L2TP if specific clients require it, but add WireGuard as the "
                "primary VPN. WireGuard is dramatically faster, traverses NAT/firewalls "
                "more reliably, and has a smaller, modern codebase."
            ),
            intent_question="Do you have a client that specifically needs L2TP?",
            maps_to={"cis_v8": "4.4"},
            effort="medium",
            impact="medium",
        ))

    # Port forwards without VPN = exposure instead of secured remote
    port_forwards = [p for p in _get_collection(colls, "portforward") if p.get("enabled")]
    has_vpn = any((
        (wireguard and wireguard.get("enabled")),
        (openvpn and openvpn.get("enabled")),
        (l2tp and l2tp.get("enabled")),
    ))
    if port_forwards and not has_vpn:
        findings.append(Finding(
            id="VPN-MISSING-001",
            section="Remote access",
            severity="high",
            status="gap",
            title=f"{len(port_forwards)} services exposed to internet, no VPN configured",
            current_state=(
                f"{len(port_forwards)} port forwards expose internal services directly "
                "to the internet. No VPN is configured, suggesting these are the primary "
                "remote-access path."
            ),
            recommendation=(
                "Set up WireGuard VPN, then remove all port forwards that exist only for "
                "remote access. Port forwards should be reserved for services that must "
                "be public (rare in home/small-business)."
            ),
            intent_question="Are any of these port forwards for services that must be public-facing (vs. just your own remote access)?",
            maps_to={"cis_v8": "4.4", "nist_csf": "PR.AC-3"},
            effort="medium",
            impact="high",
        ))

    # Good path: WireGuard configured
    if wireguard and wireguard.get("enabled"):
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


# =============================================================================
# ENHANCED: Firewall (split geo/content/safe-search)
# =============================================================================

def find_firewall_threats(colls: dict) -> list:
    """Extends find_firewall with geo/content/safe-search split."""
    from parser import Finding, _get_collection, _get_setting

    findings = []

    # Geo-IP: check both directions
    rules = _get_collection(colls, "firewallrule")
    groups = {g.get("_id"): g for g in _get_collection(colls, "firewallgroup")}

    def _is_geo_rule(rule):
        for group_id_list in (rule.get("src_firewallgroup_ids", []), rule.get("dst_firewallgroup_ids", [])):
            for gid in group_id_list:
                g = groups.get(gid, {})
                if g.get("group_type", "").startswith("country") or "geo" in g.get("name", "").lower():
                    return True
        return False

    wan_in_geo = any(r for r in rules if r.get("ruleset") == "WAN_IN" and r.get("action") == "drop" and _is_geo_rule(r))
    wan_out_geo = any(r for r in rules if r.get("ruleset") == "WAN_OUT" and r.get("action") == "drop" and _is_geo_rule(r))

    if not wan_in_geo:
        findings.append(Finding(
            id="FW-GEO-IN",
            section="Firewall",
            severity="low",
            status="recommendation",
            title="No Geo-IP blocking on inbound WAN",
            current_state="No Geo-IP rule found blocking inbound traffic from high-risk regions.",
            recommendation=(
                "Block inbound connections from countries you have no business receiving "
                "traffic from. Common blocklist: CN, RU, KP, IR (adjust based on your context). "
                "Low false-positive rate for most users."
            ),
            intent_question="Do you expect inbound traffic from these regions?",
            maps_to={"cis_v8": "13.4"},
            effort="quick",
            impact="medium",
        ))

    if not wan_out_geo:
        findings.append(Finding(
            id="FW-GEO-OUT",
            section="Firewall",
            severity="low",
            status="recommendation",
            title="No Geo-IP blocking on outbound WAN (often overlooked)",
            current_state=(
                "No outbound Geo-IP rule found. Outbound geo-blocking is less common but "
                "valuable: a compromised device calling home to a C2 server in a blocked "
                "region will fail."
            ),
            recommendation="Consider outbound geo-blocking for the same regions you block inbound.",
            intent_question="Do any of your legitimate services talk to servers in high-risk regions?",
            maps_to={"cis_v8": "13.4"},
            effort="quick",
            impact="low",
        ))

    # Content filtering (DNS-based)
    dns_filter = _get_setting(colls, "dns_filtering") or _get_setting(colls, "content_filtering") or {}
    if not dns_filter.get("enabled"):
        findings.append(Finding(
            id="FW-CONTENT-001",
            section="Firewall",
            severity="medium",
            status="recommendation",
            title="Content filtering not configured",
            current_state=(
                "DNS-based content filtering is off. No automatic blocking of malware "
                "domains, C2 infrastructure, or phishing sites at the DNS layer."
            ),
            recommendation=(
                "Enable Content Filtering with the Security category at minimum. This blocks "
                "known-malicious domains for every device without per-device config. Add the "
                "Family category if your household includes children. Content filtering is "
                "DNS-based, so it's visible (blocked pages show as errors) rather than hidden."
            ),
            intent_question="Should the network block known-malicious domains for all devices automatically?",
            maps_to={"cis_v8": "9.3", "nist_csf": "PR.PT-4"},
            effort="quick",
            impact="medium",
        ))

    return findings


# =============================================================================
# ENHANCED: Firmware (4 domains, EOL, CVE)
# =============================================================================

# Minimal EOL lookup; expand with a real dataset in production.
EOL_MODELS = {
    "UAP-AC-LITE": {"status": "eol", "eol_date": "2024-04-30"},
    "UAP-AC-LR": {"status": "eol", "eol_date": "2024-04-30"},
    "UAP-AC-PRO": {"status": "eol", "eol_date": "2024-04-30"},
    "USG": {"status": "eol", "eol_date": "2024-04-30"},
    "USG-PRO-4": {"status": "eol", "eol_date": "2025-04-30"},
    "UCK": {"status": "eol", "eol_date": "2022-12-31"},
    "UCK-G2": {"status": "eol_warning", "eol_date": "2026-12-31"},
}


def find_firmware(colls: dict) -> list:
    """Firmware currency, update domain audit, EOL, known-vulnerable."""
    from parser import Finding, _get_collection, _get_setting

    findings = []
    devices = _get_collection(colls, "device")

    # Auto-update toggle
    auto_update = _get_setting(colls, "auto_update") or {}
    if not auto_update.get("enabled"):
        findings.append(Finding(
            id="FW-AUTO-001",
            section="Firmware",
            severity="medium",
            status="gap",
            title="Automatic firmware updates disabled",
            current_state="Devices do not auto-update firmware within a maintenance window.",
            recommendation=(
                "Enable automatic firmware updates in a maintenance window (e.g., 03:00-05:00). "
                "Ubiquiti regularly ships security patches; delayed patching leaves known "
                "vulnerabilities exposed."
            ),
            intent_question="Any reason to hold back updates (specific firmware quirk, testing)?",
            maps_to={"cis_v8": "7.3", "nist_csf": "PR.IP-12"},
            effort="quick",
            impact="medium",
        ))

    # EOL hardware
    eol_devices = []
    for d in devices:
        model = d.get("model", "").upper()
        if model in EOL_MODELS:
            eol_devices.append({
                "name": d.get("name", d.get("mac")),
                "model": model,
                "status": EOL_MODELS[model]["status"],
                "eol_date": EOL_MODELS[model]["eol_date"],
            })

    if eol_devices:
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
                    f"{eol_count} device(s) are past Ubiquiti's end-of-support date. "
                    "These devices no longer receive security patches, even for severe vulnerabilities."
                ),
                recommendation=(
                    "Plan replacement for EOL devices. Budget-conscious path: prioritize "
                    "devices that face the internet (gateway, edge APs) first; interior "
                    "switches can be replaced on a longer timeline."
                ),
                intent_question="What's your replacement budget and timeline?",
                maps_to={"cis_v8": "7.3", "nist_csf": "PR.IP-12"},
                effort="project",
                impact="high",
                evidence={"devices": eol_devices},
            ))

        if warning_count:
            findings.append(Finding(
                id="FW-EOL-002",
                section="Firmware",
                severity="medium",
                status="recommendation",
                title=f"{warning_count} device(s) approaching EOL",
                current_state=f"{warning_count} device(s) will reach end-of-support within 12 months.",
                recommendation="Start planning replacements during your normal refresh cycle.",
                intent_question="Is hardware refresh on your roadmap?",
                effort="project",
                impact="medium",
                evidence={"devices": [d for d in eol_devices if d["status"] == "eol_warning"]},
            ))

    # Stale firmware check (simplified: flag anything clearly behind a reasonable threshold)
    # Real implementation: maintain a current_version_per_model.json
    for d in devices:
        ver = d.get("version", "")
        # This is placeholder logic; real version cross-ref needs a maintained dataset
        if ver and "." in ver:
            # Example: flag if version starts with 6.x or lower (very outdated)
            try:
                major = int(ver.split(".")[0])
                if major < 7:
                    findings.append(Finding(
                        id=f"FW-VER-{d.get('mac', 'x')}",
                        section="Firmware",
                        severity="high",
                        status="gap",
                        title=f"Device '{d.get('name', d.get('mac'))}' on major version behind",
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


# =============================================================================
# ENHANCED: Logging with privacy-aware retention
# =============================================================================

RETENTION_PROFILES = {
    "home": {"traffic_days": (7, 14), "admin_days": (30, 30)},
    "home_office": {"traffic_days": (14, 30), "admin_days": (90, 90)},
    "small_business": {"traffic_days": (30, 90), "admin_days": (365, 365)},
    "regulated_hipaa": {"traffic_days": (2190, 2190), "admin_days": (2190, 2190)},
    "regulated_pci": {"traffic_days": (365, 365), "admin_days": (365, 365)},
}


def find_logging(colls: dict, profile: str = "home_office") -> list:
    """Privacy-aware logging findings."""
    from parser import Finding, _get_collection, _get_setting

    findings = []
    mgmt = _get_setting(colls, "mgmt") or {}
    dpi = _get_setting(colls, "dpi") or {}

    syslog_configured = mgmt.get("syslog_host") or mgmt.get("advanced_feature_enabled")
    retention_profile = RETENTION_PROFILES.get(profile, RETENTION_PROFILES["home_office"])

    # Syslog not forwarding
    if not syslog_configured:
        findings.append(Finding(
            id="LOG-FWD-001",
            section="Logging",
            severity="low" if profile.startswith("home") else "medium",
            status="recommendation",
            title="Logs not forwarded to external destination",
            current_state="All logs live only on the gateway. Gateway loss = log loss.",
            recommendation=(
                f"For a {profile.replace('_', ' ')} profile, forward syslog to an "
                f"external destination. Retention target: {retention_profile['admin_days'][0]} days "
                "minimum. Options: syslog receiver on your NAS, a cloud SIEM, or a small "
                "log-receiver VM."
            ),
            intent_question="Do you want to set up external log storage?",
            maps_to={"cis_v8": "8.2", "nist_csf": "DE.AE-3"},
            effort="medium",
            impact="medium",
        ))

    # DPI client-level logging on home profile = privacy recommendation
    dpi_level = dpi.get("level", "disabled")
    if profile.startswith("home") and dpi_level in ("client", "fingerprint"):
        findings.append(Finding(
            id="LOG-PRIV-001",
            section="Logging",
            severity="low",
            status="recommendation",
            title="Client-level DPI logging may exceed household need",
            current_state=(
                f"DPI is set to '{dpi_level}', which retains per-client, per-application "
                "browsing metadata. For a home profile, this can be more detail than needed "
                "and creates privacy exposure if the backup or controller is compromised."
            ),
            recommendation=(
                "Consider aggregate/protocol-only DPI for a home network. Full client DPI "
                "is more appropriate for business or regulated environments where the "
                "detailed audit trail justifies the privacy cost."
            ),
            intent_question="Do you actively use the per-client DPI views for troubleshooting or monitoring?",
            maps_to={"nist_csf": "PR.DS-5"},
            effort="quick",
            impact="low",
        ))

    return findings


# =============================================================================
# ENHANCED: Backup (tested restore, destination diversity)
# =============================================================================

def find_backup_config(colls: dict) -> list:
    from parser import Finding, _get_collection, _get_setting

    findings = []
    auto_backup = _get_setting(colls, "auto_backup") or {}

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
        return findings  # No point in checking retention/destination if disabled

    # Destination diversity
    destination = auto_backup.get("destination", "local")
    if destination == "local":
        findings.append(Finding(
            id="BAK-002",
            section="Backup",
            severity="medium",
            status="gap",
            title="Backups stored only on the gateway itself",
            current_state=(
                "Auto-backups are saved only to the gateway. If the gateway is lost "
                "(hardware failure, theft, or worst case, ransomware against the device), "
                "the backups go with it."
            ),
            recommendation=(
                "Add an off-device destination. Options: (1) UniFi cloud backup (linked "
                "to your SSO account), (2) SMB share on one of your NAS devices, (3) "
                "periodic manual download to a laptop. Rule of 3-2-1: 3 copies, 2 "
                "different media, 1 offsite."
            ),
            intent_question="Which off-device option fits your setup best?",
            maps_to={"cis_v8": "11.3"},
            effort="medium",
            impact="medium",
        ))

    # Tested-restore (always flags; user confirms in gap questions)
    findings.append(Finding(
        id="BAK-003",
        section="Backup",
        severity="medium",
        status="unknown",
        title="Backup restore not verified (Schrödinger backup)",
        current_state=(
            "The backup file exists and automatic backups are running. But without a "
            "tested restore, the backup's viability is unknown. A backup that has never "
            "been restored is only hypothetically useful."
        ),
        recommendation=(
            "Schedule a quarterly restore test to a lab/throwaway controller or to a "
            "second gateway if you have one. At minimum: decrypt and open the backup "
            "file with an offline tool once a year to confirm it's parseable."
        ),
        intent_question="Have you ever restored this backup, and when?",
        maps_to={"cis_v8": "11.5", "nist_csf": "PR.IP-4"},
        effort="medium",
        impact="high",
    ))

    return findings
