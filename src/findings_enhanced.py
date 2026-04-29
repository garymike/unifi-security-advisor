"""
Enhanced findings modules for the UniFi security audit.

All functions accept a NormalizedSite (src/normalize.py) as their first argument.
"""

from __future__ import annotations


# =============================================================================
# NEW: Wireless tuning (Section 6.5)
# =============================================================================

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


# =============================================================================
# ENHANCED: VPN and remote access (Section 8)
# =============================================================================

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


# =============================================================================
# ENHANCED: Firewall (split geo/content/safe-search)
# =============================================================================

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
                if direction_hint in d or direction_hint.lower() in name:
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


# =============================================================================
# ENHANCED: Backup (tested restore, destination diversity)
# =============================================================================

def find_backup_config(site, profile: str = "home_office") -> list:
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
