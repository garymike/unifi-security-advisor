# Coverage Check: 10 Video Points vs Current Design

Legend:
- ✅ Fully covered (questionnaire + parser finding module)
- 🟡 Partially covered (covered in one place, or at shallow depth)
- ❌ Missing or very thin

| # | Topic | Questionnaire | Parser findings module | Backup field source | Status |
|---|---|---|---|---|---|
| 1 | Firmware/console/app updates | Section 12 (Q12.1-12.4) | `find_firmware` (stub only) | `device.version`, `setting.auto_update` | 🟡 Questions exist, module is a stub |
| 2 | VLANs for internal/guest/IoT | Section 5 (Q5.1-5.7) | `find_segmentation` (implemented) | `networkconf` collection | ✅ Strong |
| 3 | SSID-to-VLAN mapping + WPA2/3 | Section 6 (Q6.1-6.7) | `find_wifi` (implemented) | `wlanconf.networkconf_id`, `wpa_mode` | ✅ Strong |
| 4 | Per-AP radio tuning (channel width, tx power, disabled radios) | Not in questionnaire | Not implemented | `device.radio_table[]` (available!) | ❌ Missing |
| 5 | IDS/IPS | Section 7 Q7.3 | `find_firewall` FW-001 | `setting.threat_management` | ✅ Strong |
| 6 | Region blocking + content filtering | Section 7 Q7.5, Q7.6 | `find_firewall` stub for content filter | `firewallrule` with geo groups, `setting.dpi` | 🟡 Geo yes, content filter needs module |
| 7 | Firewall zones and rules (least-privilege inter-VLAN) | Section 5 Q5.6, Section 7 Q7.1-7.2 | `find_firewall` (partial) | `firewallrule`, ZBF policies | 🟡 Existence checked, quality not audited |
| 8 | Automatic backups and tested restore | Section 10 Q10.1-10.5 | `find_backup_config` (stub only) | `setting.auto_backup` | 🟡 Questions exist, module is a stub |
| 9 | Traffic logging and retention | Section 9 Q9.1-9.5 | `find_logging` (stub only) | `setting.mgmt.syslog`, `setting.dpi.dpiLevel` | 🟡 Questions exist, module is a stub |
| 10 | VPN (WireGuard/OpenVPN preferred) for remote access | Section 8 Q8.1-8.5 | `find_remote_access` (stub only) | `setting.vpn_teleport`, WireGuard/OpenVPN/L2TP config | 🟡 Questions exist, module is a stub |

## Verdict

9 of 10 are covered at the questionnaire level, but most of those are unimplemented parser modules so far. **1 of 10 is missing entirely from the design: Point 4 (per-AP radio tuning).**

This isn't surprising. My original questionnaire was security-focused and skipped radio/RF tuning because it sits at the boundary of security and performance. But the video is right to include it, for reasons our current design under-weights:

- **Rogue AP / evil twin exposure** scales with transmit power. Broadcasting a high-power SSID past your property line invites opportunistic attacks.
- **Disabled radios** reduces attack surface. Every active radio is a wireless listener. If you don't need 2.4 GHz, turning it off removes a whole attack class (including legacy-protocol downgrade attacks that only exist on 2.4).
- **Neighbor/overlap attacks.** Poor channel selection makes deauth and jamming easier and harder to detect.
- **Client fingerprinting/tracking.** Excess radio coverage enables drive-by fingerprinting of your household's devices.

So this is legitimately a security concern, not just performance.

---

## New questions to add (Section 6 or new Section 6.5: Wireless Tuning)

### Questionnaire additions

| # | Guided voice | Standard voice | Pro voice |
|---|---|---|---|
| 6.8 | Do you have Wi-Fi bands you don't use? (e.g., no old devices = no 2.4 GHz needed) | Are unused bands disabled at the AP level? (2.4/5/6 GHz) | Per-radio enable_state audit; 2.4 GHz disable viability given client 802.11 version distribution |
| 6.9 | Does your Wi-Fi reach outside your home or office? | Is TX power tuned, or left at auto/high? | Radio TX power profile per AP; `min_rssi`; band-steering posture |
| 6.10 | Would you know if someone nearby set up a fake version of your Wi-Fi? | Is Rogue AP Detection on? Are neighbor APs reviewed? | `setting.rogueap`; recent rogue observations in `rogueap` collection |
| 6.11 | (Not asked at Guided level) | Is channel width set manually or auto? | Channel width per radio (20/40/80/160); channel plan; DFS exclusion list |
| 6.12 | (Not asked at Guided level) | Is fast roaming (802.11r) enabled where supported? | 802.11r/k/v enablement; minimum data rate floor; legacy rate support |

All of these are answerable from the backup: `device.radio_table[]` contains `radio` (ng/na/6e), `ht` (channel width), `channel`, `tx_power_mode`, `tx_power`, `min_rssi`, `min_rssi_enabled`. `wlanconf` has `fast_roaming_enabled`, `minrate_*`, `bss_transition`.

### New parser module

```python
def find_wireless_tuning(colls: dict) -> list[Finding]:
    """Section 6.5: per-AP radio tuning posture."""
    findings = []
    for device in _get_collection(colls, "device"):
        if device.get("type") != "uap":
            continue
        radios = device.get("radio_table", [])

        # TX power at high/auto on high-gain AP
        for r in radios:
            if r.get("tx_power_mode") == "high":
                findings.append(Finding(
                    id=f"RF-{device['mac']}-001",
                    section="Wireless tuning",
                    severity="low",
                    status="recommendation",
                    title=f"AP broadcasting at 'High' power on {r.get('radio')}",
                    current_state=(
                        f"AP '{device.get('name', device.get('mac'))}' has "
                        f"TX power set to 'High' on {r.get('radio')}. "
                        "High power extends coverage beyond your physical space, "
                        "inviting opportunistic attacks from outside."
                    ),
                    recommendation=(
                        "Set TX power to 'Auto' (default) or 'Medium' for typical "
                        "indoor deployments. Use a WiFi analyzer to confirm coverage "
                        "does not extend significantly past your property line."
                    ),
                    intent_question="Is the extended coverage necessary (e.g., outdoor use, large property)?",
                    maps_to={"cis_v8": "12.5", "nist_csf": "PR.PT-4"},
                    effort="quick",
                    impact="low",
                ))

        # 2.4 GHz still on: check if needed
        has_24 = any(r.get("radio") == "ng" and not r.get("disabled") for r in radios)
        if has_24:
            findings.append(Finding(
                id=f"RF-{device['mac']}-002",
                section="Wireless tuning",
                severity="info",
                status="recommendation",
                title="2.4 GHz radio is active",
                current_state="2.4 GHz is the oldest, most crowded, most attacked band. Still needed for old IoT and low-bandwidth devices.",
                recommendation=(
                    "Audit: which devices actually require 2.4 GHz? If none, "
                    "disable the 2.4 GHz radio to reduce attack surface. If some "
                    "need it, move them to a dedicated IoT SSID on a restricted VLAN."
                ),
                intent_question="Do you have devices that require 2.4 GHz, and are they isolated?",
                effort="medium",
                impact="medium",
            ))

        # Rogue AP detection state (setting, not device-level)
        # ... checks setting.rogueap.enabled

    return findings
```

### Output-report addition

New section in the report:

```
## Wireless tuning
- AP "Living Room" on High power → consider Medium or Auto
- 2.4 GHz active on 1 AP, 14 clients observed on 2.4 band (out of 47 total)
- 6 GHz enabled, WPA3 required → good
- Rogue AP detection: [enabled/disabled]
- Fast roaming: [enabled/disabled]
```

---

## Other additions worth making while we're here

Reviewing the 10 points surfaced some sharp edges the existing questionnaire is soft on:

### A. "Tested restore" deserves its own emphasis

Point 8 includes *review restore options so you can recover quickly*. Our question 10.2 asks "have you tested a restore" but treats it as a secondary prompt. Recommend promoting this: a backup that has never been restored is a Schrödinger backup. It may be fine; it may be unreadable; you won't know until the worst moment. Add a specific finding if `restore_last_tested` is unset (or always, since the backup itself doesn't track restore tests).

### B. VPN protocol preference

Point 10 specifically recommends *WireGuard or OpenVPN*. Our questionnaire lists those plus L2TP/Teleport without opinion. Recommend tiering:
- **Preferred**: WireGuard (modern, lean, fast)
- **Acceptable**: OpenVPN, Teleport
- **Discouraged**: L2TP/IPsec (known weaknesses), PPTP (broken)

New finding rule: if L2TP or PPTP is enabled, flag as HIGH. If WireGuard is available but not in use, recommend switching.

### C. Content filtering is a distinct question from Geo-IP

My original questionnaire treated these as one bucket. Point 6 separates them. Splitting:

- **Q7.5a** Geo-IP blocking state (WAN_IN and WAN_OUT separately)
- **Q7.5b** DNS-based content filtering (malware/ads/family)
- **Q7.5c** DPI categories active (social, gambling, streaming, etc., if user wants)

Also relevant for Point 6: **safe search**. UniFi can enforce Google/Bing/YouTube safe search. Not in my original design. Add as an optional question under a "household with children" branch.

### D. "Firmware is current" is different from "auto-update is on"

Point 1 asks about staying current. Our Section 12 covers auto-update toggle. But the backup has `device.version` which we can compare to the latest known-good version per model. Adding:

- Finding: *"N devices are more than X minor versions behind"* with per-device list
- Finding: *"No devices are on a known-vulnerable firmware"* (cross-reference UniFi security advisories, requires a small static CVE database)

### E. Traffic logging has an under-examined privacy dimension

Point 9 is about logging and retention. Our Section 9 captures this. But retention has a privacy flip side: detailed client-level logs are PII. A home user probably should NOT keep DPI client logs for 90 days. An enterprise with compliance obligations should. The advisor should recommend **less** logging for home users, not always more. Adding language to Section 9 recommendations that matches retention duration to compliance profile.

### F. UniFi console vs UniFi Network app updates are distinct

Point 1 mentions "console, apps, and device firmware" as separate. These are indeed separate update domains on UniFi OS:
- **UniFi OS** (the console itself)
- **UniFi Network** app version
- **UniFi Protect** app version (if installed)
- **UniFi Access** app version (if installed)
- **Per-device firmware**

The `.unifi` container includes UCore PostgreSQL which has these versions. The `.unf` (single-site) does not have OS or app versions, only device firmware. This is another reason to prioritize full `.unifi` parsing.

---

## Proposed design changes, summarized

1. **Add Section 6.5: Wireless Tuning** (5 new questions, new parser module). Fully derivable from backup.
2. **Promote "tested restore" to a standalone finding.** Change default severity to MEDIUM if untested.
3. **Add VPN protocol-preference logic** to the VPN findings module. Flag L2TP/PPTP, recommend WireGuard.
4. **Split content filtering from Geo-IP** in Section 7. Add safe-search sub-question.
5. **Add firmware-currency check** (device version vs known-current) to `find_firmware` module.
6. **Add privacy-aware logging recommendations** to `find_logging` module.
7. **Audit the four update domains separately** in `find_firmware` (console, Network, Protect, Access, device firmware) when parsing `.unifi` files.

Total: ~7 new question items, ~6 new findings across 3 modules. All derivable from data already in the backup, so no new user friction.

---

## What's still user-asked after these additions

Per-AP radio tuning is one of those areas where the **data exists** but **intent is ambiguous**. "Is 2.4 GHz needed?" can't be answered by looking at settings; it depends on which devices the user owns and cares about. Similarly "is extended coverage intentional?" is intent, not config.

So the new Section 6.5 questions stay as confirm-intent prompts even when we know the current state. That's consistent with our design pattern.
