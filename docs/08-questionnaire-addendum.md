# Questionnaire Addendum: Coverage Fixes

Changes to the baseline questionnaire based on the 10-point gap analysis. All new questions are answerable from backup fields listed under "source."

---

## Section 6.5: Wireless Tuning (NEW)

Inserted after Section 6 (Wi-Fi).

| # | Guided voice | Standard voice | Pro voice | Source |
|---|---|---|---|---|
| 6.8 | Do you need Wi-Fi to work for old devices, or are all your gadgets from the last 5-7 years? | Are unused radio bands disabled? (2.4 / 5 / 6 GHz) | Per-radio enable state audit; 2.4 GHz viability check given client 802.11 version distribution | `device.radio_table[].disabled` |
| 6.9 | Does your Wi-Fi signal reach outside your home (driveway, street, neighbor's yard)? | Is TX power set to Auto/Medium, or High/Custom? | Per-radio `tx_power_mode` and `tx_power` (dBm); minimum RSSI enforcement | `device.radio_table[].tx_power_mode`, `tx_power`, `min_rssi_enabled`, `min_rssi` |
| 6.10 | Would you know if a stranger set up a fake version of your Wi-Fi nearby? | Is Rogue AP Detection enabled? Are neighbor APs being reviewed? | `rogueap` collection; `setting.rogueap` enablement; recent detections | `setting.rogueap`, `rogueap` collection |
| 6.11 | (Not asked at Guided level) | Is channel width set manually, or left on auto? | Per-radio HT/VHT width (20/40/80/160); channel plan; DFS state | `device.radio_table[].ht`, `channel` |
| 6.12 | (Not asked at Guided level) | Is fast roaming (802.11r) enabled where supported? | 802.11r/k/v enablement; minimum data rate floor; PMF enforcement | `wlanconf.fast_roaming_enabled`, `minrate_*`, `pmf_mode` |

### Finding logic summary

- TX power "High" → LOW severity recommendation (unless intentionally outdoor/large property)
- 2.4 GHz active with few/no 2.4-only clients → INFO recommendation to evaluate disabling
- Rogue AP detection OFF → MEDIUM finding
- Fast roaming OFF on multi-AP deployments → LOW (performance/security combo)
- PMF disabled on WPA3 SSID → MEDIUM (required by WPA3 spec)

---

## Section 7: Firewall and Threat (UPDATES)

### Split Q7.5 into three distinct questions

| Old | New |
|---|---|
| Q7.5 "Content filtering in use? (includes Geo)" | Q7.5a Geo-IP blocking, Q7.5b Content filtering (DNS-based), Q7.5c Safe-search enforcement |

### New Q7.5a: Geo-IP blocking

- **Source:** `firewallrule` referencing country groups, plus rules on `WAN_IN` and `WAN_OUT`
- **Finding logic:** Flag as recommendation if WAN_IN has no geo filter; also check WAN_OUT (often-overlooked; prevents compromised devices from phoning home to known-malicious regions).

### New Q7.5b: Content filtering

- **Source:** `setting.dns_filtering` or category-based content filter rules
- **Finding logic:** Recommend Security category minimum (blocks malware C2, phishing). Recommend Family category if user indicated children in household (from Section 1).
- **Privacy note:** Output explains this is DNS-based, so it's visible to clients (they can see what's blocked). More privacy-respecting than DPI.

### New Q7.5c: Safe-search enforcement

- **Source:** Look for DNS rewrites or CNAME overrides for `google.com`, `bing.com`, `youtube.com` to their safe-search alternatives
- **Finding logic:** Only evaluate if user indicated children/education context. Otherwise not a finding.

---

## Section 8: Remote Access (UPDATES)

### New: VPN protocol preference tiering

Existing Q8.2 ("User-facing VPN?") keeps options but findings now tier by protocol:

- **Preferred:** WireGuard (modern, lean, fast, strong defaults)
- **Acceptable:** OpenVPN, Teleport (WireGuard-based)
- **Discouraged:** L2TP/IPsec (legacy, known weaknesses, often UDP-blocked)
- **Deprecated:** PPTP (cryptographically broken; if present, CRITICAL finding)

### Finding logic

- PPTP enabled → CRITICAL (deprecated, MS-CHAPv2 broken)
- L2TP/IPsec enabled as the only VPN → MEDIUM recommendation (switch to WireGuard if possible)
- No VPN configured but port forwards active → HIGH (user is exposing services instead of using VPN)
- WireGuard configured → OK, surface as a win in the "what's going well" section

---

## Section 9: Logging (UPDATES)

### Privacy-aware recommendations

Retention recommendations now vary by profile:

| Profile | Recommended traffic log retention | Recommended admin log retention |
|---|---|---|
| Home / personal | 7-14 days | 30 days |
| Home office (this user) | 14-30 days | 90 days |
| Small business | 30-90 days | 1 year |
| Regulated (HIPAA, PCI) | 6 years | 6 years minimum |
| Regulated (NERC CIP) | 3+ years | 3+ years |

### New finding logic

- Retention longer than profile recommendation → LOW (privacy cost without benefit)
- Retention shorter than profile requirement → MEDIUM (compliance gap) or HIGH (if regulated)
- DPI logging at client level + home profile → LOW (privacy recommendation: use aggregate/protocol-only logging instead)

---

## Section 10: Backup (UPDATES)

### Promote Q10.2 to a standalone finding

"Tested restore" moves from a side question to a standalone finding.

- **Source:** Not in backup. User-only answer, but the finding always fires unless user confirms a tested restore within the last 12 months.
- **Severity:** MEDIUM for any profile. HIGH for regulated profiles.
- **Rationale:** An untested backup is a Schrödinger backup - its viability is unknown until the moment of greatest need.

### New finding: backup destination diversity

- **Source:** `setting.auto_backup` includes destination. Check if off-device destination is configured.
- **Finding logic:** Backups stored only on the gateway itself = single point of failure (hardware failure, theft, ransomware of the device itself). Recommend off-device: cloud (UniFi SSO-linked), SMB share on NAS (user already has multiple), or manual periodic download.
- **Severity:** MEDIUM

---

## Section 12: Firmware (UPDATES)

### Split into four update domains

Previously one question set. Now:

| Domain | Source | Finding |
|---|---|---|
| 12.1a Device firmware (APs, switches, gateway) | `device.version` vs current | Per-device "behind by N minor versions" |
| 12.1b UniFi OS | `system.properties.unifi_os_version` (in .unifi backup) | "Console OS behind by X" |
| 12.1c UniFi Network app | `system.properties.network_version` | "Network app behind by X" |
| 12.1d Other apps (Protect, Access, Talk) | Per-app version in system properties | "Protect/Access/Talk behind" (only if installed) |

### New finding: known-vulnerable firmware

- **Source:** Cross-reference device version + UniFi Security Advisories
- **Requires:** Small static CVE database (to be maintained; initial version can ship with ~12 months of advisories)
- **Severity:** Scales with CVE severity. Critical CVE match = CRITICAL finding with direct remediation.

### New finding: EOL hardware

- **Source:** Device model lookup against Ubiquiti EOL list
- **Examples:** UAP-AC line (most EOL), original USG, Cloud Key Gen1
- **Severity:** MEDIUM if EOL within 12 months, HIGH if already EOL

---

## Summary of additions

- **Questions added:** 7 (five in new Section 6.5, two splits in Section 7, one in Section 10 promoted, two new in Section 12)
- **New parser modules:** `find_wireless_tuning` (new), `find_vpn_protocol` (enhancement of `find_remote_access`)
- **Enhanced modules:** `find_firewall` (geo/content/safe-search split), `find_logging` (privacy-aware retention), `find_backup_config` (tested restore, destination diversity), `find_firmware` (4-domain, EOL, CVE cross-ref)
- **All additions derivable from backup data**, no net increase in user questions (the new questionnaire items map to confirm-intent prompts after automatic detection).
