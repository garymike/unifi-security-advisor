# Consolidated Questionnaire

The full questionnaire after all design iterations and the 10-point coverage analysis. Sections numbered to match the original design; new content from the addendum is integrated in place.

For each question:
- **Source** indicates how the answer is obtained: API, API+confirm, API+enrich, or User-only
- **Tiers** show three voices: Guided, Standard, Pro
- **Maps to** indicates which control framework(s) the question feeds

---

## Section 0: Profile and calibration

Sets tier routing and unlocks compliance branches. All user-only.

| # | Source | Question (Standard voice) |
|---|---|---|
| 0.1 | User-only | Networking comfort: New / Comfortable / Pro |
| 0.1a | User-only | Skills check: do you know what a VLAN is? (yes / sort of / no) - overrides 0.1 if mismatched |
| 0.2 | User-only | Day-to-day admin: solo / family / small team / MSP / IT dept |
| 0.3 | User-only | Network purpose: home / home office / small business / regulated / school / critical infra |
| 0.4 | User-only | Downtime tolerance: hours / minutes / seconds |
| 0.5 | User-only | Regulations: none / HIPAA / PCI / GLBA / FERPA / CMMC / NERC CIP / GDPR / Other |
| 0.6 | User-only | Migration context: did you move from another router/firewall? (none / yes from X) - unlocks "restore parity" mode |

---

## Section 1: Environment and intent

| # | Source | Question (Standard voice) |
|---|---|---|
| 1.1 | User-only | Priority ranking: privacy, work data, payment data, health data, IP, safety, uptime |
| 1.2 | API+enrich | Who connects: client count from API; relationships from user |
| 1.3 | API+confirm | Device inventory (auto-populated from clients via OUI/fingerprint, user labels unknowns and adds non-UniFi devices) |
| 1.4 | API | Inbound services from internet (port forwards, exposed services) |
| 1.5 | User-only | Top fears: identity, surveillance, ransomware, IoT hijack, work data theft, family content |
| 1.6 | User-only | NAS sub-section (triggered if NAS detected): how many, what's stored, remote access, backup posture |
| 1.7 | User-only | Smart home hub sub-section (triggered by HA/SmartThings/Hue/etc.): which protocols, cross-VLAN needs, remote exposure |
| 1.8 | User-only | Third-party security gear (Firewalla, pfSense, Meraki): inline/passive, where in path, what feature is desired |
| 1.9 | User-only | Other admin surfaces: ISP modem, printer, smart home bridges, personal servers |

---

## Section 2: Hardware and topology

Mostly API-derivable. User confirms or adds.

| # | Source | Question |
|---|---|---|
| 2.1 | API | Gateway model and firmware |
| 2.2 | API+enrich | Vendor mix (UniFi auto, third-party from user) |
| 2.3 | API | Switch/AP/camera/Access counts |
| 2.4 | User-only | Physical location of gateway and APs |
| 2.5 | API | Other UniFi product lines installed (Protect, Access, Talk) |
| 2.6 | API | Controller hosting: Cloud Gateway / UDM / standalone |

---

## Section 3: Internet and WAN

| # | Source | Question |
|---|---|---|
| 3.1 | API | WAN redundancy: single / dual / LTE backup |
| 3.2 | API | Static or dynamic public IP |
| 3.3 | API | Port forwards (complete list, enabled state) |
| 3.4 | API | UPnP enabled |
| 3.5 | API | DNS resolver in use |
| 3.6 | API+confirm | DoH/DoT enforcement; clients blocked from rogue resolvers |

---

## Section 4: Admin and identity

The single highest-leverage section.

| # | Source | Question |
|---|---|---|
| 4.1 | API | Admin login method (cloud SSO / local / SSO via IdP) |
| 4.2 | User-only | MFA on cloud admin account (NOT in API or backup; explicit gap question) |
| 4.3 | API | Local break-glass admin exists |
| 4.4 | API+enrich | Admin scoping; shared accounts (asked of user) |
| 4.5 | API | SSH enabled per device |
| 4.6 | User-only | Default credentials on non-UniFi devices (NAS, Firewalla, HA hub, printer, etc.) |

---

## Section 5: Segmentation and trust zones

Core to security value. Most fields API-derivable.

| # | Source | Question |
|---|---|---|
| 5.1 | API | Network/VLAN inventory and mapping |
| 5.2 | API | Management network presence and isolation |
| 5.3 | API | Client Device Isolation per WLAN |
| 5.4 | API | Camera VLAN and egress posture (if Protect installed) |
| 5.5 | API | Cross-VLAN reachability to printers, NAS, media servers |
| 5.6 | API | Firewall mode: Zone-Based Firewall vs legacy |
| 5.7 | API | Network Isolation toggle per network |

---

## Section 6: Wi-Fi

| # | Source | Question |
|---|---|---|
| 6.1 | API | Security mode per SSID (WPA2 / WPA2/3 / WPA3 / Open) |
| 6.2 | API+confirm | PSK length/entropy (fingerprint only, never plaintext) |
| 6.3 | API | Hidden SSID flags |
| 6.4 | API | SSID-to-VLAN mapping plus Guest Policies |
| 6.5 | API | PPSK / RADIUS / WPA3 Enterprise usage |
| 6.6 | API | Wireless mesh / uplink state |
| 6.7 | API | 6 GHz band usage and WPA3 enforcement |

## Section 6.5: Wireless tuning (added per coverage analysis)

| # | Source | Question |
|---|---|---|
| 6.8 | API | Unused radio bands disabled (2.4 / 5 / 6 GHz) |
| 6.9 | API | TX power per radio (Auto / Medium / High / Custom) |
| 6.10 | API | Rogue AP detection enabled |
| 6.11 | API | Channel width per radio |
| 6.12 | API | Fast roaming (802.11r) and minimum data rate floor |

---

## Section 7: Firewall and threat detection

| # | Source | Question |
|---|---|---|
| 7.1 | API | Default inter-VLAN posture (allow / deny) |
| 7.2 | API | Rule direction coverage (LAN_IN, LAN_OUT, WAN_IN, WAN_LOCAL) |
| 7.3 | API | IDS/IPS enable, level, categories |
| 7.4 | API+confirm | CyberSecure subscription state (live state authoritative; backup has flag) |
| 7.5a | API | Geo-IP blocking on WAN_IN |
| 7.5b | API | Geo-IP blocking on WAN_OUT |
| 7.5c | API | DNS-based content filtering (Security/Family categories) |
| 7.5d | API | Safe-search enforcement (conditional: only if children-in-household indicated in 1.x) |
| 7.6 | API | Honeypot deployed on any VLAN |

---

## Section 8: Remote access

| # | Source | Question |
|---|---|---|
| 8.1 | API+confirm | Admin remote management path: Site Manager / Teleport / VPN / exposed port (last is a finding) |
| 8.2 | API | User-facing VPN: WireGuard (preferred) / OpenVPN / Teleport / L2TP (discouraged) / PPTP (deprecated, CRITICAL if present) |
| 8.3 | API | VPN split-tunnel and DNS-leak posture |
| 8.4 | API | Management ports exposed to WAN |
| 8.5 | API+confirm | Teleport user list and inactive-user pruning |

---

## Section 9: Logging, detection, response

| # | Source | Question |
|---|---|---|
| 9.1 | API | Log destinations (local / syslog / SIEM / CyberSecure) |
| 9.2 | API | Retention period (with profile-aware recommendations: home = less, regulated = more) |
| 9.3 | API | Alert configuration (new admin, config change, IDS hit, firmware, new device) |
| 9.4 | User-only | Runbook for active incident |
| 9.5 | User-only | Ability to isolate a device or VLAN in under 60 seconds |

---

## Section 10: Backup, recovery, resilience

| # | Source | Question |
|---|---|---|
| 10.1 | API | Auto-backup enabled, schedule, retention |
| 10.2 | User-only | Tested restore in last 12 months (Schrödinger backup finding fires until confirmed) |
| 10.3 | API+enrich | Gateway redundancy (spare hardware, cloud auto-config) |
| 10.4 | API | Backup destination diversity (local-only is a finding) |
| 10.5 | User-only | Documented RTO/RPO |

---

## Section 11: Physical security

Mostly user observation; brief.

| # | Source | Question |
|---|---|---|
| 11.1 | User-only | Gateway/switch in locked space |
| 11.2 | API | Unused switch ports disabled |
| 11.3 | API | Port profiles and 802.1X where applicable |
| 11.4 | User-only | Physical access controls on building |
| 11.5 | User-only | Cameras cover ingress to rack/network gear (if applicable) |

---

## Section 12: Firmware and lifecycle

| # | Source | Question |
|---|---|---|
| 12.1a | API | Device firmware version vs current per model |
| 12.1b | API | UniFi OS version (only available via .unifi backup or Site Manager) |
| 12.1c | API | UniFi Network app version |
| 12.1d | API | Other apps (Protect, Access, Talk) version |
| 12.2 | User-only | Subscribed to Ubiquiti Security Advisory Bulletins |
| 12.3 | API | EOL hardware in fleet (cross-reference against EOL list) |
| 12.4 | API | Auto-update enabled and maintenance window configured |
| 12.5 | API+CVE | Known-vulnerable firmware (cross-reference advisories) |

---

## Section 13: Operational capacity

User-only; calibrates what controls are sustainable.

| # | Source | Question |
|---|---|---|
| 13.1 | User-only | Hours per week available for ops |
| 13.2 | User-only | Backup admin if primary unavailable for two weeks |
| 13.3 | User-only | Documentation for successor |
| 13.4 | User-only | Comfort with logs/IDS/PCAPs |
| 13.5 | User-only | Appetite for automation and integrations |

---

## Section 14: Compliance branch (conditional on Section 0.5)

Only the matching subset is shown.

- **HIPAA**: PHI inventory, BAA coverage, audit log retention 6 years, encryption at rest for Protect footage with PHI
- **PCI**: CDE scope reduction via segmentation, quarterly ASV scan, cardholder VLAN evidence
- **GLBA / 314.4**: MFA on all admins, encryption of NPI in transit, written infosec program
- **FERPA**: Student directory data, camera retention policy
- **NERC CIP**: ESP definition, BES Cyber Asset identification, configuration monitoring
- **CMMC**: SPRS inputs, FCI/CUI boundary, DFARS 252.204-7012 evidence

---

## Question metadata template

For each question in implementation:

```yaml
id: Q5.3
section: Segmentation
text_guided: "Can your smart gadgets talk to each other?"
text_standard: "Is Client Device Isolation enabled on the IoT SSID?"
text_pro: "Wireless client isolation per BSSID; mDNS reflector scope?"
answer_type: single_select
options: [yes, no, partial, unknown]
source: API
unknown_resolution: guided_helper  # or auto_check, or defer
free_text_allowed: true
maps_to:
  unifi_feature: client_device_isolation
  nist_csf: PR.AC-5
  cis_v8: 12.2
  zt_tenet: per-session-access-decisions
risk_class: [lateral_movement, privacy]
weight: 4
profile_applicability: [home, home_office, small_business, regulated_*]
remediation:
  yes: null
  no: "Enable Client Device Isolation on IoT and guest SSIDs."
  partial: "Audit each IoT SSID; isolation must be per-WLAN."
  unknown: "Settings > WiFi > [SSID] > Client Device Isolation."
```

---

## Always-float-to-top findings

Regardless of overall scoring, surface these to the top of any report when detected:

1. No MFA on any admin account
2. Management plane reachable from WAN
3. Flat network with mixed device classes (IoT + work + personal on one VLAN)
4. Default credentials anywhere
5. Firmware more than two majors behind with known advisories
6. PPTP or any deprecated-crypto VPN enabled
