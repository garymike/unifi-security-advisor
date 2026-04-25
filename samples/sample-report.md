# UniFi Security Advisor Report

**Source:** `backup.unf` (analyzed locally, nothing transmitted)
**Generated:** 2026-04-24 15:44 UTC
**Findings:** 11 (0 critical, 3 high, 5 medium, 2 low, 1 info)
**Controller version:** Network 9.3.47 (UniFi OS 4.1.14)
**Gateway:** UCG Fiber (1 device)
**APs:** 1 (U7 Pro ceiling mount)
**Switches:** 0
**Networks:** 1 (Default / 192.168.1.0/24)
**SSIDs:** 1 active

---

## Executive summary

Single flat network, solo admin, default rule posture, cloud-managed via UniFi mobile app. The gateway hardware is capable but most security features are off or unconfigured. Highest-impact wins are segmentation and admin account hardening; both are largely quick-to-medium effort for outsized risk reduction.

### What's going well

- Wi-Fi is WPA2/WPA3 mixed with a strong passphrase (16+ chars, mixed case, digits, symbols)
- Geo-IP blocking is configured on WAN_IN
- Auto-firmware-update is enabled within a maintenance window (03:00-05:00 local)
- Controller automatic backups are enabled (daily, 7-day retention, stored locally)
- No port forwards currently active

### Top priorities

1. **[HIGH] Flat network with IoT + NAS + personal devices all on one VLAN** - direct pivot path
2. **[HIGH] No local break-glass admin** - cloud-only auth with unknown MFA = recovery risk
3. **[HIGH] Wi-Fi passphrase strong but shared by every device type** - IoT compromise exposes WPA handshake

---

## [HIGH] Flat network (no segmentation)

*Segmentation / SEG-001*

**Found:** The controller has 1 user-defined network (Default, 192.168.1.0/24). All 47 connected clients share a single broadcast domain. This includes 3 NAS devices, 14 IoT devices (smart speakers, plugs, TVs, air quality monitors), 2 personal laptops, 4 mobile devices, and miscellaneous other clients. A compromise of any device can reach any other.

**Recommend:** Create separate networks for Main (trusted devices), IoT (smart home), Guest, and Management. Map SSIDs to the appropriate VLANs. Enable Network Isolation on each, then add explicit allow rules for the connections you actually need (e.g., trusted devices reaching the NAS, but not IoT reaching the NAS).

**Confirm intent:** Do you want to restore segmentation similar to what you had before migrating to Ubiquiti? (You noted this as an explicit goal.)

**Maps to:** NIST CSF PR.AC-5, CIS v8 12.2, Zero Trust: per-resource access

---

## [HIGH] No local break-glass admin detected

*Admin / ADM-002*

**Found:** All 1 admin account is tied to a Ubiquiti cloud account (`***@***.com`). If the cloud account is compromised, locked, or loses MFA access, there is no local recovery path to this gateway.

**Recommend:** Create a local admin account with a strong unique password. Store the password in a password manager, offline copy in a secure physical location. Never use this account for daily login - it exists only to recover from cloud-account loss.

**Confirm intent:** Do you want to add a local break-glass admin account?

**Maps to:** CIS v8 5.3, NIST CSF PR.AC-1

---

## [HIGH] NAS reachable from every device on the network

*Segmentation / SEG-005*

**Found:** 3 NAS devices at 192.168.1.20, 192.168.1.21, 192.168.1.22 are on the same subnet as all IoT devices. No firewall rules restrict which clients can reach the NAS. An IoT compromise (e.g., a vulnerable smart speaker) provides a pivot to the NAS devices that likely hold significant personal data.

**Recommend:** After segmentation (SEG-001), place NAS devices on the trusted/main VLAN. Add an explicit firewall rule allowing only your personal devices (by MAC or a trusted-group) to reach NAS ports. Block all other VLANs from NAS IPs.

**Confirm intent:** Should IoT devices be able to reach your NAS?

**Maps to:** NIST CSF PR.AC-5, CIS v8 3.3

---

## [MEDIUM] IDS/IPS is disabled

*Firewall / FW-001*

**Found:** Threat management (IDS/IPS) is not enabled. Your UCG Fiber supports line-rate IDS/IPS with minimal impact on your Gigabit service.

**Recommend:** Enable IDS/IPS at the "Security" level to start. Monitor alerts for 1-2 weeks, then tune categories to match your usage. Consider a CyberSecure subscription for enhanced threat feeds and traffic logs.

**Confirm intent:** Should IDS/IPS be turned on?

**Maps to:** CIS v8 13.3, NIST CSF DE.CM-1

---

## [MEDIUM] UPnP is enabled

*Firewall / FW-003*

**Found:** UPnP is enabled in Internet Settings. This lets applications open inbound ports automatically without notifying you. No forwards are currently active via UPnP, but this can change silently.

**Recommend:** Disable UPnP. If a specific game or application needs a port, configure it manually via Port Forwarding.

**Confirm intent:** Is there a specific application you rely on UPnP for (e.g., a specific multiplayer game, Xbox Live NAT type)?

**Maps to:** CIS v8 4.4

---

## [MEDIUM] No dedicated management network

*Segmentation / SEG-002*

**Found:** The gateway admin UI (192.168.1.1) is reachable from the same network as all other devices, including IoT. A compromised IoT device has direct network access to the controller login page.

**Recommend:** Create a management VLAN. Add a firewall rule restricting admin UI access to that VLAN only. Access the admin UI via VPN or by plugging into a management port.

**Confirm intent:** Is it acceptable that anyone on your main network (including IoT) can reach the admin interface?

**Maps to:** NIST CSF PR.AC-5

---

## [MEDIUM] SSH enabled on 1 device

*Admin / ADM-001*

**Found:** SSH is enabled on 1 device (UCG Fiber). This is a remote admin surface.

**Recommend:** Disable SSH unless you actively use it. If needed, configure key-based authentication only (no password), use a unique password on the device as a fallback, and restrict SSH access to the management VLAN via firewall rule.

**Confirm intent:** Do you use SSH to this gateway? (If unsure, you probably don't.)

**Maps to:** CIS v8 4.6, NIST CSF PR.AC-4

---

## [MEDIUM] Content filtering not configured

*Firewall / FW-004*

**Found:** No content filtering rules are active. Geo-IP blocking is configured (good) but does not block malware domains, command-and-control infrastructure, or phishing.

**Recommend:** Enable Content Filtering with Security category (blocks known malicious domains) at minimum. Consider Family category if that matches your household preferences. Applies across all clients without per-device configuration.

**Confirm intent:** Should the network block malicious domains for all devices automatically?

**Maps to:** CIS v8 9.3, NIST CSF PR.PT-4

---

## [LOW] Wi-Fi SSID uses WPA2/WPA3 mixed mode

*Wi-Fi / WIFI-Main-001*

**Found:** SSID "Main" (current name) uses WPA2/WPA3 mixed. This is a pragmatic default for IoT compatibility.

**Recommend:** When you segment, split into WPA3-only for the main SSID (stronger, and your laptops/phones support it) and WPA2-only for an IoT SSID (required by many cheap smart devices).

**Confirm intent:** This becomes actionable after segmentation (SEG-001). Defer until then.

**Maps to:** CIS v8 12.5

---

## [LOW] Single WAN with no failover

*Connectivity / CON-001*

**Found:** Single WAN connection configured. No secondary WAN, no LTE failover. The gateway has a spare WAN-capable port available.

**Recommend:** Given your earlier "seconds of downtime blocks work" answer, consider an LTE failover device or a secondary ISP. This is hardware-cost work, not a quick setting change. Alternative: revise your downtime-tolerance assumption based on realistic work impact.

**Confirm intent:** How critical is sub-minute failover, really? (Quick check: when your internet goes out for 5 minutes right now, what actually breaks?)

**Maps to:** NIST CSF PR.PT-5

---

## [INFO] No port forwards currently active

*Firewall / FW-002*

**Found:** 0 port forwards are configured. No services are directly exposed from the internet.

**Recommend:** Continue to avoid port forwards. For remote access to your NAS or services, use Teleport (Site Manager) or a WireGuard VPN. If you later need a forward, prefer strict source IP allowlisting.

**Confirm intent:** No action required unless plans change.

**Maps to:** CIS v8 4.4

---

## Notes on sanitization

- Wi-Fi passphrases were never decoded or displayed. Strength is evaluated from length and character-class diversity of the stored value.
- Admin password hashes were excluded from all output.
- Client hostnames are shown but can be redacted with `--redact-pii` for sharing with an MSP or support case.
- No data in this report was transmitted anywhere. All analysis ran locally against your backup file.
