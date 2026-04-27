# Ubiquiti Security Advisor: Sample Response Set + Design Notes

Generated from a walkthrough simulation with a self-identified tinkerer / home-office user.

---

## Part 1: Sample Response Set

### Section 0: Profile and calibration

| # | Question | Answer | Confidence |
|---|---|---|---|
| 0.1 | Networking comfort | Pretty comfortable, I tinker | Self-reported |
| 0.2 | Day-to-day admin | Just me | High |
| 0.3 | Network purpose | Home + work from home | High |
| 0.4 | Downtime tolerance | Seconds, work blocked | **Contested** |
| 0.5 | Regulations | None, personal use | High |

**Routed tier:** Standard (tinkerer). Skills-check question recommended to verify before jargon is used.

### Section 1: Environment and intent

| # | Question | Answer |
|---|---|---|
| 1.1 | Priority ranking | 1. Family privacy, 2. Smart home reliability, 3. Uptime, 4. Work data |
| 1.2 | Who uses WiFi | Me and partner/family |
| 1.3 | Device inventory (multi-select + write-ins) | Smart TVs, smart speakers, smart plugs/lights/thermostats, **smart air quality devices** (write-in), **multiple NAS** (write-in), **future Home Assistant box** (write-in) |
| 1.4 | Inbound services from internet | Not sure, asked to check |
| 1.5 | Top fears | Identity theft, surveillance via cameras/speakers, ransomware, IoT hijack |

### Section 2: Hardware and topology

| # | Question | Answer |
|---|---|---|
| 2.1 | Gateway | UCG Fiber |
| 2.2 | Vendor mix | All UniFi; owns a Firewalla, considering re-adding |
| 2.3 | Switch/AP count | 1 AP, 0 switches |
| 2.4 | AP location | Ceiling mount |
| 2.5 | Other UniFi lines | None (no Protect, Access, Talk) |

### Section 3: Internet and WAN

| # | Question | Answer |
|---|---|---|
| 3.1 | WAN redundancy | Single connection, no failover |
| 3.2 | Port forwards | Unknown, asked to check |
| 3.3 | DNS resolver | Unknown |
| 3.4 | UPnP state | Unknown |

### Section 4: Admin and identity

| # | Question | Answer |
|---|---|---|
| 4.1 | Login method | Ubiquiti cloud account (unifi.ui.com) |
| 4.2 | MFA on cloud account | **Unknown (critical to verify)** |
| 4.3 | Local break-glass admin | Probably exists, not documented |
| 4.4 | Shared accounts | Solo admin |
| 4.5 | SSH enabled | Unknown |
| 4.6 | Default passwords on other admin surfaces (NAS, Firewalla) | Some changed, some not |

### Section 5: Segmentation

| # | Question | Answer |
|---|---|---|
| 5.1 | Current segmentation | Flat / single network; **explicit goal: restore segmentation** (had it on prior router, lost in migration) |
| 5.2 | NAS reachability | All devices can reach NAS |
| 5.3 | IoT internet posture | Unknown |

### Section 6: Wi-Fi

| # | Question | Answer |
|---|---|---|
| 6.1 | Security mode | WPA2/WPA3 mixed |
| 6.2 | Password hygiene | Strong and unique |
| 6.3 | SSID count | 1 |

### Section 7: Firewall and threat detection

| # | Question | Answer |
|---|---|---|
| 7.1 | IDS/IPS enabled | Unknown |
| 7.2 | Content filtering | No |
| 7.3 | Geo-IP blocking | Yes, configured |
| 7.4 | CyberSecure subscription | Not mentioned (infer: no) |

### Section 8: Remote access

| # | Question | Answer |
|---|---|---|
| 8.1 | Remote management path | UniFi mobile app (Site Manager) |

### Sections 9-14

Not walked through in this session. Recommended to cover next:
- Logging and alerting (likely nothing configured)
- Backup and recovery (likely nothing configured)
- Firmware update posture (quick check)
- Skip: compliance (user is personal use), physical security (minimal gear)

### Explicit user-stated goals captured

1. Restore network segmentation (had it before Ubiquiti migration)
2. Decide whether to re-add Firewalla to the stack
3. Plan for adding a Home Assistant box

---

## Part 2: Accumulated Design Notes

Aggregated findings for the questionnaire design, in priority order for implementation.

### Critical (rework needed)

1. **"Not sure" must be a first-class answer with a resolution path.** In this session, 7 of ~25 answers were "not sure." That's 28%. The wizard needs:
   - **Guided helper mode:** "Here's exactly where to click to find out"
   - **Auto mode (optional):** Read-only API token, auto-pull the answer
   - **Deferred mode:** Mark as pending, surface at the end as a checklist
   Currently "not sure" just looks like a missing answer.

2. **Every question needs optional free-text.** The best signal in this session came from write-ins:
   - The segmentation history and goal statement
   - The Firewalla mention (not in any canned option)
   - The NAS count and Home Assistant plans (exceeded device list)
   Without these, the wizard would have routed to generic advice. With them, it can tailor precisely.

3. **Device inventory questions must allow write-ins.** No canned list of IoT will ever be complete. Need "+ Add other" on every multi-select. Extra credit: library of common categories (air quality, EV chargers, solar inverters, etc.) with icons to speed selection.

4. **Upfront section-level helper offer.** For technical sections (Internet/WAN, Admin, Firewall), offer at section entry: *"Want to answer these yourself, or should I check the gateway and pre-fill?"* This acknowledges that novices will hit walls and lets them opt into guided-discovery mode.

5. **Cross-answer tension detection.** Multiple examples surfaced:
   - "Seconds of downtime blocks work" + single WAN + work ranked #4 priority
   - "Mobile app remote management" + "MFA unknown" = keys-to-kingdom risk
   - "NAS reachable by everything" + "IoT internet unknown" = pivot path
   The engine needs a rules layer that detects these combinations and generates composite findings, not just independent ones.

### High priority (new questions/branches needed)

6. **Migration-from-another-platform branch.** Common scenario that explains flat configs despite user knowledge. Early question: *"Did you move to Ubiquiti from another router/firewall? (yes/no/which one)"* unlocks a "restore parity" sub-flow.

7. **Third-party security appliance branch.** Firewalla, pfSense, Meraki, Unraid+OPNsense, etc. Questions: placement (inline vs passive), feature overlap with UniFi, licensing cost, failure modes. Frame as neutral evaluation, not "remove it."

8. **Shadow admin surface inventory.** Section 4 only covers UniFi. Real attack surface includes: every NAS admin UI, Home Assistant admin, Firewalla admin, smart home hubs (Hue bridge, SmartThings), router on ISP modem if still active. Need a universal admin-surface enumeration step.

9. **Desired-state goal tracker.** Separate from current-state answers. When user says "I want X," capture as explicit goal. Output must address each captured goal, not just each gap. Also gives the user a sense of being heard.

10. **Skills verification ≠ self-reported tier.** A skills-check question ("do you know what a VLAN is?") should gate jargon tier before the wizard commits to Standard/Pro voice. Self-assessment has known bias in both directions.

### Medium priority (UX/polish)

11. **Immediate-fix mode for critical findings.** MFA unknown on cloud account shouldn't wait for the final report. Offer: *"Open account.ui.com/security now, fix it, come back. Takes 2 minutes."* Build this in-line for items that are quick and high-impact.

12. **"Some of them" answers need follow-up inventory.** When user says "some NAS/devices have default passwords," follow up with "let's list which ones are still default." Otherwise the finding is too vague to action.

13. **Auto-infer when possible.** Don't ask "how is the controller hosted?" if gateway is a Cloud Gateway (answer is implicit). Use hardware answers to trim downstream questions.

14. **Acknowledge what's been done right.** User had geo-blocking and strong WiFi password. Output should lead with wins before gaps. Otherwise feels like scolding, even when findings are real.

15. **Explain compound risk narratively.** Don't just list "flat network," "NAS reachable," "IoT unrestricted" as three bullets. Tell the story: *"A compromised smart plug could reach your NAS and your work laptop because nothing stands between them."* Biomimicry angle: the organism has no cell walls.

16. **Max-selection limits should be enforced or removed.** "Pick up to 3" was exceeded. Either enforce with UI or phrase as "pick all that apply" and weight by count.

### Lower priority (nice to have)

17. **Question-dependency graph.** If DNS resolver is unknown, don't ask about DoH/DoT - skip and revisit after helper. Current flow would generate meaningless answers.

18. **Inline education mode.** Each section could have a toggleable "why does this matter?" paragraph. Educate without forcing.

19. **Session save-and-resume.** Audits take hours. This is already in the design doc but worth elevating based on how long this partial walkthrough took.

20. **Output should distinguish "done," "quick win," "project," and "research needed."** Different remediation types need different UX. A finding requiring VLAN planning isn't the same as "toggle MFA on."

---

## Questions explicitly added based on this walkthrough

1. (Section 0) Skills verification sub-question: *"Do you know what a VLAN is?"* yes/sort of/no
2. (Section 0) Migration question: *"Did you come from another router or firewall?"*
3. (Section 1) Broader device catalog with write-in
4. (Section 1, 2) NAS sub-section: *"For each NAS: what's stored, remote access enabled, backed up where"*
5. (Section 2) Third-party security appliance sub-section
6. (Section 4) Shadow admin surface inventory
7. (Section 4) After "some devices still default": *"Which ones specifically?"*
8. (Every section) Optional free-text: *"Anything to add or clarify?"*
