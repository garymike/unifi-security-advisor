# Ubiquiti Security Advisor: Discovery-First Design

Pivot from "fill out a form" to "here's what we found, confirm or correct."

---

## Part 1: Available Data Sources

### A. Site Manager API (cloud, official)
- URL: `https://api.ui.com/v1/`
- Auth: `X-API-KEY` header, generated at unifi.ui.com
- Scope: read-only (as of early 2026), write rolling out through 2026
- Rate limit: 10,000 req/min
- Coverage: hosts, devices, sites, ISP metrics, aggregate health
- Security: no MFA bypass required; user creates a scoped key

### B. Network Integration API (local, official)
- URL: `https://{console}/proxy/network/integration/v1/`
- Auth: `X-API-KEY`
- Requires Network v9.3.43+
- Coverage: clients, WLANs, device detail, Object-Oriented Network Policies (OON), firewall policies, port forwards, traffic routes, QoS, port profiles, networks/VLANs, static routes, NAT
- Security: scoped key, no credentials stored

### C. Classic/Internal API (community)
- URL: `/api/s/{site}/...` or `/proxy/network/api/s/{site}/...`
- Auth: cookie session (requires username/password)
- Coverage: full surface (fills gaps until official API reaches parity)
- **Security tradeoff**: community clients often recommend a local admin account *without* MFA for session auth. This is a documented practice but creates an MFA-less admin surface. **The wizard should prefer official X-API-KEY paths and only fall back to Classic with explicit user consent and a time-limited scoped account.**

### D. Backup file (`.unf`)
- User-exported from Settings > System > Backup
- Contains full config (JSON-ish), readable offline
- Zero network permissions required to analyze
- Great for airgapped audits, paranoid users, and MSP "send us your backup" workflows

### E. User observation
- Screenshots of specific settings screens (user pastes)
- User describes environment (physical, non-UniFi devices, process/behavior)
- Last resort for what APIs can't see

### Recommended connection strategy

Offer three connection modes in the wizard:

1. **Full auto** (preferred): user generates Site Manager API key + Network Integration key. Wizard pulls both.
2. **Backup-file** (airgap-friendly): user uploads `.unf`. Wizard parses offline.
3. **Manual** (fallback): user answers questions and screenshots as needed.

Classic/cookie API is offered only as an explicit "advanced, requires creating a limited local admin" path. Not default.

---

## Part 2: Question-to-Data-Source Map

Legend:
- **API**: fully answerable via API or backup file, no user input needed
- **API+confirm**: fetch then ask user to validate ("we found X, is this right?")
- **API+enrich**: API gives partial answer, user fills context
- **User-only**: intent, process, or non-UniFi context; must ask

### Section 0: Profile and calibration

| # | Data Source | Notes |
|---|---|---|
| 0.1 | User-only | Comfort level (intent) |
| 0.2 | API+enrich | List of admins is API; "is this team actively managing?" is user |
| 0.3 | User-only | Purpose/intent |
| 0.4 | User-only | Tolerance (intent) |
| 0.5 | User-only | Regulation (context) |

### Section 1: Environment and intent

| # | Data Source | Notes |
|---|---|---|
| 1.1 | User-only | Priority ranking |
| 1.2 | API+enrich | Client count is API; relationships are user |
| 1.3 | **API+confirm** | Client list with MAC OUI lookup, DHCP hostname, fingerprint → pre-populate inventory, user labels/classifies unknowns |
| 1.4 | **API** | Port forwards endpoint + UPnP state + firewall rules with WAN sources |
| 1.5 | User-only | Fears (intent) |

### Section 2: Hardware and topology

| # | Data Source | Notes |
|---|---|---|
| 2.1 | **API** | Device list returns model, firmware, role |
| 2.2 | API+enrich | Wizard knows UniFi inventory; asks "anything else in the stack?" (Firewalla, pfSense, etc.) |
| 2.3 | **API** | Device count by type |
| 2.4 | User-only | Physical location |
| 2.5 | **API** | Protect/Access/Talk app presence on console |

### Section 3: Internet and WAN

| # | Data Source | Notes |
|---|---|---|
| 3.1 | **API** | WAN config, failover/load-balance settings |
| 3.2 | **API** | Port forwards endpoint (complete list with enabled state) |
| 3.3 | **API** | DHCP DNS setting per network |
| 3.4 | **API** | UPnP toggle in internet settings |
| 3.5 | API+confirm | DoH/DoT enforcement rules are API; whether clients are *forced* to the chosen resolver needs rule inspection + user context |

### Section 4: Admin and identity

| # | Data Source | Notes |
|---|---|---|
| 4.1 | **API** | Admin list with auth method per admin |
| 4.2 | API+confirm | Site Manager exposes MFA state for the cloud account; local admins require user confirmation |
| 4.3 | **API** | Local admin accounts enumerable |
| 4.4 | API+enrich | Admin list from API; "is anyone sharing?" is user |
| 4.5 | **API** | Device SSH settings |
| 4.6 | User-only | Non-UniFi admin surfaces (NAS, Firewalla, HA) |

### Section 5: Segmentation

| # | Data Source | Notes |
|---|---|---|
| 5.1 | **API** | Networks/VLANs, clients per VLAN, SSID-to-VLAN mapping |
| 5.2 | **API** | Firewall rules + ACLs determine who can reach NAS IP |
| 5.3 | **API** | Egress rules on IoT VLAN (if any); if no VLAN, infer "no restrictions" |
| 5.4 | **API** | Camera VLAN and rules (N/A for this user) |
| 5.5 | **API** | Rules touching printer/NAS IPs from IoT/guest sources |
| 5.6 | **API** | ZBF vs legacy rule engine version |
| 5.7 | **API** | Network Isolation toggle per network |

### Section 6: Wi-Fi

| # | Data Source | Notes |
|---|---|---|
| 6.1 | **API** | wlanconf: security mode, WPA version |
| 6.2 | API+confirm | PSK length/entropy is visible (not plaintext); user confirms uniqueness |
| 6.3 | **API** | Hidden SSID flag per WLAN |
| 6.4 | **API** | SSID-to-VLAN + Guest policy + isolation toggles |
| 6.5 | **API** | PPSK config, RADIUS profiles |
| 6.6 | **API** | Wireless uplink / mesh state per AP |
| 6.7 | **API** | 6 GHz band-enable, WPA3 enforcement |

### Section 7: Firewall and threat

| # | Data Source | Notes |
|---|---|---|
| 7.1 | **API** | IDS/IPS enable, level, categories |
| 7.2 | **API** | Rule direction coverage (LAN_IN, LAN_OUT, WAN_IN) |
| 7.3 | **API**/Site Manager | CyberSecure subscription state |
| 7.4 | **API** | Content filtering rules |
| 7.5 | **API** | Geo-IP rules on WAN_IN/WAN_OUT |
| 7.6 | **API** | Honeypot deployment |

### Section 8: Remote access

| # | Data Source | Notes |
|---|---|---|
| 8.1 | **API**/Site Manager | Teleport enabled, Site Manager linkage, Direct Remote Connection state, port forwards to mgmt |
| 8.2 | **API** | VPN server config (WireGuard, L2TP, OpenVPN, Teleport) |
| 8.3 | **API** | Split tunnel config, DNS push on VPN |
| 8.4 | **API** | Port forwards on 443/8443/22/etc. + firewall WAN_LOCAL rules |
| 8.5 | **API**/Site Manager | Teleport user list, last-active timestamps |

---

## Part 3: Revised Question Pattern

Old pattern:
> *Q: Do you have IDS/IPS enabled?*
> *A: Not sure*

New pattern (after API call):
> *We detected: **IDS/IPS is currently disabled.** Your gateway (UCG Fiber) supports it at up to 2.5 Gbps with minimal performance impact.*
> *Intended state?*
> *(a) Yes, turn it on at recommended level*
> *(b) Yes, but configure categories first*
> *(c) No, leave off (why?)*
> *(d) Not sure, explain more*

Three benefits:
1. **No guessing.** Current state is factual, not recalled.
2. **Shifts the conversation to intent.** The user isn't being quizzed; they're being asked to confirm or correct.
3. **Education happens at point of decision**, when it's most relevant.

### Template

```
We detected: [current state, in plain language]
Recommended for your profile: [tailored recommendation]
Intended state?
  (a) Apply recommendation
  (b) Keep as-is (why?)
  (c) Something else (describe)
  (d) Explain more before I decide
```

### Where this pattern shines vs where it fails

**Shines** when:
- The setting is binary or small-enum (on/off, level 1-4)
- The user has a mental model of what they want
- API returns the answer cleanly

**Fails** when:
- The question is about intent or goals (fears, priorities, compliance)
- The answer requires observing the real world (physical security, non-UniFi devices)
- The user is learning the concept for the first time and can't yet articulate intent

In those cases, stay with the original "ask the user" flow. The wizard needs both modes.

---

## Part 4: Sections 9-12 (Logging, Backup, Physical, Firmware)

Using the new pattern. Each question shows: (data source) + (novice-voice framing).

### Section 9: Logging, detection, response

| # | Source | Question / finding framing |
|---|---|---|
| 9.1 | **API** | "We see **[no syslog destination configured / syslog to X]**. Intended? (a) Forward to my own log server (need endpoint) (b) Use UniFi built-in only (default) (c) Add CyberSecure traffic logging" |
| 9.2 | **API** | "Log retention is currently **[N days]**. For your profile (personal use, high availability), we suggest 30 days minimum. Change it?" |
| 9.3 | **API** | "Alerts are currently enabled for: **[list]**. Not enabled for: **[list]**. Suggest enabling: new admin login, config change, IDS hit, firmware change, new unknown device. Apply suggestion?" |
| 9.4 | User-only | "Do you have a simple plan for what to do if something goes wrong right now? (yes with a written plan / I'd figure it out / no)" |
| 9.5 | User-only | "If you suspected one device was compromised, do you know how to cut it off from the network quickly? (yes / no / show me how)" |

### Section 10: Backup, recovery, resilience

| # | Source | Framing |
|---|---|---|
| 10.1 | **API** | "Controller backups: **[auto on / manual only / disabled]**. Off-site destination: **[none / cloud / other]**. Recommend: auto daily, retained 7+ days, copy to cloud storage. Apply?" |
| 10.2 | User-only | "Have you ever actually restored from a backup to make sure it works? (yes, in last 12 months / yes but over a year ago / no / never had to)" |
| 10.3 | **API**+enrich | "You have one gateway (UCG Fiber). If it dies, you're offline until replacement. Options: keep a spare (~$299), enable cloud auto-config so a new unit restores fast, or accept the downtime risk. Which matches your plan?" |
| 10.4 | **API** | N/A (no Protect/NVR) |
| 10.5 | User-only | "If everything went down, how fast do you need to be back up? (under an hour / same day / few days is ok / don't know)" |

### Section 11: Physical security

Mostly user observation. Brief for this profile (1 AP on ceiling).

| # | Source | Framing |
|---|---|---|
| 11.1 | User-only | "Is your gateway in a place a visitor could physically reach? (yes/no/describe)" |
| 11.2 | **API** | "Unused switch ports are currently: **[disabled / enabled / mixed]**. Recommend disabling unused ports. Apply?" |
| 11.3 | **API**+enrich | "Port profiles on your gateway ports: **[list]**. Any concerns about someone plugging in?" |
| 11.4 | User-only | "Any physical access controls on the building itself (door codes, locks, cameras)?" |

### Section 12: Firmware and lifecycle

| # | Source | Framing |
|---|---|---|
| 12.1 | **API** | "Auto-updates: **[on within maintenance window / manual / off]**. Current firmware versions: **[list vs latest]**. Out of date: **[list]**. Apply updates in a maintenance window?" |
| 12.2 | User-only | "Do you follow Ubiquiti Security Advisory Bulletins? (yes/no/didn't know about them) *Offer: subscribe via the wizard on your behalf*" |
| 12.3 | **API** | "End-of-support check against your devices: **[all supported / X devices EOL in Y months]**. Plan?" |
| 12.4 | User-only | "Is there a record of what gear you own and warranties, outside the controller?" |

---

## Part 5: Updated Wizard Flow

```
┌─ Phase 1: Intent calibration (5 min) ───────────────────┐
│  User-only questions: profile, priorities, fears,        │
│  regulations, downtime tolerance, migration context.     │
│  Output: user profile + explicit goals list.             │
└──────────────────────────────────────────────────────────┘
                          ↓
┌─ Phase 2: Connect (2 min) ──────────────────────────────┐
│  Three paths:                                            │
│   (a) Full auto: generate Site Manager + Network keys    │
│   (b) Backup-file: upload .unf                           │
│   (c) Manual: no connection, answer everything           │
└──────────────────────────────────────────────────────────┘
                          ↓
┌─ Phase 3: Auto-discovery (background, ~30 sec) ─────────┐
│  Pull inventory, configs, rules, admins, WLANs, VLANs,   │
│  firewalls, port forwards, UPnP, IDS/IPS, backups, fw.   │
│  Build current-state model.                              │
└──────────────────────────────────────────────────────────┘
                          ↓
┌─ Phase 4: Gap-fill interview (15-30 min) ───────────────┐
│  Only ask what API can't answer:                         │
│   - Intent/goals                                         │
│   - Non-UniFi devices (NAS, Firewalla, HA, etc.)         │
│   - Physical/process ("tested restore?", "break-glass?") │
│  Plus validation questions:                              │
│   - "We found X, is this what you wanted?"               │
└──────────────────────────────────────────────────────────┘
                          ↓
┌─ Phase 5: Output ───────────────────────────────────────┐
│  Exec summary, prioritized backlog, target-state         │
│  diagram, reassessment schedule, deltas tagged by        │
│  effort/impact, user-stated goals explicitly addressed.  │
└──────────────────────────────────────────────────────────┘
```

### Effort reduction estimate

For the profile we walked through (home/tinkerer):
- Original questionnaire: ~60 questions across 14 sections, many unanswerable ("not sure")
- Discovery-first: ~15 user-only questions + ~20 validation prompts
- **Roughly 40-50% fewer questions, and the remaining questions are higher quality** because they're about intent, not recall.

For a pro/enterprise user:
- Even bigger win. API returns exact current config, user validates intent.
- Main time sink becomes running the analysis and reviewing the report, not filling out forms.

---

## Part 6: Security Considerations for the Wizard Itself

The wizard itself is handling privileged access. Design notes:

1. **Prefer read-only API keys.** Ubiquiti's current official API is read-mostly, which is ideal. Even when write scope lands, the wizard should default to read and require explicit opt-in for each "apply" action.
2. **Never store cloud credentials.** API keys, not username/password. User revokes the key from their account when done.
3. **Offer local-only operation.** For users who don't want a third-party service touching their network: CLI or local-install mode that runs entirely on their machine, processes a backup file, and outputs a report. No telemetry.
4. **Be transparent about the Classic API tradeoff.** If the wizard falls back to cookie auth for features not in the official API, warn clearly: "this requires a local admin without MFA, which weakens your security posture. Use only for this session and rotate after."
5. **Scope narrowly.** Don't ask for write permission to make changes unless the user opted into "apply mode."
6. **Ephemeral tokens.** Where possible, generate short-lived tokens rather than long-lived ones.

---

## Part 7: Updated Recommended Next Steps

Building on the original 5-phase roadmap.

### Revised phase plan

**Phase 1: Static questionnaire + scoring (2-3 weeks)**
Validate content with 5 real networks across profiles (home novice, home tinkerer, small business, regulated). No API integration yet.

**Phase 2: Backup-file parser (3-4 weeks)**
Parse `.unf` offline. This is the highest-leverage integration because it requires no auth, works airgapped, and handles 80% of the "API" mapping above.

**Phase 3: Site Manager API read integration (2-3 weeks)**
Pulls device inventory, health, aggregate config. Limited but low-friction (no local access required).

**Phase 4: Network Integration API read (3-4 weeks)**
Pulls detailed per-site config: VLANs, firewall, WLANs, port forwards, UPnP, etc. This is where the "discovery-first" design fully lights up.

**Phase 5: Classic API fallback (optional, 2 weeks)**
Only for items not in official API (historical traffic flows, some event streams). Gated behind explicit consent and a security warning.

**Phase 6: MCP server (2-3 weeks)**
Package the wizard's API interactions as an MCP server. Lets Claude (or any MCP-compatible agent) query the user's UniFi state and collaborate on fixes. Pairs well with the user's Home Assistant plans.

**Phase 7: Apply mode with diff preview (4-6 weeks)**
Generate config changes, show diff vs current, require explicit approval per change. Uses write endpoints as they land.

**Phase 8: Continuous drift monitoring (ongoing)**
Scheduled re-runs, alert on drift from approved baseline, trigger a mini-review when drift detected.

### Biomimetic/adaptive layer (stretch)

Given your background, the engine itself can reflect natural-system patterns:
- **Immune-system analogy for the scoring model:** distinguishing self (approved baseline) from non-self (drift, new devices, policy exceptions), with graduated response levels rather than binary pass/fail.
- **Foraging/path-reinforcement for remediation ordering:** tasks that have been completed successfully in similar profiles get recommended more confidently; a feedback loop improves ranking over time.
- **Mycelial redundancy as a design principle for alerts:** multiple low-cost signals combining into a confident detection, rather than single high-sensitivity rules that generate fatigue.

These could be positioned as the wizard's differentiator in a crowded "network assessment tool" market.
