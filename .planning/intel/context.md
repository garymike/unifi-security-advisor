# Context Intel

Running notes from DOC sources, keyed by topic. Verbatim attribution preserved. Lower precedence than ADR / SPEC / PRD; informational unless a higher-precedence source contradicts.

---

## Topic: Design philosophy and core thesis

source: docs/01-design-philosophy.md

UniFi's built-in UI tells users *how* to configure things but not *whether their configuration is good*. This tool closes that gap by being:

1. Discovery-first — detect current state before asking the user anything.
2. Tier-aware — same content, three voices, routed by skills not self-assessment.
3. Intent-confirming — ask "is this what you wanted?" not "do you have X?"
4. Officially-supported by default — use Ubiquiti's documented APIs, not reverse-engineered shortcuts.
5. Credential-respecting — a security tool that requires weakening security to use it has an inverted threat model.
6. Biomimetic — layered compartments (segmentation), graduated immune response (scoring), mycelial redundancy (alert correlation).

### Discovery-first pattern

Old: *"Do you have IDS/IPS enabled?"* → user guesses → "Not sure"
New: *"IDS/IPS is currently disabled. Your gateway can run it at 2.5 Gbps. Want it on?"* → user confirms intent.

Where this fails: questions about intent, goals, fears, priorities, compliance, non-UniFi devices, physical placement, and process. These stay user-only because no API or backup can answer them.

### Three tiers (recap)

| Tier | Audience | Voice |
|---|---|---|
| Guided | Novice, non-technical | Plain language, analogies, yes/no |
| Standard | Prosumer, IT-literate | Named features, moderate jargon |
| Pro | Engineer, architect | Exact config, control IDs, CVE refs |

### Intent-confirming finding shape

Every finding explains:
1. Current state in plain language
2. Recommendation tailored to the user's profile
3. Intent question so the user can correct us

### Biomimetic framing (organizing metaphors)

- Layered compartments — segmentation as cell-walls / organ-systems analog. A compromised IoT bulb shouldn't reach a NAS.
- Graduated immune response — scoring isn't binary. Innate (default-password, MFA) checks are universal; adaptive checks layer on top by environment / threat profile / regulatory needs.
- Mycelial redundancy — multiple low-cost signals combine into confident detections. Cross-answer tension detection produces compound findings, not three separate bullets.

### What we are not

- A penetration testing tool (no exploitation, no active probing)
- A runtime IDS/IPS (UniFi has its own)
- A config-management tool (no Terraform/Pulumi for UniFi)
- A substitute for Ubiquiti's Update Manager or security advisories
- A general-purpose network scanner (UniFi-specific awareness is the whole point)

---

## Topic: Site Manager API vs Network Integration API

source: docs/03-site-manager-vs-network-integration.md

### One-line summary

| API | Purpose | Scope |
|---|---|---|
| Site Manager API | Fleet monitoring across many sites | Breadth (all sites, aggregate health) |
| Network Integration API | Detailed management of one site | Depth (firewall, WLANs, port forwards, devices, clients) |

### Site Manager API (cloud, `api.ui.com/v1/`)

- Good at: list hosts/sites/devices across an account, ISP health metrics, aggregate performance, works through CGNAT/dynamic IP/any topology, works from anywhere with internet.
- Limited: no granular config (firewall rules, specific WLAN settings), no port-forward details, no per-client details beyond counts, no VLAN/network configuration. Read-only today; writes coming.

### Network Integration API (local, `{console}/proxy/network/integration/v1/`)

- Good at: full firewall policy management (zones, ZBF), port forwards, traffic routes, NAT, all networks/VLANs with full config, all WLANs with security/guest/isolation/VLAN mapping, per-client details, device config, port profiles, radio settings, QoS.
- Limited: one site at a time; requires direct network path (or new Cloud Connector); does NOT include UniFi OS-level settings (those live above the Network app).

### Cloud Connector (April 2026)

Site Manager API keys can now proxy requests to Network Integration endpoints via Ubiquiti's cloud:

```
https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration/v1/...
```

Effectively resolves the CGNAT problem.

### Security posture (key contrasts)

| Concern | Site Manager | Network Integration |
|---|---|---|
| Dependency on Ubiquiti cloud integrity | Yes | No (unless using Cloud Connector) |
| Works if SSO account compromised | No (single point of failure) | Yes (key independent) |
| Blast radius of leaked key | Broader (fleet/account) | Narrower (one console) |
| Requires network path to use | No | Yes |
| Attack chain | 1 step (use key) | 2 steps (key + network access) |

For solo home users with one console: Network Integration has slightly better isolation. For an MSP with 50 sites: Site Manager is operationally essential. For compliance-sensitive environments: Network Integration keeps the trust boundary entirely with the user.

### Choice for the audit tool

Primary: Network Integration API.
Reasons:
1. Findings modules need firewall details, WLAN config, port forwards, VLAN structure — Site Manager doesn't expose these.
2. Trust boundary stays with the user.
3. Smaller blast radius if the tool's storage is compromised.
4. No Ubiquiti cloud dependency.

Fallback: Site Manager API + Cloud Connector — for multi-site MSP, CGNAT, or explicit user preference.

---

## Topic: Backup file (`.unf`) format and parsing

source: docs/04-backup-file-strategy.md

### File format

A `.unf` file is:
1. AES-128-CBC encrypted blob (static key and IV, public in UniFi source)
2. Decrypts to a standard ZIP archive
3. ZIP contains `db.gz` (gzipped BSON MongoDB dump) and a few metadata files
4. BSON dump contains the UniFi Network controller database

Public reverse-engineered keys (hex):

- Key: `626379616e676b6d6c756f686d617273` (ASCII: `bcyangkmluohmars`)
- IV:  `75626e74656e74657270726973656170` (ASCII: `ubntenterpriseap`)

Newer console-level `.unifi` backups (multi-site, includes PostgreSQL for UCore) are out of scope for Phase 1; targeted at Phase 4 / 1.5.

### MongoDB collections of interest

| Collection | What we learn |
|---|---|
| `device` | All adopted devices: gateways, switches, APs. Model, firmware, adoption state, SSH config, LED/location hints. Includes `radio_table[]` for per-AP radio audits. |
| `networkconf` | Networks/VLANs: subnet, gateway, DHCP, DNS, VLAN ID, purpose, isolation toggle. |
| `wlanconf` | WLANs/SSIDs: security mode, WPA version, PSK (hashed), hidden flag, VLAN mapping, guest policy, band, client isolation, PMF, PPSK entries. |
| `firewallrule` | Legacy firewall rules. |
| `firewallgroup` | IP/port groups referenced by rules. |
| `portforward` | All port forwards. |
| `routing` | Static and policy routes. |
| `setting` | System-wide settings blob. Includes `mgmt`, `super_identity`, `usg`, `auto_speedtest`, `country`, `connectivity`, `dpi`, `threat_management`, `auto_backup`, `rogueap`. |
| `account` / `admin` | Admin users, auth method, role. |
| `alarm` | Triggered alarms. |
| `user` | Known clients with fingerprint, note, fixed IP. |
| `usergroup` | Bandwidth/access policies. |
| `event` | Historical events (truncated). |

Newer UniFi OS versions may include OON (Object-Oriented Network policies) in their own collection; parser handles both schemas.

### Parser pipeline

```
.unf → decrypt.py (AES-128-CBC) → extract.py (zip + gzip + BSON) → sanitize.py
   → findings/ (one module per questionnaire section, each emits list[Finding])
   → report.py (Markdown + JSON) and gap_questions.md
```

### What backup-file mode CAN answer

Device inventory; networks/VLANs and clients per network; WLANs and security/isolation/VLAN mapping; all firewall rules and port forwards; UPnP state; DNS per network; admin auth methods; SSH per device; IDS/IPS configuration; auto-update settings; geo/content filtering; VPN server configs; backup schedule/retention; client inventory.

### What backup-file mode CANNOT answer

- MFA on cloud admin (lives in Ubiquiti SSO, not backup)
- WPA password strength (we see length + fingerprint, not the password)
- Current CyberSecure subscription state (live status authoritative)
- Remote access via Site Manager / Teleport user list (cloud-side)
- Content filtering category-list freshness (depends on live state)

### What still requires user input

- Intent, goals, priorities, fears
- Non-UniFi devices (NAS, Firewalla, Home Assistant, smart home hubs, printers)
- Physical placement
- Process: tested restore, runbook, break-glass admin documented
- Compliance obligations
- Migration context
- Future plans

### CLI surface (illustrative, from source)

```bash
usa analyze backup.unf
usa analyze backup.unf --redact-pii --out report.md
usa dump backup.unf --unsafe-include-secrets    # explicit opt-in, prints warning
usa questions backup.unf
```

### Output artifacts (per run)

- `report.md` — findings ordered by severity + section, sanitized.
- `gap_questions.md` — user-only questions scoped to user's profile.
- `state.json` — machine-readable structured output.

NOTE: docs/04 is dated when backup-file mode was the planned Phase 1 deliverable. D-007 (ADR, locked) supersedes the Phase 1 framing — backup-file mode is now Phase 4 (specialist). The technical content above (file format, collections, parser pipeline) remains current; only the phasing changed.

---

## Topic: 10-point coverage analysis vs original design

source: docs/07-coverage-analysis.md

A 10-point reference video (firmware/console updates; VLAN segmentation; SSID/WPA; per-AP radio tuning; IDS/IPS; geo + content filtering; firewall zones; auto-backup + tested restore; traffic logging + retention; VPN protocol preference) was compared against the design.

Verdict: 9 of 10 covered at the questionnaire level; most parser modules were stubs at the time of analysis. **Point 4 (per-AP radio tuning)** was missing entirely.

### Outcome

- Added Section 6.5: Wireless Tuning (5 questions, new parser module). Fully derivable from `device.radio_table[]`, `wlanconf.fast_roaming_enabled`, `setting.rogueap`.
- Promoted "tested restore" to a standalone finding (Schrödinger backup framing — viability unknown until the worst moment).
- Added VPN protocol-preference logic: PPTP CRITICAL, L2TP discouraged, WireGuard preferred.
- Split content filtering from Geo-IP in Section 7 (Q7.5a/b/c).
- Added safe-search sub-question (conditional on children-in-household).
- Added firmware-currency check (per-device version vs known-current).
- Added privacy-aware logging recommendations (less retention for home, more for regulated).
- Audited 4 update domains separately (UniFi OS / Network app / Protect-Access-Talk apps / per-device firmware).

### Reasoning for the radio-tuning add (security framing, not just performance)

- Rogue AP / evil twin exposure scales with TX power.
- Disabled radios reduce attack surface (every active radio is a wireless listener; legacy-protocol downgrade attacks live on 2.4 GHz).
- Channel selection affects deauth/jamming detectability.
- Excess radio coverage enables drive-by fingerprinting.

---

## Topic: Questionnaire addendum (coverage fixes)

source: docs/08-questionnaire-addendum.md

Supplemental updates to the baseline questionnaire integrated into QUESTIONNAIRE.md. All additions derivable from backup data, no net increase in user questions (new items map to confirm-intent prompts after automatic detection).

### Section 6.5 additions (Wireless Tuning) — finding logic summary

- TX power "High" → LOW severity recommendation (unless intentionally outdoor / large property).
- 2.4 GHz active with few/no 2.4-only clients → INFO recommendation to evaluate disabling.
- Rogue AP detection OFF → MEDIUM finding.
- Fast roaming OFF on multi-AP deployments → LOW (performance + security combo).
- PMF disabled on WPA3 SSID → MEDIUM (required by WPA3 spec).

### Section 7 split (Geo-IP / Content / Safe-search)

- Q7.5a Geo-IP — flag if WAN_IN no geo filter; also check WAN_OUT (compromised devices phoning home).
- Q7.5b Content filtering (DNS-based) — recommend Security category minimum; Family category if children indicated.
- Q7.5c Safe-search — only evaluate if user indicated children/education context.

### Section 8 VPN tiering

- PPTP enabled → CRITICAL (deprecated, MS-CHAPv2 broken).
- L2TP/IPsec only VPN → MEDIUM.
- No VPN + port forwards active → HIGH.
- WireGuard configured → OK, surface as a win.

### Section 9 retention recommendations (profile-aware)

| Profile | Traffic log retention | Admin log retention |
|---|---|---|
| Home / personal | 7-14 days | 30 days |
| Home office | 14-30 days | 90 days |
| Small business | 30-90 days | 1 year |
| Regulated (HIPAA, PCI) | 6 years | 6 years minimum |
| Regulated (NERC CIP) | 3+ years | 3+ years |

Logic:
- Longer than profile recommendation → LOW (privacy cost without benefit).
- Shorter than profile requirement → MEDIUM (compliance gap), HIGH if regulated.
- DPI logging at client level + home profile → LOW (recommend aggregate/protocol-only).

### Section 10 backup additions

- Tested-restore finding — always fires unless user confirms. MEDIUM all profiles, HIGH for regulated.
- Backup destination diversity — local-only is a finding (single point of failure: hardware failure, theft, ransomware-of-device). MEDIUM. Recommend off-device (cloud, SMB on NAS, periodic manual download).

### Section 12 firmware additions

- Split into 4 update domains (12.1a-d).
- New finding: known-vulnerable firmware (CVE cross-reference); requires small static CVE database (deferred to Phase 1.5 / Phase 2).
- New finding: EOL hardware — MEDIUM if EOL within 12 months, HIGH if already EOL.

---

## Topic: API authentication landscape (background)

source: docs/02-api-strategy.md (ADR-classified, but topical context preserved here for background)

Three authentication methods exist for the UniFi Network API, not two:

1. Classic cookie-session auth — requires MFA-less local admin (the path we avoid).
2. Network Application API Key — official, post-July-2024 MFA rollout, X-API-KEY header, no MFA tradeoff.
3. Site Manager API Key — official, cloud-routed, X-API-KEY.

Earlier framings that conflated all local auth with the cookie+MFA-less-admin tradeoff were corrected by docs/02. The X-API-KEY paths are officially supported; cookie auth still exists for legacy/full-feature cases.

### Why API-key is better than the older framing

- No MFA tradeoff
- Revocable without credential rotation
- Scoped to API use (key is not valid for web UI / mobile app login)
- Officially supported (write endpoints arriving)
- Defensible narrative for a security tool ("use Ubiquiti-recommended auth")

### "Is backup decryption hacking?"

Honest framing per docs/02:
- Ubiquiti has never published a decryption tool nor documented the format.
- Keys are static, hardcoded, trivially extractable, public since 2017+.
- Ubiquiti has not taken action against community tools (no key rotation, no DMCA).
- The user owns the backup of their own system.
- Ubiquiti does not recommend, endorse, or support backup decryption.

Best framing: **reverse-engineered, unofficial, community-supported**, not "hacking." A security tool should prefer the officially-supported path as primary; backup mode is a legitimate alternative for airgap, MSP-handoff, forensic, historical, and compliance-evidence cases.

---

## Topic: MCP tradeoff details (background)

source: docs/06-mcp-strategy.md (ADR-classified; topical context preserved)

### What sirkirby/unifi-mcp provides

- Network app MCP — 166 tools, stable
- Protect app MCP — 38 tools, beta
- Access app MCP — doors, credentials, visitors, policies
- Relay sidecar via Cloudflare Worker for cloud-side agents (no inbound ports)

### Security posture (their design)

- Credentials stay local (username/password used to authenticate directly with the local controller; not transmitted to any external service except optionally through user's own Cloudflare Worker).
- Read-only by default; write ops disabled out-of-the-box, require explicit opt-in per category.
- Preview-then-confirm for all mutations.
- Policy gates via env vars.
- API key auth supported as experimental read-only (subset of tools).
- No DB / cache / sessions stored locally.

### Auth modes

1. X-API-KEY (Network Integration API path) — read-only, experimental, subset of tools.
2. Local admin username + password via `/api/auth/login` + cookie session — enables full tool surface including writes; same mechanism as the Classic API path.

The MCP's full-feature surface requires the same MFA-less local admin we flagged as a weakness in our primary path.

### When backup-file vs MCP wins (from source)

Backup-file wins when: paranoid/regulated, MSP audit (client hands over backup), posture/config hygiene focus, network down, change-over-time, forensic-after-compromise.

MCP wins when: remediation help (not just analysis), live-state questions, interactive workflow, comfortable granting local admin, Protect/Access app audits alongside Network, NL agent driving (Claude Desktop / Code).

### Caveat (preserved from source)

The MCP auth model is the Classic API pattern. For the live/apply features, the user trades some admin-surface hardening for agent-driven remediation. The wizard should make this explicit, not slip it in. Recommendation: require a dedicated local MCP admin account with strong password in a password manager, separate from daily-use cloud admin.

NOTE: docs/06 was written when backup-file was framed as the primary mode. Its specific phase numbering ("Phase 1 backup-file, Phase 3 MCP") is superseded by D-007 in DECISIONS.md (locked ADR) and ROADMAP.md (PRD), which place Phase 1 = Live API audit, Phase 4 = backup-file specialist, Phase 5 = MCP integration. The MCP integration decision itself (D-006) is consistent across all sources.
