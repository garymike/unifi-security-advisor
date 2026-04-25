# Requirements Intel

Synthesized from PRD source: ROADMAP.md (single PRD in this set).

Each requirement is normalized to a `REQ-{slug}` ID. Acceptance criteria are derived from the ROADMAP's Phase deliverables, working-checklist items, and validation tasks. Where ROADMAP refers to specific source files (e.g., `src/unifi_audit.py`), provenance is preserved.

---

## Phase requirements (product roadmap)

### REQ-phase1-live-api-audit

- source: ROADMAP.md (Phase 1: Live API audit)
- status: in progress
- description: Audit a UniFi deployment using the Network Integration API (X-API-KEY). Read-only. Produces a sanitized markdown report and structured JSON.
- deliverable: `src/unifi_audit.py` (skeleton complete; needs validation against a real network)
- acceptance criteria:
  - Connects via X-API-KEY (Network Integration API), read-only
  - Produces sanitized markdown report
  - Produces structured JSON output
  - Wires all enhanced finding modules (currently a subset is wired)
  - Implements always-float-to-top finding override logic
  - Implements profile-aware scoring weights
  - Implements cross-answer tension detection (compound findings)
- scope: Phase 1
- depends on: REQ-finding-modules-implemented, REQ-sanitization-pre-output, REQ-audit-log

### REQ-phase2-intent-interview-wizard

- source: ROADMAP.md (Phase 2)
- status: not started
- description: Web/CLI wizard that consumes the Phase 1 JSON and asks only the gap questions (intent, non-UniFi devices, process). Merges API-detected facts with user-stated intent into a complete report.
- deliverable: Wizard frontend + question-orchestration backend
- acceptance criteria:
  - Consumes Phase 1 structured JSON
  - Asks only gap questions (those not answerable from API/backup)
  - Merges API-detected facts with user-stated intent into a unified report
  - Implements three-tier voicing (Guided / Standard / Pro) with skills-check routing
  - Supports free-text "Other" + optional clarification on every question
  - Routes "not sure" answers to guided helper / auto-check / defer
- scope: Phase 2
- open questions (from ROADMAP): web vs TUI vs both; where the skills check lives (pre-audit prompt, hidden in API output, CLI flag with optional override).

### REQ-phase3-site-manager-fallback

- source: ROADMAP.md (Phase 3)
- status: scaffolded, needs validation
- description: Site Manager API fallback for users behind CGNAT or with multi-site MSP needs. Same audit logic, different transport.
- deliverable: Site Manager API mode in `unifi_audit.py` (already partially scaffolded with `UNIFI_USE_CLOUD=true`)
- acceptance criteria:
  - Authenticates via Site Manager X-API-KEY (cloud-routed)
  - Reuses existing finding modules
  - Validates against a console with Cloud Connector enabled (post-April-2026 unified API key)
  - Subset of findings noted (Site Manager API has less depth than Network Integration; document which findings are unavailable in cloud mode)
- scope: Phase 3

### REQ-phase4-backup-file-mode

- source: ROADMAP.md (Phase 4), elaborated by docs/04-backup-file-strategy.md (DOC)
- status: skeleton only
- description: Specialist mode for `.unf` and `.unifi` parsing (airgap / forensic / MSP-handoff use cases). Same finding modules consume parsed data instead of API responses.
- deliverable: `src/parser.py` (skeleton exists), `.unifi` decryption support
- acceptance criteria:
  - AES-128-CBC decrypt of `.unf` (static key/IV; public reverse-engineered values)
  - Extract ZIP → gzipped BSON → MongoDB collection dicts
  - Sanitization pass before any output (PSKs, RADIUS, admin password hashes, etc.)
  - Finding modules emit `Finding` dataclass instances identical to live-API mode
  - CLI: `usa analyze`, `usa questions`, `usa dump --unsafe-include-secrets` (explicit opt-in)
  - Outputs: `report.md`, `gap_questions.md`, `state.json`
  - Runs entirely offline (no network calls during parse)
  - `.unifi` console-format decryption (community keys exist; not yet integrated)
- scope: Phase 4 (specialist; not primary)
- milestones (from docs/04): M1 decrypt+extract+BSON (~200 LOC), M2 sanitizer (~100 LOC), M3 sections 2-8 modules (~800 LOC), M4 sections 9-12 modules (~400 LOC), M5 report generator (~200 LOC), M6 gap-question generator (~150 LOC), M7 CLI + Python API + docs (~200 LOC), M8 test suite. Estimated ~2000 LOC plus tests.

### REQ-phase5-mcp-integration

- source: ROADMAP.md (Phase 5), elaborated by docs/06-mcp-strategy.md
- status: not started
- description: Skills/prompts that teach Claude how to use `sirkirby/unifi-mcp` tools to remediate our findings. Do NOT build our own MCP server.
- deliverable: MCP skill files mapping each finding ID to upstream MCP tool calls
- acceptance criteria:
  - One skill per finding ID describing remediation tool calls into sirkirby/unifi-mcp
  - Documented mapping (finding ID → tool name → expected effect)
  - User provides their own API key to the MCP; advisor does not store credentials
  - MCP integration explicitly opt-in with clear disclosure of the auth tradeoff (cookie path requires MFA-less local admin for full feature surface)
  - Recommend a dedicated local MCP admin account (separate from daily-use cloud admin)
- scope: Phase 5 (optional add-on)

### REQ-phase6-apply-mode

- source: ROADMAP.md (Phase 6)
- status: not started, awaiting API write GA
- description: Generate UniFi config changes that can be reviewed as a diff and applied via the API. Preview-then-confirm per change.
- deliverable: Apply mode in `unifi_audit.py` with explicit `--apply` flag
- acceptance criteria:
  - Uses official write endpoints as they stabilize
  - Preview-then-confirm flow per change (matches MCP community norms)
  - Explicit `--apply` flag required
  - Per-action opt-in (no bulk apply)
- scope: Phase 6

### REQ-phase7-continuous-drift-monitoring

- source: ROADMAP.md (Phase 7)
- status: not started
- description: Scheduled re-runs, alert on drift from approved baseline, mini-review when drift detected.
- deliverable: Scheduler + diff engine + alerting
- scope: Phase 7

---

## Phase 1 sub-requirements (working checklist)

### REQ-finding-module-segmentation
- source: ROADMAP.md (Phase 1 working checklist)
- status: implemented
- description: Flat-network detection across `networkconf` / API networks list.
- module: `src/findings_enhanced.py` / `src/unifi_audit.py`

### REQ-finding-module-wifi
- source: ROADMAP.md
- status: implemented
- description: Security mode and PSK strength findings.
- module: covered in `src/unifi_audit.py`

### REQ-finding-module-firewall
- source: ROADMAP.md
- status: implemented (basic)
- description: Port forwards basic finding logic.

### REQ-finding-module-remote-access
- source: ROADMAP.md
- status: implemented
- description: VPN protocol tiering (PPTP critical, L2TP discouraged, WireGuard preferred), port-forwards-without-VPN finding.
- reinforced by: docs/08-questionnaire-addendum.md Section 8 update.

### REQ-finding-module-devices
- source: ROADMAP.md
- status: implemented
- description: SSH enablement per device.

### REQ-finding-module-wireless-tuning
- source: ROADMAP.md, elaborated by docs/07-coverage-analysis.md and docs/08-questionnaire-addendum.md (Section 6.5)
- status: implemented
- description: TX power, 2.4 GHz audit, rogue AP, PMF (Protected Management Frames).
- acceptance criteria:
  - TX power "High" → LOW severity recommendation (unless intentionally outdoor/large property)
  - 2.4 GHz active with few/no 2.4-only clients → INFO recommendation
  - Rogue AP detection OFF → MEDIUM finding
  - Fast roaming OFF on multi-AP deployments → LOW
  - PMF disabled on WPA3 SSID → MEDIUM (required by WPA3 spec)
- evidence sources: `device.radio_table[].disabled`, `tx_power_mode`, `tx_power`, `min_rssi_enabled`, `setting.rogueap`, `wlanconf.fast_roaming_enabled`, `pmf_mode`.

### REQ-finding-module-firewall-threats
- source: ROADMAP.md, elaborated by docs/08-questionnaire-addendum.md Section 7
- status: implemented
- description: Geo-IP both directions (WAN_IN and WAN_OUT), content filtering (DNS-based), safe-search enforcement (conditional on children-in-household).
- acceptance criteria:
  - WAN_IN no geo filter → recommendation
  - WAN_OUT no geo filter → recommendation (compromised devices phoning home)
  - Content filtering Security category minimum recommended
  - Family category recommended only if children indicated in Section 1
  - Safe-search only evaluated if user indicated children/education context

### REQ-finding-module-firmware
- source: ROADMAP.md, elaborated by docs/08 Section 12
- status: implemented
- description: Auto-update toggle, EOL hardware cross-reference, stale versions.
- acceptance criteria (split into 4 update domains, per docs/08):
  - 12.1a Per-device firmware (`device.version` vs current per model)
  - 12.1b UniFi OS version (only available via `.unifi` backup or Site Manager)
  - 12.1c UniFi Network app version
  - 12.1d Other apps (Protect, Access, Talk) — only if installed
  - EOL hardware: MEDIUM if EOL within 12 months, HIGH if already EOL
  - Known-vulnerable firmware via static CVE database (deferred; ship with ~12 months of advisories initially)

### REQ-finding-module-logging
- source: ROADMAP.md, elaborated by docs/08 Section 9
- status: implemented
- description: Privacy-aware retention recommendations by profile.
- profile-recommended retention windows:
  - Home: 7-14 days (traffic), 30 days (admin)
  - Home office: 14-30 days (traffic), 90 days (admin)
  - Small business: 30-90 days (traffic), 1 year (admin)
  - Regulated (HIPAA, PCI): 6 years minimum both
  - Regulated (NERC CIP): 3+ years both
- finding logic: longer than profile → LOW (privacy cost without benefit); shorter than profile requirement → MEDIUM, or HIGH if regulated.

### REQ-finding-module-backup
- source: ROADMAP.md, elaborated by docs/08 Section 10
- status: implemented
- description: Destination diversity finding (off-device backup destination required); tested-restore Schrödinger finding (always fires unless user confirms tested restore in last 12 months).
- severity: tested-restore = MEDIUM all profiles, HIGH for regulated.

### REQ-finding-module-api-coverage-meta
- source: ROADMAP.md
- status: implemented
- description: Meta-finding tracking which questionnaire items are answered by API vs require user input.

---

## Phase 1 needs-work items (open requirements)

### REQ-wire-enhanced-modules-into-audit-script
- source: ROADMAP.md "Needs work"
- description: Wire all enhanced finding modules into the live audit script (`unifi_audit.py` currently has a subset).

### REQ-cross-answer-tension-detection
- source: ROADMAP.md "Needs work" + DECISIONS.md D-003
- description: Implement compound-finding correlation pass after individual modules run.

### REQ-profile-aware-scoring-weights
- source: ROADMAP.md "Needs work"
- description: Profile-aware scoring weights so home profiles don't get enterprise-retention recommendations and regulated profiles don't get under-tuned.

### REQ-always-float-to-top-overrides
- source: ROADMAP.md "Needs work" + CLAUDE.md "Always-float-to-top findings" + QUESTIONNAIRE.md
- description: Override logic that surfaces these findings to the top regardless of overall scoring:
  - No MFA on any admin account
  - Management plane reachable from WAN
  - Flat network with multiple device classes (IoT + work + personal) on one VLAN
  - Default credentials anywhere
  - Firmware more than two majors behind with known advisories
  - PPTP or any deprecated-crypto VPN enabled

---

## Validation requirements

### REQ-validation-real-network
- source: ROADMAP.md "Validation"
- description: Run `unifi_audit.py` against a real UniFi network and confirm endpoints respond as expected.

### REQ-validation-api-response-shapes
- source: ROADMAP.md
- description: Diff actual API response shapes against assumed shapes in `_extract_list` and similar helpers.

### REQ-validation-network-version-compat
- source: ROADMAP.md
- description: Test with Network version >= 9.3.43 (required for integration API). Test with an older version to confirm graceful 404 handling.

### REQ-validation-cloud-mode
- source: ROADMAP.md
- description: Test cloud mode (`UNIFI_USE_CLOUD=true`) once a unified key with Cloud Connector is available (April 2026 unified key).

### REQ-validation-ssl-self-signed
- source: ROADMAP.md
- description: Test SSL self-signed default for local mode.

### REQ-validation-sanitization-coverage
- source: ROADMAP.md
- description: Confirm sanitization catches all secret field names in actual API responses (regression-tested against fixtures).

### REQ-test-fixtures
- source: CLAUDE.md "Testing fixtures we need"
- description: Phase 1 validation requires:
  - At least one real UniFi Network backup file (single-site `.unf`)
  - At least one JSON dump from a live API run
  - Anonymized profiles across scales: home single-AP, home-office multi-AP, small business, simulated regulated environment
- profile labels (used in code): `home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`.

---

## Documentation requirements (delivered)

ROADMAP.md notes the following docs as complete:

- `AUDIT_QUICKSTART.md` (user-facing quickstart)
- `docs/01-design-philosophy.md`
- `docs/02-api-strategy.md`
- `docs/03-site-manager-vs-network-integration.md`
- `docs/04-backup-file-strategy.md`
- `docs/05-credential-handling.md`
- `docs/06-mcp-strategy.md`
- `docs/07-coverage-analysis.md`
- `docs/08-questionnaire-addendum.md`
- `QUESTIONNAIRE.md`
- `DECISIONS.md`
- `ROADMAP.md` (the working checklist itself)

---

## Known gaps deferred (tracked, not lost)

From ROADMAP.md "Known gaps" section:

- MFA on cloud admin account — not in any API or backup; gap question for Phase 2 wizard.
- CyberSecure subscription state — lives in cloud, not exposed via current local API.
- Real-time traffic patterns — not in backup; live API has limited visibility.
- CVE database for known-vulnerable firmware — need to maintain or source a feed.
- Protect/Access app audits — out of scope Phase 1 (Network only).
- Multi-site MSP workflows — Phase 3 territory.
- `.unifi` console-format decryption — Phase 4 territory.

---

## Out-of-scope items (Phase 1)

From CLAUDE.md "Out of scope for phase 1" + ROADMAP.md:

- Apply mode (write operations) — Phase 6
- Drift monitoring over time — Phase 7
- Continuous/scheduled audits — Phase 7
- Multi-site aggregation beyond listing — Phase 3
- Protect/Access app audits — deferred (Network only for Phase 1)
