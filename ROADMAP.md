# Roadmap and Working Checklist

## Phase plan

### Phase 1: Live API audit (in progress)

Audit a UniFi deployment using the Network Integration API (X-API-KEY). Read-only. Produces sanitized markdown report + structured JSON.

**Deliverable:** `src/unifi_audit.py` (skeleton complete; needs validation against real network)

**Status: in progress**

### Phase 2: Intent-interview wizard

Web/CLI wizard that consumes the Phase 1 JSON and asks only the gap questions (intent, non-UniFi devices, process). Merges API-detected facts with user-stated intent into a complete report.

**Deliverable:** Wizard frontend + question-orchestration backend.

**Status: not started**

### Phase 3: Site Manager API fallback

For users behind CGNAT or with multi-site MSP needs. Same audit logic, different transport.

**Deliverable:** Site Manager API mode in `unifi_audit.py` (already partially scaffolded with `UNIFI_USE_CLOUD=true`).

**Status: scaffolded, needs validation**

### Phase 4: Backup-file mode (specialist)

`.unf` and `.unifi` parsing for airgap/forensic/MSP-handoff use cases. Same finding modules consume parsed data instead of API responses.

**Deliverable:** `src/parser.py` (skeleton exists), `.unifi` decryption support.

**Status: skeleton only**

### Phase 5: MCP integration (optional add-on)

Skills/prompts that teach Claude how to use `sirkirby/unifi-mcp` tools to remediate our findings. We do NOT build our own MCP server.

**Deliverable:** MCP skill files mapping each finding ID to upstream MCP tool calls.

**Status: not started**

### Phase 6: Apply mode

Generate UniFi config changes that can be reviewed as a diff and applied via the API. Preview-then-confirm per change. Uses official write endpoints as they stabilize.

**Deliverable:** Apply mode in `unifi_audit.py` with explicit `--apply` flag.

**Status: not started, awaiting API write GA**

### Phase 7: Continuous drift monitoring

Scheduled re-runs, alert on drift from approved baseline, mini-review when drift detected.

**Deliverable:** Scheduler + diff engine + alerting.

**Status: not started**

---

## Working checklist (Phase 1)

### Infrastructure

- [x] Project structure (README, CLAUDE.md, docs/, src/, samples/)
- [x] Single-file audit script (`src/unifi_audit.py`)
- [x] Sanitization pre-output
- [x] Audit log (no secrets)
- [x] Markdown + JSON report generation
- [x] Quickstart documentation (`AUDIT_QUICKSTART.md`)

### Findings modules (in `src/unifi_audit.py` and `src/findings_enhanced.py`)

#### Implemented

- [x] Segmentation (flat-network detection)
- [x] Wi-Fi (security mode, PSK strength)
- [x] Firewall (port forwards basic)
- [x] Remote access (VPN protocol tiering, port-forwards-without-VPN)
- [x] Devices (SSH enablement)
- [x] Wireless tuning (TX power, 2.4 GHz audit, rogue AP, PMF)
- [x] Firewall threats (geo-IP both directions, content filtering)
- [x] Firmware (auto-update, EOL hardware, stale versions)
- [x] Logging (privacy-aware retention by profile)
- [x] Backup (destination diversity, tested-restore Schrödinger finding)
- [x] API coverage meta-finding

#### Needs work

- [ ] Wire all enhanced finding modules into the live audit script (`unifi_audit.py` currently has a subset)
- [ ] Cross-answer tension detection (compound findings)
- [ ] Profile-aware scoring weights
- [ ] Always-float-to-top finding override logic

### Validation

- [ ] Run `unifi_audit.py` against a real UniFi network and confirm endpoints respond as expected
- [ ] Diff actual API response shapes against assumed shapes in `_extract_list` etc.
- [ ] Test with a Network version >= 9.3.43 (required for integration API)
- [ ] Test with an older Network version to confirm graceful 404 handling
- [ ] Test cloud mode (`UNIFI_USE_CLOUD=true`) once we have a unified key with Cloud Connector
- [ ] Test the SSL self-signed default for local mode
- [ ] Confirm sanitization catches all secret field names in actual API responses

### Documentation

- [x] User-facing quickstart (`AUDIT_QUICKSTART.md`)
- [x] Design philosophy (`docs/01-design-philosophy.md`)
- [x] API strategy (`docs/02-api-strategy.md`)
- [x] Site Manager vs Network Integration (`docs/03-...`)
- [x] Backup-file strategy (`docs/04-...`)
- [x] Credential handling requirements (`docs/05-...`)
- [x] MCP strategy (`docs/06-...`)
- [x] Coverage analysis vs 10-point video (`docs/07-...`)
- [x] Questionnaire addendum (`docs/08-...`)
- [x] Consolidated questionnaire (`QUESTIONNAIRE.md`)
- [x] Decision log (`DECISIONS.md`)
- [x] Working checklist (this file)

### Open questions for next session

- Whether to validate Phase 1 against the real network now, or finish wiring all enhanced findings first (validation will surface integration issues either way)
- Tier-routing logic: where does the skills-check live? Pre-audit prompt? Hidden in the API output? CLI flag with optional override?
- Profile detection: can we infer profile from API data alone (e.g., "regulated_hipaa" if HIPAA-typical patterns present) or always require user input?
- Sample data fixtures: a real run will expose response shape differences. Should we maintain anonymized fixtures in `samples/` for regression testing?

---

## Known gaps (deferred, not forgotten)

These are explicitly out of scope for Phase 1 but tracked here so they don't get lost.

- **MFA on cloud admin account.** Not in any API or backup. Must be a gap question for the wizard (Phase 2).
- **CyberSecure subscription state.** Lives in cloud, not exposed via current local API.
- **Real-time traffic patterns.** Not in backup; live API has limited visibility.
- **CVE database for known-vulnerable firmware.** Need to maintain or source a feed.
- **Protect/Access app audits.** Out of scope for Phase 1; Network only.
- **Multi-site MSP workflows.** Phase 3 territory.
- **`.unifi` console-format decryption.** Phase 4 territory; community keys exist but not yet integrated.
