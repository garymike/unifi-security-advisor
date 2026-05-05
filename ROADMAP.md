# Roadmap and Working Checklist

## Phase plan

### Phase 1: Live API audit (complete — Python)

Audit a UniFi deployment using the Network Integration API (X-API-KEY). Read-only. Produces sanitized markdown report + structured JSON.

**Deliverable:** `src/unifi_audit.py` + `src/findings_enhanced.py` + `src/normalize.py` + `src/models.py`

**Status: complete** — 10 finding modules wired, float-to-top sorting, profile-aware severity overrides, 58 tests passing. Validation against a real UniFi controller still outstanding.

### Phase 2: Intent-interview wizard

Web/CLI wizard that consumes the Phase 1 JSON and asks only the gap questions (intent, non-UniFi devices, process). Merges API-detected facts with user-stated intent into a complete report.

**Phase 2a: TypeScript audit core (complete)**

Full TypeScript port of the Python audit core. Framework-agnostic; will be imported by the Tauri app in Phase 2b.

**Deliverable:** `src/audit/` — types, constants, sanitize, normalize, client, 11 finding modules, analyze pipeline, collectAll, report renderer, CLI entry point (`src/cli.ts`).

**Status: complete** — 55 tests passing, `tsc --noEmit` clean. Run with `npm run build && node dist/cli.js` after setting `UNIFI_API_KEY` + `UNIFI_HOST`.

**Phase 2b: Tauri desktop app + wizard (complete)**

Tauri v2 + Svelte 5 desktop app wrapping the TypeScript audit core. SQLite persistence, profile inference + confirmation, skills-check tier routing, gap question wizard, "not sure" resolution paths, final report screen.

**Deliverable:** `src-tauri/` (Rust shell), `src/db/`, `src/wizard/`, `src/lib/`, `src/routes/` (4 screens).

**Status: complete** — all screens built, 73 tests passing, Rust compiles clean. Run with `npx tauri dev`.

### Phase 3: Site Manager API + Cloud Connector (complete — TypeScript)

For users behind CGNAT or with multi-site MSP needs. Cloud Connector proxies Network Integration API requests through `api.ui.com`, giving the same audit depth as local mode without needing a direct network path.

**Deliverable:** `src/audit/collect.ts` — `buildConnectorUrl()` helper + cloud branch enumerates consoles → sites → all 9 per-site resources via Cloud Connector. Requires a Site Manager API key (from `unifi.ui.com → API Keys`) and Cloud Connector enabled on the console (`UniFi OS → System → Cloud Access`).

**Status: complete (TypeScript)** — validated against real controller in local mode; cloud connector path implemented and ready for testing with a Site Manager key. Python (`src/unifi_audit.py`) cloud mode remains scaffolded only.

### Phase 4: Backup-file mode (complete — TypeScript)

Parse `.unf` backups entirely offline to unlock all findings that the live API v1 cannot yet expose (WLANs, VPN, firewall rules, settings-based findings).

**Deliverable:** `src/audit/normalizeBackup.ts` (normalizeBackup + parseBackupNodejs), `src/routes/backup/+page.svelte` (Backup tab UI), `src-tauri/src/lib.rs` (`parse_backup` Rust command), `--backup` CLI flag. Python `src/parser.py` skeleton preserved for reference.

**Status: complete (TypeScript)** — 114 tests passing. New Backup tab in app (Analyze | Backup | Report | History). Requires Tauri restart after install. `.unifi` console-level format remains out of scope.

### Phase 5: MCP integration (optional add-on)

Skills/prompts that teach Claude how to use `sirkirby/unifi-mcp` tools to remediate our findings. We do NOT build our own MCP server.

**Deliverable:** MCP skill files mapping each finding ID to upstream MCP tool calls.

**Status: not started**

### Phase 6: Apply mode

Generate UniFi config changes that can be reviewed as a diff and applied via the API. Preview-then-confirm per change. Uses official write endpoints as they stabilize.

**Deliverable:** Apply mode in `unifi_audit.py` with explicit `--apply` flag.

**Status: not started, awaiting API write GA**

### Phase 7: Drift monitoring (complete — History tab)

Visualise security posture over time and compare any two runs to see what changed.

**Deliverable:** `src/audit/diff.ts` (diff engine), `src/routes/history/+page.svelte` (SVG line chart + diff panel), persistent tab bar (Analyze / Report / History) via `src/routes/+layout.svelte`.

**Status: complete** — 101 tests passing. Run `npx tauri dev` and open the History tab. Scheduling and alerting remain out of scope; manual re-auditing with visual comparison covers the core use case.

---

## Working checklist

### Phase 1 — Python audit core

#### Infrastructure

- [x] Project structure (README, CLAUDE.md, docs/, src/, samples/)
- [x] Single-file audit script (`src/unifi_audit.py`)
- [x] Sanitization pre-output
- [x] Audit log (no secrets)
- [x] Markdown + JSON report generation
- [x] Quickstart documentation (`AUDIT_QUICKSTART.md`)
- [x] `Finding` dataclass extracted to `src/models.py`
- [x] `NormalizedSite` + `normalize_api()` in `src/normalize.py`

#### Findings modules

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
- [x] All enhanced modules wired into `analyze()` pipeline
- [x] Always-float-to-top finding override logic
- [x] Profile-aware severity overrides (home, HIPAA, PCI)
- [ ] Cross-answer tension detection (compound findings) — **deferred to later phase**

#### Tests — Python

- [x] `tests/test_models.py` (2 tests)
- [x] `tests/test_normalize.py` (13 tests)
- [x] `tests/test_findings_enhanced.py` (31 tests)
- [x] `tests/test_analyze.py` (12 tests)
- [x] Total: **58 tests passing**

#### Validation against real network (outstanding)

- [x] Run TypeScript CLI against real UniFi controller (local + cloud modes validated Apr 2026; unifi_audit.py not yet tested)
- [ ] Diff actual API response shapes against assumed shapes
- [ ] Test with Network version >= 9.3.43 (required for integration API)
- [ ] Test with an older Network version to confirm graceful 404 handling
- [x] Test cloud mode (`UNIFI_USE_CLOUD=true`) with unified key + Cloud Connector — done Apr 2026
- [x] Confirm sanitization catches all secret field names in actual API responses — live API (devices/clients/networks) contains no secret fields; wlans/vpn_configs (404) are pre-covered in SECRET_FIELDS

---

### Phase 2a — TypeScript audit core

#### Infrastructure

- [x] `package.json` + `tsconfig.json` (ESM, NodeNext, strict)
- [x] Vitest test framework (v4.x)
- [x] `src/audit/types.ts` — Finding, NormalizedSite, FindingModule interfaces
- [x] `src/audit/constants.ts` — ALWAYS_TOP_PREDICATES, PROFILE_OVERRIDES, EOL_MODELS, SEVERITY_ORDER
- [x] `src/audit/sanitize.ts` — sanitize(), fingerprint()
- [x] `src/audit/normalize.ts` — normalizeApi(), extractList()
- [x] `src/audit/client.ts` — UniFiClient with fromEnv(), TLS self-signed support via undici
- [x] `src/audit/collect.ts` — collectAll(), extractSites()
- [x] `src/audit/analyze.ts` — analyze() pipeline, sortFindings(), applyProfileOverrides()
- [x] `src/audit/report.ts` — renderReport()
- [x] `src/cli.ts` — CLI entry point (reads env vars, runs audit, writes output files)

#### Finding modules (TypeScript)

- [x] segmentation.ts, wifi.ts, firewall.ts, remoteAccess.ts, devices.ts
- [x] wirelessTuning.ts, firewallThreats.ts, firmware.ts, logging.ts, backup.ts, apiCoverage.ts

#### Tests — TypeScript

- [x] `src/audit/__tests__/types.test.ts`
- [x] `src/audit/__tests__/sanitize.test.ts`
- [x] `src/audit/__tests__/normalize.test.ts`
- [x] `src/audit/__tests__/client.test.ts`
- [x] `src/audit/__tests__/findings/core.test.ts`
- [x] `src/audit/__tests__/findings/enhanced.test.ts`
- [x] `src/audit/__tests__/analyze.test.ts`
- [x] `src/audit/__tests__/collect.test.ts`
- [x] Total: **55 tests passing**, `tsc --noEmit` clean

#### Known issues / deferred

- [x] Fixed composite siteId in cloud mode (meta.id extraction in normalize.ts)
- [x] Cloud mode Cloud Connector enumeration implemented (Phase 3 complete); requires Site Manager key + Cloud Connector enabled

---

### Phase 2b — Tauri desktop app + wizard

- [x] Tauri v2 project scaffold + Svelte 5 + SvelteKit + @tauri-apps/plugin-sql
- [x] `src/db/schema.ts` + `src/db/queries.ts`
- [x] `src/wizard/orchestrator.ts` + `src/wizard/tiers.ts` + `src/wizard/profileInfer.ts`
- [x] `src/lib/AuditRunner.ts`
- [x] Home screen (`src/routes/+page.svelte`) — past runs, start new audit
- [x] Connection setup screen (`src/routes/audit/+page.svelte`) — API key, host, progress log
- [x] Wizard screen (`src/routes/wizard/+page.svelte`) — profile confirm → skills check → gap questions
- [x] Report screen (`src/routes/report/+page.svelte`) — severity filter, markdown export
- [x] `src/lib/components/QuestionCard.svelte` + `src/lib/components/FindingRow.svelte`
- [x] CLI `--save` flag for persisting runs to local DB
- [x] Import path bug fix (home route depth correction)
- [x] Tailwind CSS v4 installed and wired
- [x] SQL plugin permissions (allow-load, allow-execute, allow-select, allow-close)
- [x] TLS: custom Rust command (`unifi_fetch`) with `danger_accept_invalid_certs` for self-signed certs
- [x] Browser-compatible imports: undici dynamic, node:crypto → @noble/hashes
- [x] **End-to-end validated against real Cloud Gateway Fiber** — full audit → wizard → report flow working

---

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
- [x] Phase 1 design spec (`docs/superpowers/specs/2026-04-27-phase1-finalization-design.md`)
- [x] Phase 2 design spec (`docs/superpowers/specs/2026-04-27-phase2-wizard-design.md`)
- [x] Phase 1 implementation plan (`docs/superpowers/plans/2026-04-27-phase1-finalization-plan.md`)
- [x] Phase 2a implementation plan (`docs/superpowers/plans/2026-04-27-phase2a-ts-audit-core-plan.md`)
- [x] Phase 2b implementation plan (`docs/superpowers/plans/2026-04-27-phase2b-tauri-wizard-plan.md`)
- [x] Working checklist (this file)

### Open questions

- ✅ Sample data fixture added: `samples/fixture-local-api.json` — anonymized Cloud Gateway Fiber response (2 devices, 2 networks, 6 404 endpoints)
- Multi-site finding ID scoping: fix `BAK-001` → `BAK-001-${siteId}` pattern before Phase 2b wires SQLite primary keys — needs PROFILE_OVERRIDES key updates too.

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
