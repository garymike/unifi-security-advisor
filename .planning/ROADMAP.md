# Roadmap: UniFi Security Advisor

## Overview

A security posture advisor for UniFi networks, delivered as a credential-respecting local audit tool that grows from a one-shot script into a discovery-first wizard, then into a multi-deployment fallback for cloud/CGNAT users, then into a specialist offline mode for airgap and forensic use cases, then into agent-driven remediation via the upstream MCP, and finally into write-and-monitor capabilities once Ubiquiti's API write surface stabilizes. Each phase delivers a coherent, verifiable capability that builds on the credential boundary and finding model established in Phase 1.

The journey is **API-first** (`D-007` LOCKED, official X-API-KEY paths only — no MFA tradeoff), **discovery-first** (`D-002` LOCKED, detect state then ask intent), **tier-aware** (`D-001` LOCKED, three voices routed by skills check), and **read-only by default** (`C-write-001`, with writes requiring explicit per-action opt-in). Backup-file mode (the original entry point) is reframed as a Phase 4 specialist capability.

## Phases

**Phase Numbering:**
- Integer phases (1-7): Planned milestone work as committed in source intel
- Decimal phases (e.g., 2.1): Reserved for urgent insertions (none currently)

- [x] **Phase 1: Live API Audit** - Local-run audit script using Network Integration API; sanitized markdown + JSON output (COMPLETE — 8/8 plans; all acceptance bar conditions met; 202 tests pass)
- [ ] **Phase 2: Intent-Interview Wizard** - Tier-aware wizard that consumes Phase 1 JSON and asks only gap questions (intent, non-UniFi devices, process)
- [ ] **Phase 3: Site Manager API Fallback** - Cloud-routed audit path for CGNAT and multi-site MSP scenarios
- [ ] **Phase 4: Backup-File Specialist Mode** - Offline `.unf`/`.unifi` parsing for airgap, forensic, and MSP-handoff use cases
- [ ] **Phase 5: MCP Integration (Optional Add-On)** - Skills/prompts that teach Claude to remediate our findings using sirkirby/unifi-mcp tools
- [ ] **Phase 6: Apply Mode** - Preview-then-confirm config changes via official API write endpoints (awaiting API write GA)
- [ ] **Phase 7: Continuous Drift Monitoring** - Scheduled re-runs, drift alerting, mini-review when drift detected

## Phase Details

### Phase 1: Live API Audit
**Goal**: Operator runs a local script with an X-API-KEY, the script audits their UniFi deployment read-only, and produces a sanitized prioritized findings report — credentials never leave the machine.
**Depends on**: Nothing (first phase; codebase has skeleton in `src/unifi_audit.py`)
**Status**: In progress (skeleton complete; six finding modules wired; six enhanced modules implemented but not wired; validation against real network pending)
**Requirements**: REQ-phase1-live-api-audit, REQ-finding-module-segmentation, REQ-finding-module-wifi, REQ-finding-module-firewall, REQ-finding-module-remote-access, REQ-finding-module-devices, REQ-finding-module-wireless-tuning, REQ-finding-module-firewall-threats, REQ-finding-module-firmware, REQ-finding-module-logging, REQ-finding-module-backup, REQ-finding-module-api-coverage-meta, REQ-wire-enhanced-modules-into-audit-script, REQ-cross-answer-tension-detection, REQ-profile-aware-scoring-weights, REQ-always-float-to-top-overrides, REQ-validation-real-network, REQ-validation-api-response-shapes, REQ-validation-network-version-compat, REQ-validation-ssl-self-signed, REQ-validation-sanitization-coverage, REQ-test-fixtures
**Success Criteria** (what must be TRUE):
  1. Operator can run `python3 unifi_audit.py` with `UNIFI_API_KEY` and `UNIFI_HOST` env vars set, and receive a complete `report.md` + `findings.json` + `raw_sanitized.json` in `audit_output/` without the script writing or transmitting any secret.
  2. All twelve finding modules (six baseline + six enhanced) execute against a real UniFi network and produce findings; modules that fail individually log a warning and the audit continues.
  3. Always-float-to-top overrides surface the six critical findings (no MFA, mgmt plane WAN-reachable, flat network with mixed device classes, default credentials, firmware >2 majors behind with advisories, PPTP/deprecated VPN) at the top of the report — with explicit "API cannot detect this; flagged for Phase 2 wizard" notes for the three not derivable from the API alone.
  4. Cross-answer tension correlation pass runs after individual modules and emits compound findings distinct from per-module findings.
  5. Profile-aware scoring weights produce different severity rankings for the same evidence depending on the `UNIFI_PROFILE` env var (`home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`).
  6. Sanitization regression-tested against real API responses confirms no PSK, RADIUS shared secret, admin password hash, API token, or session cookie appears in any output file.
**Plans**: 8 plans
- [x] 01-01-PLAN.md � Extract sanitizer.py + pytest scaffold + fixture safety gate
- [x] 01-02-PLAN.md � API-to-collections adapter + wire 6 enhanced modules into analyze()
- [x] 01-03-PLAN.md � Cross-answer correlation pass + 3 compound rules (D-04)
- [x] 01-04-PLAN.md � Always-float-to-top override + 3 unknown findings (D-02, D-03, D-10)
- [x] 01-05-PLAN.md � Profile-aware scoring weights table (D-05, D-06)
- [x] 01-06-PLAN.md � Pipeline smoke suite + credential-leak static guard (T-1-02)
- [x] 01-07-PLAN.md � Real-network manual validation (REQ-validation-real-network) [checkpoint]
- [x] 01-08-PLAN.md � Anonymize + commit canonical fixture (T-1-03)

### Phase 2: Intent-Interview Wizard
**Goal**: Operator who has run a Phase 1 audit can answer a focused set of gap questions (intent, non-UniFi devices, process, compliance) in their preferred technical voice, and receive a unified report that merges API-detected facts with user-stated intent.
**Depends on**: Phase 1
**Status**: Not started
**Requirements**: REQ-phase2-intent-interview-wizard
**Success Criteria** (what must be TRUE):
  1. Wizard consumes a Phase 1 `findings.json` and presents only the gap questions (Section 0 profile + items where `source = User-only` or `API+enrich`) — never re-asking what the API answered.
  2. Operator completes a skills-check question at session start and is routed to one of three voices (Guided / Standard / Pro); the same finding renders in different language depending on tier; operator can switch tiers any time mid-session.
  3. Every multi-select offers "+ Other (specify)" and every question offers an optional "anything to add or clarify?" free-text field; free-text answers are persisted and influence scoring/recommendations.
  4. "Not sure" answers route to one of three resolution paths (guided helper showing where to click, opt-in auto-check via read-only API call, or defer-and-mark) — never a dead end.
  5. Final report merges API-detected facts and user-stated intent into a single prioritized backlog ranked by `(impact × user_priority_weight) / effort_hours`, with the always-float-to-top findings (including the three previously API-blind ones, now answerable from the wizard) surfaced at the top.
  6. Always-float-to-top overrides for MFA, default credentials, and management-plane WAN-reachability now resolve to actual findings (or confirmed-OK status), since the wizard fills the API gap.
**Plans**: TBD
**UI hint**: yes

### Phase 3: Site Manager API Fallback
**Goal**: Operator behind CGNAT, on a dynamic IP, or auditing multiple sites under one Ubiquiti SSO can run the audit cloud-routed via Site Manager API and receive findings comparable to the local-mode audit, with explicit notes on which findings are unavailable in cloud mode.
**Depends on**: Phase 1
**Status**: Scaffolded (cloud mode toggle exists via `UNIFI_USE_CLOUD=true`; not validated end-to-end)
**Requirements**: REQ-phase3-site-manager-fallback, REQ-validation-cloud-mode
**Success Criteria** (what must be TRUE):
  1. Operator can set `UNIFI_USE_CLOUD=true` plus a Site Manager X-API-KEY and run the audit with no other configuration changes; the script authenticates against `api.ui.com/v1/` and probes Site Manager endpoints.
  2. With a unified API key + Cloud Connector (April 2026 release), Site Manager mode proxies into Network Integration endpoints and produces full-depth findings comparable to local mode.
  3. The report explicitly lists which findings are unavailable in cloud-only mode (firewall rule depth, port-forward details, per-client details, VLAN config) versus available with Cloud Connector proxying.
  4. Multi-site listings enumerate all sites accessible to the key without leaking site IDs across reports; per-site reports are written separately.
  5. Cloud mode validation passes against a real Ubiquiti account with at least one console reachable via Cloud Connector.
**Plans**: TBD

### Phase 4: Backup-File Specialist Mode
**Goal**: Operator with a `.unf` or `.unifi` backup (airgap environment, forensic context, MSP handoff, historical review) can audit it offline with no network access and receive the same Finding output shape as a live audit.
**Depends on**: Phase 1 (shares the Finding model and sanitization patterns)
**Status**: Skeleton (`src/parser.py` + `src/inspect_backup.py` exist; three stub functions return `[]`; `.unifi` console-format decryption not yet integrated; no real backup file tested)
**Requirements**: REQ-phase4-backup-file-mode
**Success Criteria** (what must be TRUE):
  1. Operator can run `usa analyze backup.unf --out report.md` against a real `.unf` file with no network interface active and receive a complete `report.md`, `gap_questions.md`, and `state.json`.
  2. Decryption uses the public reverse-engineered AES-128-CBC key/IV; corrupted or new-format backups produce diagnostic output (first 256 bytes, format hint) rather than a generic ValueError.
  3. All finding modules from Phase 1 produce findings against parsed BSON collections; the three currently-stub functions (`find_logging`, `find_backup_config`, `find_firmware`) emit real findings via shared logic with `findings_enhanced.py`.
  4. Sanitization is unified — both `unifi_audit.py` and `parser.py` consume the same `SECRET_FIELD_NAMES` registry from a shared module; no DRY violation.
  5. `.unifi` console-format decryption (multi-site, includes PostgreSQL for UCore) is supported via community keys.
  6. Explicit `usa dump backup.unf --unsafe-include-secrets` flag exists for raw-output escape hatch with prominent warning and protected-destination requirement.
**Plans**: TBD

### Phase 5: MCP Integration (Optional Add-On)
**Goal**: When an operator wants agent-driven remediation (not just analysis), Claude — equipped with skills authored by us and the existing sirkirby/unifi-mcp tool surface — can read a finding from our report and execute the remediation tool calls with the operator's preview-then-confirm.
**Depends on**: Phase 1 (need stable Finding IDs to map from); Phase 4 helpful but not required
**Status**: Not started
**Requirements**: REQ-phase5-mcp-integration
**Success Criteria** (what must be TRUE):
  1. A documented mapping exists from each Phase 1 Finding ID to one or more sirkirby/unifi-mcp tool calls describing the remediation (tool name, expected effect, required write-mode flags).
  2. Claude, given a sanitized findings.json plus our skill files, can describe the exact tool calls needed to remediate any finding without ever requesting credentials in chat — credentials remain configured in the operator's local MCP install.
  3. The integration documentation explicitly discloses the auth tradeoff: sirkirby's full feature surface (writes) requires the same MFA-less local admin path we avoid for the primary advisor; recommend a dedicated local MCP admin account separate from daily-use cloud admin.
  4. We do not build, ship, or maintain an MCP server — `D-006` LOCKED. The deliverable is skills + mapping docs, not code that talks the MCP protocol.
**Plans**: TBD

### Phase 6: Apply Mode
**Goal**: Operator who has reviewed findings can opt in per-action to a generated config diff and apply it via the official UniFi API write endpoints with preview-then-confirm — no bulk apply, no implicit writes, explicit `--apply` flag required.
**Depends on**: Phase 1 (findings model); Ubiquiti API write GA (external blocker)
**Status**: Not started, awaiting API write GA
**Requirements**: REQ-phase6-apply-mode
**Success Criteria** (what must be TRUE):
  1. Operator can run `unifi_audit.py --apply --finding-id <ID>` and receive a preview of the config diff and the exact API call that will be made; nothing is sent to the controller until they confirm.
  2. Each apply action is opt-in per finding ID; there is no `--apply-all` or bulk-apply flag.
  3. Apply mode uses only official UniFi API write endpoints (no cookie-session writes, no reverse-engineered endpoints).
  4. Failed applies leave the controller in its prior state and surface a clear error; the audit log records the attempt with timestamp, finding ID, and HTTP response code (never the credential).
  5. The default execution path remains read-only; `--apply` is an explicit positive opt-in (`C-write-001`).
**Plans**: TBD

### Phase 7: Continuous Drift Monitoring
**Goal**: Operator can save a Phase 1 audit as an approved baseline, schedule re-runs, and receive alerts when configuration drifts from baseline — with a mini-review session to confirm whether each drift was intentional.
**Depends on**: Phase 1 (audit output); Phase 2 helpful (intent capture); persistence model decision (open question)
**Status**: Not started
**Requirements**: REQ-phase7-continuous-drift-monitoring
**Success Criteria** (what must be TRUE):
  1. Operator can mark a Phase 1 audit run as "approved baseline" and the tool persists the sanitized snapshot in a user-controlled location (no cloud).
  2. Scheduled re-runs (cron / Task Scheduler / launchd integration via documented invocation) produce a diff against baseline and emit alerts only when drift exceeds a configurable threshold.
  3. Each drift alert routes to a mini-review where the operator marks it intentional (update baseline) or unintentional (open as new finding).
  4. Drift history is queryable: operator can answer "when did SSH-on-AP-X get enabled?" from local history without re-running an audit.
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7. Phases 3 and 4 may proceed in parallel after Phase 1 completes since both depend only on Phase 1 and are independent of each other. Phase 5 can proceed in parallel with 3-4 since it only depends on stable Finding IDs from Phase 1.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Live API Audit | 8/8 | Complete | 2026-04-26 |
| 2. Intent-Interview Wizard | 0/TBD | Not started | - |
| 3. Site Manager API Fallback | 0/TBD | Not started (scaffolded) | - |
| 4. Backup-File Specialist Mode | 0/TBD | Not started (skeleton) | - |
| 5. MCP Integration (Optional) | 0/TBD | Not started | - |
| 6. Apply Mode | 0/TBD | Not started (blocked on API write GA) | - |
| 7. Continuous Drift Monitoring | 0/TBD | Not started | - |

---

*Last updated: 2026-04-25 after ingest synthesis (mode: new-project-from-ingest).*
*All seven phases mirror `.planning/intel/requirements.md`. All 19 source REQs (plus 11 sub-module IDs and 7 validation IDs surfaced for execution clarity) map to exactly one phase.*
