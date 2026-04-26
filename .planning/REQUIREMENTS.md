# Requirements: UniFi Security Advisor

**Defined:** 2026-04-25
**Source:** `.planning/intel/requirements.md` (synthesized from ROADMAP.md + DECISIONS.md + CLAUDE.md)
**Core Value:** Tell a UniFi operator whether their configuration is good — not just whether it works — without ever taking custody of their credentials.

## v1 Requirements

19 requirements normalized to `REQ-{slug}` IDs as extracted from intel. Each maps to exactly one of seven roadmap phases.

### Phase deliverables (7)

These are the seven roadmap phases as commitments. Each phase has internal sub-requirements where applicable.

- [~] **REQ-phase1-live-api-audit** — Audit a UniFi deployment using the Network Integration API (X-API-KEY), read-only. Produce sanitized markdown report and structured JSON. Wires all enhanced finding modules; implements always-float-to-top override logic; implements profile-aware scoring weights; implements cross-answer tension detection.
  - Status: **in progress** (skeleton complete in `src/unifi_audit.py`; needs validation against a real network and four needs-work items)
  - Deliverable: `src/unifi_audit.py`
- [ ] **REQ-phase2-intent-interview-wizard** — Web/CLI wizard that consumes Phase 1 JSON and asks only the gap questions (intent, non-UniFi devices, process). Three-tier voicing with skills-check routing; free-text "Other" + optional clarification on every question; "not sure" routes to guided helper / auto-check / defer.
  - Status: **not started**
- [ ] **REQ-phase3-site-manager-fallback** — Site Manager API fallback for users behind CGNAT or with multi-site MSP needs. Same audit logic, different transport.
  - Status: **scaffolded** (cloud mode toggle exists via `UNIFI_USE_CLOUD=true`; not validated)
- [ ] **REQ-phase4-backup-file-mode** — Specialist mode for `.unf` and `.unifi` parsing (airgap / forensic / MSP-handoff). Same finding modules consume parsed data instead of API responses. AES-128-CBC decrypt, ZIP extraction, gunzipped BSON parsing, sanitization, runs entirely offline.
  - Status: **skeleton** (`src/parser.py` exists; three stub functions return `[]`; `.unifi` decryption not yet integrated)
- [ ] **REQ-phase5-mcp-integration** — Skills/prompts that teach Claude how to use sirkirby/unifi-mcp tools to remediate our findings. **Do NOT build our own MCP server** (`D-006` LOCKED).
  - Status: **not started**
- [ ] **REQ-phase6-apply-mode** — Generate UniFi config changes that can be reviewed as a diff and applied via the API. Preview-then-confirm per change. Explicit `--apply` flag required; per-action opt-in.
  - Status: **not started, awaiting API write GA**
- [ ] **REQ-phase7-continuous-drift-monitoring** — Scheduled re-runs, alert on drift from approved baseline, mini-review when drift detected.
  - Status: **not started**

### Phase 1 finding modules (11)

Sub-requirements of REQ-phase1-live-api-audit. All implemented at module level; some not yet wired into the live audit script's `analyze()` (see Phase 1 needs-work items below).

- [x] **REQ-finding-module-segmentation** — Flat-network detection across `networkconf` / API networks list. (Wired)
- [x] **REQ-finding-module-wifi** — Security mode and PSK strength findings. (Wired)
- [x] **REQ-finding-module-firewall** — Port forwards basic finding logic. (Wired, basic)
- [x] **REQ-finding-module-remote-access** — VPN protocol tiering (PPTP critical, L2TP discouraged, WireGuard preferred), port-forwards-without-VPN finding. (Wired)
- [x] **REQ-finding-module-devices** — SSH enablement per device. (Wired)
- [x] **REQ-finding-module-wireless-tuning** — TX power, 2.4 GHz audit, rogue AP detection, fast roaming on multi-AP, PMF on WPA3. (Wired via adapter in Plan 01-02)
- [x] **REQ-finding-module-firewall-threats** — Geo-IP both directions (WAN_IN / WAN_OUT), content filtering (DNS-based, Security minimum), safe-search (conditional on children-in-household). (Wired via adapter in Plan 01-02)
- [x] **REQ-finding-module-firmware** — Auto-update toggle, EOL hardware cross-reference, stale versions across 4 update domains (per-device firmware, UniFi OS, Network app, other apps). (Wired via adapter in Plan 01-02; CVE database deferred)
- [x] **REQ-finding-module-logging** — Privacy-aware retention recommendations by profile (home: 7-14d traffic / 30d admin; regulated_hipaa: 6 years both; etc.). (Wired via adapter in Plan 01-02)
- [x] **REQ-finding-module-backup** — Destination diversity finding (off-device backup required); tested-restore Schrödinger finding (always fires unless user confirms tested restore in last 12 months). (Wired via adapter in Plan 01-02)
- [x] **REQ-finding-module-api-coverage-meta** — Meta-finding tracking which questionnaire items are answered by API vs require user input. (Wired)

### Phase 1 needs-work items (4 — open Phase 1 work)

These are the four gating items between current Phase 1 state and Phase 1 completion.

- [x] **REQ-wire-enhanced-modules-into-audit-script** — Wire the six enhanced finding modules (`findings_enhanced.py`) into `unifi_audit.py`'s `analyze()` modules list. RESOLVED in Plan 01-02 via api_to_collections.py adapter.
- [ ] **REQ-cross-answer-tension-detection** — Implement the compound-finding correlation pass after individual modules run (`D-003` LOCKED). Examples: priority mismatch (downtime-sensitivity + single WAN), keys-to-kingdom (mobile remote management + MFA unknown), pivot path (NAS reachable + IoT internet unknown).
- [x] **REQ-profile-aware-scoring-weights
** — Profile-aware scoring weights so home profiles don't get enterprise retention recommendations and regulated profiles don't get under-tuned. Weight table per `(profile × finding-section)`.
- [x] **REQ-always-float-to-top-overrides
** — Override logic that surfaces the six always-float-to-top findings to the top regardless of overall scoring (no MFA, mgmt plane WAN-reachable, flat network with mixed device classes, default credentials, firmware >2 majors behind with advisories, PPTP/deprecated VPN). Note: three of the six (MFA, default creds, WAN reachability) are not detectable from Network Integration API alone — these become Phase 2 questionnaire gap-questions and must be flagged accordingly.

### Validation requirements (7 — open Phase 1 work)

Required to declare Phase 1 complete.

- [ ] **REQ-validation-real-network** — Run `unifi_audit.py` against a real UniFi network and confirm endpoints respond as expected.
- [x] **REQ-validation-api-response-shapes** — Diff actual API response shapes against assumed shapes in `_extract_list` / `_extract_sites` helpers. RESOLVED in Plan 01-02: _extract_list + _unwrap() both log WARNING with observed keys on unknown shapes (T-1-04); asserted by tests.
- [ ] **REQ-validation-network-version-compat** — Test with Network ≥ 9.3.43 (required for Integration API) and an older version to confirm graceful 404 handling.
- [ ] **REQ-validation-cloud-mode** — Test cloud mode (`UNIFI_USE_CLOUD=true`) once a unified API key with Cloud Connector is available (April 2026 unified key).
- [ ] **REQ-validation-ssl-self-signed** — Test SSL self-signed default for local mode.
- [x] **REQ-validation-sanitization-coverage
** — Confirm sanitization catches all secret field names in actual API responses (regression-tested against fixtures).
- [x] **REQ-test-fixtures
** — Gather Phase 1 validation fixtures: at least one real `.unf` backup file (single-site), at least one JSON dump from a live API run, and anonymized profiles across scales (`home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`).

## v2 Requirements

Currently empty. Items deferred from v1 are tracked in **Out of Scope** below; if any are promoted to v2 they will appear here with REQ-IDs.

## Out of Scope

Explicitly excluded from v1. Documented to prevent scope creep. Reasoning preserved.

| Feature | Reason |
|---------|--------|
| Apply mode (write operations) | Deferred to Phase 6 (REQ-phase6-apply-mode); awaiting Ubiquiti API write GA. Read-only by default is `C-write-001`. |
| Drift monitoring / continuous audits | Deferred to Phase 7 (REQ-phase7-continuous-drift-monitoring). |
| Multi-site MSP aggregation beyond listing | Deferred to Phase 3 (Site Manager fallback) and Phase 7. |
| Protect / Access app audits | Network only for v1. May be reachable via Phase 5 MCP integration since sirkirby/unifi-mcp covers Protect (beta) and Access. |
| Penetration testing / active probing | Wrong threat model — this is a posture advisor. |
| Runtime IDS/IPS | UniFi has its own; we audit configuration, not traffic. |
| Config-management tool (Terraform/Pulumi for UniFi) | Out of scope; conflicts with read-only-by-default and complicates the credential boundary. |
| General-purpose network scanner | UniFi-specific awareness is the whole point. |
| Build our own MCP server | `D-006` LOCKED. Use sirkirby/unifi-mcp; our value-add is skills/prompts. |
| Classic cookie-session auth as primary | `D-007` LOCKED. Requires MFA-less local admin (anti-pattern). Available only as legacy fallback with loud warning if ever used. |
| Credentials via CLI args / chat / URL params / clipboard | Absolute constraint `C-cred-002`. Env vars, mode-600 config files, OS keychain, or interactive terminal prompts only. |
| MFA on cloud admin detection from API/backup | Not exposed by either; becomes a Phase 2 questionnaire gap-question. |
| CyberSecure subscription state detection | Lives in cloud, not exposed via current local API; Phase 2 questionnaire item. |
| Real-time traffic patterns | Not in backup; live API has limited visibility; out of scope for v1 audit. |
| CVE database for known-vulnerable firmware | Deferred — need to maintain or source a feed; ship initial release with ~12 months of advisories at most. |
| `.unifi` console-format decryption | Phase 4 territory (community keys exist; not yet integrated). |

## Traceability

Every v1 requirement maps to exactly one phase. Updated during roadmap creation; status updates after phase completion.

| Requirement | Phase | Status |
|-------------|-------|--------|
| REQ-phase1-live-api-audit | Phase 1 | In Progress |
| REQ-finding-module-segmentation | Phase 1 | Complete (wired) |
| REQ-finding-module-wifi | Phase 1 | Complete (wired) |
| REQ-finding-module-firewall | Phase 1 | Complete (wired, basic) |
| REQ-finding-module-remote-access | Phase 1 | Complete (wired) |
| REQ-finding-module-devices | Phase 1 | Complete (wired) |
| REQ-finding-module-wireless-tuning | Phase 1 | In Progress (implemented, not wired) |
| REQ-finding-module-firewall-threats | Phase 1 | In Progress (implemented, not wired) |
| REQ-finding-module-firmware | Phase 1 | In Progress (implemented, not wired) |
| REQ-finding-module-logging | Phase 1 | In Progress (implemented, not wired) |
| REQ-finding-module-backup | Phase 1 | In Progress (implemented, not wired) |
| REQ-finding-module-api-coverage-meta | Phase 1 | Complete (wired) |
| REQ-wire-enhanced-modules-into-audit-script | Phase 1 | Pending |
| REQ-cross-answer-tension-detection | Phase 1 | Pending |
| REQ-profile-aware-scoring-weights | Phase 1 | Pending |
| REQ-always-float-to-top-overrides | Phase 1 | Pending |
| REQ-validation-real-network | Phase 1 | Pending |
| REQ-validation-api-response-shapes | Phase 1 | Pending |
| REQ-validation-network-version-compat | Phase 1 | Pending |
| REQ-validation-cloud-mode | Phase 1 | Pending (depends on Phase 3 cloud validation) |
| REQ-validation-ssl-self-signed | Phase 1 | Pending |
| REQ-validation-sanitization-coverage | Phase 1 | Pending |
| REQ-test-fixtures | Phase 1 | Pending |
| REQ-phase2-intent-interview-wizard | Phase 2 | Pending |
| REQ-phase3-site-manager-fallback | Phase 3 | Pending |
| REQ-phase4-backup-file-mode | Phase 4 | Pending |
| REQ-phase5-mcp-integration | Phase 5 | Pending |
| REQ-phase6-apply-mode | Phase 6 | Pending |
| REQ-phase7-continuous-drift-monitoring | Phase 7 | Pending |

**Coverage:**
- v1 requirements: 29 total (7 phase deliverables + 11 finding modules + 4 needs-work + 7 validation)
- Mapped to phases: 29
- Unmapped: 0 ✓

Note: the source intel counts 19 requirements at the phase-deliverable + needs-work + validation levels (excluding the per-module breakouts). The 11 finding modules are intel-explicit sub-requirements of REQ-phase1-live-api-audit and are tracked here for execution clarity. Either accounting yields 100% coverage.

---
*Requirements defined: 2026-04-25 from ingest synthesis (`.planning/intel/`).*
*Last updated: 2026-04-25 after roadmap creation.*
