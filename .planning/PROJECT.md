# UniFi Security Advisor

**Project code:** USA
**Created:** 2026-04-25
**Source:** ingest mode — synthesized from `.planning/intel/SYNTHESIS.md`

## What This Is

A security posture advisor for Ubiquiti UniFi networks. It connects to a UniFi deployment via the official Network Integration API (with backup-file as a specialist fallback), audits the current configuration against industry best practices, and interviews the user for intent and context that the configuration cannot reveal. Output is a prioritized findings report with current state, recommendations, and intent-confirmation questions per finding.

Audience: three tiers in one tool — Guided (novices), Standard (prosumers/tinkerers), Pro (engineers/architects). Routing is by skills check, not self-assessment.

## Core Value

**Tell a UniFi operator whether their configuration is good — not just whether it works — without ever taking custody of their credentials.**

UniFi's built-in UI tells users *how* to configure things but not *whether their configuration is good*. This tool closes that gap discovery-first (detect state, then ask intent) while keeping credentials and raw config on the user's machine.

If everything else fails, this must remain true: the tool produces honest, profile-aware findings about a UniFi deployment, and credentials never leave the user's machine.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

(None yet — Phase 1 awaiting real-network validation.)

### Active

<!-- Current scope. Building toward these. -->

Full requirement list with REQ-IDs in `.planning/REQUIREMENTS.md`. Phase 1 (in progress) is the immediate scope; Phases 2-7 are committed roadmap.

- [x] Phase 1 skeleton: `src/unifi_audit.py` exists, sanitization wired, six finding modules wired
- [ ] Phase 1 needs-work: wire enhanced finding modules, cross-answer tension detection, profile-aware scoring weights, always-float-to-top overrides
- [ ] Phase 1 validation: real-network run, API response shape diff, version compat, cloud mode, SSL self-signed, sanitization coverage, test fixtures
- [ ] Phase 2: Intent-interview wizard
- [ ] Phase 3: Site Manager API fallback
- [ ] Phase 4: Backup-file specialist mode
- [ ] Phase 5: MCP integration (skills/prompts for sirkirby/unifi-mcp)
- [ ] Phase 6: Apply mode (awaiting API write GA)
- [ ] Phase 7: Continuous drift monitoring

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- **Apply mode (write operations) in Phase 1** — deferred to Phase 6; awaiting Ubiquiti API write GA. Read-only by default is an absolute constraint.
- **Drift monitoring / continuous audits in Phase 1** — deferred to Phase 7.
- **Multi-site MSP aggregation in Phase 1** — deferred to Phase 3 (Site Manager fallback).
- **Protect / Access app audits in Phase 1** — Network only for Phase 1; may revisit if MCP integration (Phase 5) covers them via sirkirby/unifi-mcp.
- **Penetration testing / active probing** — wrong threat model; this is a posture advisor, not an attack tool.
- **Runtime IDS/IPS** — UniFi has its own; we audit configuration, not traffic.
- **Config-management tool** — no Terraform/Pulumi for UniFi.
- **General-purpose network scanner** — UniFi-specific awareness is the whole point.
- **Building our own MCP server** — `D-006` LOCKED. Use `sirkirby/unifi-mcp`; our value-add is skills/prompts.
- **Classic cookie-session auth as primary** — requires MFA-less local admin; flagged anti-pattern. `D-007` LOCKED.
- **Credentials via CLI args / chat / URL params / clipboard** — absolute constraint. Env vars, mode-600 config files, OS keychain, or interactive terminal prompts only.

## Context

**Ecosystem & timing.** Ubiquiti rolled out X-API-KEY (Network Integration API) in July 2024 alongside MFA enforcement. As of April 2026, a unified API key with Cloud Connector spans both Network Integration (local) and Site Manager (cloud) surfaces. This unblocks our pivot from backup-first (which required reverse-engineered AES keys and dated assumptions) to API-first (officially supported, no MFA tradeoff, revocable).

**Prior work preserved.** Existing backup-parser code (`src/parser.py`, `src/inspect_backup.py`) reframed from Phase 1 deliverable to Phase 4 specialist scope. Decryption logic, BSON parsing, and `findings_enhanced.py` modules carry forward — most finding logic is portable between modes once it consumes a sanitized dict.

**User research / walkthrough learnings.**
- Self-described "tinkerer" still asked novice clarifying questions → routing must be by skills check, not self-assessment (`D-001`).
- Standard recall-style questionnaires force "not sure" → discovery-first cuts user-facing questions ~40-50% for novice profiles (`D-002`).
- Button/select answers miss critical nuance → every multi-select needs free-text "Other"; every question needs optional clarification (`D-004`).
- "Not sure" needs structured resolution (guided helper / auto-check / defer) — it cannot be a dead end (`D-005`).

**Coverage gap correction.** A 10-point reference video comparison surfaced one missing topic (per-AP radio tuning) and several stub modules. Section 6.5 was added to the questionnaire; finding logic for radio tuning, geo/content split, profile-aware retention, tested-restore, and firmware currency lives in `src/findings_enhanced.py` but is not yet wired into the live audit script — this is the largest open item in Phase 1.

**Codebase snapshot (2026-04-25).** Per `.planning/codebase/`:
- `src/unifi_audit.py` (689 LOC): primary Phase 1 deliverable, six finding modules wired
- `src/findings_enhanced.py` (624 LOC): six additional modules **not yet wired** — wireless tuning, firewall threats, enhanced remote access, enhanced firmware, logging, backup config
- `src/parser.py` (562 LOC): Phase 4 skeleton; three stub functions return `[]`
- `src/inspect_backup.py` (65 LOC): safe pre-parse inspector
- Zero automated tests
- DRY violation: two separate `SECRET_FIELD_NAMES` sets (audit + parser)

## Constraints

These bind every phase. Full enumeration with `C-` IDs in `.planning/intel/constraints.md`.

### Credential handling (absolute, structural — `C-cred-001` through `C-cred-009`)

- **Credentials never leave the user's machine.** No telemetry, no cloud relay, no logging of secrets. — `C-cred-001`
- **Allowed input channels only:** environment variables, mode-600 config files, OS keychain, interactive terminal prompts. **Prohibited:** CLI args, chat messages, URL parameters, clipboard managers. — `C-cred-002`
- **Memory hygiene:** in-process only for the duration of an audit run; no temp files, no log files. — `C-cred-003`
- **Transmission scope:** credentials may transit only to the UniFi controller via the official API endpoint. Certificate validation enforced for credential-bearing connections. — `C-cred-004`
- **Output sanitization is mandatory.** PSKs, shared secrets, admin password hashes → `{length, sha256[:12]}` fingerprints. Sanitization happens **before** any data crosses a trust boundary. Raw output requires explicit flag, warning, and protected destination. — `C-cred-005`
- **Chat-bridged input filter.** Detect credential-shaped strings in any chat-supplied input and reject. — `C-cred-006`
- **Revocation guidance.** Tool surfaces key identity (name, last 4, scope, expiration); never the only record. — `C-cred-007`
- **Audit trail.** Local-only log of API calls (timestamps, endpoint names, HTTP statuses; never the credential). — `C-cred-008`
- **Default key expiration:** shortest available (currently 1 day in Ubiquiti's UI as of April 2026). — `C-cred-009`

### Behavioral contracts

- **Read-only by default.** Writes require explicit per-action opt-in with preview-then-confirm. — `C-write-001`
- **Three tiers, one wizard** (Guided / Standard / Pro). Routing by skills check, not self-assessment. User can switch tiers any time. — `C-tier-001`
- **Always-float-to-top findings** (regardless of overall score):
  1. No MFA on any admin account
  2. Management plane reachable from WAN
  3. Flat network with multiple device classes (IoT + work + personal) on one VLAN
  4. Default credentials anywhere
  5. Firmware more than two majors behind with known advisories
  6. PPTP or any deprecated-crypto VPN enabled — `C-finding-002`

### Data acquisition

- **Preference order** (not toggleable): Network Integration API (local X-API-KEY) → Site Manager API (cloud X-API-KEY) → Unified API Key with Cloud Connector → Backup file → User answers → Classic cookie API (DO NOT USE as primary). — `C-data-001`
- **Official API paths preferred.** X-API-KEY only. Cookie auth carries a loud warning if ever used. — `C-api-001`
- **Backup-file mode must be offline.** No network access during parsing. — `C-backup-001`

### Schemas (see intel for full definitions)

- **Finding dataclass schema** (`id`, `section`, `severity`, `status`, `title`, `current_state`, `recommendation`, `intent_question`, `evidence`, `maps_to`, `effort`, `impact`). Ranking: `(impact × user_priority_weight) / effort_hours`. — `C-finding-001`
- **Question metadata schema** (id, section, three-tier text, answer_type, options, source, unknown_resolution, free_text_allowed, maps_to, risk_class, weight, profile_applicability, remediation per option). — `C-questionnaire-001`
- **Question source taxonomy:** API | API+confirm | API+enrich | User-only. — `C-questionnaire-002`
- **Section structure:** Section 0 (Profile) through Section 14 (Compliance), including added Section 6.5 (Wireless Tuning). — `C-questionnaire-003`
- **Control framework mappings required:** at least one of NIST CSF, CIS v8, Zero Trust tenet, UniFi feature name. — `C-questionnaire-004`
- **Profile labels:** `home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`. — `C-profile-001`

### Code conventions (`C-code-001`)

- **Tech stack:** Python 3.9+. Phases 1-4 use stdlib + `requests` + `pycryptodome` + `pymongo` only. Minimal deps; no framework lock-in (no Django, no FastAPI for core).
- **Style:** type hints everywhere; docstrings on every public function and module; `requests.Session` for connection reuse; verify SSL where certs allow.
- **Structure:** all modules importable standalone. — `D-009`

### Decision-making policy (`C-precedence-001`)

When designs conflict, resolve in this order: **Safety > Honesty > Usefulness > Simplicity > Aesthetic preferences**. If a feature requires weakening security, cut it. If a finding can't be honestly assessed, mark `unknown` rather than guess.

## Key Decisions

All 9 decisions extracted from `.planning/intel/decisions.md` are LOCKED (Status: Active). Six items are explicitly NOT decided yet and surfaced as open questions below.

### Locked decisions

<decisions status="locked">

| ID | Decision | Rationale | Status |
|----|----------|-----------|--------|
| D-001 | Three tiers (Guided/Standard/Pro) routed by skills check, not self-assessment | Walkthrough showed self-assessment is unreliable | LOCKED |
| D-002 | Discovery-first questionnaire pattern ("Found: X / Recommend: Y / Confirm intent: Z") | Cuts user-facing questions ~40-50% for novice profiles; shifts remaining questions toward intent | LOCKED |
| D-003 | Cross-answer tension detection is a real engine requirement (compound findings via correlation pass) | Individual findings miss compound risks (priority mismatch, keys-to-kingdom, pivot paths) | LOCKED |
| D-004 | Every multi-select needs free-text "Other"; every question allows optional clarification | Button/select answers miss critical nuance — confirmed in walkthrough | LOCKED |
| D-005 | "Not sure" is a first-class answer with three resolution paths (guided helper / auto-check / defer) | Cannot be a dead end; must route to actionable next step | LOCKED |
| D-006 | Use sirkirby/unifi-mcp; do not build a competing MCP server | sirkirby ships 166 Network tools, beta Protect/Access, mature security defaults; our value-add is skills/prompts that teach Claude how to remediate our findings using their tools | LOCKED |
| D-007 | Network Integration API (local X-API-KEY) as primary path, not backup-file | Officially supported post-July-2024 MFA rollout; no MFA tradeoff; revocable independent of admin creds; scoped to API use; defensible narrative | LOCKED |
| D-008 | Local-run audit script as Phase 1 deliverable | Pasting an API key into chat is not equivalent to running locally; clean credential boundary | LOCKED |
| D-009 | Project structure flattened with numbered docs (`docs/01-*` through `docs/08-*`) | Easier navigation; numbering implies reading order | LOCKED |

</decisions>

### Open questions (NOT YET DECIDED — surface during relevant phase)

<decisions status="open">

| Question | Where it surfaces | Notes |
|----------|------------------|-------|
| Wizard frontend technology (web app / TUI / both) | Phase 2 scoping | Affects packaging, distribution, and the skills-check UX entry point |
| Persistence model for user answers, baselines, historical findings | Phase 2 / Phase 7 | Local SQLite leading candidate; not decided |
| MSP / multi-tenant model | Phase 3 | Defer until Site Manager fallback is implemented |
| Telemetry / opt-in metrics | Post-Phase-1 | Zero for Phase 1; later opt-in undecided |
| Distribution (PyPI / single-file / Docker / all three) | Phase 1 ships single-file; later TBD | Affects on-ramp friction and update strategy |
| License (MIT / Apache 2.0 / AGPL) | Pre-public-release | Each has arguments; not yet chosen |

</decisions>

## Trust Boundary Diagram (mental model)

```
[User's machine]
  ├── env vars / keychain ──┐
  │                         ▼
  ├── unifi_audit.py  ──── X-API-KEY ────► UniFi controller (LAN or api.ui.com)
  │       │                                       │
  │       │  ◄── JSON responses (raw) ────────────┘
  │       ▼
  │  sanitize() ─── PSKs/secrets → length+sha256 fingerprints
  │       │
  │       ▼
  │  analyze() ──── Finding[] (sanitized evidence only)
  │       │
  │       ▼
  │  audit_output/  ── report.md, findings.json, raw_sanitized.json, audit.log
  │
  └── (user chooses to share sanitized output, e.g. with Claude)
```

Nothing crosses to the right of the controller. Nothing leaves the machine to the left of the user's deliberate share action.

---

*Last updated: 2026-04-25 after ingest synthesis (mode: new-project-from-ingest).*
