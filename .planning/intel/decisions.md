# Decisions Intel

Synthesized from ADR sources. Each decision preserved separately with provenance.

Precedence order applied: ADR > SPEC > PRD > DOC. All three ADRs in this set are LOCKED (precedence 0-1).

---

## D-001: Three tiers (Guided / Standard / Pro) routed by skills check, not self-assessment

- source: DECISIONS.md (D-001)
- status: locked (Active)
- scope: tier system, user routing, content authoring
- decision: Every user-facing question or finding has three voices (Guided, Standard, Pro). Routing is determined by a skills-check question (e.g., "do you know what a VLAN is?"), not by self-assessment. The user can switch tiers at any time.
- rationale: Walkthrough showed self-assessment is unreliable; a self-described "tinkerer" still asked novice clarifying questions.
- consequences: Every question authored three times; skills check adds 30-60 s at session start.
- reinforced by: docs/01-design-philosophy.md (DOC), CLAUDE.md (SPEC) "Tier system" section.

## D-002: Discovery-first questionnaire pattern

- source: DECISIONS.md (D-002)
- status: locked (Active, foundational principle)
- scope: questionnaire authoring, parser/API output integration, wizard UX
- decision: Wherever possible, detect current state via API or backup and ask the user to confirm intent rather than recall config. Pattern: "Found: X / Recommend: Y / Confirm intent: Z."
- rationale: Standard questionnaires force recall and yield "not sure"; discovery-first cuts user-facing questions ~40-50% for novice profiles and shifts remaining questions toward intent.
- reinforced by: docs/01-design-philosophy.md, QUESTIONNAIRE.md (SPEC) source-routing column, docs/04-backup-file-strategy.md (DOC).

## D-003: Cross-answer tension detection is a real engine requirement

- source: DECISIONS.md (D-003)
- status: locked (Active; implementation deferred to Phase 1 finalization)
- scope: findings engine, compound-finding correlation pass
- decision: A rules layer detects answer combinations and emits compound findings, distinct from per-question findings.
- examples (from source): "seconds-of-downtime + single WAN + work ranked #4" (priority mismatch); "mobile remote management + MFA unknown" (keys-to-kingdom risk); "NAS reachable by everything + IoT internet unknown" (pivot path).
- consequences: Adds finding-correlation pass after individual modules run.
- reinforced by: ROADMAP.md "Cross-answer tension detection (compound findings)" listed in Phase 1 "Needs work."

## D-004: Every multi-select gets free-text "Other"; every question allows optional clarification

- source: DECISIONS.md (D-004)
- status: locked (Active)
- scope: questionnaire authoring, wizard input handling, answer-tracking pipeline
- decision: All multi-select questions include "+ Other (specify)". All questions include an optional "anything to add or clarify?" free-text field. Free-text answers feed a separate "user-stated context" tracker that influences scoring and recommendations.
- consequences: Wizard implementation must support free-text alongside structured input; slightly more analysis complexity (NLP-light) but dramatically richer signal.

## D-005: "Not sure" is a first-class answer with three resolution paths

- source: DECISIONS.md (D-005)
- status: locked (Active; embedded in QUESTIONNAIRE.md)
- scope: questionnaire authoring, wizard branching
- decision: "Not sure" answers route to one of: (1) Guided helper ("here's where to click"), (2) Auto-check (read-only API call, only with consent), (3) Deferred ("mark for later").
- consequences: Each questionnaire item with selectable answers must include a "not sure" option and a defined resolution path.
- reinforced by: QUESTIONNAIRE.md metadata schema field `unknown_resolution: guided_helper | auto_check | defer`.

## D-006: Do not build a competing MCP server; integrate with sirkirby/unifi-mcp

- source: DECISIONS.md (D-006), elaborated in docs/06-mcp-strategy.md
- status: locked (Active)
- scope: MCP integration strategy, Phase 5 deliverables
- decision: Use sirkirby/unifi-mcp when MCP integration is needed. Our value-add is skills/prompts that teach Claude how to remediate our specific findings using their tools. Do NOT build our own Network MCP server.
- rationale: sirkirby/unifi-mcp already ships 166 Network tools, beta Protect/Access, mature security defaults (read-only by default, preview-then-confirm, X-API-KEY read-only mode supported, no DB/cache/sessions stored locally).
- consequences: Phase 5 is integration work, not server-building work. Ship a documented mapping (finding ID → MCP tool calls). Accept that sirkirby's roadmap influences what's possible for us.
- caveats (from docs/06-mcp-strategy.md): The MCP's full feature surface (write operations) requires the same MFA-less local admin path we avoid for the primary advisor. MCP path must be opt-in with clear disclosure of the tradeoff. Recommend a dedicated local MCP admin account, separate from cloud admin.
- reinforced by: ROADMAP.md "Phase 5: MCP integration (optional add-on)", docs/02-api-strategy.md "Phase 5: MCP integration (optional)", CLAUDE.md "Do not build a competing MCP server."

## D-007: Network Integration API as primary path, not backup-file

- source: DECISIONS.md (D-007), elaborated in docs/02-api-strategy.md
- status: locked (Active)
- scope: API strategy, Phase 1 scope, data-source preference order
- decision: Pivot from backup-first to API-first. Network Integration API (local X-API-KEY) is the primary path. Site Manager API is the cloud/CGNAT fallback. Backup-file mode (`.unf`/`.unifi`) is a specialist Phase 4 add-on for airgap, forensic, and MSP-handoff use cases. Classic cookie auth is avoided (requires MFA-less local admin).
- rationale: Officially supported by Ubiquiti (post-July-2024 X-API-KEY rollout); no MFA tradeoff; revocable independently of admin credentials; key isn't valid for web/mobile UI login (scoped to API use); compliance-friendly.
- consequences: Phase 1 scope changed from backup parsing to API integration. Existing backup-parser work (`src/parser.py`) reframed as Phase 4 deliverable. Most finding logic is portable between modes (consume sanitized dict either way).
- decision tree (from docs/02): "Can the machine running the tool reach the UniFi console directly on the LAN? Yes → Network Application API Key. No → Site Manager API Key (cloud-routed)."
- reinforced by: ROADMAP.md (Phase 1 = Live API audit, Phase 3 = Site Manager fallback, Phase 4 = backup-file specialist), CLAUDE.md "Data sources (in order of preference)" list, docs/01-design-philosophy.md "Officially-supported paths first" hierarchy, docs/03-site-manager-vs-network-integration.md.

## D-008: Local-run audit script as Phase 1 deliverable

- source: DECISIONS.md (D-008)
- status: locked (Active; locked-in as a structural property in docs/05-credential-handling.md)
- scope: Phase 1 deliverable shape, credential boundary
- decision: Phase 1 deliverable is a local-run script (`src/unifi_audit.py`). Credentials never transit chat; the user runs the audit themselves and shares the sanitized output if/when they choose.
- rationale: Pasting an API key into chat is not equivalent to running locally; clean separation keeps credentials on the user's machine and sanitized data as the only thing discussed.
- consequences: Slightly more friction for the user (env vars + run a script); sets the precedent for Phase 2 wizard.
- reinforced by: docs/05-credential-handling.md (SPEC), CLAUDE.md absolute constraints #1-3.

## D-009: Project structure flattened with numbered docs

- source: DECISIONS.md (D-009)
- status: locked (Active)
- scope: repository layout, doc organization
- decision: Three subdirectories (`docs/`, `src/`, `samples/`) plus top-level files (`README.md`, `CLAUDE.md`, `ROADMAP.md`, `DECISIONS.md`, `QUESTIONNAIRE.md`, `AUDIT_QUICKSTART.md`). Design docs use numbered prefixes (`01-…`, `02-…`) to suggest reading order.
- consequences: Easier navigation; numbering implies an order; old `backup_parser/` directory retained as historical context but new work happens in `unifi-security-advisor/`.

---

## Decisions explicitly NOT made (open)

From DECISIONS.md "Decisions explicitly NOT made yet" section. Surfaced for downstream roadmapper as known open items.

- Wizard frontend technology (web vs TUI vs both) — awaiting Phase 2 scoping.
- Persistence model for user answers, baseline configs, historical findings — local SQLite leading but not decided.
- MSP / multi-tenant model — defer to Phase 3.
- Telemetry / opt-in metrics — none for Phase 1; later opt-in undecided.
- Distribution (PyPI / single-file / Docker / all) — Phase 1 single-file; later TBD.
- License (MIT / Apache 2.0 / AGPL) — undecided.

---

## Locked decisions count: 9 (D-001 through D-009, all Status: Active)

All nine decisions in DECISIONS.md carry Status: Active and are treated as Accepted/locked per manifest classification (`locked: true`). docs/02-api-strategy.md and docs/06-mcp-strategy.md elaborate D-007 and D-006 respectively and are also classified locked; their decisions reinforce (do not contradict) the master log.
