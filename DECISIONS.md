# Design Decisions Log

Material decisions made during design, with rationale. Newest at top.

Format per entry:
- **Decision**
- **Date** (or "design-phase" if pre-implementation)
- **Context**
- **Decision rationale**
- **Consequences / tradeoffs**
- **Status**

---

## D-009: Project structure flattened with numbered docs

**Date:** Apr 25, 2026

**Context:** The original `backup_parser/` directory had 15+ files at one level mixing source, design docs, samples, and quickstart. Migrating to Claude Code in VSCode needed cleaner organization.

**Decision:** Three subdirectories (`docs/`, `src/`, `samples/`) plus four top-level files (`README.md`, `CLAUDE.md`, `ROADMAP.md`, `DECISIONS.md`, `QUESTIONNAIRE.md`, `AUDIT_QUICKSTART.md`). Design docs use numbered prefixes (`01-...`, `02-...`) to suggest reading order.

**Consequences:**
- Easier to navigate, easier to add/remove docs without breaking links
- Numbering implies an order; existing docs were assigned numbers based on conceptual flow, not creation order
- Old `backup_parser/` directory retained as historical context but new work happens in `unifi-security-advisor/`

**Status:** Active.

---

## D-008: Local-run audit script as Phase 1 deliverable

**Date:** Apr 24, 2026

**Context:** During design walkthrough, the user offered to paste an API key into chat. I initially framed "paste it here" and "run locally" as equivalent options. They aren't equivalent.

**Decision:** Phase 1 deliverable is a local-run script (`src/unifi_audit.py`). Credentials never transit chat; the user runs the audit themselves and shares the sanitized output if/when they choose.

**Consequences:**
- Clean separation: credentials stay with the user, sanitized data is what we discuss
- Slightly more friction for the user (have to set up env vars and run a script)
- Sets the right precedent for Phase 2 wizard: credentials never leave the user's machine

**Status:** Active. Locked in as a structural property in `docs/05-credential-handling.md`.

---

## D-007: Network Integration API as primary path, not backup-file

**Date:** Apr 24, 2026

**Context:** Original Phase 1 plan was backup-file mode first. Research surfaced that Ubiquiti's official API (X-API-KEY, post-July-2024) doesn't have the MFA-tradeoff problem we'd been worried about.

**Decision:** Pivot. Network Integration API (local X-API-KEY) is the primary path. Site Manager API is the cloud/CGNAT fallback. Backup-file mode is a specialist Phase 4 add-on for airgap, forensic, and MSP-handoff use cases.

**Rationale:**
- Officially supported, no MFA tradeoff
- Compliance-friendly (no community-tool dependency for primary path)
- Backup-file mode still has real use cases, but isn't the right default

**Consequences:**
- Phase 1 scope changed: API integration, not backup parsing
- Existing backup-parser work (`src/parser.py`) reframed as Phase 4 deliverable
- Most finding logic is portable between modes (consume sanitized dict either way)

**Status:** Active.

---

## D-006: Do not build a competing MCP server; integrate with sirkirby/unifi-mcp

**Date:** Apr 24, 2026

**Context:** Considered building our own MCP server. `sirkirby/unifi-mcp` already exists with 166 Network tools, beta Protect/Access, mature security defaults (read-only, preview-then-confirm).

**Decision:** Use sirkirby's MCP when MCP integration is needed (Phase 5). Our value-add is **skills/prompts** that teach Claude how to remediate our specific findings using their tools.

**Rationale:**
- Don't duplicate mature OSS work
- Their auth model (X-API-KEY support, not just cookie) lines up with our preferences
- Skills layered on top is a more honest contribution model

**Consequences:**
- Phase 5 is integration work, not MCP-server-building work
- We ship a documented mapping: finding ID → MCP tool calls to remediate
- We accept that sirkirby's roadmap influences what's possible for us

**Status:** Active.

---

## D-005: "Not sure" is a first-class answer with three resolution paths

**Date:** Apr 24, 2026

**Context:** Walkthrough testing showed 28% of answers were "not sure." Treating this as just "missing data" wastes the user's correct intuition.

**Decision:** "Not sure" answers route to one of:
1. Guided helper ("here's exactly where to click to find out")
2. Auto-check (read-only API call, only with consent)
3. Deferred ("mark for later, we'll come back")

**Consequences:**
- Each questionnaire item with selectable answers must include a "not sure" option and a defined resolution path
- Adds UX complexity but matches how real users actually answer

**Status:** Active. Embedded in questionnaire design (`QUESTIONNAIRE.md`).

---

## D-004: Every multi-select needs free-text "Other" + every question allows optional clarification

**Date:** Apr 24, 2026

**Context:** Walkthrough yielded major signal from write-ins (Firewalla, multiple NAS, Home Assistant plans, segmentation history). Closed lists missed all of it.

**Decision:** All multi-select questions include "+ Other (specify)". All questions include an optional "anything to add or clarify?" free-text field.

**Consequences:**
- Wizard implementation must support free-text alongside structured input
- Free-text answers feed into a separate "user-stated context" tracker that influences scoring and recommendations
- Slightly more analysis complexity (NLP-light) but dramatically richer signal

**Status:** Active.

---

## D-003: Cross-answer tension detection is a real engine requirement

**Date:** Apr 24, 2026

**Context:** Walkthrough surfaced compound findings invisible to single-question logic:
- "Seconds of downtime blocks work" + single WAN + work ranked #4 = priority mismatch
- Mobile app remote management + MFA unknown = keys-to-kingdom risk
- NAS reachable by everything + IoT internet unknown = pivot path

**Decision:** Build a rules layer that detects answer combinations and emits compound findings, distinct from per-question findings.

**Consequences:**
- Adds a finding-correlation pass after individual modules run
- Compound findings explain WHY a stack of small issues is more dangerous than the sum of parts
- Maps to biomimetic principle (mycelial redundancy: weak signals combining into confident detection)

**Status:** Active. Implementation deferred to Phase 1 finalization.

---

## D-002: Discovery-first questionnaire pattern

**Date:** Apr 24, 2026

**Context:** Standard questionnaires force users to recall config from memory. Walkthrough yielded multiple "not sure" answers because the user genuinely didn't know the current state.

**Decision:** Wherever possible, detect current state via API/backup and ask the user to confirm intent rather than recall config. Pattern:

> *Found:* [current state]
> *Recommend:* [tailored recommendation]
> *Confirm intent:* [is this what you wanted?]

**Consequences:**
- ~40-50% reduction in user-facing questions for novice profiles
- Higher-quality remaining questions (intent, not recall)
- Requires data-source-mapping work (which questions are answerable from API vs backup vs user only)

**Status:** Active. Foundational principle.

---

## D-001: Three tiers (Guided/Standard/Pro) routed by skills check, not self-assessment

**Date:** Apr 24, 2026

**Context:** Walkthrough user self-described as "tinkerer" but later asked basic clarifying questions. Self-assessment is unreliable.

**Decision:** Every user-facing question/finding has three voices. Routing is by a skills-check question (e.g., "do you know what a VLAN is?"), not pure self-assessment. User can switch tiers any time.

**Consequences:**
- Every question authored three times (more content work)
- Better experience for both ends of the audience spectrum
- Skills check adds 30-60 seconds at session start; worth it for routing accuracy

**Status:** Active. Foundational principle.

---

## Decisions explicitly NOT made yet

These are hot-potato items waiting for more information or a different session.

- **Wizard frontend technology.** Web app (React/Vue), TUI (Textual), or both? Awaiting Phase 2 scoping.
- **Persistence model.** Where do user answers, baseline configs, and historical findings live? Local SQLite is leading candidate but not decided.
- **MSP/multi-tenant model.** How does an MSP managing 50 sites use this? Defer to Phase 3.
- **Telemetry / opt-in metrics.** None for Phase 1 (zero telemetry). Whether to add anonymous opt-in metrics later is undecided.
- **Distribution.** PyPI package, single-file script, Docker image, all three? Phase 1 is single-file; later phases TBD.
- **License.** Not chosen yet. MIT, Apache 2.0, AGPL each have arguments.
