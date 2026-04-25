# Synthesis Summary

Single entry point for downstream consumers (gsd-roadmapper). Synthesized from 12 classified documents under `.planning/intel/classifications/` and their source files.

Mode: new (no prior PROJECT.md / REQUIREMENTS.md / ROADMAP.md to merge against).

---

## Doc counts by type

| Type | Count | Sources |
|---|---|---|
| ADR | 3 | DECISIONS.md (locked, precedence 0), docs/02-api-strategy.md (locked, precedence 1), docs/06-mcp-strategy.md (locked, precedence 1) |
| SPEC | 3 | CLAUDE.md (precedence 1), docs/05-credential-handling.md (precedence 1), QUESTIONNAIRE.md (precedence 2) |
| PRD | 1 | ROADMAP.md (precedence 3) |
| DOC | 5 | docs/01-design-philosophy.md, docs/03-site-manager-vs-network-integration.md, docs/04-backup-file-strategy.md, docs/07-coverage-analysis.md, docs/08-questionnaire-addendum.md |
| Total | 12 | |

All classifications: high confidence. No UNKNOWN-low entries.

---

## Decisions (locked)

9 decisions extracted from DECISIONS.md, all Status: Active and treated as locked. Two of the nine (D-006, D-007) have dedicated locked-ADR elaborations in docs/.

| ID | Title | Source(s) |
|---|---|---|
| D-001 | Three tiers (Guided/Standard/Pro) routed by skills check | DECISIONS.md |
| D-002 | Discovery-first questionnaire pattern | DECISIONS.md |
| D-003 | Cross-answer tension detection is a real engine requirement | DECISIONS.md |
| D-004 | Every multi-select needs free-text "Other"; every question allows clarification | DECISIONS.md |
| D-005 | "Not sure" is a first-class answer with three resolution paths | DECISIONS.md |
| D-006 | Do not build a competing MCP server; integrate sirkirby/unifi-mcp | DECISIONS.md, docs/06-mcp-strategy.md |
| D-007 | Network Integration API as primary path, not backup-file | DECISIONS.md, docs/02-api-strategy.md |
| D-008 | Local-run audit script as Phase 1 deliverable | DECISIONS.md |
| D-009 | Project structure flattened with numbered docs | DECISIONS.md |

Open / explicitly-not-made decisions surfaced for downstream: wizard frontend tech, persistence model, MSP/multi-tenant model, telemetry policy, distribution channels, license. (Six items.)

Detail: see `intel/decisions.md`.

---

## Requirements (PRD-driven)

19 requirements extracted from ROADMAP.md, normalized to `REQ-{slug}` IDs.

Phase requirements (7):
- REQ-phase1-live-api-audit (in progress)
- REQ-phase2-intent-interview-wizard (not started)
- REQ-phase3-site-manager-fallback (scaffolded)
- REQ-phase4-backup-file-mode (skeleton)
- REQ-phase5-mcp-integration (not started)
- REQ-phase6-apply-mode (not started; awaiting API write GA)
- REQ-phase7-continuous-drift-monitoring (not started)

Phase 1 sub-requirements / finding modules (11):
- REQ-finding-module-segmentation, -wifi, -firewall, -remote-access, -devices, -wireless-tuning, -firewall-threats, -firmware, -logging, -backup, -api-coverage-meta

Phase 1 needs-work items (4):
- REQ-wire-enhanced-modules-into-audit-script
- REQ-cross-answer-tension-detection
- REQ-profile-aware-scoring-weights
- REQ-always-float-to-top-overrides

Validation requirements (6):
- REQ-validation-real-network, -api-response-shapes, -network-version-compat, -cloud-mode, -ssl-self-signed, -sanitization-coverage; plus REQ-test-fixtures

Detail: see `intel/requirements.md`.

---

## Constraints (SPEC-driven)

26 constraints extracted from CLAUDE.md + docs/05-credential-handling.md + QUESTIONNAIRE.md. Type breakdown:

| Type | Count | Examples |
|---|---|---|
| nfr | 14 | C-cred-001 (creds never leave machine), C-cred-005 (output sanitization), C-precedence-001 (Safety > Honesty > Usefulness > Simplicity > Aesthetic) |
| api-contract | 4 | C-data-001 (data source preference order), C-cred-004 (credential transmission scope) |
| schema | 5 | C-finding-001 (Finding dataclass), C-questionnaire-001 (question metadata template) |
| behavioral contract | 3 | C-write-001 (read-only default), C-tier-001 (three tiers), C-finding-002 (always-float-to-top findings) |

Highlights:
- Credential handling: 9 constraints (C-cred-001 through C-cred-009) covering input channels, storage, transmission, sanitization, chat-bridge validation, revocation, audit trail, default expiration.
- Data acquisition order: locked at Network Integration API → Site Manager → Cloud Connector → backup-file → user answers → cookie auth (anti-pattern).
- Always-float-to-top findings: 6 conditions (no MFA, mgmt plane WAN-reachable, flat network with mixed device classes, default credentials, firmware >2 majors behind with advisories, PPTP/deprecated VPN).

Detail: see `intel/constraints.md`.

---

## Context (DOC-driven)

5 DOC sources synthesized into topical notes:

- Topic: Design philosophy and core thesis (docs/01-design-philosophy.md)
- Topic: Site Manager API vs Network Integration API (docs/03-site-manager-vs-network-integration.md)
- Topic: Backup file (`.unf`) format and parsing (docs/04-backup-file-strategy.md)
- Topic: 10-point coverage analysis vs original design (docs/07-coverage-analysis.md)
- Topic: Questionnaire addendum (coverage fixes) (docs/08-questionnaire-addendum.md)
- Topic: API authentication landscape (background) (docs/02-api-strategy.md, ADR but topical context preserved)
- Topic: MCP tradeoff details (background) (docs/06-mcp-strategy.md, ADR but topical context preserved)

Detail: see `intel/context.md`.

---

## Conflicts

| Bucket | Count |
|---|---|
| BLOCKERS (LOCKED-vs-LOCKED contradictions, cycle-induced, UNKNOWN-low) | 0 |
| WARNINGS (competing acceptance variants requiring user judgment) | 0 |
| INFO (auto-resolved by precedence; reinforcement notes) | 5 |

INFO entries cover:
- D-006 reinforcement across DECISIONS.md and docs/06-mcp-strategy.md
- D-007 reinforcement across DECISIONS.md, docs/02-api-strategy.md, ROADMAP.md
- ADR > DOC supersession on Phase 1 framing (docs/04 backup-file-as-Phase-1 language is stale; ADR pivot to API-first wins)
- ADR + PRD convergence on MCP at Phase 5 (docs/06's "Phase 3" framing is stale, decision content reinforces)
- CLAUDE.md ↔ docs/05- credential-handling interlock (no contradiction)

Cross-reference cycles detected (DECISIONS ↔ CLAUDE, DECISIONS ↔ docs/02-, DECISIONS ↔ ROADMAP, CLAUDE ↔ ROADMAP) are mutual reinforcing citations, not synthesis dependency cycles. Max traversal depth observed: 3.

Detail: see `.planning/INGEST-CONFLICTS.md`.

---

## File map for downstream consumers

| File | Purpose |
|---|---|
| `.planning/intel/decisions.md` | All ADR-extracted decisions with provenance, locked status, rationale, consequences. |
| `.planning/intel/requirements.md` | All PRD-extracted requirements with `REQ-` IDs, acceptance criteria, status, deliverables. |
| `.planning/intel/constraints.md` | All SPEC-extracted constraints with `C-` IDs, type (nfr/schema/api-contract/behavioral), source. |
| `.planning/intel/context.md` | DOC-source topical notes preserving rationale and background. |
| `.planning/INGEST-CONFLICTS.md` | Conflict report (BLOCKERS / WARNINGS / INFO). |
| `.planning/intel/SYNTHESIS.md` | This file — single entry point for gsd-roadmapper. |

---

## Status

READY — no blockers, no competing variants. Safe to route to gsd-roadmapper for production of PROJECT.md, REQUIREMENTS.md, ROADMAP.md.
