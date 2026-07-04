# Cross-Answer Tension Detection Design

**Date:** 2026-07-03
**Status:** Implemented
**Scope:** A correlation pass that emits compound findings from combinations of per-site findings (whose statuses reflect user intent answers). Implements DECISIONS.md D-003.

---

## Problem

Individual finding modules each look at one aspect of the config. Real risk often lives in the *combination* — "a flat network" and "an exposed port" are each medium concerns, but together they're a pivot path. Single-question logic can't see that.

## Approach

`src/audit/tensions.ts` runs after the per-site modules, inside `analyze()`'s site loop:

```
for each site:
  siteFindings = run all modules
  siteFindings += detectTensions(siteFindings, site.siteId)
```

- **`detectTensions(findings, siteId)`** runs each `TensionRule` over that site's findings via a small `SiteFindingIndex` (match by id substring + optional status) and emits a compound `Finding` per rule that fires: `id = TENSION-<rule>-<siteId>`, `section = "Compound risks"`, `evidence.contributors = [contributing ids]`, with copy explaining why the stack is worse than its parts.
- **Site-scoped:** rules only see one site's findings, so multi-site audits don't cross-contaminate.
- **Answer-aware for free:** rules key off each finding's `status`. The wizard's `mergeAnswer` rewrites status from the user's intent answers (`yes`/`not_applicable` → `ok`, `deferred` → `unknown`). So a compound fires from config alone, and an answer that clears a contributor (status → `ok`) suppresses it — genuine cross-*answer* behavior. Config-only tensions work in the CLI; the desktop refines them as the user answers (re-running `detectTensions` on the answered set post-wizard is a small follow-up).

## Initial rules (6)

| id | fires when (all statuses `gap` unless noted) | severity |
|---|---|---|
| `WAN-RCE` | `SEG-MGMT-WAN` + `ADV-*` | critical |
| `FLAT-REMOTE` | `SEG-001` + `VPN-MISSING-001` | high |
| `BACKUP-RESILIENCE` | `BAK-002` + `BAK-003` (gap/unknown) | high |
| `DEPRECATED-VPN-FLAT` | `VPN-PPTP-001` (not-ok) + `SEG-001` | high |
| `EOL-VULNERABLE` | `FW-EOL*` + `ADV-*` | high |
| `WEAK-WIFI-FLAT` | `*-PSK` + `SEG-001` | high |

`WAN-RCE` deliberately requires *confirmed* exposure (`SEG-MGMT-WAN` status `gap`, not `unknown`) so an unconfirmed-exposure heuristic doesn't raise a critical false alarm — the underlying advisory finding already floats to top on its own.

Adding a rule is one entry in `TENSION_RULES`.

## Testing

`tensions.test.ts`: each rule fires on its combination; `WAN-RCE` does not fire on unknown exposure; an answered-away contributor (`ok`) suppresses the compound; site-scoping; no-op on empty/no-match; rule-list integrity. Full suite + `tsc` clean.

## Post-wizard re-run (implemented 2026-07-03)

`src/wizard/reportAssembly.ts`'s `applyAnswersAndTensions(findings, answers, siteIds)` rebuilds the report set after the wizard: it applies each stored intent answer (via `mergeAnswer`), drops the config-time `TENSION-*` findings, and recomputes tensions on the answered set (per site). The report page calls it, so compounds reflect the user's answers — an answer that clears a contributor dissolves the compound. This also fixed a pre-existing gap where the report ignored wizard answers entirely (`getFindings` returns raw rows; answers live in a separate table).

## Out of scope

- Cross-*site* compounds (each rule is single-site by design).
