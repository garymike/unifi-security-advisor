# UX Overhaul: Score, Summary Screen, and Report Restructure

**Date:** 2026-05-01
**Status:** Approved
**Scope:** Three improvements to the Tauri desktop app UX — all Svelte 5 + TypeScript, existing Finding/NormalizedSite types, existing SQLite schema.

---

## Problem

The current app collects rich API data but buries it. The wizard jumps from "audit running" to "answer questions" without ever showing the user what was found. The report is a flat list with severity filters that doesn't communicate what the API confirmed vs. what couldn't be checked. There's no overall posture score.

---

## Implementation Order

**Part 1 (shipped first):** Report tab restructure + score engine
**Part 2 (shipped second):** Summary screen merged into wizard profile step

Part 1 is independently deployable. Part 2 depends on the score engine from Part 1.

---

## Part 1A: Score Engine

### New file: `src/audit/score.ts`

```typescript
export interface PostureScore {
  score: number;   // 0–100
  grade: string;   // A | B | C | D | F
  label: string;   // Strong | Good | Fair | Needs work | At risk
}

export function computeScore(findings: Finding[]): PostureScore
```

### Algorithm

Start at 100. Deduct per finding:

| Status | critical | high | medium | low | info |
|--------|----------|------|--------|-----|------|
| `gap` | −20 | −10 | −5 | −2 | 0 |
| `recommendation` | −10 | −5 | −2 | −1 | 0 |
| `unknown` | −5 | −3 | −1 | 0 | 0 |
| `ok` | 0 | 0 | 0 | 0 | 0 |

- Float-to-top findings (`floatTop: true`) double their deduction.
- Score is clamped to 0–100.

### Grade + Label Scale

| Score | Grade | Label |
|-------|-------|-------|
| 90–100 | A | Strong |
| 75–89 | B | Good |
| 60–74 | C | Fair |
| 45–59 | D | Needs work |
| < 45 | F | At risk |

### Tests: `src/audit/__tests__/score.test.ts`

Unit tested, no DOM or Tauri dependency. Tests cover:
- Empty findings → score 100, grade A
- Single critical gap → score 80, grade B
- Float-top finding doubles deduction
- Score floor at 0 (many severe findings)
- Grade boundaries (90→A, 89→B, 74→C, 59→D, 44→F)

---

## Part 1B: Report Tab Restructure

### Modified file: `src/routes/report/+page.svelte`

**Header** — adds score inline with title:
```
Security Report          72 / B  [Export Markdown]
```

Clicking the score shows a tooltip: `Score = 100 − deductions per finding severity`.

**Bucket bar** — proportional coloured bar above the tabs:
- Red segment: Issues count / total
- Gray segment: Unknown count / total
- Green segment: Good count / total

```html
<div style="display:flex;height:6px;border-radius:3px;overflow:hidden">
  <div style="background:#dc2626;flex:{issueCount}"></div>
  <div style="background:#94a3b8;flex:{unknownCount}"></div>
  <div style="background:#16a34a;flex:{goodCount}"></div>
</div>
```

**Tab pills** — replace existing severity filter pills:

| Tab | Filter | Default |
|-----|--------|---------|
| Issues (N) | `status === 'gap' \|\| status === 'recommendation'` | Selected |
| Unknown (N) | `status === 'unknown'` | |
| ✓ Good (N) | `status === 'ok'` | |
| All | all findings | |

Active tab has `bg-blue-600 text-white` class; inactive tabs have `hover:bg-gray-50` class.

**FindingRow.svelte** — unchanged. Existing left-border severity colours already handle visual differentiation.

**Unknown tab enhancement** — Unknown findings get an additional subtitle line: *"couldn't check via live API — use backup-file mode or check manually"*. This is rendered inline in the report page, not in FindingRow.

**Good tab** — Good findings are shown collapsed by default with a "Show all N passing checks" expand toggle. Not a separate component — a simple `let showGood = $state(false)` toggle.

---

## Part 2: Summary Screen (merged into wizard profile step)

### Modified file: `src/routes/wizard/+page.svelte`

**No new route.** The `step === 'profile'` block expands to show the full summary before the profile selector.

### State additions

```typescript
const postureScore = $derived(findings.length > 0 ? computeScore(findings) : null);

const issueFindings = $derived(findings.filter(f => f.status === 'gap' || f.status === 'recommendation'));
const unknownFindings = $derived(findings.filter(f => f.status === 'unknown'));
const goodFindings = $derived(findings.filter(f => f.status === 'ok'));
const topIssues = $derived(issueFindings.slice(0, 3));
```

Score is computed client-side from `findings` already loaded in `onMount` — no extra DB calls.

### Profile step layout

```
What we found on your network

        ┌─────────────┐
        │  72 / B     │   ← postureScore.score / postureScore.grade
        │  Fair       │   ← postureScore.label
        └─────────────┘

  ████████████░░░░░░░░░░░░░░░░░░
  Issues (3)   Unknown (4)    Good (2)

  Top findings from your controller:
  ● [HIGH] Flat network — no segmentation
  ● [HIGH] No VPN + port forwards active
  ● [LOW]  No Geo-IP blocking on inbound WAN

  ─────────────────────────────────────
  Profile confirmed as:
  [Home Office ▼]   ← ALL_PROFILES dropdown, pre-selected

  [Yes, continue →]       [Skip to report]
```

**"Skip to report"** — `goto('/report?runId=${runId}')`. Bypasses skills check and gap questions. For power users who reviewed the summary and don't need guided questions.

**"Yes, continue →"** — `confirmProfile(confirmedProfile)` as before, advancing to `step = 'skills'`.

### Bucket bar

Reuses the same inline CSS pattern as the report (no shared component — both usages are ~5 lines of inline style). If the bar needs to be reused in a third place, extract to `src/lib/components/BucketBar.svelte`.

### Score import

```typescript
import { computeScore } from '../../audit/score.js';
```

---

## Files Changed

| File | Change |
|------|--------|
| `src/audit/score.ts` | New — computeScore() with algorithm + grades |
| `src/audit/__tests__/score.test.ts` | New — unit tests for score engine |
| `src/routes/report/+page.svelte` | Replace severity pills with bucket tabs; add score header + bucket bar |
| `src/routes/wizard/+page.svelte` | Expand profile step with score, bucket bar, top findings, skip button |

`FindingRow.svelte`, `QuestionCard.svelte`, all audit modules, DB schema — untouched.

---

## Out of Scope

- Storing the score in SQLite (it can always be recomputed from findings)
- Score history / trend chart (Phase 7 territory)
- Animated bucket bar transitions
- Tier-specific score explanations (Guided/Standard/Pro voices on score)
