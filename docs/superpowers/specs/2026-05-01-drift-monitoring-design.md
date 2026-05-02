# Phase 7: Drift Monitoring Design

**Date:** 2026-05-01  
**Status:** Approved  
**Scope:** Tab-based navigation restructure + History tab with line chart + diff engine. No scheduling — purely a visualization of runs already in the database.

---

## Problem

The app stores every audit run in SQLite but has no way to visualise how security posture changes over time. Past runs are listed as text on the home screen. There is no way to compare two runs to see what appeared, disappeared, or changed.

---

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Trigger | Manual — visualise existing DB runs | No scheduling complexity; user controls when they audit |
| Navigation | Top tab bar (Analyze / Report / History) | Persistent, always accessible, consistent with desktop app patterns |
| Tab implementation | Layout wrapper approach (Option A) | Minimal disruption to existing routes |
| Comparison model | User selects any two runs on the line chart | Maximum flexibility; auto-compare to previous was too limiting |
| Chart type | Line chart with score on Y axis, date on X axis | Shows trend clearly; bars were rejected in favour of line |
| Diff display | Inline panel below chart when two runs selected | No navigation required; diff stays in context of the chart |

---

## App Structure Changes

```
src/routes/
  +layout.svelte          ← NEW: tab bar for all non-wizard routes
  +page.svelte            ← CHANGE: redirects to /history
  audit/+page.svelte      ← unchanged (Analyze tab)
  wizard/+page.svelte     ← CHANGE: suppress tab bar (linear flow)
  report/+page.svelte     ← unchanged (Report tab)
  history/+page.svelte    ← NEW: History tab
```

### Tab bar (`+layout.svelte`)

Three tabs: **Analyze** | **Report** | **History**

Active tab determined from `$page.url.pathname`:
- `/audit` or `/` → Analyze highlighted
- `/report` → Report highlighted
- `/history` → History highlighted
- `/wizard` → tab bar **not rendered** (wizard is a linear flow that must not be interrupted)

After the wizard completes, the existing `goto('/report?runId=...')` call already handles the Report tab becoming active automatically.

---

## History Tab (`/history`)

### Layout

```
┌─────────────────────────────────────────────────────┐
│ [Analyze]  [Report]  [History ●]                    │  ← tab bar
├─────────────────────────────────────────────────────┤
│  Audit History                        5 runs        │
│  ─────────────────────────────────────────────────  │
│                                                      │
│  100 ┤                                        •      │
│   80 ┤  •         •          •━━━━━━━━━━━━━━━       │
│   60 ┤      •                                       │
│   40 ┤                                              │
│      └──────────────────────────────────────────    │
│       Apr 5  Apr 12  Apr 19  Apr 26  May 1          │
│                              ↑ selected  ↑ selected  │
│                                                      │
│  ┌─────────────────────────────────────────────┐    │
│  │ Comparing Apr 26 → May 1    Score: C+ → B- ↑ │   │
│  │ ✓ RESOLVED  No VPN + port forwards (HIGH)    │   │
│  │ + NEW       SSH enabled on 1 device (MEDIUM) │   │
│  │ ~ UNCHANGED Flat network (HIGH)              │   │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

### Interaction model

- **Click one point** → navigates to `/report?runId=...` (Report tab shows that run)
- **Click a second point** → shows diff panel inline below chart (no navigation)
- **Click same point twice** → deselects it, diff panel hidden
- **Score + grade label** shown above each selected point at all times; shown on hover for unselected points

### Data flow

```
onMount → listRuns(db) → renders all run points on chart
click point 1 → selectedRunAId set → getFindings(db, runAId) → findingsA
click point 2 → selectedRunBId set → getFindings(db, runBId) → findingsB
                → diffRuns(findingsA, findingsB) → renders diff panel
```

### Chart implementation

SVG line chart built inline in the Svelte component (no chart library dependency). Points are positioned using `score` mapped to Y axis and `timestamp` mapped to X axis. The chart scales to the actual score range of runs in the DB with a minimum Y range of 0–100.

---

## Diff Engine (`src/audit/diff.ts`)

### Interface

```typescript
export interface ChangedFinding {
  before: Finding;
  after: Finding;
}

export interface DiffResult {
  added: Finding[];           // in B, not in A — new problems
  removed: Finding[];         // in A, not in B — resolved
  changed: ChangedFinding[];  // in both, severity or status changed
  scoreDelta: number;         // computeScore(findingsB).score − computeScore(findingsA).score
}

export function diffRuns(findingsA: Finding[], findingsB: Finding[]): DiffResult
```

### Matching logic

Findings are matched by `id`. A finding present in both runs is classified as "changed" if its `severity` or `status` differs. Order within each bucket follows `sortFindings()` order (float-top first, then by severity).

### Rendering in diff panel

| Bucket | Colour | Label |
|--------|--------|-------|
| `added` | Red background | `+ NEW` |
| `removed` | Green background | `✓ RESOLVED` |
| `changed` | Amber background | `~ CHANGED` |
| Score delta | Header right | `Score: 78/C+ → 82/B- ↑4` |

---

## Files Changed

| File | Action |
|------|--------|
| `src/audit/diff.ts` | **Create** — `diffRuns()` + `DiffResult` interface |
| `src/audit/__tests__/diff.test.ts` | **Create** — unit tests |
| `src/routes/+layout.svelte` | **Create** — persistent tab bar |
| `src/routes/+page.svelte` | **Modify** — redirect to `/history` |
| `src/routes/wizard/+page.svelte` | **Modify** — suppress tab bar |
| `src/routes/history/+page.svelte` | **Create** — line chart + diff panel |

`src/routes/report/+page.svelte`, `src/routes/audit/+page.svelte`, `src/db/queries.ts`, all audit modules — **untouched**.

---

## Out of Scope

- Scheduled/automatic audits
- Email or OS-level notifications
- Baseline pinning (any run can be compared to any other)
- Export of diff report
- Multi-host comparison (all comparisons are within one controller)
