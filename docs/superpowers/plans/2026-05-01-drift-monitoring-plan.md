# Phase 7: Drift Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a History tab with a line chart of all audit runs, and a diff engine that shows what changed between any two selected runs.

**Architecture:** Three independent tasks. Task 1 is pure TypeScript (diff engine, TDD). Task 2 is layout and routing changes (no tests, manually verified). Task 3 is the History Svelte page. No schema changes — scores are computed from findings loaded via the existing `getFindings()` query.

**Tech Stack:** TypeScript, Svelte 5, Vitest (Task 1 only), existing `@tauri-apps/plugin-sql` for DB

---

## File Map

| File | Change |
|------|--------|
| `src/audit/diff.ts` | **Create** — `diffRuns()` function |
| `src/audit/__tests__/diff.test.ts` | **Create** — 8 unit tests |
| `src/routes/+layout.svelte` | **Modify** — add persistent tab bar |
| `src/routes/+page.svelte` | **Replace** — redirect to `/history` |
| `src/routes/wizard/+page.svelte` | **Modify** — suppress tab bar |
| `src/routes/history/+page.svelte` | **Create** — SVG line chart + diff panel |

---

## Task 1: Diff engine

**Files:**
- Create: `src/audit/diff.ts`
- Create: `src/audit/__tests__/diff.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `src/audit/__tests__/diff.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import type { Finding } from '../types.js';
import { diffRuns } from '../diff.js';

function f(id: string, opts: Partial<Finding> = {}): Finding {
  return {
    id, section: 'Test', title: id, currentState: 'x',
    severity: 'medium', status: 'gap',
    recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'medium',
    floatTop: false,
    ...opts,
  };
}

describe('diffRuns', () => {
  it('empty vs empty → no changes, zero delta', () => {
    const r = diffRuns([], []);
    expect(r.added).toHaveLength(0);
    expect(r.removed).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
    expect(r.scoreDelta).toBe(0);
  });

  it('finding in B not in A → added', () => {
    const r = diffRuns([], [f('NEW-001')]);
    expect(r.added).toHaveLength(1);
    expect(r.added[0]!.id).toBe('NEW-001');
    expect(r.removed).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
  });

  it('finding in A not in B → removed', () => {
    const r = diffRuns([f('OLD-001')], []);
    expect(r.removed).toHaveLength(1);
    expect(r.removed[0]!.id).toBe('OLD-001');
    expect(r.added).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
  });

  it('same finding in both with identical severity+status → not in any bucket', () => {
    const finding = f('SAME-001');
    const r = diffRuns([finding], [finding]);
    expect(r.added).toHaveLength(0);
    expect(r.removed).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
  });

  it('finding in both with different status → changed', () => {
    const r = diffRuns(
      [f('A', { status: 'gap' })],
      [f('A', { status: 'ok' })],
    );
    expect(r.changed).toHaveLength(1);
    expect(r.changed[0]!.before.status).toBe('gap');
    expect(r.changed[0]!.after.status).toBe('ok');
    expect(r.added).toHaveLength(0);
    expect(r.removed).toHaveLength(0);
  });

  it('finding in both with different severity → changed', () => {
    const r = diffRuns(
      [f('A', { severity: 'high' })],
      [f('A', { severity: 'medium' })],
    );
    expect(r.changed).toHaveLength(1);
    expect(r.changed[0]!.before.severity).toBe('high');
    expect(r.changed[0]!.after.severity).toBe('medium');
  });

  it('scoreDelta is positive when posture improves (A had a gap, B does not)', () => {
    // findingsA has one high gap → score 90; findingsB is empty → score 100
    const r = diffRuns([f('A', { status: 'gap', severity: 'high' })], []);
    expect(r.scoreDelta).toBe(10); // 100 - 90 = 10 improvement
  });

  it('scoreDelta is negative when posture worsens', () => {
    // findingsA empty → 100; findingsB has one high gap → 90
    const r = diffRuns([], [f('A', { status: 'gap', severity: 'high' })]);
    expect(r.scoreDelta).toBe(-10);
  });
});
```

- [ ] **Step 2: Run — expect module not found**

```bash
npm test -- src/audit/__tests__/diff.test.ts
```

Expected: `Cannot find module '../diff.js'`

- [ ] **Step 3: Create `src/audit/diff.ts`**

```typescript
import type { Finding } from './types.js';
import { computeScore } from './score.js';
import { sortFindings } from './analyze.js';

export interface ChangedFinding {
  before: Finding;
  after: Finding;
}

export interface DiffResult {
  added: Finding[];           // in B, not in A — new problems
  removed: Finding[];         // in A, not in B — resolved
  changed: ChangedFinding[];  // in both, but severity or status changed
  scoreDelta: number;         // computeScore(B).score − computeScore(A).score
}

export function diffRuns(findingsA: Finding[], findingsB: Finding[]): DiffResult {
  const mapA = new Map(findingsA.map(f => [f.id, f]));
  const mapB = new Map(findingsB.map(f => [f.id, f]));

  const added: Finding[] = [];
  const removed: Finding[] = [];
  const changed: ChangedFinding[] = [];

  for (const [id, fb] of mapB) {
    if (!mapA.has(id)) added.push(fb);
  }

  for (const [id, fa] of mapA) {
    if (!mapB.has(id)) {
      removed.push(fa);
    } else {
      const fb = mapB.get(id)!;
      if (fa.severity !== fb.severity || fa.status !== fb.status) {
        changed.push({ before: fa, after: fb });
      }
    }
  }

  return {
    added: sortFindings(added),
    removed: sortFindings(removed),
    changed: sortFindings(changed.map(c => c.after)).map(after => ({
      before: changed.find(c => c.after.id === after.id)!.before,
      after,
    })),
    scoreDelta: computeScore(findingsB).score - computeScore(findingsA).score,
  };
}
```

- [ ] **Step 4: Run — expect 8 passed**

```bash
npm test -- src/audit/__tests__/diff.test.ts
```

Expected: 8 passed

- [ ] **Step 5: Run full suite**

```bash
npm test
```

Expected: 101 passed (93 existing + 8 new)

- [ ] **Step 6: Commit**

```bash
git add src/audit/diff.ts src/audit/__tests__/diff.test.ts
git commit -m "feat: add diffRuns() engine — added/removed/changed findings + scoreDelta"
```

---

## Task 2: Tab bar, redirects, and wizard suppression

**Files:**
- Modify: `src/routes/+layout.svelte`
- Replace: `src/routes/+page.svelte`
- Modify: `src/routes/wizard/+page.svelte`

- [ ] **Step 1: Replace `src/routes/+layout.svelte`**

The existing file only imports CSS. Replace its entire contents:

```svelte
<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';

  // Hide tabs during the wizard — it's a linear flow that must not be interrupted
  const showTabs = $derived(!$page.url.pathname.startsWith('/wizard'));

  const tabs = [
    { label: 'Analyze', href: '/audit' },
    { label: 'Report',  href: '/report' },
    { label: 'History', href: '/history' },
  ] as const;

  function isActive(href: string): boolean {
    const p = $page.url.pathname;
    if (href === '/audit') return p === '/audit' || p === '/';
    return p === href || p.startsWith(href + '/');
  }
</script>

{#if showTabs}
  <nav class="flex border-b border-gray-200 bg-white sticky top-0 z-10">
    {#each tabs as tab}
      <a
        href={tab.href}
        class="px-6 py-3 text-sm font-medium border-b-2 transition-colors
          {isActive(tab.href)
            ? 'border-blue-600 text-blue-700'
            : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}"
      >
        {tab.label}
      </a>
    {/each}
  </nav>
{/if}

<slot />
```

- [ ] **Step 2: Replace `src/routes/+page.svelte`**

Replace the entire home screen with a redirect to `/history`:

```svelte
<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  onMount(() => goto('/history', { replaceState: true }));
</script>
```

- [ ] **Step 3: Verify the Vite build still succeeds**

```bash
npm run build
```

Expected: `✔ done`

- [ ] **Step 4: Verify tests unchanged**

```bash
npm test
```

Expected: 101 passed (same as after Task 1)

- [ ] **Step 5: Commit**

```bash
git add src/routes/+layout.svelte src/routes/+page.svelte
git commit -m "feat: add persistent tab bar (Analyze/Report/History); redirect / to /history"
```

---

## Task 3: History page

**Files:**
- Create: `src/routes/history/+page.svelte`

- [ ] **Step 1: Create `src/routes/history/+page.svelte`**

```svelte
<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { computeScore } from '../../audit/score.js';
  import { diffRuns } from '../../audit/diff.js';
  import type { Finding } from '../../audit/types.js';
  import type { DiffResult } from '../../audit/diff.js';

  interface RunSummary {
    id: string;
    timestamp: string;
    host: string | null;
    score: number;
    grade: string;
    findings: Finding[];
  }

  let summaries: RunSummary[] = $state([]);
  let loading = $state(true);
  let selectedA: string | null = $state(null);
  let selectedB: string | null = $state(null);
  let diff: DiffResult | null = $state(null);

  onMount(async () => {
    const { openDb, listRuns, getFindings } = await import('../../db/queries.js');
    const db = await openDb();
    const runs = await listRuns(db);
    const result: RunSummary[] = [];
    for (const run of [...runs].reverse()) {   // oldest first for left→right chart order
      const findings = await getFindings(db, run.id);
      const posture = computeScore(findings);
      result.push({ id: run.id, timestamp: run.timestamp, host: run.host, score: posture.score, grade: posture.grade, findings });
    }
    summaries = result;
    loading = false;
  });

  // SVG chart constants
  const W = 480, H = 110, PL = 32, PR = 16, PT = 20, PB = 24;
  const innerW = W - PL - PR;
  const innerH = H - PT - PB;

  function toX(i: number): number {
    return summaries.length <= 1 ? PL + innerW / 2 : PL + (i / (summaries.length - 1)) * innerW;
  }
  function toY(score: number): number {
    return PT + innerH - (score / 100) * innerH;
  }

  const polyline = $derived(summaries.map((s, i) => `${toX(i)},${toY(s.score)}`).join(' '));

  function handleClick(id: string) {
    if (selectedA === id) {
      // Deselect A; B (if any) becomes A
      selectedA = selectedB;
      selectedB = null;
      diff = null;
    } else if (selectedB === id) {
      selectedB = null;
      diff = null;
    } else if (selectedA === null) {
      selectedA = id;
    } else if (selectedB === null) {
      selectedB = id;
      computeDiff(selectedA, id);
    } else {
      // Both already selected — replace B
      selectedB = id;
      computeDiff(selectedA, id);
    }
  }

  function computeDiff(idA: string, idB: string) {
    const sA = summaries.find(s => s.id === idA)!;
    const sB = summaries.find(s => s.id === idB)!;
    const [earlier, later] = new Date(sA.timestamp) <= new Date(sB.timestamp) ? [sA, sB] : [sB, sA];
    diff = diffRuns(earlier.findings, later.findings);
  }

  function fmt(ts: string): string {
    return new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  const selectedSummaryA = $derived(summaries.find(s => s.id === selectedA) ?? null);
  const selectedSummaryB = $derived(summaries.find(s => s.id === selectedB) ?? null);
  const [diffEarlier, diffLater] = $derived.by(() => {
    if (!selectedSummaryA || !selectedSummaryB) return [null, null];
    return new Date(selectedSummaryA.timestamp) <= new Date(selectedSummaryB.timestamp)
      ? [selectedSummaryA, selectedSummaryB]
      : [selectedSummaryB, selectedSummaryA];
  });
</script>

<main class="p-6 max-w-3xl mx-auto">
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-bold">Audit History</h1>
      {#if !loading}
        <p class="text-sm text-gray-500 mt-1">{summaries.length} run{summaries.length !== 1 ? 's' : ''}</p>
      {/if}
    </div>
    {#if summaries.length >= 2}
      <p class="text-xs text-gray-400 text-right">Click one point to select<br>Click two points to compare</p>
    {/if}
  </div>

  {#if loading}
    <p class="text-gray-400 text-center py-12">Loading history...</p>

  {:else if summaries.length === 0}
    <div class="text-center py-16">
      <p class="text-gray-400 mb-4">No audit runs yet.</p>
      <a href="/audit" class="bg-blue-600 text-white px-5 py-2 rounded-lg text-sm font-medium">Run First Audit</a>
    </div>

  {:else}
    <!-- Line chart -->
    <div class="bg-gray-50 border border-gray-200 rounded-xl p-3 mb-6">
      <svg viewBox="0 0 {W} {H}" class="w-full">
        <!-- Y-axis gridlines -->
        {#each [100, 75, 50, 25] as v}
          <line x1={PL} y1={toY(v)} x2={W - PR} y2={toY(v)} stroke="#e2e8f0" stroke-width="0.5"/>
          <text x={PL - 4} y={toY(v) + 3} font-size="8" fill="#94a3b8" text-anchor="end">{v}</text>
        {/each}

        <!-- Shaded area + line (only when 2+ runs) -->
        {#if summaries.length > 1}
          <polygon
            points="{polyline} {toX(summaries.length - 1)},{PT + innerH} {toX(0)},{PT + innerH}"
            fill="#1e40af" opacity="0.06"
          />
          <polyline
            points={polyline}
            fill="none" stroke="#1e40af" stroke-width="2.5"
            stroke-linejoin="round" stroke-linecap="round"
          />
        {/if}

        <!-- Points -->
        {#each summaries as s, i}
          {@const sel = selectedA === s.id || selectedB === s.id}
          {@const x = toX(i)}
          {@const y = toY(s.score)}
          {#if sel}
            <text x={x} y={y - 10} font-size="9" fill="#1e40af" text-anchor="middle" font-weight="bold">
              {s.score}/{s.grade}
            </text>
          {/if}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <circle
            cx={x} cy={y} r={sel ? 7 : 5}
            fill={sel ? '#1e40af' : 'white'} stroke="#1e40af" stroke-width="2"
            style="cursor:pointer"
            onclick={() => handleClick(s.id)}
          />
          <text x={x} y={H - 4} font-size="8" text-anchor="middle"
            fill={sel ? '#374151' : '#94a3b8'} font-weight={sel ? 'bold' : 'normal'}>
            {fmt(s.timestamp)}
          </text>
        {/each}
      </svg>
    </div>

    <!-- Single point selected — show View Report button -->
    {#if selectedA && !selectedB}
      <div class="flex items-center justify-between p-4 border border-gray-200 rounded-xl mb-4">
        <div class="text-sm text-gray-600">
          {#if selectedSummaryA}
            <span class="font-medium">{fmt(selectedSummaryA.timestamp)}</span> — {selectedSummaryA.score}/{selectedSummaryA.grade}
          {/if}
        </div>
        <div class="flex gap-2">
          <button
            class="text-xs text-gray-400 px-3 py-1 border rounded hover:bg-gray-50"
            onclick={() => { selectedA = null; }}
          >Deselect</button>
          <a
            href="/report?runId={selectedA}"
            class="text-xs bg-blue-600 text-white px-3 py-1 rounded font-medium hover:bg-blue-700"
          >View Report →</a>
        </div>
      </div>
      <p class="text-xs text-gray-400 text-center">Select a second point to compare</p>
    {/if}

    <!-- Two points selected — diff panel -->
    {#if diff && diffEarlier && diffLater}
      <div class="border border-gray-200 rounded-xl overflow-hidden">
        <div class="bg-gray-50 px-4 py-3 flex justify-between items-center">
          <span class="text-sm font-semibold text-gray-700">
            {fmt(diffEarlier.timestamp)} → {fmt(diffLater.timestamp)}
          </span>
          <span class="text-sm font-bold {diff.scoreDelta >= 0 ? 'text-green-600' : 'text-red-600'}">
            {diffEarlier.score}/{diffEarlier.grade} → {diffLater.score}/{diffLater.grade}
            {diff.scoreDelta > 0 ? `↑${diff.scoreDelta}` : diff.scoreDelta < 0 ? `↓${Math.abs(diff.scoreDelta)}` : '—'}
          </span>
        </div>
        <div class="p-4 space-y-2">
          {#each diff.removed as f (f.id)}
            <div class="flex items-start gap-2 p-2 bg-green-50 rounded-lg text-sm">
              <span class="text-green-700 font-bold shrink-0 text-xs">✓ RESOLVED</span>
              <span class="text-gray-700">{f.title} <span class="text-gray-400 text-xs uppercase">({f.severity})</span></span>
            </div>
          {/each}
          {#each diff.added as f (f.id)}
            <div class="flex items-start gap-2 p-2 bg-red-50 rounded-lg text-sm">
              <span class="text-red-700 font-bold shrink-0 text-xs">+ NEW</span>
              <span class="text-gray-700">{f.title} <span class="text-gray-400 text-xs uppercase">({f.severity})</span></span>
            </div>
          {/each}
          {#each diff.changed as c (c.after.id)}
            <div class="flex items-start gap-2 p-2 bg-amber-50 rounded-lg text-sm">
              <span class="text-amber-700 font-bold shrink-0 text-xs">~ CHANGED</span>
              <span class="text-gray-700">
                {c.after.title}
                <span class="text-gray-400 text-xs">{c.before.severity} → {c.after.severity}</span>
              </span>
            </div>
          {/each}
          {#if diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0}
            <p class="text-gray-400 text-sm text-center py-2">No finding changes between these runs.</p>
          {/if}
        </div>
        <div class="px-4 pb-4 flex gap-2">
          <a href="/report?runId={diffEarlier.id}" class="text-xs border rounded px-3 py-1 hover:bg-gray-50 text-gray-600">
            {fmt(diffEarlier.timestamp)} report →
          </a>
          <a href="/report?runId={diffLater.id}" class="text-xs border rounded px-3 py-1 hover:bg-gray-50 text-gray-600">
            {fmt(diffLater.timestamp)} report →
          </a>
        </div>
      </div>
    {/if}
  {/if}
</main>
```

- [ ] **Step 2: Verify Vite build**

```bash
npm run build
```

Expected: `✔ done`

- [ ] **Step 3: Verify test suite**

```bash
npm test
```

Expected: 101 passed (unchanged — Svelte component has no unit tests)

- [ ] **Step 4: Manually verify in the Tauri app**

Start `npx tauri dev`. Confirm:

1. Tab bar shows `Analyze | Report | History` on every screen except the wizard
2. Navigating to `/` redirects to History tab
3. With 0 runs: History shows "No audit runs yet" + "Run First Audit" link
4. After running an audit: History shows one point on the line chart
5. With 2+ runs: clicking one point shows a "View Report" button below the chart
6. Clicking a second point shows the diff panel with RESOLVED/NEW/CHANGED buckets
7. Clicking a selected point deselects it
8. "View Report" links in the diff panel navigate to the correct report
9. Wizard screen does NOT show the tab bar

- [ ] **Step 5: Commit**

```bash
git add src/routes/history/+page.svelte
git commit -m "feat: add History tab — line chart of all runs + finding diff between any two runs"
```
