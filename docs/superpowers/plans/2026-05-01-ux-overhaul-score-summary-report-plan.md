# UX Overhaul: Score, Summary Screen, and Report Restructure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add a posture score (72 / B), restructure the report into Issues/Unknown/Good tabs, and expand the wizard's profile step into a full API summary screen.

**Architecture:** Part 1 (Tasks 1–2) is independently shippable: new `src/audit/score.ts` + restructured report. Part 2 (Task 3) imports the score engine into the wizard. All changes are Svelte 5 + TypeScript; no schema changes; no new routes.

**Tech Stack:** TypeScript, Svelte 5, Vitest (tests for score only — Svelte components are manually tested in the running Tauri app)

---

## File Map

| File | Action |
|------|--------|
| `src/audit/score.ts` | **Create** — `computeScore()` + `PostureScore` interface |
| `src/audit/__tests__/score.test.ts` | **Create** — unit tests for score engine |
| `src/routes/report/+page.svelte` | **Replace** — tab pills, bucket bar, score header |
| `src/routes/wizard/+page.svelte` | **Modify** — expand profile step with summary |

---

## Part 1

---

### Task 1: Score engine

**Files:**
- Create: `src/audit/score.ts`
- Create: `src/audit/__tests__/score.test.ts`

- [x] **Step 1: Write the failing tests**

Create `src/audit/__tests__/score.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import type { Finding } from '../types.js';
import { computeScore } from '../score.js';

function f(opts: Partial<Finding> & { status: Finding['status']; severity: Finding['severity'] }): Finding {
  return {
    id: 'TEST', section: 'Test', title: 'Test', currentState: 'x',
    recommendation: null, intentQuestion: null, evidence: {}, mapsTo: {},
    effort: 'quick', impact: 'medium', floatTop: false,
    ...opts,
  };
}

describe('computeScore', () => {
  it('empty findings → score 100, grade A, label Strong', () => {
    const r = computeScore([]);
    expect(r.score).toBe(100);
    expect(r.grade).toBe('A');
    expect(r.label).toBe('Strong');
  });

  it('single critical gap → deducts 20 → score 80, grade B', () => {
    const r = computeScore([f({ status: 'gap', severity: 'critical' })]);
    expect(r.score).toBe(80);
    expect(r.grade).toBe('B');
  });

  it('high gap → deducts 10 → score 90, grade A', () => {
    const r = computeScore([f({ status: 'gap', severity: 'high' })]);
    expect(r.score).toBe(90);
    expect(r.grade).toBe('A');
  });

  it('recommendation deducts half vs gap', () => {
    // critical recommendation = 10 deduction
    expect(computeScore([f({ status: 'recommendation', severity: 'critical' })]).score).toBe(90);
  });

  it('unknown deducts less than gap', () => {
    // critical unknown = 5 deduction
    expect(computeScore([f({ status: 'unknown', severity: 'critical' })]).score).toBe(95);
  });

  it('ok findings do not deduct', () => {
    expect(computeScore([f({ status: 'ok', severity: 'critical' })]).score).toBe(100);
  });

  it('floatTop doubles the deduction', () => {
    // high gap = 10; floatTop doubles → 20; 100 − 20 = 80
    const r = computeScore([f({ status: 'gap', severity: 'high', floatTop: true })]);
    expect(r.score).toBe(80);
    expect(r.grade).toBe('B');
  });

  it('score is clamped to 0, grade F', () => {
    const manyGaps = Array.from({ length: 10 }, () => f({ status: 'gap', severity: 'critical' }));
    const r = computeScore(manyGaps);
    expect(r.score).toBe(0);
    expect(r.grade).toBe('F');
    expect(r.label).toBe('At risk');
  });

  it('grade boundary 90 → A', () => {
    // 100 − 10 (high gap) = 90 → A
    expect(computeScore([f({ status: 'gap', severity: 'high' })]).grade).toBe('A');
  });

  it('grade boundary 89 → B', () => {
    // 100 − 10 (high gap) − 1 (low recommendation) = 89 → B
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'recommendation', severity: 'low' }),
    ]);
    expect(r.score).toBe(89);
    expect(r.grade).toBe('B');
  });

  it('grade boundary 74 → C', () => {
    // 100 − 10 − 10 − 5 − 1 = 74 → C
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'medium' }),
      f({ status: 'recommendation', severity: 'low' }),
    ]);
    expect(r.score).toBe(74);
    expect(r.grade).toBe('C');
  });
});
```

- [x] **Step 2: Run tests — expect import error**

```bash
npm test -- src/audit/__tests__/score.test.ts
```

Expected: `Cannot find module '../score.js'`

- [x] **Step 3: Create `src/audit/score.ts`**

```typescript
import type { Finding } from './types.js';

export interface PostureScore {
  score: number;   // 0–100, clamped
  grade: string;   // A | B | C | D | F
  label: string;   // Strong | Good | Fair | Needs work | At risk
}

const DEDUCTIONS: Record<string, Record<string, number>> = {
  gap:            { critical: 20, high: 10, medium: 5, low: 2, info: 0 },
  recommendation: { critical: 10, high: 5,  medium: 2, low: 1, info: 0 },
  unknown:        { critical: 5,  high: 3,  medium: 1, low: 0, info: 0 },
  ok:             { critical: 0,  high: 0,  medium: 0, low: 0, info: 0 },
};

export function computeScore(findings: Finding[]): PostureScore {
  let score = 100;
  for (const f of findings) {
    const base = DEDUCTIONS[f.status]?.[f.severity] ?? 0;
    score -= f.floatTop ? base * 2 : base;
  }
  score = Math.round(Math.max(0, Math.min(100, score)));
  const grade =
    score >= 90 ? 'A' :
    score >= 75 ? 'B' :
    score >= 60 ? 'C' :
    score >= 45 ? 'D' : 'F';
  const label =
    score >= 90 ? 'Strong' :
    score >= 75 ? 'Good' :
    score >= 60 ? 'Fair' :
    score >= 45 ? 'Needs work' : 'At risk';
  return { score, grade, label };
}
```

- [x] **Step 4: Run tests — expect all pass**

```bash
npm test -- src/audit/__tests__/score.test.ts
```

Expected: 11 passed

- [x] **Step 5: Run full suite to confirm no regressions**

```bash
npm test
```

Expected: 78 passed (77 existing + 1 new test file with 11 tests, total increases)

- [x] **Step 6: Commit**

```bash
git add src/audit/score.ts src/audit/__tests__/score.test.ts
git commit -m "feat: add computeScore() posture score engine with grade + label"
```

---

### Task 2: Report tab restructure

**Files:**
- Modify: `src/routes/report/+page.svelte` (replace entirely)

- [x] **Step 1: Replace `src/routes/report/+page.svelte` with the new version**

```svelte
<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import FindingRow from '../../lib/components/FindingRow.svelte';
  import { computeScore } from '../../audit/score.js';
  import type { Finding } from '../../audit/types.js';

  const runId = $derived($page.url.searchParams.get('runId') ?? '');

  let findings: Finding[] = $state([]);
  let filter = $state('issues');
  let showGood = $state(false);

  onMount(async () => {
    const { openDb, getFindings } = await import('../../db/queries.js');
    findings = await getFindings(await openDb(), runId);
  });

  const posture = $derived(findings.length > 0 ? computeScore(findings) : null);

  const issueFindings  = $derived(findings.filter(f => f.status === 'gap' || f.status === 'recommendation'));
  const unknownFindings = $derived(findings.filter(f => f.status === 'unknown'));
  const goodFindings   = $derived(findings.filter(f => f.status === 'ok'));

  const visible = $derived(
    filter === 'issues'  ? issueFindings :
    filter === 'unknown' ? unknownFindings :
    filter === 'good'    ? goodFindings :
    findings
  );

  function exportMarkdown() {
    const lines = ['# UniFi Security Advisor Report', ''];
    if (posture) lines.push(`**Posture score:** ${posture.score} / ${posture.grade} — ${posture.label}`, '');
    for (const f of findings) {
      lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`*${f.section} / ${f.id}*`, '');
      lines.push(`**Current state:** ${f.currentState}`, '');
      if (f.recommendation) lines.push(`**Recommend:** ${f.recommendation}`, '');
      lines.push('---', '');
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `unifi-report-${runId.slice(0, 8)}.md`;
    a.click();
  }
</script>

<main class="p-8 max-w-3xl mx-auto">
  <div class="flex items-center justify-between mb-6">
    <div>
      <a href="/" class="text-blue-600 text-sm">← Home</a>
      <h1 class="text-2xl font-bold mt-1">Security Report</h1>
    </div>
    <div class="flex items-center gap-3">
      {#if posture}
        <span
          class="text-lg font-bold text-blue-700 cursor-help"
          title="Score = 100 − deductions per finding severity. Float-to-top findings count double."
        >
          {posture.score} / {posture.grade}
        </span>
      {/if}
      <button class="border rounded-lg px-4 py-2 text-sm font-medium hover:bg-gray-50" onclick={exportMarkdown}>
        Export Markdown
      </button>
    </div>
  </div>

  {#if findings.length > 0}
    <!-- Proportional bucket bar -->
    <div class="flex h-2 rounded-full overflow-hidden mb-4" title="Red: issues · Gray: unknown · Green: good">
      <div class="bg-red-500 transition-all" style="flex:{issueFindings.length}"></div>
      <div class="bg-gray-300 transition-all" style="flex:{unknownFindings.length}"></div>
      <div class="bg-green-500 transition-all" style="flex:{goodFindings.length}"></div>
    </div>
  {/if}

  <!-- Tab pills -->
  <div class="flex gap-2 mb-6 flex-wrap">
    {#each [
      { key: 'issues',  label: `Issues (${issueFindings.length})` },
      { key: 'unknown', label: `Unknown (${unknownFindings.length})` },
      { key: 'good',    label: `✓ Good (${goodFindings.length})` },
      { key: 'all',     label: `All (${findings.length})` },
    ] as tab (tab.key)}
      <button
        class="px-3 py-1 rounded-full text-xs font-medium border {filter === tab.key ? 'bg-blue-600 text-white border-blue-600' : 'hover:bg-gray-50'}"
        onclick={() => { filter = tab.key; showGood = false; }}
      >
        {tab.label}
      </button>
    {/each}
  </div>

  <!-- Findings list -->
  <div class="space-y-3">
    {#if filter === 'good' && !showGood && goodFindings.length > 0}
      <button
        class="w-full text-center py-3 text-sm text-gray-400 border border-dashed rounded-lg hover:bg-gray-50"
        onclick={() => showGood = true}
      >
        Show {goodFindings.length} passing check{goodFindings.length !== 1 ? 's' : ''}
      </button>
    {:else}
      {#each visible as finding (finding.id)}
        <div>
          <FindingRow {finding} />
          {#if finding.status === 'unknown'}
            <p class="text-xs text-gray-400 italic mt-1 ml-4">
              Couldn't check via live API — use backup-file mode or verify manually in your controller.
            </p>
          {/if}
        </div>
      {/each}
      {#if visible.length === 0}
        <p class="text-gray-400 text-center py-8">No findings in this category.</p>
      {/if}
    {/if}
  </div>

  <div class="mt-10 text-xs text-gray-400 border-t pt-4">
    All secrets replaced with fingerprints. No credentials in this report. Safe to share.
  </div>
</main>
```

- [x] **Step 2: Verify Vite build succeeds**

```bash
npm run build
```

Expected: `✔ done` with no errors

- [x] **Step 3: Manually verify in the running app**

Start `npx tauri dev`, run an audit, navigate to the report. Confirm:
- Score shows in header (e.g. "72 / B")
- Bucket bar renders proportionally
- "Issues" tab is selected by default
- Clicking "Unknown" shows unknown-status findings with italic note
- Clicking "✓ Good" shows the "Show N passing checks" expand button; clicking it reveals them
- "All" shows every finding
- Export Markdown includes the score line

- [x] **Step 4: Commit**

```bash
git add src/routes/report/+page.svelte
git commit -m "feat: restructure report — bucket tabs (Issues/Unknown/Good/All), score header, bucket bar"
```

---

## Part 2

---

### Task 3: Summary screen in wizard profile step

**Files:**
- Modify: `src/routes/wizard/+page.svelte`

- [x] **Step 1: Add `computeScore` import and derived values to the script block**

In `src/routes/wizard/+page.svelte`, add this import after the existing imports:

```typescript
import { computeScore } from '../../audit/score.js';
```

Then add these derived values after the existing `const progress` line (line 24):

```typescript
  const postureScore  = $derived(findings.length > 0 ? computeScore(findings) : null);
  const issueCount    = $derived(findings.filter(f => f.status === 'gap' || f.status === 'recommendation').length);
  const unknownCount  = $derived(findings.filter(f => f.status === 'unknown').length);
  const goodCount     = $derived(findings.filter(f => f.status === 'ok').length);
  const topIssues     = $derived(
    findings.filter(f => f.status === 'gap' || f.status === 'recommendation').slice(0, 3)
  );
```

- [x] **Step 2: Replace the `{#if step === 'profile'}` block in the template**

Find this block in the template (starts at line 56, ends at line 73):

```svelte
  {#if step === 'profile'}
    <h1 class="text-xl font-bold mb-2">Confirm your network profile</h1>
    <p class="text-gray-500 mb-6 text-sm">
      Based on what we found, this looks like a <strong>{profileLabel(confirmedProfile)}</strong> setup. Is that right?
    </p>
    <div class="flex gap-3 flex-wrap items-center">
      <button class="bg-blue-600 text-white px-5 py-2 rounded-lg font-medium" onclick={() => confirmProfile(confirmedProfile)}>
        Yes, that's right
      </button>
      <select class="border rounded-lg px-3 py-2 text-sm" onchange={(e) => confirmedProfile = (e.target as HTMLSelectElement).value}>
        {#each ALL_PROFILES as p}
          <option value={p} selected={p === confirmedProfile}>{profileLabel(p)}</option>
        {/each}
      </select>
      <button class="bg-gray-100 px-5 py-2 rounded-lg font-medium" onclick={() => confirmProfile(confirmedProfile)}>
        Use selected
      </button>
    </div>
```

Replace it with:

```svelte
  {#if step === 'profile'}
    <h1 class="text-xl font-bold mb-4">What we found on your network</h1>

    {#if postureScore && findings.length > 0}
      <!-- Score hero -->
      <div class="text-center mb-6">
        <div class="inline-flex flex-col items-center bg-blue-700 text-white px-8 py-4 rounded-2xl shadow">
          <span class="text-4xl font-black leading-none">{postureScore.score} / {postureScore.grade}</span>
          <span class="text-sm opacity-80 mt-1">{postureScore.label}</span>
        </div>
      </div>

      <!-- Bucket bar -->
      <div class="flex h-2 rounded-full overflow-hidden mb-2">
        <div class="bg-red-500" style="flex:{issueCount}"></div>
        <div class="bg-gray-300" style="flex:{unknownCount}"></div>
        <div class="bg-green-500" style="flex:{goodCount}"></div>
      </div>
      <div class="flex justify-between text-xs mb-6">
        <span class="text-red-600 font-medium">Issues ({issueCount})</span>
        <span class="text-gray-400">Unknown ({unknownCount})</span>
        <span class="text-green-600 font-medium">Good ({goodCount})</span>
      </div>

      <!-- Top findings preview -->
      {#if topIssues.length > 0}
        <div class="mb-6">
          <p class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
            Top findings from your controller
          </p>
          <div class="space-y-2">
            {#each topIssues as f (f.id)}
              <div class="flex items-start gap-2 text-sm">
                <span class="text-red-500 mt-0.5 shrink-0">●</span>
                <span>
                  <span class="font-medium text-xs text-gray-400 uppercase">[{f.severity}]</span>
                  {f.title}
                </span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <hr class="mb-6" />
    {/if}

    <!-- Profile confirmation (always shown) -->
    <p class="text-sm text-gray-600 mb-3">
      We think this is a <strong>{profileLabel(confirmedProfile)}</strong> setup. Confirm or change:
    </p>
    <div class="mb-6">
      <select
        class="border rounded-lg px-3 py-2 text-sm"
        onchange={(e) => confirmedProfile = (e.target as HTMLSelectElement).value}
      >
        {#each ALL_PROFILES as p}
          <option value={p} selected={p === confirmedProfile}>{profileLabel(p)}</option>
        {/each}
      </select>
    </div>
    <div class="flex gap-3 flex-wrap">
      <button
        class="bg-blue-600 text-white px-5 py-2 rounded-lg font-medium hover:bg-blue-700"
        onclick={() => confirmProfile(confirmedProfile)}
      >
        Yes, continue →
      </button>
      <button
        class="text-gray-500 px-5 py-2 rounded-lg border hover:bg-gray-50"
        onclick={() => goto(`/report?runId=${runId}`)}
      >
        Skip to report
      </button>
    </div>
```

- [x] **Step 3: Verify Vite build succeeds**

```bash
npm run build
```

Expected: `✔ done` with no errors

- [x] **Step 4: Run the full test suite**

```bash
npm test
```

Expected: all tests pass (no change in count — this is a Svelte component change, not a TypeScript module change)

- [x] **Step 5: Manually verify in the running app**

Start `npx tauri dev`, run a full audit. On the wizard's first screen, confirm:
- Score hero shows (e.g. "72 / B · Fair")
- Bucket bar renders with red/gray/green proportional segments
- Top 3 issue findings are listed below the bar
- Profile dropdown shows the inferred profile pre-selected
- "Yes, continue →" advances to the skills check
- "Skip to report" goes directly to the report screen
- When findings haven't loaded yet (e.g. slow DB), the score/bar don't render — only the profile selector shows

- [x] **Step 6: Commit**

```bash
git add src/routes/wizard/+page.svelte
git commit -m "feat: expand wizard profile step into full API summary (score, bucket bar, top findings, skip)"
```
