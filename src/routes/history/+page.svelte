<script lang="ts">
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
    const { openDb, listRuns, getAnsweredFindings } = await import('../../db/queries.js');
    const db = await openDb();
    const runs = await listRuns(db);
    const result: RunSummary[] = [];
    for (const run of [...runs].reverse()) {
      // Answered findings so the score/diff match the report for the same run.
      const findings = await getAnsweredFindings(db, run.id);
      const posture = computeScore(findings);
      result.push({ id: run.id, timestamp: run.timestamp, host: run.host, score: posture.score, grade: posture.grade, findings });
    }
    summaries = result;
    loading = false;
  });

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
  const diffPair = $derived.by(() => {
    if (!selectedA || !selectedB) return null;
    const sA = summaries.find(s => s.id === selectedA)!;
    const sB = summaries.find(s => s.id === selectedB)!;
    return new Date(sA.timestamp) <= new Date(sB.timestamp) ? [sA, sB] : [sB, sA];
  });

  const GRADE_BADGE: Record<'ok' | 'warn' | 'high', string> = {
    ok: 'bg-sev-ok-tint text-sev-ok',
    warn: 'bg-sev-warn-tint text-sev-warn',
    high: 'bg-sev-high-tint text-sev-high',
  };

  function gradeSev(grade: string): 'ok' | 'warn' | 'high' {
    const letter = grade[0];
    if (letter === 'A' || letter === 'B') return 'ok';
    if (letter === 'C') return 'warn';
    return 'high';
  }
</script>

<main class="p-6 max-w-3xl mx-auto">
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-bold text-fg">Audit History</h1>
      {#if !loading}
        <p class="text-sm text-fg-subtle mt-1">{summaries.length} run{summaries.length !== 1 ? 's' : ''}</p>
      {/if}
    </div>
    {#if summaries.length >= 2}
      <p class="text-xs text-fg-subtle text-right">Click one point to select<br>Click two points to compare</p>
    {/if}
  </div>

  {#if loading}
    <p class="text-fg-subtle text-center py-12">Loading history...</p>

  {:else if summaries.length === 0}
    <div class="text-center py-16">
      <p class="text-fg-subtle mb-4">No audit runs yet.</p>
      <a href="/audit" class="bg-accent text-on-accent px-5 py-2 rounded-lg text-sm font-medium">Run First Audit</a>
    </div>

  {:else}
    <div class="bg-surface-1 border border-line rounded-xl p-3 mb-6">
      <svg viewBox="0 0 {W} {H}" class="w-full">
        {#each [100, 75, 50, 25] as v}
          <line x1={PL} y1={toY(v)} x2={W - PR} y2={toY(v)} stroke="var(--line)" stroke-width="0.5"/>
          <text x={PL - 4} y={toY(v) + 3} font-size="8" fill="var(--fg-subtle)" text-anchor="end">{v}</text>
        {/each}

        {#if summaries.length > 1}
          <polygon
            points="{polyline} {toX(summaries.length - 1)},{PT + innerH} {toX(0)},{PT + innerH}"
            fill="var(--accent)" opacity="0.12"
          />
          <polyline
            points={polyline}
            fill="none" stroke="var(--accent)" stroke-width="2.5"
            stroke-linejoin="round" stroke-linecap="round"
          />
        {/if}

        {#each summaries as s, i}
          {@const sel = selectedA === s.id || selectedB === s.id}
          {@const x = toX(i)}
          {@const y = toY(s.score)}
          {#if sel}
            <text x={x} y={y - 10} font-size="9" fill="var(--accent)" text-anchor="middle" font-weight="bold">
              {s.score}/{s.grade}
            </text>
          {/if}
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <circle
            cx={x} cy={y} r={sel ? 7 : 5}
            fill={sel ? 'var(--accent)' : 'var(--surface-1)'} stroke="var(--accent)" stroke-width="2"
            style="cursor:pointer"
            onclick={() => handleClick(s.id)}
          />
          <text x={x} y={H - 4} font-size="8" text-anchor="middle"
            fill={sel ? 'var(--fg-muted)' : 'var(--fg-subtle)'} font-weight={sel ? 'bold' : 'normal'}>
            {fmt(s.timestamp)}
          </text>
        {/each}
      </svg>
    </div>

    {#if selectedA && !selectedB}
      <div class="flex items-center justify-between p-4 border border-line rounded-xl mb-4">
        <div class="text-sm text-fg-muted">
          {#if selectedSummaryA}
            <span class="font-medium px-2.5 py-1 rounded-full {GRADE_BADGE[gradeSev(selectedSummaryA.grade)]}">{fmt(selectedSummaryA.timestamp)} — {selectedSummaryA.score}/{selectedSummaryA.grade}</span>
          {/if}
        </div>
        <div class="flex gap-2">
          <button
            class="text-xs text-fg-subtle px-3 py-1 border border-line rounded hover:bg-surface-2"
            onclick={() => { selectedA = null; }}
          >Deselect</button>
          <a
            href="/report?runId={selectedA}"
            class="text-xs bg-accent text-on-accent px-3 py-1 rounded font-medium hover:bg-accent-hover"
          >View Report →</a>
        </div>
      </div>
      <p class="text-xs text-fg-subtle text-center">Select a second point to compare</p>
    {/if}

    {#if diff && diffPair}
      {@const [earlier, later] = diffPair}
      <div class="border border-line rounded-xl overflow-hidden">
        <div class="bg-surface-2 px-4 py-3 flex justify-between items-center">
          <span class="text-sm font-semibold text-fg-muted">
            {fmt(earlier.timestamp)} → {fmt(later.timestamp)}
          </span>
          <span class="text-sm font-bold {diff.scoreDelta >= 0 ? 'text-sev-ok' : 'text-sev-high'}">
            {earlier.score}/{earlier.grade} → {later.score}/{later.grade}
            {diff.scoreDelta > 0 ? `↑${diff.scoreDelta}` : diff.scoreDelta < 0 ? `↓${Math.abs(diff.scoreDelta)}` : '—'}
          </span>
        </div>
        <div class="p-4 space-y-2">
          {#each diff.removed as f (f.id)}
            <div class="flex items-start gap-2 p-2 bg-sev-ok-tint rounded-lg text-sm">
              <span class="text-sev-ok font-bold shrink-0 text-xs">✓ RESOLVED</span>
              <span class="text-fg-muted">{f.title} <span class="text-fg-subtle text-xs uppercase">({f.severity})</span></span>
            </div>
          {/each}
          {#each diff.added as f (f.id)}
            <div class="flex items-start gap-2 p-2 bg-sev-high-tint rounded-lg text-sm">
              <span class="text-sev-high font-bold shrink-0 text-xs">+ NEW</span>
              <span class="text-fg-muted">{f.title} <span class="text-fg-subtle text-xs uppercase">({f.severity})</span></span>
            </div>
          {/each}
          {#each diff.changed as c (c.after.id)}
            <div class="flex items-start gap-2 p-2 bg-sev-warn-tint rounded-lg text-sm">
              <span class="text-sev-warn font-bold shrink-0 text-xs">~ CHANGED</span>
              <span class="text-fg-muted">
                {c.after.title}
                {#if c.before.status !== c.after.status}
                  <span class="text-fg-subtle text-xs">{c.before.status} → {c.after.status}</span>
                {/if}
                {#if c.before.severity !== c.after.severity}
                  <span class="text-fg-subtle text-xs">{c.before.severity} → {c.after.severity}</span>
                {/if}
              </span>
            </div>
          {/each}
          {#if diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0}
            <p class="text-fg-subtle text-sm text-center py-2">No finding changes between these runs.</p>
          {/if}
        </div>
        <div class="px-4 pb-4 flex gap-2">
          <a href="/report?runId={earlier.id}" class="text-xs border border-line rounded px-3 py-1 hover:bg-surface-2 text-fg-muted">
            {fmt(earlier.timestamp)} report →
          </a>
          <a href="/report?runId={later.id}" class="text-xs border border-line rounded px-3 py-1 hover:bg-surface-2 text-fg-muted">
            {fmt(later.timestamp)} report →
          </a>
        </div>
      </div>
    {/if}
  {/if}
</main>
