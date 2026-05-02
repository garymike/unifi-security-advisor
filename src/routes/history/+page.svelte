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
    const { openDb, listRuns, getFindings } = await import('../../db/queries.js');
    const db = await openDb();
    const runs = await listRuns(db);
    const result: RunSummary[] = [];
    for (const run of [...runs].reverse()) {
      const findings = await getFindings(db, run.id);
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
    <div class="bg-gray-50 border border-gray-200 rounded-xl p-3 mb-6">
      <svg viewBox="0 0 {W} {H}" class="w-full">
        {#each [100, 75, 50, 25] as v}
          <line x1={PL} y1={toY(v)} x2={W - PR} y2={toY(v)} stroke="#e2e8f0" stroke-width="0.5"/>
          <text x={PL - 4} y={toY(v) + 3} font-size="8" fill="#94a3b8" text-anchor="end">{v}</text>
        {/each}

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

    {#if diff && diffPair}
      {@const [earlier, later] = diffPair}
      <div class="border border-gray-200 rounded-xl overflow-hidden">
        <div class="bg-gray-50 px-4 py-3 flex justify-between items-center">
          <span class="text-sm font-semibold text-gray-700">
            {fmt(earlier.timestamp)} → {fmt(later.timestamp)}
          </span>
          <span class="text-sm font-bold {diff.scoreDelta >= 0 ? 'text-green-600' : 'text-red-600'}">
            {earlier.score}/{earlier.grade} → {later.score}/{later.grade}
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
                {#if c.before.status !== c.after.status}
                  <span class="text-gray-400 text-xs">{c.before.status} → {c.after.status}</span>
                {/if}
                {#if c.before.severity !== c.after.severity}
                  <span class="text-gray-400 text-xs">{c.before.severity} → {c.after.severity}</span>
                {/if}
              </span>
            </div>
          {/each}
          {#if diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0}
            <p class="text-gray-400 text-sm text-center py-2">No finding changes between these runs.</p>
          {/if}
        </div>
        <div class="px-4 pb-4 flex gap-2">
          <a href="/report?runId={earlier.id}" class="text-xs border rounded px-3 py-1 hover:bg-gray-50 text-gray-600">
            {fmt(earlier.timestamp)} report →
          </a>
          <a href="/report?runId={later.id}" class="text-xs border rounded px-3 py-1 hover:bg-gray-50 text-gray-600">
            {fmt(later.timestamp)} report →
          </a>
        </div>
      </div>
    {/if}
  {/if}
</main>
