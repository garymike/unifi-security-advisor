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
  let noRuns = $state(false);
  let resolvedFromLatest = $state(false);

  onMount(async () => {
    const { openDb, listRuns, getAnsweredFindings } = await import('../../db/queries.js');
    const db = await openDb();

    // No run selected? Fall back to the most recent audit instead of a dead end.
    let id = runId;
    if (!id) {
      const runs = await listRuns(db); // ordered newest first
      if (runs.length === 0) { noRuns = true; return; }
      id = runs[0]!.id;
      resolvedFromLatest = true;
      const { goto } = await import('$app/navigation');
      goto(`/report?runId=${id}`, { replaceState: true, keepFocus: true, noScroll: true });
    }

    findings = await getAnsweredFindings(db, id);
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
      {#if resolvedFromLatest}
        <p class="text-xs text-gray-400 mt-1">Showing your most recent audit · <a href="/history" class="text-blue-600">pick another</a></p>
      {/if}
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

  {#if noRuns}
    <div class="text-center py-12">
      <p class="text-gray-500 mb-4">No audits yet — run one to see your report.</p>
      <div class="flex gap-3 justify-center">
        <a href="/audit" class="bg-blue-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-blue-700">Analyze my network</a>
        <a href="/backup" class="border px-5 py-2 rounded-lg text-sm font-medium hover:bg-gray-50">Use a backup file</a>
      </div>
    </div>
  {/if}

  <div class="mt-10 text-xs text-gray-400 border-t pt-4">
    All secrets replaced with fingerprints. No credentials in this report. Safe to share.
  </div>
</main>
