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
    if (!runId) return;
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

  {#if !runId}
    <p class="text-gray-400 text-center py-8">
      No report selected. <a href="/" class="text-blue-600">Return home</a>.
    </p>
  {/if}

  <div class="mt-10 text-xs text-gray-400 border-t pt-4">
    All secrets replaced with fingerprints. No credentials in this report. Safe to share.
  </div>
</main>
