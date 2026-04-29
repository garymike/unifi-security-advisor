<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import FindingRow from '../../lib/components/FindingRow.svelte';
  import type { Finding } from '../../audit/types.js';

  const runId = $derived($page.url.searchParams.get('runId') ?? '');

  let findings: Finding[] = $state([]);
  let filter = $state('all');

  onMount(async () => {
    const { openDb, getFindings } = await import('../../db/queries.js');
    findings = await getFindings(await openDb(), runId);
  });

  const counts = $derived({
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
  });

  const visible = $derived(
    filter === 'all' ? findings :
    filter === 'open' ? findings.filter(f => f.status !== 'ok') :
    findings.filter(f => f.severity === filter)
  );

  function exportMarkdown() {
    const lines = ['# UniFi Security Advisor Report', ''];
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
    <button class="border rounded-lg px-4 py-2 text-sm font-medium hover:bg-gray-50" onclick={exportMarkdown}>
      Export Markdown
    </button>
  </div>

  <div class="flex gap-3 mb-6 flex-wrap">
    {#each ['all', 'open', 'critical', 'high', 'medium', 'low'] as f}
      <button
        class="px-3 py-1 rounded-full text-xs font-medium border {filter === f ? 'bg-blue-600 text-white border-blue-600' : 'hover:bg-gray-50'}"
        onclick={() => filter = f}
      >
        {f === 'all' ? `All (${findings.length})` :
         f === 'open' ? `Open (${findings.filter(x => x.status !== 'ok').length})` :
         `${f} (${counts[f as keyof typeof counts] ?? 0})`}
      </button>
    {/each}
  </div>

  <div class="space-y-3">
    {#each visible as finding (finding.id)}
      <FindingRow {finding} />
    {/each}
    {#if visible.length === 0}
      <p class="text-gray-400 text-center py-8">No findings match this filter.</p>
    {/if}
  </div>

  <div class="mt-10 text-xs text-gray-400 border-t pt-4">
    All secrets replaced with fingerprints. No credentials in this report. Safe to share.
  </div>
</main>
