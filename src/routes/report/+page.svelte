<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { computeScore } from '../../audit/score.js';
  import type { Finding, Status } from '../../audit/types.js';

  // Maps a finding's status to a severity role (drives icon tile / tag color).
  const STATUS_SEV: Record<Status, 'high' | 'warn' | 'ok' | 'info'> = {
    gap: 'high',
    recommendation: 'warn',
    ok: 'ok',
    unknown: 'info',
  };

  const SEV_TAG: Record<string, string> = {
    high: 'GAP',
    warn: 'RECOMMENDATION',
    ok: 'OK',
    info: 'UNKNOWN',
  };

  const SEV_ICON: Record<string, string> = {
    high: 'M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
    warn: 'M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
    ok: 'M20 6 9 17l-5-5',
    info: 'M12 16v-4m0-4h.01M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0z',
  };

  // Literal class names (Tailwind v4 needs statically-analyzable utilities, so
  // these can't be built via string interpolation like `bg-sev-${sev}-tint`).
  const SEV_TINT_BG: Record<string, string> = {
    high: 'bg-sev-high-tint',
    warn: 'bg-sev-warn-tint',
    ok: 'bg-sev-ok-tint',
    info: 'bg-sev-info-tint',
  };
  const SEV_TEXT: Record<string, string> = {
    high: 'text-sev-high',
    warn: 'text-sev-warn',
    ok: 'text-sev-ok',
    info: 'text-sev-info',
  };
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

<main class="p-8 max-w-3xl mx-auto bg-surface-0 min-h-screen">
  <div class="flex items-center justify-between mb-6">
    <div>
      <a href="/" class="text-accent text-sm">← Home</a>
      <h1 class="text-2xl font-bold mt-1 text-fg">Security Report</h1>
      {#if resolvedFromLatest}
        <p class="text-xs text-fg-subtle mt-1">Showing your most recent audit · <a href="/history" class="text-accent">pick another</a></p>
      {/if}
    </div>
    <div class="flex items-center gap-3">
      {#if posture}
        <span
          class="text-lg font-bold cursor-help px-2.5 py-1 rounded-full {GRADE_BADGE[gradeSev(posture.grade)]}"
          title="Score = 100 − deductions per finding severity. Float-to-top findings count double."
        >
          <span class="text-fg">{posture.score}</span> / {posture.grade}
        </span>
      {/if}
      <button class="border border-line rounded-lg px-4 py-2 text-sm font-medium text-fg hover:bg-surface-2" onclick={exportMarkdown}>
        Export Markdown
      </button>
    </div>
  </div>

  {#if findings.length > 0}
    <!-- Proportional bucket bar -->
    <div class="flex h-2 rounded-full overflow-hidden mb-4 bg-surface-2" title="Red: issues · Gray: unknown · Green: good">
      <div class="bg-sev-high transition-all" style="flex:{issueFindings.length}"></div>
      <div class="bg-sev-warn transition-all" style="flex:{unknownFindings.length}"></div>
      <div class="bg-sev-ok transition-all" style="flex:{goodFindings.length}"></div>
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
        class="px-3 py-1 rounded-full text-xs font-medium border {filter === tab.key ? 'border-accent bg-accent-tint text-accent' : 'border-line text-fg-muted hover:bg-surface-2'}"
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
        class="w-full text-center py-3 text-sm text-fg-subtle border border-dashed border-line rounded-lg hover:bg-surface-2"
        onclick={() => showGood = true}
      >
        Show {goodFindings.length} passing check{goodFindings.length !== 1 ? 's' : ''}
      </button>
    {:else}
      {#each visible as finding (finding.id)}
        {@const sev = STATUS_SEV[finding.status] ?? 'info'}
        <div>
          <div class="bg-surface-1 border border-line rounded-xl p-4 flex gap-3.5">
            <div class="w-9 h-9 rounded-[10px] flex-none flex items-center justify-center {SEV_TINT_BG[sev]}">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" class={SEV_TEXT[sev]} stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d={SEV_ICON[sev]}/></svg>
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex justify-between items-start gap-3">
                <h3 class="text-[15px] font-semibold text-fg m-0">{finding.title}</h3>
                <span class="text-[10px] font-semibold tracking-wide uppercase flex-none mt-0.5 {SEV_TEXT[sev]}">{SEV_TAG[sev]}</span>
              </div>
              <p class="text-xs text-fg-subtle mt-1">{finding.section} · {finding.id} · {finding.effort} effort</p>
              <p class="text-sm text-fg-muted mt-2.5 leading-relaxed">{finding.currentState}</p>
              {#if finding.recommendation && finding.status !== 'ok'}
                <p class="inline-flex items-center gap-1.5 text-sm text-accent mt-2.5">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
                  {finding.recommendation}
                </p>
              {/if}
              {#if finding.intentQuestion && finding.status !== 'ok'}
                <p class="text-xs text-fg-subtle mt-2 italic">{finding.intentQuestion}</p>
              {/if}
            </div>
          </div>
          {#if finding.status === 'unknown'}
            <p class="text-xs text-fg-subtle italic mt-1 ml-4">
              Couldn't check via live API — use backup-file mode or verify manually in your controller.
            </p>
          {/if}
        </div>
      {/each}
      {#if visible.length === 0}
        <p class="text-fg-subtle text-center py-8">No findings in this category.</p>
      {/if}
    {/if}
  </div>

  {#if noRuns}
    <div class="text-center py-12">
      <p class="text-fg-muted mb-4">No audits yet — run one to see your report.</p>
      <div class="flex gap-3 justify-center">
        <a href="/audit" class="bg-accent text-on-accent px-5 py-2 rounded-lg text-sm font-medium hover:bg-accent-hover">Analyze my network</a>
        <a href="/backup" class="border border-line text-fg px-5 py-2 rounded-lg text-sm font-medium hover:bg-surface-2">Use a backup file</a>
      </div>
    </div>
  {/if}

  <div class="mt-10 text-xs text-fg-subtle border-t border-line pt-4">
    All secrets replaced with fingerprints. No credentials in this report. Safe to share.
  </div>
</main>
