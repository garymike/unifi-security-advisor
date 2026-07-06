<script lang="ts">
  import { onMount } from 'svelte';
  import { computeScore } from '../audit/score.js';
  import { profileLabel } from '../wizard/profileInfer.js';

  interface RecentRun {
    id: string;
    profile: string;
    timestamp: string;
    score: number;
    grade: string;
  }

  let recent: RecentRun[] = $state([]);
  let loaded = $state(false);
  let showHelp = $state(false);

  onMount(async () => {
    try {
      const { openDb, listRuns, getAnsweredFindings } = await import('../db/queries.js');
      const db = await openDb();
      const runs = await listRuns(db);
      const out: RecentRun[] = [];
      for (const run of runs.slice(0, 3)) {
        const s = computeScore(await getAnsweredFindings(db, run.id));
        out.push({ id: run.id, profile: run.profile, timestamp: run.timestamp, score: s.score, grade: s.grade });
      }
      recent = out;
    } catch {
      // No database yet (first run) or not in a Tauri context — show the empty state.
    } finally {
      loaded = true;
    }
  });

  function fmt(ts: string): string {
    return new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }
</script>

<main class="bg-surface-0 min-h-screen p-8 max-w-2xl mx-auto">
  <h1 class="text-2xl font-bold mb-1 text-fg">Check your UniFi network's security</h1>
  <p class="text-fg-muted mb-5">
    A private posture audit of your Ubiquiti network — findings, plain-English explanations, and what to do about them.
  </p>

  <div class="flex flex-wrap gap-2 mb-8">
    <span class="text-xs text-fg-muted bg-surface-2 rounded-lg px-3 py-1.5">Runs on your device</span>
    <span class="text-xs text-fg-muted bg-surface-2 rounded-lg px-3 py-1.5">Credentials never leave</span>
    <span class="text-xs text-fg-muted bg-surface-2 rounded-lg px-3 py-1.5">Read-only</span>
  </div>

  <p class="text-xs font-semibold text-fg-subtle uppercase tracking-wide mb-3">How would you like to start?</p>
  <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-3">
    <a href="/audit" class="block border-2 border-accent rounded-xl p-4 bg-surface-1 hover:bg-surface-2">
      <span class="inline-block text-xs bg-accent-tint text-accent px-2 py-0.5 rounded mb-2">Recommended</span>
      <p class="font-medium text-fg">Analyze my network</p>
      <p class="text-xs text-fg-subtle mt-1 leading-snug">On the same network. Uses a local API key.</p>
    </a>
    <a href="/audit?cloud=1" class="block border border-line rounded-xl p-4 bg-surface-1 hover:bg-surface-2">
      <p class="font-medium text-fg">Through the cloud</p>
      <p class="text-xs text-fg-subtle mt-1 leading-snug">Remote or CGNAT. Uses a Site Manager key.</p>
    </a>
    <a href="/backup" class="block border border-line rounded-xl p-4 bg-surface-1 hover:bg-surface-2">
      <p class="font-medium text-fg">From a backup file</p>
      <p class="text-xs text-fg-subtle mt-1 leading-snug">Fully offline. A .unf or .unifi file.</p>
    </a>
  </div>

  <button class="text-sm text-accent hover:underline mb-2" onclick={() => (showHelp = !showHelp)}>
    Not sure? Help me choose
  </button>
  {#if showHelp}
    <div class="text-sm text-fg-muted bg-surface-2 border border-line rounded-lg p-4 mb-2 space-y-2">
      <p><strong class="font-medium text-fg">On the same network as your console?</strong> Choose <em>Analyze my network</em> — the most detail, and the smallest trust boundary.</p>
      <p><strong class="font-medium text-fg">Behind CGNAT, or auditing remotely?</strong> Choose <em>Through the cloud</em> (a Site Manager key routes through Ubiquiti's cloud).</p>
      <p><strong class="font-medium text-fg">Airgapped, or reviewing a saved config?</strong> Choose <em>From a backup file</em> — nothing connects to the network.</p>
    </div>
  {/if}

  {#if loaded}
    <div class="border-t border-line mt-8 pt-4">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs font-semibold text-fg-subtle uppercase tracking-wide">Recent audits</span>
        {#if recent.length > 0}
          <a href="/history" class="text-sm text-accent hover:underline">View history</a>
        {/if}
      </div>
      {#if recent.length === 0}
        <p class="text-sm text-fg-subtle py-2">Your audits will show up here once you run one.</p>
      {:else}
        {#each recent as r (r.id)}
          <a
            href="/report?runId={r.id}"
            class="flex items-center justify-between py-2 border-b border-line last:border-0 hover:bg-surface-2 -mx-2 px-2 rounded"
          >
            <span class="text-sm text-fg-muted">{profileLabel(r.profile)} · {fmt(r.timestamp)}</span>
            <span class="text-xs font-medium text-accent bg-accent-tint px-2 py-0.5 rounded">{r.score} / {r.grade}</span>
          </a>
        {/each}
      {/if}
    </div>
  {/if}
</main>
