<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';

  interface RunRow {
    id: string;
    timestamp: string;
    host: string | null;
    profile: string;
    tier: string;
    site_count: number;
  }

  let runs: RunRow[] = $state([]);
  let dbError = $state('');

  onMount(async () => {
    try {
      const { openDb, listRuns } = await import('../db/queries.js');
      const db = await openDb();
      runs = await listRuns(db);
    } catch (e) {
      dbError = String(e);
    }
  });
</script>

<main class="p-8 max-w-3xl mx-auto">
  <h1 class="text-2xl font-bold mb-2">UniFi Security Advisor</h1>
  <p class="text-gray-500 mb-8">Audit your network. Understand your posture. Fix what matters.</p>

  <button
    class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700"
    onclick={() => goto('/audit')}
  >
    Start New Audit
  </button>

  {#if dbError}
    <p class="text-amber-600 text-sm mt-4">DB note: {dbError}</p>
  {/if}

  {#if runs.length > 0}
    <section class="mt-10">
      <h2 class="text-lg font-semibold mb-4">Past Runs</h2>
      <ul class="space-y-2">
        {#each runs as run (run.id)}
          <li>
            <button
              class="w-full text-left border rounded-lg px-4 py-3 hover:bg-gray-50"
              onclick={() => goto(`/report?runId=${run.id}`)}
            >
              <span class="font-medium">{run.host ?? 'cloud'}</span>
              <span class="text-gray-400 ml-2 text-sm">{new Date(run.timestamp).toLocaleString()}</span>
              <span class="ml-2 text-sm text-blue-600">{run.profile}</span>
            </button>
          </li>
        {/each}
      </ul>
    </section>
  {/if}
</main>
