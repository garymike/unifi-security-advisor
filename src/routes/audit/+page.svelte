<script lang="ts">
  import ModeStep from '../../lib/onboarding/ModeStep.svelte';
  import KeyInstructions from '../../lib/onboarding/KeyInstructions.svelte';
  import ValidateStep from '../../lib/onboarding/ValidateStep.svelte';
  import { runAudit } from '../../lib/AuditRunner.js';
  import { goto } from '$app/navigation';
  import { get } from 'svelte/store';
  import { connectTier } from '../../lib/stores/connectTier.js';

  type Step = 'check' | 'mode' | 'getkey' | 'validate';
  let step = $state<Step>('mode'); // Task 9 sets initial 'check'
  let mode = $state<'local' | 'cloud'>('local');
  let host = $state('');

  let running = $state(false);
  let runError = $state('');

  function toGetKey() {
    if (mode === 'local' && !host.trim()) return;
    step = 'getkey';
  }

  async function onrun({ apiKey }: { apiKey: string }) {
    running = true; runError = '';
    try {
      const { openDb, insertRun, insertFindings, insertSites } = await import('../../db/queries.js');
      const result = await runAudit(apiKey, host, mode === 'cloud', () => {});
      const db = await openDb();
      const runId = await insertRun(db, host || 'cloud', result.inferredProfile, result.sites.length, get(connectTier));
      await insertFindings(db, runId, result.findings);
      await insertSites(db, runId, result.sites.map(s => ({ siteId: s.siteId, siteName: s.siteName, apiGaps: s.apiGaps })));
      goto(`/wizard?runId=${runId}&profile=${result.inferredProfile}`);
    } catch (e) {
      runError = e instanceof Error ? e.message : String(e);
      running = false;
    }
  }
</script>

<main class="p-8 max-w-xl mx-auto">
  <a href="/" class="text-blue-600 text-sm mb-6 block">← Back</a>
  <h1 class="text-2xl font-bold mb-6">Connect to your UniFi console</h1>

  {#if step === 'mode'}
    <ModeStep bind:mode bind:host />
    <button class="mt-6 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold disabled:opacity-50"
      onclick={toGetKey} disabled={mode === 'local' && !host.trim()}>Next</button>
  {:else if step === 'getkey'}
    <KeyInstructions {mode} {host} />
    <div class="mt-6 flex gap-3">
      <button class="px-4 py-2 rounded-lg border" onclick={() => (step = 'mode')}>Back</button>
      <button class="bg-blue-600 text-white px-6 py-2 rounded-lg font-semibold"
        onclick={() => (step = 'validate')}>I have my key →</button>
    </div>
  {:else if step === 'validate'}
    <ValidateStep {mode} {host} {onrun} />
    {#if runError}<p class="text-red-600 text-sm mt-3">{runError}</p>{/if}
    {#if running}<p class="text-gray-500 text-sm mt-3">Running audit…</p>{/if}
    <button class="mt-4 px-4 py-2 rounded-lg border" onclick={() => (step = 'getkey')} disabled={running}>Back</button>
  {/if}
</main>
