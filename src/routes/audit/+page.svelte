<script lang="ts">
  import { goto } from '$app/navigation';
  import { runAudit } from '../../lib/AuditRunner.js';

  let host = $state('');
  let apiKey = $state('');
  let useCloud = $state(false);
  let running = $state(false);
  let progressLog: string[] = $state([]);
  let error = $state('');

  async function startAudit() {
    if (!apiKey.trim()) { error = 'API key is required.'; return; }
    if (!useCloud && !host.trim()) { error = 'Controller host is required for local mode.'; return; }
    running = true; error = ''; progressLog = [];

    try {
      progressLog = [...progressLog, '[1] importing db module...'];
      const { openDb, insertRun, insertFindings, insertSites } = await import('../../db/queries.js');
      progressLog = [...progressLog, '[2] starting runAudit...'];
      const result = await runAudit(apiKey, host, useCloud, msg => {
        progressLog = [...progressLog, msg];
      });
      progressLog = [...progressLog, `[3] runAudit done — ${result.findings.length} findings, ${result.sites.length} sites`];
      const db = await openDb();
      progressLog = [...progressLog, '[4] db opened, inserting run...'];
      const runId = await insertRun(db, host || 'cloud', result.inferredProfile, result.sites.length);
      progressLog = [...progressLog, `[5] run ${runId} created, inserting findings...`];
      await insertFindings(db, runId, result.findings);
      progressLog = [...progressLog, '[6] findings inserted, inserting sites...'];
      await insertSites(db, runId, result.sites.map(s => ({
        siteId: s.siteId, siteName: s.siteName, apiGaps: s.apiGaps,
      })));
      progressLog = [...progressLog, '[7] done — navigating to wizard'];
      goto(`/wizard?runId=${runId}&profile=${result.inferredProfile}`);
    } catch (err) {
      console.error('[audit] failed:', err);
      const msg = err instanceof Error
        ? `${err.message}`
        : (typeof err === 'object' ? JSON.stringify(err) : String(err));
      error = `Error: ${msg}`;
      running = false;
    }
  }
</script>

<main class="p-8 max-w-xl mx-auto">
  <a href="/" class="text-blue-600 text-sm mb-6 block">← Back</a>
  <h1 class="text-2xl font-bold mb-6">Connect to Controller</h1>

  <div class="space-y-4 mb-6">
    <label class="block">
      <span class="text-sm font-medium text-gray-700">API Key</span>
      <input
        type="password"
        bind:value={apiKey}
        placeholder="Paste your X-API-KEY here"
        class="mt-1 block w-full border rounded-lg px-3 py-2 font-mono text-sm"
      />
      <p class="text-xs text-gray-400 mt-1">Generated in Site Manager → API Keys. Revoke after use.</p>
    </label>

    <label class="flex items-center gap-2">
      <input type="checkbox" bind:checked={useCloud} />
      <span class="text-sm">Use Site Manager API (cloud/CGNAT mode)</span>
    </label>

    {#if !useCloud}
      <label class="block">
        <span class="text-sm font-medium text-gray-700">Controller Host</span>
        <input
          type="text"
          bind:value={host}
          placeholder="192.168.1.1"
          class="mt-1 block w-full border rounded-lg px-3 py-2"
        />
      </label>
    {/if}
  </div>

  {#if error}
    <p class="text-red-600 text-sm mb-4">{error}</p>
  {/if}

  <button
    class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 disabled:opacity-50"
    onclick={startAudit}
    disabled={running}
  >
    {running ? 'Running audit…' : 'Run Audit'}
  </button>

  {#if progressLog.length > 0}
    <div class="mt-6 bg-gray-50 rounded-lg p-4 font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
      {#each progressLog as line}
        <div>{line}</div>
      {/each}
    </div>
  {/if}
</main>
