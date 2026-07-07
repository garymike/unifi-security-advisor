<script lang="ts">
  import { goto } from '$app/navigation';
  import { normalizeBackup } from '../../audit/normalizeBackup.js';
  import { analyze } from '../../audit/analyze.js';

  const ALL_PROFILES = [
    'home', 'home_office', 'small_business', 'regulated_hipaa', 'regulated_pci',
  ] as const;
  const PROFILE_LABELS: Record<string, string> = {
    home: 'Home', home_office: 'Home Office', small_business: 'Small Business',
    regulated_hipaa: 'Regulated (HIPAA)', regulated_pci: 'Regulated (PCI)',
  };

  let filePath: string | null = $state(null);
  let fileName: string | null = $state(null);
  let profile = $state('home_office');
  let running = $state(false);
  let progressLog: string[] = $state([]);
  let error = $state('');

  async function browse() {
    const { open } = await import('@tauri-apps/plugin-dialog');
    const selected = await open({
      filters: [{ name: 'UniFi Backup', extensions: ['unf', 'unifi'] }],
      multiple: false,
    });
    if (typeof selected === 'string') {
      filePath = selected;
      fileName = selected.split(/[/\\]/).pop() ?? selected;
    }
  }

  async function runAnalysis() {
    if (!filePath) return;
    running = true; error = ''; progressLog = [];
    try {
      progressLog = [...progressLog, 'Decrypting and parsing backup...'];
      const { invoke } = await import('@tauri-apps/api/core');
      const collections = await invoke<Record<string, Record<string, unknown>[]>>(
        'parse_backup', { path: filePath },
      );
      const collectionCount = Object.keys(collections).length;
      progressLog = [...progressLog, `Parsed ${collectionCount} collections`];

      const sites = normalizeBackup(collections, profile);
      const site = sites[0];
      progressLog = [...progressLog,
        `Normalized — ${site?.wlans.length ?? 0} WLANs, ${site?.devices.length ?? 0} devices, ${site?.networks.length ?? 0} networks`,
      ];

      progressLog = [...progressLog, 'Running findings analysis...'];
      const findings = analyze(sites, {}, profile, (mod, _site, err) => {
        progressLog = [...progressLog, `Warning: ${mod} failed: ${err}`];
      });
      progressLog = [...progressLog, `Found ${findings.length} findings`];

      const { openDb, insertRun, insertFindings, insertSites } = await import('../../db/queries.js');
      const db = await openDb();
      const runId = await insertRun(db, `backup:${fileName}`, profile, sites.length);
      await insertFindings(db, runId, findings);
      await insertSites(db, runId, sites.map(s => ({
        siteId: s.siteId, siteName: s.siteName, apiGaps: s.apiGaps,
      })));

      goto(`/wizard?runId=${runId}&profile=${profile}`);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      running = false;
    }
  }
</script>

<main class="bg-surface-0 min-h-screen p-8 max-w-xl mx-auto">
  <h1 class="text-2xl font-bold mb-2 text-fg">Analyze Backup File</h1>
  <p class="text-fg-subtle text-sm mb-8">
    Parse a UniFi Network backup (.unf) entirely offline. Unlocks WLAN, VPN,
    firewall, and settings findings that the live API cannot yet provide.
  </p>

  <div class="space-y-4 mb-6">
    <div>
      <label for="backup-file-btn" class="block text-sm font-medium text-fg-muted mb-1">Backup file</label>
      <div class="flex items-center gap-2">
        <button
          id="backup-file-btn"
          class="px-4 py-2 border border-line rounded-lg text-sm bg-surface-1 hover:bg-surface-2 font-medium shrink-0"
          onclick={browse}
          disabled={running}
        >Browse…</button>
        {#if fileName}
          <span class="text-sm text-fg-muted flex-1 truncate">{fileName}</span>
          <button
            class="text-fg-subtle hover:text-fg-muted text-sm shrink-0"
            onclick={() => { filePath = null; fileName = null; }}
          >×</button>
        {:else}
          <span class="text-sm text-fg-subtle">No file selected</span>
        {/if}
      </div>
      <p class="text-xs text-fg-subtle mt-1">
        Supports .unf and .unifi formats. Older controllers (USG, UDM) and UniFi OS console backups (Cloud Gateway Fiber and similar) are both parsed entirely offline.
      </p>
    </div>

    <div>
      <label for="profile-select" class="block text-sm font-medium text-fg-muted mb-1">Profile</label>
      <select
        id="profile-select"
        class="border border-line rounded-lg px-3 py-2 text-sm w-full bg-surface-1 text-fg"
        bind:value={profile}
        disabled={running}
      >
        {#each ALL_PROFILES as p}
          <option value={p}>{PROFILE_LABELS[p]}</option>
        {/each}
      </select>
    </div>
  </div>

  {#if error}
    <p class="bg-sev-high-tint text-sev-high text-sm mb-4 rounded-lg px-3 py-2">{error}</p>
  {/if}

  <button
    class="bg-accent text-on-accent px-6 py-3 rounded-lg font-semibold hover:bg-accent-hover disabled:opacity-50"
    onclick={runAnalysis}
    disabled={running || !filePath}
  >
    {running ? 'Analyzing…' : 'Analyze Backup →'}
  </button>

  {#if progressLog.length > 0}
    <div class="mt-6 bg-surface-2 border border-line rounded-lg p-4 font-mono text-xs space-y-1 max-h-48 overflow-y-auto text-fg-muted">
      {#each progressLog as line}
        <div>{line}</div>
      {/each}
    </div>
  {/if}
</main>
