<script lang="ts">
  import { UniFiClient } from '../../audit/client.js';
  import { validateConnection, type ValidationResult } from './validateConnection.js';
  import { labelFor } from './keyIndex.js';
  import { connection, rememberKey } from './keychain.js';
  import CertChanged from './CertChanged.svelte';

  let { mode, host = '', onrun }: {
    mode: 'local' | 'cloud'; host?: string;
    onrun: () => void;
  } = $props();

  let apiKey = $state('');
  let remember = $state(false);
  let busy = $state(false);
  let result = $state<ValidationResult | null>(null);
  let pinned = $state<string | null>(null);

  async function validate() {
    if (!apiKey.trim()) { result = { ok: false, error: { kind: 'auth', message: 'Paste your API key first.' } }; return; }
    busy = true;
    try {
      // Hand the key to the backend, bound to this controller. From here on
      // the page only names paths; the backend adds the key.
      await connection.open(mode, host, apiKey.trim());
    } catch (e) {
      result = { ok: false, error: { kind: 'unreachable', message: e instanceof Error ? e.message : String(e) } };
      busy = false;
      return;
    }
    await check();
  }

  // Validate over the open connection. Also used after a re-pin, when the
  // backend still holds the key and the page no longer needs it.
  async function check() {
    busy = true;
    const client = new UniFiClient({
      host, useCloud: mode === 'cloud', verifySSL: mode === 'cloud', profile: 'home_office',
    });
    result = await validateConnection(client);
    pinned = null;
    if (result.ok) {
      apiKey = '';
      if (mode === 'local') {
        try { pinned = (await connection.certificate()).pinned; } catch { pinned = null; }
      }
    }
    busy = false;
  }

  async function run() {
    if (!result?.ok) return;
    if (remember) await rememberKey(labelFor(mode, host, result.consoleName));
    onrun();
  }
</script>

<div class="space-y-4">
  <label class="block">
    <span class="text-sm font-medium text-fg-muted">API key</span>
    <input type="password" bind:value={apiKey} placeholder="Paste your X-API-KEY here"
      class="mt-1 block w-full bg-surface-1 border border-line focus:border-accent rounded-lg px-3 py-2 font-mono text-sm text-fg placeholder:text-fg-subtle" />
  </label>

  <button type="button" onclick={validate} disabled={busy}
    class="px-4 py-2 rounded-lg border border-line text-fg hover:bg-surface-2 font-medium disabled:opacity-50">
    {busy ? 'Checking…' : 'Validate'}
  </button>

  {#if result?.ok}
    <div class="rounded-lg bg-sev-ok-tint border border-line p-3 text-sm text-sev-ok">
      ✓ Connected{result.consoleName ? ` · ${result.consoleName}` : ''}{result.networkVersion ? ` · Network ${result.networkVersion}` : ''}
      {#if result.sites?.length} · {result.sites.length} site{result.sites.length === 1 ? '' : 's'}{/if}
    </div>
    {#if pinned}
      <p class="text-xs text-fg-subtle">
        Console certificate saved (SHA-256): <span class="font-mono break-all">{pinned}</span>.
        Your key is only sent to a console presenting this certificate.
      </p>
    {/if}
    <label class="flex items-center gap-2 text-sm text-fg">
      <input type="checkbox" bind:checked={remember} />
      Remember this key in my keychain
    </label>
    <button onclick={run} class="bg-accent text-on-accent hover:bg-accent-hover px-6 py-3 rounded-lg font-semibold">Run Audit</button>
  {:else if result?.error?.kind === 'cert-changed'}
    <CertChanged {host} onrepinned={check} />
  {:else if result?.error}
    <div class="rounded-lg bg-sev-high-tint border border-line p-3 text-sm text-sev-high">{result.error.message}</div>
  {/if}
</div>
