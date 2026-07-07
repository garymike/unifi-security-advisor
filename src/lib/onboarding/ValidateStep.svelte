<script lang="ts">
  import { UniFiClient } from '../../audit/client.js';
  import { validateConnection, type ValidationResult } from './validateConnection.js';
  import { identityFor, labelFor } from './keyIndex.js';
  import { rememberKey } from './keychain.js';

  let { mode, host = '', onrun }: {
    mode: 'local' | 'cloud'; host?: string;
    onrun: (args: { apiKey: string }) => void;
  } = $props();

  let apiKey = $state('');
  let remember = $state(false);
  let busy = $state(false);
  let result = $state<ValidationResult | null>(null);

  async function validate() {
    if (!apiKey.trim()) { result = { ok: false, error: { kind: 'auth', message: 'Paste your API key first.' } }; return; }
    busy = true;
    const client = new UniFiClient({
      key: apiKey.trim(), host, useCloud: mode === 'cloud', verifySSL: mode === 'cloud', profile: 'home_office',
    });
    result = await validateConnection(client);
    busy = false;
  }

  async function run() {
    if (!result?.ok) return;
    if (remember) {
      const identity = identityFor(mode, host);
      await rememberKey(
        { identity, mode, host: mode === 'local' ? host.trim() : undefined, label: labelFor(mode, host, result.consoleName) },
        apiKey.trim(),
      );
    }
    onrun({ apiKey: apiKey.trim() });
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
    <label class="flex items-center gap-2 text-sm text-fg">
      <input type="checkbox" bind:checked={remember} />
      Remember this key in my keychain
    </label>
    <button onclick={run} class="bg-accent text-on-accent hover:bg-accent-hover px-6 py-3 rounded-lg font-semibold">Run Audit</button>
  {:else if result?.error}
    <div class="rounded-lg bg-sev-high-tint border border-line p-3 text-sm text-sev-high">{result.error.message}</div>
  {/if}
</div>
