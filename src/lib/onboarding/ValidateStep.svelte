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
    <span class="text-sm font-medium text-gray-700">API key</span>
    <input type="password" bind:value={apiKey} placeholder="Paste your X-API-KEY here"
      class="mt-1 block w-full border rounded-lg px-3 py-2 font-mono text-sm" />
  </label>

  <button type="button" onclick={validate} disabled={busy}
    class="px-4 py-2 rounded-lg border font-medium disabled:opacity-50">
    {busy ? 'Checking…' : 'Validate'}
  </button>

  {#if result?.ok}
    <div class="rounded-lg bg-green-50 border border-green-200 p-3 text-sm text-green-800">
      ✓ Connected{result.consoleName ? ` · ${result.consoleName}` : ''}{result.networkVersion ? ` · Network ${result.networkVersion}` : ''}
      {#if result.sites?.length} · {result.sites.length} site{result.sites.length === 1 ? '' : 's'}{/if}
    </div>
    <label class="flex items-center gap-2 text-sm">
      <input type="checkbox" bind:checked={remember} />
      Remember this key in my keychain
    </label>
    <button onclick={run} class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold">Run Audit</button>
  {:else if result?.error}
    <div class="rounded-lg bg-red-50 border border-red-200 p-3 text-sm text-red-800">{result.error.message}</div>
  {/if}
</div>
