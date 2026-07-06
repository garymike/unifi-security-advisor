<script lang="ts">
  import { openUrl } from '@tauri-apps/plugin-opener';
  import { getInstructions, type ConnectMode } from './keyInstructions.js';
  import { keyPortalUrl } from './keyPortalUrl.js';
  import { connectTier } from '../stores/connectTier.js';

  let { mode, host = '' }: { mode: ConnectMode; host?: string } = $props();

  const tiers = ['guided', 'standard', 'pro'] as const;
  let block = $derived(getInstructions(mode, $connectTier));
  let portal = $derived(keyPortalUrl(mode, host));

  async function open() {
    if (portal) await openUrl(portal);
  }
</script>

<div class="space-y-4">
  <div class="flex gap-1 text-sm">
    {#each tiers as t}
      <button type="button" class="px-3 py-1 rounded border {$connectTier === t ? 'bg-gray-800 text-white' : ''}"
        onclick={() => connectTier.set(t)}>{t[0].toUpperCase() + t.slice(1)}</button>
    {/each}
  </div>

  <ol class="list-decimal ml-5 space-y-1 text-sm text-gray-700">
    {#each block.steps as step}<li>{step}</li>{/each}
  </ol>
  <p class="text-xs text-amber-700">{block.note}</p>

  <button type="button" onclick={open} disabled={!portal}
    class="px-4 py-2 rounded-lg border font-medium disabled:opacity-40">
    Open the key page
  </button>
  {#if !portal}<p class="text-xs text-gray-400">Enter the controller host first.</p>{/if}
</div>
