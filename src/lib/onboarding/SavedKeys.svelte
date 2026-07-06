<script lang="ts">
  import type { KeyIdentity } from './keyIndex.js';
  let { saved, orphans, onuse, onforget, onscan, onskip }: {
    saved: KeyIdentity[]; orphans: string[];
    onuse: (e: KeyIdentity) => void; onforget: (identity: string) => void;
    onscan: () => void; onskip: () => void;
  } = $props();
</script>

<div class="space-y-4">
  {#if saved.length}
    <p class="text-sm text-gray-600">Saved keys found on this machine:</p>
    <ul class="space-y-2">
      {#each saved as e}
        <li class="flex items-center justify-between border rounded-lg px-3 py-2">
          <span class="text-sm">{e.label}</span>
          <span class="flex gap-2">
            <button class="text-blue-600 text-sm" onclick={() => onuse(e)}>Use</button>
            <button class="text-red-600 text-sm" onclick={() => onforget(e.identity)}>Forget</button>
          </span>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="text-sm text-gray-600">No saved keys.</p>
  {/if}

  {#if orphans.length}
    <p class="text-sm text-gray-600">Other keys under this app (from a previous install):</p>
    <ul class="space-y-2">
      {#each orphans as id}
        <li class="flex items-center justify-between border rounded-lg px-3 py-2">
          <span class="text-sm font-mono">{id}</span>
          <button class="text-red-600 text-sm" onclick={() => onforget(id)}>Forget</button>
        </li>
      {/each}
    </ul>
  {/if}

  <div class="flex gap-3">
    <button class="px-4 py-2 rounded-lg border text-sm" onclick={onscan}>Scan for leftover keys</button>
    <button class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-semibold" onclick={onskip}>
      {saved.length ? 'Add another key' : 'Get started'}
    </button>
  </div>
</div>
