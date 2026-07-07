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
    <p class="text-sm text-fg-muted">Saved keys found on this machine:</p>
    <ul class="space-y-2">
      {#each saved as e}
        <li class="flex items-center justify-between bg-surface-1 border border-line rounded-lg px-3 py-2">
          <span class="text-sm text-fg">{e.label}</span>
          <span class="flex gap-2">
            <button class="text-accent text-sm" onclick={() => onuse(e)}>Use</button>
            <button class="text-sev-high text-sm" onclick={() => onforget(e.identity)}>Forget</button>
          </span>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="text-sm text-fg-muted">No saved keys.</p>
  {/if}

  {#if orphans.length}
    <p class="text-sm text-fg-muted">Other keys under this app (from a previous install):</p>
    <ul class="space-y-2">
      {#each orphans as id}
        <li class="flex items-center justify-between bg-surface-1 border border-line rounded-lg px-3 py-2">
          <span class="text-sm font-mono text-fg">{id}</span>
          <button class="text-sev-high text-sm" onclick={() => onforget(id)}>Forget</button>
        </li>
      {/each}
    </ul>
  {/if}

  <div class="flex gap-3">
    <button class="px-4 py-2 rounded-lg border border-line text-fg hover:bg-surface-2 text-sm" onclick={onscan}>Scan for leftover keys</button>
    <button class="bg-accent text-on-accent hover:bg-accent-hover px-4 py-2 rounded-lg text-sm font-semibold" onclick={onskip}>
      {saved.length ? 'Add another key' : 'Get started'}
    </button>
  </div>
</div>
