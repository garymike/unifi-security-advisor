<script lang="ts">
  import { onMount } from 'svelte';
  import { updater, checkForUpdates, installNow, dismissUpdate } from '../stores/updater.js';

  let showNotes = $state(false);

  // Silent check on launch. The "Check for updates" button (in the layout
  // footer) drives manual checks via the same store.
  onMount(() => {
    void checkForUpdates(false);
  });
</script>

{#if $updater.state === 'available'}
  <div class="bg-accent-tint border-b border-line px-6 py-2 text-sm flex items-center gap-3 flex-wrap">
    <span class="text-accent">Version {$updater.version} is available.</span>
    {#if $updater.notes}
      <button class="text-accent hover:underline text-xs" onclick={() => (showNotes = !showNotes)}>
        {showNotes ? 'Hide' : "What's changed"}
      </button>
    {/if}
    <div class="ml-auto flex gap-2">
      <button class="bg-accent text-on-accent px-3 py-1 rounded font-medium hover:bg-accent-hover" onclick={installNow}>
        Update now
      </button>
      <button class="text-fg-subtle px-3 py-1 rounded border border-line hover:bg-surface-1" onclick={dismissUpdate}>
        Later
      </button>
    </div>
    {#if showNotes && $updater.notes}
      <p class="w-full text-xs text-fg-muted mt-1 whitespace-pre-line">{$updater.notes}</p>
    {/if}
  </div>
{:else if $updater.state === 'checking'}
  <div class="bg-surface-2 border-b border-line px-6 py-2 text-sm text-fg-muted">
    Checking for updates…
  </div>
{:else if $updater.state === 'uptodate'}
  <div class="bg-sev-ok-tint border-b border-line px-6 py-2 text-sm flex items-center gap-3">
    <span class="text-sev-ok">You're on the latest version.</span>
    <button class="ml-auto text-fg-subtle px-3 py-1 rounded border border-line hover:bg-surface-1" onclick={dismissUpdate}>
      Dismiss
    </button>
  </div>
{:else if $updater.state === 'downloading'}
  <div class="bg-accent-tint border-b border-line px-6 py-2 text-sm text-accent">
    Downloading update… {$updater.progress}% — the app will restart when it's ready.
  </div>
{:else if $updater.state === 'error'}
  <div class="bg-sev-high-tint border-b border-line px-6 py-2 text-sm flex items-center gap-3">
    <span class="text-sev-high">Update check failed: {$updater.error}</span>
    <button class="ml-auto text-fg-subtle px-3 py-1 rounded border border-line hover:bg-surface-1" onclick={dismissUpdate}>
      Dismiss
    </button>
  </div>
{/if}
