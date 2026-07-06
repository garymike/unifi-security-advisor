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
  <div class="bg-blue-50 border-b border-blue-200 px-6 py-2 text-sm flex items-center gap-3 flex-wrap">
    <span class="text-blue-800">Version {$updater.version} is available.</span>
    {#if $updater.notes}
      <button class="text-blue-600 hover:underline text-xs" onclick={() => (showNotes = !showNotes)}>
        {showNotes ? 'Hide' : "What's changed"}
      </button>
    {/if}
    <div class="ml-auto flex gap-2">
      <button class="bg-blue-600 text-white px-3 py-1 rounded font-medium hover:bg-blue-700" onclick={installNow}>
        Update now
      </button>
      <button class="text-gray-500 px-3 py-1 rounded border hover:bg-white" onclick={dismissUpdate}>
        Later
      </button>
    </div>
    {#if showNotes && $updater.notes}
      <p class="w-full text-xs text-gray-600 mt-1 whitespace-pre-line">{$updater.notes}</p>
    {/if}
  </div>
{:else if $updater.state === 'checking'}
  <div class="bg-gray-50 border-b border-gray-200 px-6 py-2 text-sm text-gray-600">
    Checking for updates…
  </div>
{:else if $updater.state === 'uptodate'}
  <div class="bg-green-50 border-b border-green-200 px-6 py-2 text-sm flex items-center gap-3">
    <span class="text-green-800">You're on the latest version.</span>
    <button class="ml-auto text-gray-500 px-3 py-1 rounded border hover:bg-white" onclick={dismissUpdate}>
      Dismiss
    </button>
  </div>
{:else if $updater.state === 'downloading'}
  <div class="bg-blue-50 border-b border-blue-200 px-6 py-2 text-sm text-blue-800">
    Downloading update… {$updater.progress}% — the app will restart when it's ready.
  </div>
{:else if $updater.state === 'error'}
  <div class="bg-red-50 border-b border-red-200 px-6 py-2 text-sm flex items-center gap-3">
    <span class="text-red-700">Update check failed: {$updater.error}</span>
    <button class="ml-auto text-gray-500 px-3 py-1 rounded border hover:bg-white" onclick={dismissUpdate}>
      Dismiss
    </button>
  </div>
{/if}
