<script lang="ts">
  import { onMount } from 'svelte';

  // The updater/process plugins only work inside the Tauri runtime; in a plain
  // browser (dev preview, static build) we stay silent.
  const IS_TAURI = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

  type State = 'hidden' | 'available' | 'downloading' | 'error';
  let state = $state<State>('hidden');
  let version = $state('');
  let notes = $state('');
  let showNotes = $state(false);
  let progress = $state(0);
  let errorMsg = $state('');
  // The Update handle from plugin-updater (kept loosely typed to avoid pulling
  // plugin types through the dynamic import).
  let update: { version: string; body?: string; downloadAndInstall: (cb: (e: DownloadEvent) => void) => Promise<void> } | null = null;

  interface DownloadEvent {
    event: 'Started' | 'Progress' | 'Finished';
    data?: { contentLength?: number; chunkLength?: number };
  }

  onMount(async () => {
    if (!IS_TAURI) return;
    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const found = await check();
      if (found) {
        update = found;
        version = found.version;
        notes = found.body ?? '';
        state = 'available';
      }
    } catch {
      // Offline, or the update endpoint is unreachable — no nag.
    }
  });

  async function installNow(): Promise<void> {
    if (!update) return;
    state = 'downloading';
    progress = 0;
    try {
      let downloaded = 0;
      let total = 0;
      await update.downloadAndInstall((e: DownloadEvent) => {
        if (e.event === 'Started') total = e.data?.contentLength ?? 0;
        else if (e.event === 'Progress') {
          downloaded += e.data?.chunkLength ?? 0;
          progress = total ? Math.round((downloaded / total) * 100) : 0;
        }
      });
      const { relaunch } = await import('@tauri-apps/plugin-process');
      await relaunch();
    } catch (e) {
      errorMsg = e instanceof Error ? e.message : String(e);
      state = 'error';
    }
  }
</script>

{#if state === 'available'}
  <div class="bg-blue-50 border-b border-blue-200 px-6 py-2 text-sm flex items-center gap-3 flex-wrap">
    <span class="text-blue-800">Version {version} is available.</span>
    {#if notes}
      <button class="text-blue-600 hover:underline text-xs" onclick={() => (showNotes = !showNotes)}>
        {showNotes ? 'Hide' : "What's changed"}
      </button>
    {/if}
    <div class="ml-auto flex gap-2">
      <button class="bg-blue-600 text-white px-3 py-1 rounded font-medium hover:bg-blue-700" onclick={installNow}>
        Update now
      </button>
      <button class="text-gray-500 px-3 py-1 rounded border hover:bg-white" onclick={() => (state = 'hidden')}>
        Later
      </button>
    </div>
    {#if showNotes && notes}
      <p class="w-full text-xs text-gray-600 mt-1 whitespace-pre-line">{notes}</p>
    {/if}
  </div>
{:else if state === 'downloading'}
  <div class="bg-blue-50 border-b border-blue-200 px-6 py-2 text-sm text-blue-800">
    Downloading update… {progress}% — the app will restart when it's ready.
  </div>
{:else if state === 'error'}
  <div class="bg-red-50 border-b border-red-200 px-6 py-2 text-sm flex items-center gap-3">
    <span class="text-red-700">Update failed: {errorMsg}</span>
    <button class="ml-auto text-gray-500 px-3 py-1 rounded border hover:bg-white" onclick={() => (state = 'hidden')}>
      Dismiss
    </button>
  </div>
{/if}
