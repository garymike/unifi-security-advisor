import { writable } from 'svelte/store';

// The updater/process plugins only work inside the Tauri runtime; in a plain
// browser (dev preview, static build) we stay silent for the auto-check and
// report "up to date" for an explicit manual check.
const IS_TAURI = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

export type UpdaterState =
  | 'idle'         // nothing to show
  | 'checking'     // a manual check is in flight
  | 'available'    // a newer version is ready to install
  | 'uptodate'     // a manual check found nothing newer (transient confirmation)
  | 'downloading'  // installing the update
  | 'error';       // a manual check or install failed

export interface UpdaterStore {
  state: UpdaterState;
  version: string;
  notes: string;
  progress: number;
  error: string;
}

interface DownloadEvent {
  event: 'Started' | 'Progress' | 'Finished';
  data?: { contentLength?: number; chunkLength?: number };
}

// The Update handle from plugin-updater, kept loosely typed to avoid pulling
// plugin types through the dynamic import.
type UpdateHandle = {
  version: string;
  body?: string;
  downloadAndInstall: (cb: (e: DownloadEvent) => void) => Promise<void>;
};

let handle: UpdateHandle | null = null;

const initial: UpdaterStore = { state: 'idle', version: '', notes: '', progress: 0, error: '' };
export const updater = writable<UpdaterStore>(initial);

/**
 * Check GitHub Releases for a newer signed version.
 * `manual` distinguishes an explicit "Check for updates" click (which surfaces
 * "up to date" and error feedback) from the silent on-launch check (which stays
 * quiet when there's nothing to install or the endpoint is unreachable).
 */
export async function checkForUpdates(manual = false): Promise<void> {
  if (!IS_TAURI) {
    if (manual) updater.set({ ...initial, state: 'uptodate' });
    return;
  }
  if (manual) updater.set({ ...initial, state: 'checking' });
  try {
    const { check } = await import('@tauri-apps/plugin-updater');
    const found = (await check()) as UpdateHandle | null;
    if (found) {
      handle = found;
      updater.set({ state: 'available', version: found.version, notes: found.body ?? '', progress: 0, error: '' });
    } else {
      handle = null;
      updater.set({ ...initial, state: manual ? 'uptodate' : 'idle' });
    }
  } catch (e) {
    handle = null;
    // Silent for the on-launch check (offline etc.); surfaced only for a manual check.
    if (manual) updater.set({ ...initial, state: 'error', error: e instanceof Error ? e.message : String(e) });
  }
}

/** Download and install the pending update, then relaunch. */
export async function installNow(): Promise<void> {
  if (!handle) return;
  updater.update((s) => ({ ...s, state: 'downloading', progress: 0, error: '' }));
  try {
    let downloaded = 0;
    let total = 0;
    await handle.downloadAndInstall((e: DownloadEvent) => {
      if (e.event === 'Started') total = e.data?.contentLength ?? 0;
      else if (e.event === 'Progress') {
        downloaded += e.data?.chunkLength ?? 0;
        updater.update((s) => ({ ...s, progress: total ? Math.round((downloaded / total) * 100) : 0 }));
      }
    });
    const { relaunch } = await import('@tauri-apps/plugin-process');
    await relaunch();
  } catch (e) {
    updater.update((s) => ({ ...s, state: 'error', error: e instanceof Error ? e.message : String(e) }));
  }
}

/** Dismiss the banner (returns to idle). */
export function dismissUpdate(): void {
  updater.update((s) => ({ ...s, state: 'idle' }));
}
