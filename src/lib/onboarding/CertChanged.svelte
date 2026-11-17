<script lang="ts">
  import { onMount } from 'svelte';
  import { connection, type CertificateInfo } from './keychain.js';

  // Shown after the backend refused a local controller because its
  // certificate no longer matches the pin. The page only displays the two
  // fingerprints and asks the backend to review; the backend raises a native
  // confirmation dialog and pins the certificate it observed itself.
  let { host, onrepinned }: { host: string; onrepinned: () => void } = $props();

  let info = $state<CertificateInfo | null>(null);
  let busy = $state(false);
  let note = $state('');

  onMount(async () => {
    try { info = await connection.certificate(); } catch { info = null; }
  });

  async function review() {
    busy = true; note = '';
    try {
      if (await connection.repin()) onrepinned();
      else note = 'Kept the saved certificate. The key will not be sent to this console until its certificate matches.';
    } catch (e) {
      note = e instanceof Error ? e.message : String(e);
    }
    busy = false;
  }
</script>

<div class="rounded-lg bg-sev-high-tint border border-line p-4 text-sm space-y-3">
  <p class="font-semibold text-sev-high">The console's certificate changed, so your key was not sent.</p>
  <p class="text-fg">
    The first time a key worked with {host || 'this console'}, the app saved the console's certificate
    and now only sends the key to that certificate. A different one was presented.
  </p>
  <p class="text-fg">
    This is expected after a console reset, a restore to new hardware, or a certificate change.
    If none of those happened, someone on your network may be intercepting the connection; keep
    the saved certificate and check the console first.
  </p>
  {#if info}
    <dl class="font-mono text-xs space-y-2 text-fg-muted">
      <div><dt class="text-fg-subtle">Saved (SHA-256)</dt><dd class="break-all">{info.pinned ?? 'none'}</dd></div>
      <div><dt class="text-fg-subtle">Presented now (SHA-256)</dt><dd class="break-all">{info.presented ?? 'unknown'}</dd></div>
    </dl>
  {/if}
  <button type="button" onclick={review} disabled={busy || !info?.presented}
    class="px-4 py-2 rounded-lg border border-line text-fg hover:bg-surface-2 font-medium disabled:opacity-50">
    {busy ? 'Waiting for confirmation…' : 'Review and trust the new certificate…'}
  </button>
  <p class="text-xs text-fg-subtle">You will be asked to confirm in a system dialog that shows both fingerprints.</p>
  {#if note}<p class="text-fg">{note}</p>{/if}
</div>
