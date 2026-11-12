<script lang="ts">
  import { onMount } from 'svelte';
  import ModeStep from '../../lib/onboarding/ModeStep.svelte';
  import KeyInstructions from '../../lib/onboarding/KeyInstructions.svelte';
  import ValidateStep from '../../lib/onboarding/ValidateStep.svelte';
  import SavedKeys from '../../lib/onboarding/SavedKeys.svelte';
  import { loadIndex, keychain, connection, forgetKey } from '../../lib/onboarding/keychain.js';
  import { validateConnection } from '../../lib/onboarding/validateConnection.js';
  import { UniFiClient } from '../../audit/client.js';
  import type { KeyIdentity } from '../../lib/onboarding/keyIndex.js';
  import { runAudit } from '../../lib/AuditRunner.js';
  import { goto } from '$app/navigation';
  import { get } from 'svelte/store';
  import { connectTier } from '../../lib/stores/connectTier.js';

  type Step = 'check' | 'mode' | 'getkey' | 'validate';
  let step = $state<Step>('check');
  let mode = $state<'local' | 'cloud'>('local');
  let host = $state('');

  let saved = $state<KeyIdentity[]>([]);
  let hints = $state<Record<string, string>>({});
  let orphans = $state<string[]>([]);
  let checkError = $state('');

  let running = $state(false);
  let runError = $state('');

  // Task 9: load the saved-key index once on mount. onMount (not $effect) is used
  // deliberately here — the body reads no reactive state, so an $effect would only
  // ever fire once anyway, but onMount makes the "runs once, mount-only" intent
  // explicit and avoids any dependency-tracking ambiguity.
  onMount(() => {
    void refreshSaved();
  });

  async function refreshSaved() {
    try { saved = await loadIndex(); } catch { saved = []; }
    // Last four characters only, so the user can match a saved key against
    // their Ubiquiti account. The backend never returns more than that.
    const next: Record<string, string> = {};
    for (const s of saved) {
      try { const h = await keychain.hint(s.identity); if (h) next[s.identity] = h; } catch { /* locked keychain */ }
    }
    hints = next;
  }

  async function onscan() {
    try {
      const known = new Set(saved.map(s => s.identity));
      orphans = (await keychain.scan()).filter(id => !known.has(id));
    } catch { orphans = []; }
  }

  async function onforget(identity: string) {
    await forgetKey(identity);
    await refreshSaved();
    orphans = orphans.filter(id => id !== identity);
  }

  async function onuse(entry: KeyIdentity) {
    checkError = '';
    let info;
    try {
      // The backend reads the key and binds it to the controller it was saved for.
      info = await connection.openSaved(entry.identity);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      checkError = msg.includes('could not be read') || msg.includes('address')
        ? msg
        : 'Could not read the saved key from your keychain. It may be locked, or you can Forget it and re-enter.';
      return;
    }
    const client = new UniFiClient({
      host: info.host ?? '', useCloud: info.mode === 'cloud',
      verifySSL: info.mode === 'cloud', profile: 'home_office',
    });
    const res = await validateConnection(client);
    if (!res.ok) { checkError = res.error?.message ?? 'The saved key no longer validates.'; return; }
    // Re-validated: hand straight to the run path.
    mode = info.mode; host = info.host ?? '';
    await onrun();
  }

  function toGetKey() {
    if (mode === 'local' && !host.trim()) return;
    step = 'getkey';
  }

  async function onrun() {
    running = true; runError = '';
    try {
      const { openDb, insertRun, insertFindings, insertSites } = await import('../../db/queries.js');
      const result = await runAudit(host, mode === 'cloud', () => {});
      await connection.close().catch(() => {});
      const db = await openDb();
      const runId = await insertRun(db, host || 'cloud', result.inferredProfile, result.sites.length, get(connectTier));
      await insertFindings(db, runId, result.findings);
      await insertSites(db, runId, result.sites.map(s => ({ siteId: s.siteId, siteName: s.siteName, apiGaps: s.apiGaps })));
      goto(`/wizard?runId=${runId}&profile=${result.inferredProfile}`);
    } catch (e) {
      runError = e instanceof Error ? e.message : String(e);
      running = false;
    }
  }
</script>

<main class="p-8 max-w-xl mx-auto">
  <a href="/" class="text-accent text-sm mb-6 block">← Back</a>
  <h1 class="text-2xl font-bold mb-6 text-fg">Connect to your UniFi console</h1>

  {#if step === 'check'}
    <SavedKeys {saved} {hints} {orphans} {onuse} {onforget} {onscan} onskip={() => (step = 'mode')} />
    {#if checkError}<p class="text-sev-high text-sm mt-3">{checkError}</p>{/if}
  {:else if step === 'mode'}
    <ModeStep bind:mode bind:host />
    <button class="mt-6 bg-accent text-on-accent hover:bg-accent-hover px-6 py-3 rounded-lg font-semibold disabled:opacity-50"
      onclick={toGetKey} disabled={mode === 'local' && !host.trim()}>Next</button>
  {:else if step === 'getkey'}
    <KeyInstructions {mode} {host} />
    <div class="mt-6 flex gap-3">
      <button class="px-4 py-2 rounded-lg border border-line text-fg hover:bg-surface-2" onclick={() => (step = 'mode')}>Back</button>
      <button class="bg-accent text-on-accent hover:bg-accent-hover px-6 py-2 rounded-lg font-semibold"
        onclick={() => (step = 'validate')}>I have my key →</button>
    </div>
  {:else if step === 'validate'}
    <ValidateStep {mode} {host} {onrun} />
    {#if runError}<p class="text-sev-high text-sm mt-3">{runError}</p>{/if}
    {#if running}<p class="text-fg-subtle text-sm mt-3">Running audit…</p>{/if}
    <button class="mt-4 px-4 py-2 rounded-lg border border-line text-fg hover:bg-surface-2" onclick={() => (step = 'getkey')} disabled={running}>Back</button>
  {/if}
</main>
