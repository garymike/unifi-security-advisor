<script lang="ts">
  import ModeStep from '../../lib/onboarding/ModeStep.svelte';
  import KeyInstructions from '../../lib/onboarding/KeyInstructions.svelte';

  type Step = 'check' | 'mode' | 'getkey' | 'validate';
  let step = $state<Step>('mode'); // Task 9 sets initial 'check'
  let mode = $state<'local' | 'cloud'>('local');
  let host = $state('');

  function toGetKey() {
    if (mode === 'local' && !host.trim()) return;
    step = 'getkey';
  }
</script>

<main class="p-8 max-w-xl mx-auto">
  <a href="/" class="text-blue-600 text-sm mb-6 block">← Back</a>
  <h1 class="text-2xl font-bold mb-6">Connect to your UniFi console</h1>

  {#if step === 'mode'}
    <ModeStep bind:mode bind:host />
    <button class="mt-6 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold disabled:opacity-50"
      onclick={toGetKey} disabled={mode === 'local' && !host.trim()}>Next</button>
  {:else if step === 'getkey'}
    <KeyInstructions {mode} {host} />
    <div class="mt-6 flex gap-3">
      <button class="px-4 py-2 rounded-lg border" onclick={() => (step = 'mode')}>Back</button>
      <button class="bg-blue-600 text-white px-6 py-2 rounded-lg font-semibold"
        onclick={() => (step = 'validate')}>I have my key →</button>
    </div>
  {:else if step === 'validate'}
    <p class="text-gray-500">Validation step — added in Task 8.</p>
    <button class="mt-4 px-4 py-2 rounded-lg border" onclick={() => (step = 'getkey')}>Back</button>
  {/if}
</main>
