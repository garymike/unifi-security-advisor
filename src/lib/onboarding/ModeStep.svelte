<script lang="ts">
  let { mode = $bindable('local'), host = $bindable('') }: {
    mode: 'local' | 'cloud'; host: string;
  } = $props();
</script>

<div class="space-y-4">
  <p class="text-sm text-gray-600">How do you want to connect?</p>
  <div class="flex gap-2">
    <button type="button" class="px-4 py-2 rounded-lg border {mode === 'local' ? 'bg-blue-600 text-white' : ''}"
      onclick={() => (mode = 'local')}>Local (Network Integration)</button>
    <button type="button" class="px-4 py-2 rounded-lg border {mode === 'cloud' ? 'bg-blue-600 text-white' : ''}"
      onclick={() => (mode = 'cloud')}>Cloud (Site Manager)</button>
  </div>
  <p class="text-xs text-gray-500">
    Choose Cloud when the console is behind CGNAT, has a dynamic WAN IP, or you manage multiple sites.
  </p>
  {#if mode === 'local'}
    <label class="block">
      <span class="text-sm font-medium text-gray-700">Controller host</span>
      <input type="text" bind:value={host} placeholder="192.168.1.1"
        class="mt-1 block w-full border rounded-lg px-3 py-2" />
    </label>
  {/if}
</div>
