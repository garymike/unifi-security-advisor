<script lang="ts">
  let { mode = $bindable('local'), host = $bindable('') }: {
    mode: 'local' | 'cloud'; host: string;
  } = $props();
</script>

<div class="space-y-4">
  <p class="text-sm text-fg-muted">How do you want to connect?</p>
  <div class="flex gap-2">
    <button type="button" class="px-4 py-2 rounded-lg border {mode === 'local' ? 'bg-accent text-on-accent border-accent' : 'border-line text-fg'}"
      onclick={() => (mode = 'local')}>Local (Network Integration)</button>
    <button type="button" class="px-4 py-2 rounded-lg border {mode === 'cloud' ? 'bg-accent text-on-accent border-accent' : 'border-line text-fg'}"
      onclick={() => (mode = 'cloud')}>Cloud (Site Manager)</button>
  </div>
  <p class="text-xs text-fg-subtle">
    Choose Cloud when the console is behind CGNAT, has a dynamic WAN IP, or you manage multiple sites.
  </p>
  {#if mode === 'local'}
    <label class="block">
      <span class="text-sm font-medium text-fg-muted">Controller host</span>
      <input type="text" bind:value={host} placeholder="192.168.1.1"
        class="mt-1 block w-full bg-surface-1 border border-line focus:border-accent rounded-lg px-3 py-2 text-fg placeholder:text-fg-subtle" />
    </label>
  {/if}
</div>
