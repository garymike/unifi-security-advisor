<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();

  // Hide tabs during the wizard — it's a linear flow that must not be interrupted
  const showTabs = $derived(!$page.url.pathname.startsWith('/wizard'));

  const tabs = [
    { label: 'Analyze', href: '/audit' },
    { label: 'Report',  href: '/report' },
    { label: 'History', href: '/history' },
  ] as const;

  function isActive(href: string): boolean {
    const p = $page.url.pathname;
    if (href === '/audit') return p === '/audit' || p === '/';
    return p === href || p.startsWith(href + '/');
  }
</script>

{#if showTabs}
  <nav class="flex border-b border-gray-200 bg-white sticky top-0 z-10">
    {#each tabs as tab}
      <a
        href={tab.href}
        class="px-6 py-3 text-sm font-medium border-b-2 transition-colors
          {isActive(tab.href)
            ? 'border-blue-600 text-blue-700'
            : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}"
      >
        {tab.label}
      </a>
    {/each}
  </nav>
{/if}

{@render children()}
