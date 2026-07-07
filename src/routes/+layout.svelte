<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import type { Snippet } from 'svelte';
  import UpdateBanner from '../lib/components/UpdateBanner.svelte';
  import { checkForUpdates } from '../lib/stores/updater.js';

  let { children }: { children: Snippet } = $props();

  // Hide tabs during the wizard — it's a linear flow that must not be interrupted
  const showTabs = $derived(!$page.url.pathname.startsWith('/wizard'));

  // App version for the footer; only resolvable inside the Tauri runtime.
  let appVersion = $state('');
  onMount(async () => {
    try {
      const { getVersion } = await import('@tauri-apps/api/app');
      appVersion = await getVersion();
    } catch {
      // Not in a Tauri context (dev preview / static build) — leave blank.
    }
  });

  const tabs = [
    { label: 'Home',    href: '/' },
    { label: 'Analyze', href: '/audit' },
    { label: 'Backup',  href: '/backup' },
    { label: 'Report',  href: '/report' },
    { label: 'History', href: '/history' },
  ] as const;

  function isActive(href: string): boolean {
    const p = $page.url.pathname;
    if (href === '/') return p === '/';
    return p === href || p.startsWith(href + '/');
  }
</script>

<UpdateBanner />

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

{#if showTabs}
  <footer class="flex items-center gap-3 px-6 py-3 mt-4 border-t border-gray-100 text-xs text-gray-400">
    {#if appVersion}<span>v{appVersion}</span>{/if}
    <button class="text-blue-600 hover:underline" onclick={() => checkForUpdates(true)}>
      Check for updates
    </button>
  </footer>
{/if}
