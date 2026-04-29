<script lang="ts">
  import type { Finding } from '../../audit/types.js';

  let { finding }: { finding: Finding } = $props();

  const COLORS: Record<string, string> = {
    critical: 'border-l-red-500 bg-red-50',
    high:     'border-l-orange-400 bg-orange-50',
    medium:   'border-l-yellow-400 bg-yellow-50',
    low:      'border-l-blue-300 bg-blue-50',
    info:     'border-l-gray-300 bg-gray-50',
  };
</script>

<div class="border-l-4 rounded-r-lg p-4 {COLORS[finding.severity] ?? 'border-l-gray-300'}">
  <div class="flex items-start justify-between mb-1">
    <span class="font-semibold text-sm">{finding.title}</span>
    <span class="text-xs font-medium uppercase tracking-wide ml-2 shrink-0 {finding.status === 'ok' ? 'text-green-600' : 'text-gray-500'}">
      {finding.status}
    </span>
  </div>
  <p class="text-xs text-gray-500 mb-2">{finding.section} · {finding.id} · {finding.effort} effort</p>
  <p class="text-sm text-gray-700">{finding.currentState}</p>
  {#if finding.recommendation && finding.status !== 'ok'}
    <p class="text-sm text-blue-700 mt-2">→ {finding.recommendation}</p>
  {/if}
  {#if finding.intentQuestion && finding.status !== 'ok'}
    <p class="text-xs text-gray-400 mt-2 italic">{finding.intentQuestion}</p>
  {/if}
</div>
