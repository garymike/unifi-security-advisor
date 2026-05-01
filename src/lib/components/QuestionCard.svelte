<script lang="ts">
  import type { Finding } from '../../audit/types.js';
  import { getTieredString } from '../../wizard/tiers.js';
  import type { Tier, AnswerValue } from '../../db/schema.js';

  let {
    finding,
    tier,
    onAnswer,
  }: {
    finding: Finding;
    tier: Tier;
    onAnswer: (answer: AnswerValue, freeText: string) => void;
  } = $props();

  let freeText = $state('');
  let showNotSure = $state(false);
  let notSurePath = $state<'guided' | 'autocheck' | null>(null);

  const currentState = $derived(getTieredString(finding, 'currentState', tier) ?? '');
  const recommendation = $derived(getTieredString(finding, 'recommendation', tier));
  const question = $derived(getTieredString(finding, 'intentQuestion', tier) ?? '');

  const SEVERITY_COLORS: Record<string, string> = {
    critical: 'border-l-red-500 bg-red-50',
    high:     'border-l-orange-400 bg-orange-50',
    medium:   'border-l-yellow-400 bg-yellow-50',
    low:      'border-l-blue-300 bg-blue-50',
    info:     'border-l-gray-300 bg-gray-50',
  };
</script>

<div class="border-l-4 rounded-r-xl p-6 bg-white shadow-sm {SEVERITY_COLORS[finding.severity] ?? 'border-l-gray-300'}">
  <div class="flex items-start justify-between mb-2">
    <span class="text-xs font-semibold uppercase tracking-wide text-gray-400">{finding.section}</span>
    <span class="text-xs font-medium px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">{finding.severity}</span>
  </div>

  <h2 class="text-lg font-semibold mb-3">{finding.title}</h2>
  <p class="text-gray-600 mb-3 text-sm">{currentState}</p>

  {#if recommendation}
    <p class="text-blue-700 text-sm mb-4 bg-blue-50 rounded-lg p-3">{recommendation}</p>
  {/if}

  <p class="font-medium mb-4">{question}</p>

  <div class="flex flex-wrap gap-2 mb-4">
    {#each (['yes', 'no', 'partially', 'not_applicable'] as AnswerValue[]) as val}
      <button
        class="px-4 py-2 rounded-lg border text-sm font-medium hover:bg-blue-50 hover:border-blue-400"
        onclick={() => onAnswer(val, freeText)}
      >
        {val === 'not_applicable' ? 'Not applicable' : val.charAt(0).toUpperCase() + val.slice(1)}
      </button>
    {/each}
    <button
      class="px-4 py-2 rounded-lg border text-sm font-medium text-gray-500 hover:bg-gray-50"
      onclick={() => { showNotSure = !showNotSure; notSurePath = null; }}
    >
      Not sure
    </button>
  </div>

  {#if showNotSure}
    <div class="border rounded-lg p-4 bg-gray-50 mb-4 space-y-2">
      <p class="text-sm font-medium text-gray-700">How would you like to resolve this?</p>
      <button class="w-full text-left px-3 py-2 rounded-lg border text-sm hover:bg-white" onclick={() => notSurePath = 'guided'}>
        Show me where to find this in my controller
      </button>
      <button class="w-full text-left px-3 py-2 rounded-lg border text-sm hover:bg-white" onclick={() => onAnswer('deferred', freeText)}>
        Mark for later (flag as unresolved in report)
      </button>
      {#if notSurePath === 'guided'}
        <div class="mt-2 p-3 bg-white rounded-lg border text-sm text-gray-600">
          Check your UniFi console for: <strong>{finding.title}</strong>
          <br/><code class="bg-gray-100 px-1 rounded text-xs">{finding.id}</code>
        </div>
      {/if}
    </div>
  {/if}

  <div>
    <label for="free-text" class="text-xs text-gray-400 block mb-1">Anything to add or clarify? (optional)</label>
    <textarea
      id="free-text"
      bind:value={freeText}
      rows="2"
      class="w-full border rounded-lg px-3 py-2 text-sm resize-none"
      placeholder="Additional context…"
    ></textarea>
  </div>
</div>
