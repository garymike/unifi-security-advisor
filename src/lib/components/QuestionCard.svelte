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

  // Literal class names (Tailwind v4 needs statically-analyzable utilities, so
  // these can't be built via string interpolation like `bg-sev-${x}-tint`).
  const SEVERITY_COLORS: Record<string, string> = {
    critical: 'border-l-sev-high bg-sev-high-tint',
    high:     'border-l-sev-high bg-sev-high-tint',
    medium:   'border-l-sev-warn bg-sev-warn-tint',
    low:      'border-l-sev-info bg-sev-info-tint',
    info:     'border-l-line-strong bg-surface-2',
  };
</script>

<div class="border-l-4 rounded-r-xl p-6 bg-surface-1 shadow-sm {SEVERITY_COLORS[finding.severity] ?? 'border-l-line-strong bg-surface-2'}">
  <div class="flex items-start justify-between mb-2">
    <span class="text-xs font-semibold uppercase tracking-wide text-fg-subtle">{finding.section}</span>
    <span class="text-xs font-medium px-2 py-0.5 rounded-full bg-surface-2 text-fg-muted">{finding.severity}</span>
  </div>

  <h2 class="text-lg font-semibold mb-3 text-fg">{finding.title}</h2>
  <p class="text-fg-muted mb-3 text-sm">{currentState}</p>

  {#if recommendation}
    <p class="text-accent text-sm mb-4 bg-accent-tint rounded-lg p-3">{recommendation}</p>
  {/if}

  <p class="font-medium mb-4 text-fg">{question}</p>

  <div class="flex flex-wrap gap-2 mb-4">
    {#each (['yes', 'no', 'partially', 'not_applicable'] as AnswerValue[]) as val}
      <button
        class="px-4 py-2 rounded-lg border border-line text-sm font-medium text-fg hover:bg-surface-2 hover:border-accent"
        onclick={() => onAnswer(val, freeText)}
      >
        {val === 'not_applicable' ? 'Not applicable' : val.charAt(0).toUpperCase() + val.slice(1)}
      </button>
    {/each}
    <button
      class="px-4 py-2 rounded-lg border border-line text-sm font-medium text-fg-subtle hover:bg-surface-2"
      onclick={() => { showNotSure = !showNotSure; notSurePath = null; }}
    >
      Not sure
    </button>
  </div>

  {#if showNotSure}
    <div class="border border-line rounded-lg p-4 bg-surface-2 mb-4 space-y-2">
      <p class="text-sm font-medium text-fg-muted">How would you like to resolve this?</p>
      <button class="w-full text-left px-3 py-2 rounded-lg border border-line text-sm text-fg hover:bg-surface-1" onclick={() => notSurePath = 'guided'}>
        Show me where to find this in my controller
      </button>
      <button class="w-full text-left px-3 py-2 rounded-lg border border-line text-sm text-fg hover:bg-surface-1" onclick={() => onAnswer('deferred', freeText)}>
        Mark for later (flag as unresolved in report)
      </button>
      {#if notSurePath === 'guided'}
        <div class="mt-2 p-3 bg-surface-1 rounded-lg border border-line text-sm text-fg-muted">
          Check your UniFi console for: <strong>{finding.title}</strong>
          <br/><code class="bg-surface-2 px-1 rounded text-xs">{finding.id}</code>
        </div>
      {/if}
    </div>
  {/if}

  <div>
    <label for="free-text" class="text-xs text-fg-subtle block mb-1">Anything to add or clarify? (optional)</label>
    <textarea
      id="free-text"
      bind:value={freeText}
      rows="2"
      class="w-full border border-line bg-surface-1 text-fg rounded-lg px-3 py-2 text-sm resize-none"
      placeholder="Additional context…"
    ></textarea>
  </div>
</div>
