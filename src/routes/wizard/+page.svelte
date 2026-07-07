<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import QuestionCard from '../../lib/components/QuestionCard.svelte';
  import { getQuestionQueue, mergeAnswer } from '../../wizard/orchestrator.js';
  import { inferProfile, profileLabel, ALL_PROFILES } from '../../wizard/profileInfer.js';
  import type { Finding } from '../../audit/types.js';
  import type { AnswerValue, Tier } from '../../db/schema.js';
  import { computeScore } from '../../audit/score.js';

  const runId = $derived($page.url.searchParams.get('runId') ?? '');

  type Step = 'profile' | 'skills' | 'questions' | 'done';
  let step: Step = $state('profile');
  // Read profile directly from URL — avoids $derived-in-$state initializer warning
  let confirmedProfile = $state($page.url.searchParams.get('profile') ?? 'home_office');
  let tier: Tier = $state('standard');
  let findings: Finding[] = $state([]);
  let queue: Finding[] = $state([]);
  let queueIndex = $state(0);

  const SKILLS_TIERS: Record<string, Tier> = { yes: 'pro', heard: 'standard', no: 'guided' };

  // Literal class maps — Tailwind v4's static scanner can't see interpolated
  // class names like `bg-sev-${x}-tint`, so runtime-selected colors must be
  // full literal strings (mirrors src/routes/report/+page.svelte).
  const GRADE_BADGE: Record<'ok' | 'warn' | 'high', string> = {
    ok: 'bg-sev-ok-tint text-sev-ok',
    warn: 'bg-sev-warn-tint text-sev-warn',
    high: 'bg-sev-high-tint text-sev-high',
  };
  function gradeSev(grade: string): 'ok' | 'warn' | 'high' {
    const letter = grade[0];
    if (letter === 'A' || letter === 'B') return 'ok';
    if (letter === 'C') return 'warn';
    return 'high';
  }
  const SEVERITY_TEXT: Record<string, string> = {
    critical: 'text-sev-high',
    high: 'text-sev-high',
    medium: 'text-sev-warn',
    low: 'text-sev-warn',
    info: 'text-fg-subtle',
  };
  const currentFinding = $derived(queue[queueIndex] ?? null);
  const progress = $derived(queue.length ? Math.round((queueIndex / queue.length) * 100) : 0);
  const postureScore  = $derived(findings.length > 0 ? computeScore(findings) : null);
  const issueCount    = $derived(findings.filter(f => f.status === 'gap' || f.status === 'recommendation').length);
  const unknownCount  = $derived(findings.filter(f => f.status === 'unknown').length);
  const goodCount     = $derived(findings.filter(f => f.status === 'ok').length);
  const topIssues     = $derived(
    findings.filter(f => f.status === 'gap' || f.status === 'recommendation').slice(0, 3)
  );

  onMount(async () => {
    const { openDb, getFindings, listRuns } = await import('../../db/queries.js');
    const db = await openDb();
    const runs = await listRuns(db);
    const run = runs.find(r => r.id === runId);
    if (run?.tier) tier = run.tier; // guard null tier (legacy rows) — keep the 'standard' default
    findings = await getFindings(db, runId);
    queue = getQuestionQueue(findings);
  });

  async function confirmProfile(p: string) {
    confirmedProfile = p;
    step = 'skills';
  }

  async function confirmTier(answer: string) {
    tier = SKILLS_TIERS[answer] ?? 'standard';
    const { openDb, updateRunTier } = await import('../../db/queries.js');
    await updateRunTier(await openDb(), runId, tier);
    step = 'questions';
  }

  async function handleAnswer(answer: AnswerValue, freeText: string) {
    if (!currentFinding) return;
    const { openDb, upsertAnswer } = await import('../../db/queries.js');
    await upsertAnswer(await openDb(), runId, currentFinding.id, answer, freeText, tier);
    findings = findings.map(f => f.id === currentFinding.id ? mergeAnswer(f, answer, freeText) : f);
    if (queueIndex + 1 < queue.length) { queueIndex++; } else { step = 'done'; }
  }
</script>

<main class="p-8 max-w-2xl mx-auto bg-surface-0 min-h-screen">

  {#if step === 'profile'}
    <h1 class="text-xl font-bold mb-4 text-fg">What we found on your network</h1>

    {#if postureScore && findings.length > 0}
      <!-- Score hero -->
      <div class="text-center mb-6">
        <div class="inline-flex flex-col items-center px-8 py-4 rounded-2xl {GRADE_BADGE[gradeSev(postureScore.grade)]}">
          <span class="text-4xl font-black leading-none">{postureScore.score} / {postureScore.grade}</span>
          <span class="text-sm mt-1">{postureScore.label}</span>
        </div>
      </div>

      <!-- Bucket bar -->
      <div class="flex h-2 rounded-full overflow-hidden mb-2 bg-surface-2">
        <div class="bg-sev-high" style="flex:{issueCount}"></div>
        <div class="bg-sev-info" style="flex:{unknownCount}"></div>
        <div class="bg-sev-ok" style="flex:{goodCount}"></div>
      </div>
      <div class="flex justify-between text-xs mb-6">
        <span class="text-sev-high font-medium">Issues ({issueCount})</span>
        <span class="text-fg-subtle">Unknown ({unknownCount})</span>
        <span class="text-sev-ok font-medium">Good ({goodCount})</span>
      </div>

      <!-- Top findings preview -->
      {#if topIssues.length > 0}
        <div class="mb-6">
          <p class="text-xs font-semibold text-fg-subtle uppercase tracking-wide mb-2">
            Top findings from your controller
          </p>
          <div class="space-y-2">
            {#each topIssues as f (f.id)}
              <div class="flex items-start gap-2 text-sm">
                <span class="{SEVERITY_TEXT[f.severity] ?? 'text-fg-subtle'} mt-0.5 shrink-0">●</span>
                <span class="text-fg">
                  <span class="font-medium text-xs text-fg-subtle uppercase">[{f.severity}]</span>
                  {f.title}
                </span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <hr class="mb-6 border-line" />
    {/if}

    <!-- Profile confirmation (always shown) -->
    <p class="text-sm text-fg-muted mb-3">
      We think this is a <strong>{profileLabel(confirmedProfile)}</strong> setup. Confirm or change:
    </p>
    <div class="mb-6">
      <select
        class="border border-line-strong bg-surface-1 text-fg rounded-lg px-3 py-2 text-sm"
        onchange={(e) => confirmedProfile = (e.target as HTMLSelectElement).value}
      >
        {#each ALL_PROFILES as p}
          <option value={p} selected={p === confirmedProfile}>{profileLabel(p)}</option>
        {/each}
      </select>
    </div>
    <div class="flex gap-3 flex-wrap">
      <button
        class="bg-accent text-on-accent px-5 py-2 rounded-lg font-medium hover:bg-accent-hover"
        onclick={() => confirmProfile(confirmedProfile)}
      >
        Yes, continue →
      </button>
      <button
        class="text-fg-subtle px-5 py-2 rounded-lg border border-line hover:bg-surface-2"
        onclick={() => goto(`/report?runId=${runId}`)}
      >
        Skip to report
      </button>
    </div>

  {:else if step === 'skills'}
    <h1 class="text-xl font-bold mb-2 text-fg">One quick question</h1>
    <p class="text-fg-muted mb-6">Do you know what a VLAN is?</p>
    <div class="space-y-2">
      <button class="w-full text-left border border-line rounded-lg px-4 py-3 text-fg hover:bg-surface-2" onclick={() => confirmTier('yes')}>Yes — I use them regularly</button>
      <button class="w-full text-left border border-line rounded-lg px-4 py-3 text-fg hover:bg-surface-2" onclick={() => confirmTier('heard')}>I've heard of them / roughly know</button>
      <button class="w-full text-left border border-line rounded-lg px-4 py-3 text-fg hover:bg-surface-2" onclick={() => confirmTier('no')}>Not sure / first time hearing it</button>
    </div>
    <p class="text-xs text-fg-subtle mt-4">This helps explain findings at the right level. You can change it any time.</p>

  {:else if step === 'questions' && !currentFinding}
    <!-- All questions exhausted but step wasn't updated — show done -->
    <div class="text-center py-12">
      <div class="text-4xl mb-4 text-sev-ok">✓</div>
      <h1 class="text-xl font-bold mb-2 text-fg">All questions answered</h1>
      <p class="text-fg-subtle mb-6">Your personalized report is ready.</p>
      <button class="bg-accent text-on-accent px-6 py-3 rounded-lg font-semibold hover:bg-accent-hover" onclick={() => goto(`/report?runId=${runId}`)}>
        View Report
      </button>
    </div>

  {:else if step === 'questions' && currentFinding}
    <div class="mb-4">
      <div class="flex justify-between text-xs text-fg-subtle mb-1">
        <span>Question {queueIndex + 1} of {queue.length}</span>
        <span>{progress}% complete</span>
      </div>
      <div class="h-1.5 bg-surface-2 rounded-full">
        <div class="h-1.5 bg-accent rounded-full transition-all" style="width: {progress}%"></div>
      </div>
    </div>
    <QuestionCard finding={currentFinding} {tier} onAnswer={handleAnswer} />

  {:else if step === 'done'}
    <div class="text-center py-12">
      <div class="text-4xl mb-4 text-sev-ok">✓</div>
      <h1 class="text-xl font-bold mb-2 text-fg">All questions answered</h1>
      <p class="text-fg-subtle mb-6">Your personalized report is ready.</p>
      <button class="bg-accent text-on-accent px-6 py-3 rounded-lg font-semibold hover:bg-accent-hover" onclick={() => goto(`/report?runId=${runId}`)}>
        View Report
      </button>
    </div>
  {/if}

</main>
