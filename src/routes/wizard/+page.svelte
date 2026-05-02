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
    const { openDb, getFindings } = await import('../../db/queries.js');
    const db = await openDb();
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

<main class="p-8 max-w-2xl mx-auto">

  {#if step === 'profile'}
    <h1 class="text-xl font-bold mb-4">What we found on your network</h1>

    {#if postureScore && findings.length > 0}
      <!-- Score hero -->
      <div class="text-center mb-6">
        <div class="inline-flex flex-col items-center bg-blue-700 text-white px-8 py-4 rounded-2xl shadow">
          <span class="text-4xl font-black leading-none">{postureScore.score} / {postureScore.grade}</span>
          <span class="text-sm opacity-80 mt-1">{postureScore.label}</span>
        </div>
      </div>

      <!-- Bucket bar -->
      <div class="flex h-2 rounded-full overflow-hidden mb-2">
        <div class="bg-red-500" style="flex:{issueCount}"></div>
        <div class="bg-gray-300" style="flex:{unknownCount}"></div>
        <div class="bg-green-500" style="flex:{goodCount}"></div>
      </div>
      <div class="flex justify-between text-xs mb-6">
        <span class="text-red-600 font-medium">Issues ({issueCount})</span>
        <span class="text-gray-400">Unknown ({unknownCount})</span>
        <span class="text-green-600 font-medium">Good ({goodCount})</span>
      </div>

      <!-- Top findings preview -->
      {#if topIssues.length > 0}
        <div class="mb-6">
          <p class="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
            Top findings from your controller
          </p>
          <div class="space-y-2">
            {#each topIssues as f (f.id)}
              <div class="flex items-start gap-2 text-sm">
                <span class="text-red-500 mt-0.5 shrink-0">●</span>
                <span>
                  <span class="font-medium text-xs text-gray-400 uppercase">[{f.severity}]</span>
                  {f.title}
                </span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <hr class="mb-6" />
    {/if}

    <!-- Profile confirmation (always shown) -->
    <p class="text-sm text-gray-600 mb-3">
      We think this is a <strong>{profileLabel(confirmedProfile)}</strong> setup. Confirm or change:
    </p>
    <div class="mb-6">
      <select
        class="border rounded-lg px-3 py-2 text-sm"
        onchange={(e) => confirmedProfile = (e.target as HTMLSelectElement).value}
      >
        {#each ALL_PROFILES as p}
          <option value={p} selected={p === confirmedProfile}>{profileLabel(p)}</option>
        {/each}
      </select>
    </div>
    <div class="flex gap-3 flex-wrap">
      <button
        class="bg-blue-600 text-white px-5 py-2 rounded-lg font-medium hover:bg-blue-700"
        onclick={() => confirmProfile(confirmedProfile)}
      >
        Yes, continue →
      </button>
      <button
        class="text-gray-500 px-5 py-2 rounded-lg border hover:bg-gray-50"
        onclick={() => goto(`/report?runId=${runId}`)}
      >
        Skip to report
      </button>
    </div>

  {:else if step === 'skills'}
    <h1 class="text-xl font-bold mb-2">One quick question</h1>
    <p class="text-gray-600 mb-6">Do you know what a VLAN is?</p>
    <div class="space-y-2">
      <button class="w-full text-left border rounded-lg px-4 py-3 hover:bg-blue-50" onclick={() => confirmTier('yes')}>Yes — I use them regularly</button>
      <button class="w-full text-left border rounded-lg px-4 py-3 hover:bg-blue-50" onclick={() => confirmTier('heard')}>I've heard of them / roughly know</button>
      <button class="w-full text-left border rounded-lg px-4 py-3 hover:bg-blue-50" onclick={() => confirmTier('no')}>Not sure / first time hearing it</button>
    </div>
    <p class="text-xs text-gray-400 mt-4">This helps explain findings at the right level. You can change it any time.</p>

  {:else if step === 'questions' && !currentFinding}
    <!-- All questions exhausted but step wasn't updated — show done -->
    <div class="text-center py-12">
      <div class="text-4xl mb-4">✓</div>
      <h1 class="text-xl font-bold mb-2">All questions answered</h1>
      <p class="text-gray-500 mb-6">Your personalized report is ready.</p>
      <button class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold" onclick={() => goto(`/report?runId=${runId}`)}>
        View Report
      </button>
    </div>

  {:else if step === 'questions' && currentFinding}
    <div class="mb-4">
      <div class="flex justify-between text-xs text-gray-400 mb-1">
        <span>Question {queueIndex + 1} of {queue.length}</span>
        <span>{progress}% complete</span>
      </div>
      <div class="h-1.5 bg-gray-100 rounded-full">
        <div class="h-1.5 bg-blue-500 rounded-full transition-all" style="width: {progress}%"></div>
      </div>
    </div>
    <QuestionCard finding={currentFinding} {tier} onAnswer={handleAnswer} />

  {:else if step === 'done'}
    <div class="text-center py-12">
      <div class="text-4xl mb-4">✓</div>
      <h1 class="text-xl font-bold mb-2">All questions answered</h1>
      <p class="text-gray-500 mb-6">Your personalized report is ready.</p>
      <button class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold" onclick={() => goto(`/report?runId=${runId}`)}>
        View Report
      </button>
    </div>
  {/if}

</main>
