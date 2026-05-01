<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import QuestionCard from '../../lib/components/QuestionCard.svelte';
  import { getQuestionQueue, mergeAnswer } from '../../wizard/orchestrator.js';
  import { inferProfile, profileLabel, ALL_PROFILES } from '../../wizard/profileInfer.js';
  import type { Finding } from '../../audit/types.js';
  import type { AnswerValue, Tier } from '../../db/schema.js';

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
    <h1 class="text-xl font-bold mb-2">Confirm your network profile</h1>
    <p class="text-gray-500 mb-6 text-sm">
      Based on what we found, this looks like a <strong>{profileLabel(confirmedProfile)}</strong> setup. Is that right?
    </p>
    <div class="flex gap-3 flex-wrap items-center">
      <button class="bg-blue-600 text-white px-5 py-2 rounded-lg font-medium" onclick={() => confirmProfile(confirmedProfile)}>
        Yes, that's right
      </button>
      <select class="border rounded-lg px-3 py-2 text-sm" onchange={(e) => confirmedProfile = (e.target as HTMLSelectElement).value}>
        {#each ALL_PROFILES as p}
          <option value={p} selected={p === confirmedProfile}>{profileLabel(p)}</option>
        {/each}
      </select>
      <button class="bg-gray-100 px-5 py-2 rounded-lg font-medium" onclick={() => confirmProfile(confirmedProfile)}>
        Use selected
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
