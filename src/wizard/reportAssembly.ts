import type { Finding } from '../audit/types.js';
import type { AnswerValue } from '../db/schema.js';
import { mergeAnswer } from './orchestrator.js';
import { detectTensions } from '../audit/tensions.js';
import { sortFindings } from '../audit/analyze.js';

export interface StoredAnswer {
  findingId: string;
  answer: AnswerValue;
  freeText: string;
}

/**
 * A finding id belongs to a site if it ends with `-<siteId>` (most modules) or
 * contains `-<siteId>-` as an infix (e.g. `WIFI-<siteId>-<ssid>-PSK`). Meta
 * findings (`META-COVERAGE`, `API-VERSION`) match no site, as intended.
 */
export function belongsToSite(findingId: string, siteId: string): boolean {
  return findingId.endsWith(`-${siteId}`) || findingId.includes(`-${siteId}-`);
}

/**
 * Rebuilds the finding set for the report after the wizard: applies each stored
 * intent answer (via mergeAnswer) and recomputes cross-answer tensions on the
 * answered results, so compound findings reflect the user's answers. The
 * config-time tension findings are dropped and recomputed. Answers that clear a
 * contributor (status → ok) therefore dissolve the compound; a "no" that leaves
 * it as a gap keeps it.
 */
export function applyAnswersAndTensions(
  findings: Finding[],
  answers: StoredAnswer[],
  siteIds: string[],
): Finding[] {
  const byId = new Map(answers.map(a => [a.findingId, a]));

  const base = findings
    .filter(f => !f.id.startsWith('TENSION-'))
    .map(f => {
      const a = byId.get(f.id);
      return a ? mergeAnswer(f, a.answer, a.freeText) : f;
    });

  const tensions: Finding[] = [];
  if (siteIds.length <= 1) {
    // Single-site (the common desktop case): every finding is one site's.
    tensions.push(...detectTensions(base, siteIds[0] ?? 'default'));
  } else {
    for (const siteId of siteIds) {
      tensions.push(...detectTensions(base.filter(f => belongsToSite(f.id, siteId)), siteId));
    }
  }

  return sortFindings([...base, ...tensions]);
}
