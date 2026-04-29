import type { Finding } from '../audit/types.js';
import { SEVERITY_ORDER } from '../audit/constants.js';
import type { AnswerValue, Tier } from '../db/schema.js';

export function getQuestionQueue(findings: Finding[]): Finding[] {
  return findings
    .filter(f => f.intentQuestion !== null)
    .filter(f => f.status === 'gap' || f.status === 'recommendation')
    .sort((a, b) => {
      if (a.floatTop && !b.floatTop) return -1;
      if (!a.floatTop && b.floatTop) return 1;
      return (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
    });
}

export function mergeAnswer(finding: Finding, answer: AnswerValue, freeText: string): Finding {
  const updated = { ...finding, evidence: { ...finding.evidence } };
  if (freeText.trim()) {
    (updated.evidence as Record<string, unknown>)['userNote'] = freeText.trim();
  }
  switch (answer) {
    case 'yes':
    case 'not_applicable':
      updated.status = 'ok';
      break;
    case 'deferred':
      updated.status = 'unknown';
      break;
    // 'no' and 'partially' leave status as-is
  }
  return updated;
}

// Re-export Tier so callers can import from orchestrator if needed
export type { Tier };
