import type { Finding, Status, Severity } from './types.js';

export interface PostureScore {
  score: number;   // 0–100, clamped
  grade: string;   // A | B | C | D | F
  label: string;   // Strong | Good | Fair | Needs work | At risk
}

const DEDUCTIONS: Record<Status, Record<Severity, number>> = {
  gap:            { critical: 20, high: 10, medium: 5, low: 2, info: 0 },
  recommendation: { critical: 10, high: 5,  medium: 2, low: 1, info: 0 },
  unknown:        { critical: 5,  high: 3,  medium: 1, low: 0, info: 0 },
  ok:             { critical: 0,  high: 0,  medium: 0, low: 0, info: 0 },
};

export function computeScore(findings: Finding[]): PostureScore {
  let score = 100;
  for (const f of findings) {
    const base = DEDUCTIONS[f.status]?.[f.severity] ?? 0;
    score -= (f.floatTop === true) ? base * 2 : base;
  }
  score = Math.round(Math.max(0, Math.min(100, score)));
  const grade =
    score >= 90 ? 'A' :
    score >= 75 ? 'B' :
    score >= 60 ? 'C' :
    score >= 45 ? 'D' : 'F';
  const label =
    score >= 90 ? 'Strong' :
    score >= 75 ? 'Good' :
    score >= 60 ? 'Fair' :
    score >= 45 ? 'Needs work' : 'At risk';
  return { score, grade, label };
}
