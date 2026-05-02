import type { Finding } from './types.js';
import { computeScore } from './score.js';
import { sortFindings } from './analyze.js';

export interface ChangedFinding {
  before: Finding;
  after: Finding;
}

export interface DiffResult {
  added: Finding[];
  removed: Finding[];
  changed: ChangedFinding[];
  scoreDelta: number;
}

export function diffRuns(findingsA: Finding[], findingsB: Finding[]): DiffResult {
  const mapA = new Map(findingsA.map(f => [f.id, f]));
  const mapB = new Map(findingsB.map(f => [f.id, f]));

  const added: Finding[] = [];
  const removed: Finding[] = [];
  const changed: ChangedFinding[] = [];

  for (const [id, fb] of mapB) {
    if (!mapA.has(id)) added.push(fb);
  }

  for (const [id, fa] of mapA) {
    if (!mapB.has(id)) {
      removed.push(fa);
    } else {
      const fb = mapB.get(id)!;
      if (fa.severity !== fb.severity || fa.status !== fb.status) {
        changed.push({ before: fa, after: fb });
      }
    }
  }

  return {
    added: sortFindings(added),
    removed: sortFindings(removed),
    changed: sortFindings(changed.map(c => c.after)).map(after => ({
      before: changed.find(c => c.after.id === after.id)!.before,
      after,
    })),
    scoreDelta: computeScore(findingsB).score - computeScore(findingsA).score,
  };
}
