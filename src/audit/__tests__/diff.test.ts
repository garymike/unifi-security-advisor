import { describe, it, expect } from 'vitest';
import type { Finding } from '../types.js';
import { diffRuns } from '../diff.js';

function f(id: string, opts: Partial<Finding> = {}): Finding {
  return {
    id, section: 'Test', title: id, currentState: 'x',
    severity: 'medium', status: 'gap',
    recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'medium',
    floatTop: false,
    ...opts,
  };
}

describe('diffRuns', () => {
  it('empty vs empty → no changes, zero delta', () => {
    const r = diffRuns([], []);
    expect(r.added).toHaveLength(0);
    expect(r.removed).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
    expect(r.scoreDelta).toBe(0);
  });

  it('finding in B not in A → added', () => {
    const r = diffRuns([], [f('NEW-001')]);
    expect(r.added).toHaveLength(1);
    expect(r.added[0]!.id).toBe('NEW-001');
    expect(r.removed).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
  });

  it('finding in A not in B → removed', () => {
    const r = diffRuns([f('OLD-001')], []);
    expect(r.removed).toHaveLength(1);
    expect(r.removed[0]!.id).toBe('OLD-001');
    expect(r.added).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
  });

  it('same finding in both with identical severity+status → not in any bucket', () => {
    const finding = f('SAME-001');
    const r = diffRuns([finding], [finding]);
    expect(r.added).toHaveLength(0);
    expect(r.removed).toHaveLength(0);
    expect(r.changed).toHaveLength(0);
  });

  it('finding in both with different status → changed', () => {
    const r = diffRuns(
      [f('A', { status: 'gap' })],
      [f('A', { status: 'ok' })],
    );
    expect(r.changed).toHaveLength(1);
    expect(r.changed[0]!.before.status).toBe('gap');
    expect(r.changed[0]!.after.status).toBe('ok');
    expect(r.added).toHaveLength(0);
    expect(r.removed).toHaveLength(0);
  });

  it('finding in both with different severity → changed', () => {
    const r = diffRuns(
      [f('A', { severity: 'high' })],
      [f('A', { severity: 'medium' })],
    );
    expect(r.changed).toHaveLength(1);
    expect(r.changed[0]!.before.severity).toBe('high');
    expect(r.changed[0]!.after.severity).toBe('medium');
  });

  it('scoreDelta is positive when posture improves (A had a gap, B does not)', () => {
    const r = diffRuns([f('A', { status: 'gap', severity: 'high' })], []);
    expect(r.scoreDelta).toBe(10);
  });

  it('scoreDelta is negative when posture worsens', () => {
    const r = diffRuns([], [f('A', { status: 'gap', severity: 'high' })]);
    expect(r.scoreDelta).toBe(-10);
  });
});
