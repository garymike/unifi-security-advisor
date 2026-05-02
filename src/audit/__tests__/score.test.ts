import { describe, it, expect } from 'vitest';
import type { Finding } from '../types.js';
import { computeScore } from '../score.js';

function f(opts: Partial<Finding> & { status: Finding['status']; severity: Finding['severity'] }): Finding {
  return {
    id: 'TEST', section: 'Test', title: 'Test', currentState: 'x',
    recommendation: null, intentQuestion: null, evidence: {}, mapsTo: {},
    effort: 'quick', impact: 'medium', floatTop: false,
    ...opts,
  };
}

describe('computeScore', () => {
  it('empty findings → score 100, grade A, label Strong', () => {
    const r = computeScore([]);
    expect(r.score).toBe(100);
    expect(r.grade).toBe('A');
    expect(r.label).toBe('Strong');
  });

  it('single critical gap → deducts 20 → score 80, grade B', () => {
    const r = computeScore([f({ status: 'gap', severity: 'critical' })]);
    expect(r.score).toBe(80);
    expect(r.grade).toBe('B');
  });

  it('high gap → deducts 10 → score 90, grade A', () => {
    const r = computeScore([f({ status: 'gap', severity: 'high' })]);
    expect(r.score).toBe(90);
    expect(r.grade).toBe('A');
  });

  it('recommendation deducts half vs gap', () => {
    expect(computeScore([f({ status: 'recommendation', severity: 'critical' })]).score).toBe(90);
  });

  it('unknown deducts less than gap', () => {
    expect(computeScore([f({ status: 'unknown', severity: 'critical' })]).score).toBe(95);
  });

  it('ok findings do not deduct', () => {
    expect(computeScore([f({ status: 'ok', severity: 'critical' })]).score).toBe(100);
  });

  it('floatTop doubles the deduction', () => {
    const r = computeScore([f({ status: 'gap', severity: 'high', floatTop: true })]);
    expect(r.score).toBe(80);
    expect(r.grade).toBe('B');
  });

  it('score is clamped to 0, grade F', () => {
    const manyGaps = Array.from({ length: 10 }, () => f({ status: 'gap', severity: 'critical' }));
    const r = computeScore(manyGaps);
    expect(r.score).toBe(0);
    expect(r.grade).toBe('F');
    expect(r.label).toBe('At risk');
  });

  it('grade boundary 90 → A', () => {
    expect(computeScore([f({ status: 'gap', severity: 'high' })]).grade).toBe('A');
  });

  it('grade boundary 89 → B', () => {
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'recommendation', severity: 'low' }),
    ]);
    expect(r.score).toBe(89);
    expect(r.grade).toBe('B');
  });

  it('grade boundary 74 → C', () => {
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'medium' }),
      f({ status: 'recommendation', severity: 'low' }),
    ]);
    expect(r.score).toBe(74);
    expect(r.grade).toBe('C');
  });
});
