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
  it('empty findings → score 100, grade A+, label Strong', () => {
    const r = computeScore([]);
    expect(r.score).toBe(100);
    expect(r.grade).toBe('A+');
    expect(r.label).toBe('Strong');
  });

  // score 80 = B- on standard +/- scale
  it('single critical gap → deducts 20 → score 80, grade B-', () => {
    const r = computeScore([f({ status: 'gap', severity: 'critical' })]);
    expect(r.score).toBe(80);
    expect(r.grade).toBe('B-');
    expect(r.label).toBe('Good');
  });

  // score 78 = C+ — this was the reported bug
  it('score 78 → grade C+, label Fair', () => {
    const r = computeScore([
      f({ status: 'gap', severity: 'critical' }),
      f({ status: 'recommendation', severity: 'medium' }),
    ]);
    expect(r.score).toBe(78);
    expect(r.grade).toBe('C+');
    expect(r.label).toBe('Fair');
  });

  it('high gap → deducts 10 → score 90, grade A-', () => {
    const r = computeScore([f({ status: 'gap', severity: 'high' })]);
    expect(r.score).toBe(90);
    expect(r.grade).toBe('A-');
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

  it('floatTop doubles the deduction → score 80, grade B-', () => {
    const r = computeScore([f({ status: 'gap', severity: 'high', floatTop: true })]);
    expect(r.score).toBe(80);
    expect(r.grade).toBe('B-');
  });

  it('score is clamped to 0, grade F', () => {
    const manyGaps = Array.from({ length: 10 }, () => f({ status: 'gap', severity: 'critical' }));
    const r = computeScore(manyGaps);
    expect(r.score).toBe(0);
    expect(r.grade).toBe('F');
    expect(r.label).toBe('At risk');
  });

  // Standard +/- grade boundaries
  it('score 97 → A+', () => {
    // 100 - 3 (unknown high) = 97
    const r = computeScore([f({ status: 'unknown', severity: 'high' })]);
    expect(r.score).toBe(97);
    expect(r.grade).toBe('A+');
  });

  it('score 93 → A', () => {
    // 100 - 5 (unknown critical) - 2 (recommendation medium) = 93
    const r = computeScore([
      f({ status: 'unknown', severity: 'critical' }),
      f({ status: 'recommendation', severity: 'medium' }),
    ]);
    expect(r.score).toBe(93);
    expect(r.grade).toBe('A');
  });

  it('grade boundary 90 → A-', () => {
    // 100 - 10 (high gap) = 90
    expect(computeScore([f({ status: 'gap', severity: 'high' })]).grade).toBe('A-');
  });

  it('grade boundary 87 → B+', () => {
    // 100 - 10 (high gap) - 3 (unknown high) = 87
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'unknown', severity: 'high' }),
    ]);
    expect(r.score).toBe(87);
    expect(r.grade).toBe('B+');
  });

  it('grade boundary 83 → B', () => {
    // 100 - 10 - 5 - 2 = 83
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'medium' }),
      f({ status: 'recommendation', severity: 'medium' }),
    ]);
    expect(r.score).toBe(83);
    expect(r.grade).toBe('B');
  });

  it('grade boundary 77 → C+', () => {
    // 100 - 10 - 10 - 2 - 1 = 77
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'low' }),
      f({ status: 'recommendation', severity: 'low' }),
    ]);
    expect(r.score).toBe(77);
    expect(r.grade).toBe('C+');
  });

  it('grade boundary 73 → C', () => {
    // 100 - 10 - 10 - 5 - 2 = 73
    const r = computeScore([
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'high' }),
      f({ status: 'gap', severity: 'medium' }),
      f({ status: 'gap', severity: 'low' }),
    ]);
    expect(r.score).toBe(73);
    expect(r.grade).toBe('C');
  });
});
