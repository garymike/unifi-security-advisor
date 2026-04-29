import { describe, it, expect } from 'vitest';
import type { Finding } from '../../types.js';
import { getQuestionQueue, mergeAnswer } from '../../../wizard/orchestrator.js';

function f(id: string, opts: Partial<Finding> = {}): Finding {
  return {
    id, section: 'Test', severity: 'medium', status: 'gap',
    title: id, currentState: 'x', recommendation: null,
    intentQuestion: 'Is this intended?',
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'medium',
    ...opts,
  };
}

describe('getQuestionQueue', () => {
  it('excludes findings with null intentQuestion', () => {
    const q = getQuestionQueue([f('A'), f('B', { intentQuestion: null })]);
    expect(q.map(x => x.id)).toEqual(['A']);
  });
  it('excludes ok findings', () => {
    const q = getQuestionQueue([f('A'), f('B', { status: 'ok' })]);
    expect(q.map(x => x.id)).toEqual(['A']);
  });
  it('float-top findings first', () => {
    const q = getQuestionQueue([
      f('NORMAL', { severity: 'high' }),
      f('VPN-PPTP-001', { severity: 'critical', floatTop: true }),
    ]);
    expect(q[0]!.id).toBe('VPN-PPTP-001');
  });
  it('sorted by severity within non-float-top', () => {
    const q = getQuestionQueue([f('LOW', { severity: 'low' }), f('HIGH', { severity: 'high' })]);
    expect(q.map(x => x.id)).toEqual(['HIGH', 'LOW']);
  });
});

describe('mergeAnswer', () => {
  it('yes sets status to ok', () => expect(mergeAnswer(f('A'), 'yes', '').status).toBe('ok'));
  it('deferred sets status to unknown', () => expect(mergeAnswer(f('A'), 'deferred', '').status).toBe('unknown'));
  it('no leaves status as gap', () => expect(mergeAnswer(f('A', { status: 'gap' }), 'no', '').status).toBe('gap'));
  it('free text appended to evidence', () => {
    const updated = mergeAnswer(f('A'), 'no', 'Extra context');
    expect((updated.evidence as Record<string, unknown>)['userNote']).toBe('Extra context');
  });
  it('not_applicable sets status to ok', () => expect(mergeAnswer(f('A'), 'not_applicable', '').status).toBe('ok'));
});
