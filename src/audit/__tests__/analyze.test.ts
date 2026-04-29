import { describe, it, expect } from 'vitest';
import type { Finding } from '../types.js';
import { sortFindings, applyProfileOverrides } from '../analyze.js';

function f(id: string, severity: Finding['severity'] = 'medium'): Finding {
  return {
    id, section: 'Test', severity, status: 'gap',
    title: id, currentState: 'x', recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'medium',
  };
}

describe('sortFindings', () => {
  it('VPN-PPTP-001 floats above medium', () => {
    expect(sortFindings([f('MEDIUM-001'), f('VPN-PPTP-001', 'critical')])[0]!.id).toBe('VPN-PPTP-001');
  });
  it('SEG-001-x floats above low', () => {
    expect(sortFindings([f('LOW-001', 'low'), f('SEG-001-x', 'high')])[0]!.id).toBe('SEG-001-x');
  });
  it('non-float sorted by severity', () => {
    expect(sortFindings([f('L', 'low'), f('H', 'high'), f('M', 'medium')]).map(x => x.id)).toEqual(['H', 'M', 'L']);
  });
});

describe('applyProfileOverrides', () => {
  it('home profile sets LOG-FWD-001 to low', () => {
    const findings = [f('LOG-FWD-001')];
    applyProfileOverrides(findings, 'home');
    expect(findings[0]!.severity).toBe('low');
  });
  it('regulated_hipaa sets BAK-001 to critical', () => {
    const findings = [f('BAK-001', 'high')];
    applyProfileOverrides(findings, 'regulated_hipaa');
    expect(findings[0]!.severity).toBe('critical');
  });
  it('unknown finding id unchanged', () => {
    const findings = [f('UNKNOWN-999')];
    applyProfileOverrides(findings, 'regulated_hipaa');
    expect(findings[0]!.severity).toBe('medium');
  });
});
