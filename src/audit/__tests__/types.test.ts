import { describe, it, expect } from 'vitest';
import type { Finding, NormalizedSite } from '../types.js';

describe('Finding type', () => {
  it('accepts required fields', () => {
    const f: Finding = {
      id: 'TEST-001', section: 'Test', severity: 'high',
      status: 'gap', title: 'A finding', currentState: 'Bad',
      recommendation: null, intentQuestion: null,
      evidence: {}, mapsTo: {}, effort: 'quick', impact: 'high',
    };
    expect(f.id).toBe('TEST-001');
    expect(f.recommendation).toBeNull();
  });
});
