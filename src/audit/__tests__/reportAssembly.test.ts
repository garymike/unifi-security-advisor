import { describe, it, expect } from 'vitest';
import { applyAnswersAndTensions, belongsToSite, type StoredAnswer } from '../../wizard/reportAssembly.js';
import type { Finding, Status } from '../types.js';

function finding(id: string, status: Status = 'gap'): Finding {
  return {
    id, section: 's', severity: 'high', status, title: id,
    currentState: '', recommendation: null, intentQuestion: 'q?',
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'high',
  };
}

const SITE = 'default';

describe('belongsToSite', () => {
  it('matches trailing and infix site ids', () => {
    expect(belongsToSite('SEG-001-default', 'default')).toBe(true);
    expect(belongsToSite('WIFI-default-HomeNet-PSK', 'default')).toBe(true);
    expect(belongsToSite('SEG-001-other', 'default')).toBe(false);
    expect(belongsToSite('META-COVERAGE', 'default')).toBe(false);
  });
});

describe('applyAnswersAndTensions', () => {
  it('applies a "yes" answer, flipping the finding to ok', () => {
    const out = applyAnswersAndTensions(
      [finding(`DEV-SSH-${SITE}`, 'gap')],
      [{ findingId: `DEV-SSH-${SITE}`, answer: 'yes', freeText: '' }],
      [SITE],
    );
    expect(out.find(f => f.id === `DEV-SSH-${SITE}`)!.status).toBe('ok');
  });

  it('recomputes tensions on the answered set (compound survives a "no")', () => {
    const raw = [
      finding(`SEG-MGMT-WAN-${SITE}`, 'gap'),
      finding(`ADV-CVE-1-${SITE}`, 'gap'),
    ];
    const answers: StoredAnswer[] = [
      { findingId: `SEG-MGMT-WAN-${SITE}`, answer: 'no', freeText: '' },
    ];
    const out = applyAnswersAndTensions(raw, answers, [SITE]);
    expect(out.some(f => f.id === `TENSION-WAN-RCE-${SITE}`)).toBe(true);
  });

  it('dissolves a compound when an answer clears a contributor', () => {
    const raw = [
      finding(`SEG-MGMT-WAN-${SITE}`, 'gap'),
      finding(`ADV-CVE-1-${SITE}`, 'gap'),
      // stale config-time tension that must be dropped and recomputed:
      finding(`TENSION-WAN-RCE-${SITE}`, 'gap'),
    ];
    // User confirms the management exposure is intentional → status ok.
    const answers: StoredAnswer[] = [
      { findingId: `SEG-MGMT-WAN-${SITE}`, answer: 'yes', freeText: 'behind a jump host' },
    ];
    const out = applyAnswersAndTensions(raw, answers, [SITE]);
    expect(out.some(f => f.id === `TENSION-WAN-RCE-${SITE}`)).toBe(false);
  });

  it('drops stale config-time tension findings from the input', () => {
    // No contributors present, but a stale tension is in the raw set.
    const out = applyAnswersAndTensions([finding(`TENSION-WAN-RCE-${SITE}`, 'gap')], [], [SITE]);
    expect(out).toEqual([]);
  });

  it('keeps tensions within a site for multi-site runs', () => {
    const raw = [
      finding('SEG-001-a', 'gap'),
      finding('VPN-MISSING-001-b', 'gap'), // different site — must not combine
    ];
    const out = applyAnswersAndTensions(raw, [], ['a', 'b']);
    expect(out.some(f => f.id.startsWith('TENSION-'))).toBe(false);
  });
});
