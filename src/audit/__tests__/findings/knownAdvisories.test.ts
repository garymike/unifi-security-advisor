import { describe, it, expect } from 'vitest';
import type { NormalizedSite } from '../../types.js';
import type { Advisory } from '../../knownAdvisoriesData.js';
import { findKnownAdvisories } from '../../findings/knownAdvisories.js';

function site(overrides: Partial<NormalizedSite> = {}): NormalizedSite {
  return {
    siteId: 'test', siteName: 'Test', devices: [], clients: [], wlans: [], networks: [],
    portForwards: [], vpnConfigs: [], firewallPolicies: [], firewallZones: [], trafficRoutes: [],
    settings: {}, profile: 'home_office', apiGaps: [], ...overrides,
  };
}

const testAdvisory: Advisory = {
  id: 'TEST-CVE-0001',
  title: 'Test advisory for a made-up UDM-Test vulnerability',
  severity: 'critical',
  cves: ['CVE-0000-00001'],
  cisaKev: true,
  affectedModels: { 'UDM-TEST': { vulnerableThrough: '5.0.16' } },
  recommendation: 'Update immediately.',
  advisoryUrl: 'https://example.com/advisory',
};

describe('findKnownAdvisories', () => {
  it('emits a gap finding when a matched device version is at or below vulnerableThrough', () => {
    const s = site({ devices: [{ model: 'UDM-Test', name: 'Gateway', version: '5.0.16' }] });
    const findings = findKnownAdvisories(s, 'home_office', [testAdvisory]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ id: 'ADV-TEST-CVE-0001-test', status: 'gap', severity: 'critical' });
    expect(findings[0]!.intentQuestion).not.toBeNull();
  });

  it('emits an unknown finding, at the advisory severity, when the matched device has no readable version', () => {
    const s = site({ devices: [{ model: 'UDM-Test', name: 'Gateway' }] });
    const findings = findKnownAdvisories(s, 'home_office', [testAdvisory]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ status: 'unknown', severity: 'critical' });
  });

  it('emits no finding when the device version is above vulnerableThrough (accepted false-negative)', () => {
    const s = site({ devices: [{ model: 'UDM-Test', name: 'Gateway', version: '5.0.17' }] });
    const findings = findKnownAdvisories(s, 'home_office', [testAdvisory]);
    expect(findings).toHaveLength(0);
  });

  it('emits no finding when no device matches the advisory model', () => {
    const s = site({ devices: [{ model: 'U6-LR', name: 'AP', version: '7.1.66' }] });
    const findings = findKnownAdvisories(s, 'home_office', [testAdvisory]);
    expect(findings).toHaveLength(0);
  });

  it('aggregates multiple affected devices into one finding, listing both in evidence', () => {
    const s = site({ devices: [
      { model: 'UDM-Test', name: 'Gateway1', version: '5.0.10' },
      { model: 'UDM-Test', name: 'Gateway2', version: '5.0.16' },
    ] });
    const findings = findKnownAdvisories(s, 'home_office', [testAdvisory]);
    expect(findings).toHaveLength(1);
    expect((findings[0]!.evidence['devices'] as unknown[])).toHaveLength(2);
  });

  it('falls back to the real bundled KNOWN_ADVISORIES when no list is passed', () => {
    const s = site({ devices: [{ model: 'UDM-PRO', name: 'Gateway', version: '5.0.10' }] });
    const findings = findKnownAdvisories(s, 'home_office');
    expect(findings.some(f => f.id.startsWith('ADV-CVE-2026-34908-9-10'))).toBe(true);
  });
});
