import { describe, it, expect } from 'vitest';
import type { NormalizedSite } from '../../types.js';
import { inferProfile } from '../../../wizard/profileInfer.js';

function site(overrides: Partial<NormalizedSite> = {}): NormalizedSite {
  return {
    siteId: 'test', siteName: 'Test',
    devices: [], clients: [], wlans: [], networks: [],
    portForwards: [], vpnConfigs: [], firewallPolicies: [],
    firewallZones: [], trafficRoutes: [], settings: {},
    profile: 'home_office', apiGaps: [], ...overrides,
  };
}

describe('inferProfile', () => {
  it('returns home_office for empty sites', () => {
    expect(inferProfile([])).toBe('home_office');
  });
  it('infers home for 1 AP, 1-2 networks', () => {
    expect(inferProfile([site({
      devices: [{ type: 'uap' }],
      networks: [{ purpose: 'corporate' }],
    })])).toBe('home');
  });
  it('infers home_office for 3 APs, 3 networks', () => {
    expect(inferProfile([site({
      devices: [{ type: 'uap' }, { type: 'uap' }, { type: 'uap' }],
      networks: [{ purpose: 'corporate' }, { purpose: 'guest' }, { purpose: 'vlan-only' }],
    })])).toBe('home_office');
  });
  it('infers small_business for 6+ APs', () => {
    expect(inferProfile([site({
      devices: Array(6).fill({ type: 'uap' }),
      networks: Array(5).fill({ purpose: 'vlan-only' }),
    })])).toBe('small_business');
  });
});
