import { describe, it, expect } from 'vitest';
import type { NormalizedSite } from '../../types.js';
import { findSegmentation } from '../../findings/segmentation.js';
import { findWifi } from '../../findings/wifi.js';
import { findFirewall } from '../../findings/firewall.js';
import { findRemoteAccess } from '../../findings/remoteAccess.js';
import { findDevices } from '../../findings/devices.js';

function site(overrides: Partial<NormalizedSite> = {}): NormalizedSite {
  return {
    siteId: 'test', siteName: 'Test',
    devices: [], clients: [], wlans: [], networks: [],
    portForwards: [], vpnConfigs: [], firewallPolicies: [],
    firewallZones: [], trafficRoutes: [], settings: {},
    profile: 'home_office', apiGaps: [], ...overrides,
  };
}

describe('findSegmentation', () => {
  it('emits SEG-001 for one network', () => {
    expect(findSegmentation(site({ networks: [{ purpose: 'corporate' }] }), 'home_office')[0]!.id).toMatch(/^SEG-001/);
  });
  it('no finding for multiple networks', () => {
    expect(findSegmentation(site({ networks: [{ purpose: 'corporate' }, { purpose: 'guest' }, { purpose: 'vlan-only' }] }), 'home_office')).toHaveLength(0);
  });
});

describe('findWifi', () => {
  it('emits WPA finding for WPA2-only SSID', () => {
    expect(findWifi(site({ wlans: [{ name: 'Net', enabled: true, security: 'wpapsk' }] }), 'home_office').some(f => f.id.includes('WPA'))).toBe(true);
  });
  it('emits PSK finding for short passphrase', () => {
    expect(findWifi(site({ wlans: [{ name: 'Net', enabled: true, x_passphrase: { length: 8 } }] }), 'home_office').some(f => f.id.includes('PSK'))).toBe(true);
  });
  it('reads live v10 securityConfiguration.type (WPA2_PERSONAL → WPA2-only)', () => {
    const fs = findWifi(site({ wlans: [{ name: 'Net', enabled: true, securityConfiguration: { type: 'WPA2_PERSONAL' } }] }), 'home_office');
    expect(fs.some(f => f.id.endsWith('-WPA'))).toBe(true);
  });
  it('does not flag WPA3 or mixed mode as WPA2-only', () => {
    for (const type of ['WPA3_PERSONAL', 'WPA2_WPA3_PERSONAL']) {
      const fs = findWifi(site({ wlans: [{ name: 'Net', enabled: true, securityConfiguration: { type } }] }), 'home_office');
      expect(fs.some(f => f.id.endsWith('-WPA')), type).toBe(false);
    }
  });
  it('flags an open SSID as high/gap (both live OPEN and backup "open")', () => {
    for (const w of [{ name: 'Guest', enabled: true, securityConfiguration: { type: 'OPEN' } }, { name: 'Guest', enabled: true, security: 'open' }]) {
      const fs = findWifi(site({ wlans: [w] }), 'home_office');
      const open = fs.find(f => f.id.endsWith('-OPEN'));
      expect(open).toMatchObject({ severity: 'high', status: 'gap' });
      expect(fs.some(f => f.id.endsWith('-WPA'))).toBe(false); // open, not WPA2-only
    }
  });
});

describe('findFirewall', () => {
  it('emits finding for active forwards', () => {
    expect(findFirewall(site({ portForwards: [{ enabled: true }] }), 'home_office').length).toBeGreaterThan(0);
  });
  it('no finding when empty', () => expect(findFirewall(site(), 'home_office')).toHaveLength(0));
});

describe('findRemoteAccess', () => {
  it('critical for PPTP', () => {
    expect(findRemoteAccess(site({ vpnConfigs: [{ type: 'pptp', enabled: true }] }), 'home_office').find(f => f.id.startsWith('VPN-PPTP-001'))?.severity).toBe('critical');
  });
  it('VPN-WG-OK for wireguard', () => {
    expect(findRemoteAccess(site({ vpnConfigs: [{ type: 'wireguard', enabled: true }] }), 'home_office').find(f => f.id.startsWith('VPN-WG-OK'))?.status).toBe('ok');
  });
  it('VPN-MISSING-001 for forwards without VPN', () => {
    expect(findRemoteAccess(site({ portForwards: [{ enabled: true }] }), 'home_office').some(f => f.id.startsWith('VPN-MISSING-001'))).toBe(true);
  });
});

describe('findDevices', () => {
  it('emits SSH finding', () => expect(findDevices(site({ devices: [{ sshEnabled: true }] }), 'home_office').length).toBeGreaterThan(0));
  it('no finding when SSH off', () => expect(findDevices(site({ devices: [{ sshEnabled: false }] }), 'home_office')).toHaveLength(0));
});
