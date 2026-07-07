import { describe, it, expect } from 'vitest';
import type { NormalizedSite } from '../../types.js';
import { findWirelessTuning } from '../../findings/wirelessTuning.js';
import { findFirewallThreats } from '../../findings/firewallThreats.js';
import { findFirmware } from '../../findings/firmware.js';
import { findLogging } from '../../findings/logging.js';
import { findBackup } from '../../findings/backup.js';
import { findApiCoverage } from '../../findings/apiCoverage.js';

function site(overrides: Partial<NormalizedSite> = {}): NormalizedSite {
  return {
    siteId: 'test', siteName: 'Test', devices: [], clients: [], wlans: [], networks: [],
    portForwards: [], vpnConfigs: [], firewallPolicies: [], firewallZones: [], trafficRoutes: [],
    settings: {}, profile: 'home_office', apiGaps: [], ...overrides,
  };
}

describe('findWirelessTuning', () => {
  it('emits RF-TX for high tx_power_mode', () => {
    const s = site({ devices: [{ type: 'uap', mac: 'aa', name: 'AP1', radio_table: [{ radio: 'na', tx_power_mode: 'high' }] }] });
    expect(findWirelessTuning(s, 'home_office').some(f => f.id.includes('-TX'))).toBe(true);
  });
  it('RF-ROGUE-001 unknown when no settings', () => {
    expect(findWirelessTuning(site(), 'home_office').find(f => f.id.startsWith('RF-ROGUE-001'))?.status).toBe('unknown');
  });
  it('RF-ROGUE-001 gap when disabled', () => {
    expect(findWirelessTuning(site({ settings: { rogueap: { report_rogue: false } } }), 'home_office').find(f => f.id.startsWith('RF-ROGUE-001'))?.status).toBe('gap');
  });
  it('PMF finding for WPA3 without PMF', () => {
    expect(findWirelessTuning(site({ wlans: [{ name: 'Sec', enabled: true, wpa_mode: 'wpa3', pmf_mode: 'disabled' }] }), 'home_office').some(f => f.id.includes('RF-PMF'))).toBe(true);
  });
});

describe('findFirewallThreats', () => {
  it('emits FW-GEO-IN when no geo inbound policy', () => {
    expect(findFirewallThreats(site(), 'home_office').some(f => f.id.startsWith('FW-GEO-IN'))).toBe(true);
  });
  it('FW-CONTENT-001 unknown when no settings', () => {
    expect(findFirewallThreats(site(), 'home_office').find(f => f.id.startsWith('FW-CONTENT-001'))?.status).toBe('unknown');
  });

  it('FW-GEO-IN/OUT degrade to unknown (not a false "no blocking" recommendation) when firewall_policies is gapped', () => {
    const fs = findFirewallThreats(site({ apiGaps: ['firewall_policies', 'port_forwards'] }), 'home_office');
    const geoIn = fs.find(f => f.id.startsWith('FW-GEO-IN'));
    const geoOut = fs.find(f => f.id.startsWith('FW-GEO-OUT'));
    expect(geoIn?.status).toBe('unknown');
    expect(geoOut?.status).toBe('unknown');
    expect(geoIn?.title).toMatch(/cannot check/i);
  });

  it('FW-GEO-IN stays a recommendation when firewall data is visible but has no geo rule', () => {
    const fs = findFirewallThreats(site({ apiGaps: [], firewallPolicies: [] }), 'home_office');
    expect(fs.find(f => f.id.startsWith('FW-GEO-IN'))?.status).toBe('recommendation');
  });

  it('SEG-MGMT-WAN unknown (no visibility) when firewall/port-forward data is unavailable', () => {
    const s = site({ apiGaps: ['firewall_policies', 'port_forwards'] });
    const f = findFirewallThreats(s, 'home_office').find(x => x.id.startsWith('SEG-MGMT-WAN'));
    expect(f).toMatchObject({ status: 'unknown', severity: 'info' });
  });

  it('SEG-MGMT-WAN unknown (no rule found) when firewall data is visible but empty', () => {
    const s = site({ firewallPolicies: [], portForwards: [], apiGaps: [] });
    const f = findFirewallThreats(s, 'home_office').find(x => x.id.startsWith('SEG-MGMT-WAN'));
    expect(f).toMatchObject({ status: 'unknown', severity: 'info' });
  });

  it('SEG-MGMT-WAN gap when a WAN_LOCAL accept rule targets a management port', () => {
    const s = site({
      apiGaps: [],
      firewallPolicies: [{ enabled: true, action: 'accept', ruleset: 'WAN_LOCAL', source: { type: 'any' }, dst_port: 443 }],
    });
    const f = findFirewallThreats(s, 'home_office').find(x => x.id.startsWith('SEG-MGMT-WAN'));
    expect(f).toMatchObject({ status: 'gap', severity: 'critical' });
  });

  it('SEG-MGMT-WAN gap when a port forward targets a management port on the gateway', () => {
    const s = site({
      apiGaps: [],
      portForwards: [{ enabled: true, dst_port: 22 }],
    });
    const f = findFirewallThreats(s, 'home_office').find(x => x.id.startsWith('SEG-MGMT-WAN'));
    expect(f).toMatchObject({ status: 'gap', severity: 'critical' });
  });

  it('SEG-MGMT-WAN unknown when a WAN_LOCAL rule exists but is disabled', () => {
    const s = site({
      apiGaps: [],
      firewallPolicies: [{ enabled: false, action: 'accept', ruleset: 'WAN_LOCAL', source: { type: 'any' }, dst_port: 443 }],
    });
    const f = findFirewallThreats(s, 'home_office').find(x => x.id.startsWith('SEG-MGMT-WAN'));
    expect(f).toMatchObject({ status: 'unknown', severity: 'info' });
  });
});

describe('findFirmware', () => {
  it('emits EOL finding for UAP-AC-LITE', () => {
    expect(findFirmware(site({ devices: [{ model: 'UAP-AC-LITE', name: 'OldAP', version: '5.0.0' }] }), 'home_office').some(f => f.id.startsWith('FW-EOL-001'))).toBe(true);
  });
  it('FW-AUTO-001 unknown when no settings', () => {
    expect(findFirmware(site(), 'home_office').find(f => f.id.startsWith('FW-AUTO-001'))?.status).toBe('unknown');
  });
});

describe('findLogging', () => {
  it('LOG-FWD-001 unknown when no settings', () => {
    expect(findLogging(site(), 'home_office').find(f => f.id.startsWith('LOG-FWD-001'))?.status).toBe('unknown');
  });
});

describe('findBackup', () => {
  it('BAK-001 unknown when no settings', () => {
    expect(findBackup(site(), 'home_office').find(f => f.id.startsWith('BAK-001'))?.status).toBe('unknown');
  });
  it('BAK-003 always emitted when backup enabled', () => {
    expect(findBackup(site({ settings: { auto_backup: { enabled: true, destination: 'cloud' } } }), 'home_office').some(f => f.id.startsWith('BAK-003'))).toBe(true);
  });
});

describe('findApiCoverage', () => {
  it('emits META-COVERAGE when endpoints failed', () => {
    expect(findApiCoverage({ _endpointsProbed: [{ name: 'wlans', status: 404 }] }).some(f => f.id === 'META-COVERAGE')).toBe(true);
  });
  it('no finding when all succeeded', () => {
    expect(findApiCoverage({ _endpointsProbed: [{ name: 'wlans', status: 200 }] })).toHaveLength(0);
  });
});
