import { describe, it, expect } from 'vitest';
import { normalizeBackup } from '../normalizeBackup.js';

const COLLECTIONS = {
  setting: [
    { key: 'super_identity', name: 'HomeNet', desc: 'Home Network' },
    { key: 'auto_update', enabled: true },
    { key: 'mgmt', syslog_host: null, advanced_feature_enabled: false },
    { key: 'rogueap', report_rogue: false },
    { key: 'auto_backup', enabled: true, destination: 'cloud' },
    { key: 'dpi', level: 'disabled' },
  ],
  device: [{ mac: 'aa:bb:cc', model: 'U7Pro', version: '8.5.21' }],
  wlanconf: [{ name: 'HomeWifi', security: 'wpapsk', wpa_mode: 'wpa3', enabled: true }],
  networkconf: [{ name: 'LAN', purpose: 'corporate', vlan: 1 }, { name: 'IoT', purpose: 'vlan-only', vlan: 20 }],
  portforward: [{ name: 'SSH', proto: 'tcp', dst_port: 22, enabled: true }],
  firewallrule: [{ name: 'Block WAN', ruleset: 'WAN_IN', action: 'drop', enabled: true }],
  firewallgroup: [],
  user: [{ hostname: 'my-laptop', mac: 'dd:ee:ff' }],
};

describe('normalizeBackup', () => {
  it('returns one site (backups are single-site)', () => {
    expect(normalizeBackup(COLLECTIONS, 'home_office')).toHaveLength(1);
  });

  it('sets siteId and siteName from super_identity setting', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.siteId).toBe('HomeNet');
    expect(site!.siteName).toBe('Home Network');
  });

  it('maps device → devices', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.devices).toHaveLength(1);
    expect(site!.devices[0]).toMatchObject({ mac: 'aa:bb:cc' });
  });

  it('maps wlanconf → wlans', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.wlans[0]).toMatchObject({ name: 'HomeWifi' });
  });

  it('maps networkconf → networks', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.networks).toHaveLength(2);
  });

  it('maps portforward → portForwards', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.portForwards).toHaveLength(1);
  });

  it('maps firewallrule → firewallPolicies', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.firewallPolicies).toHaveLength(1);
  });

  it('maps user → clients', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.clients[0]).toMatchObject({ hostname: 'my-laptop' });
  });

  it('populates settings.auto_update from setting collection (unlocks FW-AUTO-001)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.settings['auto_update']).toBeDefined();
    expect((site!.settings['auto_update'] as Record<string, unknown>)['enabled']).toBe(true);
  });

  it('populates settings.rogueap (unlocks RF-ROGUE-001)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.settings['rogueap']).toBeDefined();
    expect((site!.settings['rogueap'] as Record<string, unknown>)['report_rogue']).toBe(false);
  });

  it('populates settings.auto_backup (unlocks BAK-001)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.settings['auto_backup']).toBeDefined();
    expect((site!.settings['auto_backup'] as Record<string, unknown>)['destination']).toBe('cloud');
  });

  it('apiGaps is empty (backup has full coverage)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.apiGaps).toHaveLength(0);
  });

  it('sets profile', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'regulated_hipaa');
    expect(site!.profile).toBe('regulated_hipaa');
  });
});
