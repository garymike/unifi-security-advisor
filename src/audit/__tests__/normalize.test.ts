import { describe, it, expect } from 'vitest';
import { normalizeApi, extractList } from '../normalize.js';

const CLEAN = {
  site_default: {
    _meta: { desc: 'Home' },
    devices: { data: [{ mac: 'aa:bb:cc', type: 'ugw' }] },
    clients: { data: [] }, wlans: { data: [{ name: 'HomeNet' }] },
    networks: { data: [] }, port_forwards: { data: [] }, vpn_configs: { data: [] },
    firewall_policies: { data: [] }, firewall_zones: { data: [] }, traffic_routes: { data: [] },
  },
};

describe('normalizeApi', () => {
  it('returns one site', () => expect(normalizeApi(CLEAN, 'home_office')).toHaveLength(1));
  it('sets siteId', () => expect(normalizeApi(CLEAN, 'home_office')[0]!.siteId).toBe('default'));
  it('uses desc as siteName', () => expect(normalizeApi(CLEAN, 'home_office')[0]!.siteName).toBe('Home'));
  it('unpacks wlans', () => expect(normalizeApi(CLEAN, 'home_office')[0]!.wlans[0]).toMatchObject({ name: 'HomeNet' }));
  it('sets profile', () => expect(normalizeApi(CLEAN, 'regulated_hipaa')[0]!.profile).toBe('regulated_hipaa'));
  it('returns [] for empty input', () => expect(normalizeApi({}, 'home')).toHaveLength(0));
  it('tracks missing collections in apiGaps', () => {
    const site = normalizeApi({ site_s1: { _meta: { name: 's1' }, devices: { data: [] } } }, 'home')[0]!;
    expect(site.apiGaps).toContain('wlans');
    expect(site.apiGaps).not.toContain('devices');
  });
  it('settings is empty in API mode', () => expect(normalizeApi(CLEAN, 'home')[0]!.settings).toEqual({}));

  it('uses meta.id as siteId when present (cloud mode has composite key)', () => {
    // Cloud mode produces keys like site_{consoleId}_{siteId} — meta.id holds the real siteId
    const clean = {
      'site_CONSOLEID_SITEID': {
        _meta: { id: 'real-site-id', name: 'My Site', _consoleId: 'CONSOLEID' },
        devices: { data: [] }, clients: { data: [] }, wlans: { data: [] },
        networks: { data: [] }, port_forwards: { data: [] }, vpn_configs: { data: [] },
        firewall_policies: { data: [] }, firewall_zones: { data: [] }, traffic_routes: { data: [] },
      },
    };
    const site = normalizeApi(clean, 'home_office')[0]!;
    expect(site.siteId).toBe('real-site-id');
    expect(site.siteName).toBe('My Site');
  });
});

describe('extractList', () => {
  it('unwraps data key', () => expect(extractList({ data: [1, 2] })).toEqual([1, 2]));
  it('returns plain arrays as-is', () => expect(extractList([1, 2])).toEqual([1, 2]));
  it('returns [] for null', () => expect(extractList(null)).toEqual([]));
  it('unwraps items key', () => expect(extractList({ items: ['a'] })).toEqual(['a']));
});
