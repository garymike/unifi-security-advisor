import type { NormalizedSite } from './types.js';

const EXPECTED_COLLECTIONS = new Set([
  'devices', 'clients', 'wlans', 'networks', 'port_forwards',
  'vpn_configs', 'firewall_policies', 'firewall_zones', 'traffic_routes',
]);

export function extractList(data: unknown): Record<string, unknown>[] {
  if (data === null || data === undefined) return [];
  if (Array.isArray(data)) return data as Record<string, unknown>[];
  if (typeof data === 'object') {
    const d = data as Record<string, unknown>;
    for (const key of ['data', 'items', 'results']) {
      if (Array.isArray(d[key])) return d[key] as Record<string, unknown>[];
    }
  }
  return [];
}

export function normalizeApi(clean: Record<string, unknown>, profile: string): NormalizedSite[] {
  const sites: NormalizedSite[] = [];
  for (const [key, val] of Object.entries(clean)) {
    if (!key.startsWith('site_') || typeof val !== 'object' || val === null) continue;
    const siteId = key.slice(5);
    const siteData = val as Record<string, unknown>;
    const meta = (siteData['_meta'] ?? {}) as Record<string, unknown>;
    const siteName = String(meta['desc'] ?? meta['name'] ?? siteId);
    const apiGaps = [...EXPECTED_COLLECTIONS].filter(c => !(c in siteData)).sort();
    sites.push({
      siteId, siteName,
      devices:          extractList(siteData['devices']),
      clients:          extractList(siteData['clients']),
      wlans:            extractList(siteData['wlans']),
      networks:         extractList(siteData['networks']),
      portForwards:     extractList(siteData['port_forwards']),
      vpnConfigs:       extractList(siteData['vpn_configs']),
      firewallPolicies: extractList(siteData['firewall_policies']),
      firewallZones:    extractList(siteData['firewall_zones']),
      trafficRoutes:    extractList(siteData['traffic_routes']),
      settings: {}, profile, apiGaps,
    });
  }
  return sites;
}
