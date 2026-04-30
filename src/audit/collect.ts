import type { UniFiClient } from './client.js';

const LOCAL_GLOBAL = [
  ['info',  '/proxy/network/integration/v1/info'],
  ['sites', '/proxy/network/integration/v1/sites'],
] as const;

const SITE_SCOPED = [
  ['devices',            '/proxy/network/integration/v1/sites/{id}/devices'],
  ['clients',            '/proxy/network/integration/v1/sites/{id}/clients'],
  ['wlans',              '/proxy/network/integration/v1/sites/{id}/wlans'],
  ['firewall_policies',  '/proxy/network/integration/v1/sites/{id}/firewall-policies'],
  ['firewall_zones',     '/proxy/network/integration/v1/sites/{id}/firewall-zones'],
  ['port_forwards',      '/proxy/network/integration/v1/sites/{id}/port-forwards'],
  ['vpn_configs',        '/proxy/network/integration/v1/sites/{id}/vpn-configs'],
  ['networks',           '/proxy/network/integration/v1/sites/{id}/networks'],
  ['traffic_routes',     '/proxy/network/integration/v1/sites/{id}/traffic-routes'],
] as const;

const CLOUD_ENDPOINTS = [
  ['hosts',         'https://api.ui.com/v1/hosts'],
  ['cloud_sites',   'https://api.ui.com/v1/sites'],
  ['cloud_devices', 'https://api.ui.com/v1/devices'],
] as const;

export function buildConnectorUrl(consoleId: string, siteId: string, resource: string): string {
  return `https://api.ui.com/v1/connector/consoles/${consoleId}/proxy/network/integration/v1/sites/${siteId}/${resource}`;
}

export function extractSites(sitesResponse: unknown): Record<string, unknown>[] {
  if (Array.isArray(sitesResponse)) return sitesResponse as Record<string, unknown>[];
  if (sitesResponse !== null && typeof sitesResponse === 'object') {
    const r = sitesResponse as Record<string, unknown>;
    for (const key of ['data', 'sites', 'items']) {
      if (Array.isArray(r[key])) return r[key] as Record<string, unknown>[];
    }
  }
  return [];
}

export interface CollectResult {
  [key: string]: unknown;
  _endpointsProbed: Array<{ name: string; path: string; status: number }>;
  _errors: Array<{ endpoint: string; status: number; hint?: string }>;
  _siteCount: number;
}

export async function collectAll(client: UniFiClient, log: (msg: string) => void): Promise<CollectResult> {
  const result: CollectResult = { _endpointsProbed: [], _errors: [], _siteCount: 0 };

  if (client.config.useCloud) {
    for (const [name, url] of CLOUD_ENDPOINTS) {
      log(`GET ${url}`);
      const { status, data } = await client.get(url);
      result._endpointsProbed.push({ name, path: url, status });
      if (status === 200) result[name] = data;
      else if (status === 403) result._errors.push({ endpoint: name, status, hint: 'insufficient scope' });
    }
  } else {
    for (const [name, path] of LOCAL_GLOBAL) {
      log(`GET ${path}`);
      const { status, data } = await client.get(path);
      result._endpointsProbed.push({ name, path, status });
      if (status === 200) result[name] = data;
      else if (status === 403) result._errors.push({ endpoint: name, status, hint: 'key lacks scope' });
    }

    const siteList = extractSites(result['sites']);
    result._siteCount = siteList.length;

    for (const site of siteList) {
      const siteId = String(site['id'] ?? site['_id'] ?? site['name'] ?? '');
      if (!siteId) continue;
      const siteKey = `site_${siteId}`;
      result[siteKey] = { _meta: site };
      for (const [name, pathTpl] of SITE_SCOPED) {
        const path = pathTpl.replace('{id}', siteId);
        log(`GET ${path}`);
        const { status, data } = await client.get(path);
        result._endpointsProbed.push({ name: `${name}@${siteId}`, path, status });
        if (status === 200) (result[siteKey] as Record<string, unknown>)[name] = data;
        else if (status === 403) result._errors.push({ endpoint: `${name}@${siteId}`, status });
        await new Promise(r => setTimeout(r, 100));
      }
    }
  }

  return result;
}
