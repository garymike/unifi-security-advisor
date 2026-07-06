import type { UniFiClient } from './client.js';
import {
  GLOBAL_ENDPOINTS,
  INTEGRATION_SPEC_PATH,
  CLOUD_HOSTS_URL,
  localSitePath,
  defaultSiteEndpoints,
} from './endpoints.js';
import { parseSpecPaths, resolveSiteEndpoints } from './discover.js';

const CLOUD_ENDPOINTS = [
  ['hosts',         CLOUD_HOSTS_URL],
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
    // Step 1: Fetch metadata endpoints (hosts, sites list, devices list)
    for (const [name, url] of CLOUD_ENDPOINTS) {
      log(`GET ${url}`);
      const { status, data } = await client.get(url);
      result._endpointsProbed.push({ name, path: url, status });
      if (status === 200) result[name] = data;
      else if (status === 403) result._errors.push({ endpoint: name, status, hint: 'insufficient scope' });
    }

    // Step 2: Enumerate consoles and collect per-site data via Cloud Connector.
    // Cloud mode doesn't discover (Site Manager serves one version), so it uses
    // the default endpoint set — the full suffix is passed as the connector
    // resource so multi-segment paths (e.g. wifi/broadcasts) proxy correctly.
    const hosts = extractSites(result['hosts']);
    if (hosts.length === 0) {
      result._errors.push({ endpoint: 'hosts', status: 0, hint: 'no consoles returned; check API key scope or Cloud Connector availability' });
    }
    const cloudEndpoints = defaultSiteEndpoints();
    for (const host of hosts) {
      const consoleId = String(host['id'] ?? host['hostId'] ?? '');
      if (!consoleId) continue;

      // Enumerate sites for this console via Cloud Connector
      const sitesUrl = `https://api.ui.com/v1/connector/consoles/${consoleId}/proxy/network/integration/v1/sites`;
      log(`GET ${sitesUrl}`);
      const { status: sitesStatus, data: sitesData } = await client.get(sitesUrl);
      result._endpointsProbed.push({ name: `sites@${consoleId}`, path: sitesUrl, status: sitesStatus });

      if (sitesStatus !== 200) {
        if (sitesStatus === 403 || sitesStatus === 404) {
          result._errors.push({
            endpoint: `sites@${consoleId}`,
            status: sitesStatus,
            hint: 'Cloud Connector not enabled — enable in UniFi OS → System → Cloud Access',
          });
        }
        continue;
      }

      await new Promise(r => setTimeout(r, 100));
      const siteList = extractSites(sitesData);
      result._siteCount += siteList.length;

      for (const site of siteList) {
        const siteId = String(site['id'] ?? site['_id'] ?? site['name'] ?? '');
        if (!siteId) continue;
        const siteKey = `site_${consoleId}_${siteId}`;
        result[siteKey] = { _meta: { ...site, _consoleId: consoleId } };

        for (const [name, suffix] of cloudEndpoints) {
          const url = buildConnectorUrl(consoleId, siteId, suffix);
          log(`GET ${url}`);
          const { status, data } = await client.get(url);
          result._endpointsProbed.push({ name: `${name}@${consoleId}_${siteId}`, path: url, status });
          if (status === 200) (result[siteKey] as Record<string, unknown>)[name] = data;
          else result._errors.push({ endpoint: `${name}@${consoleId}_${siteId}`, status });
          await new Promise(r => setTimeout(r, 100));
        }
      }
    }
  } else {
    for (const [name, path] of GLOBAL_ENDPOINTS) {
      log(`GET ${path}`);
      const { status, data } = await client.get(path);
      result._endpointsProbed.push({ name, path, status });
      if (status === 200) result[name] = data;
      else if (status === 403) result._errors.push({ endpoint: name, status, hint: 'key lacks scope' });
    }

    // Discover which endpoints this console's Network version advertises, so we
    // request the right paths regardless of version and never 404 on a renamed
    // or not-yet-existing endpoint. Falls back to the default set if the console
    // doesn't serve its OpenAPI spec (older releases).
    let siteEndpoints: Array<[string, string]>;
    log(`GET ${INTEGRATION_SPEC_PATH}`);
    const spec = await client.get(INTEGRATION_SPEC_PATH);
    result._endpointsProbed.push({ name: 'api-docs', path: INTEGRATION_SPEC_PATH, status: spec.status });
    if (spec.status === 200) {
      siteEndpoints = resolveSiteEndpoints(parseSpecPaths(spec.data));
      log(`Discovered ${siteEndpoints.length} site endpoint(s) from the console's OpenAPI spec.`);
    } else {
      siteEndpoints = defaultSiteEndpoints();
      log(`Console OpenAPI spec unavailable (status ${spec.status}); using default endpoint set.`);
    }

    const siteList = extractSites(result['sites']);
    result._siteCount = siteList.length;

    for (const site of siteList) {
      const siteId = String(site['id'] ?? site['_id'] ?? site['name'] ?? '');
      if (!siteId) continue;
      const siteKey = `site_${siteId}`;
      result[siteKey] = { _meta: site };
      for (const [name, suffix] of siteEndpoints) {
        const path = localSitePath(suffix).replace('{id}', siteId);
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
