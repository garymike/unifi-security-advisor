// Single source of truth for UniFi Network Integration API endpoints.
//
// The local ("hardware") API version equals the installed Network app version,
// so different consoles expose different endpoint paths (Ubiquiti renamed
// several across v9→v10, e.g. `wlans` → `wifi/broadcasts`). Rather than hardcode
// one version's paths, each concept lists its known path aliases across
// versions; at runtime we fetch the console's own OpenAPI spec and pick
// whichever alias it advertises (see discover.ts). If the spec isn't reachable
// (older console), we fall back to the default (preferred) set.

/** Global endpoints — stable across versions. `[internalKey, localPath]`. */
export const GLOBAL_ENDPOINTS: ReadonlyArray<readonly [string, string]> = [
  ['info', '/proxy/network/integration/v1/info'],
  ['sites', '/proxy/network/integration/v1/sites'],
];

export interface EndpointConcept {
  /** Known path suffixes (relative to `/v1/sites/{siteId}/`), newest first. */
  candidates: string[];
  /**
   * Whether to request this concept when discovery is unavailable. Concepts
   * with no path in any current Network version (port forwards, traffic routes
   * — still backup-only) are `false`, so the no-discovery fallback doesn't emit
   * guaranteed 404s. They stay in `candidates` so discovery still picks them up
   * if a future version starts exposing them.
   */
  liveByDefault: boolean;
}

/** Per-concept endpoint definitions, keyed by the internal result key that
 *  normalize.ts and the finding modules read. */
export const SITE_ENDPOINT_CONCEPTS: Record<string, EndpointConcept> = {
  devices:           { candidates: ['devices'], liveByDefault: true },
  clients:           { candidates: ['clients'], liveByDefault: true },
  wlans:             { candidates: ['wifi/broadcasts', 'wlans'], liveByDefault: true },
  networks:          { candidates: ['networks'], liveByDefault: true },
  firewall_policies: { candidates: ['firewall/policies', 'firewall-policies'], liveByDefault: true },
  firewall_zones:    { candidates: ['firewall/zones', 'firewall-zones'], liveByDefault: true },
  vpn_configs:       { candidates: ['vpn/servers', 'vpn-configs'], liveByDefault: true },
  port_forwards:     { candidates: ['port-forwards'], liveByDefault: false },
  traffic_routes:    { candidates: ['traffic-matching-lists', 'traffic-routes'], liveByDefault: false },
};

/** Path to the console's own OpenAPI spec (its version's endpoint catalogue). */
export const INTEGRATION_SPEC_PATH = '/proxy/network/api-docs/integration.json';

/** Site Manager (cloud) hosts endpoint — the API host, not the unifi.ui.com portal. */
export const CLOUD_HOSTS_URL = 'https://api.ui.com/v1/hosts';

/** Spec-form path (`/v1/sites/{siteId}/<suffix>`) used to match against a spec. */
export function specSitePath(suffix: string): string {
  return `/v1/sites/{siteId}/${suffix}`;
}

/** Local request path (`/proxy/.../sites/{id}/<suffix>`) for the given suffix. */
export function localSitePath(suffix: string): string {
  return `/proxy/network/integration/v1/sites/{id}/${suffix}`;
}

/**
 * The fallback endpoint set when discovery is unavailable: the preferred
 * (first) candidate of every `liveByDefault` concept, as `[internalKey, suffix]`.
 */
export function defaultSiteEndpoints(): Array<[string, string]> {
  return Object.entries(SITE_ENDPOINT_CONCEPTS)
    .filter(([, c]) => c.liveByDefault)
    .map(([key, c]) => [key, c.candidates[0]!]);
}
