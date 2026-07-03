import { compareVersions } from './compareVersions.js';

/**
 * The UniFi Network application version range this tool has been verified
 * against. TESTED_MIN is the earliest version exposing the Integration API;
 * TESTED_MAX is the latest version whose OpenAPI spec the endpoint set was
 * checked against. The schema-drift check (tools/check-api-drift.ts) keeps
 * TESTED_MAX honest by flagging when Ubiquiti publishes a newer spec.
 */
export const TESTED_MIN = '9.0.0';
export const TESTED_MAX = '10.3.58';

export type VersionStatus = 'ok' | 'newer-than-tested' | 'older-than-min' | 'unknown';

export interface VersionAssessment {
  version: string | null;
  status: VersionStatus;
  message: string;
}

/**
 * Pulls the `applicationVersion` string from a `/v1/info` response, tolerating
 * both the bare `{ applicationVersion }` shape and a `{ data: { ... } }`
 * envelope. Returns null when absent (e.g. backup or cloud mode, where /info
 * isn't collected).
 */
export function parseApplicationVersion(info: unknown): string | null {
  if (info === null || typeof info !== 'object') return null;
  const obj = info as Record<string, unknown>;
  const direct = obj['applicationVersion'];
  if (typeof direct === 'string' && direct.length > 0) return direct;
  const data = obj['data'];
  if (data !== null && typeof data === 'object') {
    const nested = (data as Record<string, unknown>)['applicationVersion'];
    if (typeof nested === 'string' && nested.length > 0) return nested;
  }
  return null;
}

/** Classifies a controller version against the tested range. */
export function assessVersion(version: string | null): VersionAssessment {
  if (!version || !/\d+\.\d+/.test(version)) {
    return {
      version: version ?? null,
      status: 'unknown',
      message: 'Controller version could not be determined from /v1/info.',
    };
  }
  if (compareVersions(version, TESTED_MIN) < 0) {
    return {
      version,
      status: 'older-than-min',
      message: `UniFi Network ${version} is older than ${TESTED_MIN}, the earliest version with the Integration API. Live-API findings may be unavailable — prefer backup-file mode.`,
    };
  }
  if (compareVersions(version, TESTED_MAX) > 0) {
    return {
      version,
      status: 'newer-than-tested',
      message: `UniFi Network ${version} is newer than ${TESTED_MAX}, the latest version this tool was verified against. Endpoint paths or response shapes may have changed — verify firewall/WLAN/VPN findings, and check for a tool update.`,
    };
  }
  return {
    version,
    status: 'ok',
    message: `UniFi Network ${version} is within the tested range (${TESTED_MIN}–${TESTED_MAX}).`,
  };
}
