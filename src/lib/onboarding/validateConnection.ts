import { parseApplicationVersion } from '../../audit/apiVersion.js';
import { extractSites } from '../../audit/collect.js';
import { GLOBAL_ENDPOINTS, CLOUD_HOSTS_URL } from '../../audit/endpoints.js';

export type ValidationErrorKind = 'auth' | 'unreachable' | 'mode-mismatch' | 'unknown';
export interface ValidationError { kind: ValidationErrorKind; message: string }
export interface ValidationResult {
  ok: boolean;
  consoleName?: string;
  model?: string;
  networkVersion?: string;
  sites?: { id: string; name: string }[];
  error?: ValidationError;
}
export interface Fetcher {
  config: { useCloud: boolean; host: string };
  get(path: string): Promise<{ status: number; data: unknown }>;
}

const AUTH_MSG = 'Key rejected — check you pasted the whole key. It may be expired or the wrong type for this mode.';
const UNKNOWN_MSG = (status: number) => `Unexpected response from the console (${status}). Try again, or check the console is a supported UniFi Network version.`;
const unreachableMsg = (host: string) => `Couldn't reach ${host || 'the controller'} — is the console on this network and the IP correct?`;

function err(kind: ValidationErrorKind, message: string): ValidationResult {
  return { ok: false, error: { kind, message } };
}

function sitesFrom(data: unknown): { id: string; name: string }[] {
  return extractSites(data).map((s) => ({
    id: String(s['id'] ?? s['_id'] ?? s['hostId'] ?? s['name'] ?? ''),
    name: String(s['name'] ?? s['hostname'] ?? s['id'] ?? 'site'),
  }));
}

function pathFor(key: string): string {
  const found = GLOBAL_ENDPOINTS.find(([k]) => k === key);
  if (!found) throw new Error(`missing endpoint: ${key}`);
  return found[1];
}

export async function validateConnection(client: Fetcher): Promise<ValidationResult> {
  const { useCloud, host } = client.config;

  if (!useCloud && /ui\.com/i.test(host)) {
    return err('mode-mismatch', 'That looks like a cloud address — switch to Cloud (Site Manager) mode?');
  }

  try {
    if (useCloud) {
      const res = await client.get(CLOUD_HOSTS_URL);
      if (res.status === 401 || res.status === 403) return err('auth', AUTH_MSG);
      if (res.status === 0) return err('unreachable', unreachableMsg('the Site Manager API'));
      if (res.status !== 200) return err('unknown', UNKNOWN_MSG(res.status));
      const sites = sitesFrom(res.data);
      return { ok: true, sites };
    }

    const info = await client.get(pathFor('info'));
    if (info.status === 401 || info.status === 403) return err('auth', AUTH_MSG);
    if (info.status === 0) return err('unreachable', unreachableMsg(host));
    if (info.status !== 200) return err('unknown', UNKNOWN_MSG(info.status));

    const infoObj = (info.data ?? {}) as Record<string, unknown>;
    const networkVersion = parseApplicationVersion(info.data) ?? undefined;
    const consoleName = typeof infoObj['name'] === 'string' ? (infoObj['name'] as string)
      : typeof infoObj['hostname'] === 'string' ? (infoObj['hostname'] as string) : undefined;
    const model = typeof infoObj['model'] === 'string' ? (infoObj['model'] as string)
      : typeof infoObj['hardwareRevision'] === 'string' ? (infoObj['hardwareRevision'] as string) : undefined;

    const sitesRes = await client.get(pathFor('sites'));
    const sites = sitesRes.status === 200 ? sitesFrom(sitesRes.data) : [];

    return { ok: true, consoleName, model, networkVersion, sites };
  } catch {
    return err('unreachable', unreachableMsg(useCloud ? 'the Site Manager API' : host));
  }
}
