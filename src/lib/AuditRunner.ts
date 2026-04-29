import { UniFiClient } from '../audit/client.js';
import { collectAll } from '../audit/collect.js';
import { sanitize } from '../audit/sanitize.js';
import { normalizeApi } from '../audit/normalize.js';
import { analyze } from '../audit/analyze.js';
import { inferProfile } from '../wizard/profileInfer.js';
import type { Finding, NormalizedSite } from '../audit/types.js';

export interface AuditRunResult {
  findings: Finding[];
  sites: NormalizedSite[];
  inferredProfile: string;
}

export async function runAudit(
  apiKey: string,
  host: string,
  useCloud: boolean,
  onProgress: (msg: string) => void,
): Promise<AuditRunResult> {
  const client = new UniFiClient({
    key: apiKey, host, useCloud,
    verifySSL: useCloud,
    profile: 'home_office',
  });

  onProgress('Connecting to controller...');
  const raw = await collectAll(client, onProgress);

  onProgress('Sanitizing data...');
  const clean = sanitize(raw) as Record<string, unknown>;

  onProgress('Normalizing site data...');
  const sitesRaw = normalizeApi(clean, 'home_office');
  const inferredProfile = inferProfile(sitesRaw);
  const sites = normalizeApi(clean, inferredProfile);

  onProgress('Running findings analysis...');
  const findings = analyze(sites, clean, inferredProfile, (mod, site, err) => {
    onProgress(`Warning: module ${mod} failed on ${site}: ${err}`);
  });

  onProgress('Done.');
  return { findings, sites, inferredProfile };
}
