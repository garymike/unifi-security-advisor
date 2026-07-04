/**
 * Maintainer / CI tool. Detects "API drift": an endpoint concept the app relies
 * on for which NONE of its known path aliases exist in the latest published
 * UniFi Network OpenAPI spec — i.e. Ubiquiti renamed it to something we don't
 * recognise yet, so runtime discovery (src/audit/discover.ts) can no longer
 * find it. Also flags when the published spec is newer than our tested ceiling.
 *
 * Concept/alias definitions live in src/audit/endpoints.ts (the same source of
 * truth discovery uses). This compares against the newest
 * network/<version>/openapi.json in github.com/opastorello/unifi-api-docs.
 *
 * Read-only; never edits code. The scheduled workflow (.github/workflows/
 * api-drift.yml) runs this and opens a GitHub issue on drift.
 *
 * Usage: npm run check-api-drift [output-report-path]
 */
import { appendFileSync, writeFileSync } from 'node:fs';
import {
  GLOBAL_ENDPOINTS,
  SITE_ENDPOINT_CONCEPTS,
  specSitePath,
} from '../src/audit/endpoints.js';
import { TESTED_MAX } from '../src/audit/apiVersion.js';
import { compareVersions } from '../src/audit/compareVersions.js';

const MIRROR_API = 'https://api.github.com/repos/opastorello/unifi-api-docs/contents/network';
const MIRROR_RAW = 'https://raw.githubusercontent.com/opastorello/unifi-api-docs/main/network';

/** Local global endpoint paths normalised to spec form (`/v1/...`). */
function globalSpecPaths(): string[] {
  return GLOBAL_ENDPOINTS.map(([, p]) => p.replace('/proxy/network/integration', ''));
}

/**
 * Endpoint concepts (and global endpoints) for which the spec advertises none
 * of the known aliases — the app can no longer discover them. Only concepts we
 * actually rely on (`liveByDefault`) are checked; backup-only concepts
 * (port forwards, traffic routes) are exempt since we don't expect them live.
 */
export function findDriftedConcepts(specPaths: Iterable<string>): string[] {
  const present = new Set(specPaths);
  const drifted: string[] = [];

  for (const p of globalSpecPaths()) {
    if (!present.has(p)) drifted.push(p);
  }
  for (const [key, concept] of Object.entries(SITE_ENDPOINT_CONCEPTS)) {
    if (!concept.liveByDefault) continue;
    const anyPresent = concept.candidates.some(suffix => present.has(specSitePath(suffix)));
    if (!anyPresent) drifted.push(key);
  }
  return drifted;
}

function pickLatestVersion(names: string[]): string | null {
  const versions = names
    .filter(n => /^v\d+\.\d+\.\d+$/.test(n))
    .map(n => n.slice(1))
    .sort(compareVersions);
  return versions.length ? versions[versions.length - 1]! : null;
}

async function fetchLatestSpec(): Promise<{ version: string; paths: string[] }> {
  const token = process.env['GITHUB_TOKEN'];
  const headers: Record<string, string> = { Accept: 'application/vnd.github+json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const listRes = await fetch(MIRROR_API, { headers });
  if (!listRes.ok) throw new Error(`mirror listing failed: ${listRes.status}`);
  const entries = (await listRes.json()) as Array<{ name: string }>;
  const version = pickLatestVersion(entries.map(e => e.name));
  if (!version) throw new Error('no versioned specs found in mirror');

  const specRes = await fetch(`${MIRROR_RAW}/v${version}/openapi.json`);
  if (!specRes.ok) throw new Error(`spec fetch failed for v${version}: ${specRes.status}`);
  const spec = (await specRes.json()) as { paths?: Record<string, unknown> };
  return { version, paths: Object.keys(spec.paths ?? {}) };
}

function renderReport(version: string, drifted: string[], newerThanTested: boolean): string {
  if (!drifted.length && !newerThanTested) {
    return `# API drift check\n\nNo drift: every endpoint concept the app relies on has a known path in the latest UniFi Network OpenAPI spec (v${version}), which is within the tested range (≤ ${TESTED_MAX}).\n`;
  }
  const lines = ['# UniFi API drift', ''];
  if (drifted.length) {
    lines.push(
      `${drifted.length} endpoint(s) the app relies on have **no known path** in the latest UniFi Network OpenAPI spec (v${version}) — none of their aliases matched, so runtime discovery can't find them:`,
      '',
      ...drifted.map(d => {
        const concept = SITE_ENDPOINT_CONCEPTS[d];
        return concept ? `- \`${d}\` (tried: ${concept.candidates.join(', ')})` : `- \`${d}\``;
      }),
      '',
      'Add the new alias to the relevant concept in `src/audit/endpoints.ts` (see `docs/superpowers/specs/2026-07-03-api-currency-design.md`).',
      '',
    );
  }
  if (newerThanTested) {
    lines.push(
      `The latest published spec is **v${version}**, newer than this tool's tested ceiling (\`TESTED_MAX = ${TESTED_MAX}\` in \`src/audit/apiVersion.ts\`). Review the diff and bump \`TESTED_MAX\` once verified.`,
      '',
    );
  }
  return lines.join('\n');
}

async function main(): Promise<void> {
  const outputPath = process.argv[2] ?? 'api-drift-report.md';
  const { version, paths } = await fetchLatestSpec();
  const drifted = findDriftedConcepts(paths);
  const newerThanTested = compareVersions(version, TESTED_MAX) > 0;
  const drift = drifted.length > 0 || newerThanTested;

  writeFileSync(outputPath, renderReport(version, drifted, newerThanTested));

  if (drifted.length) console.log(`DRIFT: ${drifted.length} concept(s) with no known path in spec v${version}: ${drifted.join(', ')}`);
  else console.log(`Endpoints OK against spec v${version}.`);
  if (newerThanTested) console.log(`Spec v${version} is newer than TESTED_MAX ${TESTED_MAX}.`);

  const ghOutput = process.env['GITHUB_OUTPUT'];
  if (ghOutput) appendFileSync(ghOutput, `drift=${drift}\ndrifted=${drifted.length}\nlatest=${version}\n`);
}

// Only run when executed directly, not when imported for the pure helper.
if (process.argv[1]) {
  const { pathToFileURL } = await import('node:url');
  if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    main().catch(err => {
      console.error('check-api-drift failed:', err);
      process.exitCode = 1;
    });
  }
}
