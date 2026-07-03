/**
 * Maintainer / CI tool. Detects "API drift": UniFi Network Integration API
 * endpoints this app calls that no longer exist in the latest published
 * OpenAPI spec. Ubiquiti has renamed/restructured endpoints across Network app
 * versions (e.g. `wlans` → `wifi/broadcasts` in v10), which silently turns our
 * requests into 404s. This surfaces that before users hit it.
 *
 * It compares the app's real endpoint set (imported from src/audit/collect.ts)
 * against the newest `network/<version>/openapi.json` in the community mirror
 * github.com/opastorello/unifi-api-docs, and reports any of our paths missing
 * from it, plus whether the mirror's version exceeds our tested ceiling.
 *
 * Read-only; never edits code. The scheduled workflow (.github/workflows/
 * api-drift.yml) runs this and opens a GitHub issue on drift.
 *
 * Usage: npm run check-api-drift [output-report-path]
 */
import { appendFileSync, writeFileSync } from 'node:fs';
import { LOCAL_GLOBAL, SITE_SCOPED } from '../src/audit/collect.js';
import { TESTED_MAX } from '../src/audit/apiVersion.js';
import { compareVersions } from '../src/audit/compareVersions.js';

const MIRROR_API = 'https://api.github.com/repos/opastorello/unifi-api-docs/contents/network';
const MIRROR_RAW = 'https://raw.githubusercontent.com/opastorello/unifi-api-docs/main/network';

/**
 * Normalises an app request path to the `/v1/...{siteId}` form the OpenAPI
 * spec uses: strips the local proxy prefix and rewrites our `{id}` placeholder.
 */
export function toSpecPath(appPath: string): string {
  return appPath.replace('/proxy/network/integration', '').replace('{id}', '{siteId}');
}

/** The exact set of Integration API paths the app collects, in spec form. */
export const EXPECTED_ENDPOINTS: string[] = [
  ...LOCAL_GLOBAL.map(([, p]) => toSpecPath(p)),
  ...SITE_SCOPED.map(([, p]) => toSpecPath(p)),
];

/** App paths absent from the spec's path set (i.e. the app will 404 on them). */
export function findMissingEndpoints(expected: string[], specPaths: string[]): string[] {
  const present = new Set(specPaths);
  return expected.filter(e => !present.has(e));
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

function renderReport(version: string, missing: string[], newerThanTested: boolean): string {
  if (!missing.length && !newerThanTested) {
    return `# API drift check\n\nNo drift: all ${EXPECTED_ENDPOINTS.length} endpoints the app calls are present in the latest UniFi Network OpenAPI spec (v${version}), which is within the tested range (≤ ${TESTED_MAX}).\n`;
  }
  const lines = ['# UniFi API drift', ''];
  if (missing.length) {
    lines.push(
      `${missing.length} endpoint(s) the app calls are **absent** from the latest UniFi Network OpenAPI spec (v${version}) — requests to these will 404:`,
      '',
      ...missing.map(m => `- \`${m}\``),
      '',
      'These need remapping to their current paths in `src/audit/collect.ts` (see `docs/superpowers/specs/2026-07-03-api-currency-design.md`, Component C).',
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
  const missing = findMissingEndpoints(EXPECTED_ENDPOINTS, paths);
  const newerThanTested = compareVersions(version, TESTED_MAX) > 0;
  const drift = missing.length > 0 || newerThanTested;

  writeFileSync(outputPath, renderReport(version, missing, newerThanTested));

  if (missing.length) {
    console.log(`DRIFT: ${missing.length} app endpoint(s) missing from spec v${version}: ${missing.join(', ')}`);
  } else {
    console.log(`Endpoints OK against spec v${version}.`);
  }
  if (newerThanTested) console.log(`Spec v${version} is newer than TESTED_MAX ${TESTED_MAX}.`);

  const ghOutput = process.env['GITHUB_OUTPUT'];
  if (ghOutput) appendFileSync(ghOutput, `drift=${drift}\nmissing=${missing.length}\nlatest=${version}\n`);
}

// Only run when executed directly, not when imported for the pure helpers.
if (process.argv[1]) {
  const { pathToFileURL } = await import('node:url');
  if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    main().catch(err => {
      console.error('check-api-drift failed:', err);
      process.exitCode = 1;
    });
  }
}
