/**
 * Maintainer / CI tool. Detects "advisory data drift": Ubiquiti CVEs that are
 * on CISA's Known Exploited Vulnerabilities (KEV) catalog but not yet covered
 * by any entry in src/audit/knownAdvisoriesData.ts.
 *
 * It never edits the advisory data — it only reports drift, keeping a human in
 * the loop for the data itself (matching tools/fetch-advisories.ts). The
 * scheduled workflow (.github/workflows/advisory-drift.yml) runs this and opens
 * a GitHub issue when drift is found.
 *
 * Usage: npm run check-advisory-drift [output-report-path]
 * Exit code is always 0; drift is signalled via GITHUB_OUTPUT (in CI) and the
 * report file. Runs entirely against the public KEV feed — no API key needed.
 */
import { appendFileSync, writeFileSync } from 'node:fs';
import { KNOWN_ADVISORIES, type Advisory } from '../src/audit/knownAdvisoriesData.js';

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  notes: string;
}

interface KevCatalog {
  vulnerabilities: KevEntry[];
}

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/**
 * CVEs a maintainer has reviewed and deliberately left out of the advisory
 * data because they're out of scope for a UniFi Network audit. Without this,
 * the drift check would re-flag them forever (they stay in CISA KEV). Keep
 * each with a dated rationale.
 */
export const ACKNOWLEDGED_CVES: Record<string, string> = {
  'CVE-2010-5330':
    'AirOS (airMAX/airFiber) command injection. Not a UniFi Network product — ' +
    'these devices do not report a device.model in UniFi Network, so the ' +
    'findKnownAdvisories check could never match them. Reviewed 2026-07-03.',
};

/**
 * Returns the KEV CVE IDs (in their original casing) that do not appear,
 * case-insensitively, in any advisory's `cves` array, and are not in the
 * acknowledged-out-of-scope set.
 */
export function findUncoveredKevCves(
  kevCveIds: string[],
  advisories: Advisory[],
  acknowledged: Iterable<string> = [],
): string[] {
  const covered = new Set<string>();
  for (const advisory of advisories) {
    for (const cve of advisory.cves) covered.add(cve.toUpperCase());
  }
  for (const cve of acknowledged) covered.add(cve.toUpperCase());
  return kevCveIds.filter(id => !covered.has(id.toUpperCase()));
}

async function fetchUbiquitiKev(): Promise<KevEntry[]> {
  const res = await fetch(KEV_URL);
  if (!res.ok) throw new Error(`CISA KEV fetch failed: ${res.status}`);
  const catalog = (await res.json()) as KevCatalog;
  return catalog.vulnerabilities.filter(v => v.vendorProject === 'Ubiquiti');
}

function renderReport(uncovered: KevEntry[]): string {
  if (!uncovered.length) {
    return `# Advisory data drift check\n\nNo drift: every Ubiquiti CVE in the CISA KEV catalog is already covered by \`src/audit/knownAdvisoriesData.ts\`.\n`;
  }
  const rows = uncovered
    .map(e => {
      const url = e.notes.match(/https:\/\/\S+/)?.[0] ?? '';
      return `| ${e.cveID} | ${e.vulnerabilityName} | ${e.dateAdded} | ${e.dueDate} | ${url} |`;
    })
    .join('\n');
  return [
    '# Advisory data drift: uncovered Ubiquiti KEV CVEs',
    '',
    `${uncovered.length} Ubiquiti CVE(s) are on the CISA Known Exploited Vulnerabilities catalog but are **not** covered by any entry in \`src/audit/knownAdvisoriesData.ts\`:`,
    '',
    '| CVE | Name | KEV added | Due date | Bulletin |',
    '| --- | --- | --- | --- | --- |',
    rows,
    '',
    '## What to do',
    '',
    '1. Run `npm run fetch-advisories` to draft entries from KEV + NVD.',
    '2. Review each against the linked bulletin (confirm affected models and the exact `vulnerableThrough` floor).',
    '3. Hand-add an `Advisory` to `src/audit/knownAdvisoriesData.ts` and bump `ADVISORIES_LAST_REVIEWED`.',
    '4. See `docs/09-advisory-data-maintenance.md` for the full runbook.',
    '',
  ].join('\n');
}

async function main(): Promise<void> {
  const outputPath = process.argv[2] ?? 'advisory-drift-report.md';
  const kev = await fetchUbiquitiKev();
  const uncoveredIds = findUncoveredKevCves(
    kev.map(e => e.cveID),
    KNOWN_ADVISORIES,
    Object.keys(ACKNOWLEDGED_CVES),
  );
  const uncovered = kev.filter(e => uncoveredIds.includes(e.cveID));

  const report = renderReport(uncovered);
  writeFileSync(outputPath, report);

  if (uncovered.length) {
    console.log(`DRIFT: ${uncovered.length} uncovered Ubiquiti KEV CVE(s): ${uncoveredIds.join(', ')}`);
  } else {
    console.log(`No drift: all ${kev.length} Ubiquiti KEV CVE(s) are covered.`);
  }

  const ghOutput = process.env['GITHUB_OUTPUT'];
  if (ghOutput) {
    appendFileSync(ghOutput, `drift=${uncovered.length > 0}\ncount=${uncovered.length}\n`);
  }
}

// Only run when executed directly (tsx tools/check-advisory-drift.ts), not when
// imported for findUncoveredKevCves (e.g. by the test suite).
if (process.argv[1]) {
  const { pathToFileURL } = await import('node:url');
  if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    main().catch(err => {
      console.error('check-advisory-drift failed:', err);
      process.exitCode = 1;
    });
  }
}
