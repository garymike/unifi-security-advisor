/**
 * Maintainer-run tool. Not part of the shipped app or CLI, not run in CI.
 * Drafts candidate known-advisory entries from CISA KEV + NVD for a human
 * to review and hand-merge into src/audit/knownAdvisoriesData.ts. Never
 * writes to that file directly.
 *
 * Usage: npm run fetch-advisories
 * Optional: set NVD_API_KEY to raise NVD's rate limit.
 */

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  notes: string;
}

interface KevCatalog {
  vulnerabilities: KevEntry[];
}

interface NvdAffectedProduct {
  vendor: string;
  product: string;
  versions: Array<{ version: string; lessThan?: string; versionType?: string; status: string }>;
}

interface NvdCveResponse {
  vulnerabilities: Array<{
    cve: {
      id: string;
      affected?: Array<{ source: string; affectedData?: NvdAffectedProduct[] }>;
    };
  }>;
}

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

async function fetchKevForUbiquiti(): Promise<KevEntry[]> {
  const res = await fetch(KEV_URL);
  if (!res.ok) throw new Error(`CISA KEV fetch failed: ${res.status}`);
  const catalog = (await res.json()) as KevCatalog;
  return catalog.vulnerabilities.filter(v => v.vendorProject === 'Ubiquiti');
}

async function fetchNvdCve(cveId: string, apiKey?: string): Promise<NvdCveResponse> {
  const headers: Record<string, string> = apiKey ? { apiKey } : {};
  const res = await fetch(`${NVD_URL}?cveId=${cveId}`, { headers });
  if (!res.ok) throw new Error(`NVD fetch failed for ${cveId}: ${res.status}`);
  return (await res.json()) as NvdCveResponse;
}

function groupByAdvisory(entries: KevEntry[]): Map<string, KevEntry[]> {
  const groups = new Map<string, KevEntry[]>();
  for (const entry of entries) {
    const key = entry.notes.match(/https:\/\/community\.ui\.com\/releases\/\S+/)?.[0] ?? entry.dateAdded;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(entry);
  }
  return groups;
}

async function main(): Promise<void> {
  const apiKey = process.env['NVD_API_KEY'];
  const kevEntries = await fetchKevForUbiquiti();

  if (!kevEntries.length) {
    console.log('No Ubiquiti entries currently in the CISA KEV catalog.');
    return;
  }

  const groups = groupByAdvisory(kevEntries);
  for (const [advisoryUrl, entries] of groups) {
    console.log(`\n// --- Draft advisory: ${entries.map(e => e.cveID).join(', ')} ---`);
    console.log(`// Source (from KEV notes): ${advisoryUrl}`);
    for (const entry of entries) {
      await new Promise(r => setTimeout(r, apiKey ? 100 : 6000));
      const nvd = await fetchNvdCve(entry.cveID, apiKey);
      const affectedData = nvd.vulnerabilities[0]?.cve.affected?.[0]?.affectedData ?? [];
      console.log(`// ${entry.cveID}: ${entry.vulnerabilityName}`);
      if (!affectedData.length) {
        console.log('//   (no structured NVD affected-product data found — check the advisory manually)');
        continue;
      }
      for (const product of affectedData) {
        const floor = product.versions.find(v => v.status === 'affected')?.lessThan;
        console.log(`//   '${product.product.toUpperCase()}': fixed in ${floor ?? 'UNKNOWN — check NVD manually'} (NVD lessThan, exclusive) — vulnerableThrough is the last release BELOW this; confirm exact value against the bulletin before transcribing`);
      }
    }
    console.log('// Review the above against the source bulletin, then hand-add an Advisory entry to src/audit/knownAdvisoriesData.ts');
  }
}

main().catch(err => {
  console.error('fetch-advisories failed:', err);
  process.exitCode = 1;
});
