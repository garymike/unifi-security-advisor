import type { Finding, NormalizedSite } from '../types.js';
import { compareVersions } from '../compareVersions.js';
import { KNOWN_ADVISORIES, type Advisory } from '../knownAdvisoriesData.js';

interface AffectedDeviceEvidence {
  name: unknown;
  model: string;
  version: string | null;
}

export function findKnownAdvisories(
  site: NormalizedSite,
  _profile: string,
  advisories: Advisory[] = KNOWN_ADVISORIES,
): Finding[] {
  const findings: Finding[] = [];

  for (const advisory of advisories) {
    const affectedDevices: AffectedDeviceEvidence[] = [];
    let anyConfirmedGap = false;

    for (const d of site.devices) {
      const model = String(d['model'] ?? '').toUpperCase();
      const affected = advisory.affectedModels[model];
      if (!affected) continue;

      const mac = d['mac'] ?? d['macAddress'];
      const rawVersion = d['version'] ?? d['firmwareVersion'];
      const version = rawVersion === undefined || rawVersion === null ? null : String(rawVersion);

      if (version === null || !version.includes('.')) {
        affectedDevices.push({ name: d['name'] ?? mac, model, version: null });
      } else if (compareVersions(version, affected.vulnerableThrough) <= 0) {
        anyConfirmedGap = true;
        affectedDevices.push({ name: d['name'] ?? mac, model, version });
      }
      // version > vulnerableThrough: presumed patched, no entry (accepted false-negative risk)
    }

    if (!affectedDevices.length) continue;

    findings.push({
      id: `ADV-${advisory.id}-${site.siteId}`,
      section: 'Known advisories',
      severity: advisory.severity,
      status: anyConfirmedGap ? 'gap' : 'unknown',
      title: advisory.title,
      currentState: anyConfirmedGap
        ? `${affectedDevices.length} device(s) match this advisory's affected models and appear to be on a vulnerable version.`
        : `${affectedDevices.length} device(s) match this advisory's affected models, but firmware version could not be confirmed.`,
      recommendation: advisory.recommendation,
      intentQuestion: `Please confirm your UniFi OS version (Settings → System → About) against ${advisory.advisoryUrl}. Have you applied this update?`,
      evidence: { devices: affectedDevices, cves: advisory.cves, cisaKev: advisory.cisaKev },
      mapsTo: { cis_v8: '7.5', nist_csf: 'ID.RA-1' },
      effort: 'quick',
      impact: 'high',
    });
  }

  return findings;
}
