import type { Finding, Severity, Status, Effort, Impact } from './types.js';

/**
 * Cross-answer tension detection: a correlation pass that runs after the
 * per-site finding modules and emits *compound* findings for dangerous
 * combinations that no single module sees. Because rules key off each finding's
 * `status` — which the wizard's mergeAnswer() rewrites from the user's intent
 * answers (yes → ok, deferred → unknown) — a compound both fires from config
 * alone and refines as the user answers. See DECISIONS.md D-003.
 */

/** Query helper over one site's findings. Matches by an id substring so it can
 *  target a prefix (`SEG-001`) or an infix (`-PSK`), optionally by status. */
class SiteFindingIndex {
  constructor(private readonly findings: Finding[]) {}

  find(idPart: string, statuses?: Status[]): Finding[] {
    return this.findings.filter(
      f => f.id.includes(idPart) && (!statuses || statuses.includes(f.status)),
    );
  }

  has(idPart: string, statuses?: Status[]): boolean {
    return this.find(idPart, statuses).length > 0;
  }
}

interface TensionRule {
  id: string;
  severity: Severity;
  effort: Effort;
  impact: Impact;
  title: string;
  mapsTo: Record<string, string>;
  /** Returns the contributing findings if the tension holds, else null. */
  detect: (idx: SiteFindingIndex) => Finding[] | null;
  currentState: string;
  recommendation: string;
}

const GAP: Status[] = ['gap'];
const GAP_OR_UNKNOWN: Status[] = ['gap', 'unknown'];
const NOT_OK: Status[] = ['gap', 'recommendation', 'unknown'];

export const TENSION_RULES: TensionRule[] = [
  {
    id: 'WAN-RCE',
    severity: 'critical',
    effort: 'quick',
    impact: 'high',
    title: 'Internet-reachable management plane running vulnerable firmware',
    mapsTo: { nist_csf: 'PR.AC-3', cis_v8: '7.5' },
    detect: idx => {
      const exposed = idx.find('SEG-MGMT-WAN', GAP);
      const vuln = idx.find('ADV-', GAP);
      return exposed.length && vuln.length ? [...exposed, ...vuln] : null;
    },
    currentState:
      'The management plane is reachable from the WAN AND a device is running firmware with a known, actively-exploited vulnerability. This is the exact precondition for remote takeover — an attacker on the internet can reach the very service that is vulnerable. Individually each is serious; together they are a direct path to full compromise.',
    recommendation:
      'Treat as an emergency: apply the firmware update now, and block management access from the WAN (disable remote access / remove the exposing rule) until it is patched.',
  },
  {
    id: 'FLAT-REMOTE',
    severity: 'high',
    effort: 'medium',
    impact: 'high',
    title: 'Flat network with an internet-exposed entry point',
    mapsTo: { nist_csf: 'PR.AC-5', cis_v8: '4.4' },
    detect: idx => {
      const flat = idx.find('SEG-001', GAP);
      const exposed = idx.find('VPN-MISSING-001', GAP);
      return flat.length && exposed.length ? [...flat, ...exposed] : null;
    },
    currentState:
      'All device classes share one flat network AND services are exposed to the internet without a VPN. An attacker who compromises the exposed service — or any single device — can then reach everything, because nothing is segmented. The exposed port is the way in; the flat network is the pivot to the rest.',
    recommendation:
      'Put a VPN in front of remote access and remove the raw port forwards, and segment IoT/guest/work devices onto separate VLANs so one foothold cannot reach the whole network.',
  },
  {
    id: 'BACKUP-RESILIENCE',
    severity: 'high',
    effort: 'quick',
    impact: 'high',
    title: 'Backups are neither redundant nor verified',
    mapsTo: { nist_csf: 'PR.IP-4', cis_v8: '11.1' },
    detect: idx => {
      const onlyGateway = idx.find('BAK-002', GAP);
      const untested = idx.find('BAK-003', GAP_OR_UNKNOWN);
      return onlyGateway.length && untested.length ? [...onlyGateway, ...untested] : null;
    },
    currentState:
      'Backups are stored only on the gateway itself AND a restore has never been verified. If the gateway fails or is compromised, there is no off-device copy to recover from, and even the on-device backup is of unproven integrity — a single failure could mean total, unrecoverable configuration loss.',
    recommendation:
      'Add an off-device backup destination (cloud or a separate host) and perform a test restore to confirm the backup actually works.',
  },
  {
    id: 'DEPRECATED-VPN-FLAT',
    severity: 'high',
    effort: 'medium',
    impact: 'high',
    title: 'Weak-crypto VPN into a flat network',
    mapsTo: { nist_csf: 'PR.AC-3', cis_v8: '4.4' },
    detect: idx => {
      const pptp = idx.find('VPN-PPTP-001', NOT_OK);
      const flat = idx.find('SEG-001', GAP);
      return pptp.length && flat.length ? [...pptp, ...flat] : null;
    },
    currentState:
      'Remote access uses a deprecated, cryptographically broken VPN (PPTP) AND the internal network is flat. PPTP credentials and traffic can be recovered by anyone on-path, and once inside there is no segmentation to contain the attacker — the weakest possible entry point opens onto the entire network.',
    recommendation:
      'Replace PPTP with WireGuard immediately, and segment the network so a remote-access compromise is contained.',
  },
  {
    id: 'EOL-VULNERABLE',
    severity: 'high',
    effort: 'project',
    impact: 'high',
    title: 'End-of-life hardware with a known vulnerability',
    mapsTo: { nist_csf: 'ID.RA-1', cis_v8: '2.2' },
    detect: idx => {
      const eol = idx.find('FW-EOL', GAP);
      const vuln = idx.find('ADV-', GAP);
      return eol.length && vuln.length ? [...eol, ...vuln] : null;
    },
    currentState:
      'A device is end-of-life AND has a known security advisory. End-of-life hardware will never receive another security update, so this vulnerability cannot be patched — the device is permanently exposed. This is not a "patch it" problem, it is a "replace it" problem.',
    recommendation:
      'Plan to replace the end-of-life device; until then, isolate it on its own VLAN and restrict its network access as much as possible.',
  },
  {
    id: 'WEAK-WIFI-FLAT',
    severity: 'high',
    effort: 'quick',
    impact: 'high',
    title: 'Weak Wi-Fi passphrase guarding a flat network',
    mapsTo: { nist_csf: 'PR.AC-5', cis_v8: '5.2' },
    detect: idx => {
      const weakPsk = idx.find('-PSK', GAP);
      const flat = idx.find('SEG-001', GAP);
      return weakPsk.length && flat.length ? [...weakPsk, ...flat] : null;
    },
    currentState:
      'A Wi-Fi network has a short, crackable passphrase AND the internal network is flat. Wi-Fi is the perimeter here, and it is both weak and undivided: an attacker who cracks the PSK from the parking lot lands directly on a network where every device is reachable.',
    recommendation:
      'Set a long (16+ character) Wi-Fi passphrase and segment the network so cracking one SSID does not expose everything.',
  },
];

/**
 * Runs every tension rule over one site's findings and returns compound
 * findings. Each references its contributing finding IDs in evidence.
 */
export function detectTensions(findings: Finding[], siteId: string): Finding[] {
  const idx = new SiteFindingIndex(findings);
  const out: Finding[] = [];
  for (const rule of TENSION_RULES) {
    const contributors = rule.detect(idx);
    if (!contributors || contributors.length === 0) continue;
    out.push({
      id: `TENSION-${rule.id}-${siteId}`,
      section: 'Compound risks',
      severity: rule.severity,
      status: 'gap',
      title: rule.title,
      currentState: rule.currentState,
      recommendation: rule.recommendation,
      intentQuestion: null,
      evidence: { contributors: contributors.map(f => f.id) },
      mapsTo: rule.mapsTo,
      effort: rule.effort,
      impact: rule.impact,
    });
  }
  return out;
}
