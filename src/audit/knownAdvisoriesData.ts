import type { Severity } from './types.js';

export interface AffectedModel {
  /** Last known-vulnerable version (inclusive). Anything <= this is affected. */
  vulnerableThrough: string;
}

export interface Advisory {
  id: string;
  title: string;
  severity: Severity;
  cves: string[];
  cisaKev: boolean;
  affectedModels: Record<string, AffectedModel>;
  recommendation: string;
  advisoryUrl: string;
}

/**
 * Model version floors below are sourced from live NVD CVE API data
 * (captured via `tools/fetch-advisories.ts`; see
 * `.superpowers/sdd/task-6-report.md` for the raw run), which is wider
 * and more authoritative than the earlier CSA Singapore alert
 * (al-2026-059) estimate this data previously used. NVD reports each
 * affected product's `lessThan` value — the exclusive first-fixed
 * version. We record that same value as our inclusive
 * `vulnerableThrough` floor, a deliberate one-version conservative
 * overshoot (treats the fix version itself as still-vulnerable) rather
 * than a data-entry mistake, consistent with this project's
 * false-positives-over-false-negatives stance for this feature.
 *
 * Only physical gateway/console/NVR/NAS models that appear in UniFi
 * Network's own device list are included — "UniFi OS Server" is
 * omitted since it's standalone software, not a physical device
 * reporting a `device.model` string the same way; add it once its
 * reporting convention is confirmed.
 */
export const KNOWN_ADVISORIES: Advisory[] = [
  {
    id: 'CVE-2026-34908-9-10',
    title: 'UniFi OS unauthenticated RCE chain (access control + path traversal + command injection)',
    severity: 'critical',
    cves: ['CVE-2026-34908', 'CVE-2026-34909', 'CVE-2026-34910'],
    cisaKev: true,
    affectedModels: {
      'UDM': { vulnerableThrough: '5.1.12' },
      'UDM-PRO': { vulnerableThrough: '5.1.12' },
      'UDM-SE': { vulnerableThrough: '5.1.12' },
      'UDM-PRO-MAX': { vulnerableThrough: '5.1.12' },
      'UDM-BEAST': { vulnerableThrough: '5.1.11' },
      'EFG': { vulnerableThrough: '5.1.12' },
      'UDW': { vulnerableThrough: '5.1.12' },
      'UDR': { vulnerableThrough: '5.1.12' },
      'UDR7': { vulnerableThrough: '5.1.12' },
      'UDR-5G': { vulnerableThrough: '5.1.12' },
      'EXPRESS': { vulnerableThrough: '4.0.14' },
      'EXPRESS 7': { vulnerableThrough: '5.1.12' },
      'UNVR': { vulnerableThrough: '5.1.12' },
      'UNVR-PRO': { vulnerableThrough: '5.1.12' },
      'UNVR-INSTANT': { vulnerableThrough: '5.1.12' },
      'UNVR-G2': { vulnerableThrough: '5.1.12' },
      'UNVR-G2-PRO': { vulnerableThrough: '5.1.12' },
      'ENVR': { vulnerableThrough: '5.1.12' },
      'ENVR-CORE': { vulnerableThrough: '5.1.12' },
      'UNAS-2': { vulnerableThrough: '5.1.10' },
      'UNAS-4': { vulnerableThrough: '5.1.10' },
      'UNAS-PRO': { vulnerableThrough: '5.1.10' },
      'UNAS-PRO-4': { vulnerableThrough: '5.1.10' },
      'UNAS-PRO-8': { vulnerableThrough: '5.1.10' },
      'UCKP': { vulnerableThrough: '5.1.12' },
      'UCK': { vulnerableThrough: '5.1.12' },
      'UCK-ENTERPRISE': { vulnerableThrough: '5.1.12' },
      'UCG-ULTRA': { vulnerableThrough: '5.1.12' },
      'UCG-MAX': { vulnerableThrough: '5.1.12' },
      'UCG-FIBER': { vulnerableThrough: '5.1.12' },
      'UCG-INDUSTRIAL': { vulnerableThrough: '5.1.12' },
    },
    recommendation: 'Update UniFi OS immediately. This chain is on CISA\'s Known Exploited Vulnerabilities catalog (added 2026-06-23) and was under a federal emergency patching directive due 2026-06-26. If you cannot confirm your UniFi OS build number is past the affected range, treat this as urgent.',
    advisoryUrl: 'https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b',
  },
];
