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
 * Model version floors below sourced from the CISA Singapore alert
 * (al-2026-059), which aggregates CISA KEV + vendor advisory data for
 * this bulletin. Only physical gateway/console models that appear in
 * UniFi Network's own device list are included — UniFi OS Server,
 * standalone Express, and UNAS-series entries from the source advisory
 * are omitted here since their `device.model` string conventions in
 * the Network app aren't confirmed; add them once verified.
 */
export const KNOWN_ADVISORIES: Advisory[] = [
  {
    id: 'CVE-2026-34908-9-10',
    title: 'UniFi OS unauthenticated RCE chain (access control + path traversal + command injection)',
    severity: 'critical',
    cves: ['CVE-2026-34908', 'CVE-2026-34909', 'CVE-2026-34910'],
    cisaKev: true,
    affectedModels: {
      'UDM': { vulnerableThrough: '5.0.16' },
      'UDM-PRO': { vulnerableThrough: '5.0.16' },
      'UDM-SE': { vulnerableThrough: '5.0.16' },
      'UDM-PRO-MAX': { vulnerableThrough: '5.0.16' },
      'UDW': { vulnerableThrough: '5.0.16' },
      'UDR': { vulnerableThrough: '5.0.16' },
      'UDR7': { vulnerableThrough: '5.0.16' },
      'UCG-ULTRA': { vulnerableThrough: '5.0.16' },
      'UCG-MAX': { vulnerableThrough: '5.0.16' },
      'UCG-FIBER': { vulnerableThrough: '5.0.16' },
      'UDR-5G': { vulnerableThrough: '5.0.17' },
      'UCK': { vulnerableThrough: '5.0.17' },
      'UCK-ENTERPRISE': { vulnerableThrough: '5.0.17' },
      'UDM-BEAST': { vulnerableThrough: '5.1.8' },
    },
    recommendation: 'Update UniFi OS immediately. This chain is on CISA\'s Known Exploited Vulnerabilities catalog (added 2026-06-23) and was under a federal emergency patching directive due 2026-06-26. If you cannot confirm your UniFi OS build number is past the affected range, treat this as urgent.',
    advisoryUrl: 'https://community.ui.com/releases/Security-Advisory-Bulletin-066-066/984eceb3-49c8-4227-942d-671c289b3afc',
  },
];
