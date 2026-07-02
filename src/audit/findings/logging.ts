import type { Finding, NormalizedSite } from '../types.js';

const RETENTION: Record<string, { adminDays: number }> = {
  home: { adminDays: 30 }, home_office: { adminDays: 90 },
  small_business: { adminDays: 365 }, regulated_hipaa: { adminDays: 2190 }, regulated_pci: { adminDays: 365 },
};

export function findLogging(site: NormalizedSite, profile: string): Finding[] {
  const findings: Finding[] = [];
  const ret = RETENTION[profile] ?? RETENTION['home_office']!;
  const mgmt = site.settings['mgmt'] as Record<string, unknown> | undefined;

  if (mgmt === undefined) {
    findings.push({
      id: `LOG-FWD-001-${site.siteId}`, section: 'Logging', severity: 'info', status: 'unknown',
      title: 'Syslog setting: cannot check via live API',
      currentState: 'Syslog forwarding state is not exposed by the API.',
      recommendation: `Forward syslog to an external destination. Retention target: ${ret.adminDays} days.`,
      intentQuestion: 'Is syslog forwarding currently configured?',
      evidence: {}, mapsTo: { cis_v8: '8.2', nist_csf: 'DE.AE-3' }, effort: 'medium', impact: 'medium',
    });
  } else if (!mgmt['syslog_host'] && !mgmt['advanced_feature_enabled']) {
    findings.push({
      id: `LOG-FWD-001-${site.siteId}`, section: 'Logging',
      severity: profile.startsWith('home') ? 'low' : 'medium', status: 'recommendation',
      title: 'Logs not forwarded to external destination',
      currentState: 'All logs live only on the gateway. Gateway loss = log loss.',
      recommendation: `Forward syslog to an external destination. Retention target: ${ret.adminDays} days minimum.`,
      intentQuestion: 'Do you want to set up external log storage?',
      evidence: {}, mapsTo: { cis_v8: '8.2', nist_csf: 'DE.AE-3' }, effort: 'medium', impact: 'medium',
    });
  }

  const dpi = site.settings['dpi'] as Record<string, unknown> | undefined;
  if (dpi && profile.startsWith('home')) {
    const dpiLevel = String(dpi['level'] ?? 'disabled');
    if (['client', 'fingerprint'].includes(dpiLevel)) findings.push({
      id: `LOG-PRIV-001-${site.siteId}`, section: 'Logging', severity: 'low', status: 'recommendation',
      title: 'Client-level DPI logging may exceed household need',
      currentState: `DPI is set to '${dpiLevel}', retaining per-client browsing metadata.`,
      recommendation: 'Consider aggregate/protocol-only DPI for a home network.',
      intentQuestion: 'Do you actively use the per-client DPI views?',
      evidence: {}, mapsTo: { nist_csf: 'PR.DS-5' }, effort: 'quick', impact: 'low',
    });
  }

  return findings;
}
