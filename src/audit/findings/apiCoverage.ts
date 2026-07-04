import type { Finding } from '../types.js';

export function findApiCoverage(clean: Record<string, unknown>): Finding[] {
  const probed = (clean['_endpointsProbed'] ?? []) as Array<Record<string, unknown>>;
  const missing = probed.filter(p => p['status'] === 404 || p['status'] === 0);
  if (!missing.length) return [];
  return [{
    id: 'META-COVERAGE', section: 'Audit scope', severity: 'info', status: 'unknown',
    title: `${missing.length} endpoint(s) not accessible; audit scope limited`,
    currentState: `${missing.length} API endpoint(s) returned 404 on this controller. As of Network v10 the Integration API exposes devices, clients, networks, WLANs, firewall policies/zones, and VPN servers; port forwards and traffic routes are still not exposed and remain backup-only.`,
    recommendation: 'For settings the live API does not expose (e.g. port forwards), use backup-file mode which parses the .unf/.unifi backup and sees all configuration.',
    intentQuestion: null,
    evidence: { missing: missing.map(p => p['name']) },
    mapsTo: {}, effort: 'quick', impact: 'low',
  }];
}
