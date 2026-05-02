import type { Finding } from '../types.js';

export function findApiCoverage(clean: Record<string, unknown>): Finding[] {
  const probed = (clean['_endpointsProbed'] ?? []) as Array<Record<string, unknown>>;
  const missing = probed.filter(p => p['status'] === 404 || p['status'] === 0);
  if (!missing.length) return [];
  return [{
    id: 'META-COVERAGE', section: 'Audit scope', severity: 'info', status: 'unknown',
    title: `${missing.length} endpoint(s) not accessible; audit scope limited`,
    currentState: `${missing.length} API endpoint(s) returned 404. The Network Integration API v1 does not yet expose WLANs, firewall policies, port forwards, VPN configs, or traffic routes — Ubiquiti is rolling these out through 2026.`,
    recommendation: 'For full coverage of these settings, use backup-file mode (Phase 4) which parses the .unf backup and sees all configuration.',
    intentQuestion: null,
    evidence: { missing: missing.map(p => p['name']) },
    mapsTo: {}, effort: 'quick', impact: 'low',
  }];
}
