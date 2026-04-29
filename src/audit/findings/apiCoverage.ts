import type { Finding } from '../types.js';

export function findApiCoverage(clean: Record<string, unknown>): Finding[] {
  const probed = (clean['_endpointsProbed'] ?? []) as Array<Record<string, unknown>>;
  const missing = probed.filter(p => p['status'] === 404 || p['status'] === 0);
  if (!missing.length) return [];
  return [{
    id: 'META-COVERAGE', section: 'Audit scope', severity: 'info', status: 'unknown',
    title: `${missing.length} endpoint(s) not accessible; audit scope limited`,
    currentState: `${missing.length} API endpoints returned 404 or failed. May be due to Network version (need 9.3.43+) or API scope.`,
    recommendation: 'Update UniFi Network to latest stable.',
    intentQuestion: null,
    evidence: { missing: missing.map(p => p['name']) },
    mapsTo: {}, effort: 'quick', impact: 'low',
  }];
}
