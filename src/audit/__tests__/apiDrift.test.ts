import { describe, it, expect } from 'vitest';
import { findDriftedConcepts } from '../../../tools/check-api-drift.js';
import { SITE_ENDPOINT_CONCEPTS, specSitePath } from '../endpoints.js';

/** A spec path set where every concept's preferred candidate is advertised. */
function fullSpec(): string[] {
  const paths = ['/v1/info', '/v1/sites'];
  for (const c of Object.values(SITE_ENDPOINT_CONCEPTS)) paths.push(specSitePath(c.candidates[0]!));
  return paths;
}

describe('findDriftedConcepts', () => {
  it('reports no drift when every relied-on concept has a candidate present', () => {
    expect(findDriftedConcepts(fullSpec())).toEqual([]);
  });

  it('flags a concept whose aliases have all vanished from the spec', () => {
    const spec = fullSpec().filter(
      p => p !== specSitePath('wifi/broadcasts') && p !== specSitePath('wlans'),
    );
    expect(findDriftedConcepts(spec)).toContain('wlans');
  });

  it('does not flag backup-only concepts (port_forwards / traffic_routes)', () => {
    const spec = fullSpec().filter(p => !p.includes('port-forward') && !p.includes('traffic'));
    const drifted = findDriftedConcepts(spec);
    expect(drifted).not.toContain('port_forwards');
    expect(drifted).not.toContain('traffic_routes');
  });

  it('flags a missing global endpoint', () => {
    const spec = fullSpec().filter(p => p !== '/v1/info');
    expect(findDriftedConcepts(spec)).toContain('/v1/info');
  });
});
