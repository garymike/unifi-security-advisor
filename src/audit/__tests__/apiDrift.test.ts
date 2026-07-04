import { describe, it, expect } from 'vitest';
import {
  toSpecPath,
  findMissingEndpoints,
  EXPECTED_ENDPOINTS,
} from '../../../tools/check-api-drift.js';

describe('toSpecPath', () => {
  it('strips the local proxy prefix and rewrites the site placeholder', () => {
    expect(toSpecPath('/proxy/network/integration/v1/sites/{id}/devices')).toBe(
      '/v1/sites/{siteId}/devices',
    );
    expect(toSpecPath('/proxy/network/integration/v1/info')).toBe('/v1/info');
  });
});

describe('EXPECTED_ENDPOINTS', () => {
  it('is derived from the app collect inventory in spec form', () => {
    expect(EXPECTED_ENDPOINTS).toContain('/v1/info');
    expect(EXPECTED_ENDPOINTS).toContain('/v1/sites');
    expect(EXPECTED_ENDPOINTS).toContain('/v1/sites/{siteId}/devices');
    // No leftover proxy prefix or {id} placeholder should survive.
    expect(EXPECTED_ENDPOINTS.every(p => p.startsWith('/v1/'))).toBe(true);
    expect(EXPECTED_ENDPOINTS.some(p => p.includes('{id}'))).toBe(false);
  });
});

describe('findMissingEndpoints', () => {
  it('returns empty when every app endpoint is present in the spec', () => {
    const spec = ['/v1/info', '/v1/sites', '/v1/sites/{siteId}/devices'];
    const expected = ['/v1/info', '/v1/sites/{siteId}/devices'];
    expect(findMissingEndpoints(expected, spec)).toEqual([]);
  });

  it('flags an app endpoint that is absent from the spec', () => {
    const spec = ['/v1/sites/{siteId}/wifi/broadcasts'];
    const expected = ['/v1/sites/{siteId}/wlans', '/v1/sites/{siteId}/wifi/broadcasts'];
    expect(findMissingEndpoints(expected, spec)).toEqual(['/v1/sites/{siteId}/wlans']);
  });
});
