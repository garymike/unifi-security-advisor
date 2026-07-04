import { describe, it, expect } from 'vitest';
import { parseSpecPaths, resolveSiteEndpoints } from '../discover.js';
import { specSitePath } from '../endpoints.js';

describe('parseSpecPaths', () => {
  it('extracts the path keys from an OpenAPI document', () => {
    expect(parseSpecPaths({ paths: { '/v1/info': {}, '/v1/sites': {} } })).toEqual(
      new Set(['/v1/info', '/v1/sites']),
    );
  });

  it('returns an empty set for anything without a paths object', () => {
    expect(parseSpecPaths(null).size).toBe(0);
    expect(parseSpecPaths({}).size).toBe(0);
    expect(parseSpecPaths('nope').size).toBe(0);
  });
});

describe('resolveSiteEndpoints', () => {
  it('picks the advertised alias, preferring the newer one (v10 wifi/broadcasts)', () => {
    const advertised = new Set([
      specSitePath('wifi/broadcasts'),
      specSitePath('wlans'),
      specSitePath('devices'),
    ]);
    const map = Object.fromEntries(resolveSiteEndpoints(advertised));
    expect(map['wlans']).toBe('wifi/broadcasts');
    expect(map['devices']).toBe('devices');
  });

  it('falls back to an older alias when only it is advertised (v9-style console)', () => {
    const map = Object.fromEntries(resolveSiteEndpoints(new Set([specSitePath('wlans')])));
    expect(map['wlans']).toBe('wlans');
  });

  it('omits concepts the console does not advertise (so we never 404 on them)', () => {
    const keys = resolveSiteEndpoints(new Set([specSitePath('devices')])).map(([k]) => k);
    expect(keys).toEqual(['devices']);
  });

  it('picks up a concept automatically if a future version starts advertising it', () => {
    // port-forwards is backup-only today, but discovery adopts it the moment a
    // console exposes it — no code change needed.
    const map = Object.fromEntries(resolveSiteEndpoints(new Set([specSitePath('port-forwards')])));
    expect(map['port_forwards']).toBe('port-forwards');
  });
});
