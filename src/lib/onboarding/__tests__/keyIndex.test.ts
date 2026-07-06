import { describe, it, expect } from 'vitest';
import {
  identityFor, labelFor, parseIndex, serializeIndex, addIdentity, removeIdentity,
  type KeyIdentity,
} from '../keyIndex.js';

const cloud: KeyIdentity = { identity: 'cloud', mode: 'cloud', label: 'Site Manager (cloud)' };
const local: KeyIdentity = { identity: 'local:192.168.1.1', mode: 'local', host: '192.168.1.1', label: 'UCG-Fiber (local, 192.168.1.1)' };

describe('identityFor', () => {
  it('maps modes to account identifiers', () => {
    expect(identityFor('cloud')).toBe('cloud');
    expect(identityFor('local', '192.168.1.1')).toBe('local:192.168.1.1');
  });
});

describe('labelFor', () => {
  it('prefers the console name when known', () => {
    expect(labelFor('local', '192.168.1.1', 'UCG-Fiber')).toMatch(/UCG-Fiber/);
    expect(labelFor('local', '192.168.1.1', 'UCG-Fiber')).toMatch(/192\.168\.1\.1/);
  });
  it('falls back gracefully with no console name', () => {
    expect(labelFor('cloud').length).toBeGreaterThan(0);
    expect(labelFor('local', '192.168.1.1')).toMatch(/192\.168\.1\.1/);
  });
});

describe('parseIndex / serializeIndex', () => {
  it('round-trips a list', () => {
    const json = serializeIndex([cloud, local]);
    expect(parseIndex(json)).toEqual([cloud, local]);
  });
  it('returns [] for null / invalid / non-array JSON', () => {
    expect(parseIndex(null)).toEqual([]);
    expect(parseIndex('not json')).toEqual([]);
    expect(parseIndex('{"a":1}')).toEqual([]);
  });
  it('drops malformed entries', () => {
    expect(parseIndex('[{"identity":"cloud"}, 42, {"nope":true}]'))
      .toEqual([]); // entries missing required fields are dropped
  });
});

describe('addIdentity / removeIdentity', () => {
  it('adds and dedups by identity (last write wins)', () => {
    const once = addIdentity([], cloud);
    expect(once).toEqual([cloud]);
    const relabeled = { ...cloud, label: 'changed' };
    expect(addIdentity(once, relabeled)).toEqual([relabeled]);
  });
  it('removes by identity', () => {
    expect(removeIdentity([cloud, local], 'cloud')).toEqual([local]);
    expect(removeIdentity([cloud], 'absent')).toEqual([cloud]);
  });
});
