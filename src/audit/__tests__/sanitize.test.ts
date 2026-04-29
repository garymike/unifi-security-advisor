import { describe, it, expect } from 'vitest';
import { sanitize, fingerprint } from '../sanitize.js';

describe('fingerprint', () => {
  it('returns length and sha256 prefix', () => {
    const r = fingerprint('mysecret');
    expect(r.length).toBe(8);
    expect(r.fingerprint.length).toBe(12);
  });
});

describe('sanitize', () => {
  it('redacts known secret field names', () => {
    const result = sanitize({ x_passphrase: 'secret123', name: 'MyNet' }) as Record<string, unknown>;
    expect((result['x_passphrase'] as Record<string, unknown>)['length']).toBe(9);
    expect(result['name']).toBe('MyNet');
  });
  it('recurses into nested objects', () => {
    const result = sanitize({ wlan: { psk: 'abc' } }) as Record<string, unknown>;
    const wlan = result['wlan'] as Record<string, unknown>;
    expect((wlan['psk'] as Record<string, unknown>)['length']).toBe(3);
  });
  it('recurses into arrays', () => {
    const result = sanitize([{ password: 'pw' }]) as Record<string, unknown>[];
    expect((result[0]!['password'] as Record<string, unknown>)['length']).toBe(2);
  });
  it('leaves non-secret fields unchanged', () => {
    expect(sanitize({ ssid: 'HomeNet', channel: 6 })).toEqual({ ssid: 'HomeNet', channel: 6 });
  });
});
