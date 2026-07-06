import { describe, it, expect } from 'vitest';
import { validateConnection, type Fetcher } from '../validateConnection.js';

function fakeClient(useCloud: boolean, host: string, responder: (path: string) => { status: number; data: unknown } | Promise<never>): Fetcher {
  return { config: { useCloud, host }, get: async (path) => responder(path) };
}

describe('validateConnection (local)', () => {
  it('returns ok with version + sites on 200', async () => {
    const client = fakeClient(false, '192.168.1.1', (path) => {
      if (path.endsWith('/info')) return { status: 200, data: { applicationVersion: '10.3.58', name: 'UCG-Fiber' } };
      if (path.endsWith('/sites')) return { status: 200, data: [{ id: 's1', name: 'Default' }] };
      return { status: 404, data: {} };
    });
    const r = await validateConnection(client);
    expect(r.ok).toBe(true);
    expect(r.networkVersion).toBe('10.3.58');
    expect(r.sites).toEqual([{ id: 's1', name: 'Default' }]);
  });

  it('maps 401 to an auth error', async () => {
    const client = fakeClient(false, '192.168.1.1', () => ({ status: 401, data: {} }));
    const r = await validateConnection(client);
    expect(r.ok).toBe(false);
    expect(r.error?.kind).toBe('auth');
  });

  it('maps a thrown fetch to unreachable', async () => {
    const client = fakeClient(false, '10.0.0.9', () => { throw new Error('ECONNREFUSED'); });
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('unreachable');
  });

  it('flags a cloud host typed into local mode as mode-mismatch', async () => {
    const client = fakeClient(false, 'unifi.ui.com', () => ({ status: 200, data: {} }));
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('mode-mismatch');
  });

  it('maps other non-2xx to unknown', async () => {
    const client = fakeClient(false, '192.168.1.1', () => ({ status: 500, data: {} }));
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('unknown');
  });
});

describe('validateConnection (cloud)', () => {
  it('returns ok with hosts as sites', async () => {
    const client = fakeClient(true, '', () => ({ status: 200, data: [{ id: 'c1', name: 'Home' }] }));
    const r = await validateConnection(client);
    expect(r.ok).toBe(true);
    expect(r.sites).toEqual([{ id: 'c1', name: 'Home' }]);
  });
  it('maps 403 to auth', async () => {
    const client = fakeClient(true, '', () => ({ status: 403, data: {} }));
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('auth');
  });
});
