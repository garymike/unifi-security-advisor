export interface KeyIdentity {
  identity: string;            // 'cloud' | `local:${host}`
  mode: 'local' | 'cloud';
  host?: string;
  label: string;               // human-readable, non-secret
}

export function identityFor(mode: 'local' | 'cloud', host?: string): string {
  return mode === 'cloud' ? 'cloud' : `local:${(host ?? '').trim()}`;
}

export function labelFor(mode: 'local' | 'cloud', host?: string, consoleName?: string): string {
  if (mode === 'cloud') return consoleName ? `${consoleName} (cloud)` : 'Site Manager (cloud)';
  const h = (host ?? '').trim();
  return consoleName ? `${consoleName} (local, ${h})` : `Local console (${h})`;
}

function isKeyIdentity(v: unknown): v is KeyIdentity {
  if (v === null || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  return typeof o.identity === 'string'
    && (o.mode === 'local' || o.mode === 'cloud')
    && typeof o.label === 'string'
    && (o.host === undefined || typeof o.host === 'string');
}

export function parseIndex(json: string | null): KeyIdentity[] {
  if (!json) return [];
  try {
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isKeyIdentity);
  } catch {
    return [];
  }
}

export function serializeIndex(list: KeyIdentity[]): string {
  return JSON.stringify(list);
}

export function addIdentity(list: KeyIdentity[], entry: KeyIdentity): KeyIdentity[] {
  return [...list.filter(e => e.identity !== entry.identity), entry];
}

export function removeIdentity(list: KeyIdentity[], identity: string): KeyIdentity[] {
  return list.filter(e => e.identity !== identity);
}
