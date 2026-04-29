import { createHash } from 'node:crypto';

const SECRET_FIELDS = new Set([
  'x_passphrase', 'x_passphrase_rollover', 'x_radius_secret', 'x_shared_secret',
  'x_ssh_password', 'x_iapp_key', 'password', 'x_auth_key', 'auth_key',
  'private_key', 'api_key', 'token', 'passphrase', 'preSharedKey', 'presharedKey',
  'psk', 'pre_shared_key', 'privateKey', 'wpa_psk',
]);

export interface Fingerprint {
  length: number;
  fingerprint: string;
  hasSymbols: boolean;
  hasDigits: boolean;
  hasMixedCase: boolean;
}

export function fingerprint(value: string): Fingerprint {
  return {
    length: value.length,
    fingerprint: createHash('sha256').update(value).digest('hex').slice(0, 12),
    hasSymbols: /[^a-zA-Z0-9]/.test(value),
    hasDigits: /\d/.test(value),
    hasMixedCase: /[a-z]/.test(value) && /[A-Z]/.test(value),
  };
}

export function sanitize(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sanitize);
  if (obj !== null && typeof obj === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[k] = SECRET_FIELDS.has(k) && typeof v === 'string' ? fingerprint(v) : sanitize(v);
    }
    return out;
  }
  return obj;
}
