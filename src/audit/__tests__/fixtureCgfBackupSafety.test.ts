import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { FIELD_PROJECTIONS, SETTING_KEYS, RADIO_TABLE_FIELDS } from '../../../tools/anonymize-backup.js';

const FIXTURE_PATH = resolve('samples/fixture-cgf-backup.json');

// Known-leaked values from prior incidents on this branch, kept here so a
// regression trips this test immediately rather than requiring someone to
// remember the manual grep. Case-insensitive substring checks.
const KNOWN_LEAKS = [
  'a8:9c:6c:8a:df:d0',
  'a89c6c8adfd0',
  'a89c6c6a41a4',
  'mdgary@gmail.com',
  'michael gary',
  'id.ui.direct',
  '564a901c',
  '7f92ff48',
];

describe('fixture-cgf-backup.json safety', () => {
  let raw: string;
  let data: Record<string, Record<string, unknown>[]>;

  beforeAll(() => {
    if (!existsSync(FIXTURE_PATH)) {
      throw new Error(
        `${FIXTURE_PATH} does not exist. Run: npm run anonymize-backup -- <path-to-backup-file>`,
      );
    }
    raw = readFileSync(FIXTURE_PATH, 'utf-8');
    data = JSON.parse(raw);
  });

  // -------------------------------------------------------------------
  // Load-bearing structural invariant: every document in every collection
  // contains ONLY keys from that collection's projection list. This is the
  // real safety net — it holds regardless of what content ends up in an
  // allowed field, and it catches any field nobody has thought to scrub.
  // -------------------------------------------------------------------
  describe('field-level projection (structural, load-bearing)', () => {
    it('only contains collections that have a defined projection', () => {
      for (const collName of Object.keys(data)) {
        expect(Object.keys(FIELD_PROJECTIONS), `unexpected collection '${collName}' in fixture`).toContain(collName);
      }
    });

    it('every document in every collection contains only projected keys', () => {
      for (const [collName, docs] of Object.entries(data)) {
        const allowed = new Set(FIELD_PROJECTIONS[collName] ?? []);
        for (const doc of docs) {
          for (const key of Object.keys(doc)) {
            expect(
              allowed.has(key),
              `${collName} document has non-projected key '${key}' (doc: ${JSON.stringify(doc)})`,
            ).toBe(true);
          }
        }
      }
    });

    it('every device.radio_table entry contains only RADIO_TABLE_FIELDS keys', () => {
      const devices = data['device'] ?? [];
      for (const d of devices) {
        const radioTable = d['radio_table'];
        if (!Array.isArray(radioTable)) continue;
        for (const entry of radioTable as Record<string, unknown>[]) {
          for (const key of Object.keys(entry)) {
            expect(
              RADIO_TABLE_FIELDS,
              `radio_table entry has non-projected key '${key}'`,
            ).toContain(key);
          }
        }
      }
    });

    it('every setting document has a key in SETTING_KEYS', () => {
      const settings = data['setting'] ?? [];
      for (const s of settings) {
        expect(SETTING_KEYS.has(String(s['key'])), `setting doc with disallowed key '${s['key']}' survived projection`).toBe(true);
      }
    });
  });

  // -------------------------------------------------------------------
  // Defense-in-depth: PII-pattern invariants over the raw serialized file.
  // These should be redundant with the structural check above (since only
  // allowed fields survive), but they catch anonymization bugs within an
  // allowed field (e.g. a MAC embedded in a kept `name` string).
  // -------------------------------------------------------------------
  describe('PII-pattern invariants (defense in depth)', () => {
    it('contains no email addresses', () => {
      const matches = raw.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
      const real = matches.filter(m => !m.toLowerCase().endsWith('.invalid'));
      expect(real, `found non-.invalid email-like strings: ${real.join(', ')}`).toEqual([]);
    });

    it('redacts every x_-prefixed field to the fixed redaction string', () => {
      for (const docs of Object.values(data)) {
        for (const doc of docs) {
          for (const [key, value] of Object.entries(doc)) {
            if (key.startsWith('x_') && typeof value === 'string') {
              // sanitize() may have already turned known secret x_ fields
              // (e.g. x_passphrase) into a {length, fingerprint, ...} object
              // instead of a string, which is also fine — the constraint is
              // just that a raw x_-prefixed string value can't survive.
              expect(value).toBe('REDACTED_X_FIELD');
            }
          }
        }
      }
    });

    it('every colon-form MAC is in the fake aa:00:... range', () => {
      const macs = raw.match(/([0-9a-f]{2}:){5}[0-9a-f]{2}/gi) ?? [];
      const real = macs.filter(m => !m.toLowerCase().startsWith('aa:00:'));
      expect(real, `found real-looking colon-form MACs: ${real.join(', ')}`).toEqual([]);
    });

    it('every bare 12-hex MAC-like token is in the fake aa00... range', () => {
      // Bare 12-hex tokens are ambiguous with other hex data (fingerprints,
      // etc.), so we only check ones that appear in fields we know can carry
      // bare MACs (mac/macAddress) to avoid false positives on fingerprint
      // hex strings produced by sanitize().
      const devices = data['device'] ?? [];
      for (const d of devices) {
        for (const field of ['mac', 'macAddress']) {
          const v = d[field];
          if (typeof v === 'string' && /^[0-9a-f]{12}$/i.test(v)) {
            expect(v.toLowerCase().startsWith('aa00'), `bare MAC '${v}' not in fake range`).toBe(true);
          }
        }
      }
    });

    it('contains no EUI-64 ff:fe infix (link-local-derived real MAC leakage)', () => {
      expect(/ff:fe/i.test(raw)).toBe(false);
      expect(/fffe/i.test(raw.replace(/REDACTED_X_FIELD/g, ''))).toBe(false);
    });

    it('every IPv4 address is in the fake 198.51.100.0/24 range', () => {
      const ips = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
      const real = ips.filter(ip => !ip.startsWith('198.51.100.'));
      expect(real, `found real-looking IPv4 addresses: ${real.join(', ')}`).toEqual([]);
    });

    it('contains none of the historically-leaked values (case-insensitive)', () => {
      const lower = raw.toLowerCase();
      const found = KNOWN_LEAKS.filter(leak => lower.includes(leak.toLowerCase()));
      expect(found, `found known-leaked values: ${found.join(', ')}`).toEqual([]);
    });
  });
});
