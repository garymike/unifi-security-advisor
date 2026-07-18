/**
 * Maintainer diagnostic. Parses a backup locally and prints the SCHEMA of its
 * `setting` collection — the doc `key`s and, per doc, each field's name with a
 * SAFE value: booleans/numbers are shown (e.g. `auto_upgrade: true`, which is
 * not a secret and is exactly what the finding modules need), strings are
 * redacted to `<string:len>`, and anything nested is shown as its type only.
 *
 * The backup never leaves your machine — this only prints field NAMES and
 * non-secret scalar flags, so the output is safe to paste back for mapping the
 * currently-"unknown" backup findings (auto-update / auto-backup / rogue-AP).
 *
 * Usage: npm run dump-backup-settings -- path/to/backup.unifi
 */
import { parseBackupNodejs } from '../src/audit/normalizeBackup.js';

// Field names that could carry sensitive data even as scalars — always redact.
const SENSITIVE = /pass|secret|key|psk|token|cred|x_/i;

function safeValue(name: string, v: unknown): string {
  if (SENSITIVE.test(name)) return '<redacted>';
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  if (typeof v === 'string') return `<string:${v.length}>`;
  if (v === null) return 'null';
  if (Array.isArray(v)) return `<array:${v.length}>`;
  if (typeof v === 'object') return '<object>';
  return `<${typeof v}>`;
}

async function main(): Promise<void> {
  const path = process.argv[2];
  if (!path) {
    console.error('Usage: npm run dump-backup-settings -- path/to/backup.unifi');
    process.exit(1);
  }

  const collections = await parseBackupNodejs(path);

  // Collection inventory — helps spot where auto-backup/rogue-AP actually live
  // (they may be their own collection, e.g. super_mgmt / scheduletask).
  console.log('=== collections (name: doc count) ===');
  for (const [name, docs] of Object.entries(collections).sort()) {
    console.log(`  ${name}: ${docs.length}`);
  }

  const settings = collections['setting'] ?? [];
  console.log(`\n=== setting collection (${settings.length} docs) ===`);
  for (const doc of settings) {
    const key = String((doc as Record<string, unknown>)['key'] ?? '<no-key>');
    console.log(`\n### key = ${key}`);
    for (const [field, value] of Object.entries(doc as Record<string, unknown>)) {
      if (field === '_id' || field === 'key' || field === 'site_id') continue;
      console.log(`  ${field}: ${safeValue(field, value)}`);
    }
  }

  // Also surface any collection or field that looks related, in case the state
  // isn't in `setting` at all.
  console.log('\n=== fields mentioning auto/backup/rogue/upgrade (across all collections) ===');
  for (const [name, docs] of Object.entries(collections)) {
    for (const doc of docs) {
      for (const [field, value] of Object.entries(doc as Record<string, unknown>)) {
        if (/auto|backup|rogue|upgrade|report_rogue/i.test(field)) {
          console.log(`  ${name}.${field}: ${safeValue(field, value)}`);
        }
      }
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
