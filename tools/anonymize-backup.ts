/**
 * Maintainer-run tool. Reads a real UniFi backup file (classic .unf or
 * console .unifi), applies a field-level PROJECTION (a positive allowlist
 * of exactly which fields survive per collection — anything not on the
 * list is dropped unconditionally, regardless of content), then
 * anonymizes what remains (MACs, IPv6/IPv4 substrings, emails, names —
 * deterministic replacement so cross-references between collections stay
 * intact), and finally runs the existing secret-field sanitizer. Writes
 * the result as samples/fixture-cgf-backup.json for the test suite.
 *
 * Field-level projection (not collection-level allowlisting) is the
 * load-bearing safety property here: a field that isn't explicitly kept
 * can never leak, even if it's something nobody has thought to scrub yet.
 * See src/audit/__tests__/fixtureCgfBackupSafety.test.ts for the
 * structural test that enforces this.
 *
 * Runs entirely locally; the backup file is never transmitted anywhere.
 *
 * Usage: npm run anonymize-backup -- <path-to-backup-file> [output-path]
 */
import { writeFileSync } from 'node:fs';
import { parseBackupNodejs } from '../src/audit/normalizeBackup.js';
import { sanitize } from '../src/audit/sanitize.js';

// ---------------------------------------------------------------------------
// Field-level projection: an explicit "keep in" list per collection. Any
// field not listed here is dropped unconditionally when writing the fixture.
// ---------------------------------------------------------------------------

export const SETTING_KEYS = new Set([
  'super_identity', 'rogueap', 'dns_filtering', 'connectivity',
  'auto_update', 'auto_backup', 'backup', 'mgmt', 'dpi', 'threat_management',
]);

export const FIELD_PROJECTIONS: Record<string, string[]> = {
  device: ['model', 'mac', 'macAddress', 'version', 'firmwareVersion', 'name', 'sshEnabled', 'ssh_enabled', 'type', 'radio_table'],
  wlanconf: ['enabled', 'name', 'security', 'securityProtocol', 'x_passphrase', 'wpa_mode', 'pmf_mode'],
  networkconf: ['purpose', 'name'],
  user: ['radio'],
  setting: ['key', 'name', 'desc', 'enabled', 'destination', 'syslog_host', 'advanced_feature_enabled', 'report_rogue', 'level'],
};

export const RADIO_TABLE_FIELDS = ['radio', 'disabled', 'tx_power_mode'];

/**
 * Returns the projected document, or null if the whole document should be
 * dropped (currently only applies to `setting` docs whose key isn't
 * allowlisted). Only fields present on the projection list — and present on
 * the source doc — survive. `device.radio_table` entries are themselves
 * field-projected to RADIO_TABLE_FIELDS.
 */
export function projectDoc(collName: string, doc: Record<string, unknown>): Record<string, unknown> | null {
  if (collName === 'setting' && !SETTING_KEYS.has(String(doc['key']))) {
    return null;
  }

  const fields = FIELD_PROJECTIONS[collName];
  if (!fields) return null;

  const out: Record<string, unknown> = {};
  for (const field of fields) {
    if (!(field in doc)) continue;
    if (collName === 'device' && field === 'radio_table' && Array.isArray(doc['radio_table'])) {
      out['radio_table'] = (doc['radio_table'] as Record<string, unknown>[]).map(entry => {
        const radioOut: Record<string, unknown> = {};
        for (const rf of RADIO_TABLE_FIELDS) {
          if (rf in entry) radioOut[rf] = entry[rf];
        }
        return radioOut;
      });
      continue;
    }
    // NOTE: every non-radio_table field is copied verbatim. This is safe only
    // because the projected fields are all scalars (or the x_passphrase
    // fingerprint object, which sanitize() has already reduced). If you ever
    // add a field whose value is a nested object/array to a projection list,
    // add a sub-projection here (like radio_table above) — a raw nested object
    // would otherwise pass through un-projected, and the structural safety
    // test in fixtureCgfBackupSafety.test.ts only validates top-level keys.
    out[field] = doc[field];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Anonymization: deterministic replacement of MACs, IPv6/IPv4 substrings,
// emails, and name fields. x_-prefixed fields are always fully redacted
// regardless of content, since they're a UniFi convention for
// extended/vendor-private data we have no field-level guarantee about.
// ---------------------------------------------------------------------------

const REDACTED = 'REDACTED_X_FIELD';

const NAME_FIELDS = new Set(['name', 'hostname', 'desc', 'site_name', 'siteName', 'device_name', 'deviceName', 'note']);

// Colon-separated and bare 12-hex MAC forms.
const MAC_COLON_RE = /([0-9a-f]{2}:){5}[0-9a-f]{2}/gi;
const MAC_BARE_RE = /\b[0-9a-f]{12}\b/gi;

// IPv4 dotted-quad substring (not anchored — must run before IPv6 matching).
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

// IPv6 substring — deliberately broad since real addresses can be
// compressed/expanded in many ways. Requires at least two "::"-or-colon
// groups of hex to avoid matching plain single numbers or MACs (MACs are
// replaced first, so this mainly needs to avoid false positives on ports).
const IPV6_RE = /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b/gi;

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;

// RFC 3849 documented-safe IPv6 example range.
const FAKE_IPV6_BASE = '2001:db8::';
// RFC 5737 TEST-NET-2 documented-safe IPv4 range.
const FAKE_IPV4_BASE = '198.51.100.';
// RFC 2606 reserved TLD for fake emails.
const FAKE_EMAIL_DOMAIN = 'example.invalid';

function createAnonymizer() {
  const macMap = new Map<string, string>();
  const ipv6Map = new Map<string, string>();
  const ipv4Map = new Map<string, string>();
  const emailMap = new Map<string, string>();
  const nameMap = new Map<string, string>();
  let macCounter = 0;
  let ipv6Counter = 0;
  let ipv4Counter = 0;
  let emailCounter = 0;
  let nameCounter = 0;

  function fakeMacColon(real: string): string {
    const key = real.toLowerCase();
    if (!macMap.has(key)) {
      macCounter++;
      const hex = macCounter.toString(16).padStart(6, '0');
      macMap.set(key, `aa:00:${hex.slice(0, 2)}:${hex.slice(2, 4)}:${hex.slice(4, 6)}:00`);
    }
    return macMap.get(key)!;
  }

  function fakeMacBare(real: string): string {
    // Reuse the same underlying counter space as colon-form MACs so the
    // same physical MAC maps to the same fake value in either notation.
    const colonForm = real.toLowerCase().match(/.{1,2}/g)!.join(':');
    return fakeMacColon(colonForm).replace(/:/g, '');
  }

  function fakeIpv6(real: string): string {
    const key = real.toLowerCase();
    if (!ipv6Map.has(key)) {
      ipv6Counter++;
      ipv6Map.set(key, `${FAKE_IPV6_BASE}${ipv6Counter.toString(16)}`);
    }
    return ipv6Map.get(key)!;
  }

  function fakeIpv4(real: string): string {
    if (!ipv4Map.has(real)) {
      ipv4Counter++;
      ipv4Map.set(real, `${FAKE_IPV4_BASE}${(ipv4Counter % 254) + 1}`);
    }
    return ipv4Map.get(real)!;
  }

  function fakeEmail(real: string): string {
    const key = real.toLowerCase();
    if (!emailMap.has(key)) {
      emailCounter++;
      emailMap.set(key, `user${emailCounter}@${FAKE_EMAIL_DOMAIN}`);
    }
    return emailMap.get(key)!;
  }

  function fakeName(real: string): string {
    if (!nameMap.has(real)) {
      nameCounter++;
      nameMap.set(real, `Item-${String(nameCounter).padStart(2, '0')}`);
    }
    return nameMap.get(real)!;
  }

  // Sentinel used to protect already-substituted fake values from being
  // re-matched by a later regex pass in the same string (e.g. a fake MAC
  // like "aa:00:00:01:00:00" is itself a syntactically valid IPv6-shaped
  // hex-colon string, so an IPv6 pass running after the MAC pass would
  // re-match and corrupt it). Each pass parks its replacements behind this
  // marker and \x00 is never valid in real JSON string content, so it's
  // safe as a temporary in-flight marker; written as a JS escape (not a
  // literal NUL byte) so this source file stays plain text.
  const SENTINEL = '\x00';

  function anonymizeString(value: string): string {
    const vault: string[] = [];
    const park = (replacement: string): string => {
      vault.push(replacement);
      return `${SENTINEL}${vault.length - 1}${SENTINEL}`;
    };

    let out = value;

    // MACs first, so IPv4/IPv6 passes never operate on MAC substrings.
    out = out.replace(MAC_COLON_RE, m => park(fakeMacColon(m)));
    out = out.replace(MAC_BARE_RE, m => park(fakeMacBare(m)));

    // IPv4 BEFORE IPv6: an IPv6-first pass previously ate part of a URL's
    // ":port" suffix (e.g. "203.0.113.5:8443") and corrupted the output.
    out = out.replace(IPV4_RE, m => park(fakeIpv4(m)));

    out = out.replace(IPV6_RE, m => park(fakeIpv6(m)));

    out = out.replace(EMAIL_RE, m => park(fakeEmail(m)));

    // Unpark: substitute sentinel markers back with their parked
    // replacement values now that no more regex passes will run over them.
    out = out.replace(new RegExp(`${SENTINEL}(\\d+)${SENTINEL}`, 'g'), (_m, idx) => vault[Number(idx)]!);

    return out;
  }

  function anonymize(key: string | null, value: unknown): unknown {
    if (Array.isArray(value)) return value.map(v => anonymize(null, v));
    if (value !== null && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (k.startsWith('x_')) {
          out[k] = typeof v === 'string' ? REDACTED : anonymize(k, v);
          continue;
        }
        out[k] = anonymize(k, v);
      }
      return out;
    }
    if (typeof value === 'string') {
      if (key && NAME_FIELDS.has(key) && value.length > 0) return fakeName(value);
      return anonymizeString(value);
    }
    return value;
  }

  return anonymize;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.error('Usage: npm run anonymize-backup -- <path-to-backup-file> [output-path]');
    process.exitCode = 1;
    return;
  }
  const outputPath = process.argv[3] ?? 'samples/fixture-cgf-backup.json';

  const collections = await parseBackupNodejs(inputPath);
  const anonymize = createAnonymizer();

  // Only collections with a defined field projection are eligible to
  // appear in the fixture at all; everything else is dropped entirely
  // (not written as an empty array) so the fixture's key set matches
  // exactly what FIELD_PROJECTIONS declares safe.
  const result: Record<string, unknown[]> = {};
  for (const collName of Object.keys(FIELD_PROJECTIONS)) {
    const docs = collections[collName] ?? [];
    const projected = docs
      .map(doc => projectDoc(collName, doc))
      .filter((d): d is Record<string, unknown> => d !== null);
    result[collName] = projected.map(doc => sanitize(anonymize(null, doc)) as Record<string, unknown>);
  }

  writeFileSync(outputPath, JSON.stringify(result, null, 2));
  console.log(`Wrote projected+anonymized fixture to ${outputPath} (${Object.keys(result).length} collections)`);
  console.log('Review the output before committing — run the fixtureCgfBackupSafety test and the known-leak grep check.');
}

// Only run when executed directly (tsx tools/anonymize-backup.ts), not when
// imported for its exported constants (e.g. by the safety test).
if (process.argv[1]) {
  const { pathToFileURL } = await import('node:url');
  if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    main().catch(err => {
      console.error('anonymize-backup failed:', err);
      process.exitCode = 1;
    });
  }
}
