# UniFi OS Console Backup (.unifi) Decryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add decryption/parsing support for the newer UniFi OS console-level `.unifi` backup format (Cloud Gateway Fiber and similar console hardware) to the Node/TypeScript CLI backup-mode path, closing a gap this project's own history documented as unsolved.

**Architecture:** A new standalone module (`src/audit/parseUnifiOsConsoleBackup.ts`) implements three independently-testable functions — AES-256-CBC decrypt with an embedded IV, a minimal inline TAR entry extractor, and a marker-based BSON collection-stream parser. `normalizeBackup.ts`'s existing `parseBackupNodejs` becomes a two-strategy dispatcher: try the classic `.unf` path first (unchanged), fall back to the new console path on failure. Both strategies produce the same `Collections` type, so `normalizeBackup()` and every finding module downstream need zero changes.

**Tech Stack:** Node.js `node:crypto` (AES-256-CBC), `node:zlib` (gzip), `bson` npm package (already a dependency), Vitest.

## Global Constraints

- Full spec: `docs/superpowers/specs/2026-07-03-cgf-console-backup-decryption-design.md`. Read it before starting if anything below is ambiguous.
- **Scope this round: Node/TS CLI path only.** Do not touch `src-tauri/src/lib.rs` or `src/routes/backup/+page.svelte` — both are explicitly deferred (see spec's Decisions table). The desktop app's CGF hint text stays as-is; changing it now would falsely claim support the shipped app doesn't have yet.
- **UCore PostgreSQL data (`backup/ucore/database/*`) is out of scope.** Only extract and parse `backup/network/db.gz`.
- Decryption key (hex, AES-256): `e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f`. IV is the file's first 16 bytes (embedded, not static like the classic `.unf` format).
- The console format uses **default PKCS7 padding** (verified empirically) — do NOT call `setAutoPadding(false)` the way the classic `.unf` decryption does; that's specific to the old format's `NoPadding` scheme.
- Marker document shape (verified against real data): `{ _id, collection: <string>, __cmd: <anything>, ... }`. A marker sets "current collection" for all following untagged documents until the next marker.
- Every task must leave `npm run test` fully green (153 tests passing before this plan starts) and `npx tsc --noEmit` clean before its commit.
- The real backup file for end-to-end verification already exists locally at `samples/unifi_os_backup_1783048515216_a228af65-42d5-4d42-8907-616ec6ae0f2b.unifi` — gitignored (`*.unifi` was added to `.gitignore` this session), never to be committed raw.

---

### Task 1: `decryptConsoleBackup()`

**Files:**
- Create: `src/audit/parseUnifiOsConsoleBackup.ts`
- Test: `src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`

**Interfaces:**
- Produces: `decryptConsoleBackup(raw: Buffer): Buffer` — AES-256-CBC decrypt using the fixed key and an IV read from `raw`'s first 16 bytes; returns the decrypted gzip byte stream. Throws if the result isn't gzip-magic-prefixed (`0x1f 0x8b`) or if decryption itself fails (bad padding).

- [ ] **Step 1: Write the failing test**

Create `src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createCipheriv, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { decryptConsoleBackup } from '../parseUnifiOsConsoleBackup.js';

const KEY_HEX = 'e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f';

function encryptLikeConsoleBackup(plaintext: Buffer): Buffer {
  const key = Buffer.from(KEY_HEX, 'hex');
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, ciphertext]);
}

describe('decryptConsoleBackup', () => {
  it('decrypts a valid AES-256-CBC console backup to its gzip payload', () => {
    const gz = gzipSync(Buffer.from('hello world'));
    const encrypted = encryptLikeConsoleBackup(gz);
    const result = decryptConsoleBackup(encrypted);
    expect(result.subarray(0, 2)).toEqual(Buffer.from([0x1f, 0x8b]));
  });

  it('throws when decrypted data is not gzip', () => {
    const encrypted = encryptLikeConsoleBackup(Buffer.from('not gzip data at all'));
    expect(() => decryptConsoleBackup(encrypted)).toThrow(/not gzip/i);
  });

  it('throws on garbage input (invalid padding)', () => {
    const garbage = randomBytes(64);
    expect(() => decryptConsoleBackup(garbage)).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`
Expected: FAIL — `Cannot find module '../parseUnifiOsConsoleBackup.js'`.

- [ ] **Step 3: Write the implementation**

Create `src/audit/parseUnifiOsConsoleBackup.ts`:

```ts
import { createDecipheriv } from 'node:crypto';

export type Collections = Record<string, Record<string, unknown>[]>;

const CONSOLE_BACKUP_KEY_HEX = 'e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f';

/**
 * Decrypts a UniFi OS console-level (.unifi) backup file. AES-256-CBC with
 * a fixed key and a per-file IV embedded in the first 16 bytes — different
 * from the classic .unf format's AES-128-CBC with a static IV. Default
 * PKCS7 padding (the classic format uses NoPadding; this one doesn't).
 */
export function decryptConsoleBackup(raw: Buffer): Buffer {
  const key = Buffer.from(CONSOLE_BACKUP_KEY_HEX, 'hex');
  const iv = raw.subarray(0, 16);
  const ciphertext = raw.subarray(16);
  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (decrypted.length < 2 || decrypted[0] !== 0x1f || decrypted[1] !== 0x8b) {
    throw new Error('Decrypted data is not gzip — UniFi OS console backup format not recognized');
  }
  return decrypted;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`
Expected: PASS — 3 tests passing.

- [ ] **Step 5: Type-check and commit**

Run: `npx tsc --noEmit`
Expected: no output (clean).

```bash
git add src/audit/parseUnifiOsConsoleBackup.ts src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts
git commit -m "feat: add decryptConsoleBackup for UniFi OS console .unifi format"
```

---

### Task 2: `extractTarEntry()`

**Files:**
- Modify: `src/audit/parseUnifiOsConsoleBackup.ts`
- Modify: `src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`

**Interfaces:**
- Produces: `extractTarEntry(tarBuf: Buffer, entryName: string): Buffer | null` — walks a TAR archive's 512-byte header blocks looking for an entry with an exact filename match; returns its content bytes, or `null` if not found.

- [ ] **Step 1: Write the failing tests**

Add to `src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts` (after the existing `decryptConsoleBackup` describe block):

```ts
import { extractTarEntry } from '../parseUnifiOsConsoleBackup.js';

function buildTarEntry(name: string, content: Buffer): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 'utf8');
  const sizeOctal = content.length.toString(8).padStart(11, '0') + '\0';
  header.write(sizeOctal, 124, 'utf8');
  const paddedLen = Math.ceil(content.length / 512) * 512;
  const paddedContent = Buffer.alloc(paddedLen);
  content.copy(paddedContent);
  return Buffer.concat([header, paddedContent]);
}

describe('extractTarEntry', () => {
  it('extracts a matching entry by exact name', () => {
    const entry1 = buildTarEntry('backup/network/db.gz', Buffer.from('fake-gz-data'));
    const entry2 = buildTarEntry('backup/other/file.txt', Buffer.from('other'));
    const tar = Buffer.concat([entry1, entry2, Buffer.alloc(1024)]);
    const result = extractTarEntry(tar, 'backup/network/db.gz');
    expect(result?.toString('utf8')).toBe('fake-gz-data');
  });

  it('returns null when the entry is not found', () => {
    const entry1 = buildTarEntry('backup/network/db.gz', Buffer.from('data'));
    const tar = Buffer.concat([entry1, Buffer.alloc(1024)]);
    expect(extractTarEntry(tar, 'nonexistent')).toBeNull();
  });

  it('finds an entry that is not the first one in the archive', () => {
    const entry1 = buildTarEntry('backup/metadata.json', Buffer.from('{}'));
    const entry2 = buildTarEntry('backup/network/db.gz', Buffer.from('target-data'));
    const tar = Buffer.concat([entry1, entry2, Buffer.alloc(1024)]);
    expect(extractTarEntry(tar, 'backup/network/db.gz')?.toString('utf8')).toBe('target-data');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`
Expected: FAIL — `extractTarEntry` is not exported yet.

- [ ] **Step 3: Write the implementation**

Add to `src/audit/parseUnifiOsConsoleBackup.ts` (after `decryptConsoleBackup`):

```ts
/**
 * Walks a TAR archive's 512-byte header blocks looking for an exact
 * filename match. Only needs to handle plain USTAR-style headers — no
 * long-filename extensions, since UniFi backups don't use them (verified
 * against a real capture).
 */
export function extractTarEntry(tarBuf: Buffer, entryName: string): Buffer | null {
  let pos = 0;
  while (pos + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(pos, pos + 512);
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    if (!name) break; // end-of-archive marker (all-zero block)
    const sizeOctal = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeOctal, 8) || 0;
    if (name === entryName) {
      return tarBuf.subarray(pos + 512, pos + 512 + size);
    }
    pos += 512 + Math.ceil(size / 512) * 512;
  }
  return null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`
Expected: PASS — 6 tests passing (3 from Task 1 + 3 new).

- [ ] **Step 5: Type-check and commit**

Run: `npx tsc --noEmit`
Expected: no output (clean).

```bash
git add src/audit/parseUnifiOsConsoleBackup.ts src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts
git commit -m "feat: add extractTarEntry for reading a single file from a TAR archive"
```

---

### Task 3: `parseMarkerStreamBson()`

**Files:**
- Modify: `src/audit/parseUnifiOsConsoleBackup.ts`
- Modify: `src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`

**Interfaces:**
- Consumes: `Collections` type (defined in Task 1, same file).
- Produces: `parseMarkerStreamBson(bsonData: Buffer): Collections` — walks a flat length-prefixed BSON document stream; a `{ collection: string, __cmd: ... }` marker document sets which collection subsequent untagged documents belong to.

- [ ] **Step 1: Write the failing tests**

Add to `src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`:

```ts
import { BSON } from 'bson';
import { parseMarkerStreamBson } from '../parseUnifiOsConsoleBackup.js';

function bsonDoc(obj: Record<string, unknown>): Buffer {
  return Buffer.from(BSON.serialize(obj));
}

describe('parseMarkerStreamBson', () => {
  it('attributes documents to the collection named in the preceding marker', () => {
    const stream = Buffer.concat([
      bsonDoc({ _id: '1', collection: 'device', __cmd: 'insert' }),
      bsonDoc({ mac: 'aa:bb:cc', model: 'UDM-Pro' }),
      bsonDoc({ mac: 'dd:ee:ff', model: 'U6-LR' }),
      bsonDoc({ _id: '2', collection: 'networkconf', __cmd: 'insert' }),
      bsonDoc({ name: 'LAN', purpose: 'corporate' }),
    ]);
    const result = parseMarkerStreamBson(stream);
    expect(result['device']).toHaveLength(2);
    expect(result['device']![0]).toMatchObject({ mac: 'aa:bb:cc' });
    expect(result['networkconf']).toHaveLength(1);
    expect(result['networkconf']![0]).toMatchObject({ name: 'LAN' });
  });

  it('drops documents that appear before any marker', () => {
    const stream = Buffer.concat([
      bsonDoc({ orphan: true }),
      bsonDoc({ _id: '1', collection: 'device', __cmd: 'insert' }),
      bsonDoc({ mac: 'aa:bb:cc' }),
    ]);
    const result = parseMarkerStreamBson(stream);
    expect(result['device']).toHaveLength(1);
    expect(Object.values(result).flat()).not.toContainEqual(expect.objectContaining({ orphan: true }));
  });

  it('returns an empty object for empty input', () => {
    expect(parseMarkerStreamBson(Buffer.alloc(0))).toEqual({});
  });

  it('accumulates documents across multiple markers for the same collection', () => {
    const stream = Buffer.concat([
      bsonDoc({ collection: 'device', __cmd: 'insert' }),
      bsonDoc({ mac: 'aa:bb:cc' }),
      bsonDoc({ collection: 'device', __cmd: 'insert' }),
      bsonDoc({ mac: 'dd:ee:ff' }),
    ]);
    const result = parseMarkerStreamBson(stream);
    expect(result['device']).toHaveLength(2);
  });

  it('stops cleanly on an unparseable document rather than throwing', () => {
    const stream = Buffer.concat([
      bsonDoc({ collection: 'device', __cmd: 'insert' }),
      bsonDoc({ mac: 'aa:bb:cc' }),
      Buffer.from([0xff, 0xff, 0xff, 0xff]), // garbage length prefix
    ]);
    expect(() => parseMarkerStreamBson(stream)).not.toThrow();
    expect(parseMarkerStreamBson(stream)['device']).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`
Expected: FAIL — `parseMarkerStreamBson` is not exported yet.

- [ ] **Step 3: Write the implementation**

Add to the top of `src/audit/parseUnifiOsConsoleBackup.ts`, after the existing imports:

```ts
import { BSON } from 'bson';
```

Add to the end of `src/audit/parseUnifiOsConsoleBackup.ts`:

```ts
/**
 * Parses the marker-based BSON stream used by backup/network/db.gz in
 * the console backup format. Unlike the classic .unf format (where every
 * document carries its own `collection` field), most documents here are
 * untagged — a `{ collection, __cmd }` marker document precedes a run of
 * data documents belonging to that collection, until the next marker.
 * Documents before the first marker are dropped (logged), not
 * miscategorized. Stops cleanly at the first unparseable document,
 * matching the classic parser's existing behavior.
 */
export function parseMarkerStreamBson(bsonData: Buffer): Collections {
  const collections: Collections = {};
  let currentCollection: string | null = null;
  let pos = 0;

  while (pos + 4 <= bsonData.length) {
    const len = bsonData.readInt32LE(pos);
    if (len < 5 || pos + len > bsonData.length) break;

    let doc: Record<string, unknown>;
    try {
      doc = BSON.deserialize(bsonData.subarray(pos, pos + len)) as Record<string, unknown>;
    } catch {
      break;
    }

    if (typeof doc['collection'] === 'string' && '__cmd' in doc) {
      currentCollection = doc['collection'] as string;
    } else if (currentCollection !== null) {
      if (!collections[currentCollection]) collections[currentCollection] = [];
      collections[currentCollection]!.push(doc);
    }
    // else: document appeared before any marker — dropped, not miscategorized.

    pos += len;
  }

  return collections;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`
Expected: PASS — 11 tests passing (6 from Tasks 1-2 + 5 new).

- [ ] **Step 5: Type-check and commit**

Run: `npx tsc --noEmit`
Expected: no output (clean).

```bash
git add src/audit/parseUnifiOsConsoleBackup.ts src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts
git commit -m "feat: add parseMarkerStreamBson for the console backup's collection-marker stream format"
```

---

### Task 4: Wire the fallback chain into `parseBackupNodejs`

**Files:**
- Modify: `src/audit/normalizeBackup.ts`
- Test: `src/audit/__tests__/parseBackupNodejs.test.ts` (new)

**Interfaces:**
- Consumes: `decryptConsoleBackup`, `extractTarEntry`, `parseMarkerStreamBson`, `Collections` from `./parseUnifiOsConsoleBackup.js` (Tasks 1-3).
- Produces: `parseBackupNodejs(filePath: string): Promise<Collections>` (existing exported signature, unchanged) — now tries the classic `.unf` format first, falls back to the console `.unifi` format, and throws a combined error if both fail.

- [ ] **Step 1: Write the failing tests**

Create `src/audit/__tests__/parseBackupNodejs.test.ts`:

```ts
import { describe, it, expect, afterEach } from 'vitest';
import { writeFileSync, unlinkSync } from 'node:fs';
import { createDecipheriv, createCipheriv, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { BSON } from 'bson';
import AdmZip from 'adm-zip';
import { parseBackupNodejs } from '../normalizeBackup.js';

const CONSOLE_KEY_HEX = 'e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f';
const CLASSIC_KEY = Buffer.from('bcyangkmluohmars');
const CLASSIC_IV = Buffer.from('ubntenterpriseap');

function bsonDoc(obj: Record<string, unknown>): Buffer {
  return Buffer.from(BSON.serialize(obj));
}

function buildClassicUnfFile(): Buffer {
  const bsonStream = Buffer.concat([
    bsonDoc({ collection: 'device', mac: 'aa:bb:cc', model: 'U7Pro' }),
    bsonDoc({ collection: 'networkconf', name: 'LAN' }),
  ]);
  const gz = gzipSync(bsonStream);
  const zip = new AdmZip();
  zip.addFile('db.gz', gz);
  const zipBuf = zip.toBuffer();
  const cipher = createCipheriv('aes-128-cbc', CLASSIC_KEY, CLASSIC_IV);
  cipher.setAutoPadding(false);
  // AES-CBC needs block-aligned input when padding is disabled; pad the ZIP to a 16-byte boundary.
  const pad = (16 - (zipBuf.length % 16)) % 16;
  const padded = Buffer.concat([zipBuf, Buffer.alloc(pad)]);
  return Buffer.concat([cipher.update(padded), cipher.final()]);
}

function buildTarEntry(name: string, content: Buffer): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 'utf8');
  header.write(content.length.toString(8).padStart(11, '0') + '\0', 124, 'utf8');
  const paddedLen = Math.ceil(content.length / 512) * 512;
  const paddedContent = Buffer.alloc(paddedLen);
  content.copy(paddedContent);
  return Buffer.concat([header, paddedContent]);
}

function buildConsoleUnifiFile(): Buffer {
  const bsonStream = Buffer.concat([
    bsonDoc({ collection: 'device', __cmd: 'insert' }),
    bsonDoc({ mac: 'dd:ee:ff', model: 'UDM-Pro' }),
  ]);
  const dbGz = gzipSync(bsonStream);
  const tar = Buffer.concat([buildTarEntry('backup/network/db.gz', dbGz), Buffer.alloc(1024)]);
  const gzTar = gzipSync(tar);
  const key = Buffer.from(CONSOLE_KEY_HEX, 'hex');
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  const ciphertext = Buffer.concat([cipher.update(gzTar), cipher.final()]);
  return Buffer.concat([iv, ciphertext]);
}

const TEST_FILES: string[] = [];
afterEach(() => {
  for (const f of TEST_FILES.splice(0)) {
    try { unlinkSync(f); } catch { /* already gone */ }
  }
});

describe('parseBackupNodejs', () => {
  it('parses a classic .unf-format file unchanged', async () => {
    const path = 'test-classic.unf';
    writeFileSync(path, buildClassicUnfFile());
    TEST_FILES.push(path);
    const collections = await parseBackupNodejs(path);
    expect(collections['device']).toHaveLength(1);
    expect(collections['device']![0]).toMatchObject({ mac: 'aa:bb:cc' });
  });

  it('falls back to the console .unifi format when the classic format fails', async () => {
    const path = 'test-console.unifi';
    writeFileSync(path, buildConsoleUnifiFile());
    TEST_FILES.push(path);
    const collections = await parseBackupNodejs(path);
    expect(collections['device']).toHaveLength(1);
    expect(collections['device']![0]).toMatchObject({ mac: 'dd:ee:ff' });
  });

  it('throws a combined error when neither format matches', async () => {
    const path = 'test-garbage.unifi';
    writeFileSync(path, randomBytes(256));
    TEST_FILES.push(path);
    await expect(parseBackupNodejs(path)).rejects.toThrow(/neither the classic .unf scheme nor the UniFi OS console scheme/i);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/audit/__tests__/parseBackupNodejs.test.ts`
Expected: FAIL on the console-format and combined-error cases (classic-format case passes already, since that path is unchanged) — the fallback chain doesn't exist yet.

- [ ] **Step 3: Rewrite `parseBackupNodejs` in `normalizeBackup.ts`**

Replace the top of `src/audit/normalizeBackup.ts` (the `import type { NormalizedSite } from './types.js';` line) with:

```ts
import type { NormalizedSite } from './types.js';
import type { Collections } from './parseUnifiOsConsoleBackup.js';
import { decryptConsoleBackup, extractTarEntry, parseMarkerStreamBson } from './parseUnifiOsConsoleBackup.js';
```

Then find this line further down:

```ts
type Collections = Record<string, Record<string, unknown>[]>;
```

**Delete that line** — `Collections` is now imported from `parseUnifiOsConsoleBackup.ts` instead of declared locally.

Then replace the entire `parseBackupNodejs` function (from `/// CLI path: Node.js crypto + bson npm...` through its closing `}`) with:

```ts
/// CLI path: Node.js crypto + bson npm (no Tauri IPC available in CLI context)
export async function parseBackupNodejs(
  filePath: string,
): Promise<Collections> {
  const { readFile } = await import('node:fs/promises');
  const { resolve } = await import('node:path');

  const raw = await readFile(resolve(filePath));

  try {
    return await parseClassicUnfFormat(raw);
  } catch {
    try {
      return await parseConsoleUnifiFormat(raw);
    } catch {
      throw new Error(
        'Unrecognized backup format — neither the classic .unf scheme nor the UniFi OS console scheme decoded a valid archive.',
      );
    }
  }
}

async function parseClassicUnfFormat(raw: Buffer): Promise<Collections> {
  const { createDecipheriv } = await import('node:crypto');
  const { gunzipSync } = await import('node:zlib');

  const KEY = Buffer.from('bcyangkmluohmars');
  const IV = Buffer.from('ubntenterpriseap');

  const decipher = createDecipheriv('aes-128-cbc', KEY, IV);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(raw), decipher.final()]);

  if (decrypted.slice(0, 4).toString('binary') !== 'PK\x03\x04') {
    throw new Error('Not a valid .unf backup file (wrong ZIP signature)');
  }

  const AdmZip = (await import('adm-zip')).default;
  const zip = new AdmZip(decrypted);
  const entries = zip.getEntries();

  const { BSON } = await import('bson');
  const collections: Collections = {};

  const hasDbGz = entries.some(e => e.entryName === 'db.gz');

  if (hasDbGz) {
    const gz = entries.find(e => e.entryName === 'db.gz')!;
    const bsonData = gunzipSync(gz.getData());
    const docs = parseBsonStream(bsonData, BSON);
    for (const doc of docs) {
      const coll = String(
        (doc as Record<string, unknown>)['collection']
          ?? (doc as Record<string, unknown>)['_type']
          ?? '_unknown',
      );
      if (!collections[coll]) collections[coll] = [];
      collections[coll]!.push(doc as Record<string, unknown>);
    }
  } else {
    for (const entry of entries) {
      if (!entry.entryName.endsWith('.bson')) continue;
      const name = entry.entryName.split('/').pop()?.replace('.bson', '') ?? '';
      if (!name) continue;
      collections[name] = parseBsonStream(entry.getData(), BSON);
    }
  }

  return collections;
}

async function parseConsoleUnifiFormat(raw: Buffer): Promise<Collections> {
  const { gunzipSync } = await import('node:zlib');

  const decryptedGz = decryptConsoleBackup(raw);
  const tarBuf = gunzipSync(decryptedGz);
  const dbGz = extractTarEntry(tarBuf, 'backup/network/db.gz');
  if (!dbGz) {
    throw new Error('backup/network/db.gz not found in decrypted console backup archive');
  }
  const bsonData = gunzipSync(dbGz);
  return parseMarkerStreamBson(bsonData);
}
```

Leave `parseBsonStream` (the helper at the bottom of the file) and `normalizeBackup`/`findSetting` completely unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run src/audit/__tests__/parseBackupNodejs.test.ts`
Expected: PASS — 3 tests passing.

Run: `npx vitest run src/audit/__tests__/normalizeBackup.test.ts`
Expected: PASS — all pre-existing tests still passing (proves the `Collections` type re-export didn't break `normalizeBackup()` itself).

- [ ] **Step 5: Run the full suite and type-check**

Run: `npm run test`
Expected: all green, zero failures.

Run: `npx tsc --noEmit`
Expected: no output (clean).

- [ ] **Step 6: Commit**

```bash
git add src/audit/normalizeBackup.ts src/audit/__tests__/parseBackupNodejs.test.ts
git commit -m "feat: fall back to console .unifi format when classic .unf parsing fails"
```

---

### Task 5: Anonymization tool + real fixture

**Files:**
- Create: `tools/anonymize-backup.ts`
- Modify: `package.json` (add npm script)
- Create: `samples/fixture-cgf-backup.json` (generated by running the tool, then committed)

**Interfaces:**
- Standalone script. Consumes `parseBackupNodejs` (Task 4) and `sanitize` from `../src/audit/sanitize.js` (existing, unchanged).
- Produces: `samples/fixture-cgf-backup.json` — a `Collections`-shaped JSON file (not the live-API shape other fixtures use).

No unit tests for this task — it's a maintainer tool whose real output is the deliverable, verified by inspection and by Task 6's regression test consuming it.

- [ ] **Step 1: Write the tool**

Create `tools/anonymize-backup.ts`:

```ts
/**
 * Maintainer-run tool. Reads a real UniFi backup file (classic .unf or
 * console .unifi), anonymizes it (MACs, IPs, names — deterministic
 * replacement so cross-references between collections stay intact —
 * plus the existing secret-field sanitizer), and writes the result as a
 * samples/fixture-*.json for the test suite. Runs entirely locally; the
 * backup file is never transmitted anywhere.
 *
 * Usage: npm run anonymize-backup -- <path-to-backup-file> [output-path]
 */
import { writeFileSync } from 'node:fs';
import { parseBackupNodejs } from '../src/audit/normalizeBackup.js';
import { sanitize } from '../src/audit/sanitize.js';

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const NAME_FIELDS = new Set(['name', 'hostname', 'desc', 'site_name', 'siteName', 'device_name', 'deviceName', 'note']);

function createAnonymizer() {
  const macMap = new Map<string, string>();
  const ipMap = new Map<string, string>();
  const nameMap = new Map<string, string>();
  let macCounter = 0;
  let ipCounter = 0;
  let nameCounter = 0;

  function fakeMac(real: string): string {
    if (!macMap.has(real)) {
      macCounter++;
      const hex = macCounter.toString(16).padStart(4, '0');
      macMap.set(real, `aa:00:${hex.slice(0, 2)}:00:${hex.slice(2, 4)}:00`);
    }
    return macMap.get(real)!;
  }

  function fakeIp(real: string): string {
    if (!ipMap.has(real)) {
      ipCounter++;
      ipMap.set(real, `10.99.${Math.floor(ipCounter / 254)}.${(ipCounter % 254) + 1}`);
    }
    return ipMap.get(real)!;
  }

  function fakeName(real: string): string {
    if (!nameMap.has(real)) {
      nameCounter++;
      nameMap.set(real, `Item-${String(nameCounter).padStart(2, '0')}`);
    }
    return nameMap.get(real)!;
  }

  function anonymize(key: string | null, value: unknown): unknown {
    if (Array.isArray(value)) return value.map(v => anonymize(null, v));
    if (value !== null && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = anonymize(k, v);
      }
      return out;
    }
    if (typeof value === 'string') {
      if (MAC_RE.test(value)) return fakeMac(value.toLowerCase());
      if (IP_RE.test(value)) return fakeIp(value);
      if (key && NAME_FIELDS.has(key) && value.length > 0) return fakeName(value);
    }
    return value;
  }

  return anonymize;
}

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

  const result: Record<string, unknown[]> = {};
  for (const [collName, docs] of Object.entries(collections)) {
    result[collName] = docs.map(doc => sanitize(anonymize(null, doc)));
  }

  writeFileSync(outputPath, JSON.stringify(result, null, 2));
  console.log(`Wrote anonymized fixture to ${outputPath} (${Object.keys(result).length} collections)`);
  console.log('Review the output before committing — this is a draft, not auto-verified safe.');
}

main().catch(err => {
  console.error('anonymize-backup failed:', err);
  process.exitCode = 1;
});
```

- [ ] **Step 2: Add the npm script**

In `package.json`, add to `"scripts"` (after `"fetch-advisories": "tsx tools/fetch-advisories.ts"`):

```json
    "anonymize-backup": "tsx tools/anonymize-backup.ts"
```

- [ ] **Step 3: Run it against the real backup file**

Run: `npm run anonymize-backup -- samples/unifi_os_backup_1783048515216_a228af65-42d5-4d42-8907-616ec6ae0f2b.unifi`

Expected: prints `Wrote anonymized fixture to samples/fixture-cgf-backup.json (~100 collections)`. This exercises the full Task 1-4 pipeline against real data for the first time — if it throws, the bug is almost certainly in the marker-parsing logic (Task 3) or the fallback chain (Task 4); re-check those against this real file before proceeding.

- [ ] **Step 4: Inspect the output for safety**

Run this check before committing anything:

```bash
grep -oE "([0-9a-f]{2}:){5}[0-9a-f]{2}" samples/fixture-cgf-backup.json | sort -u | head -20
```

Expected: every MAC address printed starts with `aa:00:` (the anonymizer's fake-MAC prefix) — if any real-looking MAC appears, STOP, do not commit, and report back with the specific field/collection where it appeared so the anonymizer's field coverage can be fixed.

Also spot-check for IP addresses and any obviously-real hostnames:

```bash
grep -oE "\"(name|hostname|desc)\": \"[^\"]*\"" samples/fixture-cgf-backup.json | sort -u | head -30
```

Expected: values look like `Item-01`, `Item-02`, etc. — not real device/network names. If real-looking names appear, the field wasn't in `NAME_FIELDS`; note it and stop rather than committing.

- [ ] **Step 5: Type-check and commit**

Run: `npx tsc --noEmit`
Expected: no output (clean).

```bash
git add tools/anonymize-backup.ts package.json package-lock.json samples/fixture-cgf-backup.json
git commit -m "$(cat <<'EOF'
feat: add tools/anonymize-backup.ts and the first real backup fixture

Deterministic MAC/IP/name anonymization (same real value -> same fake
value everywhere, preserving cross-collection references) layered on
top of the existing sanitize() secret-field scrubber. Run against a
real Cloud Gateway Fiber .unifi backup to produce
samples/fixture-cgf-backup.json -- inspected for leaked MACs/IPs/names
before committing.
EOF
)"
```

---

### Task 6: End-to-end regression against the real fixture

**Files:**
- Create: `src/audit/__tests__/fixtureCgfBackup.test.ts`

**Interfaces:**
- Consumes: `samples/fixture-cgf-backup.json` (Task 5), `normalizeBackup` from `../normalizeBackup.js`, `analyze` from `../analyze.js`.

- [ ] **Step 1: Write the test**

Create `src/audit/__tests__/fixtureCgfBackup.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { normalizeBackup } from '../normalizeBackup.js';
import { analyze } from '../analyze.js';

function loadFixture(): Record<string, Record<string, unknown>[]> {
  const p = path.join(process.cwd(), 'samples', 'fixture-cgf-backup.json');
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

describe('fixture: real Cloud Gateway Fiber console backup, decrypted', () => {
  const collections = loadFixture();
  const sites = normalizeBackup(collections, 'home_office');
  const findings = analyze(sites, {}, 'home_office');

  it('produces exactly one site (backups are single-site)', () => {
    expect(sites).toHaveLength(1);
  });

  it('has full API coverage (apiGaps is empty in backup mode)', () => {
    expect(sites[0]!.apiGaps).toHaveLength(0);
  });

  it('populates real device, network, and firewall data from the decrypted backup', () => {
    expect(sites[0]!.devices.length).toBeGreaterThan(0);
    expect(sites[0]!.networks.length).toBeGreaterThan(0);
  });

  it('runs the full analyze() pipeline without throwing and produces findings', () => {
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('evaluates SEG-MGMT-WAN against real firewallrule/portforward data (not the live-API unknown branch)', () => {
    const seg = findings.find(f => f.id.startsWith('SEG-MGMT-WAN'));
    expect(seg).toBeDefined();
    // In backup mode apiGaps is empty, so this must NOT be the
    // "cannot check via live API" branch — it evaluated real data.
    expect(seg!.currentState).not.toMatch(/not exposed by the Network Integration API/i);
  });
});
```

- [ ] **Step 2: Run the test**

Run: `npx vitest run src/audit/__tests__/fixtureCgfBackup.test.ts`
Expected: PASS. If the `SEG-MGMT-WAN` assertion fails, read the actual finding's `currentState`/`status` and adjust the assertion to match reality — this is the first time that heuristic has ever run against real field data, so its exact behavior (gap vs. unknown-no-rule-found) depends on what's actually in this real network's firewall rules, which isn't known until this test runs. Do not weaken the test to always pass; report what was actually found.

- [ ] **Step 3: Run the full suite and type-check**

Run: `npm run test`
Expected: all green.

Run: `npx tsc --noEmit`
Expected: no output (clean).

- [ ] **Step 4: Commit**

```bash
git add src/audit/__tests__/fixtureCgfBackup.test.ts
git commit -m "test: end-to-end regression for console backup decryption through the real analyze() pipeline"
```

---

## Self-Review

**Spec coverage:** Component 1 (three functions) — Tasks 1-3. Component 2 (dispatcher) — Task 4. Component 3 (anonymization script + fixture) — Task 5. Testing plan's three bullets — Tasks 1-3 (unit), Task 4 (fallback-chain integration), Task 6 (end-to-end against real data). Error-handling requirements (typed/specific errors for format detection; never-throw-on-malformed-doc for the marker parser) — Tasks 1, 3, 4. Explicit "not touched this round" list (Rust, Svelte UI) — no task touches either file; confirmed by the Global Constraints and by no task listing them.

**Placeholder scan:** no TBD/TODO; every step has complete, real code, including the synthetic test-fixture builders needed for Tasks 4's integration tests (which can't rely on the real file, since a plan-following engineer might not have it — though in this specific execution the real file is available locally, per Global Constraints).

**Type consistency:** `Collections` is defined once (Task 1, in `parseUnifiOsConsoleBackup.ts`) and imported everywhere else that needs it (Task 4's `normalizeBackup.ts`, replacing its former local declaration). `decryptConsoleBackup(raw: Buffer): Buffer`, `extractTarEntry(tarBuf: Buffer, entryName: string): Buffer | null`, and `parseMarkerStreamBson(bsonData: Buffer): Collections` signatures match between their Task 1-3 definitions and their Task 4 call sites in `parseConsoleUnifiFormat`.
