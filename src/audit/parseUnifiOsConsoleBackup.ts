import { createDecipheriv } from 'node:crypto';
import { BSON } from 'bson';

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
