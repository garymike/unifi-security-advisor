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
