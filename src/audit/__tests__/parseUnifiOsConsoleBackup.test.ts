import { describe, it, expect } from 'vitest';
import { createCipheriv, randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { decryptConsoleBackup, extractTarEntry } from '../parseUnifiOsConsoleBackup.js';

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
