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
