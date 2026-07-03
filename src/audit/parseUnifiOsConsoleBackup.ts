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
