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
