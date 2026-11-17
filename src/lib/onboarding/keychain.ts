import { invoke } from '@tauri-apps/api/core';
import { getKv, setKv } from '../../db/queries.js';
import {
  parseIndex, serializeIndex, addIdentity, removeIdentity, type KeyIdentity,
} from './keyIndex.js';

const INDEX_KEY = 'saved_key_index';

/**
 * Keychain access from the page. There is no way to read or write a secret
 * here: the backend holds keys and uses them itself. The page can only forget
 * a key, list account names, and see a key's last four characters.
 */
export const keychain = {
  delete: (account: string) => invoke<void>('keychain_delete', { account }),
  scan: () => invoke<string[]>('keychain_scan'),
  hint: (account: string) => invoke<string | null>('keychain_hint', { account }),
};

/** What the backend reports about an open connection (never the key). */
export interface ConnectionInfo {
  account: string;
  mode: 'local' | 'cloud';
  host: string | null;
}

/**
 * A local controller's certificate pin (SHA-256, colon-separated hex). After
 * the backend refused a connection, `presented` is what the controller showed
 * instead. Neither value is secret. Cloud connections have neither.
 */
export interface CertificateInfo {
  pinned: string | null;
  presented: string | null;
}

/**
 * The backend's connection session. A key goes in once (freshly pasted) or is
 * named by its saved account; after that, requests go to the controller the
 * account is bound to and nowhere else.
 */
export const connection = {
  open: (mode: 'local' | 'cloud', host: string, apiKey: string) =>
    invoke<ConnectionInfo>('connection_open', { mode, host, apiKey }),
  openSaved: (account: string) => invoke<ConnectionInfo>('connection_open_saved', { account }),
  remember: () => invoke<ConnectionInfo>('connection_remember'),
  close: () => invoke<void>('connection_close'),
  certificate: () => invoke<CertificateInfo>('connection_certificate'),
  /**
   * Ask the backend to trust the certificate the controller just presented.
   * The backend shows a native confirmation dialog with both fingerprints and
   * pins the value it observed itself; the page cannot name one. Resolves
   * false if the user kept the old pin.
   */
  repin: () => invoke<boolean>('connection_repin'),
};

export async function loadIndex(): Promise<KeyIdentity[]> {
  return parseIndex(await getKv(INDEX_KEY));
}

export async function saveIndex(list: KeyIdentity[]): Promise<void> {
  await setKv(INDEX_KEY, serializeIndex(list));
}

/**
 * Store the open connection's key (opt-in) and record its non-secret identity
 * in the index. The backend saves the key under the connection's own account,
 * so the identity recorded here is the one the backend reports.
 */
export async function rememberKey(label: string): Promise<void> {
  const info = await connection.remember();
  const entry: KeyIdentity = {
    identity: info.account,
    mode: info.mode,
    host: info.mode === 'local' ? (info.host ?? undefined) : undefined,
    label,
  };
  await saveIndex(addIdentity(await loadIndex(), entry));
}

/** Delete a stored key and drop it from the index. */
export async function forgetKey(identity: string): Promise<void> {
  await keychain.delete(identity);
  await saveIndex(removeIdentity(await loadIndex(), identity));
}
