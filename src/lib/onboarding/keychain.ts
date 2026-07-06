import { invoke } from '@tauri-apps/api/core';
import { getKv, setKv } from '../../db/queries.js';
import {
  parseIndex, serializeIndex, addIdentity, removeIdentity, type KeyIdentity,
} from './keyIndex.js';

const INDEX_KEY = 'saved_key_index';

export const keychain = {
  save: (account: string, secret: string) => invoke<void>('keychain_set', { account, secret }),
  load: (account: string) => invoke<string | null>('keychain_get', { account }),
  delete: (account: string) => invoke<void>('keychain_delete', { account }),
  scan: () => invoke<string[]>('keychain_scan'),
};

export async function loadIndex(): Promise<KeyIdentity[]> {
  return parseIndex(await getKv(INDEX_KEY));
}

export async function saveIndex(list: KeyIdentity[]): Promise<void> {
  await setKv(INDEX_KEY, serializeIndex(list));
}

/** Store a key (opt-in) and record its non-secret identity in the index. */
export async function rememberKey(entry: KeyIdentity, secret: string): Promise<void> {
  await keychain.save(entry.identity, secret);
  await saveIndex(addIdentity(await loadIndex(), entry));
}

/** Delete a stored key and drop it from the index. */
export async function forgetKey(identity: string): Promise<void> {
  await keychain.delete(identity);
  await saveIndex(removeIdentity(await loadIndex(), identity));
}
