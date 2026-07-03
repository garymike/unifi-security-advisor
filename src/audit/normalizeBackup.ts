import type { NormalizedSite } from './types.js';
import type { Collections } from './parseUnifiOsConsoleBackup.js';
import { decryptConsoleBackup, extractTarEntry, parseMarkerStreamBson } from './parseUnifiOsConsoleBackup.js';

export function findSetting(
  collections: Collections,
  key: string,
): Record<string, unknown> | undefined {
  const settings = collections['setting'] ?? [];
  return settings.find(s => s['key'] === key) as Record<string, unknown> | undefined;
}

export function normalizeBackup(collections: Collections, profile: string): NormalizedSite[] {
  const identity = findSetting(collections, 'super_identity');
  const siteId = String(identity?.['name'] ?? 'default');
  const siteName = String(identity?.['desc'] ?? identity?.['name'] ?? 'Default');

  // VPN configs may be in multiple collections depending on UniFi version
  const vpnConfigs = [
    ...(collections['vpnserver'] ?? []),
    ...(collections['openvpn_server'] ?? []),
    ...(collections['ipsec_server'] ?? []),
    ...(collections['vpn'] ?? []),
  ];

  return [{
    siteId,
    siteName,
    devices:          collections['device'] ?? [],
    clients:          collections['user'] ?? [],
    wlans:            collections['wlanconf'] ?? [],
    networks:         collections['networkconf'] ?? [],
    portForwards:     collections['portforward'] ?? [],
    vpnConfigs,
    firewallPolicies: collections['firewallrule'] ?? [],
    firewallZones:    collections['firewallgroup'] ?? [],
    trafficRoutes:    collections['trafficrule'] ?? [],
    // settings is always {} in API mode; in backup mode we populate it from
    // the 'setting' collection, unlocking all currently-unknown findings.
    settings: {
      rogueap:           findSetting(collections, 'rogueap'),
      dns_filtering:     findSetting(collections, 'dns_filtering')
                           ?? findSetting(collections, 'connectivity'),
      auto_update:       findSetting(collections, 'auto_update'),
      auto_backup:       findSetting(collections, 'auto_backup')
                           ?? findSetting(collections, 'backup'),
      mgmt:              findSetting(collections, 'mgmt'),
      dpi:               findSetting(collections, 'dpi'),
      threat_management: findSetting(collections, 'threat_management'),
    },
    profile,
    apiGaps: [], // backup has full coverage — no API gaps
  }];
}

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

function parseBsonStream(
  data: Buffer,
  BSON: typeof import('bson').BSON,
): Record<string, unknown>[] {
  const docs: Record<string, unknown>[] = [];
  let pos = 0;
  while (pos + 4 <= data.length) {
    const len = data.readInt32LE(pos);
    if (len < 5 || pos + len > data.length) break;
    try {
      docs.push(BSON.deserialize(data.subarray(pos, pos + len)) as Record<string, unknown>);
    } catch { break; }
    pos += len;
  }
  return docs;
}
