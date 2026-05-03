# Phase 4: Backup-File Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse UniFi `.unf` backup files via a Rust Tauri command to unlock all the `unknown` findings (WLANs, VPN, firewall rules, settings) that the live API v1 cannot yet expose.

**Architecture:** Rust command (`parse_backup`) handles AES decrypt → ZIP extract → BSON parse → returns raw collections JSON. TypeScript `normalizeBackup()` maps MongoDB collection names to `NormalizedSite`, crucially populating the `settings` field from the `setting` collection. Everything downstream (analyze, wizard, report, SQLite) is unchanged. CLI gets a `--backup` flag using Node.js crypto + `bson` npm as a parallel path.

**Tech Stack:** Rust (`aes`, `cbc`, `flate2`, `zip`, `bson` crates), TypeScript, `@tauri-apps/plugin-dialog`, `adm-zip` npm (CLI only), `bson` npm (CLI only), Vitest

---

## File Map

| File | Change |
|------|--------|
| `src-tauri/Cargo.toml` | Add `aes`, `cbc`, `flate2`, `zip`, `bson`, `tauri-plugin-dialog` |
| `src-tauri/src/lib.rs` | Add `parse_backup` command + dialog plugin |
| `src-tauri/capabilities/default.json` | Add `dialog:allow-open` |
| `src/audit/normalizeBackup.ts` | **Create** — `normalizeBackup()`, `parseBackupNodejs()`, `findSetting()` |
| `src/audit/__tests__/normalizeBackup.test.ts` | **Create** — 10 unit tests |
| `src/routes/backup/+page.svelte` | **Create** — Backup tab UI |
| `src/routes/+layout.svelte` | Add Backup tab |
| `src/cli.ts` | Add `--backup` flag |

---

## Task 1: Rust `parse_backup` command + dialog plugin

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/capabilities/default.json`

- [ ] **Step 1: Add Cargo dependencies**

In `src-tauri/Cargo.toml`, add to `[dependencies]`:

```toml
aes = "0.8"
cbc = { version = "0.1", features = ["alloc"] }
flate2 = "1.0"
zip = "2"
bson = "2"
tauri-plugin-dialog = "2"
```

- [ ] **Step 2: Add `dialog:allow-open` capability**

In `src-tauri/capabilities/default.json`, add to the `permissions` array:

```json
"dialog:allow-open"
```

- [ ] **Step 3: Replace `src-tauri/src/lib.rs` entirely**

```rust
use std::collections::HashMap;
use std::io::Read;
use tauri::command;

// Public AES-128-CBC keys (from UniFi source, used by all open-source tools in this space)
const UNF_KEY: &[u8; 16] = b"bcyangkmluohmars";
const UNF_IV: &[u8; 16] = b"ubntenterpriseap";

/// HTTP fetch with TLS cert validation disabled — required for local UniFi controllers
/// which use self-signed certificates.
#[command]
async fn unifi_fetch(url: String, api_key: String) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let response = client
        .get(&url)
        .header("X-API-KEY", &api_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = response.status().as_u16();
    let data: serde_json::Value = match response.json().await {
        Ok(v) => v,
        Err(_) => serde_json::json!({ "nonJsonResponse": true }),
    };

    Ok(serde_json::json!({ "status": status, "data": data }))
}

/// Parse a UniFi .unf backup file. Returns raw MongoDB collections as JSON.
/// All crypto (AES-128-CBC) and binary parsing (ZIP, BSON) runs in Rust —
/// the decrypted data never touches the webview's JavaScript heap.
#[command]
fn parse_backup(path: String) -> Result<serde_json::Value, String> {
    use aes::Aes128;
    use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;
    use flate2::read::GzDecoder;
    use std::io::Cursor;
    use zip::ZipArchive;

    type Aes128CbcDec = Decryptor<Aes128>;

    // 1. Read and decrypt
    let ciphertext = std::fs::read(&path)
        .map_err(|e| format!("Cannot read '{}': {}", path, e))?;

    let decrypted = Aes128CbcDec::new(UNF_KEY.into(), UNF_IV.into())
        .decrypt_padded_vec_mut::<NoPadding>(&ciphertext)
        .map_err(|e| format!("AES decryption failed: {:?}", e))?;

    // 2. Verify ZIP magic bytes
    if decrypted.len() < 4 || &decrypted[..4] != b"PK\x03\x04" {
        return Err(
            "Not a valid .unf backup (wrong ZIP signature). \
             Ensure you selected a UniFi Network backup file, not a console backup."
                .to_string(),
        );
    }

    // 3. Open ZIP
    let mut zip = ZipArchive::new(Cursor::new(&decrypted))
        .map_err(|e| format!("ZIP error: {}", e))?;

    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();

    let mut collections: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    if names.iter().any(|n| n == "db.gz") {
        // Older single-file format: db.gz with all collections concatenated
        let mut gz_file = zip.by_name("db.gz").map_err(|e| e.to_string())?;
        let mut gz_data = Vec::new();
        gz_file.read_to_end(&mut gz_data).map_err(|e| e.to_string())?;
        let mut bson_data = Vec::new();
        GzDecoder::new(gz_data.as_slice())
            .read_to_end(&mut bson_data)
            .map_err(|e| e.to_string())?;
        for doc in parse_bson_stream(&bson_data)? {
            let coll = doc
                .get("collection")
                .or_else(|| doc.get("_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("_unknown")
                .to_string();
            collections.entry(coll).or_default().push(doc);
        }
    } else {
        // Newer mongodump format: dump/<db>/<collection>.bson
        for i in 0..zip.len() {
            let mut file = zip.by_index(i).map_err(|e| e.to_string())?;
            let name = file.name().to_string();
            if !name.ends_with(".bson") {
                continue;
            }
            let coll = std::path::Path::new(&name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if coll.is_empty() {
                continue;
            }
            let mut data = Vec::new();
            file.read_to_end(&mut data).map_err(|e| e.to_string())?;
            collections.insert(coll, parse_bson_stream(&data)?);
        }
    }

    serde_json::to_value(collections).map_err(|e| e.to_string())
}

fn parse_bson_stream(data: &[u8]) -> Result<Vec<serde_json::Value>, String> {
    let mut docs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        if len < 5 || pos + len > data.len() {
            break;
        }
        match bson::from_slice::<bson::Document>(&data[pos..pos + len]) {
            Ok(doc) => docs.push(serde_json::to_value(&doc).map_err(|e| e.to_string())?),
            Err(_) => break,
        }
        pos += len;
    }
    Ok(docs)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![unifi_fetch, parse_backup])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 4: Verify Rust compiles (takes 2–5 minutes first time)**

```bash
cd src-tauri && cargo check 2>&1 | tail -5
```

Expected: `Finished \`dev\` profile` with no errors. If there are import errors for `block_padding`, the cbc crate path is `cbc::cipher::block_padding::NoPadding` — verify the exact path with `cargo doc --open` if needed.

- [ ] **Step 5: Install dialog plugin npm package**

```bash
npm install @tauri-apps/plugin-dialog
```

- [ ] **Step 6: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/lib.rs src-tauri/capabilities/default.json package.json package-lock.json
git commit -m "feat: add parse_backup Rust command (AES+ZIP+BSON) and dialog plugin"
```

---

## Task 2: `normalizeBackup.ts` + tests

**Files:**
- Create: `src/audit/normalizeBackup.ts`
- Create: `src/audit/__tests__/normalizeBackup.test.ts`

- [ ] **Step 1: Install CLI-only npm packages**

```bash
npm install adm-zip bson
npm install --save-dev @types/adm-zip
```

- [ ] **Step 2: Write the failing tests**

Create `src/audit/__tests__/normalizeBackup.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { normalizeBackup } from '../normalizeBackup.js';

const COLLECTIONS = {
  setting: [
    { key: 'super_identity', name: 'HomeNet', desc: 'Home Network' },
    { key: 'auto_update', enabled: true },
    { key: 'mgmt', syslog_host: null, advanced_feature_enabled: false },
    { key: 'rogueap', report_rogue: false },
    { key: 'auto_backup', enabled: true, destination: 'cloud' },
    { key: 'dpi', level: 'disabled' },
  ],
  device: [{ mac: 'aa:bb:cc', model: 'U7Pro', version: '8.5.21' }],
  wlanconf: [{ name: 'HomeWifi', security: 'wpapsk', wpa_mode: 'wpa3', enabled: true }],
  networkconf: [{ name: 'LAN', purpose: 'corporate', vlan: 1 }, { name: 'IoT', purpose: 'vlan-only', vlan: 20 }],
  portforward: [{ name: 'SSH', proto: 'tcp', dst_port: 22, enabled: true }],
  firewallrule: [{ name: 'Block WAN', ruleset: 'WAN_IN', action: 'drop', enabled: true }],
  firewallgroup: [],
  user: [{ hostname: 'my-laptop', mac: 'dd:ee:ff' }],
};

describe('normalizeBackup', () => {
  it('returns one site (backups are single-site)', () => {
    expect(normalizeBackup(COLLECTIONS, 'home_office')).toHaveLength(1);
  });

  it('sets siteId and siteName from super_identity setting', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.siteId).toBe('HomeNet');
    expect(site!.siteName).toBe('Home Network');
  });

  it('maps device → devices', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.devices).toHaveLength(1);
    expect(site!.devices[0]).toMatchObject({ mac: 'aa:bb:cc' });
  });

  it('maps wlanconf → wlans', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.wlans[0]).toMatchObject({ name: 'HomeWifi' });
  });

  it('maps networkconf → networks', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.networks).toHaveLength(2);
  });

  it('maps portforward → portForwards', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.portForwards).toHaveLength(1);
  });

  it('maps firewallrule → firewallPolicies', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.firewallPolicies).toHaveLength(1);
  });

  it('maps user → clients', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.clients[0]).toMatchObject({ hostname: 'my-laptop' });
  });

  it('populates settings.auto_update from setting collection (unlocks FW-AUTO-001)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.settings['auto_update']).toBeDefined();
    expect((site!.settings['auto_update'] as Record<string, unknown>)['enabled']).toBe(true);
  });

  it('populates settings.rogueap (unlocks RF-ROGUE-001)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.settings['rogueap']).toBeDefined();
    expect((site!.settings['rogueap'] as Record<string, unknown>)['report_rogue']).toBe(false);
  });

  it('populates settings.auto_backup (unlocks BAK-001)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.settings['auto_backup']).toBeDefined();
    expect((site!.settings['auto_backup'] as Record<string, unknown>)['destination']).toBe('cloud');
  });

  it('apiGaps is empty (backup has full coverage)', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'home_office');
    expect(site!.apiGaps).toHaveLength(0);
  });

  it('sets profile', () => {
    const [site] = normalizeBackup(COLLECTIONS, 'regulated_hipaa');
    expect(site!.profile).toBe('regulated_hipaa');
  });
});
```

- [ ] **Step 3: Run tests — expect failures**

```bash
npm test -- src/audit/__tests__/normalizeBackup.test.ts
```

Expected: `Cannot find module '../normalizeBackup.js'`

- [ ] **Step 4: Create `src/audit/normalizeBackup.ts`**

```typescript
import type { NormalizedSite } from './types.js';

type Collections = Record<string, Record<string, unknown>[]>;

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
  const { createDecipheriv } = await import('node:crypto');
  const { resolve } = await import('node:path');
  const { gunzipSync } = await import('node:zlib');

  const KEY = Buffer.from('bcyangkmluohmars');
  const IV  = Buffer.from('ubntenterpriseap');

  const ciphertext = await readFile(resolve(filePath));
  const decipher = createDecipheriv('aes-128-cbc', KEY, IV);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  if (decrypted.slice(0, 4).toString('binary') !== 'PK\x03\x04') {
    throw new Error('Not a valid .unf backup file (wrong ZIP signature)');
  }

  // adm-zip is a Node.js-only dependency; dynamically imported so it is never
  // bundled for the Tauri webview (where Rust handles the same work).
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
```

- [ ] **Step 5: Run tests — expect all pass**

```bash
npm test -- src/audit/__tests__/normalizeBackup.test.ts
```

Expected: 13 passed

- [ ] **Step 6: Run full suite**

```bash
npm test
```

Expected: 114 passed (101 existing + 13 new)

- [ ] **Step 7: Commit**

```bash
git add src/audit/normalizeBackup.ts src/audit/__tests__/normalizeBackup.test.ts package.json package-lock.json
git commit -m "feat: add normalizeBackup() + parseBackupNodejs() — maps .unf collections to NormalizedSite"
```

---

## Task 3: Backup tab UI

**Files:**
- Create: `src/routes/backup/+page.svelte`

- [ ] **Step 1: Create `src/routes/backup/+page.svelte`**

```svelte
<script lang="ts">
  import { goto } from '$app/navigation';
  import { normalizeBackup } from '../../audit/normalizeBackup.js';
  import { analyze } from '../../audit/analyze.js';

  const ALL_PROFILES = [
    'home', 'home_office', 'small_business', 'regulated_hipaa', 'regulated_pci',
  ] as const;
  const PROFILE_LABELS: Record<string, string> = {
    home: 'Home', home_office: 'Home Office', small_business: 'Small Business',
    regulated_hipaa: 'Regulated (HIPAA)', regulated_pci: 'Regulated (PCI)',
  };

  let filePath: string | null = $state(null);
  let fileName: string | null = $state(null);
  let profile = $state('home_office');
  let running = $state(false);
  let progressLog: string[] = $state([]);
  let error = $state('');

  async function browse() {
    const { open } = await import('@tauri-apps/plugin-dialog');
    const selected = await open({
      filters: [{ name: 'UniFi Backup', extensions: ['unf'] }],
      multiple: false,
    });
    if (typeof selected === 'string') {
      filePath = selected;
      fileName = selected.split(/[/\\]/).pop() ?? selected;
    }
  }

  async function runAnalysis() {
    if (!filePath) return;
    running = true; error = ''; progressLog = [];
    try {
      progressLog = [...progressLog, 'Decrypting and parsing backup...'];
      const { invoke } = await import('@tauri-apps/api/core');
      const collections = await invoke<Record<string, Record<string, unknown>[]>>(
        'parse_backup', { path: filePath },
      );
      const collectionCount = Object.keys(collections).length;
      progressLog = [...progressLog, `Parsed ${collectionCount} collections`];

      const sites = normalizeBackup(collections, profile);
      const site = sites[0];
      progressLog = [...progressLog,
        `Normalized — ${site?.wlans.length ?? 0} WLANs, ${site?.devices.length ?? 0} devices, ${site?.networks.length ?? 0} networks`,
      ];

      progressLog = [...progressLog, 'Running findings analysis...'];
      const findings = analyze(sites, {}, profile, (mod, _site, err) => {
        progressLog = [...progressLog, `Warning: ${mod} failed: ${err}`];
      });
      progressLog = [...progressLog, `Found ${findings.length} findings`];

      const { openDb, insertRun, insertFindings, insertSites } = await import('../../db/queries.js');
      const db = await openDb();
      const runId = await insertRun(db, `backup:${fileName}`, profile, sites.length);
      await insertFindings(db, runId, findings);
      await insertSites(db, runId, sites.map(s => ({
        siteId: s.siteId, siteName: s.siteName, apiGaps: s.apiGaps,
      })));

      goto(`/wizard?runId=${runId}&profile=${profile}`);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      running = false;
    }
  }
</script>

<main class="p-8 max-w-xl mx-auto">
  <h1 class="text-2xl font-bold mb-2">Analyze Backup File</h1>
  <p class="text-gray-500 text-sm mb-8">
    Parse a UniFi Network backup (.unf) entirely offline. Unlocks WLAN, VPN,
    firewall, and settings findings that the live API cannot yet provide.
  </p>

  <div class="space-y-4 mb-6">
    <div>
      <label class="block text-sm font-medium text-gray-700 mb-1">Backup file</label>
      <div class="flex items-center gap-2">
        <button
          class="px-4 py-2 border rounded-lg text-sm hover:bg-gray-50 font-medium shrink-0"
          onclick={browse}
          disabled={running}
        >Browse…</button>
        {#if fileName}
          <span class="text-sm text-gray-700 flex-1 truncate">{fileName}</span>
          <button
            class="text-gray-400 hover:text-gray-600 text-sm shrink-0"
            onclick={() => { filePath = null; fileName = null; }}
          >×</button>
        {:else}
          <span class="text-sm text-gray-400">No file selected</span>
        {/if}
      </div>
      <p class="text-xs text-gray-400 mt-1">
        Generated in UniFi Network → System → Backup. File stays on your machine.
      </p>
    </div>

    <div>
      <label class="block text-sm font-medium text-gray-700 mb-1">Profile</label>
      <select
        class="border rounded-lg px-3 py-2 text-sm w-full"
        bind:value={profile}
        disabled={running}
      >
        {#each ALL_PROFILES as p}
          <option value={p}>{PROFILE_LABELS[p]}</option>
        {/each}
      </select>
    </div>
  </div>

  {#if error}
    <p class="text-red-600 text-sm mb-4">{error}</p>
  {/if}

  <button
    class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 disabled:opacity-50"
    onclick={runAnalysis}
    disabled={running || !filePath}
  >
    {running ? 'Analyzing…' : 'Analyze Backup →'}
  </button>

  {#if progressLog.length > 0}
    <div class="mt-6 bg-gray-50 rounded-lg p-4 font-mono text-xs space-y-1 max-h-48 overflow-y-auto">
      {#each progressLog as line}
        <div>{line}</div>
      {/each}
    </div>
  {/if}
</main>
```

- [ ] **Step 2: Verify Vite build**

```bash
npm run build
```

Expected: `✔ done`

- [ ] **Step 3: Commit**

```bash
git add src/routes/backup/+page.svelte
git commit -m "feat: add Backup tab UI — file picker, analysis progress, routes to wizard"
```

---

## Task 4: Layout tab + CLI `--backup` flag

**Files:**
- Modify: `src/routes/+layout.svelte`
- Modify: `src/cli.ts`

- [ ] **Step 1: Add Backup tab to `src/routes/+layout.svelte`**

Find the `tabs` array (currently 3 entries). Replace it:

```typescript
  const tabs = [
    { label: 'Analyze', href: '/audit' },
    { label: 'Backup',  href: '/backup' },
    { label: 'Report',  href: '/report' },
    { label: 'History', href: '/history' },
  ] as const;
```

- [ ] **Step 2: Add `--backup` flag to `src/cli.ts`**

Replace the entire `main()` function body (and add a `runBackupMode` helper before it):

```typescript
async function runBackupMode(
  backupPath: string,
  outputDir: string,
  log: (msg: string) => void,
): Promise<void> {
  const profile = process.env['UNIFI_PROFILE'] ?? 'home_office';
  log('='.repeat(60));
  log('UniFi Security Advisor - backup file mode');
  log(`File: ${backupPath}`);
  log(`Profile: ${profile}`);
  log('='.repeat(60));

  const { parseBackupNodejs, normalizeBackup } = await import('./audit/normalizeBackup.js');

  log('Parsing backup file...');
  const collections = await parseBackupNodejs(backupPath);
  log(`Parsed ${Object.keys(collections).length} collections`);

  const sites = normalizeBackup(collections, profile);
  log(`Normalized — ${sites[0]?.wlans.length ?? 0} WLANs, ${sites[0]?.devices.length ?? 0} devices`);

  log('Running findings analysis...');
  const findings = analyze(sites, {}, profile, (mod, site, err) => {
    console.error(`Module ${mod} failed on ${site}: ${err}`);
  });

  await writeFile(join(outputDir, 'findings.json'), JSON.stringify(findings, null, 2));
  log(`Wrote findings.json (${findings.length} findings)`);

  const report = renderReport(findings, profile, 0, 0);
  await writeFile(join(outputDir, 'report.md'), report);
  log('Wrote report.md');
  log('Done.');
  log('NEXT STEPS');
  log('  1. Review report.md');
}

async function main() {
  const outputDir = process.env['UNIFI_OUTPUT_DIR'] ?? './audit_output';
  await mkdir(outputDir, { recursive: true });
  const log = (msg: string) => console.log(msg);

  const backupIdx = process.argv.indexOf('--backup');
  if (backupIdx !== -1) {
    const backupPath = process.argv[backupIdx + 1];
    if (!backupPath) {
      console.error('Error: --backup requires a file path\nUsage: node dist/cli.js --backup ./backup.unf');
      process.exit(1);
    }
    await runBackupMode(backupPath, outputDir, log);
    return;
  }

  // Live API mode (existing flow)
  const client = UniFiClient.fromEnv();
  log('='.repeat(60));
  log('UniFi Security Advisor - starting audit');
  log(`Mode: ${client.config.useCloud ? 'cloud (Site Manager)' : 'local'}`);
  if (!client.config.useCloud) log(`Host: ${client.config.host}`);
  log(`Profile: ${client.config.profile}`);
  log('='.repeat(60));

  const raw = await collectAll(client, log);
  log('Sanitizing collected data...');
  const clean = sanitize(raw) as Record<string, unknown>;

  await writeFile(join(outputDir, 'raw_sanitized.json'), JSON.stringify(clean, null, 2));
  log('Wrote raw_sanitized.json');

  log('Running findings analysis...');
  const sites = normalizeApi(clean, client.config.profile);
  if (sites.length === 0) {
    log('Warning: no sites normalized from API response. Check API key scope and controller connectivity.');
    if (client.config.useCloud) {
      log('  Cloud mode: ensure Cloud Connector is enabled on the console (UniFi OS → System → Cloud Access).');
    }
  }
  const findings = analyze(sites, clean, client.config.profile, (mod, site, err) => {
    console.error(`Module ${mod} failed on ${site}: ${err}`);
  });

  await writeFile(join(outputDir, 'findings.json'), JSON.stringify(findings, null, 2));
  log(`Wrote findings.json (${findings.length} findings)`);

  const report = renderReport(
    findings,
    client.config.profile,
    (clean['_endpointsProbed'] as unknown[]).length,
    ((clean['_errors'] as unknown[]) ?? []).length,
  );
  await writeFile(join(outputDir, 'report.md'), report);
  log('Wrote report.md');
  log('='.repeat(60));
  log('Done.');

  if (process.argv.includes('--save')) {
    try {
      const { openDb, insertRun, insertFindings, insertSites } = await import('./db/queries.js');
      const db = await openDb();
      const runId = await insertRun(db, client.config.host || 'cloud', client.config.profile, sites.length);
      await insertFindings(db, runId, findings);
      await insertSites(db, runId, sites.map(s => ({
        siteId: s.siteId, siteName: s.siteName, apiGaps: s.apiGaps,
      })));
      log(`Saved run ${runId} to local DB.`);
    } catch {
      log('Note: --save requires Tauri runtime context. DB write skipped in CLI mode.');
    }
  }

  log('NEXT STEPS');
  log('  1. Review report.md');
  log('  2. Revoke the API key in Site Manager');
}
```

- [ ] **Step 3: Build CLI and verify it still works**

```bash
npm run build:audit 2>&1 | tail -3
```

Expected: no TypeScript errors

- [ ] **Step 4: Run full test suite**

```bash
npm test
```

Expected: 114 passed (unchanged — layout and CLI changes have no unit tests)

- [ ] **Step 5: Verify live API mode still works**

```bash
export $(cat .env | xargs) && node dist/cli.js 2>&1 | grep "findings\|Done"
```

Expected: `Wrote findings.json (9 findings)` and `Done.`

- [ ] **Step 6: Verify backup CLI mode works (requires a real .unf file)**

Generate a backup from UniFi Network → System → Backup → Download. Then:

```bash
UNIFI_PROFILE=home_office node dist/cli.js --backup ./path/to/backup.unf 2>&1
```

Expected: log shows collection count, WLAN count, finding count. `audit_output/report.md` contains findings for WLANs, firewall rules, VPN config, and settings-based findings that previously showed `unknown`.

- [ ] **Step 7: Commit**

```bash
git add src/routes/+layout.svelte src/cli.ts
git commit -m "feat: add Backup tab to nav; add --backup flag to CLI"
```

---

## Task 5: Tauri restart and end-to-end verify

The Rust changes from Task 1 require a full `npx tauri dev` restart (Cargo compile).

- [ ] **Step 1: Stop existing `npx tauri dev` process (Ctrl+C)**

- [ ] **Step 2: Start fresh**

```bash
npx tauri dev
```

Wait for Rust compile (2–5 minutes for new crates). The window reopens when done.

- [ ] **Step 3: Verify Backup tab appears in nav**

Open the app. Confirm four tabs: **Analyze | Backup | Report | History**

- [ ] **Step 4: Verify Backup tab UI**

Click the Backup tab. Confirm:
- "Browse…" button and explanatory text render
- Clicking Browse opens a native file dialog filtered to `.unf`
- Selecting a file shows the filename
- Profile dropdown shows all 5 profiles
- "Analyze Backup →" button is disabled until a file is selected

- [ ] **Step 5: Run a backup analysis end-to-end**

Generate a backup: UniFi Network → System → Backup → Download Now → wait → Download.

Select the `.unf` file in the Backup tab. Click "Analyze Backup →". Confirm:
- Progress log shows: decrypting, collection count, WLAN/device counts, finding count
- Wizard opens (profile confirm, skills check, gap questions)
- Report shows findings including ones that were previously `unknown` in live mode:
  - `RF-ROGUE-001` should now show `gap` or `ok` (not `unknown`)
  - `FW-AUTO-001` should reflect actual auto-update setting
  - `BAK-001`/`BAK-002` should reflect actual backup config
  - `LOG-FWD-001` should reflect actual syslog config
- History tab shows the backup run with `backup:filename.unf` label

- [ ] **Step 6: Final commit if any small fixes were needed**

```bash
git add -A
git commit -m "fix: backup mode end-to-end adjustments from manual verification"
```
