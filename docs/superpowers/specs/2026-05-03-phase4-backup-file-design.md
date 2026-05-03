# Phase 4: Backup-File Mode Design

**Date:** 2026-05-03  
**Status:** Approved  
**Scope:** Parse UniFi `.unf` backup files to unlock all `unknown` findings that the live Network Integration API v1 cannot yet expose.

---

## Problem

The live Network Integration API v1 returns 404 for 6 of 9 endpoints (WLANs, firewall policies, port forwards, VPN configs, firewall zones, traffic routes). This means 5+ findings always show `status: 'unknown'` — auto-update, backup schedule, DNS filtering, rogue AP detection, syslog. The `.unf` backup file contains all of this data.

---

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| UI surface | Both Tauri app (new Backup tab) and CLI (`--backup` flag) | Users need both; same underlying logic |
| Tab structure | Four tabs: Analyze \| Backup \| Report \| History | Backup is a distinct input mode, not a variant of Analyze |
| Parsing runtime | Rust Tauri command for app, Node.js crypto + bson npm for CLI | Rust: security/isolation (decryption never in webview heap); Node: CLI has no Tauri context |
| Data returned by Rust | Raw collections as JSON | TypeScript handles normalization; Rust handles only the unsafe native operations |
| Backup format | `.unf` only (single-site, AES-encrypted ZIP+BSON) | `.unifi` console format is out of scope |

---

## Architecture

```
.unf file on disk
      │
      ▼
[Rust: parse_backup command]
  AES-128-CBC decrypt (static public key)
  ZIP extract in memory
  BSON parse per collection
      │
      ▼  HashMap<String, Vec<serde_json::Value>>
[TypeScript: normalizeBackup()]
  maps MongoDB collection names → NormalizedSite fields
  populates settings{} from 'setting' collection  ← KEY UNLOCK
      │
      ▼  NormalizedSite[]
[existing analyze() pipeline — unchanged]
  10 finding modules run
  float-top sorting, profile overrides, score
      │
      ▼
[existing wizard + report flow — unchanged]
  stored in SQLite as a normal run
  host = 'backup:filename.unf'
```

For CLI mode, `parseBackupNodejs()` replaces the Rust command using `node:crypto` (built-in AES-128-CBC) and `bson` npm package. Same `IS_TAURI` detection pattern as `client.ts`.

---

## Section 1: Rust `parse_backup` Command

### New Cargo dependencies

```toml
# src-tauri/Cargo.toml
aes = "0.8"
cbc = { version = "0.1", features = ["alloc"] }
flate2 = "1.0"
zip = "2"
bson = "2"
```

### Command signature

```rust
#[tauri::command]
async fn parse_backup(path: String) -> Result<serde_json::Value, String>
```

### Processing steps

1. Read file bytes from `path`
2. Decrypt AES-128-CBC:
   - Key: `62 63 79 61 6e 67 6b 6d 6c 75 6f 68 6d 61 72 73` ("bcyangkmluohmars")
   - IV:  `75 62 6e 74 65 6e 74 65 72 70 72 69 73 65 61 70` ("ubntenterpriseap")
3. Verify ZIP magic bytes (`PK\x03\x04`) — return descriptive error if wrong
4. Extract ZIP in memory; detect format:
   - **Older format:** single `db.gz` entry → decompress gzip → parse as concatenated BSON
   - **Newer format:** `dump/<db>/<collection>.bson` files → one BSON file per collection
5. Return `{ "wlanconf": [...], "networkconf": [...], "setting": [...], ... }` as JSON

### Capability change

None required — the file path is passed as a command argument, not accessed via Tauri's filesystem plugin.

---

## Section 2: `normalizeBackup()` TypeScript Function

**New file:** `src/audit/normalizeBackup.ts`

### Collection name mapping

| MongoDB collection | `NormalizedSite` field |
|---|---|
| `device` | `devices` |
| `user` | `clients` |
| `wlanconf` | `wlans` |
| `networkconf` | `networks` |
| `portforward` | `portForwards` |
| `firewallrule` | `firewallPolicies` |
| `firewallgroup` | `firewallZones` |
| `vpnserver` / `openvpn_server` / `ipsec_server` | `vpnConfigs` |
| `trafficrule` | `trafficRoutes` |

### The critical unlock: `settings` field

In API mode, `settings` is always `{}`. In backup mode it is populated from the `setting` collection, enabling every currently-`unknown` finding:

```typescript
settings: {
  auto_update:      findSetting(colls, 'auto_update'),
  backup:           findSetting(colls, 'backup'),
  mgmt:             findSetting(colls, 'mgmt'),
  rogueap:          findSetting(colls, 'rogueap'),
  dpi:              findSetting(colls, 'dpi'),
  dns_filtering:    findSetting(colls, 'connectivity'),
  threat_management: findSetting(colls, 'threat_management'),
}
```

`findSetting(colls, key)` finds the document in the `setting` collection where `doc.key === key`.

### Site identity

`siteId` is derived from `findSetting(colls, 'super_identity')?.name ?? 'default'`. A `.unf` is always single-site, so `normalizeBackup` returns a 1-element array.

### CLI parallel function

`parseBackupNodejs(filePath: string): Promise<Record<string, unknown[]>>` uses:
- `node:crypto` → `createDecipheriv('aes-128-cbc', key, iv)` for decryption
- `bson` npm package → `BSON.deserialize()` for BSON parsing  
- `fflate` (already a transitive dep) or `node:zlib` for gzip

---

## Section 3: Backup Tab UI

**New route:** `src/routes/backup/+page.svelte`

**Tab bar** (`src/routes/+layout.svelte`): add `{ label: 'Backup', href: '/backup' }` between Analyze and Report.

### Flow

1. "Browse…" button → `@tauri-apps/plugin-dialog` `open({ filters: [{ name: 'UniFi Backup', extensions: ['unf'] }] })`
2. Path shown inline; "×" to clear
3. Profile dropdown (same `ALL_PROFILES` options as wizard)
4. "Analyze Backup →" button:
   - Calls `invoke('parse_backup', { path })`
   - Calls `normalizeBackup(collections, profile)` → `NormalizedSite[]`
   - Calls `analyze(sites, {}, profile)` → `Finding[]`
   - Calls `insertRun(db, 'backup:' + filename, profile, sites.length)`
   - Calls `insertFindings(db, runId, findings)`
   - `goto('/wizard?runId=...')`
5. Progress log shows each step (same pattern as Analyze tab)

### Run identification in History

`host` column stored as `'backup:' + basename(path)` (e.g. `backup:backup-2026-04-26.unf`). History chart labels backup runs distinctly from live API runs with a different marker style.

---

## Section 4: CLI `--backup` Flag

**Modified:** `src/cli.ts`

```bash
UNIFI_PROFILE=home_office node dist/cli.js --backup ./backup.unf
```

When `process.argv.includes('--backup')`:
1. Skip `collectAll()` and `UniFiClient.fromEnv()` 
2. Read backup path from `process.argv[process.argv.indexOf('--backup') + 1]`
3. Call `parseBackupNodejs(path)` → raw collections
4. Call `normalizeBackup(collections, profile)` → `NormalizedSite[]`
5. Call `analyze(sites, {}, profile, onError)` → findings
6. Write `audit_output/raw_sanitized.json`, `findings.json`, `report.md` as normal

---

## Files Changed

| File | Change |
|------|--------|
| `src-tauri/src/lib.rs` | Add `parse_backup` Tauri command |
| `src-tauri/Cargo.toml` | Add `aes`, `cbc`, `flate2`, `zip`, `bson` crates |
| `src/audit/normalizeBackup.ts` | **New** — `normalizeBackup()`, `parseBackupNodejs()`, `findSetting()` |
| `src/audit/__tests__/normalizeBackup.test.ts` | **New** — unit tests for mapping and settings extraction |
| `src/routes/backup/+page.svelte` | **New** — Backup tab UI with file picker + progress log |
| `src/routes/+layout.svelte` | Add Backup tab |
| `src/cli.ts` | Add `--backup` flag |

**Unchanged:** All existing finding modules, `analyze()`, `normalize.ts`, wizard, report, history, SQLite schema.

---

## What This Unlocks

Findings that currently show `status: 'unknown'` that will fire with real data:

| Finding ID | Currently | After backup mode |
|---|---|---|
| `RF-ROGUE-001` | unknown (API can't see) | gap or ok |
| `FW-CONTENT-001` | unknown | gap or recommendation |
| `FW-AUTO-001` | unknown | gap or ok |
| `LOG-FWD-001` | unknown | gap or recommendation |
| `BAK-001` / `BAK-002` | unknown | gap or ok |
| `FW-GEO-IN` / `FW-GEO-OUT` | recommendation (heuristic) | confirmed from firewallrule |
| `VPN-*` | only from portForwards | full VPN config visible |
| `WIFI-*-PSK` | only for WLANs returned by API | all WLANs visible |

---

## Out of Scope

- `.unifi` console-level backup format (PostgreSQL, multi-site)
- Automatic backup detection/watching
- Apply mode (read-only)
- Decrypting community keys for newer `.unifi` format
