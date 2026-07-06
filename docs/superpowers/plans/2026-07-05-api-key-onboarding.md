# API-Key Onboarding Flow — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the bare connect form with a guided onboarding stepper that helps the user mint a UniFi API key, validates it with live feedback, and optionally stores it in the OS keychain.

**Architecture:** A Rust `keychain.rs` module exposes `keychain_set/get/delete/scan` Tauri commands (keyring crate for get/set/delete; platform-native enumeration for scan) and the app registers `tauri-plugin-opener` for deep-links. The frontend gets focused, unit-tested pure modules (`keyPortalUrl`, `keyInstructions`, `keyIndex`, `validateConnection`), Tauri-bridge glue (`keychain.ts`, `connectTier` store, an `app_kv` DB table), and a `ConnectWizard` stepper composed of `SavedKeys`/`ModeStep`/`KeyInstructions`/`ValidateStep`. The shared TS audit core and the Node CLI are untouched.

**Tech Stack:** Rust (Tauri v2, `keyring` v3, `tauri-plugin-opener`, platform crates `windows`/`security-framework`/`secret-service`), TypeScript, SvelteKit (Svelte 5 runes), Vitest, `@tauri-apps/plugin-sql`, `@tauri-apps/plugin-opener`.

## Global Constraints

- **Desktop only.** No changes to the Node CLI credential path (env-var/config). Shared audit core (`client.ts`, `apiVersion.ts`, `discover.ts`, `endpoints.ts`, `collect.ts`) is reused, not forked.
- **No credential via CLI arg, URL param, or chat.** Masked paste field only.
- **Key never logged, never written to SQLite/config.** Session memory or opt-in OS keychain only. The non-secret *index* stores identities (`cloud`, `local:<host>`), never secrets.
- **Do not hardcode API URLs.** Reuse `GLOBAL_ENDPOINTS`, `endpoints.ts`, and `UniFiClient` base-URL logic. The one cloud hosts URL is exported once and reused.
- **Keychain service name:** `unifi-security-advisor`. **Account (identity):** `cloud` for Site Manager; `local:<host>` for Network Integration.
- **`keychain_scan` returns identifiers only** — never secret values — and returns an empty list (never errors) on unsupported/headless platforms.
- **Keychain consent is opt-in:** the "Remember this key" checkbox defaults **unchecked**.
- **Tier control default:** `guided`. Reuse the existing `Tier = 'guided' | 'standard' | 'pro'` from `src/db/schema.ts`.
- **Test runner:** Vitest excludes `src-tauri/**` and Svelte components. Pure TS modules are unit-tested with Vitest; Rust is tested with `cargo test`; Svelte/bridge glue is verified with `npm run typecheck` (`svelte-kit sync && tsc --noEmit`) and `npm run build`.
- **Commit style:** no Claude attribution / Co-Authored-By trailers.

---

### Task 1: Rust keychain commands + opener plugin

**Files:**
- Create: `src-tauri/src/keychain.rs`
- Modify: `src-tauri/Cargo.toml` (add deps), `src-tauri/src/lib.rs` (module + command registration + opener plugin), `src-tauri/capabilities/default.json` (opener permission)
- Test: `#[cfg(test)]` module inside `src-tauri/src/keychain.rs`

**Interfaces:**
- Produces (Tauri commands, callable from JS via `invoke`):
  - `keychain_set(account: String, secret: String) -> Result<(), String>`
  - `keychain_get(account: String) -> Result<Option<String>, String>`
  - `keychain_delete(account: String) -> Result<(), String>`
  - `keychain_scan() -> Result<Vec<String>, String>`
- Service constant: `const SERVICE: &str = "unifi-security-advisor";`

- [ ] **Step 1: Add dependencies to `src-tauri/Cargo.toml`**

Add to `[dependencies]` (below the existing `bson = "2"` line):

```toml
keyring = { version = "3", features = ["apple-native", "windows-native", "sync-secret-service", "crypto-rust"] }
tauri-plugin-opener = "2"

[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = ["Win32_Foundation", "Win32_Security_Credentials"] }

[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "2"

[target.'cfg(target_os = "linux")'.dependencies]
secret-service = { version = "4", features = ["rt-tokio-crypto-rust"] }
```

Note: if a listed version fails to resolve, bump to the newest compatible release — the feature names above are what matter (keyring's native backends, the two Windows API namespaces). The Step-6 round-trip test will catch a wrong Windows target-name assumption.

- [ ] **Step 2: Write `src-tauri/src/keychain.rs` with the get/set/delete commands**

```rust
use keyring::Entry;
use tauri::command;

pub const SERVICE: &str = "unifi-security-advisor";

#[command]
pub fn keychain_set(account: String, secret: String) -> Result<(), String> {
    let entry = Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    entry.set_password(&secret).map_err(|e| e.to_string())
}

#[command]
pub fn keychain_get(account: String) -> Result<Option<String>, String> {
    let entry = Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[command]
pub fn keychain_delete(account: String) -> Result<(), String> {
    let entry = Entry::new(SERVICE, &account).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
```

- [ ] **Step 3: Add the platform-gated `keychain_scan` command to `src-tauri/src/keychain.rs`**

Append. Each platform lists accounts stored under `SERVICE`, returning account identifiers only. The unsupported-platform arm returns an empty list.

```rust
/// Enumerate account identifiers stored under our service. Identifiers only —
/// never secret values. Returns an empty list on platforms without an
/// enumeration path rather than erroring.
#[command]
pub fn keychain_scan() -> Result<Vec<String>, String> {
    scan_impl()
}

#[cfg(windows)]
fn scan_impl() -> Result<Vec<String>, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_ALL_CREDENTIALS,
    };
    // keyring's windows-native backend stores the target name as
    // "{service}.{account}". Filter to our service prefix, then strip it to
    // recover the account. The Step-6 round-trip test validates this mapping.
    let prefix = format!("{}.", SERVICE);
    let mut wide: Vec<u16> = format!("{}*", prefix).encode_utf16().chain(std::iter::once(0)).collect();
    let mut count: u32 = 0;
    let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();
    let mut out: Vec<String> = Vec::new();
    unsafe {
        match CredEnumerateW(PCWSTR(wide.as_mut_ptr()), 0, &mut count, &mut creds) {
            Ok(()) => {
                let slice = std::slice::from_raw_parts(creds, count as usize);
                for &cred in slice {
                    let target = (*cred).TargetName;
                    if target.is_null() { continue; }
                    let s = target.to_string().unwrap_or_default();
                    if let Some(account) = s.strip_prefix(&prefix) {
                        out.push(account.to_string());
                    }
                }
                CredFree(creds as *const _);
                Ok(out)
            }
            Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
fn scan_impl() -> Result<Vec<String>, String> {
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::generic_password());
    opts.limit(Limit::All);
    opts.load_attributes(true);
    let results = match opts.search() {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for item in results {
        if let SearchResult::Dict(map) = item {
            let svc = map.get("svce").map(|v| v.to_string()).unwrap_or_default();
            if svc == SERVICE {
                if let Some(acct) = map.get("acct") {
                    out.push(acct.to_string());
                }
            }
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn scan_impl() -> Result<Vec<String>, String> {
    use secret_service::blocking::SecretService;
    use secret_service::EncryptionType;
    use std::collections::HashMap;
    let ss = match SecretService::connect(EncryptionType::Dh) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()),
    };
    let mut attrs = HashMap::new();
    attrs.insert("service", SERVICE);
    let items = match ss.search_items(attrs) {
        Ok(i) => i,
        Err(_) => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for item in items.unlocked.into_iter().chain(items.locked.into_iter()) {
        if let Ok(a) = item.get_attributes() {
            if let Some(account) = a.get("account") {
                out.push(account.clone());
            }
        }
    }
    Ok(out)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn scan_impl() -> Result<Vec<String>, String> {
    Ok(Vec::new())
}
```

Note: keyring's Linux/macOS backends set searchable attributes (`service`/`account` on secret-service, `svce`/`acct` on macOS). If the Step-6 round-trip test does not find a just-set account on macOS/Linux, adjust the attribute keys to match the installed keyring version's schema (the test is the oracle).

- [ ] **Step 4: Register the module, commands, and opener plugin in `src-tauri/src/lib.rs`**

At the top of the file (after the existing `use` lines), add:

```rust
mod keychain;
```

Change the plugin/handler chain (currently around lib.rs:451-455) to add the opener plugin and the four commands:

```rust
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            unifi_fetch,
            parse_backup,
            keychain::keychain_set,
            keychain::keychain_get,
            keychain::keychain_delete,
            keychain::keychain_scan
        ])
```

- [ ] **Step 5: Add the opener permission to `src-tauri/capabilities/default.json`**

Add `"opener:default"` to the `permissions` array (after `"process:allow-restart"`):

```json
    "process:allow-restart",
    "opener:default"
```

- [ ] **Step 6: Write the Rust tests in `src-tauri/src/keychain.rs`**

Append. Uses keyring's built-in mock store for the get/set/delete round-trip (hermetic, no real vault), and a real-store round-trip for scan on the host platform (unique account, cleaned up).

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();
    fn use_mock() {
        INIT.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
    }

    #[test]
    fn set_get_delete_round_trip() {
        use_mock();
        let acct = "local:__unit_test__";
        keychain_set(acct.into(), "secret-123".into()).unwrap();
        assert_eq!(keychain_get(acct.into()).unwrap(), Some("secret-123".to_string()));
        keychain_delete(acct.into()).unwrap();
        // mock store returns NoEntry after delete -> Ok(None)
        assert_eq!(keychain_get(acct.into()).unwrap(), None);
    }

    #[test]
    fn get_missing_returns_none() {
        use_mock();
        assert_eq!(keychain_get("local:__absent__".into()).unwrap(), None);
    }

    // scan uses the REAL platform store (not the mock), so run it against a
    // uniquely-named account and clean up. On the unsupported-platform arm this
    // still passes (empty list, account simply absent).
    #[test]
    fn scan_lists_a_real_stored_account() {
        let acct = "local:__scan_probe__";
        // Use a fresh Entry that bypasses the mock builder set above by other
        // tests is not guaranteed; guard by only asserting membership where the
        // platform supports enumeration.
        let entry = Entry::new(SERVICE, acct).unwrap();
        if entry.set_password("probe").is_err() {
            return; // no usable store in this environment; nothing to assert
        }
        let listed = keychain_scan().unwrap();
        let _ = entry.delete_credential();
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        assert!(listed.contains(&acct.to_string()), "scan did not surface {acct}: {listed:?}");
    }
}
```

- [ ] **Step 7: Run the Rust tests**

Run: `cd src-tauri && cargo test keychain`
Expected: PASS (3 tests). If `scan_lists_a_real_stored_account` fails on your platform, fix the account-name parsing / attribute keys in `scan_impl` until it passes — the test is the spec.

- [ ] **Step 8: Commit**

```bash
git add src-tauri/src/keychain.rs src-tauri/src/lib.rs src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/capabilities/default.json
git commit -m "feat(desktop): OS keychain commands + opener plugin"
```

---

### Task 2: `keyPortalUrl` deep-link builder

**Files:**
- Create: `src/lib/onboarding/keyPortalUrl.ts`
- Test: `src/lib/onboarding/__tests__/keyPortalUrl.test.ts`

**Interfaces:**
- Produces: `keyPortalUrl(mode: 'local' | 'cloud', host?: string): string | null` — cloud → `https://unifi.ui.com`; local → `https://<host>/network/`; local without a host → `null`.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { keyPortalUrl } from '../keyPortalUrl.js';

describe('keyPortalUrl', () => {
  it('returns the Site Manager portal for cloud', () => {
    expect(keyPortalUrl('cloud')).toBe('https://unifi.ui.com');
  });
  it('builds the local Network app URL from a bare host', () => {
    expect(keyPortalUrl('local', '192.168.1.1')).toBe('https://192.168.1.1/network/');
  });
  it('respects a host that already has a scheme and trims trailing slashes', () => {
    expect(keyPortalUrl('local', 'https://udm.local/')).toBe('https://udm.local/network/');
  });
  it('returns null for local with no host yet', () => {
    expect(keyPortalUrl('local')).toBeNull();
    expect(keyPortalUrl('local', '   ')).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/lib/onboarding/__tests__/keyPortalUrl.test.ts`
Expected: FAIL (cannot find module `../keyPortalUrl.js`).

- [ ] **Step 3: Write the implementation**

```ts
// Builds the "mint a key" deep-link. The cloud PORTAL is unifi.ui.com (distinct
// from the api.ui.com API host used for validation). Local opens the Network
// app root — the exact Integrations sub-path varies by Network 8/9/10.
export function keyPortalUrl(mode: 'local' | 'cloud', host?: string): string | null {
  if (mode === 'cloud') return 'https://unifi.ui.com';
  const h = (host ?? '').trim();
  if (!h) return null;
  const base = h.startsWith('http') ? h : `https://${h}`;
  return `${base.replace(/\/+$/, '')}/network/`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/lib/onboarding/__tests__/keyPortalUrl.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/lib/onboarding/keyPortalUrl.ts src/lib/onboarding/__tests__/keyPortalUrl.test.ts
git commit -m "feat(onboarding): keyPortalUrl deep-link builder"
```

---

### Task 3: `keyInstructions` tiered copy

**Files:**
- Create: `src/lib/onboarding/keyInstructions.ts`
- Test: `src/lib/onboarding/__tests__/keyInstructions.test.ts`

**Interfaces:**
- Produces:
  - `type ConnectMode = 'local' | 'cloud'`
  - `type ConnectTier = 'guided' | 'standard' | 'pro'`
  - `interface InstructionBlock { steps: string[]; note: string }`
  - `getInstructions(mode: ConnectMode, tier: ConnectTier): InstructionBlock`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { getInstructions, type ConnectMode, type ConnectTier } from '../keyInstructions.js';

const MODES: ConnectMode[] = ['local', 'cloud'];
const TIERS: ConnectTier[] = ['guided', 'standard', 'pro'];

describe('getInstructions', () => {
  it('has a non-empty block for every mode × tier', () => {
    for (const mode of MODES) {
      for (const tier of TIERS) {
        const block = getInstructions(mode, tier);
        expect(block.steps.length, `${mode}/${tier} steps`).toBeGreaterThan(0);
        expect(block.steps.every(s => s.trim().length > 0)).toBe(true);
        expect(block.note.trim().length, `${mode}/${tier} note`).toBeGreaterThan(0);
      }
    }
  });
  it('local instructions mention Integrations; cloud mention the API section', () => {
    expect(getInstructions('local', 'pro').steps.join(' ')).toMatch(/Integrations/i);
    expect(getInstructions('cloud', 'guided').steps.join(' ')).toMatch(/unifi\.ui\.com/i);
  });
  it('every note carries the shortest-expiration / revoke guidance', () => {
    for (const mode of MODES) for (const tier of TIERS) {
      expect(getInstructions(mode, tier).note).toMatch(/shortest|revoke/i);
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/lib/onboarding/__tests__/keyInstructions.test.ts`
Expected: FAIL (cannot find module).

- [ ] **Step 3: Write the implementation**

```ts
export type ConnectMode = 'local' | 'cloud';
export type ConnectTier = 'guided' | 'standard' | 'pro';
export interface InstructionBlock { steps: string[]; note: string }

const REVOKE_NOTE = 'Pick the shortest expiration offered, and revoke the key after this audit.';

const LOCAL: Record<ConnectTier, InstructionBlock> = {
  guided: {
    steps: [
      'Open your UniFi console in a browser and sign in as an admin.',
      'Go to Settings (the gear), then Control Plane, then Integrations.',
      'Give the key a name, choose the shortest expiration, and create it.',
      'Copy the key it shows you — it is only shown once — and paste it below.',
    ],
    note: REVOKE_NOTE,
  },
  standard: {
    steps: [
      'In the UniFi Network application: Settings → Control Plane → Integrations.',
      'Create API Key → name it → set the shortest expiration → Create.',
      'Copy the key (shown once) and paste it below.',
    ],
    note: REVOKE_NOTE,
  },
  pro: {
    steps: [
      'Settings → Control Plane → Integrations → Create API Key.',
      'This mints a Network Integration (local) X-API-KEY, sent as the X-API-KEY header to /proxy/network/integration/v1.',
      'Menu path varies by Network 8/9/10; the key is displayed once — copy it immediately.',
    ],
    note: REVOKE_NOTE,
  },
};

const CLOUD: Record<ConnectTier, InstructionBlock> = {
  guided: {
    steps: [
      'Open unifi.ui.com in a browser and sign in with your Ubiquiti account.',
      'In the left menu, click API.',
      'Click Create API Key, then copy the key it shows — it appears only once.',
      'Paste the key below.',
    ],
    note: REVOKE_NOTE,
  },
  standard: {
    steps: [
      'Sign in at unifi.ui.com → left nav → API.',
      'Create API Key → copy it (shown once).',
      'Paste the key below.',
    ],
    note: REVOKE_NOTE,
  },
  pro: {
    steps: [
      'unifi.ui.com → API → Create API Key.',
      'This is a Site Manager X-API-KEY (cloud), used against https://api.ui.com; one key can span multiple consoles/sites under the account.',
      'Displayed once — copy immediately.',
    ],
    note: REVOKE_NOTE,
  },
};

const TABLE: Record<ConnectMode, Record<ConnectTier, InstructionBlock>> = { local: LOCAL, cloud: CLOUD };

export function getInstructions(mode: ConnectMode, tier: ConnectTier): InstructionBlock {
  return TABLE[mode][tier];
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/lib/onboarding/__tests__/keyInstructions.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/lib/onboarding/keyInstructions.ts src/lib/onboarding/__tests__/keyInstructions.test.ts
git commit -m "feat(onboarding): tiered key-minting instructions"
```

---

### Task 4: `keyIndex` pure index transforms

**Files:**
- Create: `src/lib/onboarding/keyIndex.ts`
- Test: `src/lib/onboarding/__tests__/keyIndex.test.ts`

**Interfaces:**
- Produces:
  - `interface KeyIdentity { identity: string; mode: 'local' | 'cloud'; host?: string; label: string }`
  - `identityFor(mode: 'local' | 'cloud', host?: string): string` — `'cloud'` or `` `local:${host}` ``
  - `labelFor(mode, host?, consoleName?): string`
  - `parseIndex(json: string | null): KeyIdentity[]`
  - `serializeIndex(list: KeyIdentity[]): string`
  - `addIdentity(list: KeyIdentity[], entry: KeyIdentity): KeyIdentity[]` (dedup by `identity`)
  - `removeIdentity(list: KeyIdentity[], identity: string): KeyIdentity[]`

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import {
  identityFor, labelFor, parseIndex, serializeIndex, addIdentity, removeIdentity,
  type KeyIdentity,
} from '../keyIndex.js';

const cloud: KeyIdentity = { identity: 'cloud', mode: 'cloud', label: 'Site Manager (cloud)' };
const local: KeyIdentity = { identity: 'local:192.168.1.1', mode: 'local', host: '192.168.1.1', label: 'UCG-Fiber (local, 192.168.1.1)' };

describe('identityFor', () => {
  it('maps modes to account identifiers', () => {
    expect(identityFor('cloud')).toBe('cloud');
    expect(identityFor('local', '192.168.1.1')).toBe('local:192.168.1.1');
  });
});

describe('labelFor', () => {
  it('prefers the console name when known', () => {
    expect(labelFor('local', '192.168.1.1', 'UCG-Fiber')).toMatch(/UCG-Fiber/);
    expect(labelFor('local', '192.168.1.1', 'UCG-Fiber')).toMatch(/192\.168\.1\.1/);
  });
  it('falls back gracefully with no console name', () => {
    expect(labelFor('cloud').length).toBeGreaterThan(0);
    expect(labelFor('local', '192.168.1.1')).toMatch(/192\.168\.1\.1/);
  });
});

describe('parseIndex / serializeIndex', () => {
  it('round-trips a list', () => {
    const json = serializeIndex([cloud, local]);
    expect(parseIndex(json)).toEqual([cloud, local]);
  });
  it('returns [] for null / invalid / non-array JSON', () => {
    expect(parseIndex(null)).toEqual([]);
    expect(parseIndex('not json')).toEqual([]);
    expect(parseIndex('{"a":1}')).toEqual([]);
  });
  it('drops malformed entries', () => {
    expect(parseIndex('[{"identity":"cloud"}, 42, {"nope":true}]'))
      .toEqual([]); // entries missing required fields are dropped
  });
});

describe('addIdentity / removeIdentity', () => {
  it('adds and dedups by identity (last write wins)', () => {
    const once = addIdentity([], cloud);
    expect(once).toEqual([cloud]);
    const relabeled = { ...cloud, label: 'changed' };
    expect(addIdentity(once, relabeled)).toEqual([relabeled]);
  });
  it('removes by identity', () => {
    expect(removeIdentity([cloud, local], 'cloud')).toEqual([local]);
    expect(removeIdentity([cloud], 'absent')).toEqual([cloud]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/lib/onboarding/__tests__/keyIndex.test.ts`
Expected: FAIL (cannot find module).

- [ ] **Step 3: Write the implementation**

```ts
export interface KeyIdentity {
  identity: string;            // 'cloud' | `local:${host}`
  mode: 'local' | 'cloud';
  host?: string;
  label: string;               // human-readable, non-secret
}

export function identityFor(mode: 'local' | 'cloud', host?: string): string {
  return mode === 'cloud' ? 'cloud' : `local:${(host ?? '').trim()}`;
}

export function labelFor(mode: 'local' | 'cloud', host?: string, consoleName?: string): string {
  if (mode === 'cloud') return consoleName ? `${consoleName} (cloud)` : 'Site Manager (cloud)';
  const h = (host ?? '').trim();
  return consoleName ? `${consoleName} (local, ${h})` : `Local console (${h})`;
}

function isKeyIdentity(v: unknown): v is KeyIdentity {
  if (v === null || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  return typeof o.identity === 'string'
    && (o.mode === 'local' || o.mode === 'cloud')
    && typeof o.label === 'string'
    && (o.host === undefined || typeof o.host === 'string');
}

export function parseIndex(json: string | null): KeyIdentity[] {
  if (!json) return [];
  try {
    const parsed = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isKeyIdentity);
  } catch {
    return [];
  }
}

export function serializeIndex(list: KeyIdentity[]): string {
  return JSON.stringify(list);
}

export function addIdentity(list: KeyIdentity[], entry: KeyIdentity): KeyIdentity[] {
  return [...list.filter(e => e.identity !== entry.identity), entry];
}

export function removeIdentity(list: KeyIdentity[], identity: string): KeyIdentity[] {
  return list.filter(e => e.identity !== identity);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/lib/onboarding/__tests__/keyIndex.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/onboarding/keyIndex.ts src/lib/onboarding/__tests__/keyIndex.test.ts
git commit -m "feat(onboarding): non-secret key index transforms"
```

---

### Task 5: `validateConnection` probe

**Files:**
- Create: `src/lib/onboarding/validateConnection.ts`
- Modify: `src/audit/endpoints.ts` (export the cloud hosts URL once), `src/audit/collect.ts` (reuse that export instead of the inline literal)
- Test: `src/lib/onboarding/__tests__/validateConnection.test.ts`

**Interfaces:**
- Consumes: `parseApplicationVersion` (`src/audit/apiVersion.ts`), `extractSites` (`src/audit/collect.ts`), `GLOBAL_ENDPOINTS` + new `CLOUD_HOSTS_URL` (`src/audit/endpoints.ts`).
- Produces:
  - `type ValidationErrorKind = 'auth' | 'unreachable' | 'mode-mismatch' | 'unknown'`
  - `interface ValidationError { kind: ValidationErrorKind; message: string }`
  - `interface ValidationResult { ok: boolean; consoleName?: string; model?: string; networkVersion?: string; sites?: { id: string; name: string }[]; error?: ValidationError }`
  - `interface Fetcher { config: { useCloud: boolean; host: string }; get(path: string): Promise<{ status: number; data: unknown }> }`
  - `validateConnection(client: Fetcher): Promise<ValidationResult>`

- [ ] **Step 1: Export the cloud hosts URL from `src/audit/endpoints.ts`**

Add after `INTEGRATION_SPEC_PATH` (endpoints.ts:45):

```ts
/** Site Manager (cloud) hosts endpoint — the API host, not the unifi.ui.com portal. */
export const CLOUD_HOSTS_URL = 'https://api.ui.com/v1/hosts';
```

Then in `src/audit/collect.ts`, import it and replace the inline `'https://api.ui.com/v1/hosts'` in `CLOUD_ENDPOINTS` (collect.ts:11) with `CLOUD_HOSTS_URL`:

```ts
import { CLOUD_HOSTS_URL /* , ...existing */ } from './endpoints.js';
// ...
const CLOUD_ENDPOINTS = [
  ['hosts',         CLOUD_HOSTS_URL],
  ['cloud_sites',   'https://api.ui.com/v1/sites'],
  ['cloud_devices', 'https://api.ui.com/v1/devices'],
] as const;
```

- [ ] **Step 2: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { validateConnection, type Fetcher } from '../validateConnection.js';

function fakeClient(useCloud: boolean, host: string, responder: (path: string) => { status: number; data: unknown } | Promise<never>): Fetcher {
  return { config: { useCloud, host }, get: async (path) => responder(path) };
}

describe('validateConnection (local)', () => {
  it('returns ok with version + sites on 200', async () => {
    const client = fakeClient(false, '192.168.1.1', (path) => {
      if (path.endsWith('/info')) return { status: 200, data: { applicationVersion: '10.3.58', name: 'UCG-Fiber' } };
      if (path.endsWith('/sites')) return { status: 200, data: [{ id: 's1', name: 'Default' }] };
      return { status: 404, data: {} };
    });
    const r = await validateConnection(client);
    expect(r.ok).toBe(true);
    expect(r.networkVersion).toBe('10.3.58');
    expect(r.sites).toEqual([{ id: 's1', name: 'Default' }]);
  });

  it('maps 401 to an auth error', async () => {
    const client = fakeClient(false, '192.168.1.1', () => ({ status: 401, data: {} }));
    const r = await validateConnection(client);
    expect(r.ok).toBe(false);
    expect(r.error?.kind).toBe('auth');
  });

  it('maps a thrown fetch to unreachable', async () => {
    const client = fakeClient(false, '10.0.0.9', () => { throw new Error('ECONNREFUSED'); });
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('unreachable');
  });

  it('flags a cloud host typed into local mode as mode-mismatch', async () => {
    const client = fakeClient(false, 'unifi.ui.com', () => ({ status: 200, data: {} }));
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('mode-mismatch');
  });

  it('maps other non-2xx to unknown', async () => {
    const client = fakeClient(false, '192.168.1.1', () => ({ status: 500, data: {} }));
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('unknown');
  });
});

describe('validateConnection (cloud)', () => {
  it('returns ok with hosts as sites', async () => {
    const client = fakeClient(true, '', () => ({ status: 200, data: [{ id: 'c1', name: 'Home' }] }));
    const r = await validateConnection(client);
    expect(r.ok).toBe(true);
    expect(r.sites).toEqual([{ id: 'c1', name: 'Home' }]);
  });
  it('maps 403 to auth', async () => {
    const client = fakeClient(true, '', () => ({ status: 403, data: {} }));
    const r = await validateConnection(client);
    expect(r.error?.kind).toBe('auth');
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run src/lib/onboarding/__tests__/validateConnection.test.ts`
Expected: FAIL (cannot find module).

- [ ] **Step 4: Write the implementation**

```ts
import { parseApplicationVersion } from '../../audit/apiVersion.js';
import { extractSites } from '../../audit/collect.js';
import { GLOBAL_ENDPOINTS, CLOUD_HOSTS_URL } from '../../audit/endpoints.js';

export type ValidationErrorKind = 'auth' | 'unreachable' | 'mode-mismatch' | 'unknown';
export interface ValidationError { kind: ValidationErrorKind; message: string }
export interface ValidationResult {
  ok: boolean;
  consoleName?: string;
  model?: string;
  networkVersion?: string;
  sites?: { id: string; name: string }[];
  error?: ValidationError;
}
export interface Fetcher {
  config: { useCloud: boolean; host: string };
  get(path: string): Promise<{ status: number; data: unknown }>;
}

const AUTH_MSG = 'Key rejected — check you pasted the whole key. It may be expired or the wrong type for this mode.';
const UNKNOWN_MSG = (status: number) => `Unexpected response from the console (${status}). Try again, or check the console is a supported UniFi Network version.`;
const unreachableMsg = (host: string) => `Couldn't reach ${host || 'the controller'} — is the console on this network and the IP correct?`;

function err(kind: ValidationErrorKind, message: string): ValidationResult {
  return { ok: false, error: { kind, message } };
}

function sitesFrom(data: unknown): { id: string; name: string }[] {
  return extractSites(data).map((s) => ({
    id: String(s['id'] ?? s['_id'] ?? s['hostId'] ?? s['name'] ?? ''),
    name: String(s['name'] ?? s['hostname'] ?? s['id'] ?? 'site'),
  }));
}

function pathFor(key: string): string {
  const found = GLOBAL_ENDPOINTS.find(([k]) => k === key);
  if (!found) throw new Error(`missing endpoint: ${key}`);
  return found[1];
}

export async function validateConnection(client: Fetcher): Promise<ValidationResult> {
  const { useCloud, host } = client.config;

  if (!useCloud && /ui\.com/i.test(host)) {
    return err('mode-mismatch', 'That looks like a cloud address — switch to Cloud (Site Manager) mode?');
  }

  try {
    if (useCloud) {
      const res = await client.get(CLOUD_HOSTS_URL);
      if (res.status === 401 || res.status === 403) return err('auth', AUTH_MSG);
      if (res.status === 0) return err('unreachable', unreachableMsg('the Site Manager API'));
      if (res.status !== 200) return err('unknown', UNKNOWN_MSG(res.status));
      const sites = sitesFrom(res.data);
      return { ok: true, sites };
    }

    const info = await client.get(pathFor('info'));
    if (info.status === 401 || info.status === 403) return err('auth', AUTH_MSG);
    if (info.status === 0) return err('unreachable', unreachableMsg(host));
    if (info.status !== 200) return err('unknown', UNKNOWN_MSG(info.status));

    const infoObj = (info.data ?? {}) as Record<string, unknown>;
    const networkVersion = parseApplicationVersion(info.data) ?? undefined;
    const consoleName = typeof infoObj['name'] === 'string' ? (infoObj['name'] as string)
      : typeof infoObj['hostname'] === 'string' ? (infoObj['hostname'] as string) : undefined;
    const model = typeof infoObj['model'] === 'string' ? (infoObj['model'] as string)
      : typeof infoObj['hardwareRevision'] === 'string' ? (infoObj['hardwareRevision'] as string) : undefined;

    const sitesRes = await client.get(pathFor('sites'));
    const sites = sitesRes.status === 200 ? sitesFrom(sitesRes.data) : [];

    return { ok: true, consoleName, model, networkVersion, sites };
  } catch {
    return err('unreachable', unreachableMsg(useCloud ? 'the Site Manager API' : host));
  }
}
```

- [ ] **Step 5: Run all tests (new module + the touched audit tests)**

Run: `npx vitest run src/lib/onboarding/__tests__/validateConnection.test.ts src/audit/__tests__/collect.test.ts`
Expected: PASS (new module green; `collect.test.ts` still green after the `CLOUD_HOSTS_URL` refactor).

- [ ] **Step 6: Commit**

```bash
git add src/lib/onboarding/validateConnection.ts src/lib/onboarding/__tests__/validateConnection.test.ts src/audit/endpoints.ts src/audit/collect.ts
git commit -m "feat(onboarding): lightweight connection validation probe"
```

---

### Task 6: keychain bridge + `app_kv` persistence

**Files:**
- Create: `src/lib/onboarding/keychain.ts`
- Modify: `src/db/schema.ts` (add `app_kv` table), `src/db/queries.ts` (add `getKv`/`setKv`)
- Test: `src/db/__tests__/schema.test.ts` (assert the new table is registered) — or extend an existing schema test if present

**Interfaces:**
- Consumes: `invoke` from `@tauri-apps/api/core`; `openDb` (`src/db/queries.ts`); pure transforms from `keyIndex.ts`.
- Produces (all async):
  - `keychain.save(account, secret)`, `keychain.load(account): Promise<string | null>`, `keychain.delete(account)`, `keychain.scan(): Promise<string[]>`
  - `loadIndex(): Promise<KeyIdentity[]>`, `saveIndex(list): Promise<void>`
  - `rememberKey(entry: KeyIdentity, secret: string): Promise<void>`
  - `forgetKey(identity: string): Promise<void>`
  - `getKv(key): Promise<string | null>`, `setKv(key, value): Promise<void>` (from queries.ts)

- [ ] **Step 1: Add the `app_kv` table to `src/db/schema.ts`**

Append a new entry to the `CREATE_TABLES` array (after the `sites` table):

```ts
  `CREATE TABLE IF NOT EXISTS app_kv (
    key   TEXT PRIMARY KEY,
    value TEXT
  )`,
```

- [ ] **Step 2: Write the failing schema test**

Create `src/db/__tests__/schema.test.ts` (or add to an existing one):

```ts
import { describe, it, expect } from 'vitest';
import { CREATE_TABLES } from '../schema.js';

describe('schema', () => {
  it('registers the app_kv key/value table', () => {
    expect(CREATE_TABLES.some(sql => /CREATE TABLE IF NOT EXISTS app_kv/.test(sql))).toBe(true);
  });
});
```

Run: `npx vitest run src/db/__tests__/schema.test.ts`
Expected: PASS (the table was added in Step 1; this test guards it).

- [ ] **Step 3: Add `getKv`/`setKv` to `src/db/queries.ts`**

Append:

```ts
export async function getKv(key: string): Promise<string | null> {
  const db = await openDb();
  const rows = await db.select<{ value: string }[]>('SELECT value FROM app_kv WHERE key = ?', [key]);
  return rows.length ? rows[0]!.value : null;
}

export async function setKv(key: string, value: string): Promise<void> {
  const db = await openDb();
  await db.execute(
    'INSERT INTO app_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    [key, value],
  );
}
```

- [ ] **Step 4: Write `src/lib/onboarding/keychain.ts`**

```ts
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
```

- [ ] **Step 5: Typecheck (bridge glue is Tauri-only; verified by the compiler, not Vitest)**

Run: `npm run typecheck`
Expected: PASS (no type errors).

- [ ] **Step 6: Run the schema test + commit**

Run: `npx vitest run src/db/__tests__/schema.test.ts`
Expected: PASS.

```bash
git add src/lib/onboarding/keychain.ts src/db/schema.ts src/db/queries.ts src/db/__tests__/schema.test.ts
git commit -m "feat(onboarding): keychain bridge + app_kv index persistence"
```

---

### Task 7: ConnectWizard container + Mode & Get-Key steps + connectTier

**Files:**
- Create: `src/lib/stores/connectTier.ts`, `src/lib/onboarding/ModeStep.svelte`, `src/lib/onboarding/KeyInstructions.svelte`
- Modify: `src/routes/audit/+page.svelte` (becomes the stepper host)
- Verification: `npm run typecheck` + `npm run build` (Svelte components are not unit-tested per the Global Constraints)

**Interfaces:**
- Consumes: `keyPortalUrl` (Task 2), `getInstructions` + `ConnectTier`/`ConnectMode` (Task 3), `openUrl` from `@tauri-apps/plugin-opener`.
- Produces:
  - `connectTier` — a persisted Svelte `Writable<ConnectTier>` (localStorage-backed, default `'guided'`).
  - `ModeStep` props: `mode: 'local' | 'cloud'`, `host: string`, and callbacks `onchange`.
  - `KeyInstructions` props: `mode`, `host`.
  - Stepper state type: `type Step = 'check' | 'mode' | 'getkey' | 'validate'` (managed in `+page.svelte`).

- [ ] **Step 1: Add `@tauri-apps/plugin-opener` to the frontend deps**

Run: `npm install @tauri-apps/plugin-opener`
Expected: `package.json` gains the dependency.

- [ ] **Step 2: Write the persisted `connectTier` store**

`src/lib/stores/connectTier.ts`:

```ts
import { writable } from 'svelte/store';
import type { ConnectTier } from '../onboarding/keyInstructions.js';

const KEY = 'connectTier';
const initial: ConnectTier =
  (typeof localStorage !== 'undefined' && (localStorage.getItem(KEY) as ConnectTier)) || 'guided';

export const connectTier = writable<ConnectTier>(initial);

connectTier.subscribe((v) => {
  if (typeof localStorage !== 'undefined') localStorage.setItem(KEY, v);
});
```

- [ ] **Step 3: Write `ModeStep.svelte`**

`src/lib/onboarding/ModeStep.svelte`:

```svelte
<script lang="ts">
  let { mode = $bindable('local'), host = $bindable('') }: {
    mode: 'local' | 'cloud'; host: string;
  } = $props();
</script>

<div class="space-y-4">
  <p class="text-sm text-gray-600">How do you want to connect?</p>
  <div class="flex gap-2">
    <button type="button" class="px-4 py-2 rounded-lg border {mode === 'local' ? 'bg-blue-600 text-white' : ''}"
      onclick={() => (mode = 'local')}>Local (Network Integration)</button>
    <button type="button" class="px-4 py-2 rounded-lg border {mode === 'cloud' ? 'bg-blue-600 text-white' : ''}"
      onclick={() => (mode = 'cloud')}>Cloud (Site Manager)</button>
  </div>
  <p class="text-xs text-gray-500">
    Choose Cloud when the console is behind CGNAT, has a dynamic WAN IP, or you manage multiple sites.
  </p>
  {#if mode === 'local'}
    <label class="block">
      <span class="text-sm font-medium text-gray-700">Controller host</span>
      <input type="text" bind:value={host} placeholder="192.168.1.1"
        class="mt-1 block w-full border rounded-lg px-3 py-2" />
    </label>
  {/if}
</div>
```

- [ ] **Step 4: Write `KeyInstructions.svelte`**

`src/lib/onboarding/KeyInstructions.svelte`:

```svelte
<script lang="ts">
  import { openUrl } from '@tauri-apps/plugin-opener';
  import { getInstructions, type ConnectMode } from './keyInstructions.js';
  import { keyPortalUrl } from './keyPortalUrl.js';
  import { connectTier } from '../stores/connectTier.js';

  let { mode, host = '' }: { mode: ConnectMode; host?: string } = $props();

  const tiers = ['guided', 'standard', 'pro'] as const;
  let block = $derived(getInstructions(mode, $connectTier));
  let portal = $derived(keyPortalUrl(mode, host));

  async function open() {
    if (portal) await openUrl(portal);
  }
</script>

<div class="space-y-4">
  <div class="flex gap-1 text-sm">
    {#each tiers as t}
      <button type="button" class="px-3 py-1 rounded border {$connectTier === t ? 'bg-gray-800 text-white' : ''}"
        onclick={() => connectTier.set(t)}>{t[0].toUpperCase() + t.slice(1)}</button>
    {/each}
  </div>

  <ol class="list-decimal ml-5 space-y-1 text-sm text-gray-700">
    {#each block.steps as step}<li>{step}</li>{/each}
  </ol>
  <p class="text-xs text-amber-700">{block.note}</p>

  <button type="button" onclick={open} disabled={!portal}
    class="px-4 py-2 rounded-lg border font-medium disabled:opacity-40">
    Open the key page
  </button>
  {#if !portal}<p class="text-xs text-gray-400">Enter the controller host first.</p>{/if}
</div>
```

- [ ] **Step 5: Rewrite `src/routes/audit/+page.svelte` as the stepper host (mode → getkey; validate/check added in later tasks)**

Replace the file contents with a stepper that drives Steps 1–2 and hands off to a `ValidateStep` placeholder import added in Task 8. For this task, wire `check → mode → getkey → validate` with `check` auto-forwarding to `mode` (real Step 0 lands in Task 9):

```svelte
<script lang="ts">
  import ModeStep from '../../lib/onboarding/ModeStep.svelte';
  import KeyInstructions from '../../lib/onboarding/KeyInstructions.svelte';

  type Step = 'check' | 'mode' | 'getkey' | 'validate';
  let step = $state<Step>('mode'); // Task 9 sets initial 'check'
  let mode = $state<'local' | 'cloud'>('local');
  let host = $state('');

  function toGetKey() {
    if (mode === 'local' && !host.trim()) return;
    step = 'getkey';
  }
</script>

<main class="p-8 max-w-xl mx-auto">
  <a href="/" class="text-blue-600 text-sm mb-6 block">← Back</a>
  <h1 class="text-2xl font-bold mb-6">Connect to your UniFi console</h1>

  {#if step === 'mode'}
    <ModeStep bind:mode bind:host />
    <button class="mt-6 bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold disabled:opacity-50"
      onclick={toGetKey} disabled={mode === 'local' && !host.trim()}>Next</button>
  {:else if step === 'getkey'}
    <KeyInstructions {mode} {host} />
    <div class="mt-6 flex gap-3">
      <button class="px-4 py-2 rounded-lg border" onclick={() => (step = 'mode')}>Back</button>
      <button class="bg-blue-600 text-white px-6 py-2 rounded-lg font-semibold"
        onclick={() => (step = 'validate')}>I have my key →</button>
    </div>
  {:else if step === 'validate'}
    <p class="text-gray-500">Validation step — added in Task 8.</p>
    <button class="mt-4 px-4 py-2 rounded-lg border" onclick={() => (step = 'getkey')}>Back</button>
  {/if}
</main>
```

- [ ] **Step 6: Typecheck and build**

Run: `npm run typecheck && npm run build`
Expected: PASS (no type errors; the static build succeeds).

- [ ] **Step 7: Commit**

```bash
git add src/lib/stores/connectTier.ts src/lib/onboarding/ModeStep.svelte src/lib/onboarding/KeyInstructions.svelte src/routes/audit/+page.svelte package.json package-lock.json
git commit -m "feat(onboarding): ConnectWizard shell with mode + get-key steps"
```

---

### Task 8: ValidateStep (paste → validate → result → opt-in remember) + run wiring

**Files:**
- Create: `src/lib/onboarding/ValidateStep.svelte`
- Modify: `src/routes/audit/+page.svelte` (replace the `validate` placeholder; wire Run Audit)
- Verification: `npm run typecheck` + `npm run build`

**Interfaces:**
- Consumes: `validateConnection` + `Fetcher` (Task 5), `UniFiClient` (`src/audit/client.ts`), `rememberKey` + `keychain` (Task 6), `identityFor`/`labelFor` (Task 4), `runAudit` (`src/lib/AuditRunner.ts`), DB writers (`openDb`, `insertRun`, `insertFindings`, `insertSites` from `src/db/queries.ts`), `connectTier`.
- Produces: `ValidateStep` props `mode`, `host`, and callbacks `onvalidated(result)`, plus emits a `run` action. Internally owns the `apiKey`, `remember` checkbox, and result state.

- [ ] **Step 1: Write `ValidateStep.svelte`**

```svelte
<script lang="ts">
  import { UniFiClient } from '../../audit/client.js';
  import { validateConnection, type ValidationResult } from './validateConnection.js';
  import { identityFor, labelFor } from './keyIndex.js';
  import { rememberKey } from './keychain.js';

  let { mode, host = '', onrun }: {
    mode: 'local' | 'cloud'; host?: string;
    onrun: (args: { apiKey: string }) => void;
  } = $props();

  let apiKey = $state('');
  let remember = $state(false);
  let busy = $state(false);
  let result = $state<ValidationResult | null>(null);

  async function validate() {
    if (!apiKey.trim()) { result = { ok: false, error: { kind: 'auth', message: 'Paste your API key first.' } }; return; }
    busy = true;
    const client = new UniFiClient({
      key: apiKey.trim(), host, useCloud: mode === 'cloud', verifySSL: mode === 'cloud', profile: 'home_office',
    });
    result = await validateConnection(client);
    busy = false;
  }

  async function run() {
    if (!result?.ok) return;
    if (remember) {
      const identity = identityFor(mode, host);
      await rememberKey(
        { identity, mode, host: mode === 'local' ? host.trim() : undefined, label: labelFor(mode, host, result.consoleName) },
        apiKey.trim(),
      );
    }
    onrun({ apiKey: apiKey.trim() });
  }
</script>

<div class="space-y-4">
  <label class="block">
    <span class="text-sm font-medium text-gray-700">API key</span>
    <input type="password" bind:value={apiKey} placeholder="Paste your X-API-KEY here"
      class="mt-1 block w-full border rounded-lg px-3 py-2 font-mono text-sm" />
  </label>

  <button type="button" onclick={validate} disabled={busy}
    class="px-4 py-2 rounded-lg border font-medium disabled:opacity-50">
    {busy ? 'Checking…' : 'Validate'}
  </button>

  {#if result?.ok}
    <div class="rounded-lg bg-green-50 border border-green-200 p-3 text-sm text-green-800">
      ✓ Connected{result.consoleName ? ` · ${result.consoleName}` : ''}{result.networkVersion ? ` · Network ${result.networkVersion}` : ''}
      {#if result.sites?.length} · {result.sites.length} site{result.sites.length === 1 ? '' : 's'}{/if}
    </div>
    <label class="flex items-center gap-2 text-sm">
      <input type="checkbox" bind:checked={remember} />
      Remember this key in my keychain
    </label>
    <button onclick={run} class="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold">Run Audit</button>
  {:else if result?.error}
    <div class="rounded-lg bg-red-50 border border-red-200 p-3 text-sm text-red-800">{result.error.message}</div>
  {/if}
</div>
```

- [ ] **Step 2: Wire `ValidateStep` + Run Audit into `src/routes/audit/+page.svelte`**

Replace the `validate` branch placeholder and add the run handler (reuse the exact DB-write sequence from the original file). Add to the `<script>`:

```ts
  import ValidateStep from '../../lib/onboarding/ValidateStep.svelte';
  import { runAudit } from '../../lib/AuditRunner.js';
  import { goto } from '$app/navigation';
  import { get } from 'svelte/store';
  import { connectTier } from '../../lib/stores/connectTier.js';

  let running = $state(false);
  let runError = $state('');

  async function onrun({ apiKey }: { apiKey: string }) {
    running = true; runError = '';
    try {
      const { openDb, insertRun, insertFindings, insertSites } = await import('../../db/queries.js');
      const result = await runAudit(apiKey, host, mode === 'cloud', () => {});
      const db = await openDb();
      const runId = await insertRun(db, host || 'cloud', result.inferredProfile, result.sites.length, get(connectTier));
      await insertFindings(db, runId, result.findings);
      await insertSites(db, runId, result.sites.map(s => ({ siteId: s.siteId, siteName: s.siteName, apiGaps: s.apiGaps })));
      goto(`/wizard?runId=${runId}&profile=${result.inferredProfile}`);
    } catch (e) {
      runError = e instanceof Error ? e.message : String(e);
      running = false;
    }
  }
```

Replace the `validate` branch markup:

```svelte
  {:else if step === 'validate'}
    <ValidateStep {mode} {host} {onrun} />
    {#if runError}<p class="text-red-600 text-sm mt-3">{runError}</p>{/if}
    {#if running}<p class="text-gray-500 text-sm mt-3">Running audit…</p>{/if}
    <button class="mt-4 px-4 py-2 rounded-lg border" onclick={() => (step = 'getkey')} disabled={running}>Back</button>
  {/if}
```

Note: `insertRun` gains a 5th `tier` argument here — that signature change is made in Task 10. Until Task 10 lands, `insertRun(db, host, profile, siteCount, get(connectTier))` will be a type error; if executing strictly in order, do Task 10 before running the Task 8 typecheck, or temporarily drop the 5th arg. (The subagent controller should sequence Task 10's `insertRun` change to unblock this.)

- [ ] **Step 3: Typecheck and build**

Run: `npm run typecheck && npm run build`
Expected: PASS (assuming Task 10's `insertRun` signature is in place — see the note).

- [ ] **Step 4: Commit**

```bash
git add src/lib/onboarding/ValidateStep.svelte src/routes/audit/+page.svelte
git commit -m "feat(onboarding): validate step with opt-in keychain save and run wiring"
```

---

### Task 9: SavedKeys + Step 0 keychain check (entry point)

**Files:**
- Create: `src/lib/onboarding/SavedKeys.svelte`
- Modify: `src/routes/audit/+page.svelte` (initial step `check`; mount logic; scan button)
- Verification: `npm run typecheck` + `npm run build`

**Interfaces:**
- Consumes: `loadIndex`, `keychain` (`.load`, `.scan`), `forgetKey` (Task 6); `identityFor` (Task 4); `UniFiClient` + `validateConnection` (re-validate on Use); `KeyIdentity` type.
- Produces: `SavedKeys` props `saved: KeyIdentity[]`, `orphans: string[]`, callbacks `onuse(entry)`, `onforget(identity)`, `onscan()`, `onskip()`.

- [ ] **Step 1: Write `SavedKeys.svelte`**

```svelte
<script lang="ts">
  import type { KeyIdentity } from './keyIndex.js';
  let { saved, orphans, onuse, onforget, onscan, onskip }: {
    saved: KeyIdentity[]; orphans: string[];
    onuse: (e: KeyIdentity) => void; onforget: (identity: string) => void;
    onscan: () => void; onskip: () => void;
  } = $props();
</script>

<div class="space-y-4">
  {#if saved.length}
    <p class="text-sm text-gray-600">Saved keys found on this machine:</p>
    <ul class="space-y-2">
      {#each saved as e}
        <li class="flex items-center justify-between border rounded-lg px-3 py-2">
          <span class="text-sm">{e.label}</span>
          <span class="flex gap-2">
            <button class="text-blue-600 text-sm" onclick={() => onuse(e)}>Use</button>
            <button class="text-red-600 text-sm" onclick={() => onforget(e.identity)}>Forget</button>
          </span>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="text-sm text-gray-600">No saved keys.</p>
  {/if}

  {#if orphans.length}
    <p class="text-sm text-gray-600">Other keys under this app (from a previous install):</p>
    <ul class="space-y-2">
      {#each orphans as id}
        <li class="flex items-center justify-between border rounded-lg px-3 py-2">
          <span class="text-sm font-mono">{id}</span>
          <button class="text-red-600 text-sm" onclick={() => onforget(id)}>Forget</button>
        </li>
      {/each}
    </ul>
  {/if}

  <div class="flex gap-3">
    <button class="px-4 py-2 rounded-lg border text-sm" onclick={onscan}>Scan for leftover keys</button>
    <button class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-semibold" onclick={onskip}>
      {saved.length ? 'Add another key' : 'Get started'}
    </button>
  </div>
</div>
```

- [ ] **Step 2: Wire Step 0 into `src/routes/audit/+page.svelte`**

Set the initial step to `'check'`, load the index on mount, and handle use/forget/scan. Add to the `<script>`:

```ts
  import SavedKeys from '../../lib/onboarding/SavedKeys.svelte';
  import { loadIndex, keychain, forgetKey } from '../../lib/onboarding/keychain.js';
  import { validateConnection } from '../../lib/onboarding/validateConnection.js';
  import { UniFiClient } from '../../audit/client.js';
  import type { KeyIdentity } from '../../lib/onboarding/keyIndex.js';

  let saved = $state<KeyIdentity[]>([]);
  let orphans = $state<string[]>([]);
  let checkError = $state('');

  // change the initial step:
  // let step = $state<Step>('check');

  $effect(() => { void refreshSaved(); }); // runs on mount

  async function refreshSaved() {
    try { saved = await loadIndex(); } catch { saved = []; }
  }

  async function onscan() {
    try {
      const known = new Set(saved.map(s => s.identity));
      orphans = (await keychain.scan()).filter(id => !known.has(id));
    } catch { orphans = []; }
  }

  async function onforget(identity: string) {
    await forgetKey(identity);
    await refreshSaved();
    orphans = orphans.filter(id => id !== identity);
  }

  async function onuse(entry: KeyIdentity) {
    checkError = '';
    const secret = await keychain.load(entry.identity);
    if (!secret) { checkError = 'That saved key could not be read; it may have been removed.'; return; }
    const client = new UniFiClient({
      key: secret, host: entry.host ?? '', useCloud: entry.mode === 'cloud',
      verifySSL: entry.mode === 'cloud', profile: 'home_office',
    });
    const res = await validateConnection(client);
    if (!res.ok) { checkError = res.error?.message ?? 'The saved key no longer validates.'; return; }
    // Re-validated: hand straight to the run path.
    mode = entry.mode; host = entry.host ?? '';
    await onrun({ apiKey: secret });
  }
```

Add the `check` branch at the top of the markup (before `mode`):

```svelte
  {#if step === 'check'}
    <SavedKeys {saved} {orphans} {onuse} {onforget} {onscan} onskip={() => (step = 'mode')} />
    {#if checkError}<p class="text-red-600 text-sm mt-3">{checkError}</p>{/if}
  {:else if step === 'mode'}
```

(and change `let step = $state<Step>('mode')` to `'check'`.)

- [ ] **Step 3: Typecheck and build**

Run: `npm run typecheck && npm run build`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/lib/onboarding/SavedKeys.svelte src/routes/audit/+page.svelte
git commit -m "feat(onboarding): step 0 keychain check with saved keys + orphan scan"
```

---

### Task 10: `insertRun` tier param + wizard pre-seed

**Files:**
- Modify: `src/db/queries.ts` (`insertRun` accepts a `tier`), `src/wizard/+page.svelte` or the wizard init (consume the run's stored tier — verify current behavior first)
- Test: `src/db/__tests__/queries.test.ts` if `insertRun` is covered there; otherwise `npm run typecheck`

**Interfaces:**
- Produces: `insertRun(db, host, profile, siteCount, tier: Tier = 'standard'): Promise<string>`.

- [ ] **Step 1: Change `insertRun` in `src/db/queries.ts` to accept a tier (default preserves current behavior)**

```ts
export async function insertRun(
  db: DbInstance,
  host: string,
  profile: string,
  siteCount: number,
  tier: Tier = 'standard',
): Promise<string> {
  const id = crypto.randomUUID();
  await db.execute(
    'INSERT INTO runs (id, timestamp, host, profile, tier, site_count) VALUES (?, ?, ?, ?, ?, ?)',
    [id, new Date().toISOString(), host, profile, tier, siteCount],
  );
  return id;
}
```

Confirm `Tier` is imported (it is already, via `import type { AnswerValue, Tier } from './schema.js'`).

- [ ] **Step 2: Verify the wizard reads `run.tier`**

Run: `grep -rn "\.tier\|updateRunTier\|run.tier" src/routes/wizard src/wizard 2>/dev/null`
Expected: confirm the wizard initializes its tier from the stored run (it does today via the `runs.tier` column). No change needed if it already reads `run.tier`; if it hardcodes a tier at wizard start, set it to read the run row's `tier`. Record the finding in the commit message.

- [ ] **Step 3: Run the DB/query tests (or typecheck if none cover insertRun)**

Run: `npx vitest run src/db/__tests__` (Expected: PASS — the default arg keeps existing callers valid)
Then: `npm run typecheck` (Expected: PASS — the Task 8 `insertRun(..., get(connectTier))` call now type-checks.)

- [ ] **Step 4: Commit**

```bash
git add src/db/queries.ts
git commit -m "feat(onboarding): pre-seed the wizard tier from the connect-time choice"
```

---

### Task 11: End-to-end typecheck, full test run, and manual smoke

**Files:** none (verification task)

- [ ] **Step 1: Full unit-test suite**

Run: `npm test`
Expected: PASS (all existing tests plus the new `keyPortalUrl`, `keyInstructions`, `keyIndex`, `validateConnection`, and `schema` tests).

- [ ] **Step 2: Typecheck + build**

Run: `npm run typecheck && npm run build`
Expected: PASS.

- [ ] **Step 3: Rust tests**

Run: `cd src-tauri && cargo test`
Expected: PASS (including the three `keychain` tests).

- [ ] **Step 4: Manual smoke (documented for the reviewer; requires `npm run tauri dev` and a real or mock console)**

Verify by hand: Step 0 shows "No saved keys" on a clean machine; Mode → host → Get-key opens the correct portal via the deep-link button; pasting a bad key shows the mapped error; a good key shows the ✓ scope card; ticking "Remember" then re-launching shows the saved key in Step 0; "Use" re-validates and runs; "Forget" removes it; "Scan for leftover keys" lists nothing extra on a clean machine.

- [ ] **Step 5: Commit (if any doc/notes were added)**

```bash
git commit --allow-empty -m "test(onboarding): full-suite + manual smoke checklist verified"
```

---

## Self-Review

**1. Spec coverage:**
- Step 0 keychain check (index + native scan) → Tasks 1 (scan cmd), 6 (index), 9 (UI). ✓
- Mode step → Task 7. ✓
- Get-key with tiered instructions + deep-link + connectTier pre-seed → Tasks 3, 7, 10. ✓
- Paste + validate + result card → Tasks 5, 8. ✓
- Opt-in unchecked keychain save → Tasks 6, 8. ✓
- Keychain service/account scheme, index (non-secret), forget, orphans → Tasks 1, 4, 6, 9. ✓
- Validation endpoints (reuse, no hardcode) + host distinction → Task 5. ✓
- Error mapping (auth/unreachable/mode-mismatch/unknown) → Task 5. ✓
- Security invariants (paste-only, no logging, identifiers-only scan) → enforced across Tasks 1/5/6/8. ✓
- Testing (TS units + Rust mock + scan) → Tasks 2–6, 11. ✓
- Out-of-scope items are not implemented. ✓

**2. Placeholder scan:** No "TBD"/"implement later"/"add error handling"-style placeholders. The one forward-reference (Task 8 depends on Task 10's `insertRun` signature) is called out explicitly with sequencing guidance, not left implicit.

**3. Type consistency:** `ConnectMode`/`ConnectTier` (`keyInstructions.ts`) reused by `keyPortalUrl`, `KeyInstructions.svelte`, `connectTier.ts`. `KeyIdentity` shape is identical across `keyIndex.ts`, `keychain.ts`, `SavedKeys.svelte`, `ValidateStep.svelte`. `ValidationResult`/`Fetcher` from `validateConnection.ts` used consistently in Task 8. `identityFor`/`labelFor` signatures match their call sites. `insertRun`'s new `tier` param aligns with the `Tier` type and the Task 8 caller.
