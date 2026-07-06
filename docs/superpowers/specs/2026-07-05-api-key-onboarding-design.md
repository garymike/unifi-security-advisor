# API-Key Onboarding Flow — Design Spec

**Date:** 2026-07-05
**Status:** Approved (pending spec review)
**Scope:** Desktop app (Tauri) only. Shared TS audit core reused unchanged; Node CLI keeps its existing env-var/config path (out of scope).

## Problem

Today's connect screen (`src/routes/audit/+page.svelte`) is a bare form: a password field, a cloud checkbox, a host field, and one inaccurate hint. It jumps straight into a full audit with:

- no help minting an API key (users don't know where to get one),
- no deep-link to the portal,
- no validation — a wrong/expired/wrong-type key fails deep inside the audit with an opaque error,
- no credential persistence — the key is re-pasted every run,
- no tiering for novice vs expert.

We replace it with a guided onboarding stepper that walks the user through getting a key, validates it with live feedback, and optionally stores it in the OS keychain.

## Constraints (from CLAUDE.md / DECISIONS.md — do not violate)

- **No credential input via CLI args, chat messages, or URL parameters.** Paste field only.
- **Credentials never leave the machine.** Validation is a direct machine→console call; no relay, no telemetry.
- **No credential logging.** The key is never written to logs, SQLite, or config. In-session memory or (opt-in) OS keychain only.
- **Outputs sanitized.** The key is masked in the field and never rendered back.
- **Official API paths preferred.** X-API-KEY for Network Integration (local) and Site Manager (cloud). No cookie auth.
- **Shortest-expiration guidance.** Instructions tell the user to pick the shortest expiration and revoke after use. (The API does not expose a key's expiration, so we cannot detect it — guidance only.)

## Key facts that shape the design

- **No OAuth / connected-app flow exists** in Ubiquiti's platform. Both APIs are token-only with manually-minted keys. A third party cannot mint a key on the user's behalf, and automating creation would require driving an authenticated admin session (the cookie-auth anti-pattern we rejected). So "user mints, pastes once" is the correct trust boundary, not a limitation to work around.
- **Tier is unknown at connect time.** The Guided/Standard/Pro tier is chosen by the wizard's skills-check, which runs *after* the audit. So onboarding carries its own tier control and pre-seeds the wizard from it.
- **The `keyring` crate cannot enumerate** entries under a service — only get/set/delete on a known `(service, account)`. Discovering orphaned entries from prior installs requires platform-native enumeration.

## Decisions (resolved during brainstorming)

| Decision | Choice |
| --- | --- |
| Flow shape | Guided stepper (multi-step; collapses for returning users) |
| Keychain consent | Opt-in, checkbox **unchecked** by default |
| Instruction tier at connect time | Segmented `Guided \| Standard \| Pro` toggle, default Guided, choice persisted to pre-seed the wizard tier |
| Validation depth | Lightweight identity + scope (reuses `apiVersion.ts`/`discover.ts`) |
| Startup keychain check | **Both**: index-based auto-check on mount + on-demand "Scan for leftover keys" native enumeration |
| New dependencies | `keyring`, `windows` / `security-framework` / `secret-service` (platform-gated, for enumeration), `tauri-plugin-opener` |

## UX flow

### Step 0 — Check keychain (on mount)
- **Index-based auto-check:** probe the fixed `cloud` account and every locally-remembered `local:<host>` identity (identities are stored in a small non-secret index — see "Keychain design"). For each hit, show a saved-key card: *"UCG-Fiber (local, 192.168.1.1)"* with **Use** · **Forget**.
- **Use** re-validates the stored key before proceeding (it may have expired or been revoked since last run). On validation failure, show the mapped error and fall through to the paste step, keeping the stored entry so the user can Forget it.
- **"Scan for leftover keys"** button → native enumeration lists *all* accounts under our service (identities only, never secret values), including orphans from previous installs whose index entry is gone. Each is Forget-able.
- If nothing is stored and the scan finds nothing, advance to Step 1.

### Step 1 — Mode
- Local (Network Integration) vs Cloud (Site Manager), radio/segmented.
- Local reveals a **host** field (`192.168.1.1` placeholder).
- A one-liner: choose Cloud when the console is behind CGNAT, has a dynamic WAN IP, or you manage multiple sites.

### Step 2 — Get a key
- A `Guided | Standard | Pro` segmented toggle (default Guided). The selection is persisted to a `connectTier` store and used to pre-seed the wizard's tier later.
- Voice-appropriate steps from `keyInstructions.ts` for the chosen mode:
  - **Local:** Settings → Control Plane → Integrations → name the key → pick the **shortest expiration** → Create API Key → copy (shown once).
  - **Cloud:** Sign in at unifi.ui.com → left nav **API** → Create API Key → copy (shown once).
- **"Open the key page"** button deep-links via `tauri-plugin-opener`:
  - Cloud: `https://unifi.ui.com`
  - Local: `https://<host>/network/` (the Integrations settings area; exact sub-path varies by Network 8/9/10, so we open the Network app root rather than guess a version-specific slug).
- Guidance line: "Pick the shortest expiration and revoke the key after this audit."

### Step 3 — Paste & validate
- Password field (masked) + **Validate** button.
- Validate runs the lightweight round-trip (see below) and shows a result card:
  - success: *"✓ UCG-Fiber · Network v10.x · 1 site"* (cloud: site/host count + names),
  - failure: a mapped error (see Error handling).
- On success, an **unchecked** "Remember this key in my keychain" checkbox appears, then **Run Audit** (calls the unchanged `runAudit()` → DB writes → `/wizard`).
- If "remember" is ticked, store the key under its identity and add the identity to the index before running.

## Components & files

### Rust (`src-tauri/`)
- **`src/keychain.rs`** (new): commands
  - `keychain_set(account: String, secret: String) -> Result<(), String>`
  - `keychain_get(account: String) -> Result<Option<String>, String>`
  - `keychain_delete(account: String) -> Result<(), String>`
  - `keychain_scan() -> Result<Vec<String>, String>` — returns account identifiers under our service, no secrets. Platform-gated via `#[cfg(...)]`:
    - Windows: `CredEnumerate` filtered to our target prefix (`windows` crate).
    - macOS: `SecItemCopyMatching` with `kSecClassGenericPassword` + service filter (`security-framework` crate).
    - Linux: libsecret search by attributes (`secret-service` crate).
  - Service name constant: `unifi-security-advisor`.
- **`src/lib.rs`**: register the four commands in `invoke_handler`; add `.plugin(tauri_plugin_opener::init())`.
- **`Cargo.toml`**: add `keyring`, `tauri-plugin-opener`, and platform-gated `windows` / `security-framework` / `secret-service`.
- **`capabilities/default.json`**: add `opener:allow-open-url` (scoped to `https://unifi.ui.com` and `https://*` for local hosts) and any opener default perms.

### Frontend (`src/`)
- **`routes/audit/+page.svelte`**: becomes the `ConnectWizard` host (stepper state machine: `check → mode → getkey → validate`).
- **`lib/onboarding/ModeStep.svelte`**, **`KeyInstructions.svelte`**, **`ValidateStep.svelte`**, **`SavedKeys.svelte`** (Step 0 list): presentational step components.
- **`lib/onboarding/validateConnection.ts`**: the probe. Returns
  ```ts
  interface ValidationResult {
    ok: boolean;
    consoleName?: string;   // e.g. "UCG-Fiber"
    model?: string;
    networkVersion?: string;
    sites?: { id: string; name: string }[];
    error?: ValidationError;  // discriminated: 'auth' | 'unreachable' | 'mode-mismatch' | 'unknown'
  }
  ```
  Reuses `apiVersion.ts` / `discover.ts` and the existing `unifi_fetch` Tauri command.
- **`lib/onboarding/keychain.ts`**: thin TS wrapper over the Rust commands (`saveKey`, `loadKey`, `deleteKey`, `scanKeys`) plus the non-secret **index** helpers (`listIndex`, `addToIndex`, `removeFromIndex`).
- **`lib/onboarding/keyPortalUrl.ts`**: `keyPortalUrl(mode: 'local' | 'cloud', host?: string): string`.
- **`lib/onboarding/keyInstructions.ts`**: the `{ local, cloud } × { guided, standard, pro }` copy blocks.
- **`lib/stores/connectTier.ts`**: persisted tier store; read by the wizard to pre-seed its tier.

## Keychain design

- **Service:** `unifi-security-advisor`.
- **Account (identity):** `cloud` for Site Manager; `local:<host>` for Network Integration. This gives each console/mode its own entry and makes the `cloud` entry probe-able without an index.
- **Index (non-secret):** a small list of stored identities kept in app config/SQLite (identities only — e.g. `["cloud", "local:192.168.1.1"]`), used by the Step-0 index-based check. Never contains secrets.
- **Persistence rule:** the key is stored **only** when the user ticks "remember". A "Forget" control deletes the keychain entry and removes it from the index.
- **Orphans:** entries whose index record is gone (e.g. after an uninstall wiped app config) are surfaced by `keychain_scan` and can be forgotten.

## Validation round-trip

Reuses the existing paths in `endpoints.ts` / `collect.ts` and the `UniFiClient` base-URL logic — do not hardcode new URLs, call through the client.

- **Local:** `GET https://<host>/proxy/network/integration/v1/info` (via `unifi_fetch`) → `applicationVersion` (parsed by `apiVersion.ts`), console model/name, reachability. This also warms the audit's version discovery.
- **Cloud:** `GET https://api.ui.com/v1/hosts` (and `/v1/sites` if needed) → console/site count + names.
- Read-only, 1–2 calls. Self-signed TLS on local is already accepted by `unifi_fetch` (`danger_accept_invalid_certs`).

**Host distinction (do not conflate):** the cloud *API host* is `https://api.ui.com` (used for validation and the audit). The cloud *portal* for minting a key is `https://unifi.ui.com` (used only by the Step-2 deep-link button). Local mode uses `https://<host>` for the API and opens `https://<host>/network/` for the deep-link.

## Error handling (mapped messages)

| Condition | Message |
| --- | --- |
| `401` / `403` | "Key rejected — check you pasted the whole key. It may be expired or the wrong type for this mode." |
| timeout / connection refused | "Couldn't reach `<host>` — is the console on this network and the IP correct?" |
| cloud key used in local mode (or vice-versa), detectable by response shape/status | "This looks like a `<other>` key — switch to `<other>` mode?" |
| other non-2xx / parse failure | "Unexpected response from the console (`<status>`). Try again or check the console is a supported UniFi Network version." |

Errors never include the key value.

## Security invariants (restated)

- Key entered only via the masked paste field — never CLI arg, URL param, or chat.
- Key never logged, never written to SQLite or config; kept in session memory, or in the OS keychain only on explicit opt-in.
- Validation and audit calls go directly from the machine to the console (local) or to the official Site Manager endpoint (cloud) — no third party.
- `keychain_scan` returns identifiers only; secret values are never enumerated or surfaced to the frontend.

## Testing

- **TS units:**
  - `validateConnection` — response parsing and each error-mapping branch against mocked `unifi_fetch` responses (200 with info, 401, timeout, mode-mismatch).
  - `keyPortalUrl` — correct URLs for `local`/`cloud`, host interpolation, missing-host guard.
  - `keyInstructions` — every `mode × tier` block is present and non-empty.
  - `keychain` index helpers — add/list/remove round-trip (index only; the Rust bridge is mocked).
- **Rust units (`keychain.rs`):** `set`/`get`/`delete` round-trip and a not-found path using `keyring`'s **mock** credential store, so CI needs no real vault. `keychain_scan` is exercised on the platform where tests run; on unsupported/CI-headless platforms it returns an empty list rather than erroring.

## Out of scope (YAGNI)

- mDNS / LAN host auto-discovery.
- Keychain support in the Node CLI (keeps env-var/config).
- Reading a key's expiration (not exposed by the API — guidance only).
- Any multi-key management UI beyond one-entry-per-identity + forget + scan.
- Rotating/refreshing keys automatically.
