# UniFi OS Console Backup (.unifi) Decryption Design

**Date:** 2026-07-03
**Status:** Approved
**Scope:** Node/TypeScript CLI path only (`src/audit/normalizeBackup.ts`'s `parseBackupNodejs`). The Rust/Tauri desktop-app path (`src-tauri/src/lib.rs`) is explicitly deferred to a fast-follow round, once this format/parsing approach is proven end-to-end against real data.

---

## Problem

`docs/04-backup-file-strategy.md` and this project's own commit history (5 commits, 8 weeks ago) document the newer UniFi OS console-level `.unifi` backup format — produced by Cloud Gateway Fiber and other UniFi OS console hardware — as using "device-specific encryption not yet publicly documented." The backup-tab UI still tells CGF users to use the live API instead, since backup mode can't parse their format at all.

This was re-tested live this session against a real CGF backup file and **fully cracked**:

- **Encryption:** AES-**256**-CBC (not the classic `.unf` format's AES-128), static key `e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f`, IV read from the file's first 16 bytes (not the classic format's static IV).
- **Container:** decrypts to a **gzip'd TAR archive** (not a ZIP), containing `backup/network/`, `backup/ucore/` (UCore's PostgreSQL data), `backup/uos/`, `backup/users/`.
- **`backup/network/db.gz`**, once extracted from the tar and gunzipped, is a gzipped BSON stream — the same underlying format the classic `.unf` parser already reads — but with a **different internal structure**: most documents are *not* self-tagged with their collection name. Instead, a small `{ collection: X, __cmd: ... }` marker document precedes a run of untagged data documents that belong to collection `X` until the next marker appears. Verified against the real file: this produced ~95 correctly-attributed marker records plus ~205 previously-"unknown" documents that are genuinely valid `networkconf`/`device`/etc. records once attributed via the marker.

All of the above was verified empirically against a real backup file this session (decrypted, gunzipped, tar-walked, and BSON-parsed successfully, producing ~100 real UniFi collection names including `firewallrule`, `firewall_policy`, `firewall_zone`, `portforward`, `networkconf`, `wlanconf`, `device`, `setting`).

---

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Runtime scope this round | Node/TS CLI only; Rust/Tauri deferred | Can be directly verified against the real file without needing to drive the desktop GUI; lower risk than debugging two implementations of a newly-reverse-engineered format at once |
| UCore PostgreSQL data (`backup/ucore/database/*`) | Deferred entirely | Different format (pg_dump custom binary, not BSON); no current finding module consumes it — would be built-ahead-of-need |
| Module placement | New dedicated `src/audit/parseUnifiOsConsoleBackup.ts`, not folded into `normalizeBackup.ts` | Different crypto, different container, different collection-parsing logic — genuinely separate concern. `normalizeBackup()` itself needs zero changes; both formats produce the same `Collections` shape |
| TAR parsing | Minimal inline reader, no new dependency | CLAUDE.md's minimal-deps convention; TAR's 512-byte-header-block format is simple, and we only need one entry (`backup/network/db.gz`), not full extraction |
| Fixture anonymization | Reusable script (`tools/anonymize-backup.ts`), not hand-editing | ~100 collections is too much surface area to safely hand-scrub; a script preserves cross-collection referential consistency (same MAC → same fake MAC everywhere) and is reusable for future backups |
| Desktop app UI hint text | Left unchanged this round | It's shown by the Tauri app, which still calls the un-fixed Rust `parse_backup` command this round. Changing it now would falsely claim support the shipped app doesn't have yet |

---

## Component 1: `src/audit/parseUnifiOsConsoleBackup.ts`

Three independently-testable functions:

### `decryptConsoleBackup(raw: Buffer): Buffer`

AES-256-CBC, static key `e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f` (hex), IV = `raw.subarray(0, 16)`, ciphertext = `raw.subarray(16)`. Returns the decrypted gzip byte stream. Throws if the result isn't valid gzip (checked via the `1f 8b` magic bytes) — this is the format-detection signal used by the dispatcher in Component 2.

### `extractTarEntry(tarBuf: Buffer, entryName: string): Buffer | null`

Walks 512-byte TAR header blocks: reads the 100-byte null-terminated filename field and the 12-byte octal size field, compares the filename to `entryName`, and if matched returns the following `size` bytes (no need to handle TAR extensions, long-filename records, or anything beyond what a UniFi backup actually produces — verified empirically against the real file's TAR structure, which uses plain USTAR-style headers throughout). Returns `null` if not found (used by the dispatcher to detect "this decrypted fine but isn't the container we expect").

### `parseMarkerStreamBson(bsonData: Buffer): Collections`

Walks the flat BSON document stream (same length-prefixed framing the classic parser already uses). For each document: if it has a `collection` field (the marker shape is `{ _id, collection, __cmd, ... }` — verified against the real file), set `currentCollection = doc.collection` and do **not** include the marker itself in the output (it carries no real data). Otherwise, push the document onto `collections[currentCollection]`. Documents encountered before any marker (if any) are logged and dropped, not silently included under `undefined`.

---

## Component 2: Dispatcher in `parseBackupNodejs`

`normalizeBackup.ts`'s `parseBackupNodejs` gets a fallback chain, preserving 100% of the existing classic-`.unf` behavior as the first attempt:

1. Try the existing AES-128 static-key/IV → ZIP-signature-check → `db.gz` (or `dump/<db>/<collection>.bson`) path, exactly as today.
2. If that throws, try `decryptConsoleBackup` → gunzip → `extractTarEntry(tar, 'backup/network/db.gz')` → gunzip → `parseMarkerStreamBson`.
3. If both throw, raise a single combined error: `"Unrecognized backup format — neither the classic .unf scheme nor the UniFi OS console scheme decoded a valid archive."` (replacing the current CGF-specific "not yet publicly documented" message, which is no longer true).

Both paths return the same `Collections` type (`Record<string, Record<string, unknown>[]>`), so every downstream consumer — `normalizeBackup()`, all finding modules — needs zero changes.

---

## Component 3: Anonymization script + fixture

`tools/anonymize-backup.ts` — maintainer-run, same category as `tools/fetch-advisories.ts`:

- Input: a real `.unifi` file path (read locally, never transmitted anywhere — matches the project's offline backup-mode constraint).
- Runs it through `parseBackupNodejs` to get the real `Collections` object.
- Walks every collection recursively, replacing: MAC addresses (deterministic fake MAC, same real MAC → same fake MAC everywhere it appears, preserving cross-references between e.g. `device` and `user`/client records), IP addresses (deterministic fake IP within the same private range), hostnames/site names/device names (generic placeholders, e.g. `Device-01`, `Site-01`), and any field name already in the sanitizer's known-secret-field set (PSKs, admin password hashes, API keys, certs/keys — the TAR already showed `unifi-core*.crt`/`.key` files, though those live outside `db.gz` and aren't parsed by this pipeline at all, so no risk there).
- Output: `samples/fixture-cgf-backup.json`, storing the **`Collections` shape directly** (not the live-API shape `fixture-local-api.json` uses) — this is a new fixture category for backup-mode, consumed via `normalizeBackup(collections, profile)` directly rather than `normalizeApi`.
- Never auto-commits — the maintainer reviews the anonymized output before adding it to git, consistent with `tools/fetch-advisories.ts`'s "draft, don't auto-apply" pattern.

---

## Testing plan

- `parseUnifiOsConsoleBackup.test.ts`: `decryptConsoleBackup` (valid file decrypts to gzip-magic-prefixed bytes; garbage input throws), `extractTarEntry` (finds a known entry, returns `null` for a missing one, handles a minimal synthetic TAR fixture), `parseMarkerStreamBson` (marker-then-data sequence attributes correctly, multiple collections in sequence, documents before the first marker are dropped not miscategorized, empty input returns empty `Collections`).
- `normalizeBackup.test.ts` (existing file): add a case proving the classic `.unf` path is untouched (existing tests already cover this — just confirm no regressions) plus a case exercising the new fallback path with a small synthetic AES-256/tar/marker-stream fixture built inline (not the full real file — unit-level, fast).
- **End-to-end regression against the real file:** the anonymized `fixture-cgf-backup.json` (Component 3) run through `normalizeBackup()` → `analyze()`, asserting real findings come out (e.g. `SEG-MGMT-WAN` now gets real data to evaluate instead of the `unknown` no-visibility branch, `FW-GEO-IN`/`FW-GEO-OUT` evaluate real `firewallrule` data) — this simultaneously validates the new parser **and** finally exercises the `SEG-MGMT-WAN` heuristic against real field shapes, which was an explicitly-flagged unverified risk from the CVE-tracking feature shipped earlier today.

## Error handling

- `decryptConsoleBackup` and `extractTarEntry` fail fast with specific, typed errors (not generic throws) so the dispatcher in Component 2 can distinguish "wrong format, try the other path" from "right format, but corrupt data" — the latter should surface a clearer error to the CLI user than a silent fallback-and-fail.
- `parseMarkerStreamBson` never throws on malformed individual documents — matches the classic parser's existing `try { BSON.deserialize } catch { break }` behavior (stop cleanly at the first unparseable document rather than crash the whole backup analysis).

## Files touched

**New:** `src/audit/parseUnifiOsConsoleBackup.ts`, `src/audit/__tests__/parseUnifiOsConsoleBackup.test.ts`, `tools/anonymize-backup.ts`, `samples/fixture-cgf-backup.json` (anonymized, committed), `src/audit/__tests__/fixtures-cgf-backup.test.ts` (or added to existing `fixtures.test.ts`).

**Modified:** `src/audit/normalizeBackup.ts` (`parseBackupNodejs` fallback chain + updated error message), `src/audit/__tests__/normalizeBackup.test.ts` (new fallback-path test case).

**Explicitly not touched this round:** `src-tauri/src/lib.rs`, `src/routes/backup/+page.svelte` (see Decisions table).

---

## Out of scope for this round

- Rust/Tauri desktop app port — separate fast-follow round once this is proven.
- UCore PostgreSQL data (`backup/ucore/database/*`) — no consumer exists yet.
- `backup/uos/` and `backup/users/` subdirectories — not needed by any current finding module (Network app data in `backup/network/db.gz` is the entire win this round).
- Updating the backup-tab UI hint text — accurate only once the Rust path is also fixed.
