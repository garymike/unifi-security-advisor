# UniFi OS Console `.unifi` Decryption — Rust/Tauri Port Design

**Date:** 2026-07-03
**Status:** Approved
**Scope:** Port the console `.unifi` backup decryption (already shipped in the Node/TS CLI as `src/audit/parseUnifiOsConsoleBackup.ts`) into the Tauri desktop app's Rust `parse_backup` command (`src-tauri/src/lib.rs`), so the desktop Backup tab can parse Cloud Gateway Fiber / UniFi OS console backups. Fast-follow to the 2026-07-03 Node-side design.

---

## Problem

The desktop app's Backup tab calls the Rust `parse_backup` command (`src/routes/backup/+page.svelte:39`) and feeds the returned collections into `normalizeBackup()`. The Rust command only handles the classic `.unf` format (AES-128-CBC → ZIP → BSON). For console `.unifi` backups it falls through to `try_embedded_iv_strategies`, which guesses AES-**128** embedded-IV variants — it never decoded the real format, and its error text still claims the encryption is "not yet reverse-engineered." The Node CLI cracked and implemented the real format weeks ago; this brings the desktop app to parity.

The real console format (verified live, see the Node-side spec): **AES-256-CBC**, static key `e383…985f`, **IV embedded in the first 16 bytes**, decrypting to a **gzip'd TAR** whose `backup/network/db.gz` is a **marker-based BSON stream** (`{collection, __cmd}` marker precedes untagged data docs for that collection).

---

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Dispatch shape | Classic ZIP path first (unchanged), console path as fallback | Mirrors the Node dispatcher; zero risk to the working classic path |
| Replace `try_embedded_iv_strategies` | Yes — delete it | AES-128 embedded-IV guessing never decoded the real format and its error message is now false. The console path supersedes it |
| Console key storage | `[u8; 32]` byte-array literal | Avoids a hex-decode dependency and keeps the (gitleaks-flagged) hex string out of the Rust source entirely |
| Padding | PKCS7 (default), not `NoPadding` | The console ciphertext uses standard PKCS7; the classic path's `NoPadding` is specific to that format |
| TAR reader | Inline USTAR walker (~30 lines) | Matches the Node design's minimal-deps choice; mirrors the proven TS logic exactly; no new crate |
| Marker BSON | New `parse_marker_stream_bson` | The existing `parse_bson_stream` returns a flat Vec with per-doc `collection` tags; the console stream needs marker-based attribution |
| UI hint | Update `+page.svelte:101` | It currently tells CGF users the format is unsupported; that is no longer true for the desktop app |

---

## Components (`src-tauri/src/lib.rs`)

Three new functions mirroring `parseUnifiOsConsoleBackup.ts`, plus a dispatcher change:

### `decrypt_console_backup(raw: &[u8]) -> Result<Vec<u8>, String>`
AES-256-CBC, `CONSOLE_KEY` (`[u8; 32]`), IV = `raw[0..16]`, ciphertext = `raw[16..]`, PKCS7 padding. Returns the decrypted bytes only if they start with the gzip magic `1f 8b` (the format-detection signal); otherwise `Err`.

### `extract_tar_entry(tar: &[u8], name: &str) -> Option<Vec<u8>>`
Walks 512-byte USTAR header blocks: reads the 100-byte NUL-terminated filename and the 12-byte octal size field; on a name match returns the following `size` bytes. `None` if not found. No long-name/extension handling (the real backup uses plain USTAR).

### `parse_marker_stream_bson(data: &[u8]) -> Result<HashMap<String, Vec<Value>>, String>`
Walks the length-prefixed BSON document stream (same framing as `parse_bson_stream`). A doc containing a `collection` field sets the current collection and is **not** emitted; other docs are pushed onto the current collection. Docs before the first marker are dropped. Never panics on a malformed doc — stops cleanly (matches `parse_bson_stream`).

### Dispatcher in `parse_backup`
After the classic ZIP strategies fail to produce a ZIP, attempt: `decrypt_console_backup(raw)` → gunzip → `extract_tar_entry(tar, "backup/network/db.gz")` → gunzip → `parse_marker_stream_bson`. If that also fails, return one combined error naming both schemes (replacing the old "not yet reverse-engineered" message). Both paths return the same `HashMap<String, Vec<Value>>`, so `normalizeBackup()` and the frontend are untouched.

---

## Testing

`#[cfg(test)]` unit tests in `lib.rs` (the crate currently has none). The real backup is gitignored, so end-to-end validation against it stays local/manual — same constraint as the Node side. Synthetic fixtures built inline in the tests:

- `decrypt_console_backup`: AES-256-encrypt a gzip blob with a random-IV-prefixed layout and assert it round-trips to gzip-magic bytes; assert garbage input errors.
- `extract_tar_entry`: build a minimal USTAR archive with one named entry; assert it extracts, and that a missing name returns `None`.
- `parse_marker_stream_bson`: encode a marker doc followed by two data docs (and a second collection) and assert correct attribution; assert docs before the first marker are dropped; assert empty input returns empty.

Local verification: `cargo test` (in `src-tauri/`) and `cargo build`.

---

## Out of scope

- UCore PostgreSQL data (`backup/ucore/*`) — no consumer, deferred (same as Node side).
- Any change to the classic `.unf` path behavior.
- Rust CI job — the app has no Rust CI today; adding one is a separate decision.
