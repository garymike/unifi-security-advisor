# Desktop Auto-Update Design

**Date:** 2026-07-03
**Status:** Proposed (design for review; build deferred to staged follow-ups)
**Scope:** Give the Tauri desktop app a notify-then-consent self-update capability using the official Tauri Updater and signed GitHub Releases. This depends on first standing up a real release/distribution pipeline, which does not exist today.

---

## Goal

When a new version is tagged and released on GitHub, the installed desktop app notices, tells the user (with the changelog), and — on the user's consent — downloads a **cryptographically signed** update, verifies it, installs it, and relaunches. No silent installs, no telemetry of user data.

## Current state (what exists / doesn't)

- Tauri v2 app, version `0.2.0`, `bundle.active: true`, `targets: "all"`.
- **No updater plugin**, **no signing keys**, **no release/build CI** — the app only runs via `tauri dev`. It produces no installers today.
- CI today: `test.yml` (JS + `cargo test`), `security.yml` (reusable scan; enforces action-version pinning), plus the two drift workflows.
- Version is duplicated across `package.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, `Cargo.lock`.

So auto-update sits on top of **distribution**, which is the real prerequisite: **package → sign → release-automation → in-app updater**.

## Industry-standard approach (Tauri v2)

The canonical stack, all first-party:

1. **`tauri-plugin-updater`** (Rust) + **`@tauri-apps/plugin-updater`** (JS) — the in-app updater.
2. **Update signing (minisign)** — a Tauri keypair. The private key signs each build; the app embeds the public key and refuses any update not signed by it. Separate from OS code-signing.
3. **Update manifest (`latest.json`)** — version, per-platform download URLs, per-artifact signatures, and notes. Served at a stable URL.
4. **GitHub Releases as the feed** — free, stable URLs. Manifest at `https://github.com/garymike/unifi-security-advisor/releases/latest/download/latest.json`; bundles as release assets.
5. **`tauri-apps/tauri-action`** in CI — on a version tag, builds each OS, signs, and publishes the Release with bundles + updater artifacts + `latest.json`.

---

## Architecture — three layers

### Layer 1 — Release pipeline (`.github/workflows/release.yml`)

- **Trigger:** push of a tag matching `v*` (e.g. `v0.3.0`).
- **Matrix:** start with `windows-latest` only (the maintainer's platform), structured so `macos-latest` / `ubuntu-latest` can be added later without rework. Linux needs the same WebKitGTK system deps the `rust` test job already installs.
- **Steps per runner:** checkout → setup-node + `npm ci` → (Linux: apt deps) → `tauri-action` with `TAURI_SIGNING_PRIVATE_KEY` + `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` env, which runs `npm run build` (frontend) then `tauri build`, signs artifacts, and creates/updates a GitHub Release (draft first, or published) with the bundles + `.sig` files + `latest.json`.
- **Action pinning:** `tauri-action` and `actions/*` pinned to a version tag (matches the repo's existing pinning check).
- **`bundle.createUpdaterArtifacts: true`** in `tauri.conf.json` so the updater `.sig`/archive artifacts are produced.

### Layer 2 — Signing

- **Updater key (required):** `tauri signer generate -w ~/.tauri/unifi-advisor.key` → a public key (committed in `tauri.conf.json` → `plugins.updater.pubkey`) and a password-protected private key. The private key + password become **GitHub Actions secrets** (`TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`). The maintainer generates and stores these; they never enter the repo.
- **OS code-signing (optional, deferred):** Windows Authenticode / macOS notarization remove the SmartScreen/Gatekeeper "unknown publisher" warning. They require paid certs / an Apple Developer account and the maintainer's identity, so they're out of scope for the first cut. Documented as a known first-run wart on Windows/macOS until added. Linux AppImage is unaffected.

### Layer 3 — In-app updater (notify-then-consent)

- Add `tauri-plugin-updater` (Rust, `run()` builder) + `@tauri-apps/plugin-updater` (JS) + the `updater:default` capability permission, and `plugins.updater` config (`endpoints` = the `latest.json` URL; `pubkey`).
- **UX (notify-then-consent):** on app launch, a small `src/lib/UpdateBanner.svelte` (mounted in `+layout.svelte`) calls `check()`. If an update exists, it shows a non-blocking banner: *"Version X is available"* + a "What's changed" link (the release notes / CHANGELOG) + **Update now** / **Later**. "Update now" calls `downloadAndInstall()` with a progress indicator, then `relaunch()`. No auto-download before consent.
- **Failure handling:** a failed or offline check is silent (no nag); a failed download surfaces a dismissible error. Signature-verification failure aborts hard — never installs.
- **Manual path:** a "Check for updates" action (e.g. on the Home screen) for users who disable or miss the launch check.

---

## Version & release flow

1. Bump the version in all four files (`package.json`, `tauri.conf.json`, `Cargo.toml`, `Cargo.lock`) — add a small `npm run bump -- <version>` script (or a documented checklist) to keep them in sync, since the updater compares `tauri.conf.json`'s version against `latest.json`.
2. Update `CHANGELOG.md` (move `[Unreleased]` → the new version) and commit.
3. Tag `vX.Y.Z` and push → `release.yml` builds, signs, and publishes the GitHub Release + `latest.json`.
4. Installed apps see the new `latest.json`, notify their users, and update on consent.

This reuses the existing release ritual (we already cut `v0.2.0` this way) — it just adds the signed-artifact build and the `latest.json`.

---

## Privacy & security decisions (this app's constraints)

The absolute constraints (`docs/05`) say no telemetry and credentials never leave the machine. The updater is compatible, but must be deliberate:

- **The update check is a metadata request** to GitHub (sends app version + platform + OS via the HTTP user-agent). It carries **no** user/network/credential data. Documented as such in `docs/05` so it isn't mistaken for telemetry.
- **Notify-then-consent, not silent** — chosen deliberately: a tool that reads a user's network config should let them see what's changing and choose to update.
- **Signature verification is mandatory and non-bypassable** — a security tool that auto-installs unsigned code would be a supply-chain hole. The minisign check is the floor; OS code-signing is the follow-on.
- **The public key is committed; the private key is a CI secret** the maintainer controls. Key compromise = ability to push malicious updates, so it's treated with the same care as a release-signing key.

---

## What the maintainer must provide

1. Generate the updater keypair (`tauri signer generate`) and add `TAURI_SIGNING_PRIVATE_KEY` + `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` as GitHub Actions secrets. (I can walk through the exact commands.)
2. Decide target platforms for the first release (recommend Windows-only to start).
3. Optional/later: OS code-signing certs (Windows Authenticode, Apple notarization) to remove first-run warnings.

Everything else — workflow, config, plugin wiring, in-app UI — I can build.

---

## Staged build plan (after this design is approved)

- **Stage A — Release pipeline:** `release.yml` (Windows first) + `createUpdaterArtifacts` + a version-bump helper. Produces a signed installer + `latest.json` on tag. Verifiable by cutting a `v0.2.1` test release and downloading the artifact.
- **Stage B — In-app updater:** plugin + config + `UpdateBanner.svelte` (notify-then-consent) + manual check. Verifiable by installing an older build and confirming it detects/offers the newer release.
- **Stage C — Polish/hardening (optional):** OS code-signing, macOS/Linux matrix, staged rollout, a settings toggle for auto-check.

Each stage is its own PR.

## Testing / verification

- Stage A: tag a throwaway `v0.2.1`, confirm the Release contains the platform bundle, its `.sig`, and a well-formed `latest.json`; confirm `tauri-action` signed with the CI key.
- Stage B: build `0.2.0` locally, point it at the real endpoint, confirm it detects `0.2.1`, shows the banner, and that a **tampered** artifact fails signature verification (must not install).

## Risks & non-goals

- **Unsigned OS installers** → SmartScreen/Gatekeeper warnings on first run until code-signing is added. Acceptable for an early-access security tool; documented.
- **Cross-platform build cost** — a full matrix triples CI minutes; mitigated by Windows-first.
- **Not** an app-store distribution (MS Store / Mac App Store) — their sandboxing conflicts with a local-network tool and adds review friction. GitHub Releases is the right host here.
- **Not** silent auto-update (explicitly rejected for this app).
