# Changelog

All notable changes to UniFi Security Advisor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, version numbers reflect feature milestones, not stability guarantees.

---

## [Unreleased]

## [0.5.2] - 2026-07-07

### Findings
- Wi-Fi security is now assessed on **live audits**, not just backups. The audit reads the v10 API's nested `securityConfiguration` (WPA2 / WPA2-WPA3 mixed / WPA3 / open), so a WPA2-only SSID gets the "consider WPA3" recommendation on a live run instead of being silently skipped.
- New finding: an **open (unencrypted) SSID** is flagged as a high-severity gap, with an intent question so an intentional captive-portal guest network can be acknowledged rather than nagged about.

### Desktop app
- The report's guidance line on "unknown" findings is now aware of how the audit was run: a backup-file audit no longer tells you to "use backup-file mode" (you already did) — it points you to verify the setting in your controller instead.

## [0.5.1] - 2026-07-07

Bug-fix release from dogfooding the audit against a real Cloud Gateway Fiber (UniFi Network 10.4.57).

### Findings
- Firmware currency now trusts the controller's own `firmwareUpdatable` signal instead of a "major version < 7" heuristic. A Cloud Gateway Fiber on UniFi OS 5.x was being wrongly flagged as "multiple major versions behind"; the check now reports a device as needing an update only when the controller says one is available.
- Geo-IP findings no longer false-alarm when the firewall ruleset isn't readable. On API versions where `firewall/policies` is gapped, an empty policy list meant "we couldn't look", not "no rule exists" — so `FW-GEO-IN`/`FW-GEO-OUT` now degrade to an honest "cannot check via live API" (matching `SEG-MGMT-WAN`) instead of recommending a block that may already be in place. When firewall data is visible and genuinely has no geo rule, the recommendation still fires.

### Desktop app
- Fixed the report's **Export Markdown** button, which did nothing in the packaged app: it used a browser download that the Tauri webview ignores. It now saves through a native save dialog (with a Rust `write_text_file` command). Added a **Copy** button that puts the report on the clipboard, plus a small status line for both actions.

## [0.5.0] - 2026-07-06

### Desktop app
- Visual overhaul: a new dark-first look with a UniFi-blue accent, calmer severity colors, the Inter font, and every screen restyled (home, connect, report, wizard, history, backup). Theme has three modes: **system** (the default, which follows your OS and updates live), **light**, and **dark**, switched from a control in the footer. Built on a design-token system so both themes stay consistent.
- Fixed the local API-key instructions after dogfooding a real console: the key is created in a dedicated **Integrations** section (visible to the console Owner account), not under Settings → Control Plane, and the guidance now includes a cloud-key fallback if the local Integrations page isn't available.

### Build / internal
- CI now runs only the test suites a change can affect (path-filtered), so docs or metadata edits no longer trigger the full Rust build.
- Stopped tracking local editor/tooling config (`.claude/`) in the repo, and refreshed the README for the current app plus the download/install story.

## [0.4.1] - 2026-07-06

### Desktop app
- Added a manual **Check for updates** button (in the footer, next to the app version) alongside the existing silent on-launch check. A manual check now reports "You're on the latest version" or an error, while the launch check stays quiet when there's nothing new. The updater logic moved to a shared store (`src/lib/stores/updater.ts`).
- Fixed the Home landing screen so the **Recommended** badge no longer overlaps the "Analyze my network" card title (it's now an in-flow chip above the title).

### Release / distribution
- The in-app updater's "What's changed" now shows the real release notes: the release pipeline populates the GitHub Release body (and therefore `latest.json`'s notes) from the matching `CHANGELOG` section via `tools/changelog-section.mjs`, instead of a generic line.

### Build / dependencies
- Dropped `bzip2` and `zstd` from the `zip` crate (`default-features = false`, `deflate` only). `.unf` parsing only needs Deflate/Stored, so this removes the `bzip2-sys`/`zstd-sys` native-C compilation from the build.

## [0.4.0] - 2026-07-06

### Desktop app
- Guided API-key onboarding: the connect screen is now a stepper that helps the user obtain and use a UniFi API key instead of a bare form. It opens on a keychain check for previously-saved keys (with an on-demand native scan for keys left by prior installs), then walks through choosing local (Network Integration) vs cloud (Site Manager) mode, tiered `Guided | Standard | Pro` instructions for minting a key with a deep-link to the right portal page, and a paste-and-validate step that does a lightweight read-only round-trip and shows what the key can see (console · Network version · site count) before running the full audit. The chosen instruction tier pre-seeds the post-audit wizard. See `docs/superpowers/specs/2026-07-05-api-key-onboarding-design.md`.
- Optional OS keychain storage for API keys (Windows Credential Manager, macOS Keychain, Linux Secret Service), opt-in per key via an unchecked-by-default "Remember this key" checkbox. Saved keys are re-validated before reuse; a "Forget" control removes them. The secret is never logged, never written to the app database or config, and never leaves the machine — only a non-secret index of key identities (e.g. `cloud`, `local:<host>`) is persisted. New Rust commands `keychain_set/get/delete/scan` (identifiers only; scan never returns secret values) and the `tauri-plugin-opener` plugin for the portal deep-links.

### Release / distribution
- The Windows updater now prefers the NSIS installer over the MSI (`updaterJsonPreferNsis`). NSIS does smooth per-user background self-updates; MSI auto-updates can trigger UAC or a full reinstall. Both installers are still published; only which one the updater fetches changed.

### Notes
- Folds in the changes previously staged for the never-published 0.3.0 draft (below); 0.4.0 is the first public release since 0.2.0.

## [0.3.0] - 2026-07-05

### Build / dependencies
- Removed dead dependencies to slim the build and the shipped binary: `tauri-plugin-log` + the `log` crate (declared but never registered/used), and `tauri-plugin-http` / `@tauri-apps/plugin-http` (the frontend never imported it — controller requests go through the custom `unifi_fetch` reqwest command). Also dropped the now-unused `http:default` capability. No behavior change.

### Release / distribution
- In-app auto-update (stage B): the desktop app checks GitHub Releases on launch and, if a newer signed version exists, shows a notify-then-consent banner (`src/lib/components/UpdateBanner.svelte`) with the changelog and an "Update now" button — never silent. Wires `tauri-plugin-updater` + `tauri-plugin-process`, `bundle.createUpdaterArtifacts`, and the committed signing public key. Updates are verified against the public key before install; a failed/offline check is silent. See `docs/superpowers/specs/2026-07-03-auto-update-design.md`.
- Release pipeline (stage A of desktop auto-update): `.github/workflows/release.yml` builds the desktop app via `tauri-apps/tauri-action` on a `v*` tag and publishes a draft GitHub Release, ready to sign updater artifacts once the signing secrets are set. Adds `npm run bump -- <X.Y.Z>` to sync the version across `package.json`, `tauri.conf.json`, `Cargo.toml`, and `Cargo.lock`, plus a `RELEASING.md` runbook. The in-app updater (config + notify-then-consent UI) follows in stage B. See `docs/superpowers/specs/2026-07-03-auto-update-design.md`.

### Desktop app
- Consistent scores everywhere: History and the Home "recent audits" list now use the same answered-findings view as the report (`getAnsweredFindings`), so the same run no longer shows a different score on different screens.
- The Report tab is no longer a dead end when opened cold — it falls back to your most recent audit (with a "pick another" link), or shows a run-an-audit empty state if there are none.
- First-run front door: the app now opens on a real landing screen (`/`) instead of redirecting to an empty History graph. It leads with the value proposition and the privacy trust strip (runs on your device · credentials never leave · read-only), offers the three entry modes as cards (analyze locally / through the cloud / from a backup file) with a "help me choose" decision guide, and lists recent audits with score chips. Adds a Home tab; the cloud card pre-selects Site Manager mode via `?cloud=1`.
- The report now applies the wizard's intent answers and recomputes cross-answer tensions on the answered set (`src/wizard/reportAssembly.ts`), so compound findings reflect what the user told us — an answer that clears a contributor dissolves the compound. This also fixed a gap where the report previously ignored wizard answers entirely.

### Findings
- Cross-answer tension detection: a correlation pass (`src/audit/tensions.ts`) runs after the per-site finding modules and emits compound findings (section "Compound risks") for dangerous combinations no single module sees — e.g. an internet-reachable management plane running known-vulnerable firmware, a flat network with an exposed entry point, or backups that are neither redundant nor verified. Rules key off finding status, which the wizard rewrites from user answers, so compounds fire from config and refine as the user answers (DECISIONS D-003). Six initial rules; adding more is a one-entry change. See `docs/superpowers/specs/2026-07-03-tension-detection-design.md`.

### API currency & drift resilience
- Runtime endpoint discovery (local mode): the audit fetches the console's own OpenAPI spec (`/proxy/network/api-docs/integration.json`) and requests only the endpoints that version advertises, picking the right path alias per concept (`src/audit/endpoints.ts` + `discover.ts`). This adapts across Network versions (v9's `wlans` vs v10's `wifi/broadcasts` both resolve to the same internal key), never 404s on renamed/absent endpoints, and auto-adopts a concept if a future version starts exposing it. Falls back to the default set when the spec is unavailable (older consoles). The schema-drift check is now concept-aware (flags a relied-on concept only when all its known aliases vanish). Also fixed a cloud-connector URL truncation bug for multi-segment v10 paths. See `docs/superpowers/specs/2026-07-03-api-endpoint-discovery-design.md`.
- Runtime version self-check: the audit reads `/v1/info`, compares the controller's UniFi Network version to a tested range (`src/audit/apiVersion.ts`), and surfaces it as an `API-VERSION` meta-finding (informational in range; a low-severity recommendation when newer/older than tested).
- Schema-drift CI: `tools/check-api-drift.ts` + `.github/workflows/api-drift.yml` weekly-diff the app's endpoint set against the latest published UniFi Network OpenAPI (community mirror) and open/auto-close a tracking issue on drift.
- Updated the live-API endpoint paths to the current v10 API (`wlans`→`wifi/broadcasts`, `firewall-policies`→`firewall/policies`, `firewall-zones`→`firewall/zones`, `vpn-configs`→`vpn/servers`); `port-forwards`/`traffic-routes` have no v1 equivalent and remain backup-only. Response shapes derived from the v10.3.58 OpenAPI; live device firmware now feeds advisory matching, and modules degrade gracefully (no false alarms) where the v10 shape differs — verified by `samples/fixture-local-api-v10.json`. WLAN/firewall/VPN finding coverage on live data still awaits adapters validated against real v10 hardware. See `docs/superpowers/specs/2026-07-03-api-currency-design.md`.

### Known advisories
- Advisory-data freshness: a weekly scheduled drift-check (`tools/check-advisory-drift.ts` + `advisory-drift.yml`) opens/auto-closes a tracking GitHub issue when a Ubiquiti CISA-KEV CVE isn't covered by `knownAdvisoriesData.ts`; an `ACKNOWLEDGED_CVES` list suppresses out-of-scope (non-UniFi) CVEs; an `ADVISORIES_LAST_REVIEWED` date is surfaced in the report; and `docs/09-advisory-data-maintenance.md` documents the refresh runbook.

### Backup-file mode
- UniFi OS console `.unifi` decryption ported to the desktop app's Rust `parse_backup` command (`src-tauri/src/lib.rs`) — AES-256-CBC + embedded IV → gzip'd TAR → marker-based BSON, mirroring the Node CLI implementation. The Backup tab now parses Cloud Gateway Fiber / UniFi OS console backups directly instead of directing users to the live API. Adds the crate's first Rust unit tests (9).

## [0.2.0] - 2026-07-03

### Phase 1 (Live API audit)
- Audit engine via Ubiquiti Network Integration API (X-API-KEY auth).
- Known CVE advisory cross-reference: `findKnownAdvisories` module seeded with CVE-2026-34908/9/10 (UDM-Pro firmware ≤ 5.1.11); `tools/fetch-advisories.ts` maintainer script pulls live CISA KEV + NVD data for manual curation.
- `SEG-MGMT-WAN` detection: flags when the management plane is reachable from WAN.
- End-to-end regression test against `fixture-small-business.json` (UCG-Fiber @ 5.0.10).
- Security hardening: migrated to reusable `garymike/security-workflows` caller, `SECURITY.md`, `repo-metadata.yml`.

### Backup-file mode
- UniFi OS console `.unifi` backup decryption (Node CLI): decrypts and parses the previously-undocumented console-level System Backup format (Cloud Gateway Fiber and other UniFi OS consoles). AES-256-CBC with an embedded per-file IV → gzip'd TAR → marker-based BSON stream (`backup/network/db.gz`). Implemented as a fallback in `parseBackupNodejs` alongside the unchanged classic `.unf` path; both produce the same `Collections` shape. New module `src/audit/parseUnifiOsConsoleBackup.ts`.
- `tools/anonymize-backup.ts` maintainer tool: turns a real backup into a safe committed test fixture via a field-level projection (positive per-collection allowlist — any field not explicitly kept is dropped), guarded by a permanent structural safety test. Raw backups are gitignored (`*.unf`, `*.unifi`).

[Unreleased]: https://github.com/garymike/unifi-security-advisor/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.5.2
[0.5.1]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.5.1
[0.5.0]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.5.0
[0.4.1]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.4.1
[0.4.0]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.4.0
[0.3.0]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.3.0
[0.2.0]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.2.0
