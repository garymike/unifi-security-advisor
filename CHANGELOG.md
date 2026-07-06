# Changelog

All notable changes to UniFi Security Advisor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, version numbers reflect feature milestones, not stability guarantees.

---

## [Unreleased]

### Release / distribution
- The Windows updater now prefers the NSIS installer over the MSI (`updaterJsonPreferNsis`). NSIS does smooth per-user background self-updates; MSI auto-updates can trigger UAC or a full reinstall. Both installers are still published; only which one the updater fetches changed. Takes effect for the next release's `latest.json`.

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

[Unreleased]: https://github.com/garymike/unifi-security-advisor/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.3.0
[0.2.0]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.2.0
