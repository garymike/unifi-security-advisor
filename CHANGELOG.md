# Changelog

All notable changes to UniFi Security Advisor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, version numbers reflect feature milestones, not stability guarantees.

---

## [Unreleased]

### API currency & drift resilience
- Runtime version self-check: the audit reads `/v1/info`, compares the controller's UniFi Network version to a tested range (`src/audit/apiVersion.ts`), and surfaces it as an `API-VERSION` meta-finding (informational in range; a low-severity recommendation when newer/older than tested).
- Schema-drift CI: `tools/check-api-drift.ts` + `.github/workflows/api-drift.yml` weekly-diff the app's endpoint set against the latest published UniFi Network OpenAPI (community mirror) and open/auto-close a tracking issue on drift. It currently flags 6 v9-era endpoint paths (`wlans`, `firewall-policies`, `firewall-zones`, `port-forwards`, `vpn-configs`, `traffic-routes`) that Ubiquiti renamed/restructured in v10 — tracked for a follow-up (Component C), pending validation against a live v10 controller. See `docs/superpowers/specs/2026-07-03-api-currency-design.md`.

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

[Unreleased]: https://github.com/garymike/unifi-security-advisor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/garymike/unifi-security-advisor/releases/tag/v0.2.0
