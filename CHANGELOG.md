# Changelog

All notable changes to UniFi Security Advisor are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0, version numbers reflect feature milestones, not stability guarantees.

---

## [Unreleased]

### In progress — Phase 1 (Live API audit)
- Audit engine via Ubiquiti Network Integration API (X-API-KEY auth).
- Known CVE advisory cross-reference: `findKnownAdvisories` module seeded with CVE-2026-34908/9/10 (UDM-Pro firmware ≤ 5.1.11); `tools/fetch-advisories.ts` maintainer script pulls live CISA KEV + NVD data for manual curation.
- `SEG-MGMT-WAN` detection: flags when the management plane is reachable from WAN.
- End-to-end regression test against `fixture-small-business.json` (UCG-Fiber @ 5.0.10).
- Security hardening: migrated to reusable `garymike/security-workflows` caller, `SECURITY.md`, `repo-metadata.yml`.
