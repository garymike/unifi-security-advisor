# UniFi Security Advisor

[![Test](https://github.com/garymike/unifi-security-advisor/actions/workflows/test.yml/badge.svg)](https://github.com/garymike/unifi-security-advisor/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A security posture advisor for Ubiquiti UniFi networks — from tech-illiterate novices to seasoned professionals — that audits your setup and tells you not just *how* it's configured, but *whether that configuration is good*.

It reads your network (via the official API or an offline backup file), audits it against industry best practices, interviews you for the intent that isn't in the config, and produces a prioritized, plain-English findings report. Everything runs on your machine; credentials never leave it.

## Design principles

- **Discovery-first.** Detect the current state and ask you to confirm intent, rather than making you remember your config.
- **Progressive disclosure.** The same findings in three voices — Guided (novice), Standard (prosumer), Pro (engineer).
- **Credentials in, never out.** Read locally; all output is sanitized (secrets become length + fingerprint) and safe to share.
- **Officially-supported paths first.** Primary integration is Ubiquiti's Network Integration API (X-API-KEY); backup-file parsing is a specialist mode for airgap / forensic / MSP use.
- **Findings map to frameworks.** NIST CSF, CIS Controls v8, Zero Trust tenets.

## What it does

- **Live audit** against a controller via the local Network Integration API or the cloud Site Manager API. Adapts to the controller's Network version by discovering the endpoints it actually exposes.
- **Backup-file mode** — parses classic `.unf` and the newer UniFi OS console `.unifi` backups (Cloud Gateway Fiber etc.) entirely offline.
- **Findings** across segmentation, Wi-Fi, firewall, remote access, firmware, logging, backups, and more — including **known-CVE advisory** matching and **cross-answer compound risks** that no single check sees.
- **Guided wizard + report** in a desktop app (Tauri + Svelte), with a posture score, an intent interview, and drift history across runs.
- **Self-updating** desktop app via signed GitHub Releases (notify-then-consent).

## Running it

**Desktop app (audit + wizard + report):**
```bash
npm install
npm run tauri dev
```

**CLI (headless audit):**
```bash
npm install
npm run build:audit
# live mode:
UNIFI_NETWORK_API_KEY=... UNIFI_HOST=192.168.1.1 node dist/cli.js
# backup mode:
node dist/cli.js --backup path/to/backup.unifi
```

Credentials are only ever read from environment variables or interactive prompts — never from CLI args. See `docs/05-credential-handling.md`.

## Repository layout

```
src/audit/        Framework-agnostic audit core (normalize, findings, analyze, report)
src/routes/       SvelteKit desktop UI (home, connect, backup, wizard, report, history)
src/wizard/       Profile inference, tier routing, intent-answer merge
src/db/           Local SQLite persistence (runs, findings, answers)
src-tauri/        Rust shell (backup decryption, TLS fetch, updater)
tools/            Maintainer scripts (advisory + API drift checks, fixture anonymizer, version bump)
docs/             Design docs, API strategy, credential handling, maintenance runbooks
```

## Documentation

- **Design & rationale:** `docs/01-design-philosophy.md`, then `DECISIONS.md`
- **API strategy:** `docs/02-api-strategy.md`
- **Backup format internals:** `docs/04-backup-file-strategy.md`
- **Credential handling (absolute rules):** `docs/05-credential-handling.md`
- **Roadmap & status:** `ROADMAP.md`
- **Releasing / auto-update:** `RELEASING.md`

## Contributing

See `CONTRIBUTING.md`. In short: `npm test` and `npm run typecheck` must pass; findings map to a control framework; secrets never appear in output.

## License

[MIT](LICENSE).

## Non-goals

- Not a penetration-testing tool (no exploitation, no active probing).
- Not a runtime IDS/IPS (UniFi has its own).
- Not a config-management tool.
- Not a substitute for Ubiquiti's own update manager or advisories.
