# UniFi Security Advisor

[![Test](https://github.com/garymike/unifi-security-advisor/actions/workflows/test.yml/badge.svg)](https://github.com/garymike/unifi-security-advisor/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A desktop app that audits a Ubiquiti UniFi network and tells you not just how it's configured, but whether that configuration is actually any good.

It reads your network (through Ubiquiti's official API, or from an offline backup file), checks it against security best practices, asks you about the intent that isn't stored in the config, and gives you a plain-English report of what to fix and why. Everything runs on your own machine. Your credentials never leave it.

It's meant to work for a range of people. If you don't know a VLAN from a VPN, it explains things in plain language. If you're a network engineer, it hands you exact settings, control IDs, and CVE references. Same findings, three different voices.

## Install

The easiest way is to grab a prebuilt installer from the [latest release](https://github.com/garymike/unifi-security-advisor/releases/latest).

On Windows, download the `.exe` installer and run it. SmartScreen may warn about an unknown publisher while code signing is still being set up; click "More info" then "Run anyway".

Once it's installed, the app checks for a newer version on launch and offers to update itself, so you only install it by hand once. If you'd rather build it yourself, see [Running from source](#running-from-source).

## How it works

You point it at your UniFi console one of three ways:

- **On the same network.** Create a read-only API key on the console and paste it in. This is the local path and gives the most detail.
- **Through the cloud.** Use a Site Manager key from unifi.ui.com when the console is behind CGNAT or you're auditing it remotely.
- **From a backup file.** Fully offline. It decrypts and parses both the classic `.unf` format and the newer UniFi OS console `.unifi` format (Cloud Gateway Fiber and similar).

A short setup flow walks you through creating the key, and it can save the key to your OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service) so you don't paste it every time. The key is only ever typed in by hand, never passed as a command-line argument or a URL.

From there it collects the config, runs its checks, asks you a few questions the config can't answer, and produces a scored report.

## What it checks

Findings cover segmentation, Wi-Fi, firewall rules, remote access, firmware, logging, and backups, among other areas. On top of the individual checks it does two things most tools skip:

- It matches your firmware against known Ubiquiti CVEs.
- It looks for compound risks that no single check would catch alone, like a management plane that's reachable from the internet *and* running vulnerable firmware.

Every finding is ranked by impact and effort, mapped to a control framework (NIST CSF, CIS Controls v8, Zero Trust), and comes with a recommendation you can act on. Results are stored locally, so you can see how your posture changes from one run to the next.

## What it won't do

- No penetration testing. It never exploits anything or actively probes.
- No intrusion detection. UniFi already does that.
- No config changes. It reads your setup, it doesn't push anything back.
- It's not a replacement for Ubiquiti's own updates and advisories.

## Principles

A few rules the project holds to:

- **Credentials stay on your machine.** No telemetry, no cloud relay, nothing sensitive written to logs. Anything secret in the report (keys, PSKs, shared secrets) is replaced with a length and a fingerprint, so the report is safe to share.
- **Ask, don't assume.** It detects the current state and asks you to confirm what you intended, instead of making you remember how you set it up.
- **Read-only by default.** It never changes your configuration.
- **Official API paths first.** The main route is Ubiquiti's Network Integration API. Backup parsing is a specialist mode for airgapped, forensic, or MSP work.

## Running from source

You'll need Node and a Rust toolchain (Rust is for the Tauri shell).

Desktop app:

```bash
npm install
npm run tauri dev
```

Headless CLI audit:

```bash
npm install
npm run build:audit
# live:
UNIFI_NETWORK_API_KEY=... UNIFI_HOST=192.168.1.1 node dist/cli.js
# from a backup:
node dist/cli.js --backup path/to/backup.unifi
```

The CLI reads credentials from environment variables or an interactive prompt only, never from arguments. The full credential rules are in [docs/05-credential-handling.md](docs/05-credential-handling.md).

## Layout

```
src/audit/    Audit core: normalize, run findings, analyze, report (no UI framework)
src/routes/   Desktop UI (home, connect, backup, wizard, report, history)
src/wizard/   Profile inference, tier routing, intent answers
src/db/       Local SQLite (runs, findings, answers)
src-tauri/    Rust shell: backup decryption, TLS fetch, keychain, updater
tools/        Maintainer scripts (drift checks, fixture anonymizer, version bump)
docs/         Design notes, API strategy, credential rules, runbooks
```

## More reading

- Why it's built this way: [docs/01-design-philosophy.md](docs/01-design-philosophy.md), then [DECISIONS.md](DECISIONS.md)
- API choices and tradeoffs: [docs/02-api-strategy.md](docs/02-api-strategy.md)
- What's inside a backup file: [docs/04-backup-file-strategy.md](docs/04-backup-file-strategy.md)
- The credential rules, in full: [docs/05-credential-handling.md](docs/05-credential-handling.md)
- Where it's headed: [ROADMAP.md](ROADMAP.md)
- Cutting a release: [RELEASING.md](RELEASING.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: `npm test` and `npm run typecheck` have to pass, every finding maps to a control framework, and secrets never show up in output.

## License

[MIT](LICENSE).
