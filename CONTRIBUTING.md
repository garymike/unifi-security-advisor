# Contributing

Thanks for your interest. This is a security tool for people's home and business
networks, so the bar is correctness and privacy over feature volume.

## Development setup

```bash
npm install
npm test            # vitest (fast; ~2s)
npm run typecheck   # svelte-kit sync + tsc --noEmit
npm run tauri dev   # run the desktop app
```

Rust (the Tauri shell / backup decryption) lives in `src-tauri/`:

```bash
cargo test --manifest-path src-tauri/Cargo.toml --lib
```

CI runs the JS suite + typecheck and `cargo test` on every PR.

## Ground rules (non-negotiable)

These are structural properties of the project, not preferences:

1. **Credentials never leave the machine.** No telemetry, no cloud relay, no logging of secrets.
2. **No credential input via CLI args, chat, or URLs** — env vars, config files, OS keychain, or interactive prompts only.
3. **All output is sanitized.** PSKs, shared secrets, and passwords become length + SHA-256 fingerprints, never raw values (`src/audit/sanitize.ts`).
4. **Read-only by default.** No write/apply operations to a controller in this phase.
5. **Never commit real backups, keys, or PII.** `*.unf`/`*.unifi` and `*.key` are gitignored. Test fixtures are anonymized via `npm run anonymize-backup` and guarded by `fixtureCgfBackupSafety.test.ts`.

See `docs/05-credential-handling.md` for the full detail.

## Adding a finding

1. Add the logic to a module under `src/audit/findings/` and wire it into `analyze.ts`.
2. Map it to at least one control framework (NIST CSF, CIS v8, or a Zero Trust tenet).
3. Set severity, effort, and impact; note which profiles it applies to.
4. Add tests. Findings are pure functions (`site → Finding[]`) — test them directly.

## Conventions

- TypeScript with types everywhere; framework-agnostic audit core (no UI imports in `src/audit/`).
- Findings are deterministic and defensive: an absent field yields "unknown", never a false alarm.
- Match the surrounding code's style. See `CLAUDE.md` for the fuller convention notes.

## Pull requests

Keep PRs focused. Ensure `npm test`, `npm run typecheck`, and `cargo test` pass. Describe
what changed and why; if it's a new finding, say what it detects and how it maps to a framework.
