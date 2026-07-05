# Releasing

How a new version is built, signed, and published so the desktop app can
distribute (and, once the in-app updater lands, self-update). Design:
`docs/superpowers/specs/2026-07-03-auto-update-design.md`.

## One-time setup (updater signing key)

The Tauri updater only accepts updates signed with your private key. Generate
the keypair once:

```bash
npm run tauri signer generate -- -w ~/.tauri/unifi-advisor.key
```

This prints a **public key** and writes a password-protected **private key**.

- The **public key** is already committed in `src-tauri/tauri.conf.json` under
  `plugins.updater.pubkey`, alongside `bundle.createUpdaterArtifacts: true`. If
  you ever rotate the signing key, replace it there.
- Add the **private key** and its **password** as GitHub Actions secrets
  (Settings → Secrets and variables → Actions):
  - `TAURI_SIGNING_PRIVATE_KEY` — the contents of the generated `.key` file.
  - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — the password you chose.

Keep the private key safe: whoever holds it can sign updates the app will
trust. Never commit it.

> OS code-signing (Windows Authenticode / macOS notarization) is separate and
> optional. Without it users see a one-time "unknown publisher" warning on
> first install. It needs paid certificates and is deferred.

## Cutting a release

1. Bump the version everywhere it must match:
   ```bash
   npm run bump -- 0.3.0
   ```
   (updates `package.json`, `src-tauri/tauri.conf.json`, `Cargo.toml`, `Cargo.lock`.)
2. Move the `[Unreleased]` section of `CHANGELOG.md` to a dated `## [0.3.0]` heading.
3. Commit on a branch, open a PR, merge to `main`.
4. Tag the merge commit and push the tag:
   ```bash
   git checkout main && git pull
   git tag v0.3.0
   git push origin v0.3.0
   ```
5. The `Release` workflow (`.github/workflows/release.yml`) builds the
   installer(s), signs the updater artifacts (if the secrets are set), and
   creates a **draft** GitHub Release with the bundles + `latest.json`.
6. Review the draft Release, then **publish** it. Installed apps only see the
   update once the release is published (a draft is never "latest").

## Verifying (first time)

- Confirm the draft Release contains the Windows installer, its `.sig`, and a
  `latest.json` whose `version` matches the tag.
- After the in-app updater lands: install the previous version, publish the new
  release, and confirm the app shows the update banner and installs on consent.
  Confirm a tampered artifact fails signature verification and does not install.
