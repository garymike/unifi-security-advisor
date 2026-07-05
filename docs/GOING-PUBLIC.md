# Going Public / Open-Source Checklist

Steps to flip `garymike/unifi-security-advisor` from private to public and set up
free code signing. Do them in order — the first item is a hard blocker.

## 1. Scrub real PII (DONE)

The one PII artifact was the `KNOWN_LEAKS` array in
`src/audit/__tests__/fixtureCgfBackupSafety.test.ts` (the maintainer's real
email, name, and device MACs, used as negative-test guards).

- [x] Moved out of the committed test into a local, gitignored
      `src/audit/__tests__/known-leaks.local.json` that the test loads when
      present and skips when absent (public CI / fresh clones). The structural
      field-projection test and the PII-pattern invariants still protect the
      fixture. (#26)
- [x] Confirmed no PII string remains in any tracked file.
- [x] **Git history purged.** Rewrote history with
      `git filter-repo --replace-text` to redact all eight values across every
      commit, and force-pushed `main`, `archive/phase1-python`, and the `v0.2.0`
      tag. Verified 0 occurrences remain in the remote history.

Residual note: old (now-unreachable) commits may linger in GitHub's storage
until it garbage-collects, but they are not included in clones and are not
reachable from any branch/tag. Author metadata (`Michael <…@users.noreply>`)
was left as-is — low risk, no-reply email.

Note on git author metadata: commits are authored as
`Michael <garymike@users.noreply.github.com>`. The no-reply email is
privacy-preserving; the first name in commit metadata is low-risk and typical
for OSS — rewriting it is optional.

## 2. Legal / licensing

- [x] `LICENSE` (MIT) added, copyright `garymike`. Change the holder if you want
      a different name/org, or swap to Apache-2.0 if you want an explicit patent
      grant (reasonable for a security tool).
- [x] `package.json` `license` field set.
- [ ] Confirm you have the right to publish everything (all first-party code; the
      static UniFi decryption constants are public firmware values, already
      documented in `docs/04`).

## 3. Repo hygiene for a public audience

- [x] `README.md` rewritten to describe the current TypeScript/Tauri app.
- [x] `CONTRIBUTING.md` added.
- [x] `SECURITY.md` vulnerability-report policy is present.
- [ ] Skim `docs/` and `DECISIONS.md` for anything you'd rather not publish
      (they're design docs — currently fine).
- [ ] The real backup (`samples/*.unifi`) and signing keys (`~/.tauri/*.key`) are
      outside the repo / gitignored — confirm with `git ls-files | grep -iE "\.unifi|\.key"` (should be empty).

## 4. Flip the repo public

- [ ] GitHub → repo Settings → Danger Zone → Change visibility → Public.
- [ ] After flipping, the README badges and the drift-check issue automation keep
      working; nothing else changes.

## 5. Free Windows code signing (SignPath Foundation)

Once public + MIT-licensed, apply for free OSS signing:

- [ ] Apply at https://signpath.org/apply with the repo URL and license.
- [ ] They review for legitimacy (public, OSI license, a real project). Approval
      grants an OV certificate held in SignPath's HSM; the Windows publisher name
      shows as **"SignPath Foundation"**.
- [ ] Once approved, add the SignPath **organization id / project / signing
      policy** and an `SIGNPATH_API_TOKEN` secret, then add a signing step to
      `.github/workflows/release.yml` after `tauri-action` builds the installer
      (submit the artifact to SignPath, get back the signed one, attach it to the
      release). *(Assistant can wire this once you have the SignPath IDs.)*

This is separate from — and additional to — the updater's minisign signature,
which already works. OS code-signing only removes the Windows "unknown publisher"
SmartScreen warning.

### Other platforms (optional)
- **Linux:** no signing gatekeeper; GPG-sign AppImages with your own key if you like (free).
- **macOS:** notarization needs an Apple Developer account ($99/yr) — no free/OSS
  exception. Skip until/unless you ship a Mac build.

## 6. First signed release

- [ ] `npm run bump -- <version>`, update `CHANGELOG.md`, tag, push (see `RELEASING.md`).
- [ ] Confirm the published release's installer is signed by SignPath and that the
      updater's `latest.json` is present.
