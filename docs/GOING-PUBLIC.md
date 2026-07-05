# Going Public / Open-Source Checklist

Steps to flip `garymike/unifi-security-advisor` from private to public and set up
free code signing. Do them in order — the first item is a hard blocker.

## 1. Scrub real PII (BLOCKER — do before making the repo public)

The repo is clean except for one deliberate artifact: the `KNOWN_LEAKS` array in
`src/audit/__tests__/fixtureCgfBackupSafety.test.ts`. It hardcodes the
maintainer's **real email, name, and device MAC addresses** in plaintext, as the
negative-test guard that proves the committed fixture doesn't contain them. That
was fine in a private repo; it must not go public.

- [ ] Move the leak values out of the committed test into a local, gitignored
      file (e.g. `src/audit/__tests__/known-leaks.local.json`) that the test
      loads *if present* and skips that specific check when absent. Add the file
      to `.gitignore`. The load-bearing guarantee — the structural field-level
      projection test plus the PII-pattern invariants (email/MAC/IPv4/`ff:fe`) —
      stays in the committed test and still protects the fixture. *(Ask the
      maintainer's assistant to do this; it's a ~15-line test change.)*
- [ ] Confirm nothing else PII-bearing is tracked:
      `git grep -iE "you@example\.com|<your name>|<your device MAC>"` returns
      only the (now local) file.

- [ ] **Git history still contains the old plaintext values.** The
      `KNOWN_LEAKS` array was committed in earlier PRs, so the real email / name
      / MACs remain greppable in old commits even after the current file is
      cleaned. Removing them from the tip is necessary but not sufficient for a
      fully-clean public history. Options, in order of thoroughness:
      1. Rewrite history to redact those specific strings across all commits
         (`git filter-repo --replace-text`), then force-push. Best done **now**,
         before the repo is public and before there are external clones/forks.
         Rewrites commit SHAs.
      2. Accept it: the values are the maintainer's own email/name/device MACs,
         the repo was private until launch, and severity is low. Simpler.
      *(The maintainer's assistant can do option 1 on request.)*

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
