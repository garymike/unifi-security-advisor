/**
 * Bumps the app version in the four places that must stay in sync for a
 * release (the Tauri updater compares tauri.conf.json's version against the
 * published latest.json):
 *   - package.json
 *   - src-tauri/tauri.conf.json
 *   - src-tauri/Cargo.toml        ([package] version)
 *   - src-tauri/Cargo.lock        (the `app` package entry)
 *
 * Usage: npm run bump -- <X.Y.Z>
 * Does not commit, tag, or touch the changelog — that stays a deliberate step.
 * Computes every replacement first and only writes once all four match, so a
 * miss never leaves the files half-updated.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
  console.error('Usage: npm run bump -- <X.Y.Z>  (e.g. 0.3.0)');
  process.exit(1);
}

const edits = [
  // package.json — the first top-level "version" key.
  { path: 'package.json', pattern: /"version": "\d+\.\d+\.\d+"/, replacement: `"version": "${version}"` },
  // tauri.conf.json — top-level "version".
  { path: 'src-tauri/tauri.conf.json', pattern: /"version": "\d+\.\d+\.\d+"/, replacement: `"version": "${version}"` },
  // Cargo.toml — the [package] version (anchored at line start; inline dep versions are not).
  { path: 'src-tauri/Cargo.toml', pattern: /^version = "\d+\.\d+\.\d+"/m, replacement: `version = "${version}"` },
  // Cargo.lock — the `app` package block (tolerate CRLF line endings).
  { path: 'src-tauri/Cargo.lock', pattern: /(name = "app"\r?\nversion = ")\d+\.\d+\.\d+(")/, replacement: `$1${version}$2` },
];

const writes = edits.map(({ path, pattern, replacement }) => {
  const before = readFileSync(path, 'utf8');
  const after = before.replace(pattern, replacement);
  if (after === before) {
    console.error(`No version match in ${path} — aborting without writing anything.`);
    process.exit(1);
  }
  return { path, after };
});

for (const { path, after } of writes) writeFileSync(path, after);

console.log(`Bumped version to ${version} in package.json, tauri.conf.json, Cargo.toml, Cargo.lock.`);
console.log(`Next: update CHANGELOG.md, commit, then  git tag v${version}  and push the tag.`);
