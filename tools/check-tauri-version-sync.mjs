#!/usr/bin/env node
// CI guard. Tauri requires the npm package and the Rust crate of each plugin
// (and of the core) to be on the same major/minor; it only enforces this
// inside `tauri build`, which our regular CI doesn't run (typecheck + vitest +
// cargo test only). A mismatch therefore slips through to release time — as it
// did for v0.5.3, where the crate `tauri-plugin-updater` was bumped to 2.14.1
// but npm `@tauri-apps/plugin-updater` stayed at 2.10.1.
//
// This compares the RESOLVED versions (package-lock.json vs src-tauri/
// Cargo.lock), the same thing `tauri build` checks, and exits non-zero on any
// major/minor mismatch so it's caught on the PR instead.
//
// Pairs checked: @tauri-apps/plugin-<x> <-> tauri-plugin-<x>, and (when the npm
// package is present) @tauri-apps/api <-> tauri. Read-only; no deps.
//
// Usage: node tools/check-tauri-version-sync.mjs

import { readFileSync } from 'node:fs';

const majorMinor = (v) => v.split('.').slice(0, 2).join('.');

/** Resolved npm versions, keyed by package name, from package-lock.json (v3). */
function npmVersions() {
  const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
  const out = new Map();
  for (const [path, info] of Object.entries(lock.packages ?? {})) {
    // Keys look like "node_modules/@tauri-apps/plugin-updater"; take the last
    // "node_modules/" segment so a nested copy maps to the same package name.
    const idx = path.lastIndexOf('node_modules/');
    if (idx === -1) continue;
    const name = path.slice(idx + 'node_modules/'.length);
    if (name.startsWith('@tauri-apps/') && info?.version) out.set(name, info.version);
  }
  return out;
}

/** Resolved crate versions, keyed by crate name, from src-tauri/Cargo.lock. */
function crateVersions() {
  const lines = readFileSync('src-tauri/Cargo.lock', 'utf8').split(/\r?\n/);
  const out = new Map();
  let name = null;
  for (const line of lines) {
    const n = /^name = "([^"]+)"$/.exec(line);
    if (n) { name = n[1]; continue; }
    const v = /^version = "([^"]+)"$/.exec(line);
    if (v && name) { out.set(name, v[1]); name = null; }
  }
  return out;
}

function main() {
  const npm = npmVersions();
  const crates = crateVersions();

  // Build the pairs to check: every @tauri-apps/plugin-* present on either side,
  // plus the core (@tauri-apps/api <-> tauri).
  const pairs = [];
  for (const npmName of npm.keys()) {
    const m = /^@tauri-apps\/plugin-(.+)$/.exec(npmName);
    if (m) pairs.push({ npmName, crateName: `tauri-plugin-${m[1]}` });
  }
  if (npm.has('@tauri-apps/api')) pairs.push({ npmName: '@tauri-apps/api', crateName: 'tauri' });

  const mismatches = [];
  const checked = [];
  for (const { npmName, crateName } of pairs) {
    const npmVer = npm.get(npmName);
    const crateVer = crates.get(crateName);
    // Only compare when both sides are present; a plugin used on only one side
    // (e.g. a Rust-only or JS-only plugin) isn't a mismatch.
    if (!npmVer || !crateVer) continue;
    checked.push({ npmName, npmVer, crateName, crateVer });
    if (majorMinor(npmVer) !== majorMinor(crateVer)) {
      mismatches.push({ npmName, npmVer, crateName, crateVer });
    }
  }

  if (mismatches.length) {
    console.error('Tauri version mismatch — npm package and Rust crate must share a major/minor:\n');
    for (const m of mismatches) {
      console.error(`  ${m.crateName} (crate ${m.crateVer})  !=  ${m.npmName} (npm ${m.npmVer})`);
    }
    console.error('\nBump the lagging side so both resolve to the same major/minor, then commit the updated lockfile.');
    process.exit(1);
  }

  console.log(`Tauri versions in sync — ${checked.length} crate/npm pair(s) matched on major/minor:`);
  for (const c of checked) console.log(`  ${c.crateName} ${c.crateVer} == ${c.npmName} ${c.npmVer}`);
}

main();
