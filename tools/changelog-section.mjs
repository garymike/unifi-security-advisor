#!/usr/bin/env node
// Print the CHANGELOG.md section for a given version, used to populate the
// GitHub Release body (which the in-app updater surfaces as "What's changed").
//
// Usage: node tools/changelog-section.mjs <version>
//   e.g. node tools/changelog-section.mjs 0.4.1
// Falls back to a generic line if the section isn't found, so a release never
// fails just because the changelog wasn't updated.

import { readFileSync } from 'node:fs';

const version = (process.argv[2] ?? '').replace(/^v/, '').trim();
if (!version) {
  console.error('usage: changelog-section.mjs <version>');
  process.exit(2);
}

const fallback = `See the CHANGELOG for what changed in ${version}.`;

let md;
try {
  md = readFileSync('CHANGELOG.md', 'utf8');
} catch {
  console.log(fallback);
  process.exit(0);
}

const lines = md.split(/\r?\n/);
// Match the heading for this version, e.g. "## [0.4.1] - 2026-07-06". Parse the
// bracketed version with a static regex and compare as a string, so the
// user-supplied version is never interpolated into a RegExp (no injection).
const HEADING = /^##\s*\[([^\]]+)\]/;
const start = lines.findIndex((l) => {
  const m = HEADING.exec(l);
  return m !== null && m[1] === version;
});
if (start === -1) {
  console.log(fallback);
  process.exit(0);
}

// The section runs until the next "## [" heading (or end of file).
const rest = lines.slice(start + 1);
const nextIdx = rest.findIndex((l) => /^##\s*\[/.test(l));
const body = (nextIdx === -1 ? rest : rest.slice(0, nextIdx)).join('\n').trim();

console.log(body.length > 0 ? body : fallback);
