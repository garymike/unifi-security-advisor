// Fails a pull request that ADDS a known-vulnerable package version.
//
//   node tools/audit-new-advisories.mjs <base> <head> [project]
//
// Runs `npm audit --json` on the PR's base and on its merge result, and
// compares them one row per advisory and affected package:
//
//   only in the head  -> error, and the run fails: this PR adds it
//   in both           -> warning: it is already on the base branch
//   only in the base  -> notice: this PR's tree no longer reports it
//
// The PR contributes one input: its package-lock.json. Each audit runs in a
// throwaway directory holding the BASE's package.json and .npmrc beside one
// side's lockfile, so the two audits differ in exactly that one file.
//
// Why the base's .npmrc and not the PR's. Measured against this project's own
// lockfile, which reports 8 packages before each test:
//   - a project .npmrc of `omit=dev` empties the report, 0 packages, exit 0;
//   - a project .npmrc of `registry=<host>` sends the audit to that host, and
//     a dead one returns exit 1 with no report at all, which is why audit()
//     below checks the body and not just the exit code.
// The flags below override both, `--include` the first and `--registry` the
// second, so the file and the command line have to agree before a scope can be
// dropped or a lookup redirected. `--include` takes one scope per flag, and
// that detail matters: the comma-joined `--include=dev,optional,peer` is
// rejected as an invalid config, with a warning on stderr and no effect, so a
// script relying on it alone would quietly audit whatever .npmrc chose. Both
// defences are here because either one can fail like that.
//
// npm's report is keyed by package, not by advisory, so one advisory shows up
// as many entries. The picomatch advisory counts 8 packages here:
//   picomatch, fdir, tinyglobby, vite, vitest, @sveltejs/kit,
//   @sveltejs/adapter-static and @sveltejs/vite-plugin-svelte
// Exactly one of them, picomatch itself, carries an OBJECT in `via` -- the
// advisory. The other seven carry only STRINGS, each naming the dependency it
// inherits the problem through, and sometimes more than one: `vite` carries
// ['picomatch', 'tinyglobby']. rows() reads only the objects, so it reports
// 1 row, not 8. npm also omits the installed version of the affected package,
// so a row is keyed by advisory and package name, with the affected range
// shown as detail.
//
// The schema, that package count and the exit-code invariant audit() relies on
// were each confirmed on npm 10.9.11, 11.21.3 and 12.2.2 against this
// lockfile, so the reader does not depend on whichever npm a node version
// happens to ship.
//
// .github/workflows/dependency-audit.yml says why it compares rather than
// failing on every advisory, and what a pull_request check cannot stop.
//
// Plain JavaScript with node: imports only, as tools/check-tauri-version-sync.mjs
// is, so CI runs it with no install and no tsx. tsconfig.json's include is
// ["src", "*"], which does not reach tools/, so a .ts file here would go
// unchecked; the .ts tools in this directory are run through tsx instead.

import { spawnSync } from 'node:child_process'
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { isAbsolute, join } from 'node:path'

const REGISTRY = 'https://registry.npmjs.org/'
const LOCKFILE = 'package-lock.json'

// The npm project's location inside each checkout, for messages. main() sets
// it from the optional third argument; '.' means the checkout root.
let PROJECT_LABEL = '.'

// The files npm reads at a project root that can change what an audit reports
// or where it asks. Only the base's copies are ever used.
const BASE_CONFIG = ['package.json', '.npmrc']

// Registry text is displayed, never trusted. JSON.stringify turns every
// control character into a visible escape, so an advisory field can neither
// start a new line, which is how a workflow command is injected, nor move the
// cursor.
function clean(value) {
  return JSON.stringify(String(value ?? '')).slice(1, -1)
}

// Workflow-command encoding, as actions/toolkit's escapeData and
// escapeProperty do it.
const data = s => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
const property = s => data(s).replace(/:/g, '%3A').replace(/,/g, '%2C')

function annotate(level, title, message) {
  console.log(`::${level} title=${property(title)}::${data(message)}`)
}

// A directory holding the base's configuration and one side's lockfile. A
// lockfile missing on either side stops the run with exit 3 rather than
// auditing an empty tree, because there is then nothing to compare.
function auditDir(root, side, baseCheckout, lockfileFrom) {
  const dir = join(root, side)
  mkdirSync(dir)
  for (const file of BASE_CONFIG) {
    if (existsSync(join(baseCheckout, file))) copyFileSync(join(baseCheckout, file), join(dir, file))
  }
  const lockfile = join(lockfileFrom, LOCKFILE)
  if (!existsSync(lockfile)) {
    throw new Error(`the ${side} has no ${LOCKFILE} in ${PROJECT_LABEL}, so there is nothing to compare`)
  }
  copyFileSync(lockfile, join(dir, LOCKFILE))
  return dir
}

function asReport(text) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  if (parsed.auditReportVersion !== 2) return null
  const { vulnerabilities, metadata } = parsed
  if (typeof vulnerabilities !== 'object' || vulnerabilities === null || Array.isArray(vulnerabilities)) return null
  if (typeof metadata !== 'object' || metadata === null) return null
  if (typeof metadata.vulnerabilities?.total !== 'number') return null
  return parsed
}

// An audit that did not happen must never read as a clean one. With
// --audit-level=info, npm exits 0 when its report counts nothing and 1 when it
// counts something, so any other exit, a body that is not a report, or a
// report that disagrees with its own exit code is a failed audit, and the run
// fails rather than passes. The registry's audit endpoint is a network call,
// so it gets one retry.
function audit(dir, side) {
  const attempts = []
  for (let attempt = 1; attempt <= 2; attempt++) {
    const run = spawnSync('npm', [
      'audit', '--json',
      // Audit the lockfile as written, with no install and no node_modules.
      '--package-lock-only',
      // Every scope, one flag each: see the header on the comma-joined form.
      // Reclassifying a package as a devDependency must not mute its advisory,
      // and the absolute high-or-critical gate in ci.yml is the one that
      // scopes itself to what ships.
      '--include=dev', '--include=optional', '--include=peer',
      // Count everything, so "exit 1" and "the report lists something" mean
      // the same thing and can be checked against each other.
      '--audit-level=info',
      `--registry=${REGISTRY}`,
    ], {
      cwd: dir,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      // npm is npm.cmd on Windows, which only a shell can start.
      shell: process.platform === 'win32',
    })
    const report = asReport(run.stdout ?? '')
    const counted = report ? report.metadata.vulnerabilities.total : -1
    if (report && ((run.status === 0 && counted === 0) || (run.status === 1 && counted > 0))) return report
    const said = run.error?.message || run.stderr || run.stdout || ''
    attempts.push(`attempt ${attempt}: exit ${run.status ?? run.signal ?? 'none'}, counted ${counted}, ${clean(said.slice(0, 400))}`)
  }
  throw new Error(`npm audit of the ${side}'s lockfile returned no usable report. ${attempts.join(' | ')}`)
}

// One row per advisory and affected package. An entry's `via` holds advisory
// objects for the package the advisory is against, and plain strings naming
// another package for everything downstream of it; only the objects are
// advisories.
function rows(report) {
  const out = new Map()
  for (const [name, entry] of Object.entries(report.vulnerabilities)) {
    for (const via of entry?.via ?? []) {
      if (typeof via !== 'object' || via === null) continue
      // npm gives no GHSA field; the id is in the advisory URL. Fall back to
      // npm's own numeric id, never to a shared placeholder: two different
      // advisories must not merge into one row, or a new one would read as
      // already on the base.
      const ghsa = /GHSA(-[23456789cfghjmpqrvwx]{4}){3}/i.exec(String(via.url ?? ''))
      const id = ghsa ? ghsa[0] : `npm advisory ${clean(via.source ?? 'unknown')}`
      const pkg = String(via.name ?? name)
      const key = `${id} ${pkg}`
      out.set(key, {
        key,
        id,
        pkg,
        severity: via.severity ?? entry?.severity ?? 'unknown',
        title: via.title ?? '',
        range: via.range ?? '',
        url: via.url ?? '',
        // What else in the tree this advisory is reported through, which is
        // the difference between one advisory and npm's package count.
        effects: Array.isArray(entry?.effects) ? entry.effects.length : 0,
        paths: Array.isArray(entry?.nodes) ? entry.nodes.length : 0,
      })
    }
  }
  return out
}

const label = row => `${clean(row.pkg)}@${clean(row.range || '*')}`

function describe(row) {
  const through = row.effects ? `, reported through ${row.effects} dependent package${row.effects === 1 ? '' : 's'}` : ''
  return `${clean(row.id)} (${clean(row.severity)}) ${label(row)}${through}: ${clean(row.title)}. ${clean(row.url)}`
}

function summarise(added, kept, gone) {
  const file = process.env.GITHUB_STEP_SUMMARY
  if (!file) return
  const cell = s => s.replace(/\|/g, '\\|')
  const line = (change, r) =>
    `| ${change} | ${cell(clean(r.id))} | ${cell(clean(r.severity))} | ${cell(label(r))} | ${cell(clean(r.title))} |`
  const table = [
    ...added.map(r => line('**added by this PR**', r)),
    ...kept.map(r => line('already on the base branch', r)),
    ...gone.map(r => line('no longer reported', r)),
  ]
  const head = `## Dependency audit\n\n${added.length} added, ${kept.length} already on the base branch, ${gone.length} no longer reported. ` +
    `Both audits used the base branch's package.json and .npmrc; the only input taken from this PR is its ${LOCKFILE}.\n`
  const body = table.length
    ? `\n| change | advisory | severity | package | title |\n|---|---|---|---|---|\n${table.join('\n')}\n`
    : '\n`npm audit` reports nothing on either side.\n'
  appendFileSync(file, head + body)
}

// Exit codes:
//   0  nothing added
//   1  this PR adds an advisory
//   2  usage
//   3  an audit did not run
function main() {
  const [baseCheckout, headCheckout, project = '.'] = process.argv.slice(2)
  if (!baseCheckout || !headCheckout) {
    console.error('usage: node tools/audit-new-advisories.mjs <base-checkout> <head-checkout> [project]')
    return 2
  }
  // The project path comes from the workflow, not from the PR's content, but a
  // typo that walked out of the checkout would audit something unrelated and
  // still look like a clean comparison.
  if (isAbsolute(project) || project.split(/[\\/]/).includes('..')) {
    console.error(`the project path ${JSON.stringify(project)} must stay inside the checkout`)
    return 2
  }
  PROJECT_LABEL = project

  const root = mkdtempSync(join(tmpdir(), 'dependency-audit-'))
  try {
    // The base supplies the configuration for both sides; only the lockfile
    // differs, and on the head side it is the PR's.
    const baseProject = join(baseCheckout, project)
    const headProject = join(headCheckout, project)
    const base = rows(audit(auditDir(root, 'base', baseProject, baseProject), 'base'))
    const head = rows(audit(auditDir(root, 'head', baseProject, headProject), 'head'))
    const added = [...head.values()].filter(r => !base.has(r.key))
    const kept = [...head.values()].filter(r => base.has(r.key))
    const gone = [...base.values()].filter(r => !head.has(r.key))

    for (const r of added) annotate('error', `Advisory added by this PR: ${label(r)}`, describe(r))
    for (const r of kept) annotate('warning', `Advisory already on the base branch: ${label(r)}`, describe(r))
    for (const r of gone) annotate('notice', `Advisory no longer reported: ${label(r)}`, describe(r))
    console.log(`${added.length} added, ${kept.length} already on the base branch, ${gone.length} no longer reported ` +
      `(both audited with the base's configuration; only the lockfile comes from this PR)`)
    summarise(added, kept, gone)
    return added.length > 0 ? 1 : 0
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

try {
  process.exit(main())
} catch (error) {
  // Fail as an annotation the PR shows, not only as a stack trace in the log,
  // and with its own exit code, so "the audit did not run" can never be read
  // as "this PR adds an advisory", or as a pass.
  const message = error instanceof Error ? error.message : String(error)
  annotate('error', 'npm audit did not run', message)
  const file = process.env.GITHUB_STEP_SUMMARY
  if (file) appendFileSync(file, `## Dependency audit\n\n**npm audit did not run**, so nothing was compared. ${message}\n`)
  process.exit(3)
}
