# Advisory Data Freshness Design

**Date:** 2026-07-03
**Status:** Approved
**Scope:** Keep `src/audit/knownAdvisoriesData.ts` from silently going stale. Three parts: a scheduled CI drift-check that opens a GitHub issue when a new Ubiquiti CISA-KEV CVE isn't yet covered, a recorded "last reviewed" date surfaced in the report, and a maintainer runbook.

---

## Problem

`KNOWN_ADVISORIES` is hand-maintained. `tools/fetch-advisories.ts` drafts candidate entries from CISA KEV + NVD, but only when a maintainer remembers to run it. Two silent-staleness failure modes: (1) a newly actively-exploited Ubiquiti CVE lands in CISA KEV and nobody notices; (2) nothing on the shipped data tells you how current it is.

We deliberately keep humans in the loop for the *data itself* (the drift-check never edits `knownAdvisoriesData.ts`), consistent with the existing "draft, don't auto-apply" tool design. The automation's job is to **notice** drift, not fix it.

---

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Drift source | CISA KEV, filtered to `vendorProject == "Ubiquiti"` | KEV is the actively-exploited subset — exactly the "always-float-to-top" case. Needs no API key, so no CI secrets |
| Drift reaction | Open (or update) a GitHub issue; auto-close when resolved | Persistent and actionable; doesn't clutter the Actions tab with red |
| Data mutation | None — never edits `knownAdvisoriesData.ts` | Human-in-loop for advisory data; matches `fetch-advisories.ts` |
| Freshness signal | `ADVISORIES_LAST_REVIEWED` constant, surfaced in the report header | Cheap, visible recency indicator |
| Schedule | Weekly (Mondays 09:00 UTC) + `workflow_dispatch` | New KEV entries are infrequent; weekly is ample, dispatch allows on-demand |

---

## Component 1: `tools/check-advisory-drift.ts`

Maintainer/CI tool. Exports a pure, testable diff function and a guarded `main`:

```ts
/** KEV CVE IDs (as given) not present, case-insensitively, in any advisory.cves. */
export function findUncoveredKevCves(kevCveIds: string[], advisories: Advisory[]): string[]
```

`main()`:
1. Fetch the CISA KEV catalog, filter to Ubiquiti, collect CVE IDs.
2. `findUncoveredKevCves(kevIds, KNOWN_ADVISORIES)`.
3. Write a markdown report (`advisory-drift-report.md`, or `argv[2]`) — either "N uncovered CVEs" with a table (CVE, name, dateAdded, dueDate, bulletin URL) or an all-clear note.
4. Print a summary to stdout.
5. If `process.env.GITHUB_OUTPUT` is set, append `drift=true|false` and `count=N`.
6. Always exit 0 — the workflow decides what to do with the drift flag.

`main()` runs only when the file is executed directly (guarded via `import.meta.url === pathToFileURL(process.argv[1]).href`, matching `tools/anonymize-backup.ts`) so tests can import `findUncoveredKevCves` without triggering a network fetch.

`package.json`: add `"check-advisory-drift": "tsx tools/check-advisory-drift.ts"`.

## Component 2: `.github/workflows/advisory-drift.yml`

- `on`: `schedule` (weekly) + `workflow_dispatch`.
- `permissions`: `contents: read`, `issues: write`.
- Steps: checkout → setup-node 20 (npm cache) → `npm ci` → `npm run check-advisory-drift` → an issue-management step using `gh` (env `GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}`), keyed on a fixed issue title:
  - drift + no open issue → `gh issue create` with the report as body.
  - drift + open issue exists → `gh issue comment` with the current report.
  - no drift + open issue exists → comment "resolved" and `gh issue close`.
  - no drift + none → nothing.

No third-party actions (uses `gh`, preinstalled on the runner), so no action-pinning concerns.

## Component 3: freshness date

- `knownAdvisoriesData.ts`: add `export const ADVISORIES_LAST_REVIEWED = 'YYYY-MM-DD';`.
- `report.ts`: import it and add a header line `**Advisory data reviewed:** <date>`. No signature change (the two `cli.ts` callers are unaffected).

## Component 4: runbook

`docs/09-advisory-data-maintenance.md`: the pipeline overview, how the weekly drift-check works, how to respond to a drift issue (run `fetch-advisories`, review against the bulletin, hand-add the entry, bump `ADVISORIES_LAST_REVIEWED`), and the false-positives-over-false-negatives `vulnerableThrough` convention. Linked from `ROADMAP.md`.

---

## Testing

`src/audit/__tests__/advisoryDrift.test.ts` (imports the pure fn from the tool, like the existing `fixtureCgfBackupSafety` test imports from `tools/`):
- uncovered CVE detected when KEV has a CVE absent from the data;
- case-insensitive match (KEV `CVE-...` vs data lowercase);
- empty result when all KEV CVEs are covered;
- a CVE covered as part of a multi-CVE advisory `cves` array is considered covered.

Plus a small assertion that `ADVISORIES_LAST_REVIEWED` is an ISO `YYYY-MM-DD` string. The network fetch itself is not unit-tested (same boundary as `fetch-advisories.ts`).

## Out of scope

- Auto-editing `knownAdvisoriesData.ts`.
- Broad NVD scanning beyond KEV (KEV is the actionable signal; NVD stays a manual drafting aid via `fetch-advisories.ts`).
- Failing the scheduled job on drift (issue-based alerting was chosen instead).
