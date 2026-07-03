# Advisory Data Maintenance

How the known-advisory data (`src/audit/knownAdvisoriesData.ts`) stays current, and what to do when it drifts.

## What this data is

`KNOWN_ADVISORIES` powers the `findKnownAdvisories` finding: it flags devices whose model + firmware version fall within a published, security-relevant advisory (e.g. an actively-exploited UniFi OS RCE chain). It is **hand-maintained** — deliberately, so a human confirms affected models and version floors against the source bulletin before we act on them.

`ADVISORIES_LAST_REVIEWED` (same file) records when the data was last checked against upstream sources. It's surfaced in the audit report so readers can see recency. **Bump it whenever you review or update the data**, even if nothing changed.

## The freshness pipeline

Three moving parts keep this from silently going stale:

1. **`tools/check-advisory-drift.ts`** (`npm run check-advisory-drift`) — fetches the public [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) feed, filters to Ubiquiti, and reports any KEV CVE not already covered in `knownAdvisoriesData.ts`. Read-only; never edits the data. No API key needed.
2. **`.github/workflows/advisory-drift.yml`** — runs the drift check weekly (Mondays 09:00 UTC) and on demand (`workflow_dispatch`). When drift is found it opens (or updates) a single tracking GitHub issue titled *"Advisory data drift: uncovered Ubiquiti KEV CVEs"*; when drift is resolved it comments and closes that issue automatically.
3. **`tools/fetch-advisories.ts`** (`npm run fetch-advisories`) — drafts candidate `Advisory` entries from KEV + NVD for you to review and hand-merge. Also read-only. Set `NVD_API_KEY` to raise NVD's rate limit.

## When you get a drift issue

1. Run `npm run fetch-advisories` to draft entries for the newly-listed CVE(s).
2. Open the linked Ubiquiti bulletin. Confirm the **affected models** (only physical gateway/console/NVR/NAS models that report a `device.model` string) and the **fixed version** for each.
3. Add an `Advisory` to `KNOWN_ADVISORIES`. Record each model's floor as `vulnerableThrough`.
   - NVD reports the *exclusive first-fixed* version (`lessThan`). We record that same value as our **inclusive** `vulnerableThrough` — a deliberate one-version conservative overshoot (treats the fix version itself as still-vulnerable). This is intentional: for this feature we prefer false positives over false negatives.
4. Bump `ADVISORIES_LAST_REVIEWED` to today.
5. Run `npm test` and `npm run typecheck`. Open a PR. Merging it (with the covering CVE now in the data) makes the next drift run auto-close the tracking issue.

### If the CVE is out of scope

Some Ubiquiti KEV entries are not UniFi Network products (e.g. AirOS / airMAX / airFiber), so `findKnownAdvisories` could never match them — a device on that firmware doesn't report a UniFi `device.model`. Adding an `Advisory` for it would be dead weight. Instead, add the CVE ID to `ACKNOWLEDGED_CVES` in `tools/check-advisory-drift.ts` with a dated rationale. The drift check then treats it as covered and stops re-flagging it, so the tracking issue can close.

## Routine review (no drift)

Even without a drift alert, periodically run `npm run check-advisory-drift` and skim the Ubiquiti bulletins, then bump `ADVISORIES_LAST_REVIEWED`. The drift check only sees CISA KEV (the actively-exploited subset); high-severity advisories that never reach KEV still warrant manual attention.
