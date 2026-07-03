# UniFi API Currency & Drift-Resilience Design

**Date:** 2026-07-03
**Status:** Approved (scope A+B+C; C is OpenAPI-spec-driven, pending live v10 validation)
**Scope:** Make the audit resilient to UniFi API/schema changes and keep the endpoint set current. Three parts: (A) a runtime version self-check, (B) a maintainer schema-drift CI check, (C) updating the stale endpoint paths to the current v10 API.

---

## Research findings (2026-07-03)

- The app's **auth and base URLs are current**: Network Integration API (`/proxy/network/integration/v1`) local, Site Manager (`api.ui.com/v1`) cloud, `X-API-KEY`. No drift. (Sources: help.ui.com "Getting Started with the Official UniFi API", developer.ui.com, artofwifi.net/unifi-api.)
- The console exposes two currency signals the app does not use yet:
  - **`GET /v1/info`** → `{ applicationVersion: string }` (the running Network app version).
  - An **OpenAPI 3.1 spec** at `/proxy/network/api-docs/integration.json`, specific to the running version. A daily community mirror exists at `github.com/opastorello/unifi-api-docs` (`network/<version>/openapi.json`).
- **The API has already drifted.** Current Network app is **v10.3.58**; the app targets ~v9.3.x names. Diff of the app's 9 site-scoped endpoints vs the v10.3.58 spec:

  | App path segment | v10.3.58 | 
  |---|---|
  | `devices`, `clients`, `networks` (+ global `info`, `sites`) | unchanged |
  | `wlans` | `wifi/broadcasts` |
  | `firewall-policies` | `firewall/policies` |
  | `firewall-zones` | `firewall/zones` |
  | `vpn-configs` | `vpn/servers` (+ `vpn/site-to-site-tunnels`) |
  | `traffic-routes` | `traffic-matching-lists` |
  | `port-forwards` | not present in the integration API |

  The 6 renamed/absent endpoints were **already 404ing** (v9.3.x never had them either), so the app degrades gracefully to backup mode via `apiGaps` — a schema change doesn't crash it, but it silently misses live data that v10 now exposes.

---

## Component A — Runtime version self-check

**Goal:** the audit knows and reports which controller version it ran against, and whether that's within the range the app was built/tested for.

- Add `src/audit/apiVersion.ts`:
  - `TESTED_MIN = '9.0.0'` (integration API availability floor) and `TESTED_MAX = '10.3.58'` (latest verified against the published spec), plus a short comment pointing at the drift check (B) that keeps `TESTED_MAX` honest.
  - `parseApplicationVersion(info: unknown): string | null` — pulls `applicationVersion` from the `/v1/info` response (already collected as `result['info']`).
  - `assessVersion(version: string | null): { version: string | null; status: 'ok' | 'newer-than-tested' | 'older-than-min' | 'unknown'; message: string }` using the existing `compareVersions()`.
- Surface it:
  - In the report header (`report.ts`): `**Controller Network version:** <v> (tested against 9.0.0–10.3.58)` + a one-line warning when `newer-than-tested` / `older-than-min`.
  - As an informational meta-finding (id `API-VERSION`, section "API coverage") when status isn't `ok`, so it shows up in the findings backlog. `unknown`/`ok` produce no finding.
- Backup mode has no live API, so this is live-mode only (no `info` → no finding).

## Component B — Schema-drift CI check

**Goal:** find out when Ubiquiti changes the API *before* users hit 404s. Mirrors the advisory-drift pattern merged in PR #12.

- Add `tools/check-api-drift.ts`:
  - A declared endpoint inventory (the single source of truth the app collects), exported for reuse: `EXPECTED_ENDPOINTS` = the site-scoped + global path templates the app calls, as `/v1/...` forms (normalized to compare against a spec's `paths`).
  - Fetches the latest Network OpenAPI from the community mirror (highest `network/v*` folder via the GitHub API), extracts `paths`, and reports:
    - **breaking drift**: any `EXPECTED_ENDPOINTS` entry not present in the current spec (the app will 404);
    - the latest spec version seen, and whether it exceeds `TESTED_MAX`.
  - Pure, testable core `findMissingEndpoints(expected: string[], specPaths: string[]): string[]`. Network fetch is guarded behind the direct-execution check so tests can import the pure fn.
  - Writes a markdown report and (in CI) `drift`/`count` to `GITHUB_OUTPUT`.
- Add `.github/workflows/api-drift.yml`: weekly + `workflow_dispatch`, `issues: write`, opens/auto-closes a single tracking issue (same `gh` pattern as `advisory-drift.yml`).
- `package.json`: `"check-api-drift": "tsx tools/check-api-drift.ts"`.

## Component C — Update endpoints to v10 (spec-driven, unvalidated live)

**Goal:** request the correct current endpoints so live mode actually collects firewall/wifi/vpn/network data.

- In `collect.ts`, update the **URL path** of each `SITE_SCOPED` entry to its v10 name while keeping the **internal result key stable** (`wlans`, `firewall_policies`, …). Because `normalize.ts` and the finding modules key off those internal names, and `extractList()` already tolerates `{data:[]}`/array/`{items:[]}`, this is contained:
  - `wlans` → `wifi/broadcasts`
  - `firewall_policies` → `firewall/policies`
  - `firewall_zones` → `firewall/zones`
  - `vpn_configs` → `vpn/servers`
  - `traffic_routes` → `traffic-matching-lists`
  - `port_forwards` → **drop from live collection** (not in the integration API); it stays a backup-only source. `normalize.ts` keeps the field (empty in live mode) so nothing downstream breaks.
- Keep the same graceful 404 handling; no behavior regression is possible since these paths returned nothing before.
- Provide a live-shape fixture derived from the **OpenAPI response examples** (`samples/fixture-local-api-v10.json`) and a regression test that runs it through `normalizeApi` → `analyze`, so the new shapes have spec-level coverage.
- **Explicitly marked unvalidated against live hardware.** A/B are the safety net: the runtime check reports the real version, and the drift check flags any future rename. A `docs/` note records that C's response mapping is derived from the v10.3.58 OpenAPI and should be confirmed against a live controller.

---

## Testing

- A: `apiVersion.test.ts` — `parseApplicationVersion` (valid/missing/nested), `assessVersion` (ok / newer / older / unknown boundaries around 9.0.0 and 10.3.58).
- B: `apiDrift.test.ts` — `findMissingEndpoints` (all present → empty; a renamed path flagged; template `{id}`↔`{siteId}` normalization).
- C: an end-to-end test over `samples/fixture-local-api-v10.json` (spec-example shapes) through `normalizeApi` → `analyze`.
- Full suite + `tsc` clean; both CI jobs green.

## Sequencing

Two PRs: **PR 1 = A + B** (safe, no live validation needed, immediate resilience value); **PR 2 = C** (spec-driven endpoint update, leaning on A+B as the safety net). Keeps review focused and lands the drift-resilience first.

## Out of scope

- Consuming brand-new v10 endpoints the app has no finding for yet (dns/policies, acl-rules, switching/*, radius/profiles, device-tags) — additive, no current consumer.
- Auto-updating endpoint paths from the spec at runtime (we alert; a human updates — same human-in-loop stance as advisory data).
- Site Manager (cloud) endpoint currency beyond what A/B cover — the cloud `v1/hosts|sites|devices` set is unchanged.
