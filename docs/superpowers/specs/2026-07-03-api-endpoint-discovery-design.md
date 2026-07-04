# Runtime API Endpoint Discovery Design

**Date:** 2026-07-03
**Status:** Implemented
**Scope:** Make live-mode endpoint selection version-adaptive (Component D of the API-currency work). Extends `2026-07-03-api-currency-design.md`.

---

## Problem

The local ("hardware") Network Integration API version equals the installed Network app version, which varies per console (older hardware caps at older releases). Ubiquiti renames paths across versions (`wlans` → `wifi/broadcasts` in v10). Hardcoding one version's paths means older/newer consoles get 404s on the mismatched ones. (The Site Manager "website" API has no such skew — it serves one version — so this applies to local mode only.)

## Approach: discover, don't guess

Each console serves its own OpenAPI spec at `/proxy/network/api-docs/integration.json`, describing exactly what *that* version exposes. On connect (local mode), we fetch it and request only the paths it advertises.

- **`src/audit/endpoints.ts`** — single source of truth. Each endpoint *concept* (the internal key `normalize.ts`/findings read) carries an ordered list of known path aliases across versions (`candidates`) and a `liveByDefault` flag. `GLOBAL_ENDPOINTS` (info, sites) are version-stable.
- **`src/audit/discover.ts`** — `parseSpecPaths(spec)` extracts advertised paths; `resolveSiteEndpoints(advertised)` picks, per concept, the first candidate the console advertises (omitting concepts it doesn't expose, so we never 404).
- **`collect.ts`** — local mode fetches the spec, resolves endpoints, and collects those; if the spec is unreachable (older console without api-docs), it falls back to `defaultSiteEndpoints()` (today's behavior). Cloud mode uses the default set (no per-console spec) and now passes the full multi-segment suffix as the connector resource (fixing a truncation bug from the v10 path update).

## Properties

- **Version-adaptive:** v9 console advertising `wlans` → we call `wlans`; v10 advertising `wifi/broadcasts` → we call that; both resolve to the same internal `wlans` key, so findings are unaffected.
- **No 404s from renames:** we only request advertised paths.
- **Self-healing for additions:** a concept that's backup-only today (port forwards) is adopted automatically the moment a console starts advertising it — no code change.
- **Graceful fallback:** no spec → default set → identical to pre-discovery behavior.
- **Bounded by known aliases:** if Ubiquiti renames a concept to a name not in `candidates`, discovery can't find it — which is exactly what the schema-drift check (now concept-aware: flags a relied-on concept whose aliases have all vanished) catches, prompting a one-line `endpoints.ts` update.

Response-shape drift across versions is still handled by the finding modules' defensive field reads (see the api-currency spec), not by discovery.

## Testing

`discover.test.ts` (path parsing, alias resolution preference, omission, future-adoption); `apiDrift.test.ts` (concept drift, backup-only exemption, global-endpoint check); `collect.test.ts` (multi-segment connector URL). Full suite + `tsc` clean; live drift check clean against v10.3.58.
