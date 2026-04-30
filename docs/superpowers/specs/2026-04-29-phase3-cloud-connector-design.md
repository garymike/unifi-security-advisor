# Phase 3: Site Manager API + Cloud Connector Design

**Date:** 2026-04-29
**Status:** Approved
**Scope:** TypeScript audit core only (`src/audit/collect.ts`). Complete cloud mode so it produces real audit data via the Cloud Connector proxy.

---

## Problem

The current cloud mode (`UNIFI_USE_CLOUD=true` / "Use Site Manager API" checkbox) fetches three top-level metadata endpoints from `api.ui.com/v1/` and stores them as `hosts`, `cloud_sites`, `cloud_devices`. Because none of these produce `site_*`-prefixed keys, `normalizeApi()` returns 0 sites and all finding modules are skipped — the report is empty.

---

## Solution

Use the **Cloud Connector** (available April 2026) to proxy Network Integration API requests through `api.ui.com`. This gives the same depth of data as local mode — firewall policies, WLANs, VPNs, segmentation — without needing a direct network path to the console.

Cloud Connector URL pattern:
```
https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration/v1/sites/{siteId}/{resource}
```

---

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Approach | Inline expansion of cloud branch (Option A) | Minimal diff, no refactoring of working local path |
| Scope | TypeScript only | Python is Phase 1 validation tooling; TypeScript is the going-forward path |
| Multi-console | Audit all consoles | Aggregates findings across the whole account |
| Site key format | `site_{consoleId}_{siteId}` | Avoids ID collisions across consoles |

---

## Data Flow

### Before (cloud mode produces nothing useful)
```
GET /v1/hosts         → result['hosts']
GET /v1/sites         → result['cloud_sites']
GET /v1/devices       → result['cloud_devices']
→ normalizeApi: 0 sites, 0 findings
```

### After (full audit via Cloud Connector)
```
GET /v1/hosts         → result['hosts'] + enumerate consoles
GET /v1/sites         → result['cloud_sites']   (kept for coverage meta)
GET /v1/devices       → result['cloud_devices']  (kept for coverage meta)

For each console (consoleId from hosts[].id, fallback hosts[].hostId):
  GET /v1/connector/consoles/{consoleId}/proxy/network/integration/v1/sites
    → enumerate sites

  For each site (siteId):
    result['site_{consoleId}_{siteId}'] = { _meta: siteObj }
    GET .../sites/{siteId}/devices
    GET .../sites/{siteId}/clients
    GET .../sites/{siteId}/wlans
    GET .../sites/{siteId}/firewall-policies
    GET .../sites/{siteId}/firewall-zones
    GET .../sites/{siteId}/port-forwards
    GET .../sites/{siteId}/vpn-configs
    GET .../sites/{siteId}/networks
    GET .../sites/{siteId}/traffic-routes

→ normalizeApi: N sites, full findings pipeline
```

---

## URL Construction

The Cloud Connector URL reuses the resource segment from the existing `SITE_SCOPED` path templates:

```typescript
// Existing SITE_SCOPED entry:
'/proxy/network/integration/v1/sites/{id}/firewall-policies'
//                                         ↓ .split('/').at(-1)
//                                    'firewall-policies'

// Built URL:
// https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration/v1/sites/{siteId}/firewall-policies
```

A small exported helper makes this testable:
```typescript
export function buildConnectorUrl(consoleId: string, siteId: string, resource: string): string {
  return `https://api.ui.com/v1/connector/consoles/${consoleId}/proxy/network/integration/v1/sites/${siteId}/${resource}`;
}
```

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Cloud Connector not enabled on console | 403/404 on sites endpoint → skip console, add to `_errors` with hint: "Cloud Connector not enabled — enable in UniFi OS → System → Cloud Access" |
| 0 consoles returned from `/v1/hosts` | Loop exits immediately; existing zero-sites warning in `cli.ts` fires |
| Per-site endpoint 403 | Added to `_errors`; other endpoints for that site continue |
| Per-site endpoint 404 | Logged as info (older firmware, endpoint not yet available); collection continues |
| Rate limiting | Existing 100ms sleep between requests is preserved across all consoles/sites |

---

## File Changes

### Modified: `src/audit/collect.ts`

- Export new `buildConnectorUrl(consoleId, siteId, resource)` helper (~5 lines)
- Extend cloud branch: after metadata fetch, enumerate consoles → sites → per-site data (~35 lines added)

### Modified: `src/audit/__tests__/collect.test.ts`

- Add 1 test for `buildConnectorUrl`
- Total test count: 74 (up from 73)

### No other changes

`normalize.ts`, all finding modules, `analyze.ts`, `cli.ts`, `AuditRunner.ts`, Tauri UI, DB layer, wizard — all unaffected.

---

## Out of Scope

- Python (`src/unifi_audit.py`) — TypeScript is the going-forward path
- Console selection UI — all consoles audited automatically
- Site Manager native-only path (no Cloud Connector) — not implemented; Cloud Connector delivers full audit depth
- Multi-site MSP aggregation beyond listing — Phase 3 scope is per-site findings, not cross-site rollup
