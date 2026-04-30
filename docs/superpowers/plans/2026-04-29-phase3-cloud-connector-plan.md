# Phase 3: Cloud Connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the cloud audit mode so it produces real findings by using the Cloud Connector to proxy Network Integration API requests through `api.ui.com`.

**Architecture:** Two focused changes to `src/audit/collect.ts`: add a `buildConnectorUrl()` helper, then extend the cloud branch of `collectAll()` to enumerate consoles → sites → per-site data. All downstream code (`normalize.ts`, finding modules, Tauri UI) is untouched.

**Tech Stack:** TypeScript, Vitest. No new dependencies.

---

## File Map

| File | Change |
|------|--------|
| `src/audit/collect.ts` | Add `buildConnectorUrl()` export; extend cloud branch in `collectAll()` |
| `src/audit/__tests__/collect.test.ts` | Add tests for `buildConnectorUrl()` and the resource-segment extraction pattern |

---

## Task 1: `buildConnectorUrl` helper + tests

**Files:**
- Modify: `src/audit/collect.ts`
- Modify: `src/audit/__tests__/collect.test.ts`

- [ ] **Step 1: Write the failing tests**

Open `src/audit/__tests__/collect.test.ts` and append:

```typescript
import { buildConnectorUrl } from '../collect.js';

describe('buildConnectorUrl', () => {
  it('builds the correct Cloud Connector URL', () => {
    expect(buildConnectorUrl('abc123', 'default', 'devices'))
      .toBe('https://api.ui.com/v1/connector/consoles/abc123/proxy/network/integration/v1/sites/default/devices');
  });

  it('handles hyphenated resource names', () => {
    expect(buildConnectorUrl('abc123', 'default', 'firewall-policies'))
      .toBe('https://api.ui.com/v1/connector/consoles/abc123/proxy/network/integration/v1/sites/default/firewall-policies');
  });

  it('resource segment extracted from SITE_SCOPED path template', () => {
    // Verify the extraction pattern used in collectAll works for all SITE_SCOPED entries
    const pathTpl = '/proxy/network/integration/v1/sites/{id}/vpn-configs';
    expect(pathTpl.split('/').at(-1)).toBe('vpn-configs');
  });
});
```

- [ ] **Step 2: Run tests — expect failures**

```bash
npm test -- --reporter=verbose src/audit/__tests__/collect.test.ts
```

Expected output: `Cannot find module` or `buildConnectorUrl is not exported`

- [ ] **Step 3: Add `buildConnectorUrl` to `src/audit/collect.ts`**

Add this function after the `CLOUD_ENDPOINTS` constant (before `extractSites`):

```typescript
export function buildConnectorUrl(consoleId: string, siteId: string, resource: string): string {
  return `https://api.ui.com/v1/connector/consoles/${consoleId}/proxy/network/integration/v1/sites/${siteId}/${resource}`;
}
```

- [ ] **Step 4: Run tests — expect all pass**

```bash
npm test -- --reporter=verbose src/audit/__tests__/collect.test.ts
```

Expected output: 6 passed (3 existing + 3 new)

- [ ] **Step 5: Run full suite to confirm no regressions**

```bash
npm test
```

Expected: 76 passed (73 existing + 3 new)

- [ ] **Step 6: Commit**

```bash
git add src/audit/collect.ts src/audit/__tests__/collect.test.ts
git commit -m "feat: add buildConnectorUrl helper for Cloud Connector URLs"
```

---

## Task 2: Cloud Connector enumeration in `collectAll`

**Files:**
- Modify: `src/audit/collect.ts` (cloud branch only)

- [ ] **Step 1: Replace the cloud branch in `collectAll`**

In `src/audit/collect.ts`, find the `if (client.config.useCloud)` block (lines 47–54). Replace it entirely with:

```typescript
  if (client.config.useCloud) {
    // Step 1: Fetch metadata endpoints (hosts, sites list, devices list)
    for (const [name, url] of CLOUD_ENDPOINTS) {
      log(`GET ${url}`);
      const { status, data } = await client.get(url);
      result._endpointsProbed.push({ name, path: url, status });
      if (status === 200) result[name] = data;
      else if (status === 403) result._errors.push({ endpoint: name, status, hint: 'insufficient scope' });
    }

    // Step 2: Enumerate consoles and collect per-site data via Cloud Connector
    const hosts = extractSites(result['hosts']);
    for (const host of hosts) {
      const consoleId = String(host['id'] ?? host['hostId'] ?? '');
      if (!consoleId) continue;

      // Enumerate sites for this console via Cloud Connector
      const sitesUrl = `https://api.ui.com/v1/connector/consoles/${consoleId}/proxy/network/integration/v1/sites`;
      log(`GET ${sitesUrl}`);
      const { status: sitesStatus, data: sitesData } = await client.get(sitesUrl);
      result._endpointsProbed.push({ name: `sites@${consoleId}`, path: sitesUrl, status: sitesStatus });

      if (sitesStatus !== 200) {
        if (sitesStatus === 403 || sitesStatus === 404) {
          result._errors.push({
            endpoint: `sites@${consoleId}`,
            status: sitesStatus,
            hint: 'Cloud Connector not enabled — enable in UniFi OS → System → Cloud Access',
          });
        }
        continue;
      }

      const siteList = extractSites(sitesData);
      result._siteCount += siteList.length;

      for (const site of siteList) {
        const siteId = String(site['id'] ?? site['_id'] ?? site['name'] ?? '');
        if (!siteId) continue;
        const siteKey = `site_${consoleId}_${siteId}`;
        result[siteKey] = { _meta: { ...site, _consoleId: consoleId } };

        for (const [name, pathTpl] of SITE_SCOPED) {
          const resource = pathTpl.split('/').at(-1)!;
          const url = buildConnectorUrl(consoleId, siteId, resource);
          log(`GET ${url}`);
          const { status, data } = await client.get(url);
          result._endpointsProbed.push({ name: `${name}@${consoleId}_${siteId}`, path: url, status });
          if (status === 200) (result[siteKey] as Record<string, unknown>)[name] = data;
          else if (status === 403) result._errors.push({ endpoint: `${name}@${consoleId}_${siteId}`, status });
          await new Promise(r => setTimeout(r, 100));
        }
      }
    }
  } else {
```

**Important:** The `} else {` at the end of the replacement is the start of the existing local branch. Do not modify anything from `} else {` onwards.

- [ ] **Step 2: Run the full test suite**

```bash
npm test
```

Expected: 76 passed (same count as after Task 1 — no new tests for the enumeration loop; integration testing against the real controller covers it)

- [ ] **Step 3: Verify TypeScript compiles cleanly**

```bash
npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 4: Smoke-test URL construction via npm test**

The three `buildConnectorUrl` tests added in Task 1 already verify the URL pattern for `devices`, `firewall-policies`, and `vpn-configs`. Run them to confirm the helper works correctly with the resource extraction pattern:

```bash
npm test -- --reporter=verbose src/audit/__tests__/collect.test.ts
```

Expected: 6 passed, including `resource segment extracted from SITE_SCOPED path template`

- [ ] **Step 5: Commit**

```bash
git add src/audit/collect.ts
git commit -m "feat: complete cloud mode via Cloud Connector — enumerate consoles, sites, per-site data"
```

---

## Task 3: Validate against real controller

This task runs the actual audit against your UniFi controller using `UNIFI_USE_CLOUD=true` and a real Site Manager API key.

**Prerequisites:**
- A Site Manager API key (generated at `unifi.ui.com → API Keys` or `Settings → API Keys`)
- Cloud Connector enabled on the console (`UniFi OS → System → Cloud Access → Cloud Connector`)
- Node.js available in terminal

- [ ] **Step 1: Build the TypeScript CLI**

```bash
npm run build:audit
```

Expected: compiles without errors, `dist/` directory updated

- [ ] **Step 2: Run the audit in cloud mode**

```bash
UNIFI_API_KEY='<your-key>' UNIFI_USE_CLOUD=true node dist/cli.js
```

Expected output (abbreviated):
```
============================================================
UniFi Security Advisor - starting audit
Mode: cloud (Site Manager)
Profile: home_office
============================================================
GET https://api.ui.com/v1/hosts
GET https://api.ui.com/v1/sites
GET https://api.ui.com/v1/devices
GET https://api.ui.com/v1/connector/consoles/.../proxy/network/integration/v1/sites
GET https://api.ui.com/v1/connector/consoles/.../proxy/network/integration/v1/sites/default/devices
...
Wrote findings.json (N findings)
Wrote report.md
```

- [ ] **Step 3: Verify findings were generated**

```bash
node -e "const d=JSON.parse(require('fs').readFileSync('audit_output/findings.json','utf8')); console.log('findings:', d.length, '| severities:', [...new Set(d.map(f=>f.severity))].join(', '))"
```

Expected: at least one finding, severities include `high` or `medium` (not all `info`)

- [ ] **Step 4: Check the raw sanitized data for site coverage**

```bash
node -e "const d=JSON.parse(require('fs').readFileSync('audit_output/raw_sanitized.json','utf8')); const siteKeys=Object.keys(d).filter(k=>k.startsWith('site_')); console.log('site keys:', siteKeys)"
```

Expected: at least one `site_*` key (e.g., `site_abc123_default`)

- [ ] **Step 5: Review `audit_output/report.md`**

Open and scan for:
- At least one finding with a `current_state` that references real data (e.g. actual SSID name, real device model)
- No `[object Object]` or serialisation artifacts
- Sanitised PSK shown as `{ length: N, fingerprint: "..." }` not raw value

- [ ] **Step 6: Update ROADMAP**

In `ROADMAP.md`, change Phase 3 status from `scaffolded, needs validation` to `complete`. Add a note about Cloud Connector requirement.

- [ ] **Step 7: Commit ROADMAP update**

```bash
git add ROADMAP.md
git commit -m "docs: mark Phase 3 complete after real-controller validation"
```
