# Phase 2a: TypeScript Audit Core + CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the Python audit core in TypeScript, producing a working CLI tool (`node dist/cli.js`) that outputs the same sanitized markdown + JSON report as the Python script.

**Architecture:** Pure TypeScript Node.js package. No Tauri yet — that is Phase 2b. The audit core (`src/audit/`) is framework-agnostic and will be imported by the Tauri app in Phase 2b. CLI entry point is `src/cli.ts`. Tests use Vitest.

**Tech Stack:** Node.js 20+, TypeScript 5, Vitest, `node-fetch` (or Node 18+ native fetch)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `package.json` | Create | Dependencies, scripts |
| `tsconfig.json` | Create | TypeScript config |
| `src/audit/types.ts` | Create | `Finding`, `NormalizedSite` interfaces |
| `src/audit/constants.ts` | Create | `ALWAYS_TOP_PREDICATES`, `PROFILE_OVERRIDES`, `EOL_MODELS`, `SEVERITY_ORDER` |
| `src/audit/sanitize.ts` | Create | `sanitize()`, `fingerprint()` |
| `src/audit/normalize.ts` | Create | `normalizeApi()`, `extractList()` |
| `src/audit/client.ts` | Create | `UniFiClient` — fetch-based, read-only |
| `src/audit/findings/segmentation.ts` | Create | Flat-network detection |
| `src/audit/findings/wifi.ts` | Create | WPA version, PSK strength |
| `src/audit/findings/firewall.ts` | Create | Port-forward audit |
| `src/audit/findings/remoteAccess.ts` | Create | VPN protocol audit |
| `src/audit/findings/devices.ts` | Create | SSH enablement |
| `src/audit/findings/wirelessTuning.ts` | Create | TX power, 2.4 GHz, rogueAP, PMF |
| `src/audit/findings/firewallThreats.ts` | Create | Geo-IP, content filtering |
| `src/audit/findings/firmware.ts` | Create | Auto-update, EOL, stale versions |
| `src/audit/findings/logging.ts` | Create | Syslog forwarding, DPI privacy |
| `src/audit/findings/backup.ts` | Create | Auto-backup, destination, Schrödinger |
| `src/audit/findings/apiCoverage.ts` | Create | Meta-finding on missing endpoints |
| `src/audit/analyze.ts` | Create | `analyze()` pipeline, float-top, profile overrides |
| `src/cli.ts` | Create | CLI entry point — reads env vars, runs audit, writes files |
| `src/audit/__tests__/` | Create | Vitest test files |

---

## Task 1: Project scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `src/audit/__tests__/.gitkeep`

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "unifi-security-advisor",
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "test:watch": "vitest",
    "cli": "node --loader ts-node/esm src/cli.ts"
  },
  "dependencies": {},
  "devDependencies": {
    "typescript": "^5.4.0",
    "vitest": "^1.6.0",
    "ts-node": "^10.9.0",
    "@types/node": "^20.0.0"
  }
}
```

- [ ] **Step 2: Create `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "declaration": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

- [ ] **Step 3: Install dependencies**

```bash
npm install
```

- [ ] **Step 4: Verify Vitest works**

Create `src/audit/__tests__/scaffold.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';

describe('scaffold', () => {
  it('is alive', () => {
    expect(1 + 1).toBe(2);
  });
});
```

Run:
```bash
npm test
```

Expected: `1 passed`

- [ ] **Step 5: Commit**

```bash
git add package.json tsconfig.json src/audit/__tests__/scaffold.test.ts
git commit -m "feat: typescript project scaffold with vitest"
```

---

## Task 2: Types and constants

**Files:**
- Create: `src/audit/types.ts`
- Create: `src/audit/constants.ts`
- Modify: `src/audit/__tests__/scaffold.test.ts` → replace with `src/audit/__tests__/types.test.ts`

- [ ] **Step 1: Write the test**

Create `src/audit/__tests__/types.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import type { Finding, NormalizedSite } from '../types.js';

describe('Finding type', () => {
  it('accepts required fields', () => {
    const f: Finding = {
      id: 'TEST-001', section: 'Test', severity: 'high',
      status: 'gap', title: 'A finding', currentState: 'Bad',
      recommendation: null, intentQuestion: null,
      evidence: {}, mapsTo: {}, effort: 'quick', impact: 'high',
    };
    expect(f.id).toBe('TEST-001');
    expect(f.recommendation).toBeNull();
  });
});
```

- [ ] **Step 2: Run — expect compile error (types.ts missing)**

```bash
npm test
```

Expected: TypeScript error about missing module

- [ ] **Step 3: Create `src/audit/types.ts`**

```typescript
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Status = 'ok' | 'gap' | 'recommendation' | 'unknown';
export type Effort = 'quick' | 'medium' | 'project';
export type Impact = 'low' | 'medium' | 'high';

export interface TierOverrides {
  currentState?: string;
  recommendation?: string;
  intentQuestion?: string;
}

export interface Finding {
  id: string;
  section: string;
  severity: Severity;
  status: Status;
  title: string;
  currentState: string;
  recommendation: string | null;
  intentQuestion: string | null;
  evidence: Record<string, unknown>;
  mapsTo: Record<string, string>;
  effort: Effort;
  impact: Impact;
  floatTop?: boolean;
  tiers?: { guided?: TierOverrides; pro?: TierOverrides };
}

export interface NormalizedSite {
  siteId: string;
  siteName: string;
  devices: Record<string, unknown>[];
  clients: Record<string, unknown>[];
  wlans: Record<string, unknown>[];
  networks: Record<string, unknown>[];
  portForwards: Record<string, unknown>[];
  vpnConfigs: Record<string, unknown>[];
  firewallPolicies: Record<string, unknown>[];
  firewallZones: Record<string, unknown>[];
  trafficRoutes: Record<string, unknown>[];
  settings: Record<string, unknown>;
  profile: string;
  apiGaps: string[];
}

export type FindingModule = (site: NormalizedSite, profile: string) => Finding[];
```

- [ ] **Step 4: Create `src/audit/constants.ts`**

```typescript
import type { Finding } from './types.js';

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

export const ALWAYS_TOP_PREDICATES: Array<(f: Finding) => boolean> = [
  (f) => f.id.startsWith('MFA-'),
  (f) => f.id === 'SEG-MGMT-WAN',
  (f) => f.id.startsWith('SEG-001'),
  (f) => f.id.startsWith('CRED-DEFAULT'),
  (f) => f.id.startsWith('FW-EOL') && f.severity === 'high',
  (f) => f.id === 'VPN-PPTP-001',
];

export const PROFILE_OVERRIDES: Record<string, Record<string, Partial<Finding>>> = {
  home: {
    'LOG-FWD-001': { severity: 'low' },
    'LOG-PRIV-001': { severity: 'medium' },
  },
  regulated_hipaa: {
    'LOG-FWD-001': { severity: 'high' },
    'BAK-001': { severity: 'critical' },
  },
  regulated_pci: {
    'LOG-FWD-001': { severity: 'high' },
    'FW-GEO-IN': { severity: 'medium' },
  },
};

export const EOL_MODELS: Record<string, { status: string; eolDate: string }> = {
  'UAP-AC-LITE': { status: 'eol', eolDate: '2024-04-30' },
  'UAP-AC-LR':   { status: 'eol', eolDate: '2024-04-30' },
  'UAP-AC-PRO':  { status: 'eol', eolDate: '2024-04-30' },
  'USG':         { status: 'eol', eolDate: '2024-04-30' },
  'USG-PRO-4':   { status: 'eol', eolDate: '2025-04-30' },
  'UCK':         { status: 'eol', eolDate: '2022-12-31' },
  'UCK-G2':      { status: 'eol_warning', eolDate: '2026-12-31' },
};
```

- [ ] **Step 5: Run tests**

```bash
npm test
```

Expected: 1 passed

- [ ] **Step 6: Commit**

```bash
git add src/audit/types.ts src/audit/constants.ts src/audit/__tests__/types.test.ts
git commit -m "feat: add Finding/NormalizedSite types and audit constants"
```

---

## Task 3: Sanitize and normalize

**Files:**
- Create: `src/audit/sanitize.ts`
- Create: `src/audit/normalize.ts`
- Create: `src/audit/__tests__/sanitize.test.ts`
- Create: `src/audit/__tests__/normalize.test.ts`

- [ ] **Step 1: Write sanitize tests**

Create `src/audit/__tests__/sanitize.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { sanitize, fingerprint } from '../sanitize.js';

describe('fingerprint', () => {
  it('returns length and sha256 prefix for a string', () => {
    const r = fingerprint('mysecret');
    expect(r.length).toBe(8);
    expect(typeof r.fingerprint).toBe('string');
    expect(r.fingerprint.length).toBe(12);
  });
});

describe('sanitize', () => {
  it('redacts known secret field names', () => {
    const result = sanitize({ x_passphrase: 'secret123', name: 'MyNet' }) as Record<string, unknown>;
    expect((result.x_passphrase as Record<string, unknown>).length).toBe(9);
    expect(result.name).toBe('MyNet');
  });

  it('recurses into nested objects', () => {
    const result = sanitize({ wlan: { psk: 'abc' } }) as Record<string, unknown>;
    const wlan = result.wlan as Record<string, unknown>;
    expect((wlan.psk as Record<string, unknown>).length).toBe(3);
  });

  it('recurses into arrays', () => {
    const result = sanitize([{ password: 'pw' }]) as Record<string, unknown>[];
    expect((result[0].password as Record<string, unknown>).length).toBe(2);
  });

  it('leaves non-secret fields unchanged', () => {
    expect(sanitize({ ssid: 'HomeNet', channel: 6 })).toEqual({ ssid: 'HomeNet', channel: 6 });
  });
});
```

- [ ] **Step 2: Write normalize tests**

Create `src/audit/__tests__/normalize.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { normalizeApi, extractList } from '../normalize.js';

const CLEAN_ONE_SITE = {
  _endpointsProbed: [], _errors: [], _siteCount: 1,
  site_default: {
    _meta: { desc: 'Home', name: 'default' },
    devices:           { data: [{ mac: 'aa:bb:cc', type: 'ugw' }] },
    clients:           { data: [] },
    wlans:             { data: [{ name: 'HomeNet', enabled: true }] },
    networks:          { data: [{ name: 'LAN', purpose: 'corporate' }] },
    port_forwards:     { data: [] },
    vpn_configs:       { data: [] },
    firewall_policies: { data: [] },
    firewall_zones:    { data: [] },
    traffic_routes:    { data: [] },
  },
};

describe('normalizeApi', () => {
  it('returns one site', () => expect(normalizeApi(CLEAN_ONE_SITE, 'home_office')).toHaveLength(1));
  it('sets siteId', () => expect(normalizeApi(CLEAN_ONE_SITE, 'home_office')[0].siteId).toBe('default'));
  it('uses desc as siteName', () => expect(normalizeApi(CLEAN_ONE_SITE, 'home_office')[0].siteName).toBe('Home'));
  it('unpacks wlans', () => expect(normalizeApi(CLEAN_ONE_SITE, 'home_office')[0].wlans[0]).toMatchObject({ name: 'HomeNet' }));
  it('sets profile', () => expect(normalizeApi(CLEAN_ONE_SITE, 'regulated_hipaa')[0].profile).toBe('regulated_hipaa'));
  it('returns [] for empty input', () => expect(normalizeApi({}, 'home')).toHaveLength(0));
  it('tracks missing collections in apiGaps', () => {
    const clean = { site_s1: { _meta: { name: 's1' }, devices: { data: [] } } };
    const site = normalizeApi(clean, 'home')[0];
    expect(site.apiGaps).toContain('wlans');
    expect(site.apiGaps).not.toContain('devices');
  });
  it('settings is empty in API mode', () => {
    expect(normalizeApi(CLEAN_ONE_SITE, 'home')[0].settings).toEqual({});
  });
});

describe('extractList', () => {
  it('unwraps data key', () => expect(extractList({ data: [1, 2] })).toEqual([1, 2]));
  it('returns plain arrays as-is', () => expect(extractList([1, 2])).toEqual([1, 2]));
  it('returns [] for null', () => expect(extractList(null)).toEqual([]));
  it('unwraps items key', () => expect(extractList({ items: ['a'] })).toEqual(['a']));
});
```

- [ ] **Step 3: Run — expect failures**

```bash
npm test
```

Expected: errors on both test files (modules don't exist)

- [ ] **Step 4: Create `src/audit/sanitize.ts`**

```typescript
import { createHash } from 'node:crypto';

const SECRET_FIELDS = new Set([
  'x_passphrase', 'x_passphrase_rollover', 'x_radius_secret', 'x_shared_secret',
  'x_ssh_password', 'x_iapp_key', 'password', 'x_auth_key', 'auth_key',
  'private_key', 'api_key', 'token', 'passphrase', 'preSharedKey', 'presharedKey',
  'psk', 'pre_shared_key', 'privateKey', 'wpa_psk',
]);

export interface Fingerprint {
  length: number;
  fingerprint: string;
  hasSymbols: boolean;
  hasDigits: boolean;
  hasMixedCase: boolean;
}

export function fingerprint(value: string): Fingerprint {
  return {
    length: value.length,
    fingerprint: createHash('sha256').update(value).digest('hex').slice(0, 12),
    hasSymbols: /[^a-zA-Z0-9]/.test(value),
    hasDigits: /\d/.test(value),
    hasMixedCase: /[a-z]/.test(value) && /[A-Z]/.test(value),
  };
}

export function sanitize(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(sanitize);
  if (obj !== null && typeof obj === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[k] = SECRET_FIELDS.has(k) && typeof v === 'string' ? fingerprint(v) : sanitize(v);
    }
    return out;
  }
  return obj;
}
```

- [ ] **Step 5: Create `src/audit/normalize.ts`**

```typescript
import type { NormalizedSite } from './types.js';

const EXPECTED_COLLECTIONS = new Set([
  'devices', 'clients', 'wlans', 'networks', 'port_forwards',
  'vpn_configs', 'firewall_policies', 'firewall_zones', 'traffic_routes',
]);

export function extractList(data: unknown): Record<string, unknown>[] {
  if (data === null || data === undefined) return [];
  if (Array.isArray(data)) return data as Record<string, unknown>[];
  if (typeof data === 'object') {
    const d = data as Record<string, unknown>;
    for (const key of ['data', 'items', 'results']) {
      if (Array.isArray(d[key])) return d[key] as Record<string, unknown>[];
    }
  }
  return [];
}

export function normalizeApi(clean: Record<string, unknown>, profile: string): NormalizedSite[] {
  const sites: NormalizedSite[] = [];
  for (const [key, val] of Object.entries(clean)) {
    if (!key.startsWith('site_') || typeof val !== 'object' || val === null) continue;
    const siteId = key.slice(5);
    const siteData = val as Record<string, unknown>;
    const meta = (siteData['_meta'] ?? {}) as Record<string, unknown>;
    const siteName = String(meta['desc'] ?? meta['name'] ?? siteId);
    const apiGaps = [...EXPECTED_COLLECTIONS].filter(c => !(c in siteData)).sort();
    sites.push({
      siteId,
      siteName,
      devices:           extractList(siteData['devices']),
      clients:           extractList(siteData['clients']),
      wlans:             extractList(siteData['wlans']),
      networks:          extractList(siteData['networks']),
      portForwards:      extractList(siteData['port_forwards']),
      vpnConfigs:        extractList(siteData['vpn_configs']),
      firewallPolicies:  extractList(siteData['firewall_policies']),
      firewallZones:     extractList(siteData['firewall_zones']),
      trafficRoutes:     extractList(siteData['traffic_routes']),
      settings:          {},
      profile,
      apiGaps,
    });
  }
  return sites;
}
```

- [ ] **Step 6: Run tests**

```bash
npm test
```

Expected: all sanitize and normalize tests pass

- [ ] **Step 7: Commit**

```bash
git add src/audit/sanitize.ts src/audit/normalize.ts src/audit/__tests__/sanitize.test.ts src/audit/__tests__/normalize.test.ts
git commit -m "feat: add sanitize and normalizeApi modules with tests"
```

---

## Task 4: API client

**Files:**
- Create: `src/audit/client.ts`
- Create: `src/audit/__tests__/client.test.ts`

- [ ] **Step 1: Write tests**

Create `src/audit/__tests__/client.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { UniFiClient } from '../client.js';

describe('UniFiClient', () => {
  it('throws if UNIFI_API_KEY is not set', () => {
    const env = { UNIFI_API_KEY: '', UNIFI_HOST: '192.168.1.1' };
    expect(() => UniFiClient.fromEnv(env)).toThrow('UNIFI_API_KEY');
  });

  it('throws if neither UNIFI_HOST nor UNIFI_USE_CLOUD is set', () => {
    const env = { UNIFI_API_KEY: 'k', UNIFI_HOST: '', UNIFI_USE_CLOUD: '' };
    expect(() => UniFiClient.fromEnv(env)).toThrow('UNIFI_HOST');
  });

  it('sets verifySSL true by default for cloud mode', () => {
    const env = { UNIFI_API_KEY: 'k', UNIFI_USE_CLOUD: 'true', UNIFI_HOST: '' };
    const c = UniFiClient.fromEnv(env);
    expect(c.config.verifySSL).toBe(true);
  });

  it('sets verifySSL false by default for local mode', () => {
    const env = { UNIFI_API_KEY: 'k', UNIFI_HOST: '192.168.1.1', UNIFI_USE_CLOUD: '' };
    const c = UniFiClient.fromEnv(env);
    expect(c.config.verifySSL).toBe(false);
  });
});
```

- [ ] **Step 2: Run — expect failures**

```bash
npm test -- --reporter=verbose src/audit/__tests__/client.test.ts
```

Expected: `Cannot find module '../client.js'`

- [ ] **Step 3: Create `src/audit/client.ts`**

```typescript
export interface ClientConfig {
  key: string;
  host: string;
  useCloud: boolean;
  verifySSL: boolean;
  profile: string;
}

export interface FetchResult {
  status: number;
  data: unknown;
}

export class UniFiClient {
  readonly config: ClientConfig;

  constructor(config: ClientConfig) {
    this.config = config;
  }

  static fromEnv(env: Record<string, string | undefined> = process.env as Record<string, string>): UniFiClient {
    const key = (env['UNIFI_API_KEY'] ?? '').trim();
    if (!key) throw new Error('UNIFI_API_KEY environment variable not set');

    const host = (env['UNIFI_HOST'] ?? '').trim();
    const useCloud = ['1', 'true', 'yes'].includes((env['UNIFI_USE_CLOUD'] ?? '').toLowerCase());
    if (!host && !useCloud) throw new Error('UNIFI_HOST not set (and UNIFI_USE_CLOUD not enabled)');

    const verifySslEnv = (env['UNIFI_VERIFY_SSL'] ?? '').toLowerCase();
    const verifySSL = verifySslEnv === '1' || verifySslEnv === 'true' ? true
      : verifySslEnv === '0' || verifySslEnv === 'false' ? false
      : useCloud;

    return new UniFiClient({
      key, host, useCloud, verifySSL,
      profile: env['UNIFI_PROFILE'] ?? 'home_office',
    });
  }

  private baseUrl(): string {
    if (this.config.useCloud) return 'https://api.ui.com';
    const h = this.config.host;
    return h.startsWith('http') ? h : `https://${h}`;
  }

  async get(path: string): Promise<FetchResult> {
    const url = path.startsWith('http') ? path : `${this.baseUrl()}${path}`;
    const options: RequestInit = {
      headers: { 'X-API-KEY': this.config.key, 'Accept': 'application/json' },
    };
    try {
      const resp = await fetch(url, options);
      let data: unknown;
      try { data = await resp.json(); } catch { data = { nonJsonResponse: true }; }
      return { status: resp.status, data };
    } catch (err) {
      const msg = String(err).replace(this.config.key, '<REDACTED>');
      return { status: 0, data: { error: msg } };
    }
  }
}
```

- [ ] **Step 4: Run tests**

```bash
npm test
```

Expected: all client tests pass

- [ ] **Step 5: Commit**

```bash
git add src/audit/client.ts src/audit/__tests__/client.test.ts
git commit -m "feat: add UniFiClient with env-based config"
```

---

## Task 5: Core finding modules (segmentation, wifi, firewall, remoteAccess, devices)

**Files:**
- Create: `src/audit/findings/segmentation.ts`
- Create: `src/audit/findings/wifi.ts`
- Create: `src/audit/findings/firewall.ts`
- Create: `src/audit/findings/remoteAccess.ts`
- Create: `src/audit/findings/devices.ts`
- Create: `src/audit/__tests__/findings/core.test.ts`

- [ ] **Step 1: Write tests**

Create `src/audit/__tests__/findings/core.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import type { NormalizedSite } from '../../types.js';
import { findSegmentation } from '../../findings/segmentation.js';
import { findWifi } from '../../findings/wifi.js';
import { findFirewall } from '../../findings/firewall.js';
import { findRemoteAccess } from '../../findings/remoteAccess.js';
import { findDevices } from '../../findings/devices.js';

function site(overrides: Partial<NormalizedSite> = {}): NormalizedSite {
  return {
    siteId: 'test', siteName: 'Test',
    devices: [], clients: [], wlans: [], networks: [],
    portForwards: [], vpnConfigs: [], firewallPolicies: [],
    firewallZones: [], trafficRoutes: [], settings: {},
    profile: 'home_office', apiGaps: [],
    ...overrides,
  };
}

describe('findSegmentation', () => {
  it('emits SEG-001 when only one network', () => {
    const s = site({ networks: [{ purpose: 'corporate', name: 'LAN' }] });
    const ids = findSegmentation(s, 'home_office').map(f => f.id);
    expect(ids[0]).toMatch(/^SEG-001/);
  });

  it('no finding when multiple networks', () => {
    const s = site({ networks: [
      { purpose: 'corporate' }, { purpose: 'guest' }, { purpose: 'vlan-only' },
    ]});
    expect(findSegmentation(s, 'home_office')).toHaveLength(0);
  });
});

describe('findWifi', () => {
  it('emits WPA finding for WPA2-only SSID', () => {
    const s = site({ wlans: [{ name: 'Net', enabled: true, security: 'wpapsk' }] });
    const ids = findWifi(s, 'home_office').map(f => f.id);
    expect(ids.some(id => id.includes('WPA'))).toBe(true);
  });

  it('emits PSK finding for short passphrase', () => {
    const s = site({ wlans: [{ name: 'Net', enabled: true, x_passphrase: { length: 8 } }] });
    const ids = findWifi(s, 'home_office').map(f => f.id);
    expect(ids.some(id => id.includes('PSK'))).toBe(true);
  });
});

describe('findFirewall', () => {
  it('emits port-forward finding when forwards active', () => {
    const s = site({ portForwards: [{ enabled: true, dstPort: '80' }] });
    expect(findFirewall(s, 'home_office').length).toBeGreaterThan(0);
  });

  it('no finding when no active forwards', () => {
    expect(findFirewall(site(), 'home_office')).toHaveLength(0);
  });
});

describe('findRemoteAccess', () => {
  it('emits critical for PPTP', () => {
    const s = site({ vpnConfigs: [{ type: 'pptp', enabled: true }] });
    const pptp = findRemoteAccess(s, 'home_office').find(f => f.id === 'VPN-PPTP-001');
    expect(pptp?.severity).toBe('critical');
  });

  it('emits VPN-MISSING when forwards without VPN', () => {
    const s = site({ portForwards: [{ enabled: true }] });
    const ids = findRemoteAccess(s, 'home_office').map(f => f.id);
    expect(ids).toContain('VPN-MISSING-001');
  });

  it('emits VPN-WG-OK for wireguard', () => {
    const s = site({ vpnConfigs: [{ type: 'wireguard', enabled: true }] });
    const ids = findRemoteAccess(s, 'home_office').map(f => f.id);
    expect(ids).toContain('VPN-WG-OK');
  });
});

describe('findDevices', () => {
  it('emits SSH finding when SSH enabled on device', () => {
    const s = site({ devices: [{ sshEnabled: true, name: 'AP1' }] });
    expect(findDevices(s, 'home_office').length).toBeGreaterThan(0);
  });

  it('no finding when SSH disabled', () => {
    const s = site({ devices: [{ sshEnabled: false, name: 'AP1' }] });
    expect(findDevices(s, 'home_office')).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run — expect failures**

```bash
npm test
```

Expected: module not found errors for finding modules

- [ ] **Step 3: Create `src/audit/findings/segmentation.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

export function findSegmentation(site: NormalizedSite, _profile: string): Finding[] {
  const userNets = site.networks.filter(n =>
    ['corporate', 'guest', 'vlan-only'].includes(String(n['purpose'] ?? ''))
  );
  if (userNets.length <= 1) {
    return [{
      id: `SEG-001-${site.siteId}`,
      section: 'Segmentation', severity: 'high', status: 'gap',
      title: 'Flat network (no segmentation)',
      currentState: `Site '${site.siteName}' has ${userNets.length} user-defined network(s). A compromise of any device can reach any other.`,
      recommendation: 'Create separate networks for main, IoT, guest, and management. Map SSIDs to VLANs. Enable Zone-Based Firewall rules.',
      intentQuestion: 'Do you want to segment the network?',
      evidence: { networkCount: userNets.length },
      mapsTo: { nist_csf: 'PR.AC-5', cis_v8: '12.2' },
      effort: 'project', impact: 'high',
    }];
  }
  return [];
}
```

- [ ] **Step 4: Create `src/audit/findings/wifi.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

export function findWifi(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  for (const w of site.wlans) {
    if (w['enabled'] === false) continue;
    const name = String(w['name'] ?? '<unnamed>');
    const security = String(w['security'] ?? w['securityProtocol'] ?? '').toLowerCase();
    if (security.includes('wpa2') && !security.includes('wpa3')) {
      findings.push({
        id: `WIFI-${site.siteId}-${name}-WPA`,
        section: 'Wi-Fi', severity: 'low', status: 'recommendation',
        title: `SSID '${name}' is WPA2-only`,
        currentState: `SSID '${name}' uses WPA2. WPA3 or mixed mode offers stronger protection.`,
        recommendation: 'Switch to WPA2/WPA3 mixed mode, or WPA3-only if all clients support it.',
        intentQuestion: `Do any clients on '${name}' require WPA2-only?`,
        evidence: {}, mapsTo: { cis_v8: '12.5' }, effort: 'quick', impact: 'low',
      });
    }
    const psk = w['x_passphrase'] as Record<string, unknown> | undefined;
    if (psk && typeof psk['length'] === 'number' && psk['length'] < 12) {
      findings.push({
        id: `WIFI-${site.siteId}-${name}-PSK`,
        section: 'Wi-Fi', severity: 'high', status: 'gap',
        title: `SSID '${name}' has a short passphrase`,
        currentState: `Passphrase is ${psk['length']} characters. Short PSKs are vulnerable to offline attacks.`,
        recommendation: 'Use a passphrase of at least 16 characters with mixed case, numbers, and symbols.',
        intentQuestion: null,
        evidence: {}, mapsTo: { cis_v8: '5.2' }, effort: 'quick', impact: 'high',
      });
    }
  }
  return findings;
}
```

- [ ] **Step 5: Create `src/audit/findings/firewall.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

export function findFirewall(site: NormalizedSite, _profile: string): Finding[] {
  const active = site.portForwards.filter(p => p['enabled'] !== false);
  if (!active.length) return [];
  return [{
    id: `FW-${site.siteId}-PF`,
    section: 'Firewall', severity: 'info', status: 'recommendation',
    title: `${active.length} port forward(s) active`,
    currentState: `${active.length} port forwards expose internal services.`,
    recommendation: 'Review each. Prefer VPN for admin access; use source IP allowlists for public services.',
    intentQuestion: 'Want to review each port forward?',
    evidence: { count: active.length }, mapsTo: { cis_v8: '4.4' }, effort: 'medium', impact: 'high',
  }];
}
```

- [ ] **Step 6: Create `src/audit/findings/remoteAccess.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

export function findRemoteAccess(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  const vpnByType: Record<string, Record<string, unknown>> = {};
  for (const v of site.vpnConfigs) {
    if (v['enabled'] === false) continue;
    const t = String(v['type'] ?? '').toLowerCase().replace(/[-/]/g, '_');
    vpnByType[t] = v as Record<string, unknown>;
  }

  const pptp = vpnByType['pptp'];
  const l2tp = vpnByType['l2tp'] ?? vpnByType['l2tp_ipsec'];
  const wireguard = vpnByType['wireguard'] ?? vpnByType['wg'];
  const openvpn = vpnByType['openvpn'];

  if (pptp) findings.push({
    id: 'VPN-PPTP-001', section: 'Remote access', severity: 'critical', status: 'gap',
    title: 'PPTP VPN enabled (broken protocol)',
    currentState: 'PPTP is enabled. MS-CHAPv2 is cryptographically broken; credentials and traffic can be recovered by anyone on-path.',
    recommendation: 'Disable PPTP immediately. Replace with WireGuard. Rotate all credentials used over PPTP.',
    intentQuestion: null,
    evidence: {}, mapsTo: { cis_v8: '4.4', nist_csf: 'PR.AC-3' }, effort: 'quick', impact: 'high',
  });

  if (l2tp && !wireguard && !openvpn) findings.push({
    id: 'VPN-L2TP-001', section: 'Remote access', severity: 'medium', status: 'recommendation',
    title: 'L2TP/IPsec is the only VPN (consider WireGuard)',
    currentState: 'L2TP/IPsec is the only VPN. Often blocked by hotel/public Wi-Fi; slower than WireGuard.',
    recommendation: 'Add WireGuard as the primary VPN.',
    intentQuestion: 'Do you have a client that specifically requires L2TP?',
    evidence: {}, mapsTo: { cis_v8: '4.4' }, effort: 'medium', impact: 'medium',
  });

  const activeForwards = site.portForwards.filter(p => p['enabled'] !== false);
  if (activeForwards.length && !wireguard && !openvpn && !l2tp) findings.push({
    id: 'VPN-MISSING-001', section: 'Remote access', severity: 'high', status: 'gap',
    title: `${activeForwards.length} services exposed to internet, no VPN configured`,
    currentState: `${activeForwards.length} port forwards expose internal services. No VPN configured.`,
    recommendation: 'Set up WireGuard VPN, then remove port forwards used only for remote access.',
    intentQuestion: 'Are any port forwards for services that must be public-facing?',
    evidence: {}, mapsTo: { cis_v8: '4.4', nist_csf: 'PR.AC-3' }, effort: 'medium', impact: 'high',
  });

  if (wireguard) findings.push({
    id: 'VPN-WG-OK', section: 'Remote access', severity: 'info', status: 'ok',
    title: 'WireGuard VPN configured',
    currentState: 'WireGuard VPN is enabled. This is the recommended remote access path.',
    recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: { cis_v8: '4.4' }, effort: 'quick', impact: 'low',
  });

  return findings;
}
```

- [ ] **Step 7: Create `src/audit/findings/devices.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

export function findDevices(site: NormalizedSite, _profile: string): Finding[] {
  const sshOn = site.devices.filter(d => d['sshEnabled'] || d['ssh_enabled']);
  if (!sshOn.length) return [];
  return [{
    id: `DEV-SSH-${site.siteId}`,
    section: 'Admin', severity: 'medium', status: 'recommendation',
    title: `SSH enabled on ${sshOn.length} device(s)`,
    currentState: `SSH is enabled on ${sshOn.length} device(s). This is a remote admin surface.`,
    recommendation: 'Disable SSH unless actively used. If needed, key-based auth only, scoped to management VLAN.',
    intentQuestion: 'Do you use SSH to these devices?',
    evidence: {}, mapsTo: { cis_v8: '4.6' }, effort: 'quick', impact: 'medium',
  }];
}
```

- [ ] **Step 8: Run tests**

```bash
npm test
```

Expected: all core findings tests pass

- [ ] **Step 9: Commit**

```bash
git add src/audit/findings/ src/audit/__tests__/findings/
git commit -m "feat: add core finding modules (segmentation, wifi, firewall, remoteAccess, devices)"
```

---

## Task 6: Enhanced finding modules

**Files:**
- Create: `src/audit/findings/wirelessTuning.ts`
- Create: `src/audit/findings/firewallThreats.ts`
- Create: `src/audit/findings/firmware.ts`
- Create: `src/audit/findings/logging.ts`
- Create: `src/audit/findings/backup.ts`
- Create: `src/audit/findings/apiCoverage.ts`
- Create: `src/audit/__tests__/findings/enhanced.test.ts`

- [ ] **Step 1: Write tests**

Create `src/audit/__tests__/findings/enhanced.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import type { NormalizedSite } from '../../types.js';
import { findWirelessTuning } from '../../findings/wirelessTuning.js';
import { findFirewallThreats } from '../../findings/firewallThreats.js';
import { findFirmware } from '../../findings/firmware.js';
import { findLogging } from '../../findings/logging.js';
import { findBackup } from '../../findings/backup.js';
import { findApiCoverage } from '../../findings/apiCoverage.js';

function site(overrides: Partial<NormalizedSite> = {}): NormalizedSite {
  return {
    siteId: 'test', siteName: 'Test',
    devices: [], clients: [], wlans: [], networks: [],
    portForwards: [], vpnConfigs: [], firewallPolicies: [],
    firewallZones: [], trafficRoutes: [], settings: {},
    profile: 'home_office', apiGaps: [],
    ...overrides,
  };
}

describe('findWirelessTuning', () => {
  it('emits RF-TX for high tx_power_mode', () => {
    const s = site({ devices: [{ type: 'uap', mac: 'aa', name: 'AP1', radio_table: [{ radio: 'na', tx_power_mode: 'high' }] }] });
    expect(findWirelessTuning(s, 'home_office').some(f => f.id.includes('-TX'))).toBe(true);
  });
  it('emits unknown for rogue AP when no settings', () => {
    const rogue = findWirelessTuning(site(), 'home_office').find(f => f.id === 'RF-ROGUE-001');
    expect(rogue?.status).toBe('unknown');
  });
  it('emits gap when rogue AP disabled in settings', () => {
    const s = site({ settings: { rogueap: { report_rogue: false } } });
    const rogue = findWirelessTuning(s, 'home_office').find(f => f.id === 'RF-ROGUE-001');
    expect(rogue?.status).toBe('gap');
  });
  it('emits PMF finding for WPA3 without PMF', () => {
    const s = site({ wlans: [{ name: 'Sec', enabled: true, wpa_mode: 'wpa3', pmf_mode: 'disabled' }] });
    expect(findWirelessTuning(s, 'home_office').some(f => f.id.includes('RF-PMF'))).toBe(true);
  });
});

describe('findFirewallThreats', () => {
  it('emits FW-GEO-IN when no geo inbound policy', () => {
    expect(findFirewallThreats(site(), 'home_office').some(f => f.id === 'FW-GEO-IN')).toBe(true);
  });
  it('FW-CONTENT-001 is unknown when no settings', () => {
    const cf = findFirewallThreats(site(), 'home_office').find(f => f.id === 'FW-CONTENT-001');
    expect(cf?.status).toBe('unknown');
  });
  it('FW-CONTENT-001 is recommendation when disabled in settings', () => {
    const s = site({ settings: { dns_filtering: { enabled: false } } });
    const cf = findFirewallThreats(s, 'home_office').find(f => f.id === 'FW-CONTENT-001');
    expect(cf?.status).toBe('recommendation');
  });
});

describe('findFirmware', () => {
  it('emits EOL finding for UAP-AC-LITE', () => {
    const s = site({ devices: [{ model: 'UAP-AC-LITE', name: 'OldAP', version: '5.0.0' }] });
    expect(findFirmware(s, 'home_office').some(f => f.id === 'FW-EOL-001')).toBe(true);
  });
  it('FW-AUTO-001 unknown when no settings', () => {
    expect(findFirmware(site(), 'home_office').find(f => f.id === 'FW-AUTO-001')?.status).toBe('unknown');
  });
  it('FW-AUTO-001 gap when disabled in settings', () => {
    const s = site({ settings: { auto_update: { enabled: false } } });
    expect(findFirmware(s, 'home_office').find(f => f.id === 'FW-AUTO-001')?.status).toBe('gap');
  });
});

describe('findLogging', () => {
  it('LOG-FWD-001 unknown when no settings', () => {
    expect(findLogging(site(), 'home_office').find(f => f.id === 'LOG-FWD-001')?.status).toBe('unknown');
  });
  it('LOG-FWD-001 recommendation when syslog not configured', () => {
    const s = site({ settings: { mgmt: { syslog_host: null } } });
    expect(findLogging(s, 'home_office').find(f => f.id === 'LOG-FWD-001')?.status).toBe('recommendation');
  });
});

describe('findBackup', () => {
  it('BAK-001 unknown when no settings', () => {
    expect(findBackup(site(), 'home_office').find(f => f.id === 'BAK-001')?.status).toBe('unknown');
  });
  it('BAK-001 gap when disabled', () => {
    const s = site({ settings: { auto_backup: { enabled: false } } });
    expect(findBackup(s, 'home_office').find(f => f.id === 'BAK-001')?.status).toBe('gap');
  });
  it('BAK-003 always emitted when backup enabled', () => {
    const s = site({ settings: { auto_backup: { enabled: true, destination: 'cloud' } } });
    expect(findBackup(s, 'home_office').some(f => f.id === 'BAK-003')).toBe(true);
  });
});

describe('findApiCoverage', () => {
  it('emits META-COVERAGE when endpoints failed', () => {
    const clean = { _endpointsProbed: [{ name: 'wlans', status: 404 }], _errors: [] };
    expect(findApiCoverage(clean).some(f => f.id === 'META-COVERAGE')).toBe(true);
  });
  it('no finding when all endpoints succeeded', () => {
    const clean = { _endpointsProbed: [{ name: 'wlans', status: 200 }], _errors: [] };
    expect(findApiCoverage(clean)).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run — expect failures**

```bash
npm test
```

Expected: module not found errors

- [ ] **Step 3: Create `src/audit/findings/wirelessTuning.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

export function findWirelessTuning(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  const aps = site.devices.filter(d => d['type'] === 'uap');

  for (const d of aps) {
    const apName = String(d['name'] ?? d['mac'] ?? 'unnamed');
    for (const r of (d['radio_table'] as Record<string, unknown>[] ?? [])) {
      const band = String(r['radio'] ?? 'unknown');
      const bandLabel = ({ ng: '2.4 GHz', na: '5 GHz', '6e': '6 GHz' } as Record<string, string>)[band] ?? band;
      if (r['tx_power_mode'] === 'high') {
        findings.push({
          id: `RF-${d['mac']}-${band}-TX`, section: 'Wireless tuning',
          severity: 'low', status: 'recommendation',
          title: `AP '${apName}' broadcasting at High power on ${bandLabel}`,
          currentState: `AP '${apName}' ${bandLabel} radio is set to High TX power. High power extends coverage past your physical space.`,
          recommendation: 'Set TX power to Auto or Medium for typical indoor use.',
          intentQuestion: 'Is extended coverage deliberate (outdoor, large property)?',
          evidence: {}, mapsTo: { cis_v8: '12.5', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'low',
        });
      }
    }
  }

  const apsWith24 = aps.filter(d =>
    (d['radio_table'] as Record<string, unknown>[] ?? []).some(r => r['radio'] === 'ng' && !r['disabled'])
  );
  if (apsWith24.length) {
    const clientsOn24 = site.clients.filter(c => c['radio'] === 'ng').length;
    const totalWifi = site.clients.filter(c => c['radio']).length;
    findings.push({
      id: 'RF-BAND-24GHZ', section: 'Wireless tuning', severity: 'info', status: 'recommendation',
      title: '2.4 GHz radio active across AP(s)',
      currentState: `${apsWith24.length} AP(s) have 2.4 GHz enabled. ${clientsOn24} of ${totalWifi} clients are on 2.4 GHz.`,
      recommendation: 'Identify which devices need 2.4 GHz. Disable if few do to shrink attack surface.',
      intentQuestion: 'Do you have devices that truly require 2.4 GHz?',
      evidence: { apsWith24: apsWith24.length, clientsOn24, totalWifi },
      mapsTo: { cis_v8: '12.5' }, effort: 'medium', impact: 'medium',
    });
  }

  const rogueSetting = (site.settings['rogueap'] as Record<string, unknown> | undefined);
  if (rogueSetting === undefined) {
    findings.push({
      id: 'RF-ROGUE-001', section: 'Wireless tuning', severity: 'info', status: 'unknown',
      title: 'Rogue AP detection: cannot check via live API',
      currentState: 'Rogue AP detection state is not exposed by the Network Integration API. Use backup-file mode or check Settings → WiFi → Advanced.',
      recommendation: 'Enable Rogue AP Detection in Settings → WiFi → Advanced.',
      intentQuestion: 'Is rogue AP detection currently enabled?',
      evidence: {}, mapsTo: { cis_v8: '12.6', nist_csf: 'DE.CM-7' }, effort: 'quick', impact: 'medium',
    });
  } else if (!rogueSetting['report_rogue']) {
    findings.push({
      id: 'RF-ROGUE-001', section: 'Wireless tuning', severity: 'medium', status: 'gap',
      title: 'Rogue AP detection not enabled',
      currentState: 'Rogue AP reporting is disabled.',
      recommendation: 'Enable Rogue AP Detection in Settings → WiFi → Advanced.',
      intentQuestion: 'Want rogue AP detection on? (no performance cost)',
      evidence: {}, mapsTo: { cis_v8: '12.6', nist_csf: 'DE.CM-7' }, effort: 'quick', impact: 'medium',
    });
  }

  for (const w of site.wlans) {
    if (w['enabled'] === false) continue;
    const name = String(w['name'] ?? '<unnamed>');
    const wpaMode = String(w['wpa_mode'] ?? '').toLowerCase();
    const pmf = String(w['pmf_mode'] ?? 'disabled');
    if (wpaMode.includes('wpa3') && pmf === 'disabled') {
      findings.push({
        id: `RF-PMF-${name}`, section: 'Wireless tuning', severity: 'medium', status: 'gap',
        title: `SSID '${name}' uses WPA3 but PMF is disabled`,
        currentState: `SSID '${name}' has WPA3 but PMF (802.11w) is off. PMF blocks deauth attacks.`,
        recommendation: `Set PMF to Required on '${name}'.`,
        intentQuestion: null,
        evidence: {}, mapsTo: { cis_v8: '12.5' }, effort: 'quick', impact: 'medium',
      });
    }
  }

  return findings;
}
```

- [ ] **Step 4: Create `src/audit/findings/firewallThreats.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

function hasGeoPolicy(policies: Record<string, unknown>[], directionHint: string): boolean {
  for (const p of policies) {
    if (p['enabled'] === false || p['action'] !== 'drop') continue;
    const src = (p['source'] ?? {}) as Record<string, unknown>;
    if (!src['geo']) continue;
    const name = String(p['name'] ?? '').toLowerCase();
    const dir = String(p['direction'] ?? '').toUpperCase();
    if (dir.includes(directionHint) || name.includes(directionHint.toLowerCase())) return true;
  }
  return false;
}

export function findFirewallThreats(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];

  if (!hasGeoPolicy(site.firewallPolicies, 'WAN_IN')) findings.push({
    id: 'FW-GEO-IN', section: 'Firewall', severity: 'low', status: 'recommendation',
    title: 'No Geo-IP blocking on inbound WAN',
    currentState: 'No policy found blocking inbound traffic from high-risk regions.',
    recommendation: 'Block inbound from CN, RU, KP, IR. Low false-positive rate for most users.',
    intentQuestion: 'Do you expect inbound traffic from these regions?',
    evidence: {}, mapsTo: { cis_v8: '13.4' }, effort: 'quick', impact: 'medium',
  });

  if (!hasGeoPolicy(site.firewallPolicies, 'WAN_OUT')) findings.push({
    id: 'FW-GEO-OUT', section: 'Firewall', severity: 'low', status: 'recommendation',
    title: 'No Geo-IP blocking on outbound WAN (often overlooked)',
    currentState: 'No outbound Geo-IP policy. A compromised device calling home to a C2 in a blocked region would succeed.',
    recommendation: 'Apply outbound geo-blocking for the same regions you block inbound.',
    intentQuestion: 'Do any of your services legitimately talk to servers in high-risk regions?',
    evidence: {}, mapsTo: { cis_v8: '13.4' }, effort: 'quick', impact: 'low',
  });

  const dnsFilter = site.settings['dns_filtering'] as Record<string, unknown> | undefined;
  if (dnsFilter === undefined) {
    findings.push({
      id: 'FW-CONTENT-001', section: 'Firewall', severity: 'info', status: 'unknown',
      title: 'Content filtering: cannot check via live API',
      currentState: 'DNS content filtering state is not exposed by the API. Check Settings → Security → Content Filtering.',
      recommendation: 'Enable Content Filtering with the Security category at minimum.',
      intentQuestion: 'Is DNS content filtering currently enabled?',
      evidence: {}, mapsTo: { cis_v8: '9.3', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'medium',
    });
  } else if (!dnsFilter['enabled']) {
    findings.push({
      id: 'FW-CONTENT-001', section: 'Firewall', severity: 'medium', status: 'recommendation',
      title: 'Content filtering not configured',
      currentState: 'DNS-based content filtering is off. No automatic blocking of malware domains.',
      recommendation: 'Enable Content Filtering with the Security category at minimum.',
      intentQuestion: 'Should the network block known-malicious domains automatically?',
      evidence: {}, mapsTo: { cis_v8: '9.3', nist_csf: 'PR.PT-4' }, effort: 'quick', impact: 'medium',
    });
  }

  return findings;
}
```

- [ ] **Step 5: Create `src/audit/findings/firmware.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';
import { EOL_MODELS } from '../constants.js';

export function findFirmware(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];

  const autoUpdate = site.settings['auto_update'] as Record<string, unknown> | undefined;
  if (autoUpdate === undefined) {
    findings.push({
      id: 'FW-AUTO-001', section: 'Firmware', severity: 'info', status: 'unknown',
      title: 'Auto-update setting: cannot check via live API',
      currentState: 'Auto-update state is not exposed by the API. Check Settings → System → Updates.',
      recommendation: 'Enable automatic firmware updates in a maintenance window (e.g. 03:00–05:00).',
      intentQuestion: 'Is automatic firmware update enabled?',
      evidence: {}, mapsTo: { cis_v8: '7.3', nist_csf: 'PR.IP-12' }, effort: 'quick', impact: 'medium',
    });
  } else if (!autoUpdate['enabled']) {
    findings.push({
      id: 'FW-AUTO-001', section: 'Firmware', severity: 'medium', status: 'gap',
      title: 'Automatic firmware updates disabled',
      currentState: 'Devices do not auto-update firmware.',
      recommendation: 'Enable automatic firmware updates in a maintenance window.',
      intentQuestion: 'Any reason to hold back updates?',
      evidence: {}, mapsTo: { cis_v8: '7.3', nist_csf: 'PR.IP-12' }, effort: 'quick', impact: 'medium',
    });
  }

  const eolDevices: Record<string, unknown>[] = [];
  for (const d of site.devices) {
    const model = String(d['model'] ?? '').toUpperCase();
    if (model in EOL_MODELS) eolDevices.push({ ...EOL_MODELS[model], name: d['name'] ?? d['mac'], model });
  }

  const eolCount = eolDevices.filter(d => d['status'] === 'eol').length;
  const warnCount = eolDevices.filter(d => d['status'] === 'eol_warning').length;

  if (eolCount) findings.push({
    id: 'FW-EOL-001', section: 'Firmware', severity: 'high', status: 'gap',
    title: `${eolCount} device(s) past end-of-support`,
    currentState: `${eolCount} device(s) are past Ubiquiti's end-of-support date and no longer receive security patches.`,
    recommendation: 'Plan replacement. Prioritise internet-facing devices first.',
    intentQuestion: 'What is your replacement budget and timeline?',
    evidence: { devices: eolDevices.filter(d => d['status'] === 'eol') },
    mapsTo: { cis_v8: '7.3', nist_csf: 'PR.IP-12' }, effort: 'project', impact: 'high',
  });

  if (warnCount) findings.push({
    id: 'FW-EOL-002', section: 'Firmware', severity: 'medium', status: 'recommendation',
    title: `${warnCount} device(s) approaching EOL`,
    currentState: `${warnCount} device(s) reach end-of-support within 12 months.`,
    recommendation: 'Start planning replacements during your normal refresh cycle.',
    intentQuestion: 'Is hardware refresh on your roadmap?',
    evidence: { devices: eolDevices.filter(d => d['status'] === 'eol_warning') },
    mapsTo: { cis_v8: '7.3' }, effort: 'project', impact: 'medium',
  });

  for (const d of site.devices) {
    const ver = String(d['version'] ?? '');
    if (ver.includes('.')) {
      const major = parseInt(ver.split('.')[0]!, 10);
      if (!isNaN(major) && major < 7) findings.push({
        id: `FW-VER-${d['mac'] ?? 'x'}`, section: 'Firmware', severity: 'high', status: 'gap',
        title: `Device '${d['name'] ?? d['mac']}' on outdated major version`,
        currentState: `Firmware ${ver} is multiple major versions behind current.`,
        recommendation: 'Update to latest stable firmware in a maintenance window.',
        intentQuestion: null,
        evidence: {}, mapsTo: { cis_v8: '7.3' }, effort: 'quick', impact: 'high',
      });
    }
  }

  return findings;
}
```

- [ ] **Step 6: Create `src/audit/findings/logging.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

const RETENTION_PROFILES: Record<string, { trafficDays: number; adminDays: number }> = {
  home:            { trafficDays: 7,    adminDays: 30  },
  home_office:     { trafficDays: 14,   adminDays: 90  },
  small_business:  { trafficDays: 30,   adminDays: 365 },
  regulated_hipaa: { trafficDays: 2190, adminDays: 2190 },
  regulated_pci:   { trafficDays: 365,  adminDays: 365 },
};

export function findLogging(site: NormalizedSite, profile: string): Finding[] {
  const findings: Finding[] = [];
  const ret = RETENTION_PROFILES[profile] ?? RETENTION_PROFILES['home_office']!;

  const mgmt = site.settings['mgmt'] as Record<string, unknown> | undefined;
  if (mgmt === undefined) {
    findings.push({
      id: 'LOG-FWD-001', section: 'Logging', severity: 'info', status: 'unknown',
      title: 'Syslog setting: cannot check via live API',
      currentState: 'Syslog forwarding state is not exposed by the API. Check Settings → System → Logging.',
      recommendation: `Forward syslog to an external destination. Retention target: ${ret.adminDays} days.`,
      intentQuestion: 'Is syslog forwarding to an external destination currently configured?',
      evidence: {}, mapsTo: { cis_v8: '8.2', nist_csf: 'DE.AE-3' }, effort: 'medium', impact: 'medium',
    });
  } else if (!mgmt['syslog_host'] && !mgmt['advanced_feature_enabled']) {
    findings.push({
      id: 'LOG-FWD-001', section: 'Logging',
      severity: profile.startsWith('home') ? 'low' : 'medium', status: 'recommendation',
      title: 'Logs not forwarded to external destination',
      currentState: 'All logs live only on the gateway. Gateway loss = log loss.',
      recommendation: `Forward syslog to an external destination. Retention target: ${ret.adminDays} days minimum.`,
      intentQuestion: 'Do you want to set up external log storage?',
      evidence: {}, mapsTo: { cis_v8: '8.2', nist_csf: 'DE.AE-3' }, effort: 'medium', impact: 'medium',
    });
  }

  const dpi = site.settings['dpi'] as Record<string, unknown> | undefined;
  if (dpi && profile.startsWith('home')) {
    const dpiLevel = String(dpi['level'] ?? 'disabled');
    if (['client', 'fingerprint'].includes(dpiLevel)) findings.push({
      id: 'LOG-PRIV-001', section: 'Logging', severity: 'low', status: 'recommendation',
      title: 'Client-level DPI logging may exceed household need',
      currentState: `DPI is set to '${dpiLevel}', retaining per-client browsing metadata.`,
      recommendation: 'Consider aggregate/protocol-only DPI for a home network.',
      intentQuestion: 'Do you actively use the per-client DPI views?',
      evidence: {}, mapsTo: { nist_csf: 'PR.DS-5' }, effort: 'quick', impact: 'low',
    });
  }

  return findings;
}
```

- [ ] **Step 7: Create `src/audit/findings/backup.ts`**

```typescript
import type { Finding, NormalizedSite } from '../types.js';

export function findBackup(site: NormalizedSite, _profile: string): Finding[] {
  const findings: Finding[] = [];
  const autoBackup = site.settings['auto_backup'] as Record<string, unknown> | undefined;

  if (autoBackup === undefined) {
    findings.push({
      id: 'BAK-001', section: 'Backup', severity: 'info', status: 'unknown',
      title: 'Backup setting: cannot check via live API',
      currentState: 'Auto-backup state is not exposed by the API. Check Settings → System → Backup.',
      recommendation: 'Enable daily automatic backups, retention at least 7 days.',
      intentQuestion: 'Is automatic backup currently enabled?',
      evidence: {}, mapsTo: { cis_v8: '11.2', nist_csf: 'PR.IP-4' }, effort: 'quick', impact: 'high',
    });
    return findings;
  }

  if (!autoBackup['enabled']) {
    findings.push({
      id: 'BAK-001', section: 'Backup', severity: 'high', status: 'gap',
      title: 'Automatic backups disabled',
      currentState: 'Controller config backups are not running automatically.',
      recommendation: 'Enable daily automatic backups, retention at least 7 days.',
      intentQuestion: null,
      evidence: {}, mapsTo: { cis_v8: '11.2', nist_csf: 'PR.IP-4' }, effort: 'quick', impact: 'high',
    });
    return findings;
  }

  if ((autoBackup['destination'] ?? 'local') === 'local') findings.push({
    id: 'BAK-002', section: 'Backup', severity: 'medium', status: 'gap',
    title: 'Backups stored only on the gateway itself',
    currentState: 'Auto-backups are saved only to the gateway. If the gateway is lost, the backups go with it.',
    recommendation: 'Add an off-device destination: cloud backup, SMB share, or periodic download. Rule of 3-2-1.',
    intentQuestion: 'Which off-device option fits your setup best?',
    evidence: {}, mapsTo: { cis_v8: '11.3' }, effort: 'medium', impact: 'medium',
  });

  findings.push({
    id: 'BAK-003', section: 'Backup', severity: 'medium', status: 'unknown',
    title: 'Backup restore not verified (Schrödinger backup)',
    currentState: 'Backups are running. Without a tested restore, viability is unknown.',
    recommendation: 'Schedule a quarterly restore test. At minimum: decrypt and open the backup file once a year.',
    intentQuestion: 'Have you ever restored this backup, and when?',
    evidence: {}, mapsTo: { cis_v8: '11.5', nist_csf: 'PR.IP-4' }, effort: 'medium', impact: 'high',
  });

  return findings;
}
```

- [ ] **Step 8: Create `src/audit/findings/apiCoverage.ts`**

```typescript
import type { Finding } from '../types.js';

export function findApiCoverage(clean: Record<string, unknown>): Finding[] {
  const probed = (clean['_endpointsProbed'] ?? []) as Array<Record<string, unknown>>;
  const missing = probed.filter(p => p['status'] === 404 || p['status'] === 0);
  if (!missing.length) return [];
  return [{
    id: 'META-COVERAGE', section: 'Audit scope', severity: 'info', status: 'unknown',
    title: `${missing.length} endpoint(s) not accessible; audit scope limited`,
    currentState: `${missing.length} API endpoints returned 404 or failed. May be due to Network version (need 9.3.43+) or API scope.`,
    recommendation: 'Update UniFi Network to latest stable. For endpoints not in the official API, consider backup-file mode.',
    intentQuestion: null,
    evidence: { missing: missing.map(p => p['name']) },
    mapsTo: {}, effort: 'quick', impact: 'low',
  }];
}
```

- [ ] **Step 9: Run all tests**

```bash
npm test
```

Expected: all enhanced finding tests pass

- [ ] **Step 10: Commit**

```bash
git add src/audit/findings/ src/audit/__tests__/findings/enhanced.test.ts
git commit -m "feat: add enhanced finding modules (wireless, firewall, firmware, logging, backup)"
```

---

## Task 7: `analyze.ts` — pipeline, float-top, profile overrides

**Files:**
- Create: `src/audit/analyze.ts`
- Create: `src/audit/__tests__/analyze.test.ts`

- [ ] **Step 1: Write tests**

Create `src/audit/__tests__/analyze.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import type { Finding } from '../types.js';
import { sortFindings, applyProfileOverrides } from '../analyze.js';

function f(id: string, severity: Finding['severity'] = 'medium'): Finding {
  return {
    id, section: 'Test', severity, status: 'gap',
    title: id, currentState: 'x', recommendation: null, intentQuestion: null,
    evidence: {}, mapsTo: {}, effort: 'quick', impact: 'medium',
  };
}

describe('sortFindings', () => {
  it('VPN-PPTP-001 floats above medium findings', () => {
    const result = sortFindings([f('MEDIUM-001'), f('VPN-PPTP-001', 'critical')]);
    expect(result[0].id).toBe('VPN-PPTP-001');
  });

  it('SEG-001-x floats above low findings', () => {
    const result = sortFindings([f('LOW-001', 'low'), f('SEG-001-x', 'high')]);
    expect(result[0].id).toBe('SEG-001-x');
  });

  it('non-float-top sorted by severity', () => {
    const result = sortFindings([f('L', 'low'), f('H', 'high'), f('M', 'medium')]);
    expect(result.map(x => x.id)).toEqual(['H', 'M', 'L']);
  });
});

describe('applyProfileOverrides', () => {
  it('home profile sets LOG-FWD-001 to low', () => {
    const findings = [f('LOG-FWD-001')];
    applyProfileOverrides(findings, 'home');
    expect(findings[0].severity).toBe('low');
  });

  it('regulated_hipaa sets BAK-001 to critical', () => {
    const findings = [f('BAK-001', 'high')];
    applyProfileOverrides(findings, 'regulated_hipaa');
    expect(findings[0].severity).toBe('critical');
  });

  it('unknown finding id is unchanged', () => {
    const findings = [f('UNKNOWN-999')];
    applyProfileOverrides(findings, 'regulated_hipaa');
    expect(findings[0].severity).toBe('medium');
  });
});
```

- [ ] **Step 2: Run — expect failures**

```bash
npm test -- src/audit/__tests__/analyze.test.ts
```

Expected: `Cannot find module '../analyze.js'`

- [ ] **Step 3: Create `src/audit/analyze.ts`**

```typescript
import type { Finding, FindingModule, NormalizedSite } from './types.js';
import { SEVERITY_ORDER, ALWAYS_TOP_PREDICATES, PROFILE_OVERRIDES } from './constants.js';
import { findSegmentation } from './findings/segmentation.js';
import { findWifi } from './findings/wifi.js';
import { findFirewall } from './findings/firewall.js';
import { findRemoteAccess } from './findings/remoteAccess.js';
import { findDevices } from './findings/devices.js';
import { findWirelessTuning } from './findings/wirelessTuning.js';
import { findFirewallThreats } from './findings/firewallThreats.js';
import { findFirmware } from './findings/firmware.js';
import { findLogging } from './findings/logging.js';
import { findBackup } from './findings/backup.js';
import { findApiCoverage } from './findings/apiCoverage.js';

const MODULES: Array<[string, FindingModule]> = [
  ['segmentation',    findSegmentation],
  ['wifi',            findWifi],
  ['firewall',        findFirewall],
  ['remoteAccess',    findRemoteAccess],
  ['devices',         findDevices],
  ['wirelessTuning',  findWirelessTuning],
  ['firewallThreats', findFirewallThreats],
  ['firmware',        findFirmware],
  ['logging',         findLogging],
  ['backup',          (site, profile) => findBackup(site, profile)],
];

export function isFloatTop(f: Finding): boolean {
  return ALWAYS_TOP_PREDICATES.some(pred => pred(f));
}

export function sortFindings(findings: Finding[]): Finding[] {
  const top = findings.filter(isFloatTop).sort((a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );
  const rest = findings.filter(f => !isFloatTop(f)).sort((a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5) || a.section.localeCompare(b.section)
  );
  return [...top, ...rest];
}

export function applyProfileOverrides(findings: Finding[], profile: string): void {
  const overrides = PROFILE_OVERRIDES[profile] ?? {};
  for (const f of findings) {
    const o = overrides[f.id];
    if (o) Object.assign(f, o);
  }
}

export function analyze(
  sites: NormalizedSite[],
  clean: Record<string, unknown>,
  profile: string,
  onError?: (module: string, site: string, err: unknown) => void,
): Finding[] {
  const findings: Finding[] = [];
  for (const site of sites) {
    for (const [name, fn] of MODULES) {
      try {
        findings.push(...fn(site, profile));
      } catch (err) {
        onError?.(name, site.siteId, err);
      }
    }
  }
  findings.push(...findApiCoverage(clean));
  applyProfileOverrides(findings, profile);
  return sortFindings(findings);
}
```

- [ ] **Step 4: Run all tests**

```bash
npm test
```

Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/audit/analyze.ts src/audit/__tests__/analyze.test.ts
git commit -m "feat: add analyze() pipeline with float-top sorting and profile overrides"
```

---

## Task 8: `collectAll()` function

**Files:**
- Create: `src/audit/collect.ts`
- Create: `src/audit/__tests__/collect.test.ts`

- [ ] **Step 1: Write tests**

Create `src/audit/__tests__/collect.test.ts`:

```typescript
import { describe, it, expect, vi } from 'vitest';
import { extractSites } from '../collect.js';

describe('extractSites', () => {
  it('parses data array shape', () => {
    expect(extractSites({ data: [{ id: 's1', name: 'Home' }] })).toHaveLength(1);
  });
  it('parses plain array shape', () => {
    expect(extractSites([{ id: 's1' }])).toHaveLength(1);
  });
  it('returns [] for unrecognised shape', () => {
    expect(extractSites(null)).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Create `src/audit/collect.ts`**

```typescript
import type { UniFiClient } from './client.js';

const LOCAL_GLOBAL = [
  ['info',  '/proxy/network/integration/v1/info'],
  ['sites', '/proxy/network/integration/v1/sites'],
] as const;

const SITE_SCOPED = [
  ['devices',            '/proxy/network/integration/v1/sites/{id}/devices'],
  ['clients',            '/proxy/network/integration/v1/sites/{id}/clients'],
  ['wlans',              '/proxy/network/integration/v1/sites/{id}/wlans'],
  ['firewall_policies',  '/proxy/network/integration/v1/sites/{id}/firewall-policies'],
  ['firewall_zones',     '/proxy/network/integration/v1/sites/{id}/firewall-zones'],
  ['port_forwards',      '/proxy/network/integration/v1/sites/{id}/port-forwards'],
  ['vpn_configs',        '/proxy/network/integration/v1/sites/{id}/vpn-configs'],
  ['networks',           '/proxy/network/integration/v1/sites/{id}/networks'],
  ['traffic_routes',     '/proxy/network/integration/v1/sites/{id}/traffic-routes'],
] as const;

const CLOUD_ENDPOINTS = [
  ['hosts',         'https://api.ui.com/v1/hosts'],
  ['cloud_sites',   'https://api.ui.com/v1/sites'],
  ['cloud_devices', 'https://api.ui.com/v1/devices'],
] as const;

export function extractSites(sitesResponse: unknown): Record<string, unknown>[] {
  if (Array.isArray(sitesResponse)) return sitesResponse as Record<string, unknown>[];
  if (sitesResponse !== null && typeof sitesResponse === 'object') {
    const r = sitesResponse as Record<string, unknown>;
    for (const key of ['data', 'sites', 'items']) {
      if (Array.isArray(r[key])) return r[key] as Record<string, unknown>[];
    }
  }
  return [];
}

export interface CollectResult {
  [key: string]: unknown;
  _endpointsProbed: Array<{ name: string; path: string; status: number }>;
  _errors: Array<{ endpoint: string; status: number; hint?: string }>;
  _siteCount: number;
}

export async function collectAll(client: UniFiClient, log: (msg: string) => void): Promise<CollectResult> {
  const result: CollectResult = { _endpointsProbed: [], _errors: [], _siteCount: 0 };

  if (client.config.useCloud) {
    for (const [name, url] of CLOUD_ENDPOINTS) {
      log(`GET ${url}`);
      const { status, data } = await client.get(url);
      result._endpointsProbed.push({ name, path: url, status });
      if (status === 200) result[name] = data;
      else if (status === 403) result._errors.push({ endpoint: name, status, hint: 'insufficient scope' });
    }
  } else {
    for (const [name, path] of LOCAL_GLOBAL) {
      log(`GET ${path}`);
      const { status, data } = await client.get(path);
      result._endpointsProbed.push({ name, path, status });
      if (status === 200) result[name] = data;
      else if (status === 403) result._errors.push({ endpoint: name, status, hint: 'key lacks scope' });
    }

    const siteList = extractSites(result['sites']);
    result._siteCount = siteList.length;

    for (const site of siteList) {
      const siteId = String(site['id'] ?? site['_id'] ?? site['name'] ?? '');
      if (!siteId) continue;
      const siteKey = `site_${siteId}`;
      result[siteKey] = { _meta: site };
      for (const [name, pathTpl] of SITE_SCOPED) {
        const path = pathTpl.replace('{id}', siteId);
        log(`GET ${path}`);
        const { status, data } = await client.get(path);
        result._endpointsProbed.push({ name: `${name}@${siteId}`, path, status });
        if (status === 200) (result[siteKey] as Record<string, unknown>)[name] = data;
        else if (status === 403) result._errors.push({ endpoint: `${name}@${siteId}`, status });
        await new Promise(r => setTimeout(r, 100));
      }
    }
  }

  return result;
}
```

- [ ] **Step 3: Run tests**

```bash
npm test
```

Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add src/audit/collect.ts src/audit/__tests__/collect.test.ts
git commit -m "feat: add collectAll() and extractSites()"
```

---

## Task 9: CLI entry point + report renderer

**Files:**
- Create: `src/audit/report.ts`
- Create: `src/cli.ts`

- [ ] **Step 1: Create `src/audit/report.ts`**

```typescript
import type { Finding } from './types.js';

export function renderReport(findings: Finding[], profile: string, endpointsProbed: number, endpointErrors: number): string {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  const lines = [
    '# UniFi Security Advisor - Live Audit Report', '',
    `**Profile:** ${profile}  `,
    `**Findings:** ${findings.length}  `,
    `**By severity:** ${JSON.stringify(counts)}`,
    '',
    `**Endpoints probed:** ${endpointsProbed}  `,
    `**Endpoint errors:** ${endpointErrors}`,
    '', '---', '',
  ];

  for (const f of findings) {
    lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`*${f.section} / ${f.id}*`, '');
    lines.push(`**Current state:** ${f.currentState}`, '');
    if (f.recommendation) lines.push(`**Recommend:** ${f.recommendation}`, '');
    if (f.intentQuestion) lines.push(`**Confirm intent:** ${f.intentQuestion}`, '');
    if (Object.keys(f.mapsTo).length) lines.push(`**Maps to:** ${Object.entries(f.mapsTo).map(([k, v]) => `${k}:${v}`).join(', ')}`, '');
    lines.push('---', '');
  }

  lines.push(
    '## Notes', '',
    '- All secrets replaced with length + sha256 fingerprints before output.',
    '- No API key in any output file or log.',
    '- Only GET (read-only) requests were made.',
    '- Safe to share this report.', '',
    '## Next steps', '',
    '1. **Revoke the API key** at unifi.ui.com → Site Manager → API Keys.',
    '2. Review this report and decide which findings to act on.',
  );

  return lines.join('\n');
}
```

- [ ] **Step 2: Create `src/cli.ts`**

```typescript
#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { UniFiClient } from './audit/client.js';
import { collectAll } from './audit/collect.js';
import { sanitize } from './audit/sanitize.js';
import { normalizeApi } from './audit/normalize.js';
import { analyze } from './audit/analyze.js';
import { renderReport } from './audit/report.js';

async function main() {
  const client = UniFiClient.fromEnv();
  const outputDir = process.env['UNIFI_OUTPUT_DIR'] ?? './audit_output';
  await mkdir(outputDir, { recursive: true });

  const log = (msg: string) => console.log(msg);

  log('='.repeat(60));
  log('UniFi Security Advisor - starting audit');
  log(`Mode: ${client.config.useCloud ? 'cloud (Site Manager)' : 'local'}`);
  if (!client.config.useCloud) log(`Host: ${client.config.host}`);
  log(`Profile: ${client.config.profile}`);
  log('='.repeat(60));

  const raw = await collectAll(client, log);
  log('Sanitizing collected data...');
  const clean = sanitize(raw) as Record<string, unknown>;

  await writeFile(join(outputDir, 'raw_sanitized.json'), JSON.stringify(clean, null, 2));
  log(`Wrote raw_sanitized.json`);

  log('Running findings analysis...');
  const sites = normalizeApi(clean, client.config.profile);
  const findings = analyze(sites, clean, client.config.profile, (mod, site, err) => {
    console.error(`Module ${mod} failed on ${site}: ${err}`);
  });

  await writeFile(join(outputDir, 'findings.json'), JSON.stringify(findings, null, 2));
  log(`Wrote findings.json (${findings.length} findings)`);

  const report = renderReport(
    findings,
    client.config.profile,
    (clean['_endpointsProbed'] as unknown[]).length,
    ((clean['_errors'] as unknown[]) ?? []).length,
  );
  await writeFile(join(outputDir, 'report.md'), report);
  log(`Wrote report.md`);

  log('='.repeat(60));
  log('Done.');
  log('NEXT STEPS');
  log('  1. Review report.md');
  log('  2. Revoke the API key in Site Manager');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
```

- [ ] **Step 3: Run full test suite**

```bash
npm test
```

Expected: all tests pass

- [ ] **Step 4: Verify CLI compiles**

```bash
npx tsc --noEmit
```

Expected: no errors

- [ ] **Step 5: Final commit**

```bash
git add src/audit/report.ts src/cli.ts
git commit -m "feat: add report renderer and CLI entry point — Phase 2a complete"
```
