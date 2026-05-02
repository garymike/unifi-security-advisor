# Sample Fixtures

Anonymized data fixtures for offline testing without a live UniFi controller.

## fixture-local-api.json

**Source:** Real Cloud Gateway Fiber (UCG Fiber + U7 Pro AP) running UniFi Network on the local Network Integration API.

**What it represents:**
- 1 site, 2 devices, 8 clients, 2 networks
- UCG Fiber (firmware 5.0.16) + U7 Pro (firmware 8.5.21) — current hardware, no EOL findings expected
- 2 networks (Primary VLAN 1, IoT VLAN 2) — segmented, SEG-001 will NOT fire
- 6 endpoints return 404 (wlans, firewall_policies, firewall_zones, port_forwards, vpn_configs, traffic_routes) — META-COVERAGE finding expected
- No VPN configs, no firewall policies — expected findings: VPN-MISSING-001 (if port forwards present), geo-IP recommendations

**Anonymized:** site UUID, device/client MACs, IPs, and names replaced. Device models and firmware versions preserved — they matter for EOL and firmware findings.

**Expected findings when analyzed with `home_office` profile:**
- `META-COVERAGE` (info/unknown) — 6 endpoints not accessible
- `LOG-FWD-001` (info/unknown) — syslog not visible via API
- `BAK-001` (info/unknown) — backup not visible via API
- `FW-AUTO-001` (info/unknown) — auto-update not visible via API
- `RF-ROGUE-001` (info/unknown) — rogue AP setting not visible via API
- `FW-CONTENT-001` (info/unknown) — DNS filtering not visible via API

**Usage:**

```typescript
import { normalizeApi } from '../src/audit/normalize.js';
import { analyze } from '../src/audit/analyze.js';

const raw = JSON.parse(fs.readFileSync('samples/fixture-local-api.json', 'utf8'));
const sites = normalizeApi(raw, 'home_office');
const findings = analyze(sites, raw, 'home_office');
```
