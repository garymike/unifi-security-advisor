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

---

## Profile-scale fixtures

Synthetic (not real-network-derived) live-API-shaped fixtures covering the remaining profile
labels used in code (`home`, `small_business`, `regulated_hipaa`, `regulated_pci`), per the
testing-fixture requirements in `CLAUDE.md`. All follow the same 404-gap pattern as
`fixture-local-api.json`: the Network Integration API v1 does not yet expose `wlans`,
`firewall-policies`, `firewall-zones`, `port-forwards`, `vpn-configs`, or `traffic-routes`, so
those collections are always empty and `META-COVERAGE` always fires. Exercised and asserted on
in `src/audit/__tests__/fixtures.test.ts` — run `npm test` to regenerate expected output if a
finding module changes.

### fixture-home.json (profile: `home`)

1 site, gateway + 1 AP (single-AP), 3 clients, 1 flat network (no VLAN segmentation).

**Expected with `home` profile:** `SEG-001` (high/gap — flat network), `FW-GEO-IN`/`FW-GEO-OUT`
(low), `LOG-FWD-001` (low/unknown — home profile downgrades this from the module's default
info), `META-COVERAGE`, `BAK-001`, `FW-CONTENT-001`, `FW-AUTO-001`, `RF-BAND-24GHZ`,
`RF-ROGUE-001` (all info/unknown-or-recommendation — not visible via live API). No EOL,
outdated-firmware, SSH, or high-TX-power findings — clean, current hardware.

### fixture-small-business.json (profile: `small_business`)

1 site, gateway + 3 APs (multi-AP) + 1 controller, 12 clients, 3 VLANs (staff/guest/IoT —
segmented, so `SEG-001` does not fire). Deliberately mixes in one EOL access point
(`UAP-AC-LITE`, firmware `5.2.3`) and one EOL-warning controller (`UCK-G2`) to exercise the
firmware/hardware-age findings, and sets that EOL AP's TX power to `high` on both radios.

**Expected with `small_business` profile:** `FW-EOL-001` (high/gap), `FW-EOL-002`
(medium/recommendation), `FW-VER-<mac>` (high/gap — firmware major version < 7),
`RF-<mac>-ng-TX` + `RF-<mac>-na-TX` (low — high TX power), `DEV-SSH` (medium — gateway has SSH
enabled), `FW-GEO-IN`/`FW-GEO-OUT` (low), `RF-BAND-24GHZ`, plus the same always-present
API-visibility gaps as the other fixtures. No `small_business` entry exists in
`PROFILE_OVERRIDES`, so `LOG-FWD-001`/`BAK-001` stay at their module defaults (info/unknown).

### fixture-regulated.json (profiles: `regulated_hipaa` and `regulated_pci`)

1 site simulating a small clinic — gateway + 2 APs, current firmware, no SSH, 3 VLANs
(staff/guest/facility devices — segmented). One dataset, analyzed under both regulated
profiles to show how the same underlying network produces different severities purely from
`PROFILE_OVERRIDES`:

- **`regulated_hipaa`:** `BAK-001` escalates to **critical** (untested backup posture is
  unacceptable for PHI), `LOG-FWD-001` escalates to **high**. `FW-GEO-IN` stays at the
  module's default low (no hipaa override for it).
- **`regulated_pci`:** `FW-GEO-IN` escalates to **medium**, `LOG-FWD-001` escalates to
  **high**. `BAK-001` stays at the module's default info/unknown (no pci override for it).

Both: no `SEG-001` (segmented), plus the standard API-visibility gaps.
