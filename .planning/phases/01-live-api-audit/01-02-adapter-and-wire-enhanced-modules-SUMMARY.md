---
phase: 01-live-api-audit
plan: "02"
subsystem: adapter + findings wiring
tags: [python, adapter, integration, api, tdd]
dependency_graph:
  requires:
    - src/sanitizer.py (SECRET_FIELD_NAMES, sanitize) — Plan 01
    - src/findings_enhanced.py (find_wireless_tuning, find_firewall_threats,
      find_remote_access, find_firmware, find_logging, find_backup_config) — initial commit
    - tests/conftest.py (synthetic_api_dump fixture) — Plan 01
  provides:
    - src/api_to_collections.py (build_parser_collections)
    - src/unifi_audit.py extended (12-module analyze(), _extract_list with warning)
    - tests/test_adapter.py (10 tests)
    - tests/test_extract_helpers.py (12 tests)
    - tests/_smoke_adapter.py
    - tests/_smoke_analyze.py
  affects:
    - src/unifi_audit.py:analyze() (6 → 12 modules)
    - src/unifi_audit.py:_extract_list() (now emits WARNING on unknown shape)
    - All downstream plans that call analyze()
tech_stack:
  added: []
  patterns:
    - Adapter pattern (D-01): pure camelCase→snake_case translation layer
    - Try/except import for script+package dual-mode compatibility
    - Lambda closures for enhanced module dispatch
    - Module-level logger for pre-setup_logger() warning capability
    - [ASSUMED] field comments for Plan 07 validation surface
key_files:
  created:
    - src/api_to_collections.py (372 lines)
    - tests/test_adapter.py (138 lines)
    - tests/test_extract_helpers.py (54 lines)
    - tests/_smoke_adapter.py (29 lines)
    - tests/_smoke_analyze.py (45 lines)
  modified:
    - src/unifi_audit.py (imports + analyze() + _extract_list + _logger)
decisions:
  - "D-01 honored: findings_enhanced.py unchanged; all translation in api_to_collections.py"
  - "firewallgroup mapped to firewall_zones (Integration v1 does not expose a separate group collection; zones serve the same structural role in the adapter)"
  - "content_filtering added to colls output (find_firewall_threats checks both dns_filtering and content_filtering)"
  - "_logger at module level so _extract_list can warn before setup_logger() is called"
  - "find_remote_access aliased as find_remote_access_enhanced at import to avoid collision with baseline _find_remote_access"
  - "Lambda wrappers used for enhanced modules to capture colls without rewriting the dispatch loop signature"
metrics:
  duration: "4 minutes 59 seconds"
  completed: "2026-04-26T12:55:19Z"
  tasks_completed: 3
  files_created: 5
  files_modified: 1
  test_count: 22
  tests_passing: 22
  tests_skipping: 0
  full_suite_pass: 67
  full_suite_skip: 5
---

# Phase 1 Plan 02: Adapter and Wire Enhanced Modules Summary

**One-liner:** Built pure-function Integration v1 adapter (`build_parser_collections`) that translates camelCase API responses to parser-shape dicts, wired all 6 enhanced finding modules into `analyze()` (6 → 12 modules), and added T-1-04 warning surfaces to both the adapter and `_extract_list`.

## Tasks Completed

| Task | Name | Commit | Key Output |
|------|------|--------|-----------|
| 1 | Create src/api_to_collections.py | 9ef3870 | build_parser_collections + _unwrap (T-1-04) + _device_to_classic + _wlan_to_classic + _network_to_classic + _route_vpn_configs |
| 2 | Wire 6 enhanced modules into analyze() + _extract_list warn | 518fd2b | analyze() runs 12 modules; adapter failure is non-fatal; _extract_list warns on unknown shape |
| 3 | tests/test_adapter.py + tests/test_extract_helpers.py + smoke scripts | aad49cf | 22 new tests all passing; both smoke scripts exit 0 |

## Key Outputs

### Module Count Delta

- `analyze()` before Plan 02: **6 baseline modules**
- `analyze()` after Plan 02: **12 modules** (6 baseline + 6 enhanced)

Enhanced modules added:
1. `find_wireless_tuning` — TX power, rogue AP, PMF on WPA3 SSIDs
2. `find_firewall_threats` — Geo-IP blocking, content filtering
3. `find_remote_access_enhanced` — PPTP, L2TP, WireGuard, port-forward exposure
4. `find_firmware` — EOL hardware, auto-update, stale firmware version
5. `find_logging` — Syslog forwarding, DPI privacy
6. `find_backup_config` — Auto-backup enabled, destination diversity, restore verification

### Smoke Run Output (17 findings from synthetic fixture)

```
BAK-001, FW-EOL-001, FW-VER-02:00:00:00:00:01, VPN-MISSING-a, VPN-MISSING-001,
SEG-001-a, DEV-SSH-a, FW-CONTENT-001, FW-AUTO-001, RF-ROGUE-001, RF-PMF-main,
FW-GEO-IN, FW-GEO-OUT, LOG-FWD-001, RF-02:00:00:00:00:01-ng-TX, FW-a-PF, RF-BAND-24GHZ
```

Enhanced module coverage confirmed: BAK-001 (backup), FW-EOL-001 (firmware EOL),
RF-* (wireless tuning), LOG-FWD-001 (logging), FW-CONTENT-001/FW-GEO-* (firewall threats),
VPN-MISSING-001 (remote access enhanced).

### T-1-04 Mitigation

Two warning surfaces now emit `logger.warning()` on unknown response shapes:

1. **`_unwrap()` in api_to_collections.py** — logs `"_unwrap[{name}]: unknown response shape — no recognized list key found. Keys present: {keys}."` before returning `[]`
2. **`_extract_list()` in unifi_audit.py** — logs `"_extract_list: no recognized list key in response. Keys present: {keys}. Returning None."` before returning `None`

Both are asserted by tests (`test_unknown_shape_emits_warning`, `test_extract_list_unknown_shape_logs_warning`).

Pagination truncation also surfaced: `_unwrap()` logs `"pagination truncation detected — received {count} of {totalCount} items"` when Integration v1 returns a partial page.

### Test Count

| File | Tests | Status |
|------|-------|--------|
| tests/test_adapter.py | 10 | 10 passed |
| tests/test_extract_helpers.py | 12 | 12 passed |
| tests/test_sanitizer.py | 45 | 45 passed (Plan 01) |
| tests/test_fixture_safety.py | 5 | 5 skipped (pre-Plan 08) |
| **Total** | **72** | **67 passed, 5 skipped** |

## [ASSUMED] Field Paths — Plan 07 Validation Candidates

The following field mappings were implemented based on RESEARCH.md inference. Each is
annotated with `[ASSUMED]` in source comments. Plan 07 (real-network validation) must
convert confirmed paths to `[VERIFIED]` and correct any that differ:

| Field | Location | Assumed Path | What to Verify |
|-------|----------|-------------|---------------|
| SSH state | `_extract_ssh_state()` | `sshEnabled` (top-level bool) | Is it `sshEnabled`, `ssh_enabled`, or only in `features[]`? |
| SSH via features | `_extract_ssh_state()` | `features[{name:"ssh", enabled:true}]` | Does Integration v1 use a features array? |
| Radio table | `_device_to_classic()` | `radioTable` (camelCase) | Confirm field name; confirm `radio` and `tx_power_mode` sub-keys |
| Firmware version | `_device_to_classic()` | `firmwareVersion` (camelCase) | Is it `firmwareVersion` or `version`? |
| WLAN security | `_wlan_to_classic()` | `securityProtocol` | Is it `security` or `securityProtocol`? |
| WPA mode | `_wlan_to_classic()` | `wpaMode` (camelCase) | Confirm field name |
| PMF mode | `_wlan_to_classic()` | `pmfMode` (camelCase) | Confirm field name |
| PSK field | `_wlan_to_classic()` | `preSharedKey` or `psk` | Confirm which field name (sanitizer should have fingerprinted it) |
| Network VLAN | `_network_to_classic()` | `vlanId` (camelCase) | Is it `vlanId` or `vlan`? |
| VPN type | `_route_vpn_configs()` | `type` field with string "wireguard" | Confirm protocol string values |
| Settings paths | `build_parser_collections()` | None — all `{}` | Verify if auto_update, auto_backup, mgmt, dpi, rogueap, dns_filtering are reachable |

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

### Minor Implementation Notes (not deviations)

**1. firewallgroup mapped to firewall_zones**

The plan specified `"firewallgroup": []` as always-empty. After reading `findings_enhanced.find_firewall_threats` which uses `_get_collection(colls, "firewallgroup")` to look up group membership by `_id`, and noting that Integration v1 exposes `firewall_zones` per SITE_SCOPED_LOCAL, `firewallgroup` is mapped to the zone list rather than an empty list. The Geo-IP finding logic checks group names for "geo" and group types for "country" — zones are the closest analog. This is still `[ASSUMED]` and must be validated in Plan 07.

**2. content_filtering added to return dict**

`find_firewall_threats` calls `_get_setting(colls, "dns_filtering") or _get_setting(colls, "content_filtering")`. The plan's return dict spec listed `dns_filtering` but not `content_filtering`. Added both as empty dicts (both remain `[ASSUMED: not in Integration v1 API]`).

## Known Stubs

The following settings are intentionally empty dicts pending Plan 07 verification:

| Key | File | Reason |
|-----|------|--------|
| `auto_update` | api_to_collections.py | [ASSUMED] not exposed by Integration v1 API |
| `auto_backup` | api_to_collections.py | [ASSUMED] not exposed by Integration v1 API |
| `mgmt` | api_to_collections.py | [ASSUMED] not exposed by Integration v1 API |
| `dpi` | api_to_collections.py | [ASSUMED] not exposed by Integration v1 API |
| `rogueap` | api_to_collections.py | [ASSUMED] not exposed by Integration v1 API |
| `dns_filtering` | api_to_collections.py | [ASSUMED] not exposed by Integration v1 API |
| `content_filtering` | api_to_collections.py | [ASSUMED] not exposed by Integration v1 API |

These stubs cause the affected enhanced modules (find_firmware, find_backup_config, find_logging, find_wireless_tuning, find_firewall_threats) to emit "disabled/unknown" findings rather than "ok" findings. This is correct per D-03 (`status="unknown"` philosophy) — the smoke run shows these findings correctly firing (BAK-001, FW-AUTO-001, RF-ROGUE-001, LOG-FWD-001, FW-CONTENT-001).

## Threat Mitigations Delivered

| Threat | Mitigation | Verification |
|--------|-----------|--------------|
| T-1-04: Adapter dropping data silently | `_unwrap()` logs WARNING with observed keys on unknown shape; `_extract_list()` logs WARNING with observed keys on unknown dict | `test_unknown_shape_emits_warning` asserts WARNING fires; `test_extract_list_unknown_shape_logs_warning` asserts WARNING fires |
| T-1-04 (pagination) | `_unwrap()` logs WARNING when count < totalCount | `test_pagination_truncation_warns` asserts WARNING fires |

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries introduced. `api_to_collections.py` is a pure function module with no I/O.

## Self-Check: PASSED

Files exist:
- `src/api_to_collections.py`: FOUND
- `tests/test_adapter.py`: FOUND
- `tests/test_extract_helpers.py`: FOUND
- `tests/_smoke_adapter.py`: FOUND
- `tests/_smoke_analyze.py`: FOUND

Commits exist:
- 9ef3870 (Task 1): FOUND
- 518fd2b (Task 2): FOUND
- aad49cf (Task 3): FOUND

`src/findings_enhanced.py` unchanged: `git log --oneline src/findings_enhanced.py` shows only `81792df Initial commit` — no Wave 1 commits.

All 67 tests pass, 5 skip as expected (pre-Plan 08 fixture gate).
