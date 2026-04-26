---
phase: 01-live-api-audit
fixed_at: 2026-04-26T00:00:00Z
review_path: .planning/phases/01-live-api-audit/01-REVIEW.md
iteration: 1
findings_in_scope: 4
fixed: 4
skipped: 0
status: all_fixed
---

# Phase 01: Code Review Fix Report

**Fixed at:** 2026-04-26
**Source review:** `.planning/phases/01-live-api-audit/01-REVIEW.md`
**Iteration:** 1

**Summary:**
- Findings in scope: 4 (WR-01, WR-02, WR-03, WR-04 — fix_scope: critical_warning)
- Fixed: 4
- Skipped: 0

Test suite status: 207 passed, 0 failed after all fixes (started at 202; 5 new regression tests added).

## Fixed Issues

### WR-01: `correlate_priority_mismatch` uses overly broad `FW-` prefix — false positives on non-port-forward findings

**Files modified:** `src/findings_correlations.py`, `tests/test_correlations.py`
**Commit:** 2ff2bac
**Applied fix:** Replaced the broad `_has_finding_id(findings, "FW-")` prefix check with
`any(f.id.endswith("-PF") or f.id == "FW-002" for f in findings)`. Port-forward findings
are always emitted as `FW-{site_id}-PF` (live-API path) or `FW-002` (parser path); firmware
EOL, auto-update, and geo-filter findings (also starting with `FW-`) no longer trigger the rule.

Added three regression tests to `tests/test_correlations.py`:
- `test_priority_mismatch_no_fire_on_fw_eol_without_port_forwards` — FW-EOL-001 + FW-AUTO-001 + FW-GEO-IN + VPN-MISSING must NOT fire CORR-PRIORITY-001
- `test_priority_mismatch_fires_with_fw_002` — FW-002 + VPN-MISSING must fire
- Existing `test_priority_mismatch_fires` (FW-default-PF) continues to pass

---

### WR-02: `sanitize()` does not recurse into a `list` value under a secret key

**Files modified:** `src/sanitizer.py`, `tests/test_sanitizer.py`
**Commit:** cf80fe2
**Applied fix:** Added an explicit `elif isinstance(v, list)` branch inside the
`if k in SECRET_FIELD_NAMES` block. Each element is handled as follows:
- `str` elements: fingerprinted via `_fingerprint()` (length + sha256 prefix + character-class hints)
- `dict` elements: passed through unchanged (already-sanitized fingerprint dicts — preserves idempotency)
- All other types (int, bool, None, etc.): replaced with `{"type": type(i).__name__, "redacted": True}`

Idempotency verified: `sanitize(sanitize({psk: ["a","b"]})) == sanitize({psk: ["a","b"]})` — on the
second pass the list elements are fingerprint dicts, which hit the `dict` pass-through branch.

Added three regression tests to `tests/test_sanitizer.py`:
- `test_secret_list_elements_are_fingerprinted` — string list elements yield fingerprint dicts, raw values absent from JSON
- `test_secret_list_with_non_string_elements_redacted` — int/None/bool elements yield `{"redacted": True}` markers
- `test_secret_list_idempotent` — `sanitize(sanitize(x)) == sanitize(x)` for list-valued secret fields

---

### WR-03: Missing comment explaining dual `sshEnabled`/`ssh_enabled` check in `_find_devices`

**Files modified:** `src/unifi_audit.py`
**Commit:** 415e039
**Applied fix:** Added a six-line comment above line 712 explaining that this baseline module
reads the raw Integration v1 API dict (camelCase `sshEnabled`) while the adapter maps it to
`ssh_enabled` for the enhanced-module path. The dual check is intentional belt-and-suspenders:
if a future firmware version renames the field and only the adapter is updated, this module
continues to detect SSH via the snake_case fallback. No behavioral change.

---

### WR-04: `_route_vpn_configs` silently discards non-`enabled` fields from earlier configs

**Files modified:** `src/api_to_collections.py`
**Commit:** b1ef452
**Applied fix:** Added a "Known limitation (WR-04)" paragraph to the `_route_vpn_configs`
docstring documenting that when multiple configs share the same protocol key, the last config's
non-enabled fields overwrite the first config's fields (only `enabled` is OR-aggregated correctly).
The docstring explains why this is acceptable for Phase 1 (finding modules only inspect `enabled`)
and specifies the correct fix path for when a future finding module reads other fields.

The behavioral change (Option A: merge instead of replace) was assessed as too risky for automated
fixing given the endpoint has never returned live data (404 on Network 10.3.55) and field names
remain unconfirmed. Documentation-only fix (Option B) applied instead.

---

_Fixed: 2026-04-26_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
