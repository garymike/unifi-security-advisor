---
phase: 01-live-api-audit
plan: 07
type: execute
wave: 6
depends_on: [06]
files_modified:
  - src/api_to_collections.py
  - src/unifi_audit.py
  - tests/fixtures/captured_real_network_run.md
autonomous: false
requirements:
  - REQ-validation-real-network
  - REQ-validation-api-response-shapes
  - REQ-validation-network-version-compat
  - REQ-validation-ssl-self-signed
requirements_addressed:
  - REQ-validation-real-network
  - REQ-validation-api-response-shapes
  - REQ-validation-network-version-compat
  - REQ-validation-ssl-self-signed
threat_refs: [T-1-02]
tags: [validation, real-network, manual, fixtures]

user_setup:
  - service: ubiquiti-unifi
    why: "Real-network validation requires the user's actual UniFi controller (≥ 9.3.43)"
    env_vars:
      - name: UNIFI_API_KEY
        source: "unifi.ui.com → Site Manager → API Keys (or local controller → Settings → Control Plane → Integrations); use shortest expiration available (1 day default per C-cred-009)"
      - name: UNIFI_HOST
        source: "Local IP/hostname of the UniFi controller (e.g., 192.168.1.1)"
      - name: UNIFI_PROFILE
        source: "Optional; one of home / home_office / small_business / regulated_hipaa / regulated_pci. Defaults to home_office"
      - name: UNIFI_VERIFY_SSL
        source: "Optional; defaults to false for local mode (self-signed certs). Set to 'true' to enforce verification"
    dashboard_config:
      - task: "Generate API key with shortest expiration (1 day)"
        location: "unifi.ui.com → Site Manager → API Keys"
      - task: "Confirm Network app is at version ≥ 9.3.43 (Integration API requires it)"
        location: "Settings → System → Updates"

must_haves:
  truths:
    - "unifi_audit.py runs end-to-end against ≥ one real UniFi network ≥ 9.3.43 without raising"
    - "audit_output/raw_sanitized.json is produced and contains no raw secrets"
    - "audit_output/findings.json contains findings from baseline modules (segmentation/wifi/firewall/remote_access/devices/api_coverage)"
    - "audit_output/findings.json contains the 3 unknown findings (MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001)"
    - "Tagged-secret round trip on the captured raw_sanitized.json passes (no raw secrets present)"
    - "SSL self-signed default is exercised (UNIFI_VERIFY_SSL unset, local controller, no TLS errors)"
    - "Adapter [ASSUMED] field paths are now confirmed [VERIFIED] or [DIVERGENT] based on actual response shapes"
    - "tests/fixtures/raw_sanitized.json is captured (gitignored — local user copy only); samples-bound version is created in Plan 08"
    - "tests/fixtures/captured_real_network_run.md documents observed shapes, [VERIFIED]/[DIVERGENT] field paths, and any adapter fixes applied"
  artifacts:
    - path: "tests/fixtures/captured_real_network_run.md"
      provides: "Observed real-network response shapes; verifies/refutes the A1-A8 assumptions from RESEARCH.md"
    - path: "src/api_to_collections.py"
      provides: "Adapter with [ASSUMED] tags converted to [VERIFIED] or [DIVERGENT] based on real responses; any divergent field path is corrected"
  key_links:
    - from: "tests/fixtures/captured_real_network_run.md"
      to: ".planning/phases/01-live-api-audit/01-RESEARCH.md"
      via: "Each A1-A8 assumption is referenced and resolved"
      pattern: "A1|A2|A3|A4|A5|A6|A7|A8"
---

<objective>
Run unifi_audit.py against a real UniFi controller (≥ 9.3.43) to validate the entire Phase 1 pipeline end-to-end. This is a CHECKPOINT plan — only the user has access to a real controller. The executor walks the user through the run, captures the resulting raw_sanitized.json into tests/fixtures/ (gitignored), inspects the captured shapes against the [ASSUMED] field paths in RESEARCH.md, and updates src/api_to_collections.py to convert [ASSUMED] → [VERIFIED] or [DIVERGENT] (with the correct path) for each.

After this plan: REQ-validation-real-network, REQ-validation-api-response-shapes, REQ-validation-network-version-compat, and REQ-validation-ssl-self-signed are demonstrated with empirical evidence. Plan 08 then takes the captured fixture, anonymizes it further (MAC, IP, hostname, device names per RESEARCH.md §"Fixture Anonymization Strategy"), and commits the safe canonical version under samples/fixtures/.

Output:
- A captured `tests/fixtures/raw_sanitized.json` (the user's copy, gitignored)
- `tests/fixtures/captured_real_network_run.md` documenting observed shapes
- `src/api_to_collections.py` patches: each `[ASSUMED]` comment becomes `[VERIFIED]` (path correct) or `[DIVERGENT]` with the corrected mapping
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/REQUIREMENTS.md
@.planning/phases/01-live-api-audit/01-CONTEXT.md
@.planning/phases/01-live-api-audit/01-RESEARCH.md
@.planning/phases/01-live-api-audit/01-VALIDATION.md
@.planning/phases/01-live-api-audit/01-06-pipeline-smoke-suite-PLAN.md
@CLAUDE.md
@docs/05-credential-handling.md
</context>

<tasks>

<task type="checkpoint:human-action" gate="blocking">
  <name>Task 1: User runs unifi_audit.py against their real UniFi controller</name>
  <files>tests/fixtures/raw_sanitized.json (captured by user; gitignored)</files>
  <action>This is a checkpoint:human-action task � see <how-to-verify> for full step-by-step user instructions. The executor presents the steps; the user runs them on their machine; the user reports back via <resume-signal>.</action>
  <verify>User confirms via the resume-signal options below; outputs are inspected during the resume.</verify>
  <done>User has run unifi_audit.py against a real UniFi controller; tests/fixtures/raw_sanitized.json exists; API key has been revoked; user resumed with one of the documented signals.</done>
  <what-built>
    All Phase 1 code (Plans 01-06) is in place:
    - sanitizer.py with snake_case + camelCase secret-field coverage
    - api_to_collections.py adapter (with [ASSUMED] field paths flagged)
    - unifi_audit.py with 12 finding modules wired, _correlate_findings, _emit_unknown_always_top, _apply_float_top, profile-weighted ranking
    - Full pytest suite green; sanitizer coverage ≥ 95%
  </what-built>
  <how-to-verify>
**This is a manual step that requires your real UniFi controller.** The executor cannot run this; only you have access to your network.

### Step 1 — Generate a short-lived API key

1. Log in to https://unifi.ui.com → Site Manager → API Keys (or local controller → Settings → Control Plane → Integrations).
2. Create a new key. **Set the expiration to the shortest available option (1 day per C-cred-009).** Name it something recognizable like `phase1-validation-2026-04-25`.
3. Copy the key value. **Do NOT paste it into chat or any other UI** — only into the env var below in your local terminal.

### Step 2 — Verify your Network app version is ≥ 9.3.43

1. UniFi Network → Settings → System → Updates. Note the version. The Integration API needs ≥ 9.3.43.
2. If the version is older, the audit will hit 404 on most endpoints (graceful skip — confirms REQ-validation-network-version-compat). Either upgrade or note the older-version behaviour for the report.

### Step 3 — Set environment variables (local terminal only)

```bash
export UNIFI_API_KEY='<paste your key here>'
export UNIFI_HOST='192.168.1.1'   # your controller IP/hostname
# Optional:
export UNIFI_PROFILE='home_office'  # or home / small_business / regulated_*
# Leave UNIFI_VERIFY_SSL unset to test the local self-signed default (verify_ssl=False)
```

### Step 4 — Install runtime dependencies and run

```bash
cd C:/_dev/unifi-security-advisor
pip install requests
python src/unifi_audit.py
```

### Step 5 — Verify outputs

After the run completes, you should see:

```
audit_output/
├── audit.log               # endpoint URLs + status codes only — NO key, NO response bodies
├── raw_sanitized.json      # all API responses with secrets fingerprinted
├── findings.json           # structured findings list
└── report.md               # human-readable report
```

Run the verification checks (the executor will paste these commands for you):

```bash
# 1. No exceptions raised — confirmed by exit code 0
echo "Exit code: $?"

# 2. raw_sanitized.json contains only fingerprint dicts under secret keys (no raw strings).
#    The fixture-safety test will confirm this in Plan 08; for now, manually:
python -c "
import json
data = json.loads(open('audit_output/raw_sanitized.json').read())
import sys; sys.path.insert(0, 'src')
from sanitizer import SECRET_FIELD_NAMES

def walk(o, path=''):
    if isinstance(o, dict):
        for k, v in o.items():
            new = f'{path}.{k}' if path else k
            yield (new, k, v)
            yield from walk(v, new)
    elif isinstance(o, list):
        for i, x in enumerate(o):
            yield from walk(x, f'{path}[{i}]')

leaks = [(p, repr(v)[:30]) for p, k, v in walk(data) if k in SECRET_FIELD_NAMES and isinstance(v, str)]
print(f'Raw-secret leaks under known field names: {len(leaks)}')
for p, v in leaks[:10]:
    print(f'  LEAK at {p}: {v}')
"

# 3. findings.json contains the 3 unknown findings
python -c "
import json
findings = json.loads(open('audit_output/findings.json').read())
ids = [f['id'] for f in findings]
print(f'Total findings: {len(findings)}')
print(f'Has MFA-UNKNOWN-001: {\"MFA-UNKNOWN-001\" in ids}')
print(f'Has CRED-DEFAULT-001: {\"CRED-DEFAULT-001\" in ids}')
print(f'Has WAN-MGMT-001: {\"WAN-MGMT-001\" in ids}')
"

# 4. SSL self-signed default exercised (UNIFI_VERIFY_SSL unset on local mode):
grep -i "ssl" audit_output/audit.log
# Expected: no TLS error stack traces; possibly an InsecureRequestWarning suppressed message

# 5. audit.log contains no API key
grep -F "$UNIFI_API_KEY" audit_output/audit.log && echo "FAIL: key in log!" || echo "OK: key not in log"
```

### Step 6 — Copy raw_sanitized.json into tests/fixtures/

```bash
mkdir -p tests/fixtures
cp audit_output/raw_sanitized.json tests/fixtures/raw_sanitized.json
```

This file stays gitignored (it's still your real network data, just sanitized for secrets — but contains MAC addresses, hostnames, and other identifying data). Plan 08 takes this file, anonymizes the PII, and commits the safe version to samples/fixtures/.

### Step 7 — Revoke the API key

Per `C-cred-009`: revoke the key NOW that the run is complete.

1. unifi.ui.com → Site Manager → API Keys → revoke the key you just used.
  </how-to-verify>
  <resume-signal>
Reply with one of:
- `"completed"` — Run was successful; tests/fixtures/raw_sanitized.json exists; no leaks; key revoked. Include the output of Step 5 verification commands.
- `"older-version"` — Network app < 9.3.43; the run produced 404s for most endpoints. Include the audit.log tail showing the 404 pattern; this satisfies REQ-validation-network-version-compat (graceful 404 skip).
- `"failed: <reason>"` — Run raised an exception. Paste the traceback. Executor will diagnose and fix in a follow-up commit.
- `"deferred"` — User cannot run this right now. Plan 07/08 are blocked until this completes.
  </resume-signal>
</task>

<task type="auto">
  <name>Task 2: Document observed response shapes in tests/fixtures/captured_real_network_run.md</name>
  <files>tests/fixtures/captured_real_network_run.md</files>
  <read_first>
    - tests/fixtures/raw_sanitized.json (just captured by user in Task 1)
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Assumptions Log" — A1 through A8; §"API Response Shapes")
    - src/api_to_collections.py (every `[ASSUMED]` comment that A1-A8 references)
  </read_first>
  <behavior>
    - The markdown file documents every observed top-level key in raw_sanitized.json
    - For each [ASSUMED] field path in src/api_to_collections.py, the doc states VERIFIED, DIVERGENT, or UNKNOWN (endpoint not exposed) with the actual observed path
    - Includes the device, wlan, network, port_forward, vpn_config, firewall_policy field names that were observed
    - Notes any unknown response shapes that the adapter logged WARN about during the run
    - Notes any pagination truncation warnings (count < totalCount)
    - Notes whether sshEnabled / radioTable / firmwareVersion / etc. are top-level or nested
  </behavior>
  <action>
Open `tests/fixtures/raw_sanitized.json` (the user's captured file). Walk its structure and produce `tests/fixtures/captured_real_network_run.md` with the following sections.

The file template (fill in the `<observed>` placeholders by reading the actual JSON):

```markdown
# Phase 1 Real-Network Validation Capture

**Captured:** <date of Task 1 completion>
**Network version:** <from raw_sanitized.json's info endpoint, e.g. "9.4.12">
**Profile used:** <from UNIFI_PROFILE env at run time>
**Site count:** <number of site_<id> top-level keys in raw_sanitized.json>

## Top-Level Keys Observed

| Key | Type | Notes |
|-----|------|-------|
| _endpoints_probed | list[dict] | <count> entries |
| _errors | list[dict] | <count> entries |
| _site_count | int | <number> |
| info | dict | <observed shape> |
| sites | dict|list | <observed shape> |
| site_<id> | dict | <list per-site key here> |

## Per-Site Endpoint Status

For each site, list which endpoints returned 200 vs 404 vs 403:

| Endpoint | Status | Notes |
|----------|--------|-------|
| devices  | 200/404/403 | Field names observed: <camelCase keys> |
| clients  | 200/404/403 | |
| wlans    | 200/404/403 | |
| networks | 200/404/403 | |
| firewall_policies | 200/404/403 | |
| firewall_zones | 200/404/403 | |
| port_forwards | 200/404/403 | |
| vpn_configs | 200/404/403 | |
| traffic_routes | 200/404/403 | |

## A1 — SSH state field path [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed in adapter:** `sshEnabled` top-level OR `features[].name == "ssh"` with `enabled` flag.
**Observed:** <document the actual path; if neither was present, mark UNKNOWN and note that find_devices may produce no findings until the adapter is updated>

## A2 — radio_table field path [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed:** `radioTable` (camelCase) OR `radio_table` (snake_case) on the device object.
**Observed:** <actual path>

## A3 — Settings-level data availability [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed:** Integration v1 does NOT expose `auto_update`, `auto_backup`, `mgmt`, `rogueap`, `dns_filtering` settings.
**Observed:** <list any settings-style data actually present; if any of these turn out to be exposed, the adapter should be updated>

## A4 — WLAN field names [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed:** `security`, `wpaMode`/`wpa_mode`, `pmfMode`/`pmf_mode` on WLAN objects.
**Observed:** <actual field names>

## A5 — Network purpose values [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed:** `purpose` field with values `corporate`/`guest`/`vlan-only`.
**Observed:** <actual values; if "lan"/"vlan-only" instead of "corporate", the SEG-001 detection logic in baseline _find_segmentation needs adjustment>

## A6 — Firmware version field name [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed:** `version` OR `firmwareVersion`.
**Observed:** <actual field name>

## A7 — Port-forward enabled flag [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed:** `enabled` boolean on port-forward object.
**Observed:** <actual field>

## A8 — VPN config protocol field [VERIFIED|DIVERGENT|UNKNOWN]

**Assumed:** `type` OR `protocol` field on vpn-config object with values `pptp`/`l2tp`/`wireguard`/`openvpn`.
**Observed:** <actual field and values>

## Adapter [ASSUMED] → [VERIFIED]/[DIVERGENT] Conversion

For each `[ASSUMED]` comment in src/api_to_collections.py, record the resolution:

| Comment Location | Assumption | Resolution | Action Required |
|------------------|------------|------------|-----------------|
| _extract_ssh_state docstring | Path varies | <VERIFIED/DIVERGENT/UNKNOWN> | <if DIVERGENT: patch the function in Task 3; if UNKNOWN: leave as-is> |
| _device_to_classic radio_table | radioTable nested or absent | <res> | <action> |
| _wlan_to_classic field names | security/wpaMode/pmfMode | <res> | <action> |
| _network_to_classic purpose | corporate/guest/vlan-only | <res> | <action> |
| Settings-level dicts (auto_update etc.) | Not exposed | <res> | <action> |
| _route_vpn_configs proto values | pptp/l2tp/wireguard/openvpn | <res> | <action> |

## Adapter Warnings Observed

Tail of audit.log entries where the adapter logged WARN (per Plan 02 T-1-04 mitigation):

```
<paste any "Adapter._unwrap" or "_extract_list" WARN lines>
```

## Pagination

| Endpoint | count | totalCount | Truncation? |
|----------|-------|------------|-------------|
| <endpoint> | N | M | yes/no |

If any truncation observed: file a backlog item to add pagination loop in collect_all().

## SSL Self-Signed (REQ-validation-ssl-self-signed)

- UNIFI_VERIFY_SSL was unset → cfg["verify_ssl"] = False (local default)
- TLS handshake: <succeeded with no warnings | succeeded with InsecureRequestWarning suppressed>
- No TLS errors raised: <yes/no>

## Findings Summary

| Section | Count | Notable IDs |
|---------|-------|-------------|
| Segmentation | <n> | SEG-001-<site> |
| Wi-Fi | <n> | WIFI-... |
| Firewall | <n> | FW-... |
| Remote access | <n> | VPN-... |
| Admin | <n> | DEV-SSH-, MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001 |
| Wireless tuning | <n> | RF-... |
| Firmware | <n> | FW-EOL-001, FW-AUTO-001, FW-VER-... |
| Logging | <n> | LOG-FWD-001 |
| Backup | <n> | BAK-001/002/003 |
| Risk correlation | <n> | CORR-PIVOT-001, CORR-KEYS-001, CORR-PRIORITY-001 |

Always-top findings present at positions 0-N: <list IDs in order>

## Acceptance Bar Sign-Off (from VALIDATION.md)

- [x] 1. unifi_audit.py runs end-to-end against a real UniFi network ≥ 9.3.43 without raising
- [x] 2. raw_sanitized.json survives tagged-secret round-trip (no raw secrets)
- [x] 3. pytest -q tests/ passes against the canonical fixture (note: fixture committed in Plan 08)
- [x] 4. All 12 finding modules produce a list (empty acceptable for API-limited paths)
- [x] 5. Always-top override produces 3 unknown Findings + correctly orders detectable always-top
- [x] 6. At least 1 compound finding fires on a constructed test case (test_correlations.py covers this)
- [x] 7. src/sanitizer.py imported by both audit and parser (no duplicates)
- [x] 8. Coverage on src/sanitizer.py ≥ 95%

## Next Step

Plan 08 takes `tests/fixtures/raw_sanitized.json`, applies the additional anonymization (MAC, IP, hostname, device-name pass per RESEARCH.md §"Fixture Anonymization Strategy"), and commits the result to `samples/fixtures/api_dump_home_office.json`.
```

Fill in every `<placeholder>` from the actual `tests/fixtures/raw_sanitized.json` content. The doc is the empirical record of what the API actually exposed at run time.
  </action>
  <verify>
    <automated>test -f tests/fixtures/captured_real_network_run.md && grep -c "VERIFIED\|DIVERGENT\|UNKNOWN" tests/fixtures/captured_real_network_run.md | awk '{exit ($1 < 6)}'</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/fixtures/captured_real_network_run.md` exists
    - File contains at least 6 of: VERIFIED, DIVERGENT, UNKNOWN markers (one per A1-A6 minimum)
    - Document references each of A1-A8 from RESEARCH.md
    - Document includes a Findings Summary table with counts
    - Document includes a SSL/TLS section
    - Document includes the Acceptance Bar checklist
  </acceptance_criteria>
  <done>Capture document is a complete record of the real-network run; every adapter assumption resolved or flagged for follow-up.</done>
</task>

<task type="auto">
  <name>Task 3: Patch src/api_to_collections.py to convert [ASSUMED] → [VERIFIED] or [DIVERGENT]</name>
  <files>src/api_to_collections.py</files>
  <read_first>
    - tests/fixtures/captured_real_network_run.md (Task 2 output)
    - src/api_to_collections.py (current state with [ASSUMED] tags)
    - tests/test_adapter.py (tests that may need to be expanded for newly-known shapes)
  </read_first>
  <behavior>
    - Every [ASSUMED] comment in src/api_to_collections.py is now [VERIFIED] (path correct) or [DIVERGENT] (path corrected based on real response) or [UNKNOWN] (endpoint not exposed by Integration v1 — no change to adapter, but comment updated)
    - If a DIVERGENT case requires a new field-mapping, the adapter is updated (e.g., if SSH state is actually under `device.config.sshEnabled` instead of `device.sshEnabled`, add the new path in _extract_ssh_state)
    - All existing tests still pass (pytest -q tests/)
    - If a new field path was added, a new test in tests/test_adapter.py covers it
  </behavior>
  <action>
For each row in the "Adapter [ASSUMED] → [VERIFIED]/[DIVERGENT] Conversion" table from Task 2:

**Case A — [VERIFIED]:** Update the comment. Example before:

```python
# [ASSUMED] field path - validate against real fixture.
def _extract_ssh_state(device: dict) -> bool:
```

After:

```python
# [VERIFIED 2026-04-25] sshEnabled is a top-level boolean per real UniFi 9.4.12 response.
def _extract_ssh_state(device: dict) -> bool:
```

**Case B — [DIVERGENT]:** Update the comment AND fix the implementation. Example before:

```python
# [ASSUMED] WLAN field names - validate in Plan 07.
def _wlan_to_classic(w: dict) -> dict:
    return {
        "security": (w.get("security") or w.get("securityProtocol") or ""),
        ...
    }
```

If real responses use `securityType` instead, update to:

```python
# [DIVERGENT 2026-04-25] WLAN field is `securityType`, not `security`/`securityProtocol`.
# Updated per tests/fixtures/captured_real_network_run.md A4.
def _wlan_to_classic(w: dict) -> dict:
    return {
        "security": (w.get("securityType") or w.get("security") or w.get("securityProtocol") or ""),
        ...
    }
```

Add a new test to tests/test_adapter.py:

```python
def test_wlan_security_type_field_mapped():
    """Regression for A4 DIVERGENT: real API uses securityType, not security."""
    r = build_parser_collections({
        "site_a": {"wlans": {"data": [{"name": "x", "enabled": True, "securityType": "wpa3"}]}}
    })
    assert r["wlanconf"][0]["security"] == "wpa3"
```

**Case C — [UNKNOWN]:** Update the comment to `[UNKNOWN 2026-04-25]` indicating the endpoint is not exposed; no implementation change needed (adapter already returns empty for that path, which is correct per D-03).

After ALL [ASSUMED] tags are resolved:

```bash
# Confirm no [ASSUMED] tags remain in the adapter
grep -c "\[ASSUMED" src/api_to_collections.py
# Should return 0

# Confirm replacement tags are present
grep -c "\[VERIFIED\|\[DIVERGENT\|\[UNKNOWN" src/api_to_collections.py
# Should return ≥ the number of original [ASSUMED] tags

# Run full test suite
pytest -q tests/
```

If a divergent path required adapter logic changes, add corresponding tests AND update tests/fixtures/captured_real_network_run.md to mark "Action Required" rows as DONE.
  </action>
  <verify>
    <automated>grep -c "\[ASSUMED" src/api_to_collections.py | awk '{exit ($1 != 0)}' && pytest -q tests/</automated>
  </verify>
  <acceptance_criteria>
    - `grep -c "\[ASSUMED" src/api_to_collections.py` returns 0 (every assumption resolved)
    - `grep -c "\[VERIFIED\|\[DIVERGENT\|\[UNKNOWN" src/api_to_collections.py` returns ≥ 6 (one per A1-A6 minimum, more if A7/A8 covered)
    - `pytest -q tests/` exits 0 (no regressions)
    - Any DIVERGENT case has a corresponding new test in tests/test_adapter.py
    - tests/fixtures/captured_real_network_run.md "Action Required" column updated with DONE markers
  </acceptance_criteria>
  <done>Adapter assumptions resolved against empirical evidence; field-path divergences fixed and covered by tests; full suite green.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User's controller → user's machine | The API key transits ONLY between the user's machine and their controller. No telemetry. No relay. The audit.log never contains the key. |
| Captured fixture in tests/fixtures/ | Real-network captures may contain MAC addresses, hostnames, etc. — kept gitignored. Plan 08 produces the safe-to-commit version. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-1-02 | Information Disclosure | audit.log during real-network run | mitigate | The static guard from Plan 06 (test_no_credential_leak.py) already prevents response.text logging. The user's manual verification in Task 1 Step 5 confirms `grep -F "$UNIFI_API_KEY" audit_output/audit.log` returns no matches. |
</threat_model>

<verification>
After all tasks complete:

```bash
# Adapter assumptions all resolved
grep -c "\[ASSUMED" src/api_to_collections.py    # → 0
grep -c "\[VERIFIED" src/api_to_collections.py   # ≥ several
grep -c "\[DIVERGENT" src/api_to_collections.py  # 0 or several
grep -c "\[UNKNOWN" src/api_to_collections.py    # 0 or several

# Capture document exists
test -f tests/fixtures/captured_real_network_run.md

# Captured raw fixture exists (gitignored, user's local only)
test -f tests/fixtures/raw_sanitized.json

# Full suite green
pytest -q tests/
```
</verification>

<success_criteria>
- User has run unifi_audit.py against a real UniFi controller ≥ 9.3.43 without exceptions
- audit_output/raw_sanitized.json contains no raw secrets (manual verification + Plan 08 fixture-safety gate confirms)
- The 3 unknown findings are present in findings.json
- tests/fixtures/captured_real_network_run.md documents observed shapes against A1-A8
- src/api_to_collections.py: every [ASSUMED] tag is now [VERIFIED]/[DIVERGENT]/[UNKNOWN]
- All tests still pass after adapter patches
- API key has been revoked
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-07-SUMMARY.md` with:
- Network version observed
- Number of sites/devices/wlans/networks audited
- A1-A8 resolution table summary
- Number of [ASSUMED] tags converted
- Any adapter divergences fixed
- Total findings count by section
- Confirmation that all 4 validation REQs are met empirically
- Captured fixture path (gitignored) ready for Plan 08
</output>
