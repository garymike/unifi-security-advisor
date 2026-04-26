---
phase: 01-live-api-audit
reviewed: 2026-04-26T00:00:00Z
depth: standard
files_reviewed: 27
files_reviewed_list:
  - src/sanitizer.py
  - src/api_to_collections.py
  - src/findings_correlations.py
  - src/profile_weights.py
  - src/unifi_audit.py
  - src/parser.py
  - tools/anonymize_fixture.py
  - tests/conftest.py
  - tests/test_sanitizer.py
  - tests/test_adapter.py
  - tests/test_correlations.py
  - tests/test_float_top.py
  - tests/test_profile_weights.py
  - tests/test_pipeline_smoke.py
  - tests/test_no_credential_leak.py
  - tests/test_fixture_safety.py
  - tests/test_extract_helpers.py
  - tests/test_segmentation.py
  - tests/_smoke_adapter.py
  - tests/_smoke_analyze.py
  - tests/_smoke_correlate.py
  - tests/_smoke_float_top.py
  - tests/_smoke_profile_weights.py
  - tests/__init__.py
  - pyproject.toml
  - requirements-dev.txt
  - samples/fixtures/api_dump_home_office.json
findings:
  critical: 0
  warning: 4
  info: 5
  total: 9
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-04-26
**Depth:** standard
**Files Reviewed:** 27
**Status:** issues_found

## Summary

Reviewed the complete Phase 1 live-API-audit deliverable: sanitizer, adapter, correlation rules, profile weights, main audit orchestrator, parser, anonymizer tool, and the full test suite.

The security-critical paths are well-executed. Credential handling is clean — the API key is read only from environment variables, redacted in exception handlers, never passed as a CLI argument, never logged, and not present in any output artifact. Sanitization is comprehensive: `SECRET_FIELD_NAMES` covers both snake\_case and camelCase variants, the `sanitize()` function recurses correctly through nested dicts and lists, and idempotency is preserved. The always-top float pass runs correctly after the profile-weight sort, satisfying T-1-05 and T-1-06. The canonical fixture is properly anonymized with RFC 5737 IPs, locally-administered MACs, and stable fake UUIDs.

Four warning-level issues were found, the most significant being a false-positive trigger in `correlate_priority_mismatch` caused by an overly broad `FW-` prefix match. Five info-level issues are noted, primarily around test coverage gaps and a data-loss case in the VPN config aggregator.

No critical issues were found.

---

## Warnings

### WR-01: `correlate_priority_mismatch` uses overly broad `FW-` prefix — false positives on non-port-forward findings

**File:** `src/findings_correlations.py:61`

**Issue:** `_has_finding_id(findings, "FW-")` matches any finding whose ID starts with `FW-`, including `FW-EOL-001` (EOL hardware), `FW-EOL-002`, `FW-AUTO-001` (auto-update disabled), `FW-GEO-IN`, `FW-GEO-OUT`, `FW-CONTENT-001`, and `FW-VER-*` (firmware version). The rule's intent is to fire when active **port-forwards** are present without a VPN — but as written it fires whenever any firmware, auto-update, or geo-filter finding exists alongside `VPN-MISSING`. A site with only an EOL device and no VPN would incorrectly receive `CORR-PRIORITY-001` saying "port-forwards without VPN suggest exposure-as-remote-access path" even though there are no port-forwards at all.

The companion test `test_priority_mismatch_fires` (using `_F("FW-default-PF")`) correctly reflects the intent, but the implementation does not match the test's assumption.

**Fix:**
```python
# src/findings_correlations.py, line 61 — tighten to port-forward specific IDs only
# Port-forward findings are emitted as FW-{site_id}-PF by _find_firewall()
# and as FW-002 by parser.py find_firewall()
has_pf = (
    _has_finding_id(findings, "FW-") and
    any(f.id.endswith("-PF") or f.id == "FW-002" for f in findings)
    and _has_finding_id(findings, "VPN-MISSING")
)
```

Or, more robustly, rename the port-forward finding IDs to a distinct prefix (e.g., `PF-{site_id}`) to eliminate the ambiguity entirely.

---

### WR-02: `sanitize()` does not recurse into a `list` value under a secret key

**File:** `src/sanitizer.py:92-100`

**Issue:** When the value at a `SECRET_FIELD_NAMES` key is a `list`, the `else` branch (line 100) replaces it with `{"type": "list", "redacted": True}`. This is technically safe (the list is replaced, not leaked), but it is **not idempotent** and silently destroys structure. More importantly, if a secret key holds a list of strings (e.g., a `psk` field that is a list of pre-shared keys for multi-PSK networks), all individual secret values are redacted without fingerprinting — callers that expect a fingerprint dict will get a plain redaction marker instead, which differs from the string-path output. The idempotency claim in the docstring is also broken for this case: `sanitize({"psk": ["a", "b"]})` returns `{"psk": {"type": "list", "redacted": True}}`, and `sanitize` of that result is `{"psk": {"type": "list", "redacted": True}}` (unchanged) — so idempotency holds by accident. However, the comment on line 96-97 says only the dict path is idempotent; the list path has no equivalent comment or test.

This is not a credential leak (the list is redacted), but it creates inconsistency between what callers receive for string vs. list secret values, and the PSK length/fingerprint information is lost.

**Fix:**
```python
# src/sanitizer.py, inside the `if k in SECRET_FIELD_NAMES:` block
if isinstance(v, str):
    out[k] = _fingerprint(v)
elif isinstance(v, dict):
    out[k] = v  # already-sanitized fingerprint dict — pass through (idempotency)
elif isinstance(v, list):
    # Fingerprint each string element; recurse into nested dicts/lists
    out[k] = [_fingerprint(i) if isinstance(i, str) else {"type": type(i).__name__, "redacted": True} for i in v]
else:
    out[k] = {"type": type(v).__name__, "redacted": True}
```

---

### WR-03: `_find_devices` baseline module reads raw camelCase `sshEnabled` from unsanitized site data — will miss SSH detection on any site whose data has passed through the adapter

**File:** `src/unifi_audit.py:706`

**Issue:** `_find_devices` is a **baseline** module that reads directly from the sanitized `clean` dict (the raw API response, not the adapter-translated collection). It checks both `d.get("sshEnabled")` and `d.get("ssh_enabled")` for backwards compatibility. That is correct for the baseline path. However, note that the enhanced module path uses `find_admin` from `findings_enhanced.py` (via `parser.py`'s `find_admin`) which checks `d.get("ssh_enabled") is True`. The adapter's `_device_to_classic()` correctly maps `sshEnabled` → `ssh_enabled`. So for the live-API path, SSH detection fires from the baseline module (which checks `sshEnabled` on the raw dict) and potentially again from the enhanced path.

More concretely: the `_find_devices` module will correctly detect SSH when the raw API response includes `sshEnabled: True`, but if a future firmware version changes the field name (and only the adapter is updated), the baseline module would silently miss SSH devices while the enhanced module would still catch them. The dual-field fallback (`or d.get("ssh_enabled")`) is the mitigation, but it is not documented as intentional belt-and-suspenders.

This is low severity now but could become a silent detection gap. Adding a comment noting the intentional dual-check would suffice; the actual fix is to keep this pattern.

**Fix:** Add a comment making the intent explicit:
```python
# ssh_enabled: adapter maps sshEnabled→ssh_enabled; check both for belt-and-suspenders
# (baseline module reads raw API dict; enhanced module reads adapter output).
ssh_on = [d for d in devices if d.get("sshEnabled") or d.get("ssh_enabled")]
```

---

### WR-04: `_route_vpn_configs` silently discards non-`enabled` fields from earlier configs when multiple configs share the same protocol

**File:** `src/api_to_collections.py:337-338`

**Issue:** The OR-aggregate logic captures `existing_enabled` before overwriting `routed[key]` with the new config's fields, then restores the OR'd `enabled` flag. This means if there are two WireGuard configs (e.g., a site-to-site tunnel and a remote-access tunnel), the first config's fields — port, peers, endpoint address, etc. — are silently overwritten by the second config's fields. Only the `enabled` flag is correctly merged; all other fields from the first config are lost without a warning.

This does not affect security findings in Phase 1 (only `enabled` is checked), but the behavior is surprising and undocumented, and if a future finding module reads other fields from VPN settings, it will silently see only the last config's values.

**Fix:**
```python
# Option A: warn and merge
existing_enabled = routed[key].get("enabled", False)
# Merge instead of replace: OR the enabled flag, keep other fields from first occurrence
routed[key]["enabled"] = existing_enabled or enabled
# (remove the routed[key] = dict(config) line entirely)

# Option B: document the known limitation
routed[key] = dict(config)  # NOTE: last config wins for non-enabled fields
routed[key]["enabled"] = existing_enabled or enabled
```

---

## Info

### IN-01: `test_correlation_failure_does_not_abort` reloads `unifi_audit` globally — may leave test state dirty for subsequent tests

**File:** `tests/test_correlations.py:147-158`

**Issue:** The test uses `importlib.reload(ua)` after monkeypatching `fc.CORRELATION_RULES`. This reloads the `unifi_audit` module which re-executes all module-level imports and registrations. While `monkeypatch` will restore the attribute after the test, the `reload()` creates a new module object that may not be the same reference as what other tests in the same process have imported. In pytest's default execution order, this is unlikely to cause a problem, but it makes the test fragile and dependent on import isolation.

**Fix:** Rather than reloading the module, pass the patched rules directly to `_correlate_findings`:
```python
new = ua._correlate_findings(findings, "home_office", logger)
# _correlate_findings reads CORRELATION_RULES from findings_correlations, not unifi_audit.
# Monkeypatch fc.CORRELATION_RULES directly and don't reload.
```

---

### IN-02: `test_pipeline_correlation_sees_mfa_unknown` mutates the shared `synthetic_api_dump` fixture

**File:** `tests/test_float_top.py:173-186`

**Issue:** The `synthetic_api_dump` fixture has `scope` defaulting to `function` (not `session`), so each test gets its own copy. However, the mutation on line 173 (`synthetic_api_dump["site_default"]["port_forwards"]["data"] = [...]`) modifies the fixture's nested dict in place. If pytest ever runs these tests in a different order or if the fixture scope changes, this mutation will bleed across tests. Using a function-scoped fixture should prevent cross-test contamination, but the mutation style is fragile.

**Fix:**
```python
# Make a shallow copy of the mutable inner list instead of mutating in place
dump = {**synthetic_api_dump}
dump["site_default"] = {**synthetic_api_dump["site_default"]}
dump["site_default"]["port_forwards"] = {"data": [{"enabled": True, "name": "test-fwd"}], "totalCount": 1}
```

---

### IN-03: `test_no_credential_leak.py` static scan does not cover `logger.info(f"...")` f-string patterns that embed `response.text`

**File:** `tests/test_no_credential_leak.py:40-50`

**Issue:** The regex `r"logger\.(info|warning|error|debug|exception|critical)\([^)]*response\.text"` matches only when the `response.text` string appears **inside** the parentheses of the logger call on the same line. An f-string like `logger.info(f"body: {response.text}")` would be caught, but a multi-line f-string or a pre-formatted string assigned to a variable then passed to logger would not be. This is a low risk given the current codebase, but the test gives false confidence about multi-line patterns.

**Fix:** Add a complementary check for variable assignments that capture `response.text` into a variable that is later logged:
```python
# Supplemental: look for any assignment of response.text to a local variable in a logger context
pattern_assign = re.compile(r"\bresponse\.text\b")
lines = text.splitlines()
for i, line in enumerate(lines):
    if pattern_assign.search(line):
        context = "\n".join(lines[max(0, i-3):i+4])
        if re.search(r"logger\.", context):
            # flag for manual review
```

---

### IN-04: `anonymize_fixture.py` has no MAC-anonymization for `macAddress` values that appear outside `MAC_FIELDS` dict-key context — e.g., inside a string value

**File:** `tools/anonymize_fixture.py:249-258`

**Issue:** The `anonymize()` function catches bare MAC-shaped strings at the scalar level (line 249-250: `if MAC_RE.match(obj): return _anon_mac(obj)`). However, this only fires when the string value IS a MAC address (anchored full-match). A string like `"Connected via aa:bb:cc:dd:ee:ff"` — a partial MAC embedded in a text field — would not be caught because `MAC_RE` is anchored (`^...$`) and would not match a substring. In the current captured fixture, there do not appear to be such embedded MACs in string values, but if the UniFi API ever returns device descriptions or notes containing MAC addresses, they would slip through.

This is low risk given the current fixture content, but it is a latent anonymization gap.

**Fix:** For string-type values that are not full MACs, apply `MAC_RE` (non-anchored search) and replace any embedded MAC patterns:
```python
# In the scalar string branch of anonymize():
if MAC_RE.match(obj):      # full-string MAC
    return _anon_mac(obj)
# Check for embedded MACs in longer strings
MAC_EMBED_RE = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
if MAC_EMBED_RE.search(obj):
    return MAC_EMBED_RE.sub(lambda m: _anon_mac(m.group(0)), obj)
```

---

### IN-05: `parser.py:find_wifi` checks raw PSK string length — will fire on sanitized data (where PSK is a fingerprint dict, not a string)

**File:** `src/parser.py:367-381`

**Issue:** The `find_wifi` function in `parser.py` (the backup-mode parser) checks `if isinstance(psk, str) and len(psk) < 12`. After `sanitize(raw_collections, redact_pii=redact_pii)` is called in `parser.py:analyze()` (line 438), the PSK value has already been replaced with a fingerprint dict. So `isinstance(psk, str)` will always be `False` on sanitized data, and the short-PSK finding will never fire via the backup path.

This is the same pattern that was correctly handled in `src/unifi_audit.py:_find_wifi()` (which checks `isinstance(psk, dict) and psk.get("length", 0) < 12` at line 635). The parser's `find_wifi` was not updated to match.

Note: `parser.py` is described as a "single-file skeleton" and its finding modules are stubs or under-developed. This is likely a known tech debt item. Still flagging as the inconsistency between the two `find_wifi` implementations could cause confusion.

**Fix:** Update `parser.py:find_wifi` to check the fingerprint dict:
```python
psk = w.get("x_passphrase", "")
# After sanitize(), PSK is a fingerprint dict; check dict length field
if isinstance(psk, dict) and psk.get("length", 0) < 12:
    findings.append(Finding(
        id=f"WIFI-{name}-002",
        ...
        current_state=f"SSID '{name}' passphrase is {psk.get('length')} characters ...",
    ))
elif isinstance(psk, str) and len(psk) < 12:
    # Fallback for unsanitized input (should not occur in normal pipeline)
    findings.append(Finding(...))
```

---

_Reviewed: 2026-04-26_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
