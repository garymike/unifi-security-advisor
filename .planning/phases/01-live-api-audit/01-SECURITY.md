---
phase: 01-live-api-audit
audited_at: 2026-04-26
threats_total: 6
threats_closed: 6
threats_open: 0
status: secured
asvs_level: 1
block_on: high
---

# Security Audit — Phase 01: Live API Audit

## Threat Register

| Threat ID | Category | Component | Disposition | Status | Evidence |
|-----------|----------|-----------|-------------|--------|----------|
| T-1-01 | Information Disclosure (STRIDE: I) | src/sanitizer.py SECRET_FIELD_NAMES | mitigate | CLOSED | See T-1-01 detail below |
| T-1-02 | Information Disclosure (STRIDE: I) | Logging / exceptions | mitigate | CLOSED | See T-1-02 detail below |
| T-1-03 | Information Disclosure (STRIDE: I) | Fixture commit | mitigate | CLOSED | See T-1-03 detail below |
| T-1-04 | Tampering / Information Disclosure (STRIDE: T+I) | Adapter | mitigate | CLOSED | See T-1-04 detail below |
| T-1-05 | Tampering (STRIDE: T) | Scoring | mitigate | CLOSED | See T-1-05 detail below |
| T-1-06 | Tampering (STRIDE: T) | Sort order | mitigate | CLOSED | See T-1-06 detail below |

---

## Per-Threat Verification Evidence

### T-1-01 — Sanitization bypass on a new camelCase field name

**Declared mitigation:** SECRET_FIELD_NAMES frozenset in src/sanitizer.py with snake_case + camelCase variants; tagged-secret round-trip test in tests/test_sanitizer.py; hypothesis property tests; coverage >= 95%.

**Verification:**

- `src/sanitizer.py` lines 25-54: `SECRET_FIELD_NAMES` is a `frozenset` with 26 entries including all declared camelCase variants: `preSharedKey`, `presharedKey`, `sharedSecret`, `radiusSecret`, `sshPassword`, `authKey`, `iappKey`, `privateKey`, `apiKey`, `wifiPassword`.
- `src/sanitizer.py` line 25: `frozenset` (immutable — prevents silent runtime appends).
- `src/unifi_audit.py` lines 63-65: imports `SECRET_FIELD_NAMES, _fingerprint, sanitize` from `sanitizer` (no local definition — DRY violation closed).
- `src/parser.py` lines 34-36: same import pattern; no local definition.
- `tests/test_sanitizer.py` lines 20-41: three `test_tagged_secret_*` functions inject a unique tag string (`UNIQUE_SECRET_TAG_7f3a9b2c_DO_NOT_COMMIT`) into every key in SECRET_FIELD_NAMES, call `sanitize()`, and assert the tag does not appear anywhere in `json.dumps(result)`.
- `tests/test_sanitizer.py` lines 46-99: parametrized `test_camelcase_secret_field_redacted` covers all 10 camelCase keys; parametrized `test_snake_case_secret_field_redacted` covers all 15 snake_case keys.
- `tests/test_sanitizer.py` line 189-193: `test_secret_field_names_includes_camelcase` asserts the four highest-risk camelCase keys are present; regression guard against accidental removal.
- `tests/test_sanitizer.py`: hypothesis `@given` property tests confirm idempotency and no raw secret string survives any SECRET_FIELD_NAMES key for 200 generated examples.
- Reported coverage on `src/sanitizer.py`: **100%** (Plan 08 SUMMARY confirms 100% after coverage gap tests added; Plan 01 SUMMARY confirmed 96% at initial delivery — both exceed the 95% threshold).
- Post-review fix WR-02 (commit cf80fe2) added list-valued secret key handling with per-element fingerprinting; idempotency confirmed by `test_secret_list_idempotent`.

**CLOSED.**

---

### T-1-02 — Credential leak via raw response.text in exception messages or logging

**Declared mitigation:** tests/test_no_credential_leak.py static guard scanning src/*.py for forbidden patterns.

**Verification:**

- `tests/test_no_credential_leak.py` exists (Plan 06 SUMMARY confirms creation in commit 9bde066).
- File scans 8 owned src files: `unifi_audit.py`, `sanitizer.py`, `api_to_collections.py`, `findings_correlations.py`, `profile_weights.py`, `findings_enhanced.py`, `parser.py`, `inspect_backup.py`.
- `test_no_response_text_in_logger_calls` (line 38-50): regex asserts no `logger.{level}(... response.text ...)` in any src file.
- `test_no_response_text_in_print_calls` (line 53-62): asserts no `print(... response.text ...)`.
- `test_no_print_of_api_key_variable` (line 64-82): asserts no print of `api_key`, `cfg["key"]`, or `UNIFI_API_KEY`.
- `test_no_logger_emits_full_cfg` (line 84-97): asserts no `logger.*(self.cfg)` or `logger.*(cfg)`.
- `test_existing_safe_pattern_present` (line 99-111): regression guard asserting the `str(e).replace(self.cfg["key"], "<REDACTED>")` scrub pattern is still present in `src/unifi_audit.py`. If it is removed, the test fails.
- `test_audit_log_format_does_not_include_response_body` (line 114-123): confirms `logger.info(f"GET {url}")` pattern is present (URL + status code only; no response body).
- Plan 06 SUMMARY confirms 34 parametrized tests all passing; 207 tests pass post-review-fix.

**CLOSED.**

---

### T-1-03 — Committed fixture leaks a real PSK if anonymizer misses a field

**Declared mitigation:** tests/test_fixture_safety.py runs before commit; tools/anonymize_fixture.py strips PII beyond sanitizer scope.

**Verification:**

- `tests/test_fixture_safety.py` exists with 5 tests (confirmed present by Glob; Plan 01 SUMMARY documents creation in commit ebec8bc).
- `test_canonical_fixture_no_raw_secrets` (line 54-83): walks the entire committed JSON, asserts that every value under any SECRET_FIELD_NAMES key is a fingerprint dict (keys `length` + `fingerprint`) or a redaction marker (`redacted: True`). Raw string values under SECRET_FIELD_NAMES cause a hard failure with path details.
- `test_canonical_fixture_under_size_budget` (line 44-51): asserts fixture < 200 KB (D-08 constraint).
- `test_canonical_fixture_is_valid_json` (line 53-57): structural integrity check.
- `samples/fixtures/api_dump_home_office.json` exists (Glob confirmed; Plan 08 SUMMARY confirms 15,012 bytes, well under 200 KB).
- `tools/anonymize_fixture.py` exists (Glob confirmed; Plan 08 SUMMARY documents creation in commit b4e6930). Applies MAC→RFC 5737, IP→192.0.2.x, hostname, serial, and UUID anonymization on top of the sanitizer's secret-field fingerprinting.
- Plan 08 SUMMARY confirms all 5 fixture-safety gate tests pass (previously skipped pre-Plan 08; all activated cleanly with zero failures).
- `tests/fixtures/.gitignore` prevents raw captured dumps from being committed (Plan 01 SUMMARY confirms file created).

**CLOSED.**

---

### T-1-04 — API response shape change silently drops data; downstream findings see empty surface

**Declared mitigation:** src/api_to_collections.py `_unwrap` and `_extract_list` emit logger.warning on unmatched shapes.

**Verification:**

- `src/api_to_collections.py` line 89: `logger.warning("_unwrap[%s]: unknown response shape — no recognized list key found. ...")` fires when no recognized list key (`data`, `items`, `results`, `list`) is found in a response dict. Keys observed are included in the message.
- `src/unifi_audit.py` lines 778-781: `_extract_list` emits `logger.warning("_extract_list: no recognized list key in response. Keys present: ...")` before returning `None` for unknown dict shapes.
- `tests/test_adapter.py` line 96: `test_unknown_shape_emits_warning` uses `caplog` to assert the WARNING fires when `_unwrap` receives an unrecognized shape.
- `tests/test_extract_helpers.py` line 25: `test_extract_list_unknown_shape_logs_warning` uses `caplog` to assert the WARNING fires from `_extract_list`.
- Plan 02 SUMMARY also documents pagination truncation warning: `_unwrap()` logs WARNING when received count < totalCount; asserted by `test_pagination_truncation_warns`.
- Plan 07 SUMMARY confirms real-network run with 6 endpoints returning 404; warnings fired correctly and were captured in test output. The META-COVERAGE finding surfaces these gaps to the user.
- Try/except per enhanced module in `analyze()` ensures one module's failure does not abort the audit (Plan 02 SUMMARY confirms this pattern; consistent with established pattern in src/unifi_audit.py).

**CLOSED.**

---

### T-1-05 — Profile-weight misapplication silently down-weights a critical finding

**Declared mitigation:** tests/test_profile_weights.py asserts always-top findings bypass weight calculation + 50-cell coverage assertion.

**Verification:**

- `src/profile_weights.py` exists (Plan 05 SUMMARY confirms creation in commit afe8e06; 50-cell WEIGHTS dict, `get_weight`, `score_finding`, `KNOWN_PROFILES`).
- `tests/test_profile_weights.py` lines 44-50: `test_weights_cover_all_profile_section_cells` iterates all 5 profiles x 10 sections = 50 combinations and asserts each `(profile, section)` tuple is present in WEIGHTS. A missing cell causes a hard failure listing the absent cells.
- `tests/test_profile_weights.py` lines 53-55: `test_weights_cell_count` asserts `len(WEIGHTS) >= 50`.
- `tests/test_profile_weights.py` line 124: `test_always_top_bypasses_weights` reproduces the `analyze()` sort + `_apply_float_top()` pass manually and asserts that VPN-PPTP-001 floats first even with the worst possible score.
- `src/unifi_audit.py` line 536: comment confirms `_apply_float_top()` runs LAST in `analyze()` — structural guarantee that weight-based sort cannot demote always-top findings.
- `src/unifi_audit.py` line 545: `findings = _apply_float_top(findings)` is the final step in the pipeline, after the profile-weighted sort.
- Plan 05 SUMMARY confirms `test_always_top_set_is_first_under_every_profile` tests all 5 profiles end-to-end.

**CLOSED.**

---

### T-1-06 — Future change reorders findings such that always-top no longer floats

**Declared mitigation:** tests/test_float_top.py + tests/test_pipeline_smoke.py assert findings[0].id is in ALWAYS_TOP_FINDING_IDS when fixture would fire any always-top.

**Verification:**

- `tests/test_float_top.py` line 138: `test_pipeline_first_findings_are_always_top` calls `analyze()` with the synthetic fixture, counts always-top findings in the result, then asserts the first N positions all satisfy `f.id.startswith(prefix)` for some prefix in `ALWAYS_TOP_FINDING_IDS`. Any reordering that moves a non-always-top finding ahead would fail this test.
- `tests/test_pipeline_smoke.py` line 108-116: `test_pptp_finding_is_first_when_present` injects VPN-PPTP-001 into the fixture via `fixture_firing_all_modules`, runs `analyze()`, and asserts all findings before (and including) the PPTP finding are always-top.
- `tests/test_pipeline_smoke.py` line 286: `test_canonical_fixture_pipeline_smoke` (Plan 08 addition) asserts `findings[0].id.startswith(p)` for some `p` in `ALWAYS_TOP_FINDING_IDS` against the committed real-data canonical fixture.
- `src/unifi_audit.py` line 138-145: `ALWAYS_TOP_FINDING_IDS` is a `frozenset` of 6 string prefixes (`"VPN-PPTP-001"`, `"SEG-001"`, `"FW-EOL-001"`, `"MFA-UNKNOWN-001"`, `"CRED-DEFAULT-001"`, `"WAN-MGMT-001"`).
- `src/unifi_audit.py` lines 430-438: `_apply_float_top()` uses `startswith` prefix match (handles per-site suffix variants like `SEG-001-default`). Confirmed idempotent.
- Final test suite: 207 passed, 0 failed, 0 skipped.

**CLOSED.**

---

## Accepted Risks

None. All 6 declared threats closed with verifiable mitigations.

---

## Unregistered Threat Flags (from SUMMARY.md ## Threat Flags sections)

All 8 phase plans (01-01 through 01-08) explicitly declare "Threat Flags: None" in their SUMMARY.md files. No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries were introduced beyond what the threat register anticipated. No unregistered flags to log.

---

## Audit Trail

| Field | Value |
|-------|-------|
| Audited at | 2026-04-26 |
| Phase | 01-live-api-audit |
| Plans audited | 01-01 through 01-08 (8 plans) |
| ASVS level | 1 |
| block_on | high |
| Threats declared | 6 |
| Threats closed | 6 |
| Threats open | 0 |
| Unregistered flags | 0 |
| Final test suite | 207 passed, 0 failed, 0 skipped |
| Sanitizer coverage | 100% (src/sanitizer.py) |
| Review findings resolved | WR-01, WR-02, WR-03, WR-04 (all 4 warnings closed per 01-REVIEW-FIX.md) |
| Auditor | GSD security auditor (Claude Sonnet 4.6) |
