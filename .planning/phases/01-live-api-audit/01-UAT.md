---
status: complete
phase: 01-live-api-audit
source:
  - 01-01-extract-sanitizer-SUMMARY.md
  - 01-02-adapter-and-wire-enhanced-modules-SUMMARY.md
  - 01-03-correlations-SUMMARY.md
  - 01-04-float-top-and-unknowns-SUMMARY.md
  - 01-05-profile-weights-SUMMARY.md
  - 01-06-pipeline-smoke-suite-SUMMARY.md
  - 01-07-real-network-validation-SUMMARY.md
  - 01-08-anonymize-and-commit-fixture-SUMMARY.md
started: 2026-04-26T00:00:00Z
updated: 2026-04-26T00:00:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Cold Start Smoke Test
expected: |
  With UNIFI_API_KEY and UNIFI_HOST set (or via .env + run_audit.ps1), running
  `python src/unifi_audit.py` against a UniFi controller exits 0 and produces all
  four output files: audit_output/{audit.log, raw_sanitized.json, findings.json,
  report.md}. Audit.log shows the endpoint URLs and HTTP status codes (200 for
  reachable endpoints, 404 for endpoints the controller doesn't expose). No
  exception traceback appears.
result: pass
note: |
  Initially failed with UnicodeEncodeError on Path.write_text() at
  src/unifi_audit.py:886 (Windows cp1252 default cannot encode '→'). Fixed
  inline by passing encoding="utf-8" to all 5 write_text() calls in src/
  + adding tests/test_write_text_encoding.py as a structural regression
  guard. Commit: 9885ed2. Re-verified pass.

### 2. Sanitization Correctness on Real Output
expected: |
  Open audit_output/raw_sanitized.json. Any field whose key matches a known
  secret name (preSharedKey, sharedSecret, x_passphrase, etc.) is shown as a
  dict like {"length": N, "fingerprint": "abc123def456", "has_symbols": true,
  "has_digits": true, "has_mixed_case": true} — never as a raw string. Plain
  config (network names, VLAN IDs, device models) appears unredacted.
result: pass

### 3. Always-Top Unknowns Appear at Top of Report
expected: |
  Open audit_output/report.md or findings.json. The first three findings (or
  the topmost section in the markdown report) include the API-undetectable
  always-top items: MFA-UNKNOWN-001, CRED-DEFAULT-001, WAN-MGMT-001. Each has
  status="unknown" and an intent_question prompting Phase 2 wizard handoff
  (e.g., "Is MFA enabled on every admin account?"). They appear above any
  scored findings.
result: pass

### 4. SEG-001 Evidence Reflects Real Network Count
expected: |
  Open audit_output/findings.json. The SEG-001 finding (if present) has
  evidence.network_count showing the actual count of user-defined networks
  on your controller (not 0). On your captured run the value should be 1
  (your IoT VLAN). Pre-fix this was always 0 because the raw-path filter
  didn't recognize Integration v1's metadata.origin field.
result: pass

### 5. Profile Label Says "(manual)" in Report
expected: |
  Open audit_output/report.md. Near the top, the Profile line reads
  "Profile: home_office (manual)" (or whichever profile UNIFI_PROFILE was set
  to, with "(manual)" appended). This signals to readers that auto-detection
  is deferred to Phase 2 — D-06.
result: pass
note: |
  Originally blocked behind Test 1's UnicodeEncodeError. After the fix
  (commit 9885ed2) report.md is produced and the "(manual)" label is
  visible. Re-verified pass.

### 6. Adapter Pagination Warning Logged
expected: |
  Open audit_output/audit.log. If any endpoint returned a paginated response
  with count < totalCount (the clients endpoint hit this on your run with
  25 of 30), a WARNING line appears like:
  "_unwrap[<endpoint>]: pagination truncation detected — received 25 of 30 items..."
  The audit still produces findings for the partial data — graceful degradation.
result: pass

### 7. Test Suite Green End-to-End
expected: |
  Run `pytest -q tests/` from the repo root. Exit code 0. Output ends with
  "207 passed" (or higher — was 207 after the Plan 08 + SEG-001 fix + 4
  code-review fixes). No skipped tests other than legitimate ones (none
  remain after the canonical fixture commit). No failures.
result: pass

### 8. Canonical Fixture Anonymization Holds
expected: |
  Open samples/fixtures/api_dump_home_office.json. All MAC addresses look
  locally-administered (e.g., "ca:dc:..." or "02:..." — first octet has
  bit 0x02 set). All IP addresses are in the 192.0.2.x range (RFC 5737
  documentation range). Hostnames are generic (gateway-N, ap-N, device-N).
  No real device names or network names that could identify your home
  network.
result: pass

## Summary

total: 8
passed: 8
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

- truth: "python src/unifi_audit.py runs to completion and produces all four output files including audit_output/report.md"
  status: failed
  reason: "User reported: UnicodeEncodeError on Path.write_text() in main() at src/unifi_audit.py:886 — Python 3.14 default cp1252 encoding cannot encode '→' (U+2192) from render_report output. Crashes after findings.json is written. report.md never written."
  severity: blocker
  test: 1
  root_cause: "Path.write_text() called without encoding='utf-8'. On Windows with Python 3.14 the default is cp1252. render_report() emits '→' characters (likely in section dividers or finding rendering) that cp1252 cannot encode. SUMMARY of plan 01-05 explicitly noted 'write_text encoding=utf-8 required on Windows due to arrow characters in render_report output' — the fix was applied for the audit.log writer but missed the report.md writer at line 886."
  resolution: |
    Fixed inline during UAT (commit 9885ed2). All 5 Path.write_text() calls in
    src/ (3 in unifi_audit.py, 2 in parser.py) now pass encoding="utf-8".
    Regression guard: tests/test_write_text_encoding.py — structural test that
    scans src/ for unguarded write_text() calls. Suite now 209 passed.
    Test 1 re-verified pass; Test 5 unblocked and verified pass.
  artifacts:
    - path: "src/unifi_audit.py"
      issue: "Line 886: report_path.write_text(render_report(...)) — missing encoding='utf-8'"
  missing:
    - "Add encoding='utf-8' to Path.write_text() call(s) in main() that write rendered report or any other text containing non-ASCII characters"
    - "Audit other write_text() calls in src/ for the same issue (sanitizer.py, parser.py, etc.)"
    - "Add a regression test that runs main() against a fixture and asserts report.md exists post-run"
  debug_session: ""
