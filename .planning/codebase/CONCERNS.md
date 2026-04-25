# Codebase Concerns

**Analysis Date:** 2026-04-25

## Tech Debt and Implementation Gaps

### Enhanced Finding Modules Not Wired Into Live Audit

**Issue:** `src/findings_enhanced.py` contains fully implemented finding modules for wireless tuning, VPN protocol preference, firewall threats (geo/content split), firmware currency, and logging with profile-aware retention. None of these are imported or called from `src/unifi_audit.py`.

**Files:** 
- `src/unifi_audit.py:359-375` - only six finding modules wired: segmentation, wifi, firewall (basic), remote_access, devices, api_coverage
- `src/findings_enhanced.py` - contains six additional modules: find_wireless_tuning, find_firewall_threats, find_remote_access (enhanced), find_firmware (enhanced), find_logging, find_backup_config

**Current state:** Live audit output is missing half of the implemented coverage.

**Fix approach:** Import and integrate findings_enhanced modules into the analyze() function in unifi_audit.py. Handle any data-model incompatibilities (e.g., findings_enhanced assumes parser.py collection names, unifi_audit.py uses API response keys).

---

### Parser.py Stub Functions Return Empty Lists

**Issue:** `src/parser.py` contains three function definitions that are stubs—they return empty lists instead of running analysis.

**Files:** `src/parser.py:431-433`
```python
def find_logging(colls: dict) -> list[Finding]: return []
def find_backup_config(colls: dict) -> list[Finding]: return []
def find_firmware(colls: dict) -> list[Finding]: return []
```

These are then called from `src/parser.py:471-473` in the findings list, so backup-mode analysis silently produces zero findings for these sections.

**Impact:** Phase 4 (backup-file mode) will have no logging, backup, or firmware findings unless findings_enhanced.py functions are ported to use parser.py's data model.

**Fix approach:** Port the three enhanced functions to parser.py, converting from API collection names to BSON field names. Alternatively, update parser.py to import from findings_enhanced after ensuring both modules can coexist.

---

### No Automated Tests

**Issue:** The codebase has zero test files. This is a critical concern for a security tool.

**Files:** No `test_*.py`, `*_test.py`, or `conftest.py` found anywhere.

**Impact:**
- Finding logic changes (e.g., modified WPA severity threshold) have no regression protection
- Sanitization logic is untested; if a new secret field name is missed, raw values could leak
- API response parsing (especially `_extract_list`, `_extract_sites`) is untested; API schema changes could cause silent failures
- Backup parser decryption, BSON parsing, and collection routing are untested against real backup files

**Risk level:** HIGH. A security tool without automated tests can ship broken findings or accidentally log secrets.

**Fix approach:**
1. Add `pytest` + `pytest-cov` to dev dependencies
2. Create `tests/` directory
3. Write unit tests for:
   - `unifi_audit.py:sanitize()` with all SECRET_FIELD_NAMES and edge cases
   - `unifi_audit.py:_extract_list()` and `_extract_sites()` with API response variants
   - Each finding module with mock collections
   - `parser.py:decrypt_unf()` with a real test .unf file (anonymized backup fixture)
   - `parser.py:extract_collections()` with both db.gz and mongodump-style backups
4. Set up GitHub Actions CI to run tests on every PR

---

### Profile Detection Not Implemented

**Issue:** The codebase defines five profile labels (`home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`) in CLAUDE.md and uses them in recommendations (e.g., `src/findings_enhanced.py:505` checks `if profile.startswith("home")`). However, there is no automatic profile detection.

**Files:**
- `src/unifi_audit.py:154` - profile is read from environment variable only
- `src/findings_enhanced.py:489-546` - logging findings use profile to adjust severity/recommendations

**Current state:** User must manually set `UNIFI_PROFILE=regulated_hipaa` before running the script. If not set, defaults to `home_office`.

**Coverage gap:** Per ROADMAP.md line 126, this is listed as an "open question": "Profile detection: can we infer profile from API data alone (e.g., 'regulated_hipaa' if HIPAA-typical patterns present) or always require user input?"

**Fix approach:**
1. Add profile inference heuristics in `unifi_audit.py:analyze()`:
   - Detect `home`: single site, <5 users, <10 devices, no VLAN segmentation
   - Detect `home_office`: single site, <20 users, moderate device count, some VLAN use
   - Detect `small_business`: multiple devices, dedicated management VLAN, firewall rules present
   - Detect `regulated_hipaa`: encryption at rest/in transit configured, NAS backups enabled, syslog forwarding
   - Detect `regulated_pci`: strict firewall rules, WAN geo-blocking, network segmentation, MFA presence
2. Allow user override: if `UNIFI_PROFILE` env var is set, trust user input; otherwise, infer
3. Display inferred profile and allow user to correct before audit begins

---

## Security Concerns Relative to CLAUDE.md Absolute Constraints

### Absolute Constraint Status: Credentials Never Leave User's Machine

**Status: ✅ MET** - `src/unifi_audit.py` correctly handles API key:
- Line 122-128: only reads from environment variable (never CLI args)
- Line 231-234: X-API-KEY header added only to session, never logged
- Line 258: exception scrubbing replaces key with `<REDACTED>` before logging
- Line 268: session.close() clears memory after run

**Exception handling risk:** Line 256-260 catches RequestException and logs `safe_msg`. However, exception text could theoretically contain a leaked key from a previous response if the exception message references response objects. Current approach is defensive and adequate.

---

### Absolute Constraint Status: Credentials via Environment, Config, Keychain, or Interactive Prompts Only

**Status: ✅ MET** - `src/unifi_audit.py:load_config()` enforces this. No argparse credential acceptance.

**Note:** `src/inspect_backup.py` and `src/parser.py` use argparse for file paths (not credentials), which is correct.

---

### Absolute Constraint Status: All Outputs are Sanitized

**Status: ✅ MET with minor duplication risk**

Two separate sanitization implementations exist:

1. `src/unifi_audit.py:183-216` - sanitize() function for API responses
2. `src/parser.py:103-148` - sanitize() function for backup data

Both implement the same SECRET_FIELD_NAMES set. If a new secret field is discovered, it must be added to both places.

**Risk:** DRY violation increases chance of missed secrets.

**Fix approach:** Extract sanitization logic to a shared `src/sanitizer.py` module imported by both unifi_audit.py and parser.py.

---

### Absolute Constraint Status: Read-Only by Default

**Status: ✅ MET** - `src/unifi_audit.py` makes only GET requests. No write endpoints called.

**Out of scope for Phase 1** per CLAUDE.md line 80.

---

### Absolute Constraint Status: Official API Paths Preferred

**Status: ✅ MET** - `src/unifi_audit.py:71-93` uses official Network Integration API (`/proxy/network/integration/v1/`) and Site Manager API (`api.ui.com/v1/`).

**Note:** Cookie-based auth is not implemented; only X-API-KEY.

---

### Absolute Constraint Status: Backup-File Mode Must Be Offline

**Status: ⚠️ NOT YET TESTABLE** - `src/parser.py` and `src/inspect_backup.py` do not open network connections (confirmed by grep search). However, Phase 4 is not yet validated against real backup files.

**Fix approach:** Before Phase 4 launch, test parser.py in a network-isolated environment (no network interface active) to prove compliance.

---

### Absolute Constraint Status: Default Expiration on Throwaway Keys: Shortest Available

**Status: ⚠️ NOT IMPLEMENTED** - The tool does not currently create or manage API keys. Per ROADMAP.md line 6, Phase 1 assumes the user has already created a key.

**Document to add:** `AUDIT_QUICKSTART.md` should explicitly recommend users set 1-day expiration when creating a temporary API key in Site Manager. (Confirm whether this is already documented in AUDIT_QUICKSTART.md—not provided in this analysis scope.)

---

## Always-Float-to-Top Findings: Implementation Status

Per CLAUDE.md line 69-76, six findings must float to top regardless of score:

| Finding | Implemented? | Location | Status |
|---------|-------------|----------|--------|
| No MFA on any admin account | ❌ Missing | N/A | MFA state not exposed via Network Integration API; deferred to Phase 2 questionnaire (ROADMAP.md line 135) |
| Management plane reachable from WAN | ❌ Missing | N/A | API schema incomplete; cannot detect open ports/services |
| Flat network with multiple device classes (IoT + work + personal) on one VLAN | ⚠️ Partial | `src/unifi_audit.py:387-417` | Detects flat network (SEG-001) but does NOT check for mixed device classes on single VLAN |
| Default credentials anywhere | ❌ Missing | N/A | API does not expose credential data; requires backup mode or manual review |
| Firmware more than two majors behind with known advisories | ✅ Partial | `src/findings_enhanced.py:456-471` | Firmware version check exists but CVE database is not integrated; EOL list is static/minimal |
| PPTP or any deprecated-crypto VPN enabled | ✅ Implemented | `src/findings_enhanced.py:156-179` | VPN-PPTP-001 flags PPTP as critical, but module not wired into live audit |

**Critical gap:** Only 1 of 6 is fully implemented AND wired into live audit. Three are known limitations of Phase 1 API scope (MFA, credentials, WAN reachability).

---

## Performance Bottlenecks and Fragile Areas

### API Response Parsing Assumes Consistent Schema

**Issue:** Functions like `_extract_list()` and `_extract_sites()` try multiple key names (line 342-348, 562-572) to handle API response variations. However, this is defensive but fragile.

**Files:** `src/unifi_audit.py:340-348`, `src/unifi_audit.py:562-572`

**Example:** `_extract_sites()` checks for `data`, `sites`, `items` keys because the API schema is still evolving.

**Risk:** If Ubiquiti adds a new response shape not covered by these fallbacks, the function silently returns an empty list instead of raising an error. This leads to zero findings for an entire site.

**Fix approach:** 
1. Add detailed logging for the actual response structure when a response doesn't match expected shapes
2. Raise an exception if the top-level structure is not a list or dict (fail fast)
3. Maintain a version matrix: Network version → expected response shapes

---

### Network Request Timeout is Fixed at 30 Seconds

**Files:** `src/unifi_audit.py:255` - `timeout=30`

**Risk:** Large controllers with many devices may need longer. No override possible without code change.

**Fix approach:** Make timeout configurable via `UNIFI_REQUEST_TIMEOUT` environment variable with a sensible default (30s is reasonable).

---

### Backup Parser Decryption Has Unhandled Edge Cases

**Files:** `src/parser.py:45-64`

**Issue:** The decrypt_unf() function assumes:
- UniFi doesn't pad in the standard PKCS7 way (line 53 comment: `-nopad in the reference openssl cmd`)
- Plaintext is a valid ZIP file starting with `PK\x03\x04` (line 58)

If either assumption is wrong, a corrupted or new-format backup raises ValueError with generic message.

**Risk:** User has no way to debug; could be file corruption, new UniFi format, or wrong decryption key.

**Fix approach:**
1. Try both padded and unpadded decryption variants
2. If ZIP signature check fails, dump first 256 bytes (hex) to stdout for diagnosis
3. Add a tool to help users identify backup format (already done in `src/inspect_backup.py`, but could be surfaced better)

---

### Site Iteration Sleeps Between Requests

**Files:** `src/unifi_audit.py:335` - `time.sleep(0.1)`

**Impact:** Benign rate-limiting. For 50 sites with 8 endpoints each = 400 requests × 0.1s = 40 seconds extra. Acceptable for Phase 1 (read-only, not a user-blocking operation), but may become a bottleneck in Phase 3 (multi-site MSP scenario).

**Note:** Not a bug, just documenting architectural decision.

---

## Sanitization Implementation Duplication Risk

### Two Separate SECRET_FIELD_NAMES Sets

**Files:**
- `src/unifi_audit.py:183-188`
- `src/parser.py:103-116`

Both define SECRET_FIELD_NAMES with identical entries. If new secrets are discovered (e.g., a new Ubiquiti field `x_oauth_token`), both must be updated.

**Risk level:** MEDIUM. Easy to miss one.

**Fix approach:** Extract to `src/sanitizer.py` or add a `SECRETS` constant in a shared config module.

---

## Coverage Gaps Relative to 10-Point Video / ROADMAP.md

Per `docs/07-coverage-analysis.md`, here is the status:

| # | Topic | Phase 1 Live API | Phase 1 Backup | Phase 4+ | Status |
|---|-------|-----------------|----------------|----------|--------|
| 1 | Firmware/console/app updates | Stub only | Stub only | Planned | 🟡 Partial |
| 2 | VLANs for internal/guest/IoT | Implemented | Implemented | — | ✅ Strong |
| 3 | SSID-to-VLAN mapping + WPA2/3 | Implemented | Implemented | — | ✅ Strong |
| 4 | Per-AP radio tuning | Not implemented | Implemented in findings_enhanced.py | — | 🟡 Unwired |
| 5 | IDS/IPS | Partial | Partial | — | 🟡 Shallow |
| 6 | Region blocking + content filtering | Partial | Implemented in findings_enhanced.py | — | 🟡 Unwired |
| 7 | Firewall zones and rules | Partial | Partial | — | 🟡 Quality not audited |
| 8 | Automatic backups and tested restore | Stub only | Implemented in findings_enhanced.py | — | 🟡 Unwired |
| 9 | Traffic logging and retention | Stub only | Implemented in findings_enhanced.py | — | 🟡 Unwired |
| 10 | VPN (WireGuard/OpenVPN preferred) | Partial | Implemented in findings_enhanced.py | — | 🟡 Unwired |

**Summary:** 9 of 10 topics are addressable from current data. 5 of 9 have complete implementations in findings_enhanced.py but are not wired into live audit.

---

## Test Coverage State

**Automated tests:** None (0 test files)

**Manual validation:** Per ROADMAP.md line 99-105:
- [ ] Run against a real UniFi network
- [ ] Diff API response shapes vs assumed shapes
- [ ] Test Network >= 9.3.43
- [ ] Test with older Network version (graceful 404 handling)
- [ ] Test cloud mode (UNIFI_USE_CLOUD=true)
- [ ] Test SSL self-signed default

**Priority:** Must validate Phase 1 before Phase 2 (wizard) can proceed, as Phase 2 will depend on Phase 1's correctness.

---

## Backup Mode (parser.py) Maturity vs Live API Mode

### Live API Mode (`src/unifi_audit.py`)

**Maturity:** Scaffolded, feature-complete for current scope. Documented (AUDIT_QUICKSTART.md), handles errors gracefully, logs are clean.

**Validation:** Awaiting real-network test.

---

### Backup Mode (`src/parser.py`)

**Maturity:** Skeleton with stubs. Six core modules are wired, but three (logging, backup_config, firmware) return empty lists. Finding modules for radio tuning, firewall threats (enhanced), and remote access (enhanced) are written in findings_enhanced.py but not integrated into parser.py.

**Data model:** Parser.py assumes MongoDB collection names (`device`, `wlanconf`, `networkconf`); unifi_audit.py uses API response keys. No adapter layer between them.

**Validation:** No real backup file tested yet. No automated decryption tests.

**Risks:**
1. Decryption may fail silently on new backup formats
2. BSON collection routing is inferred, not documented
3. Phase 4 will likely need significant rework to match API findings

---

## Detailed Concern List

### Concern 1: Critical Finding Modules Unwired from Live Audit

**Severity:** HIGH

**Problem:** Five complete finding modules exist in findings_enhanced.py (wireless_tuning, firewall_threats, firmware enhanced, logging, backup_config, and remote_access enhanced) but are not called from unifi_audit.py's analyze() function.

**Impact:** Users running the live audit miss ~50% of coverage. Users switching from backup mode to live API get different findings.

**Evidence:**
- `src/unifi_audit.py:359-375` - only six modules listed
- `src/findings_enhanced.py:17-625` - six complete implementations

**Priority:** CRITICAL for Phase 1 launch. Must be wired before go-live.

---

### Concern 2: No Automated Tests

**Severity:** CRITICAL for a security tool

**Problem:** Zero test files. Sanitization logic, finding modules, and API parsing are untested.

**Impact:** 
- Regression risk on every change
- Secrets could leak if sanitization logic is modified incorrectly
- API schema changes could silently break findings

**Evidence:** No `test*.py`, `*_test.py`, or `tests/` directory found.

**Priority:** CRITICAL. Add before Phase 2, or risk shipping broken findings.

---

### Concern 3: DRY Violation in Sanitization

**Severity:** MEDIUM

**Problem:** Two separate sanitize() implementations with duplicate SECRET_FIELD_NAMES lists.

**Impact:** New secret fields must be added to two places, increasing missed-secret risk.

**Evidence:**
- `src/unifi_audit.py:183-216`
- `src/parser.py:103-148`

**Priority:** MEDIUM. Extract to shared module before Phase 4.

---

### Concern 4: Parser.py Stub Functions Return Empty

**Severity:** HIGH for Phase 4

**Problem:** find_logging, find_backup_config, find_firmware return `[]` instead of running analysis.

**Impact:** Backup-mode users get zero findings for three major sections.

**Evidence:** `src/parser.py:431-433`

**Priority:** HIGH for Phase 4 launch. Port findings_enhanced.py to parser.py or find another integration path.

---

### Concern 5: API Response Schema Fragility

**Severity:** MEDIUM

**Problem:** _extract_list() and _extract_sites() try multiple key names, but fail silently if none match.

**Impact:** If API response shape changes, findings silently drop.

**Evidence:** `src/unifi_audit.py:340-348`, 562-572

**Priority:** MEDIUM. Add error logging and version matrix.

---

### Concern 6: Always-Float-to-Top Findings Mostly Unimplemented

**Severity:** HIGH

**Problem:** Of six critical findings, only one is fully wired into live audit (PPTP). Three are API limitation (MFA, credentials, WAN reachability). Two have stubs (flat network device class detection, firmware + CVE).

**Impact:** Users may miss critical security issues.

**Evidence:**
- Flat network check exists but doesn't verify mixed device classes
- Firmware check doesn't correlate with CVE database
- MFA, WAN reachability, default credentials are deferred to Phase 2

**Priority:** HIGH for Phase 2. Phase 1 should document these gaps in output report.

---

### Concern 7: Profile Inference Not Implemented

**Severity:** MEDIUM

**Problem:** Five profile tiers defined but user must manually set UNIFI_PROFILE env var. No automatic inference.

**Impact:** Default profile (home_office) may not match user's environment, leading to incorrect severity/recommendations.

**Evidence:** `src/unifi_audit.py:154` only reads env var; no inference logic.

**Priority:** MEDIUM. Should be added before Phase 2 (wizard) ships, to improve UX.

---

### Concern 8: Backup Parser Edge Cases Unhandled

**Severity:** MEDIUM

**Problem:** decrypt_unf() assumes non-standard padding and valid ZIP signature. Corrupted or new-format backups fail with generic error.

**Impact:** Users debugging backup issues have no path forward.

**Evidence:** `src/parser.py:45-64`

**Priority:** MEDIUM. Add variant handling and diagnostic output before Phase 4.

---

### Concern 9: Large Fixture Data Missing

**Severity:** MEDIUM

**Problem:** Testing against real backup files requires anonymized fixtures. CLAUDE.md line 117-122 lists required profiles; none are currently in `samples/` (not checked in analysis scope, but ROADMAP.md lists as a "known gap").

**Impact:** Phase 4 validation will require real network/backup for testing.

**Evidence:** ROADMAP.md line 127: "Sample data fixtures: a real run will expose response shape differences."

**Priority:** MEDIUM. Gather fixtures during first real-network validation.

---

### Concern 10: CVE Database Not Integrated

**Severity:** MEDIUM

**Problem:** Firmware check in findings_enhanced.py has a static EOL_MODELS dict (line 354-362) but no CVE correlation.

**Impact:** Firmware findings flag EOL hardware but not specific known-vulnerable versions.

**Evidence:** `src/findings_enhanced.py:354-362`, line 456 comment says "placeholder logic".

**Priority:** MEDIUM. Required for "Always-float-to-top" firmware finding to work correctly.

---

## Summary

**Critical issues blocking Phase 1 launch:**
1. Enhanced finding modules not wired into live audit
2. No automated tests
3. Real-network validation not yet done

**High-priority for Phase 2:**
1. Implement missing always-float-to-top findings (MFA, credentials, WAN)
2. Add profile inference
3. Extract sanitization to shared module

**Phase 4 (Backup mode):**
1. Integrate findings_enhanced modules into parser.py
2. Port stub functions to real implementations
3. Handle decryption edge cases
4. Gather and test against real backup fixtures

---

*Concerns audit: 2026-04-25*
