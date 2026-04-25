# Architecture

**Analysis Date:** 2026-04-25

## Pattern Overview

**Overall:** Three-phase audit engine with credential isolation, data sanitization, and modular findings analysis.

**Key Characteristics:**
- **Discovery-first:** Detects current state via API or backup file, asks user to confirm intent rather than recall configuration
- **Credential isolation:** API key read only from environment variables; never logged, never output
- **Sanitization boundary:** All secrets (PSKs, passwords, shared secrets) converted to length + SHA256 fingerprint before any analysis or output
- **Modular findings:** Independent analysis modules (segmentation, Wi-Fi, firewall, etc.) run in isolation; one failure doesn't abort the audit
- **Profile-aware:** Findings severity/scoring adjusted based on user context (home vs. home office vs. small business vs. regulated)

## Layers

**Transport & Credential Layer:**
- Purpose: Safely load and use API credentials without exposing them
- Location: `src/unifi_audit.py` (`load_config()`, `UniFiClient` class)
- Contains: Environment variable parsing, SSL verification control, session management with X-API-KEY header
- Depends on: requests library; environment variables only (never CLI args)
- Used by: Collection phase

**Collection Layer:**
- Purpose: Probe endpoints and aggregate API/backup data into a unified dict structure
- Location: `src/unifi_audit.py` (`collect_all()`, `_extract_sites()`, `_extract_list()`)
- Contains: Endpoint enumeration for Network Integration API (local) and Site Manager API (cloud); graceful 404 handling for version mismatches
- Depends on: UniFiClient; configuration
- Used by: Sanitization layer

**Sanitization Layer:**
- Purpose: Convert secrets to fingerprints before any data leaves the credential boundary
- Location: `src/unifi_audit.py` (`sanitize()`, `_fingerprint()`) and `src/parser.py` (backup mode)
- Contains: Secret field name registry (`SECRET_FIELD_NAMES`); recursive dict/list sanitizer; fingerprinting via SHA256 hash
- Depends on: Collection layer output
- Used by: Analysis phase

**Analysis/Findings Layer:**
- Purpose: Run independent checks on sanitized data and produce structured Finding objects
- Location: `src/unifi_audit.py` (_find_segmentation, _find_wifi, _find_firewall, _find_remote_access, _find_devices, _find_api_coverage); extended modules in `src/findings_enhanced.py`
- Contains: Each module inspects the safe dict and yields Finding(id, section, severity, status, title, current_state, recommendation, intent_question, evidence, maps_to, effort, impact)
- Depends on: Sanitized data dict; helper functions (_extract_list, _all_sites)
- Used by: Report generation and findings persistence

**Reporting & Persistence Layer:**
- Purpose: Serialize findings and generate human-readable reports
- Location: `src/unifi_audit.py` (`render_report()`, `main()`)
- Contains: Findings JSON serialization, markdown report generation, output file writing (audit_output/)
- Depends on: Analysis phase output
- Used by: User review and optional chat-based discussion

**Specialist Mode (Backup Parser):**
- Purpose: Parse `.unf` and `.unifi` backup files for airgap, forensic, or historical analysis
- Location: `src/parser.py` (`decrypt_unf()`, `extract_collections()`, sanitization, Finding modules)
- Contains: AES-128-CBC decryption of `.unf` files; ZIP extraction; BSON parsing; same Finding modules as live API
- Depends on: pycryptodome, pymongo (BSON)
- Used by: Phase 4 offline audits

## Data Flow

**Live API Mode (Primary Path, Phase 1):**

1. Load Config (environment only) → host, key, cloud flag
2. Create UniFiClient → session with X-API-KEY header, SSL config
3. Probe Global Endpoints → /proxy/network/integration/v1/info, /sites
4. Enumerate Sites → iterate site IDs
5. Probe Site-Scoped Endpoints → devices, clients, WLANs, firewall policies, VPN, port forwards, etc. per site
6. Aggregate into collected dict → { "sites": [...], "site_<id>": { "devices": [...], "networks": [...], ... }, "_endpoints_probed": [...], "_errors": [...] }
7. Sanitize → walk the dict, fingerprint any field in SECRET_FIELD_NAMES, return clean
8. Write raw_sanitized.json → inspection artifact (no raw secrets)
9. Analyze → run all Finding modules on clean dict
10. Write findings.json + report.md → user deliverables
11. Log audit trail → audit.log (no secrets, only endpoint names and HTTP statuses)

**Backup File Mode (Phase 4 Specialist):**

1. Inspect → `inspect_backup.py` detects `.unf` vs `.unifi` format
2. Decrypt → `decrypt_unf()` uses static AES-128-CBC key to unwrap
3. Extract ZIP → unzip the plaintext
4. Parse BSON → older format: db.gz with concatenated BSON docs; newer: mongodump-style directory
5. Organize into Collections → { "networkconf": [...], "device": [...], "wlanconf": [...], ... }
6. Sanitize → same fingerprinting as live API mode
7. Analyze → same Finding modules consume the dict
8. Output → same JSON + markdown as live mode

**State Management:**

- **Credentials:** In-memory only (session.headers["X-API-KEY"]). Never persisted, never logged, never in exceptions.
- **Raw collected data:** Dict with both API response shapes and metadata (_endpoints_probed, _errors).
- **Clean data:** Sanitized version written to raw_sanitized.json (safe for sharing).
- **Findings:** List[Finding] dataclass; serialized to findings.json for structured access.
- **User context:** Profile string (home, home_office, small_business, regulated_hipaa, regulated_pci) passed to analysis modules for scoring.

## Key Abstractions

**Finding Dataclass:**
- Purpose: Represents a single audit result with detection, recommendation, and framework mapping
- Location: `src/unifi_audit.py` (lines 100–114); `src/parser.py` (lines 155–169)
- Fields:
  - `id`: Unique identifier (e.g., "SEG-001", "WIFI-003")
  - `section`: Questionnaire section name (e.g., "Segmentation", "Wi-Fi")
  - `severity`: info | low | medium | high | critical
  - `status`: ok | gap | recommendation | unknown
  - `title`: Short human description
  - `current_state`: Plain-English summary of what was found
  - `recommendation`: Optional remediation guidance
  - `intent_question`: Optional confirmation question ("Is this what you intended?")
  - `evidence`: Dict with supporting data (sanitized)
  - `maps_to`: Dict { nist_csf, cis_v8, zt_tenet, ... } for control mapping
  - `effort`: quick | medium | project
  - `impact`: low | medium | high
- Pattern: Findings are produced independently by analysis modules; combined into a prioritized list sorted by severity

**UniFiClient:**
- Purpose: Minimal HTTP client that handles X-API-KEY auth, SSL verification, and graceful failure
- Location: `src/unifi_audit.py` (lines 223–270)
- Pattern: Session-based; GET-only; logs endpoints but never the key; scrubs exceptions for key leakage

**Analysis Modules (Finding Factories):**
- Purpose: Inspect sanitized data and yield Finding objects
- Pattern: Each module is a pure function that takes (clean: dict, profile: str) → list[Finding]
- Modules in `src/unifi_audit.py`:
  - `_find_segmentation()`: Detects flat networks, missing management VLANs
  - `_find_wifi()`: WPA version, PSK strength, rogue AP detection
  - `_find_firewall()`: Port forwarding patterns, geo-IP settings
  - `_find_remote_access()`: VPN protocols (PPTP → critical, WireGuard → ok), port-forwards-without-VPN
  - `_find_devices()`: SSH enabled, firmware staleness
  - `_find_api_coverage()`: Meta-finding on what endpoints failed (version mismatch, scope)
- Extended modules in `src/findings_enhanced.py`: wireless tuning, threat detection, logging, backup validation

**Tier System (Voice Routing):**
- Purpose: Present findings in three levels of technical depth without rewriting findings
- Pattern: Single Finding object with `title`, `current_state`, `recommendation` written in "Standard" voice
- Future (Phase 2): Render the same Finding differently for Guided (novice) vs. Pro (engineer) tiers based on skills-check result
- Current status: All output is Standard voice; tier logic scaffolded

**Profile System:**
- Purpose: Adjust findings severity and scoring based on user context
- Pattern: Passed as `profile` parameter through `analyze()` to each module
- Profiles: home, home_office, small_business, regulated_hipaa, regulated_pci
- Example: "Flat network" is critical for regulated_hipaa but medium for home
- Status: Scaffolded in code; profile-specific weight logic deferred to Phase 1 finalization

## Entry Points

**Live Audit Script:**
- Location: `src/unifi_audit.py` (lines 631–689)
- Invocation: `python3 unifi_audit.py` (after setting UNIFI_API_KEY, UNIFI_HOST env vars)
- Triggers: User runs script locally; credentials never transit network except to UniFi controller
- Responsibilities: Load config, create client, collect all, sanitize, analyze, write outputs

**Backup Inspector:**
- Location: `src/inspect_backup.py` (lines 19–65)
- Invocation: `python3 inspect_backup.py path/to/backup.unf`
- Triggers: User wants to preview a backup before parsing
- Responsibilities: Detect format, report file size and structure, no decryption or analysis

**Backup Parser (Phase 4):**
- Location: `src/parser.py` (skeleton; not yet integrated with live audit)
- Invocation: `python3 parser.py analyze path/to/backup.unf --out report.md`
- Triggers: User needs offline audit (airgap, forensic, MSP handoff)
- Responsibilities: Decrypt, extract BSON, sanitize, run same Finding modules, output report

## Error Handling

**Strategy:** Graceful degradation. Individual failures don't abort the audit.

**Patterns:**

- **Collection phase:** Each endpoint is probed independently. 404 → skip and log. 403 → add to _errors with hint "insufficient scope". Network failure → continue.
- **Analysis phase:** Each Finding module is wrapped in try/except. Module exception → logged as warning, next module runs. If all fail, return empty list.
- **Report phase:** Always succeeds; worst case, report has findings from partial data.

**Example (unifi_audit.py lines 367–371):**
```python
for name, fn in modules:
    try:
        findings.extend(fn(clean, profile))
    except Exception as e:
        logger.warning(f"Module {name} failed: {e}")
```

## Cross-Cutting Concerns

**Logging:**
- Framework: Python logging module, file + stderr
- No secrets: Keys, PSKs, passwords never logged (scrubbed in UniFiClient.get() exception handler)
- Audit trail: Endpoint names, HTTP statuses, Finding counts written to audit.log
- File: `src/unifi_audit.py` (setup_logger, lines 162–176)

**Validation:**
- Where: Happens during Finding module execution (each module validates the structure it expects)
- Pattern: Defensive; modules call _extract_list() to handle {"data": [...]}, {...}, etc. response shapes
- Fallback: If validation fails, module returns empty findings (no crash)

**Credential Handling:**
- Read: Environment variables only (UNIFI_API_KEY, UNIFI_HOST, UNIFI_USE_CLOUD, UNIFI_VERIFY_SSL)
- Transport: X-API-KEY header in requests.Session
- Memory: Held only for the duration of collect_all(); dropped when client.close()
- Output: Never appears in findings.json, report.md, raw_sanitized.json, or audit.log
- Verified: Scrub logic in UniFiClient.get() (line 258: `safe_msg = str(e).replace(self.cfg["key"], "<REDACTED>")`)

---

*Architecture analysis: 2026-04-25*
