# Technology Stack

**Analysis Date:** 2026-04-25

## Languages

**Primary:**
- Python 3.9+ - Full codebase. Core audit logic, finding engines, backup parsing, report generation.

## Runtime

**Environment:**
- Python 3.9+ (standard CPython interpreter)

**Package Manager:**
- pip (PyPI)
- Lockfile: `package-lock.json` present (empty, placeholder for Node/JavaScript tooling if added later)

## Frameworks

**Core:**
- No web framework (Phase 1) - Pure Python functions and dataclasses. API client uses stdlib + requests only.
- `dataclasses` (stdlib) - Finding and config models. See `src/unifi_audit.py` line 100-114 for `Finding` dataclass.

**Testing:**
- Not yet implemented. Phase 1 uses manual validation against real/sample networks.

**Build/Dev:**
- No build system configured yet. Deliverables are standalone Python scripts.

## Key Dependencies

**Critical (Phase 1-4):**
- `requests` (for Network Integration and Site Manager API calls)
  - Used in `src/unifi_audit.py` lines 55-56, 223-269
  - `requests.Session` for connection reuse, X-API-KEY headers
  - No version pinning yet (design calls for minimal lock-in)

**Conditional (Phase 4 - backup-file mode):**
- `pycryptodome` (AES-128-CBC decryption for .unf files)
  - Used in `src/parser.py` line 47 (deferred import)
  - Decrypts .unf backup format using static keys from UniFi source
- `pymongo` (BSON parsing from MongoDB dumps in backup files)
  - Used in `src/parser.py` line 69 (deferred import)
  - Parses gunzipped BSON from backup's db.gz

**Standard Library Only:**
- `hashlib` - SHA256 fingerprinting of secrets before output (sanitization)
- `json` - API response parsing, findings report serialization
- `logging` - Audit trail (no secrets in logs)
- `os` - Environment variable loading for credentials
- `sys` - CLI arg parsing, error handling
- `time` - Rate-limiting between API calls (0.1s sleep between site-scoped requests)
- `pathlib.Path` - Output directory management
- `dataclasses` - Finding and config models
- `typing` - Type hints (required per CLAUDE.md)
- `argparse` - CLI argument parsing for backup-file mode
- `gzip`, `zipfile`, `io` - Backup archive handling
- `requests.exceptions`, `urllib3.exceptions` - HTTP error handling

## Configuration

**Environment Variables (required):**
- `UNIFI_API_KEY` - X-API-KEY for authentication (env var only, never CLI args per CLAUDE.md constraint)
- `UNIFI_HOST` - Controller IP/hostname for local mode (e.g., 192.168.1.1)
- Optional: `UNIFI_USE_CLOUD` - Set to "true" for Site Manager API (cloud-routed)
- Optional: `UNIFI_VERIFY_SSL` - Override SSL verification (defaults: true for cloud, false for local self-signed)
- Optional: `UNIFI_PROFILE` - Scoring profile: `home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`. Default: `home_office`

**Environment Files:**
- No .env file support yet. Credentials from environment variables or OS keychain only (see `docs/05-credential-handling.md`).
- No .env.example file (per CLAUDE.md constraint: never store secrets in files).

**Configuration Files:**
- `AUDIT_QUICKSTART.md` - User-facing setup instructions
- `QUESTIONNAIRE.md` - Finding definitions and user-interview templates
- Project docs in `docs/` - Design philosophy, API strategy, etc.

## Build

**Scripts:**
- `src/unifi_audit.py` - Phase 1 deliverable. Executable directly: `python3 unifi_audit.py`
- `src/parser.py` - Phase 4 skeleton. Usage: `python parser.py analyze path/to/backup.unf --out report.md`
- `src/inspect_backup.py` - Safe structural inspection of backup files. Usage: `python inspect_backup.py <path>`
- `src/findings_enhanced.py` - Modular finding functions (imported by parser.py in Phase 4 build)

**Distribution:**
- Phase 1: Single-file script (no packaging yet)
- Future: PyPI package, Docker image, or bundled executable (undecided per DECISIONS.md D-195)

## Platform Requirements

**Development:**
- Python 3.9+ with `requests` library installed
- Network access to UniFi controller (local) or `api.ui.com` (cloud) for auditing
- Unix-like shell (bash recommended; Windows WSL2 or native bash in Git Bash works)
- Text editor or IDE with Python support

**Production:**
- Python 3.9+ with `requests` library
- For local auditing: Network connectivity to UniFi controller on same LAN
- For cloud auditing: Outbound HTTPS to `api.ui.com`
- For backup-file mode: Local filesystem access; `pycryptodome` and `pymongo` installed

**Tested Against:**
- UniFi Network 9.3.43+ (Network Integration API requires this minimum version)
- Older versions gracefully skip unavailable endpoints (404 handling in `unifi_audit.py` lines 301-302)
- Phase 4 backup-file mode: .unf format (single-site backup), .unifi format (console-level backup, future)

---

*Stack analysis: 2026-04-25*
