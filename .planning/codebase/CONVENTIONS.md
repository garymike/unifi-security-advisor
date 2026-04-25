# Coding Conventions

**Analysis Date:** 2026-04-25

## Naming Patterns

**Files:**
- Python modules use lowercase with underscores: `unifi_audit.py`, `findings_enhanced.py`, `inspect_backup.py`
- Main entry points include verb + domain: `unifi_audit.py` (primary), `inspect_backup.py` (utility)
- Parser/analysis modules organized by function: `parser.py` (monolithic Phase 1 skeleton), split into domain modules in production (`findings_enhanced.py`, etc.)

**Functions:**
- Lowercase with underscores: `load_config()`, `collect_all()`, `analyze()`, `_fingerprint()`, `render_report()`
- Private helpers prefixed with underscore: `_extract_sites()`, `_extract_list()`, `_all_sites()`
- Finder functions follow pattern `find_[domain]()`: `find_segmentation()`, `find_wifi()`, `find_firewall()`, `find_remote_access()`, `find_devices()`, `find_admin()`, `find_api_coverage()`

**Variables:**
- Local: lowercase with underscores: `cfg`, `site_id`, `clean`, `raw`, `logger`
- Configuration/constants: UPPERCASE with underscores for globals: `OUTPUT_DIR`, `SECRET_FIELD_NAMES`, `ENDPOINTS_LOCAL`, `SITE_SCOPED_LOCAL`, `ENDPOINTS_CLOUD`
- Class fields match Python convention (camelCase in nested data objects from API responses, sanitized to snake_case in internal models)

**Types/Dataclasses:**
- PascalCase: `Finding`, `UniFiClient`
- All public dataclasses include `from dataclasses import asdict, dataclass, field`
- Field defaults use `field(default_factory=dict)` for mutable defaults

## Code Style

**Formatting:**
- No formatter configured yet (PEP 8 de facto standard)
- Line length: implicit 100-120 character target (observed in practice)
- Indentation: 4 spaces (Python standard)
- Double quotes for strings (observed consistently)
- Blank lines separate logical sections within functions

**Linting:**
- Not enforced in Phase 1 (no `.pylintrc`, `.flake8`, or `pyproject.toml` present)
- Type hints enforced by convention (not by runtime checker yet)

## Import Organization

**Order:**
1. `from __future__ import annotations` (always first for Python 3.9+ forward compatibility)
2. Standard library imports: `import hashlib`, `import json`, `import logging`, `import os`, `import sys`, `import time`
3. Collections and type hints: `from dataclasses import asdict, dataclass, field` / `from pathlib import Path` / `from typing import Any`
4. Third-party imports (with deferred/conditional loading for optional deps): `import requests`, `from requests.exceptions import RequestException`
5. Relative imports from modules in same package

**Path Aliases:**
- None in use; absolute imports only

**Deferred Imports:**
- Heavy dependencies deferred until needed: `from Crypto.Cipher import AES` (inside function that uses it), `import bson` (inside function). This allows `--help` and utilities like `inspect_backup.py` to run without full dependency set installed.

**Import Guards:**
- Try/except with user-friendly error message on missing deps (see `unifi_audit.py:54-60`):
  ```python
  try:
      import requests
      from requests.exceptions import RequestException
  except ImportError:
      sys.stderr.write("Missing dependency. Run: pip install requests\n")
      sys.exit(1)
  ```

## Error Handling

**Patterns:**
- Credential loading errors: exit early with clear user guidance, never attempt retry
- API errors: catch `RequestException`, sanitize exception text by redacting credential strings, log safe message, return `(0, {error: ...})` rather than raise
- Collection parsing: graceful degradation; skip 404 endpoints with info-level log, continue with next endpoint
- Module failures: wrapped in try/except at analysis layer; log warning and continue (one failed module doesn't abort audit)
- Config validation: explicit checks with sys.exit() and stderr messages (not exceptions)

**Exception Handling:**
- Exceptions sanitized before logging (e.g., `safe_msg = str(e).replace(self.cfg["key"], "<REDACTED>")`)
- No traceback printing that could leak credentials
- Error dictionary includes hint (e.g., `{"endpoint": name, "status": 403, "hint": "insufficient scope"}`)

## Credential Handling (Critical — see docs/05-credential-handling.md)

**Input Sources (Absolute constraint):**
- Environment variables ONLY: `UNIFI_API_KEY`, `UNIFI_HOST`, `UNIFI_USE_CLOUD`, `UNIFI_VERIFY_SSL`, `UNIFI_PROFILE`
- No CLI args, no chat input, no URL parameters, no config files with secrets (Phase 1)
- Implementation: `load_config()` reads `os.environ.get()`, validates, exits on missing required vars

**Key Handling in Memory:**
- Held in `cfg` dict passed to `UniFiClient.__init__()`
- Never logged directly; redacted in log messages via string replacement (`.replace(self.cfg["key"], "<REDACTED>")`)
- Never included in exception messages (all exceptions sanitized before logging)
- Never written to any output file
- Session closed explicitly after use: `client.close()`

**Sanitization Before Output:**
- All secrets redacted to fingerprints BEFORE any data crosses trust boundary (before file write)
- Secret field detection: exact name matching against `SECRET_FIELD_NAMES` set (PSK, RADIUS secrets, SSH passwords, API keys, auth tokens)
- Fingerprint format: `{length, fingerprint (SHA256 first 12 chars), has_symbols, has_digits, has_mixed_case}`
- Sanitization is recursive, handles nested dicts and lists
- Applied once at collection phase (line 652 in `unifi_audit.py`): `clean = sanitize(raw)`
- All downstream code (findings, reports) works with sanitized data only

**Transport Security:**
- API calls use requests.Session with `verify_ssl` flag (defaults to False for local self-signed, True for cloud)
- Header includes only `X-API-KEY: <value>` and `Accept: application/json`
- No telemetry, no cloud relay, no logging of keys

**Audit Trail:**
- Logging to `audit.log` in `OUTPUT_DIR`; shows API calls and timestamps but never the key itself
- Log format: `%(asctime)s %(levelname)s %(message)s`
- Example log entry: `2026-04-25 10:30:45,123 INFO GET https://192.168.1.1/proxy/network/integration/v1/info` (URL visible, no key)

## Comments

**When to Comment:**
- Section headers use multi-line blocks for large logical sections (see `unifi_audit.py` — data model sections, collection phase, findings phase, report generation are all marked with `# =============================================================================` comment blocks)
- Inline comments explain WHY, not WHAT (e.g., `# UniFi doesn't pad in the standard way; -nopad in the reference openssl cmd.`)
- Comments on non-obvious algorithm choices or workarounds (e.g., handling varying response shapes for list endpoints)

**Docstrings:**
- Mandatory on all public functions (per CLAUDE.md)
- Mandatory on all public classes and modules
- Module-level docstring at top (e.g., `unifi_audit.py:1-40`)
- Function signature + one-line summary + longer description + usage notes where helpful
- Format: standard Python docstrings (not Google/NumPy style yet)
- Example from `unifi_audit.py:224-225`:
  ```python
  def get(self, path: str) -> tuple[int, Any]:
      """GET a path or absolute URL. Returns (status_code, json_or_text)."""
  ```

## Type Hints

**Scope:**
- Type hints on all public functions (per CLAUDE.md): parameter types and return types
- Type hints on class methods and private functions too (observed pattern)
- Type hints in dataclass field definitions

**Patterns:**
- Use `|` for union (Python 3.10+ syntax, enabled by `from __future__ import annotations` at top of every file)
- Use `Any` from typing for truly dynamic data (API responses, dicts)
- Use `dict[str, list[dict[str, Any]]]` for complex nested structures (not just `dict`)
- Use `list[Finding]` for lists of dataclass instances
- Use `tuple[int, Any]` for multi-value returns
- Optional return types: `str | None`, `dict | None` (not `Optional[str]`)

**Examples from codebase:**
```python
def load_config() -> dict:
def collect_all(client: UniFiClient, logger: logging.Logger) -> dict:
def analyze(clean: dict, profile: str, logger: logging.Logger) -> list[Finding]:
def get(self, path: str) -> tuple[int, Any]:
def _fingerprint(value: Any) -> dict[str, Any]:
def _extract_sites(sites_response: Any) -> list[dict]:
```

## Function Design

**Size:**
- Typical functions 10-40 lines; larger functions (50+) broken into helper functions
- `collect_all()` at 60 lines is on high end; it's a coordinator that iterates endpoints
- Finding modules (`_find_wifi()`, etc.) are 30-60 lines each; reasonable for a single audit concern

**Parameters:**
- Prefer passing structured objects (e.g., `cfg: dict`, `client: UniFiClient`) over many individual args
- Limit to 3-5 explicit parameters; use dict/dataclass for config bundles
- Logger often passed explicitly for observability (not global)

**Return Values:**
- Functions return data structures (lists, dicts, dataclass instances) not side effects
- Coordinate with side effects (file writes, logging) at call site (main/orchestrator level)
- Findings modules return `list[Finding]` with empty list if no issues found

## Module Design

**Exports:**
- Public functions/classes not prefixed with underscore
- Private helpers prefixed with underscore: `_extract_list()`, `_extract_sites()`, `_all_sites()`, `_fingerprint()`, `_find_segmentation()` (wait, these are public finders, not private)
- Actually: finders are public (called by `analyze()`), but internal helpers are private

**Barrel Files:**
- No `__init__.py` files in `src/` directory (not a package yet; each module stands alone or is imported directly)
- Modules importable standalone per CLAUDE.md requirement

**Module Independence:**
- Each module can be imported and used independently: `from src.parser import Finding, sanitize()`
- Dependencies on stdlib + requests + pycryptodome + pymongo only (Phase 1-4 constraint)
- No cross-module imports between `unifi_audit.py`, `parser.py`, etc. yet (they share patterns, not code)

## Tier System (Guided / Standard / Pro)

**Implementation:**
- Not yet in code (Phase 1 is API audit script, not wizard)
- Defined in QUESTIONNAIRE.md with three voices per question
- Example from QUESTIONNAIRE.md section 0:
  - Guided: "How good are you at networking?"
  - Standard: "Networking comfort: New / Comfortable / Pro"
  - Pro: "Describe your network topology and admin style"
- Routing logic will be in Phase 2 wizard; Phase 1 script uses `UNIFI_PROFILE` env var to select context (home, home_office, small_business, regulated_hipaa, regulated_pci)

---

*Convention analysis: 2026-04-25*
