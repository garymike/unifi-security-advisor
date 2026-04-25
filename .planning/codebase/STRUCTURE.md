# Codebase Structure

**Analysis Date:** 2026-04-25

## Directory Layout

```
unifi-security-advisor/
├── .planning/                   # Generated during development
│   └── codebase/                # Codebase analysis outputs
│
├── docs/                        # Design documentation (reading order: 01-08)
│   ├── 01-design-philosophy.md  # Biomimetic framing, discovery-first pattern
│   ├── 02-api-strategy.md       # Network Integration vs Site Manager tradeoffs
│   ├── 03-site-manager-vs-network-integration.md  # Detailed API comparison
│   ├── 04-backup-file-strategy.md  # .unf/.unifi formats, Phase 4 scope
│   ├── 05-credential-handling.md   # Security constraints and compliance
│   ├── 06-mcp-strategy.md          # Why we integrate sirkirby/unifi-mcp, not build our own
│   ├── 07-coverage-analysis.md     # Gap analysis vs 10-point video
│   └── 08-questionnaire-addendum.md # Free-text and "not sure" resolution
│
├── src/                         # Source code (executable and library)
│   ├── unifi_audit.py           # Main Phase 1 deliverable (689 lines)
│   ├── parser.py                # Backup parser skeleton, Phase 4 (562 lines)
│   ├── findings_enhanced.py     # Extended finding modules (624 lines, not yet wired in)
│   └── inspect_backup.py        # Safe backup file inspector (65 lines)
│
├── samples/                     # Example outputs and walkthrough data
│   ├── discovery-first-design-notes.md
│   ├── sample-gap-questions.md
│   ├── sample-report.md
│   └── walkthrough-responses.md
│
├── .claude/                     # Claude Code project config
│   └── settings.local.json      # Local permission settings
│
├── README.md                    # Project overview and quick-start links
├── CLAUDE.md                    # Claude Code context (conventions, constraints)
├── ROADMAP.md                   # Phase plan and working checklist
├── DECISIONS.md                 # Key decisions with rationale
├── QUESTIONNAIRE.md             # Full consolidated questionnaire (10KB)
├── AUDIT_QUICKSTART.md          # User-facing 5-minute setup
└── package-lock.json            # Minimal (placeholder for future)
```

## Directory Purposes

**docs/:**
- Purpose: Design rationale and architecture documentation
- Contains: 8 numbered markdown files; each 5-15KB
- Reading order: Sequential (01 → 08) recommended for new contributors
- Committed: Yes; part of design record
- Key files: `docs/01-design-philosophy.md` (foundation), `docs/02-api-strategy.md` (why API-first), `docs/05-credential-handling.md` (security model)

**src/:**
- Purpose: Executable code and library modules
- Contains: Python 3.9+ modules for audit, parsing, and finding generation
- Key invariant: All modules importable standalone; no framework lock-in
- Committed: Yes
- Key files:
  - `src/unifi_audit.py` (689 lines): Primary entry point for Phase 1
  - `src/parser.py` (562 lines): Backup decryption and BSON parsing (Phase 4 skeleton)
  - `src/findings_enhanced.py` (624 lines): Extended finding modules (not yet integrated)
  - `src/inspect_backup.py` (65 lines): Safe pre-check for backup files

**samples/:**
- Purpose: Example outputs, walkthrough transcripts, test data guidance
- Contains: Markdown files showing expected report formats, user interaction patterns
- Committed: Yes; reference material for Phase 2 wizard design
- Key files: `samples/sample-report.md` (what output looks like), `samples/walkthrough-responses.md` (user intent examples)

**.planning/codebase/:**
- Purpose: Machine-readable codebase analysis (generated)
- Contains: ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, STACK.md, INTEGRATIONS.md, CONCERNS.md
- Generated: Yes (via /gsd-map-codebase)
- Committed: Yes; used by /gsd-plan-phase and /gsd-execute-phase

## Key File Locations

**Entry Points:**

- `src/unifi_audit.py` (`main()`): Primary script for live API audits. Invoked as `python3 unifi_audit.py` after env vars set.
- `src/inspect_backup.py` (`inspect()`): Preview backup format before parsing. Invoked as `python3 inspect_backup.py path/to/file.unf`.
- `src/parser.py` (`main()` stub): Future CLI for backup-file mode. Currently skeleton.

**Configuration & Constants:**

- `src/unifi_audit.py` (lines 67–93): `ENDPOINTS_LOCAL`, `ENDPOINTS_CLOUD`, `SITE_SCOPED_LOCAL` (endpoint definitions)
- `src/unifi_audit.py` (lines 183–188): `SECRET_FIELD_NAMES` (field names to fingerprint)
- `src/parser.py` (lines 40–42): `UNF_KEY`, `UNF_IV` (AES-128-CBC key and IV for .unf decryption)
- `CLAUDE.md`: Profile labels: home, home_office, small_business, regulated_hipaa, regulated_pci

**Core Logic:**

- `src/unifi_audit.py` (lines 100–114): `Finding` dataclass
- `src/unifi_audit.py` (lines 120–155): `load_config()`, credential loading from env
- `src/unifi_audit.py` (lines 223–270): `UniFiClient` class (HTTP session management)
- `src/unifi_audit.py` (lines 276–337): `collect_all()` (endpoint enumeration and data aggregation)
- `src/unifi_audit.py` (lines 191, 205): `_fingerprint()`, `sanitize()` (secret redaction)
- `src/unifi_audit.py` (lines 355–559): `analyze()` and all Finding modules (`_find_segmentation`, `_find_wifi`, etc.)
- `src/unifi_audit.py` (lines 579–624): `render_report()` (markdown generation)

**Testing:**

- No test framework integrated yet (Phase 1 validation against real network pending)
- Fixtures deferred: `samples/sample-report.md`, `samples/sample-gap-questions.md` are reference outputs, not automated tests

## Naming Conventions

**Files:**

- Module files: snake_case.py (e.g., `unifi_audit.py`, `findings_enhanced.py`)
- Documentation: UPPERCASE.md (e.g., `README.md`, `CLAUDE.md`, `ROADMAP.md`)
- Design docs: numbered-prefixes (e.g., `01-design-philosophy.md`, `02-api-strategy.md`)

**Directories:**

- Single-word lowercase for source (`src`, `docs`, `samples`)
- Hidden config (`.claude`, `.planning`) use leading dot
- Nested for organization (`.planning/codebase/`)

**Functions:**

- Private (module-internal): leading underscore (e.g., `_find_segmentation()`, `_extract_list()`)
- Public: no underscore (e.g., `load_config()`, `collect_all()`, `analyze()`)
- Finding modules: `_find_<section>()` pattern (e.g., `_find_wifi()`, `_find_firewall()`)

**Classes:**

- PascalCase (e.g., `Finding`, `UniFiClient`)
- Dataclass pattern used for Finding (immutable, JSON-serializable)

**Constants:**

- UPPERCASE_WITH_UNDERSCORES (e.g., `SECRET_FIELD_NAMES`, `ENDPOINTS_LOCAL`, `UNF_KEY`)

## Where to Add New Code

**New Finding Module:**
- Primary location: `src/unifi_audit.py` (if small/foundational) or `src/findings_enhanced.py` (if extended)
- Pattern: Function `_find_<section>(clean: dict, profile: str) -> list[Finding]`
- Integration: Register in `analyze()` modules list (`src/unifi_audit.py`, line 359)
- Related: Add questionnaire item to `QUESTIONNAIRE.md`
- Related: Add framework mapping to Finding (`maps_to` dict)

**New Endpoint:**
- If local API: Add to `SITE_SCOPED_LOCAL` or `ENDPOINTS_LOCAL` (`src/unifi_audit.py`, lines 71–86)
- If cloud API: Add to `ENDPOINTS_CLOUD` (`src/unifi_audit.py`, lines 89–93)
- Pattern: `("endpoint_name", "/proxy/network/integration/v1/...")` for local
- Collection: Automatically probed in `collect_all()`, gracefully skipped if 404

**New Helper Function:**
- Location: Inline in `src/unifi_audit.py` or `src/parser.py` (avoid new files in Phase 1)
- Pattern: Leading underscore if module-private (e.g., `_extract_list()`)
- Example: `_extract_list()` (line 562) handles varying response shapes

**New Config Variable:**
- Environment variable: Load in `load_config()` (lines 120–155)
- Pattern: `os.environ.get("UNIFI_<UPPERCASE>", default)`
- Current env vars: `UNIFI_API_KEY`, `UNIFI_HOST`, `UNIFI_USE_CLOUD`, `UNIFI_VERIFY_SSL`, `UNIFI_PROFILE`

**Tests:**
- Phase 1: Manual validation against real UniFi network (see `ROADMAP.md`)
- Phase 2+: Automated fixtures planned (`samples/` directory prepared for this)
- Runner: pytest or unittest (TBD in Phase 2)

## Special Directories

**.planning/codebase/:**
- Purpose: Generated codebase analysis documents
- Generated: Yes, via /gsd-map-codebase
- Committed: Yes, to guide /gsd-plan-phase and /gsd-execute-phase
- Contents: ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, STACK.md, INTEGRATIONS.md, CONCERNS.md

**audit_output/ (runtime-generated):**
- Purpose: Outputs from running `unifi_audit.py`
- Generated: Yes, at runtime
- Committed: No (git-ignored)
- Contains: audit.log, raw_sanitized.json, findings.json, report.md

**.claude/:**
- Purpose: Project-specific Claude Code config
- Status: `settings.local.json` present (permission allowlist)
- Use: Defines project conventions for Claude Code sessions

## Module Dependencies

**unifi_audit.py dependencies:**
- Standard library: hashlib, json, logging, os, sys, time, dataclasses, pathlib
- Third-party: requests (only external dependency for Phase 1)
- Internal: None (standalone executable)

**parser.py dependencies:**
- Standard library: argparse, gzip, hashlib, io, json, sys, zipfile, dataclasses, pathlib
- Third-party: pycryptodome (Crypto.Cipher.AES), pymongo (bson)
- Internal: None (standalone executable)

**findings_enhanced.py dependencies:**
- Internal: Imports from `parser.py` (Finding class, _get_collection, _get_setting helpers)
- Status: Currently not wired into `unifi_audit.py`'s `analyze()` modules list

**inspect_backup.py dependencies:**
- Standard library: sys, zipfile, pathlib
- No third-party or internal dependencies (pure inspection)

---

*Structure analysis: 2026-04-25*
