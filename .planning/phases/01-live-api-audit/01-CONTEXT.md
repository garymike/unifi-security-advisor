# Phase 1: Live API Audit - Context

**Gathered:** 2026-04-25
**Status:** Ready for planning
**Source:** Interactive `/gsd-discuss-phase 1` — all 6 gray areas discussed.

<domain>
## Phase Boundary

Finalize the live UniFi API audit so it runs end-to-end against a real Network Integration deployment, emits sanitized markdown + JSON output, and covers the 6 always-float-to-top findings to the extent the API allows (with the 3 undetectable ones surfaced as `unknown` Findings for Phase 2 handoff).

**In scope:**
- Wire 6 enhanced finding modules (`findings_enhanced.py`) into `unifi_audit.py`'s `analyze()` pipeline
- Implement always-float-to-top override (`C-finding-002`)
- Implement cross-answer / compound-finding correlation pass (`D-003`)
- Implement profile-aware scoring weights table
- Surface API-undetectable findings honestly as `unknown` Findings with intent questions
- Validate against a real UniFi network (≥ 9.3.43)
- Add minimal pytest infrastructure focused on highest-risk surfaces (sanitization + API parsing)
- Extract `src/sanitizer.py` to remove DRY violation between audit + parser

**Out of scope (explicit):**
- Apply mode (Phase 6) — `C-write-001`
- Multi-site MSP aggregation (Phase 3)
- Backup-file mode work (Phase 4) — except for sharing `sanitizer.py`
- Wizard / tier-aware rendering (Phase 2)
- Auto profile inference — deferred to Phase 2 wizard
- Detection of MFA / default creds / WAN-reachable mgmt-plane — these become `unknown` Findings with intent questions, not detection logic
- CVE database integration — deferred (firmware finding ships with EOL list only)

</domain>

<decisions>
## Implementation Decisions

### Enhanced-Module Integration (Area 1)

- **D-01:** **API-to-collections adapter.** `unifi_audit.py:analyze()` builds a parser-shaped dict (keyed by collection names like `device`, `wlanconf`, `networkconf`) from the sanitized API response, then passes it to the existing `findings_enhanced.py` modules **unmodified**. The adapter is one new function/module (~50-100 LOC). This preserves Phase 4 (backup) reuse: backup mode already produces parser-shape data, so the same enhanced modules run there with no adapter.

  - Keep `findings_enhanced.py` source untouched in this phase
  - Adapter lives in a new file (e.g., `src/api_to_collections.py`) — single responsibility, testable in isolation
  - Adapter must produce shapes that match what `findings_enhanced.py` already reads, verified by passing a captured API fixture through the adapter and confirming each enhanced module produces non-empty findings

### Pipeline Extension: Always-Float-to-Top + Compound Correlation (Area 2)

- **D-02:** **Two new analyze() passes after individual modules.**
  1. `_correlate_findings(findings, profile) -> list[Finding]` — runs the compound-finding rules (D-003), emits new Findings (e.g., "priority mismatch", "keys-to-kingdom", "pivot path"). Pure-Python rules.
  2. `_apply_float_top(findings) -> list[Finding]` — re-sorts the combined list. Always-top finding IDs come from a single canonical list (likely a constant in `unifi_audit.py` or a sibling module).

- **D-03:** **API-undetectable always-top findings become `status="unknown"` Findings.** For the 3 not detectable from Network Integration API alone (no MFA / default credentials / management plane WAN-reachable), Phase 1 emits Findings with:
  - `status="unknown"`
  - `current_state="Cannot be determined via Network Integration API alone"`
  - `intent_question` populated (becomes a Phase 2 wizard input)
  - `recommendation` pointing to the Phase 2 wizard
  - Float-to-top still applies — they appear at the top of the report so users see the gap

  This is the Honesty > Usefulness ordering from `C-precedence-001` made concrete.

- **D-04:** **Compound correlation rules live in a new `src/findings_correlations.py`.** One Python function per compound finding, returns `Finding | None`. Consistent with the `findings_enhanced.py` module style. No new YAML format, no rules engine to maintain.

  Compound findings to implement at minimum (from `intel/decisions.md` D-003 examples):
  - Priority mismatch — downtime-sensitivity high + single WAN + work ranked low
  - Keys-to-kingdom — mobile remote management on + MFA unknown
  - Pivot path — NAS reachable by all + IoT internet-access unknown

  Additional compound findings can be added in this file without touching the per-section modules.

### Profile-Aware Scoring (Area 3)

- **D-05:** **`WEIGHTS` dict in a new `src/profile_weights.py`**, keyed `(profile, section) -> multiplier`. Imported by `analyze()` and applied in the ranking step (`(impact × user_priority_weight × WEIGHTS[(profile, section)]) / effort_hours`). Format choice: simple Python dict (auditable, type-checkable, no parsing layer).

  Profiles: `home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci` (per `C-profile-001`).
  Sections: align with questionnaire sections (per `C-questionnaire-003`).

  Weight table starts conservative — `1.0` for typical (section, profile) pairs; lift specific cells (e.g., `(regulated_hipaa, logging) = 2.0` to surface long-retention recommendations; `(home, logging) = 0.5` to suppress them). Concrete values land in the plan.

- **D-06:** **Manual profile only in Phase 1.** `UNIFI_PROFILE` env var, default `home_office`. Report shows `"Profile: home_office (manual)"` so the user knows what shaped the scoring.

  Auto-detection (per CONCERNS.md heuristics) is deferred to Phase 2 — the wizard has the skills-check and interactive-correction UX needed to do auto-detection responsibly. Inferring silently in Phase 1 risks miscategorizing and degrading scoring quality for the user.

### Validation Strategy & Test Infrastructure (Area 4)

- **D-07:** **Manual real-network run captures fixtures, then a focused pytest suite uses them.** Approach:
  1. User runs `unifi_audit.py` against a real UniFi network ≥ 9.3.43
  2. Sanitized output (`raw_sanitized.json`) is the canonical fixture
  3. Pytest tests target the highest-risk code paths first: `sanitize()`, `_extract_list()`, `_extract_sites()`, plus a smoke test that runs the full pipeline against the captured fixture and asserts findings shape
  4. Add `pytest` + `tests/` directory + `conftest.py` to the project. Pytest is dev-only — does not violate the stdlib + requests/pycryptodome/pymongo runtime-dep rule from `C-code-001`

  Rationale: zero tests is flagged as CRITICAL for a security tool in CONCERNS.md. Going test-first on sanitization specifically is the strongest leak-prevention move available.

- **D-08:** **Commit one anonymized canonical fixture to `samples/fixtures/`.** A single sanitized API JSON dump (e.g., `samples/fixtures/api_dump_home_office.json`) lives in the repo, used by pytest for regression. User-supplied or freshly captured fixtures stay under `tests/fixtures/` (gitignored). The repo fixture must:
  - Be sanitized through `sanitize()` (so it contains only fingerprints, never raw secrets)
  - Have device names, MAC addresses, IPs, hostnames anonymized beyond the standard sanitizer scope
  - Be small enough to read in code review (<200 KB ideally)

### Sanitization DRY Fix (Area 5)

- **D-09:** **Extract `src/sanitizer.py` now** as the first task of this phase. Both `src/unifi_audit.py:183` and `src/parser.py:103` import `SECRET_FIELD_NAMES`, `_fingerprint`, and `sanitize` from it. Eliminates the duplicate-set leak risk immediately and makes the enhanced-module wiring (D-01) cleaner — the adapter doesn't need to think about which of two sanitization paths to use.

  Bonus: `findings_enhanced.py` modules can also import from `sanitizer.py` if they ever need it (they currently don't, but standardizes the surface).

### Coverage-Gap Surfacing in Phase 1 Output (Area 6)

- **D-10:** **Each undetectable always-top finding emits an `unknown` Finding** (already covered in D-03). The Phase 1 report renders these alongside detected findings, not in a separate "Limitations" section. Rationale: keeps the report's structure single-track (everything is a Finding), surfaces gaps where the user is already paying attention, and provides Phase 2 wizard inputs in a structured form (`intent_question` populated) rather than free-text limitations prose.

### Claude's Discretion

These were not asked but the planner has flexibility:
- Exact directory layout for `tests/` (e.g., `tests/unit/` vs flat `tests/`)
- Specific multipliers in the `WEIGHTS` dict (start with 1.0 baseline, lift cells where evidence suggests)
- Adapter implementation style (function vs class — pick what reads cleanly)
- Naming of the always-top constant list (e.g., `ALWAYS_TOP_FINDING_IDS` — bikeshed welcome but not blocking)
- Pytest configuration details (`pyproject.toml` vs `pytest.ini`)
- Whether to add a `--profile` CLI flag in addition to `UNIFI_PROFILE` env var (env var is required; CLI flag is optional sugar)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project-level (binding)

- `.planning/PROJECT.md` — Locked decisions D-001..D-009, 26 constraints (`C-*`), trust boundary diagram. Read first.
- `.planning/REQUIREMENTS.md` — Phase 1 scope: 22 REQ-IDs (1 phase deliverable + 11 finding modules + 4 needs-work + 7 validation items)
- `.planning/STATE.md` — Current Phase 1 progress and outstanding blockers
- `.planning/intel/decisions.md` — D-001..D-009 with full rationale and consequences
- `.planning/intel/constraints.md` — `C-*` constraints with provenance
- `CLAUDE.md` — Project conventions, absolute constraints, finding data model
- `DECISIONS.md` — ADR log (mirrors `.planning/intel/decisions.md`)

### Phase-relevant specs

- `docs/05-credential-handling.md` — Authoritative source for `C-cred-001..C-cred-009`. Sanitization pipeline (`sanitizer.py` extraction must honor this).
- `docs/02-api-strategy.md` — Network Integration API rationale, scope (`D-007` elaboration)
- `docs/01-design-philosophy.md` — Discovery-first pattern (`D-002`), three-tier voicing (`D-001`)
- `docs/07-coverage-analysis.md` — 10-point coverage gap analysis; the source for the "5 of 9 enhanced modules are unwired" framing
- `QUESTIONNAIRE.md` — Question metadata schema (`C-questionnaire-001..004`); the `intent_question` field on `unknown` Findings (D-03) feeds Phase 2 wizard

### Codebase analysis (current state)

- `.planning/codebase/ARCHITECTURE.md` — Audit pipeline layers; the `analyze()` extension point for D-02
- `.planning/codebase/STRUCTURE.md` — File layout; where new files (`src/sanitizer.py`, `src/api_to_collections.py`, `src/findings_correlations.py`, `src/profile_weights.py`) belong
- `.planning/codebase/CONCERNS.md` — Tech debt drives this phase: enhanced-module unwiring, sanitization DRY, profile detection, no tests, schema fragility
- `.planning/codebase/CONVENTIONS.md` — Type hints, docstrings, import order, `requests.Session` usage
- `.planning/codebase/TESTING.md` — Test scope plan (sanitization at 100% coverage, fixture spec)
- `.planning/codebase/STACK.md` — Python 3.9+, stdlib + `requests` + `pycryptodome` + `pymongo`; pytest is dev-only

### Source files (the work happens here)

- `src/unifi_audit.py` — Phase 1 deliverable; `analyze()` at lines ~355-559; `sanitize()` at lines 191-216; `_extract_list`/`_extract_sites` helpers
- `src/findings_enhanced.py` — 6 enhanced modules to wire in; do NOT edit signatures (D-01 keeps them unchanged)
- `src/parser.py` — Sanitization duplicate at lines 103-148 (gets removed by D-09); Phase 4 scope, but its data shape defines the adapter target (D-01)
- `src/inspect_backup.py` — Untouched in Phase 1

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`Finding` dataclass** (`src/unifi_audit.py:100-114`) — schema is locked (`C-finding-001`). Compound findings (D-04) and `unknown` Findings (D-03) use this same structure.
- **`UniFiClient`** (`src/unifi_audit.py:223-270`) — credential isolation is already correct (`C-cred-001..009` met). No changes needed in this phase.
- **`requests.Session`** with X-API-KEY header — connection reuse pattern; preserve.
- **`_extract_list` / `_extract_sites`** (`src/unifi_audit.py:340-348`, `562-572`) — defensive multi-key fallback. D-07 makes these the first pytest target.
- **Existing `analyze()` modules-list pattern** (`src/unifi_audit.py:359-375`) — current six modules (segmentation, wifi, firewall, remote_access, devices, api_coverage) registered as a list. Wiring approach for D-01 follows this same pattern: extend the list with the 6 enhanced modules (after the adapter has built the parser-shape dict).

### Established Patterns

- **Try/except around each finding module** (`src/unifi_audit.py:367-371`) — graceful degradation. Compound correlation pass (D-02) and float-top pass (D-02) wrap in try/except too.
- **Sanitization-before-output** (`src/unifi_audit.py:205-216`) — sanitize() runs before any data is serialized. The new `src/sanitizer.py` (D-09) preserves this contract.
- **Module-level constants for endpoints** (`src/unifi_audit.py:67-93`) — `ENDPOINTS_LOCAL`, `ENDPOINTS_CLOUD`, `SITE_SCOPED_LOCAL`. Same pattern for `ALWAYS_TOP_FINDING_IDS` (D-02), `WEIGHTS` (D-05).
- **Audit log writes endpoint name + status, never key** (`src/unifi_audit.py:162-176`) — `C-cred-008` met. Preserve in any new code paths.

### Integration Points

- **`analyze()` is the extension point.** D-01 (adapter), D-02 (correlation + float-top), D-05 (weights in ranking) all hook here.
- **`SECRET_FIELD_NAMES` set** is duplicated between `unifi_audit.py:183-188` and `parser.py:103-116`. D-09 collapses these into `src/sanitizer.py`.
- **`render_report()`** (`src/unifi_audit.py:579-624`) — markdown report renderer. D-03's `unknown` Findings render through this same path; no separate "limitations" code (D-10).
- **`samples/`** — already exists with markdown samples. New subdirectory `samples/fixtures/` houses the committed anonymized fixture (D-08).

</code_context>

<specifics>
## Specific Ideas

### File creation list (planner reference)

Phase 1 introduces these new files:

- `src/sanitizer.py` — extracted shared module (D-09). Imports replace duplicates in `unifi_audit.py` and `parser.py`.
- `src/api_to_collections.py` — adapter mapping API responses → parser-shape dict (D-01). Pure transformation, no I/O.
- `src/findings_correlations.py` — compound finding rules as Python functions (D-04). One function per compound finding.
- `src/profile_weights.py` — `WEIGHTS` dict + helper (D-05).
- `tests/` directory + `tests/conftest.py` (D-07). Subdirs at planner discretion.
- `tests/test_sanitizer.py` — first test file; targets `sanitize()` and `_fingerprint` exhaustively.
- `tests/test_extract_helpers.py` — `_extract_list` / `_extract_sites` against API response variants.
- `tests/test_pipeline_smoke.py` — end-to-end on the canonical fixture; asserts findings shape.
- `samples/fixtures/api_dump_home_office.json` — committed canonical fixture (D-08).

### File modification list

- `src/unifi_audit.py` — replace local `sanitize()`/`SECRET_FIELD_NAMES` with import from `sanitizer.py`; extend `analyze()` modules list with adapter-fed enhanced modules; add `_correlate_findings()` and `_apply_float_top()` passes; integrate `WEIGHTS` into ranking; emit the 3 `unknown` always-top Findings.
- `src/parser.py` — replace local sanitize/SECRET_FIELD_NAMES with import from `sanitizer.py`. No other Phase 1 changes (Phase 4 inherits the wiring later).

### Testing fixture spec

The committed `samples/fixtures/api_dump_home_office.json` represents a `home_office` profile run. Future fixtures (one per profile label) are nice-to-have but Phase 1 only commits the one. They get gathered as users run validations and contribute back.

### Validation acceptance bar

The phase is "validated" when:
1. `unifi_audit.py` runs end-to-end against ≥ one real UniFi network (≥ 9.3.43) without raising
2. The captured `raw_sanitized.json` survives `sanitize()` round-trip (no raw secrets present)
3. Pytest suite passes against the canonical fixture
4. The smoke test asserts that all 12 finding modules produce a non-empty list of valid `Finding` objects when the canonical fixture is sufficient to fire them
5. Always-top override produces the 3 `unknown` Findings + correctly orders the 3 detectable always-top findings ahead of scored ones
6. At least 1 compound finding fires on a constructed test case

</specifics>

<deferred>
## Deferred Ideas

### To Phase 2 (Wizard)

- **Auto profile inference** (CONCERNS.md heuristics). Phase 2 has the skills-check and interactive-correction UX needed.
- **MFA / default credentials / mgmt-plane WAN-reachable detection** — surfaced as `unknown` Findings in Phase 1, resolved via wizard intent questions in Phase 2.
- **Tier-aware report rendering** (Guided / Standard / Pro voices on the same Finding). Phase 1 ships Standard voice only.

### To Phase 3 (Site Manager)

- **`UNIFI_USE_CLOUD=true` validation** — `REQ-validation-cloud-mode`. Requires unified API key with Cloud Connector. Phase 1 keeps the toggle scaffolded but does not validate it.

### To Phase 4 (Backup mode)

- **Wire `findings_enhanced.py` modules into `parser.py`** — Phase 1's adapter approach (D-01) means Phase 4 can `import` enhanced modules directly with no adapter. Stub functions in `parser.py:431-433` (`find_logging`, `find_backup_config`, `find_firmware`) get replaced by importing the enhanced modules.

### Backlog (no committed phase)

- **CVE database integration** for firmware always-top finding. Requires sourcing or maintaining a feed. Phase 1 firmware finding ships with the static EOL list only; the always-top firmware finding fires on EOL, not CVE.
- **Network request timeout configurable** via `UNIFI_REQUEST_TIMEOUT` env var (CONCERNS.md flags fixed 30s as inflexible).
- **Schema-version response matrix** for `_extract_list`/`_extract_sites` — fail-fast logging when no fallback matches (CONCERNS.md Concern 5). Phase 1 adds basic logging; the full version matrix is post-Phase-1.

</deferred>

---

*Phase: 01-live-api-audit*
*Context gathered: 2026-04-25 (interactive `/gsd-discuss-phase 1`, all 6 gray areas, all recommendations accepted)*
