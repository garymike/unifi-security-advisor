# Testing

**Last updated:** 2026-04-25
**Focus:** quality / testing

## Current state

**There are no automated tests in this codebase.** No `tests/` directory, no `pytest`/`unittest` configuration, no CI test runner. The project is at the end of Phase 1 with `src/unifi_audit.py` (689 lines), `src/findings_enhanced.py` (624 lines), `src/parser.py` (562 lines, skeleton), and `src/inspect_backup.py` (65 lines) — all untested by automated suite.

This is intentional, not an oversight. Phase 1's deliverable is a runnable audit script validated by hand against a real UniFi network (`ROADMAP.md` § "Validation"). Test infrastructure is Phase 2 work.

## Why deferred

- **D-008** (`DECISIONS.md`): Phase 1 = local-run script delivery. Robustness work follows.
- **`ROADMAP.md` § Phase 1 / Validation:** The unchecked items (run against real network, diff response shapes, version-compat checks) are validation-by-execution, not unit-test work. Real-network discovery of API response shapes is a precondition for writing meaningful fixture-based tests.
- **CLAUDE.md § Testing fixtures we need:** Lists fixtures that don't yet exist (real `.unf` backup, JSON dump from live API run). Without those, unit tests would be exercising assumed-shape data that the validation pass is meant to correct.

## Recommended framework

**`pytest`** — Python's de-facto standard, fits the stdlib-first dependency posture (CLAUDE.md § Code conventions allows `requests`, `pycryptodome`, `pymongo` for phases 1–4; pytest is dev-only and doesn't violate the runtime minimalism rule).

Suggested layout (none of this exists yet):

```
tests/
  unit/                       # fast, no I/O, fixture-driven
    test_sanitize.py
    test_fingerprint.py
    test_findings_segmentation.py
    test_findings_wifi.py
    ...
  integration/                # parser + finding modules end-to-end against fixtures
    test_audit_against_api_fixture.py
    test_parser_against_unf_fixture.py
  fixtures/
    profiles/
      home/
      home_office/
      small_business/
      regulated_hipaa/
      regulated_pci/
    api_dumps/                # JSON outputs from live `unifi_audit.py` runs (sanitized)
    backups/                  # anonymized .unf files
  conftest.py                 # shared fixture loaders
```

## Critical test surfaces (100% coverage targets)

These are non-negotiable per `CLAUDE.md` § Absolute constraints. A regression here is a credential-leak risk, not a behavioral bug.

| Surface | Location | Why 100% |
|---|---|---|
| `_fingerprint()` | `src/unifi_audit.py:191`, `src/parser.py:119` | Converts secrets to length+sha256. Every secret-redacting code path goes through this. |
| `sanitize()` | `src/unifi_audit.py:205`, `src/parser.py:134` | Recursive sanitizer applied to every output blob. Missed field name = leaked secret in report. |
| Credential input rejection | wherever credentials are loaded | Must REJECT credentials passed via `argv`, URL params, or chat. Only env vars / config file (600 perms) / OS keychain / interactive TTY prompts allowed (CLAUDE.md § Absolute constraints #2). |
| Backup-mode network isolation | `src/parser.py`, `src/inspect_backup.py` | Backup mode MUST make zero network calls (CLAUDE.md § Absolute constraints #6). Test by patching `requests` and asserting it's never invoked. |
| Output redaction end-to-end | report generators in `src/unifi_audit.py` | Generated markdown + JSON must contain no raw PSKs, shared secrets, admin passwords, session cookies, X-API-KEY values. Property-test: feed in a known secret, grep all generated artifacts for it, expect zero hits. |

## Sanitization duplication risk (test-driven mitigation)

`sanitize()` and `_fingerprint()` are implemented twice — once in `src/unifi_audit.py` and once in `src/parser.py` (slightly different signature: `parser.py` adds a `redact_pii` flag). Tests should:

1. Run a shared sensitive-fields contract suite against both implementations.
2. Assert that any field name added to one implementation's redaction list is also covered by the other (or fail loud — this is a pre-merge guardrail, not a runtime check).

Long-term: extract shared `sanitize` into a single module both audit and parser import. That's a refactor, not a test, but tests are what makes the refactor safe.

## Fixture spec (per CLAUDE.md § Testing fixtures we need)

**Required for Phase 2 validation:**
- At least one real UniFi Network backup file (single-site `.unf`)
- At least one JSON dump from a live API run (generate via `python src/unifi_audit.py` then sanitize the output)
- Anonymized profiles for each profile label used in code:

| Profile | Scale | Compliance hint |
|---|---|---|
| `home` | single-AP | none |
| `home_office` | multi-AP | none |
| `small_business` | multi-site small | none |
| `regulated_hipaa` | small-medium | HIPAA-typical patterns |
| `regulated_pci` | small-medium | PCI-typical patterns |

Profiles are referenced in `CLAUDE.md` § Testing fixtures and influence which findings apply (CLAUDE.md § "When adding a new finding" step 5: "Note which profiles it applies to — home profile shouldn't get enterprise retention recommendations"). Profile-aware filtering is a key test surface.

## Phase 2 priority test areas

Once fixtures exist:

1. **Per-finding module outputs against fixtures.** For each finding ID (e.g., `SEG-001`), feed the canonical fixture in, assert the produced `Finding` dataclass matches the expected severity/status/recommendation/intent_question.
2. **Profile-aware finding suppression.** Run the same input through different profiles. Assert `home` doesn't receive enterprise-only findings (e.g., long log retention recommendations); `regulated_hipaa` does receive them.
3. **Always-float-to-top finding override.** When any of the six "always float to top" findings (CLAUDE.md § Always-float-to-top) is present, it must appear above any score-ranked finding regardless of `(impact × user_priority_weight) / effort_hours` ordering.
4. **Cross-answer tension detection** (D-003). Compound findings emerge from answer combinations, not individual answers. Test cases need multi-answer fixtures: e.g., "single WAN + downtime blocks work + work ranked low" → priority-mismatch compound finding.
5. **Tier routing.** Skills-check question routes user to guided/standard/pro voice. Same finding ID rendered three different ways. Test: same finding through all three tiers, assert language-complexity differs.
6. **`requests.Session` SSL behavior.** Local mode self-signed default vs. cloud mode strict. The unchecked item in `ROADMAP.md` § Validation about "SSL self-signed default for local mode" should land as a regression test once validated.

## Gaps relative to ROADMAP.md

`ROADMAP.md` § Validation lists seven unchecked items. Each is a candidate test:

- [ ] `unifi_audit.py` against a real UniFi network → smoke test once a fixture API dump exists
- [ ] Diff actual API response shapes vs. assumed shapes in `_extract_list` → contract test once shapes are known
- [ ] Network version >= 9.3.43 vs. older → version-compat test matrix
- [ ] Cloud mode (`UNIFI_USE_CLOUD=true`) → integration test once unified key with Cloud Connector is available
- [ ] Self-signed SSL default for local mode → unit test for the verify= flag wiring
- [ ] Sanitization catches all secret field names in actual API responses → property test driven by real API dumps

## Credential-safety testing rules

These are constraints on *how* tests are written, not what they test:

- **No real credentials in fixtures, ever.** Use synthetic API keys (`X-API-KEY: test-key-not-real`) and synthetic PSKs.
- **Tests must verify secrets never appear in any output artifact.** Logs, generated markdown, generated JSON, exception messages, stack traces. Use a property-style check: feed a unique tagged secret into the system, then `grep -r 'TAGGED_SECRET' ./test-output/` must return zero matches.
- **Test fixtures are committable; real credentials are not.** Add fixture files under `tests/fixtures/` to git; never add `.env`, real `.unf` backups, or live API dumps.
- **Backup-mode tests run with networking patched off.** `monkeypatch.setattr('requests.Session.request', mock_that_raises)` — any network call during backup-parser tests is a test failure, regardless of what the test was checking.

## What good test infrastructure looks like for this project

Three signals to aim for in Phase 2:

1. `pytest tests/unit/` runs in under 5 seconds with no network, no real backup files. New contributors can run it without any setup.
2. `pytest tests/integration/` runs in under 30 seconds against committed fixtures. Catches finding-module regressions.
3. `pytest --cov=src/unifi_audit.py --cov=src/parser.py --cov-report=term-missing` shows ≥95% line coverage with the missing 5% explicitly justified (e.g., `__main__` blocks, defensive branches that can only fire on corrupt fixture data).
