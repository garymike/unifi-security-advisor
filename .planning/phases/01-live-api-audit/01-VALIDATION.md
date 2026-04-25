---
phase: 1
slug: live-api-audit
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-25
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Filled by planner (Wave 0 + per-task verify map). Initial scaffold from research findings.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.0.3 (already installed) |
| **Config file** | `pyproject.toml` (Wave 0 adds `[tool.pytest.ini_options]`) |
| **Quick run command** | `pytest -q tests/` |
| **Full suite command** | `pytest -q --cov=src --cov-report=term-missing tests/` |
| **Estimated runtime** | ~5 seconds quick, ~15 seconds full (no real network) |

---

## Sampling Rate

- **After every task commit:** Run `pytest -q tests/`
- **After every plan wave:** Run `pytest -q --cov=src tests/`
- **Before `/gsd-verify-work`:** Full suite must be green; coverage on `src/sanitizer.py` ≥ 95%
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

*Filled by planner. Each task in Phase 1 plans gets a row here mapping to a test command.*

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| (planner fills) | | | | | | | | | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/conftest.py` — shared pytest fixtures: `canonical_api_dump`, `tagged_secret_blob`, `profiles[]`
- [ ] `tests/test_sanitizer.py` — stubs for REQ-validation-sanitization-coverage; targets `sanitize()` and `_fingerprint()` from new `src/sanitizer.py`
- [ ] `tests/test_extract_helpers.py` — stubs for REQ-validation-api-response-shapes; targets `_extract_list` and `_extract_sites` against captured + crafted shape variants
- [ ] `tests/test_pipeline_smoke.py` — stub for end-to-end run against `samples/fixtures/api_dump_home_office.json`
- [ ] `tests/test_correlations.py` — stub for compound finding rules from `src/findings_correlations.py`
- [ ] `tests/test_profile_weights.py` — stub for `WEIGHTS` table coverage across all `(profile, section)` cells
- [ ] `pyproject.toml` — add `[tool.pytest.ini_options]` block with `testpaths = ["tests"]`, `addopts = "-q"`
- [ ] `requirements-dev.txt` — pin `pytest>=9.0`, `pytest-cov>=5.0`, optional `hypothesis>=6.100` for property-based sanitization tests
- [ ] `samples/fixtures/api_dump_home_office.json` — committed canonical anonymized fixture (D-08; populated after first real-network run + manual anonymization pass)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real UniFi network end-to-end run | REQ-validation-real-network | Cannot run real Network Integration API in CI; needs human-controlled controller | Set `UNIFI_API_KEY`, `UNIFI_HOST`, `UNIFI_VERIFY_SSL=false` env vars on a machine with LAN access to a UniFi controller ≥ 9.3.43; run `python src/unifi_audit.py`; confirm zero exceptions, `audit_output/raw_sanitized.json` produced, `findings.json` contains findings from all 12 modules. |
| Sanitization round-trip with tagged secret | REQ-validation-sanitization-coverage | Property-based test in `tests/test_sanitizer.py` is the automated half; manual verification on a real captured response confirms no novel field name slipped through | After capturing a real `raw.json` (pre-sanitize), inject a recognizable tagged value (`MARKER-SECRET-7c93af`) into a known PSK field; run `sanitize()`; grep all output artifacts (markdown, json, log) for the marker → must return zero matches. |
| Network version compatibility (≥9.3.43 + older version) | REQ-validation-network-version-compat | Cannot maintain controllers of multiple Network versions in CI | Run audit against ≥9.3.43 (must succeed) and against an older version known to lack Integration API (must produce graceful 404 messages, not stack traces). Document observed behavior in `samples/fixtures/api_dump_home_office.json` companion notes. |
| SSL self-signed local-mode default | REQ-validation-ssl-self-signed | TLS handshake against self-signed cert requires real controller | Set `UNIFI_VERIFY_SSL=false` (default), confirm audit runs without TLS errors. Set `UNIFI_VERIFY_SSL=true` against a self-signed controller, confirm clear error message (not silent failure). |
| Cloud mode (UNIFI_USE_CLOUD=true) | REQ-validation-cloud-mode | Requires unified API key with Cloud Connector (April 2026 unified key) | Deferred — Phase 1 keeps the toggle scaffolded but does not validate it. Validation lives in Phase 3 (Site Manager fallback). Marked manual-only here to acknowledge the open item. |

---

## Acceptance Bar (from CONTEXT.md)

The phase is "validated" when ALL of these are demonstrable:

1. ✅ `unifi_audit.py` runs end-to-end against ≥ one real UniFi network (≥9.3.43) without raising
2. ✅ The captured `raw_sanitized.json` survives a tagged-secret round-trip (no raw secrets present)
3. ✅ `pytest -q tests/` passes (all unit tests green) against the canonical fixture
4. ✅ Smoke test asserts all 12 finding modules produce a non-empty list of valid `Finding` objects when the canonical fixture has the data to fire them
5. ✅ Always-top override produces 3 `unknown` Findings (MFA / default creds / WAN-reachable mgmt) + correctly orders the 3 detectable always-top findings ahead of scored ones
6. ✅ At least 1 compound finding fires on a constructed test case
7. ✅ `src/sanitizer.py` exports `SECRET_FIELD_NAMES`, `sanitize()`, `_fingerprint` and is imported by both `src/unifi_audit.py` and `src/parser.py` (no duplicate definitions)
8. ✅ Coverage on `src/sanitizer.py` ≥ 95% (security-critical surface)

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
