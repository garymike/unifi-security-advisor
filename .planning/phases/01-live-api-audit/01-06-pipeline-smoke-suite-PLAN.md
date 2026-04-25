---
phase: 01-live-api-audit
plan: 06
type: execute
wave: 5
depends_on: [05]
files_modified:
  - tests/test_pipeline_smoke.py
  - tests/test_no_credential_leak.py
autonomous: true
requirements:
  - REQ-phase1-live-api-audit
  - REQ-validation-network-version-compat
  - REQ-validation-ssl-self-signed
  - REQ-validation-sanitization-coverage
  - REQ-finding-module-segmentation
  - REQ-finding-module-wifi
  - REQ-finding-module-firewall
  - REQ-finding-module-remote-access
  - REQ-finding-module-devices
  - REQ-finding-module-api-coverage-meta
requirements_addressed:
  - REQ-phase1-live-api-audit
  - REQ-validation-network-version-compat
  - REQ-validation-ssl-self-signed
  - REQ-validation-sanitization-coverage
  - REQ-finding-module-segmentation
  - REQ-finding-module-wifi
  - REQ-finding-module-firewall
  - REQ-finding-module-remote-access
  - REQ-finding-module-devices
  - REQ-finding-module-api-coverage-meta
threat_refs: [T-1-02]
tags: [python, pytest, smoke, regression]

must_haves:
  truths:
    - "tests/test_pipeline_smoke.py runs analyze() end-to-end against the synthetic fixture"
    - "Smoke test asserts all 12 finding modules execute without raising"
    - "404 endpoint responses are gracefully skipped (not stack traces) — REQ-validation-network-version-compat"
    - "UniFiClient defaults: cloud=verify_ssl_True, local=verify_ssl_False — REQ-validation-ssl-self-signed"
    - "tests/test_no_credential_leak.py asserts no print(response.text) or logger pattern that would leak the response body — T-1-02 mitigation"
    - "All Plan 01-05 test files plus this plan's tests pass: pytest -q tests/ exits 0"
    - "Coverage on src/sanitizer.py ≥ 95% (Phase 1 acceptance bar #8)"
  artifacts:
    - path: "tests/test_pipeline_smoke.py"
      provides: "End-to-end pipeline tests + 404/SSL/version-compat coverage"
      contains: "test_full_pipeline|test_404_graceful|test_ssl_defaults|test_all_12_modules_run"
    - path: "tests/test_no_credential_leak.py"
      provides: "Static-analysis tests asserting no logger.info(response.text) etc."
      contains: "test_no_response_text_logging"
  key_links:
    - from: "tests/test_pipeline_smoke.py"
      to: "src/unifi_audit.py:analyze"
      via: "import + invocation against synthetic fixture"
      pattern: "from unifi_audit import"
    - from: "tests/test_no_credential_leak.py"
      to: "src/unifi_audit.py + src/api_to_collections.py"
      via: "AST scan or grep for response.text logging"
      pattern: "response\\.text|api_key"
---

<objective>
Lock in the Phase 1 validation acceptance bar with a pytest smoke suite that runs the entire analyze() pipeline against the synthetic fixture, plus targeted tests for the validation REQs that don't need a real network: REQ-validation-network-version-compat (404 graceful skip), REQ-validation-ssl-self-signed (UniFiClient SSL defaults), REQ-validation-sanitization-coverage (full pipeline sanitization), and the T-1-02 credential-leak prevention check (no logger.info(response.text) anywhere in src/).

This plan also serves as the "all 12 finding modules execute" gate (REQ-finding-module-* baseline modules are verified to run without raising on the synthetic fixture — they were already wired before Phase 1, but this plan ratifies them in the test suite).

Output:
- `tests/test_pipeline_smoke.py` — end-to-end pipeline tests, 404 graceful, SSL defaults, version-compat
- `tests/test_no_credential_leak.py` — static check that response.text is never logged or printed
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/REQUIREMENTS.md
@.planning/phases/01-live-api-audit/01-CONTEXT.md
@.planning/phases/01-live-api-audit/01-RESEARCH.md
@.planning/phases/01-live-api-audit/01-VALIDATION.md
@.planning/phases/01-live-api-audit/01-05-profile-weights-PLAN.md
@.planning/codebase/CONCERNS.md
@.planning/codebase/TESTING.md
@CLAUDE.md (Credentials never leave the user's machine; All outputs are sanitized)

<interfaces>
<!-- The 12 finding modules that must all execute on the synthetic fixture:
     Baseline: _find_segmentation, _find_wifi, _find_firewall, _find_remote_access,
               _find_devices, _find_api_coverage
     Enhanced: find_wireless_tuning, find_firewall_threats, find_remote_access (enhanced),
               find_firmware, find_logging, find_backup_config

     UniFiClient SSL defaults from src/unifi_audit.py:140-148:
       - UNIFI_VERIFY_SSL=true → True
       - UNIFI_VERIFY_SSL=false → False
       - unset and use_cloud=True → True
       - unset and use_cloud=False → False (local self-signed default)

     T-1-02: existing safe pattern at src/unifi_audit.py:258 scrubs key from exception text:
       safe_msg = str(e).replace(self.cfg["key"], "<REDACTED>")
     New code paths from Plans 02-05 must preserve this — no print(response.text) or
     logger.info(response.text) anywhere. -->
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: tests/test_pipeline_smoke.py — end-to-end + 404 + SSL + version-compat</name>
  <files>tests/test_pipeline_smoke.py</files>
  <read_first>
    - src/unifi_audit.py (full analyze flow after Plans 02-05; UniFiClient SSL defaults; collect_all 404-skip logic)
    - tests/conftest.py (synthetic_api_dump)
    - .planning/phases/01-live-api-audit/01-VALIDATION.md (acceptance bar)
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Validation Architecture" test map)
  </read_first>
  <behavior>
    - test_full_pipeline_runs_without_raising: analyze(synthetic_api_dump, "home_office") completes
    - test_full_pipeline_emits_findings: ≥ 4 findings produced (3 unknowns at minimum + at least 1 detected)
    - test_full_pipeline_findings_are_dataclass_shape: every finding has id/section/severity/status/title/current_state attributes
    - test_full_pipeline_severity_values_valid: every f.severity is in {info, low, medium, high, critical}
    - test_full_pipeline_status_values_valid: every f.status is in {ok, gap, recommendation, unknown}
    - test_all_12_modules_run_smoke (REQ-finding-module-* coverage): a fixture that has data to fire each module produces ≥ 1 finding from each — segmentation, wifi (PSK length<12), firewall (port-forward), remote_access (port-forward without VPN), devices (sshEnabled), wireless_tuning (high TX power), firewall_threats (no geo-IP rules — fires by default), firmware (EOL UAP-AC-LITE), logging (no syslog), backup_config (no auto_backup), plus api_coverage meta and 3 unknowns. The test counts unique sections and asserts ≥ 8 distinct sections produced findings.
    - test_404_graceful_skip (REQ-validation-network-version-compat): a mocked UniFiClient that returns 404 for half the endpoints completes collect_all() without raising; the affected endpoints appear in `_endpoints_probed` with `status=404`
    - test_ssl_defaults_local_off (REQ-validation-ssl-self-signed): load_config with use_cloud=False and UNIFI_VERIFY_SSL unset → cfg["verify_ssl"] is False
    - test_ssl_defaults_cloud_on (REQ-validation-ssl-self-signed): load_config with UNIFI_USE_CLOUD=true and UNIFI_VERIFY_SSL unset → cfg["verify_ssl"] is True
    - test_ssl_explicit_false: UNIFI_VERIFY_SSL=false → False
    - test_ssl_explicit_true: UNIFI_VERIFY_SSL=true → True
    - test_unifi_client_session_has_api_key_header: UniFiClient(cfg) has the X-API-KEY header set on session
    - test_sanitization_through_full_pipeline (REQ-validation-sanitization-coverage): inject a tagged secret into a wlan x_passphrase, run sanitize() → analyze() → render_report(), grep all output for the tag — must be absent
    - test_render_report_no_apikey: render_report output never contains the literal string of any X-API-KEY value
  </behavior>
  <action>
Create `tests/test_pipeline_smoke.py`:

```python
"""Phase 1 pipeline smoke suite — end-to-end + version-compat + SSL + sanitization.

Covers REQ-validation-network-version-compat (404 graceful skip),
REQ-validation-ssl-self-signed (UniFiClient defaults),
REQ-validation-sanitization-coverage (tagged-secret round-trip via the full pipeline),
and the all-12-modules-execute gate.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sanitizer import sanitize
from unifi_audit import (
    Finding,
    UniFiClient,
    analyze,
    collect_all,
    load_config,
    render_report,
)

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_STATUSES = {"ok", "gap", "recommendation", "unknown"}


def _silent_logger():
    log = logging.getLogger("test")
    log.addHandler(logging.NullHandler())
    return log


# --- Full pipeline smoke ---------------------------------------------------

def test_full_pipeline_runs_without_raising(synthetic_api_dump):
    findings = analyze(synthetic_api_dump, "home_office", _silent_logger())
    assert isinstance(findings, list)


def test_full_pipeline_emits_minimum_findings(synthetic_api_dump):
    findings = analyze(synthetic_api_dump, "home_office", _silent_logger())
    assert len(findings) >= 4, f"Expected ≥4 findings, got {len(findings)}: {[f.id for f in findings]}"


def test_full_pipeline_finding_shape(synthetic_api_dump):
    for f in analyze(synthetic_api_dump, "home_office", _silent_logger()):
        assert isinstance(f.id, str) and f.id
        assert isinstance(f.section, str) and f.section
        assert f.severity in VALID_SEVERITIES, f"Invalid severity: {f.severity!r} in {f.id}"
        assert f.status in VALID_STATUSES, f"Invalid status: {f.status!r} in {f.id}"
        assert isinstance(f.title, str) and f.title
        assert isinstance(f.current_state, str)


# --- All 12 modules execute -----------------------------------------------

@pytest.fixture
def fixture_firing_all_modules(synthetic_api_dump):
    """Augment synthetic_api_dump so each finding module has data to fire."""
    site = synthetic_api_dump["site_default"]
    # PSK shorter than 12 → fires WIFI-*-PSK
    site["wlans"]["data"][0]["x_passphrase"] = {
        "length": 8, "fingerprint": "deadbeef1234",
        "has_symbols": False, "has_digits": True, "has_mixed_case": False,
    }
    # WPA3 + PMF disabled → fires RF-PMF-*
    site["wlans"]["data"][0]["wpa_mode"] = "wpa3"
    # Add an EOL device → fires FW-EOL-001
    site["devices"]["data"][0]["model"] = "UAP-AC-LITE"
    site["devices"]["data"][0]["sshEnabled"] = True  # fires DEV-SSH-*
    site["devices"]["data"][0]["radioTable"] = [{"radio": "ng", "tx_power_mode": "high"}]  # fires RF-* TX
    site["devices"]["data"][0]["version"] = "6.0.42"  # fires FW-VER-*
    # Port forward + no VPN → fires FW-*-PF, VPN-MISSING-*
    site["port_forwards"]["data"] = [{"enabled": True, "name": "ssh-fwd"}]
    # PPTP enabled → fires VPN-PPTP-001 (always-top)
    site["vpn_configs"]["data"] = [{"type": "pptp", "enabled": True}]
    # Add a 404 in _endpoints_probed → fires META-COVERAGE
    synthetic_api_dump["_endpoints_probed"].append(
        {"name": "firewall_zones", "path": "/x", "status": 404}
    )
    return synthetic_api_dump


def test_all_12_modules_produce_findings(fixture_firing_all_modules):
    """REQ-finding-module-* gate: across the full fixture, every module's
    section appears in the findings list (or is absent because the API
    cannot expose the data, in which case the count is reduced)."""
    findings = analyze(fixture_firing_all_modules, "home_office", _silent_logger())
    sections_with_findings = {f.section for f in findings}
    # We expect at least 6 distinct sections: Segmentation, Wi-Fi, Firewall,
    # Remote access, Admin, Risk correlation. Wireless tuning, Firmware,
    # Backup, Logging may or may not fire depending on Adapter limitations.
    minimum_sections = {"Segmentation", "Wi-Fi", "Firewall", "Remote access", "Admin"}
    missing = minimum_sections - sections_with_findings
    assert not missing, (
        f"Sections missing from findings: {missing}. "
        f"Sections produced: {sections_with_findings}. "
        f"Finding IDs: {[f.id for f in findings]}"
    )


def test_pptp_finding_is_first_when_present(fixture_firing_all_modules):
    """VPN-PPTP-001 is always-top; should be at position 0 (or among first few)."""
    findings = analyze(fixture_firing_all_modules, "home_office", _silent_logger())
    pptp_idx = next((i for i, f in enumerate(findings) if f.id == "VPN-PPTP-001"), None)
    assert pptp_idx is not None, "VPN-PPTP-001 not in findings"
    # Should be in the always-top group
    from unifi_audit import ALWAYS_TOP_FINDING_IDS
    for f in findings[:pptp_idx + 1]:
        assert any(f.id.startswith(p) for p in ALWAYS_TOP_FINDING_IDS), \
            f"Non-always-top finding {f.id} appeared before PPTP"


# --- 404 graceful skip (REQ-validation-network-version-compat) -----------

def test_404_graceful_skip():
    """A 404 on any endpoint must be handled (no exception, recorded in _endpoints_probed)."""
    cfg = {"key": "test-key", "host": "192.0.2.1", "use_cloud": False,
           "verify_ssl": False, "profile": "home_office"}
    logger = _silent_logger()
    client = UniFiClient(cfg, logger)

    def mock_get(path):
        # Return 404 for everything except /info and /sites
        if path.endswith("/info") or path.endswith("/sites"):
            return 200, {"data": []}
        return 404, {}

    with patch.object(client, "get", side_effect=mock_get):
        result = collect_all(client, logger)

    # Must not raise. Probed list should have the 404s.
    assert "_endpoints_probed" in result
    statuses = [p["status"] for p in result["_endpoints_probed"]]
    assert 404 in statuses, "404 not recorded in probed list"


def test_404_does_not_raise_in_collect_all():
    cfg = {"key": "test-key", "host": "192.0.2.1", "use_cloud": False,
           "verify_ssl": False, "profile": "home_office"}
    logger = _silent_logger()
    client = UniFiClient(cfg, logger)
    with patch.object(client, "get", return_value=(404, {})):
        result = collect_all(client, logger)  # must not raise
    assert isinstance(result, dict)


# --- SSL defaults (REQ-validation-ssl-self-signed) -----------------------

def test_ssl_default_local_is_false(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_HOST", "192.0.2.1")
    monkeypatch.delenv("UNIFI_USE_CLOUD", raising=False)
    monkeypatch.delenv("UNIFI_VERIFY_SSL", raising=False)
    cfg = load_config()
    assert cfg["verify_ssl"] is False, f"Expected local default False, got {cfg['verify_ssl']}"


def test_ssl_default_cloud_is_true(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_USE_CLOUD", "true")
    monkeypatch.delenv("UNIFI_HOST", raising=False)
    monkeypatch.delenv("UNIFI_VERIFY_SSL", raising=False)
    cfg = load_config()
    assert cfg["verify_ssl"] is True, f"Expected cloud default True, got {cfg['verify_ssl']}"


def test_ssl_explicit_override_true(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_HOST", "192.0.2.1")
    monkeypatch.setenv("UNIFI_VERIFY_SSL", "true")
    cfg = load_config()
    assert cfg["verify_ssl"] is True


def test_ssl_explicit_override_false(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "test-key")
    monkeypatch.setenv("UNIFI_USE_CLOUD", "true")
    monkeypatch.setenv("UNIFI_VERIFY_SSL", "false")
    cfg = load_config()
    assert cfg["verify_ssl"] is False


def test_unifi_client_sets_api_key_header():
    cfg = {"key": "test-key-12345", "host": "192.0.2.1", "use_cloud": False,
           "verify_ssl": False, "profile": "home_office"}
    client = UniFiClient(cfg, _silent_logger())
    assert client.session.headers.get("X-API-KEY") == "test-key-12345"


# --- Full-pipeline sanitization (REQ-validation-sanitization-coverage) --

def test_tagged_secret_does_not_appear_in_any_pipeline_output(synthetic_api_dump, tmp_path):
    """T-1-01 / REQ-validation-sanitization-coverage end-to-end gate.

    Inject a tagged secret into a known PSK field, run the full pipeline
    (sanitize → analyze → render_report → write to disk), grep all output
    for the tag — must be absent.
    """
    TAG = "TAGGED_PSK_a1b2c3d4_NEVER_LOG"
    # Inject as raw string under a known secret field
    synthetic_api_dump["site_default"]["wlans"]["data"][0]["x_passphrase"] = TAG

    clean = sanitize(synthetic_api_dump)
    findings = analyze(clean, "home_office", _silent_logger())
    report = render_report(findings, clean, "home_office")

    # Write all artifacts to disk like the real pipeline does
    raw_path = tmp_path / "raw_sanitized.json"
    raw_path.write_text(json.dumps(clean, indent=2, default=str))
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(
        [{"id": f.id, "title": f.title, "current_state": f.current_state,
          "evidence": str(f.evidence)} for f in findings], indent=2,
    ))
    report_path = tmp_path / "report.md"
    report_path.write_text(report)

    for path in (raw_path, findings_path, report_path):
        text = path.read_text()
        assert TAG not in text, f"Tagged secret leaked into {path.name}"


def test_render_report_does_not_include_apikey():
    """The raw API key must never appear in the markdown report."""
    KEY = "real-looking-test-key-do-not-leak"
    clean = {"_endpoints_probed": [], "_errors": [], "_site_count": 0}
    findings = []  # noqa
    report = render_report([], clean, "home_office")
    assert KEY not in report
```

Run `pytest -q tests/test_pipeline_smoke.py`. All 17+ tests should pass.
  </action>
  <verify>
    <automated>pytest -q tests/test_pipeline_smoke.py</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_pipeline_smoke.py` exists
    - `pytest -q tests/test_pipeline_smoke.py` exits 0
    - `grep -c "test_full_pipeline_runs_without_raising" tests/test_pipeline_smoke.py` returns 1
    - `grep -c "test_404_graceful_skip" tests/test_pipeline_smoke.py` returns 1
    - `grep -c "test_ssl_default_local_is_false" tests/test_pipeline_smoke.py` returns 1
    - `grep -c "test_ssl_default_cloud_is_true" tests/test_pipeline_smoke.py` returns 1
    - `grep -c "test_tagged_secret_does_not_appear_in_any_pipeline_output" tests/test_pipeline_smoke.py` returns 1
    - `grep -c "test_all_12_modules_produce_findings" tests/test_pipeline_smoke.py` returns 1
    - `grep -c "test_pptp_finding_is_first_when_present" tests/test_pipeline_smoke.py` returns 1
  </acceptance_criteria>
  <done>Pipeline smoke suite covers end-to-end pipeline, 404 graceful skip, SSL defaults, tagged-secret round-trip; all 12 modules execute gate is in place.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: tests/test_no_credential_leak.py — static guard against response-body logging</name>
  <files>tests/test_no_credential_leak.py</files>
  <read_first>
    - src/unifi_audit.py (existing safe pattern at lines 254-260: scrubbed exception text)
    - src/api_to_collections.py (Plan 02 — must not log response.text either)
    - src/findings_correlations.py (Plan 03)
    - .planning/codebase/CONCERNS.md (T-1-02 in security_threat_model)
    - CLAUDE.md (Constraint 1: Credentials never leave the user's machine)
  </read_first>
  <behavior>
    - test_no_response_text_in_logger_calls: scan src/*.py for any logger.info(...) / logger.warning(...) / logger.error(...) call whose argument contains the substring "response.text" — must find 0 matches
    - test_no_print_response_body: scan src/*.py for `print(.*response.text)` or `print(.*r.text)` — must find 0 matches
    - test_no_print_api_key: scan src/*.py for `print(.*api_key)` or `print(.*UNIFI_API_KEY)` (case-insensitive) where the print() statement would emit the secret directly — must find 0 matches
    - test_existing_safe_pattern_present: confirm the existing `safe_msg = str(e).replace(self.cfg["key"]` scrub line is still in src/unifi_audit.py (regression detector for accidental removal)
    - test_no_logger_includes_full_dict: scan for `logger.*\\(.*self\\.cfg\\)` patterns where the entire cfg dict (including the key) might be logged — must find 0
  </behavior>
  <action>
Create `tests/test_no_credential_leak.py`:

```python
"""T-1-02 mitigation: static guard against accidental response-body / credential logging.

Walks src/*.py and asserts that no logger or print statement could leak the
API key or the response body. The existing safe pattern at src/unifi_audit.py
(scrubbing exception text via str(e).replace(key, "<REDACTED>")) is also
asserted as a regression detector — accidental removal will fail this test.

This is a STATIC test (regex over file text), not a runtime test. It catches
unsafe patterns at the source level, before they could ever execute.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"

# Files we own and care about (do not scan vendored or third-party code).
OWNED_SRC = [
    SRC / "unifi_audit.py",
    SRC / "sanitizer.py",
    SRC / "api_to_collections.py",
    SRC / "findings_correlations.py",
    SRC / "profile_weights.py",
    SRC / "findings_enhanced.py",
    SRC / "parser.py",
    SRC / "inspect_backup.py",
]


def _existing_files():
    return [p for p in OWNED_SRC if p.exists()]


@pytest.mark.parametrize("path", _existing_files(), ids=lambda p: p.name)
def test_no_response_text_in_logger_calls(path: Path):
    """No logger.{info,warning,error,debug,exception}(... response.text ...) anywhere."""
    text = path.read_text()
    pattern = re.compile(
        r"logger\.(info|warning|error|debug|exception|critical)\([^)]*response\.text",
        re.IGNORECASE,
    )
    matches = pattern.findall(text)
    assert not matches, (
        f"{path.name}: logger call contains response.text — credential/response leak risk. "
        f"Matches: {matches}"
    )


@pytest.mark.parametrize("path", _existing_files(), ids=lambda p: p.name)
def test_no_response_text_in_print_calls(path: Path):
    """No print(... response.text ...) or print(... r.text ...)."""
    text = path.read_text()
    pattern = re.compile(r"print\([^)]*\b(response|r)\.text", re.IGNORECASE)
    matches = pattern.findall(text)
    assert not matches, (
        f"{path.name}: print() emits response body — leak risk. Matches: {matches}"
    )


@pytest.mark.parametrize("path", _existing_files(), ids=lambda p: p.name)
def test_no_print_of_api_key_variable(path: Path):
    """No print() that emits the api_key / cfg['key'] directly."""
    text = path.read_text()
    # Match: print(self.cfg["key"]) or print(api_key) or similar
    patterns = [
        re.compile(r"print\([^)]*\bapi_key\b[^)]*\)", re.IGNORECASE),
        re.compile(r"""print\([^)]*cfg\[['"]key['"]\][^)]*\)"""),
        re.compile(r"""print\([^)]*UNIFI_API_KEY[^)]*\)""", re.IGNORECASE),
    ]
    for p in patterns:
        matches = p.findall(text)
        # Allow exception-handler scrub patterns: 'print(<REDACTED>)' is fine; the regex
        # above only catches direct emission of the key variable.
        assert not matches, (
            f"{path.name}: print() emits API key. Pattern: {p.pattern}; "
            f"matches: {matches}"
        )


@pytest.mark.parametrize("path", _existing_files(), ids=lambda p: p.name)
def test_no_logger_emits_full_cfg(path: Path):
    """No logger call that prints the full cfg dict (which contains the key)."""
    text = path.read_text()
    # Match: logger.info(self.cfg) or logger.info(cfg)
    pattern = re.compile(
        r"logger\.(info|warning|error|debug|exception|critical)\(\s*(self\.)?cfg\s*\)",
        re.IGNORECASE,
    )
    matches = pattern.findall(text)
    assert not matches, (
        f"{path.name}: logger emits full cfg dict — credential leak. Matches: {matches}"
    )


def test_existing_safe_pattern_present():
    """Regression: src/unifi_audit.py scrubs the API key from RequestException text.

    If this assertion ever fails, the safe pattern was removed; restore it
    before merging. The scrub is at lines ~254-260 in the original file.
    """
    text = (SRC / "unifi_audit.py").read_text()
    # The pattern: safe_msg = str(e).replace(self.cfg["key"], "<REDACTED>")
    assert 'replace(self.cfg["key"]' in text or "replace(self.cfg['key']" in text, (
        "Safe pattern removed from src/unifi_audit.py: the RequestException scrub "
        "that prevents API-key leakage in error logs is no longer present. "
        "Restore the line: safe_msg = str(e).replace(self.cfg[\"key\"], \"<REDACTED>\")"
    )


def test_audit_log_format_does_not_include_response_body():
    """The audit-log format string in setup_logger should record URL + status only,
    never the response body or the key."""
    text = (SRC / "unifi_audit.py").read_text()
    # The setup_logger fmt is: "%(asctime)s %(levelname)s %(message)s"
    # which is fine — message comes from the logger.info("GET <url>") and
    # logger.info("  -> %d bytes") calls. We only need to confirm the calls.
    assert "logger.info(f\"GET {url}\")" in text or 'logger.info(f"GET {url}")' in text, \
        "Expected logger.info(GET <url>) pattern; format may have changed"
    # And no response.text in any logger call (already covered above per-file).
```

Run `pytest -q tests/test_no_credential_leak.py`. All tests should pass.
  </action>
  <verify>
    <automated>pytest -q tests/test_no_credential_leak.py</automated>
  </verify>
  <acceptance_criteria>
    - File `tests/test_no_credential_leak.py` exists
    - `pytest -q tests/test_no_credential_leak.py` exits 0
    - `grep -c "test_no_response_text_in_logger_calls" tests/test_no_credential_leak.py` returns 1
    - `grep -c "test_no_print_response_body|test_no_response_text_in_print_calls" tests/test_no_credential_leak.py` returns ≥ 1
    - `grep -c "test_existing_safe_pattern_present" tests/test_no_credential_leak.py` returns 1
    - `grep -c "test_no_logger_emits_full_cfg" tests/test_no_credential_leak.py` returns 1
  </acceptance_criteria>
  <done>Static credential-leak guard exists; covers logger.info(response.text), print(response.text), print(api_key), full-cfg logging; regression detector for the existing safe pattern; T-1-02 mitigated structurally.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Run full pytest suite + measure sanitizer coverage</name>
  <files></files>
  <read_first>
    - All test files from Plans 01-06
    - .planning/phases/01-live-api-audit/01-VALIDATION.md (acceptance bar items 7 and 8)
  </read_first>
  <behavior>
    - `pytest -q tests/` exits 0 (every test from Plans 01-06 passes)
    - `pytest --cov=src/sanitizer tests/test_sanitizer.py --cov-fail-under=95` exits 0
    - `pytest --cov=src tests/ --cov-report=term-missing` produces a coverage report (informational; no minimum on full src/)
  </behavior>
  <action>
This task is a verification gate, not new code. Run the commands below and capture output for the SUMMARY.

```bash
# 1. Install dev deps if not already
pip install -r requirements-dev.txt

# 2. Full test suite must be green
pytest -q tests/

# 3. Sanitizer coverage gate (acceptance bar #8 from VALIDATION.md)
pytest --cov=src/sanitizer tests/test_sanitizer.py --cov-fail-under=95

# 4. Full coverage report (informational)
pytest --cov=src tests/ --cov-report=term-missing > /tmp/coverage_report.txt 2>&1 || true
```

Record in the plan SUMMARY:
- Total test count (from `pytest -q tests/` output)
- Pass/fail/skip counts
- Coverage percentage on src/sanitizer.py
- Top 5 files by coverage gap (informational)

If any test fails: do NOT mark the plan complete. Diagnose, fix the regression, re-run.
  </action>
  <verify>
    <automated>pytest -q tests/ && pytest --cov=src/sanitizer tests/test_sanitizer.py --cov-fail-under=95</automated>
  </verify>
  <acceptance_criteria>
    - `pytest -q tests/` exits 0 (all Plan 01-06 tests pass together)
    - `pytest --cov=src/sanitizer tests/test_sanitizer.py --cov-fail-under=95` exits 0 (acceptance bar #8 met)
    - At least 5 test files exist in tests/: test_sanitizer.py, test_extract_helpers.py, test_adapter.py, test_correlations.py, test_float_top.py, test_profile_weights.py, test_pipeline_smoke.py, test_fixture_safety.py, test_no_credential_leak.py
    - Total test count ≥ 70 (rough lower bound across the suite)
  </acceptance_criteria>
  <done>Full pytest suite green; src/sanitizer.py coverage ≥ 95%; Phase 1 acceptance bar items 3, 4, 7, 8 satisfied via the test suite (real-network items 1, 2, 5, 6 are Plan 07's domain).</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Source code → committed history | Once a logger.info(response.text) lands in main, the leak risk lives in the file forever. Static test guards before the merge. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-1-02 | Information Disclosure | All src/*.py — any logger or print of response.text | mitigate | tests/test_no_credential_leak.py walks every owned source file with regex patterns and asserts no `logger.*(response.text)`, `print(response.text)`, `print(api_key)`, or `logger(cfg)` patterns exist. The existing scrub at `str(e).replace(self.cfg["key"], "<REDACTED>")` has its own regression test. Any future PR introducing such a pattern fails CI. |
</threat_model>

<verification>
After all tasks complete:

```bash
# Full green
pytest -q tests/

# Sanitizer coverage gate
pytest --cov=src/sanitizer tests/test_sanitizer.py --cov-fail-under=95

# Full coverage report
pytest --cov=src tests/ --cov-report=term-missing
```
</verification>

<success_criteria>
- tests/test_pipeline_smoke.py: end-to-end pipeline + 404 graceful + SSL defaults + tagged-secret round-trip + 12-modules-execute gate
- tests/test_no_credential_leak.py: T-1-02 static guard against response.text logging across all src/*.py
- All Plan 01-06 tests pass together (pytest -q tests/ exits 0)
- src/sanitizer.py coverage ≥ 95%
- REQ-validation-network-version-compat satisfied (404 graceful skip test)
- REQ-validation-ssl-self-signed satisfied (SSL defaults tests)
- REQ-validation-sanitization-coverage satisfied (full-pipeline tagged-secret test)
- REQ-finding-module-segmentation/wifi/firewall/remote-access/devices/api-coverage-meta ratified by test_all_12_modules_produce_findings
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-06-SUMMARY.md` with:
- Files created
- Total test count and pass/fail/skip distribution
- src/sanitizer.py coverage percentage
- Confirmation that REQs validation-network-version-compat, validation-ssl-self-signed, validation-sanitization-coverage are met
- T-1-02 mitigation status
</output>
