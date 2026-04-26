"""T-1-02 mitigation: static guard against accidental response-body / credential logging.

Walks src/*.py and asserts that no logger or print statement could leak the
API key or the response body. The existing safe pattern at src/unifi_audit.py
(scrubbing exception text via str(e).replace(key, "<REDACTED>")) is also
asserted as a regression detector -- accidental removal will fail this test.

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
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"logger\.(info|warning|error|debug|exception|critical)\([^)]*response\.text",
        re.IGNORECASE,
    )
    matches = pattern.findall(text)
    assert not matches, (
        f"{path.name}: logger call contains response.text -- credential/response leak risk. "
        f"Matches: {matches}"
    )


@pytest.mark.parametrize("path", _existing_files(), ids=lambda p: p.name)
def test_no_response_text_in_print_calls(path: Path):
    """No print(... response.text ...) or print(... r.text ...)."""
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"print\([^)]*\b(response|r)\.text", re.IGNORECASE)
    matches = pattern.findall(text)
    assert not matches, (
        f"{path.name}: print() emits response body -- leak risk. Matches: {matches}"
    )


@pytest.mark.parametrize("path", _existing_files(), ids=lambda p: p.name)
def test_no_print_of_api_key_variable(path: Path):
    """No print() that emits the api_key / cfg['key'] directly."""
    text = path.read_text(encoding="utf-8")
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
    text = path.read_text(encoding="utf-8")
    # Match: logger.info(self.cfg) or logger.info(cfg)
    pattern = re.compile(
        r"logger\.(info|warning|error|debug|exception|critical)\(\s*(self\.)?cfg\s*\)",
        re.IGNORECASE,
    )
    matches = pattern.findall(text)
    assert not matches, (
        f"{path.name}: logger emits full cfg dict -- credential leak. Matches: {matches}"
    )


def test_existing_safe_pattern_present():
    """Regression: src/unifi_audit.py scrubs the API key from RequestException text.

    If this assertion ever fails, the safe pattern was removed; restore it
    before merging. The scrub is at lines ~254-260 in the original file.
    """
    text = (SRC / "unifi_audit.py").read_text(encoding="utf-8")
    # The pattern: safe_msg = str(e).replace(self.cfg["key"], "<REDACTED>")
    assert 'replace(self.cfg["key"]' in text or "replace(self.cfg['key']" in text, (
        "Safe pattern removed from src/unifi_audit.py: the RequestException scrub "
        "that prevents API-key leakage in error logs is no longer present. "
        'Restore the line: safe_msg = str(e).replace(self.cfg["key"], "<REDACTED>")'
    )


def test_audit_log_format_does_not_include_response_body():
    """The audit-log format string in setup_logger should record URL + status only,
    never the response body or the key."""
    text = (SRC / "unifi_audit.py").read_text(encoding="utf-8")
    # The setup_logger fmt is: "%(asctime)s %(levelname)s %(message)s"
    # which is fine -- message comes from the logger.info("GET <url>") and
    # logger.info("  -> %d bytes") calls. We only need to confirm the calls.
    assert 'logger.info(f"GET {url}")' in text or "logger.info(f'GET {url}')" in text, \
        "Expected logger.info(GET <url>) pattern; format may have changed"
    # And no response.text in any logger call (already covered above per-file).
