"""Regression: every Path.write_text() call in src/ must specify encoding='utf-8'.

Background: Python's Path.write_text() defaults to the locale encoding when none
is provided. On Windows + Python 3.14 that's cp1252, which cannot encode the
non-ASCII characters used in render_report() output (e.g. the '->' arrow).
A real-network audit run hit this bug at src/unifi_audit.py:886, crashing
after findings.json was written but before report.md.

This is a structural test — it scans the source files and fails if any
write_text() call lacks encoding="utf-8". Cheaper and more reliable than a
behavioral test that monkey-patches the locale.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

# Capture each .write_text(...) call (handles multi-line argument lists).
WRITE_TEXT_CALL = re.compile(r"\.write_text\s*\((.*?)\)\s*$", re.DOTALL | re.MULTILINE)


def _iter_write_text_calls():
    """Yield (file_path, line_number, full_call_text) for each write_text call."""
    for py_path in SRC_DIR.rglob("*.py"):
        text = py_path.read_text(encoding="utf-8")
        # Track running line number by counting newlines up to each match.
        for m in WRITE_TEXT_CALL.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            yield py_path.relative_to(REPO_ROOT), line_no, m.group(0)


def test_every_write_text_in_src_specifies_utf8_encoding():
    """No bare write_text() calls — every call must include encoding="utf-8".

    This guards against the cp1252 default that crashed Test 1's UAT run.
    """
    offenders = []
    for rel_path, line_no, call_text in _iter_write_text_calls():
        if 'encoding="utf-8"' not in call_text and "encoding='utf-8'" not in call_text:
            offenders.append(f"{rel_path}:{line_no}: {call_text.strip()[:120]}")

    assert not offenders, (
        "write_text() calls without encoding='utf-8' (Windows cp1252 will crash on "
        f"non-ASCII characters):\n  " + "\n  ".join(offenders)
    )


def test_at_least_one_write_text_call_exists_in_src():
    """Sanity: ensure the regex actually finds the production write_text calls.
    Catches cases where the source layout changes and the regex silently misses."""
    calls = list(_iter_write_text_calls())
    assert len(calls) >= 3, (
        f"Expected to find at least 3 write_text() calls in src/, got {len(calls)}. "
        "Regex may be broken or write_text usage was removed."
    )
