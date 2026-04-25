---
phase: 01-live-api-audit
plan: 08
type: execute
wave: 7
depends_on: [07]
files_modified:
  - tools/anonymize_fixture.py
  - samples/fixtures/api_dump_home_office.json
  - tests/fixtures/.gitignore
autonomous: false
requirements:
  - REQ-test-fixtures
requirements_addressed:
  - REQ-test-fixtures
threat_refs: [T-1-03]
tags: [fixture, anonymization, commit, security]

must_haves:
  truths:
    - "tools/anonymize_fixture.py exists as a one-shot script (committed for reproducibility)"
    - "samples/fixtures/api_dump_home_office.json exists and is < 200 KB"
    - "Every value under any SECRET_FIELD_NAMES key in the committed fixture is a fingerprint dict (verified by tests/test_fixture_safety.py)"
    - "MAC addresses in the fixture are deterministic-fake (locally-administered range, e.g., 02:xx:xx:xx:xx:xx)"
    - "IP addresses in the fixture are RFC 5737 documentation ranges (192.0.2.x / 198.51.100.x / 203.0.113.x)"
    - "Hostnames in the fixture are generic placeholders (device-N.local / ap-N / switch-N)"
    - "Site names anonymized to test-site-* style"
    - "Serial numbers anonymized to SIM-{n:05d}"
    - "tests/test_fixture_safety.py: ALL tests now PASS (no skip — fixture exists)"
    - "tests/test_pipeline_smoke.py: canonical_api_dump fixture is now available; tests using it pass"
    - "tests/conftest.py canonical_api_dump fixture loads successfully"
  artifacts:
    - path: "tools/anonymize_fixture.py"
      provides: "One-shot anonymization tool (committed for reproducibility; not run automatically)"
      min_lines: 80
    - path: "samples/fixtures/api_dump_home_office.json"
      provides: "Committed canonical fixture (anonymized + sanitized; safe to read in code review)"
    - path: "tests/fixtures/.gitignore"
      provides: "Ensures user-captured raw_sanitized.json never gets committed accidentally"
  key_links:
    - from: "samples/fixtures/api_dump_home_office.json"
      to: "tests/conftest.py:canonical_api_dump"
      via: "conftest loads the file via Path.read_text"
      pattern: "samples/fixtures/api_dump_home_office.json"
    - from: "tests/test_fixture_safety.py"
      to: "samples/fixtures/api_dump_home_office.json"
      via: "_walk traversal with SECRET_FIELD_NAMES check"
      pattern: "CANONICAL_FIXTURE"
---

<objective>
Anonymize the user's captured `tests/fixtures/raw_sanitized.json` from Plan 07 and commit the safe version to `samples/fixtures/api_dump_home_office.json` (D-08). The committed fixture must:

1. Survive `tests/test_fixture_safety.py` (T-1-03 mitigation): no raw strings under SECRET_FIELD_NAMES keys.
2. Be < 200 KB so it is review-friendly.
3. Have all PII (MAC, IP, hostname, device names, site names, serial numbers) replaced with deterministic fake values.

After this plan, `pytest -q tests/` runs ALL tests including those that previously skipped because canonical_api_dump did not exist. The smoke suite gains a real-data smoke check, and REQ-test-fixtures is closed.

Output:
- `tools/anonymize_fixture.py` — one-shot anonymization script (committed for reproducibility)
- `samples/fixtures/api_dump_home_office.json` — committed canonical fixture
- All tests pass; nothing skips on absence of canonical_api_dump
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
@.planning/phases/01-live-api-audit/01-07-real-network-validation-PLAN.md
@CLAUDE.md (Constraint 3: All outputs are sanitized)
@docs/05-credential-handling.md
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Create tools/anonymize_fixture.py</name>
  <files>tools/anonymize_fixture.py</files>
  <read_first>
    - .planning/phases/01-live-api-audit/01-RESEARCH.md (§"Fixture Anonymization Strategy (D-08)" lines ~848-890)
    - tests/fixtures/raw_sanitized.json (the user's captured input)
    - tests/test_fixture_safety.py (the gate this script's output must pass)
  </read_first>
  <behavior>
    - Reads tests/fixtures/raw_sanitized.json (the gitignored captured file from Plan 07)
    - Walks the JSON tree, replacing identifying values with deterministic fakes
    - MAC addresses → locally-administered fake (02:xx:xx:xx:xx:xx) seeded from sha256 of original
    - IP addresses → RFC 5737 documentation range (192.0.2.x for IPv4 host octet)
    - Hostnames containing common patterns → generic placeholders
    - Device names → ap-N / switch-N / gateway-N counters
    - Site names → test-site-home-office
    - Serial numbers → SIM-{n:05d}
    - BSSIDs → same MAC anonymization
    - Writes to samples/fixtures/api_dump_home_office.json
    - Idempotent — running twice produces the same output
    - Output passes tests/test_fixture_safety.py
  </behavior>
  <action>
Create `tools/` directory if it does not exist. Then create `tools/anonymize_fixture.py`:

```python
#!/usr/bin/env python3
"""
Phase 1 fixture anonymization tool (D-08, REQ-test-fixtures).

Reads tests/fixtures/raw_sanitized.json (the user-captured real-network fixture
from Plan 07) and writes samples/fixtures/api_dump_home_office.json (the
committed-to-git canonical fixture).

Anonymization strategy (per RESEARCH.md §"Fixture Anonymization Strategy"):
- MAC addresses → locally-administered fake (02:xx:xx:xx:xx:xx; sha256-seeded)
- IPv4 addresses → RFC 5737 documentation range (192.0.2.X)
- Hostnames / device names → generic placeholders (ap-N, switch-N, etc.)
- Site names → test-site-home-office
- Serial numbers → SIM-{index:05d}

The sanitizer.py SECRET_FIELD_NAMES already replaces secrets with fingerprint
dicts; this script handles the additional PII layer.

Usage:
    python tools/anonymize_fixture.py
    # Reads:  tests/fixtures/raw_sanitized.json
    # Writes: samples/fixtures/api_dump_home_office.json

Run once (after Plan 07's real-network capture). Re-run if the captured
fixture changes (e.g., a new controller version).
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
INPUT = REPO_ROOT / "tests" / "fixtures" / "raw_sanitized.json"
OUTPUT = REPO_ROOT / "samples" / "fixtures" / "api_dump_home_office.json"

# Fields where the value is a MAC-shaped string
MAC_FIELDS = {"mac", "macAddress", "bssid", "bssId", "wanMac", "lanMac"}
# Fields where the value is an IP-shaped string
IP_FIELDS = {"ip", "ipAddress", "lanIp", "wanIp", "gatewayIp", "natIp", "ext_ip"}
# Fields where the value is a hostname or device name
NAME_FIELDS = {"hostname", "name", "deviceName", "siteName", "displayName"}
# Fields where the value is a serial number
SERIAL_FIELDS = {"serial", "serialNumber", "deviceSerial"}
# Patterns
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Deterministic counters keyed by original value so the same source maps to the
# same anonymized output on every run (idempotence).
_COUNTERS: dict[str, dict[str, str]] = {
    "device": {},
    "host": {},
    "site": {},
    "serial": {},
}


def _anon_mac(mac: str) -> str:
    """Deterministic fake MAC in locally-administered range.

    Set the locally-administered bit (0x02) on the first octet so analysts
    immediately recognize it as fake.
    """
    h = hashlib.sha256(mac.encode()).hexdigest()
    octets = [h[i:i + 2] for i in range(0, 12, 2)]
    first = (int(octets[0], 16) | 0x02) & 0xFE  # locally-administered, unicast
    rest = ":".join(octets[1:])
    return f"{first:02x}:{rest}"


def _anon_ipv4(ip: str) -> str:
    """RFC 5737 documentation range; preserve last octet for traceability within fixture."""
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    try:
        last = int(parts[3]) % 254 + 1
    except ValueError:
        last = 1
    return f"192.0.2.{last}"


def _anon_name(value: str, kind: str = "device") -> str:
    """Map name to a counter under its kind (device, host, site, serial)."""
    bucket = _COUNTERS.setdefault(kind, {})
    if value in bucket:
        return bucket[value]
    n = len(bucket) + 1
    if kind == "device":
        # Try to preserve device-class hint if recognizable
        v_low = value.lower()
        if any(w in v_low for w in ("ap", "u6", "uap", "u7")):
            new = f"ap-{n}"
        elif any(w in v_low for w in ("switch", "usw")):
            new = f"switch-{n}"
        elif any(w in v_low for w in ("gateway", "udm", "usg")):
            new = f"gateway-{n}"
        else:
            new = f"device-{n}"
    elif kind == "host":
        new = f"host-{n}.local"
    elif kind == "site":
        new = "test-site-home-office"
    elif kind == "serial":
        new = f"SIM-{n:05d}"
    else:
        new = f"anon-{n}"
    bucket[value] = new
    return new


def _classify_name_field(key: str, value: str) -> str:
    if key.lower() in {"hostname"}:
        return "host"
    if key.lower() in {"sitename"}:
        return "site"
    return "device"


def anonymize(obj: Any) -> Any:
    """Recursively anonymize a JSON-decoded value."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in MAC_FIELDS and isinstance(v, str) and MAC_RE.match(v):
                out[k] = _anon_mac(v)
            elif k in IP_FIELDS and isinstance(v, str) and IPV4_RE.match(v):
                out[k] = _anon_ipv4(v)
            elif k in NAME_FIELDS and isinstance(v, str) and v:
                out[k] = _anon_name(v, kind=_classify_name_field(k, v))
            elif k in SERIAL_FIELDS and isinstance(v, str) and v:
                out[k] = _anon_name(v, kind="serial")
            else:
                out[k] = anonymize(v)
        return out
    if isinstance(obj, list):
        return [anonymize(x) for x in obj]
    if isinstance(obj, str):
        # Catch BSSIDs / MACs that appear as values rather than under a known key
        if MAC_RE.match(obj):
            return _anon_mac(obj)
    return obj


def main() -> int:
    if not INPUT.exists():
        sys.stderr.write(
            f"Error: input fixture not found at {INPUT}.\n"
            "Run Plan 07 first to capture a real-network fixture.\n"
        )
        return 1

    raw = json.loads(INPUT.read_text())
    anonymized = anonymize(raw)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    # Pretty-print with 2 spaces, sort keys for diff stability
    OUTPUT.write_text(json.dumps(anonymized, indent=2, sort_keys=True))

    size = OUTPUT.stat().st_size
    print(f"Wrote {OUTPUT} ({size} bytes)")
    if size > 200 * 1024:
        sys.stderr.write(
            f"Warning: fixture is {size} bytes (>200 KB budget per D-08). "
            "Consider trimming or splitting.\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

This script is idempotent because the counter dicts are seeded from the original values — same input → same output.
  </action>
  <verify>
    <automated>python -c "import ast; src = open('tools/anonymize_fixture.py').read(); ast.parse(src); print('parses OK')"</automated>
  </verify>
  <acceptance_criteria>
    - File `tools/anonymize_fixture.py` exists
    - File parses as valid Python (verified by ast.parse via the verify command above)
    - `grep -c "def anonymize" tools/anonymize_fixture.py` returns 1
    - `grep -c "def _anon_mac" tools/anonymize_fixture.py` returns 1
    - `grep -c "def _anon_ipv4" tools/anonymize_fixture.py` returns 1
    - `grep -c "192.0.2" tools/anonymize_fixture.py` returns ≥ 1 (RFC 5737 range used)
    - `grep -c "0x02" tools/anonymize_fixture.py` returns ≥ 1 (locally-administered MAC bit)
  </acceptance_criteria>
  <done>Anonymization script committed; deterministic; idempotent; covers MAC/IP/hostname/device-name/site-name/serial fields; reads from tests/fixtures/raw_sanitized.json and writes to samples/fixtures/api_dump_home_office.json.</done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <name>Task 2: Run the anonymization tool and review the output before commit</name>
  <files>samples/fixtures/api_dump_home_office.json</files>
  <action>This is a checkpoint:human-verify task � see <how-to-verify> for full step-by-step instructions. The executor runs the anonymization tool and the fixture-safety tests; the user reviews the output JSON for any leaked PII or secrets before approving the commit.</action>
  <verify>User confirms via resume-signal that the fixture is review-clean and under the size budget.</verify>
  <done>Anonymization output reviewed; no PII or raw secrets visible; size under budget; user approved commit via resume-signal.</done>
  <what-built>
    tools/anonymize_fixture.py is ready. The user's captured tests/fixtures/raw_sanitized.json from Plan 07 is on disk (gitignored).
  </what-built>
  <how-to-verify>
Run the anonymization tool:

```bash
cd C:/_dev/unifi-security-advisor
python tools/anonymize_fixture.py
# Expected: "Wrote samples/fixtures/api_dump_home_office.json (<size> bytes)"
# If size > 200 KB, the script warns; trim the fixture (drop large embedded blobs) and re-run.
```

Then run the fixture-safety gate:

```bash
pytest -q tests/test_fixture_safety.py
# All 4 tests should now PASS (no skip — fixture exists).
```

Then run the full test suite to confirm nothing broke:

```bash
pytest -q tests/
```

**MANUAL REVIEW STEP — read the file before committing.** Open `samples/fixtures/api_dump_home_office.json` and skim it (or use `python -m json.tool samples/fixtures/api_dump_home_office.json | head -100`). Confirm:

1. No real MAC addresses (all should look like `02:xx:xx:xx:xx:xx`).
2. No real IP addresses (all should be `192.0.2.x`).
3. No real hostnames or device names (look like `device-1`, `ap-1`, `host-1.local`).
4. No raw secrets — every PSK / shared secret / password should be a `{"length": N, "fingerprint": "..."}` dict.
5. No sensitive note fields with personal information.
6. File size < 200 KB.

If anything looks personally identifying, edit the script to handle that field (e.g., add a new field name to NAME_FIELDS), re-run, and re-review. Do NOT commit until the review passes.
  </how-to-verify>
  <resume-signal>
Reply with one of:
- `"approved — ready to commit"` — fixture reviewed, no PII or secrets visible, size under budget. Plan 08 Task 3 proceeds.
- `"needs adjustment: <description>"` — a field type was missed; iterate on the script and re-run.
- `"oversized: <size>"` — fixture is over 200 KB; need to trim. Identify the largest embedded blob (look for big base64 strings, log fragments, etc.) and decide whether to truncate it.
  </resume-signal>
</task>

<task type="auto">
  <name>Task 3: Stage and verify the committed fixture passes all gates</name>
  <files>samples/fixtures/api_dump_home_office.json, tests/fixtures/.gitignore</files>
  <read_first>
    - samples/fixtures/api_dump_home_office.json (just produced by Task 2)
    - tests/test_fixture_safety.py (the gate)
    - tests/fixtures/.gitignore (Plan 01 created this; confirm `*` + `!.gitignore`)
  </read_first>
  <behavior>
    - samples/fixtures/api_dump_home_office.json exists and is < 200 KB
    - tests/test_fixture_safety.py: ALL tests PASS (none skip)
    - canonical_api_dump fixture in conftest.py loads the file successfully
    - A new smoke test against the canonical fixture confirms analyze() produces ≥ 4 findings on real data
    - tests/fixtures/.gitignore is intact (no real captures sneak in)
    - Full pytest suite green
  </behavior>
  <action>
1. Confirm `samples/fixtures/api_dump_home_office.json` exists and is < 200 KB:

```bash
ls -la samples/fixtures/api_dump_home_office.json
test $(stat -c%s samples/fixtures/api_dump_home_office.json 2>/dev/null || stat -f%z samples/fixtures/api_dump_home_office.json) -lt 204800
```

2. Confirm `tests/fixtures/.gitignore` is intact (no accidental check-in of the real capture):

```bash
cat tests/fixtures/.gitignore
# Expected:
# *
# !.gitignore
```

If `tests/fixtures/raw_sanitized.json` exists, confirm `git check-ignore tests/fixtures/raw_sanitized.json` reports it is ignored.

3. Run the fixture-safety tests with NO skip:

```bash
pytest -q tests/test_fixture_safety.py -v
# All 4 tests must PASS (none should skip — that means the fixture file exists and conformed)
```

4. Add a small smoke test that exercises the canonical fixture in tests/test_pipeline_smoke.py. Append to that file:

```python
def test_canonical_fixture_pipeline_smoke(canonical_api_dump):
    """REQ-test-fixtures + REQ-validation-real-network: real-data pipeline smoke.

    Runs analyze() on the canonical fixture (sanitized + anonymized real capture
    from Plan 07/08). Asserts findings shape and non-empty result.
    """
    import logging
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())
    findings = analyze(canonical_api_dump, "home_office", logger)
    assert len(findings) >= 4, f"Expected ≥4 findings on real fixture, got {len(findings)}"
    # Validate shape
    for f in findings:
        assert f.severity in VALID_SEVERITIES
        assert f.status in VALID_STATUSES
    # Always-top must include the 3 unknowns at minimum
    ids = {f.id for f in findings}
    assert "MFA-UNKNOWN-001" in ids
    assert "CRED-DEFAULT-001" in ids
    assert "WAN-MGMT-001" in ids
```

5. Run the full suite:

```bash
pytest -q tests/
# Must exit 0
```

6. Stage the new files for commit (the orchestrator's git_commit step will create the commit; this task only verifies the staging is correct):

```bash
git add tools/anonymize_fixture.py samples/fixtures/api_dump_home_office.json
git status
# Expected output should show:
#   - new file:   tools/anonymize_fixture.py
#   - new file:   samples/fixtures/api_dump_home_office.json
# Should NOT show:
#   - tests/fixtures/raw_sanitized.json  (gitignored)
#   - audit_output/*  (gitignored)
```

If `git status` shows `tests/fixtures/raw_sanitized.json` is being staged, the .gitignore is broken; do not commit until fixed.
  </action>
  <verify>
    <automated>pytest -q tests/test_fixture_safety.py -v && pytest -q tests/</automated>
  </verify>
  <acceptance_criteria>
    - `samples/fixtures/api_dump_home_office.json` exists
    - File size < 200 KB
    - `pytest -q tests/test_fixture_safety.py` exits 0 with all tests PASSED (none skipped)
    - `pytest -q tests/` exits 0 (full suite green)
    - `tests/fixtures/.gitignore` exists and contains `*` + `!.gitignore`
    - `git check-ignore tests/fixtures/raw_sanitized.json` reports the file is ignored (if it exists)
    - tests/test_pipeline_smoke.py contains a `test_canonical_fixture_pipeline_smoke` function
    - `grep -c "test_canonical_fixture_pipeline_smoke" tests/test_pipeline_smoke.py` returns 1
  </acceptance_criteria>
  <done>Canonical fixture committed; gates pass with no skips; full test suite green; tests/fixtures/raw_sanitized.json properly gitignored; canonical-fixture smoke test added.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User's machine → public git history | The committed fixture goes into git history forever. Once leaked, it cannot be revoked. The fixture-safety gate is the last line of defense. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-1-03 | Information Disclosure | samples/fixtures/api_dump_home_office.json | mitigate | tests/test_fixture_safety.py is the gate that runs BEFORE the commit lands. It walks the JSON tree, asserts every value under SECRET_FIELD_NAMES is a fingerprint dict, and asserts file size < 200 KB. The anonymization script handles PII; the sanitizer handled secrets in Plan 01. The combination of (a) sanitization at run time + (b) PII anonymization at fixture-build time + (c) static gate at test time is the layered defense. |
</threat_model>

<verification>
After all tasks complete:

```bash
# Fixture exists and is committable
ls -la samples/fixtures/api_dump_home_office.json
file samples/fixtures/api_dump_home_office.json   # should be JSON

# Gates pass
pytest -q tests/test_fixture_safety.py -v
pytest -q tests/

# Real-capture is still gitignored
test -f tests/fixtures/raw_sanitized.json && git check-ignore tests/fixtures/raw_sanitized.json

# Anonymization script is reproducible
python tools/anonymize_fixture.py     # idempotent — should produce identical output
diff samples/fixtures/api_dump_home_office.json samples/fixtures/api_dump_home_office.json.new 2>/dev/null
```
</verification>

<success_criteria>
- tools/anonymize_fixture.py exists, parses, idempotent
- samples/fixtures/api_dump_home_office.json exists; <200 KB; no raw secrets; no real PII
- tests/test_fixture_safety.py: 4/4 pass (no skips)
- pytest -q tests/ exits 0
- T-1-03 mitigated by the layered defense (sanitizer + anonymizer + safety gate)
- REQ-test-fixtures closed
- The user-captured tests/fixtures/raw_sanitized.json is gitignored — never committed
</success_criteria>

<output>
After completion, create `.planning/phases/01-live-api-audit/01-08-SUMMARY.md` with:
- Anonymization script line count
- Final fixture size in bytes
- test_fixture_safety.py pass/fail status (must be 4/4 PASS)
- Confirmation that REQ-test-fixtures is closed
- Confirmation that all 22 phase REQ-IDs are now satisfied (link to ROADMAP.md update)
- Phase 1 acceptance bar status: 8/8 satisfied
</output>
