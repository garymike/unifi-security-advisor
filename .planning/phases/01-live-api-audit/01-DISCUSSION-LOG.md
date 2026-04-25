# Phase 1: Live API Audit - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in `01-CONTEXT.md` — this log preserves the alternatives considered.

**Date:** 2026-04-25
**Phase:** 01-live-api-audit
**Mode:** Interactive (text mode), batched questions
**Areas discussed:** Enhanced-module integration, Always-float-to-top + tension detection, Profile-aware scoring + auto-detection, Validation strategy & test infrastructure, Sanitization DRY fix scope, Coverage-gap surfacing in Phase 1 output

---

## Area 1 — Enhanced-Module Integration Strategy

### Q1: Bridge approach between API response keys and parser collection names?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) API-to-collections adapter | `unifi_audit.py:analyze()` builds parser-shape dict from API responses, passes to `findings_enhanced.py` modules unchanged. ~50-100 LOC. Phase 4 reuses enhanced modules without an adapter. | ✓ |
| (b) Refactor enhanced modules to accept both shapes | Inject a small data accessor. Cleaner long-term but invasive (touches 6 modules). | |
| (c) Keep two parallel implementations | One module set per data source. | |

**User's choice:** (a)
**Notes:** Lowest risk, preserves Phase 4 reuse, smallest diff. Adapter file location at planner discretion (likely `src/api_to_collections.py`).

---

## Area 2 — Always-Float-to-Top + Compound Correlation Mechanism

### Q2a: Pipeline shape?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) Two new analyze() passes | `_correlate_findings()` emits compound Findings (D-003). `_apply_float_top()` reorders using a hard-coded ID list. The 3 API-undetectable always-top findings become `status="unknown"` Findings with `intent_question` populated — they still float to top so they're visible (Honesty > Usefulness per `C-precedence-001`). | ✓ |
| (b) Add float_top + compound flags to the `Finding` dataclass | Sort by `(float_top, severity, score)`. Schema change. | |
| (c) YAML rules-engine for correlations | New format to maintain. | |

**User's choice:** (a)
**Notes:** Composable, explicit, no schema changes to the locked `Finding` dataclass. The `unknown` Finding pattern primes Phase 2's wizard inputs structurally.

### Q2b: Where do compound rules live?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) Pure Python in new `src/findings_correlations.py` | One function per compound finding, returns `Finding | None`. Consistent with `findings_enhanced.py` style, no new format. | ✓ |
| (b) YAML rules file consumed by interpreter | New format, new interpreter. | |
| (c) Decorators on existing finding modules | Couples per-section modules with cross-section logic. | |

**User's choice:** (a)
**Notes:** Compound findings to seed the file: priority mismatch (downtime + single WAN + work ranked low), keys-to-kingdom (mobile remote management + MFA unknown), pivot path (NAS reachable by all + IoT internet-access unknown). Per `intel/decisions.md` D-003.

---

## Area 3 — Profile-Aware Scoring + Auto-Detection

### Q3a: Weight table location?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) `WEIGHTS` dict in new `src/profile_weights.py`, keyed `(profile, section) → multiplier` | Imported by `analyze()`, applied during ranking. Easy to audit, change, test. | ✓ |
| (b) Per-profile classes (HomeProfile, RegulatedHipaaProfile) | Subclass dispatch; more extensible long-term. | |
| (c) YAML config file | New format to parse. | |

**User's choice:** (a)
**Notes:** Multipliers start at 1.0 baseline; specific cells lifted (e.g., `(regulated_hipaa, logging) = 2.0`). Concrete values land in the planner's output, not here.

### Q3b: Profile detection in Phase 1?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) Manual `UNIFI_PROFILE` env var only | Default `home_office`. Report shows "Profile: home_office (manual)". Defer auto-detection to Phase 2 wizard. | ✓ |
| (b) Auto-detect from API data with override | Per CONCERNS.md heuristics. | |
| (c) Defer entirely to Phase 2 | No Phase 1 surfacing at all. | |

**User's choice:** (a)
**Notes:** Phase 2 has the skills-check + interactive-correction UX needed for auto-detection. Inferring silently in Phase 1 risks miscategorizing.

---

## Area 4 — Validation Strategy & Test Infrastructure

### Q4a: Validation shape?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) Manual real-network run captures fixtures → focused pytest suite | Pytest goes in now (CONCERNS.md flags zero tests as CRITICAL for a security tool). First targets: `sanitize()`, `_extract_list()`, `_extract_sites()`. | ✓ |
| (b) Manual checklist only | Defer all tests to Phase 2. | |
| (c) Full pytest setup with mocked HTTP layer | No real-network needed; more setup cost. | |

**User's choice:** (a)
**Notes:** pytest is dev-only — does not violate the runtime stdlib + requests/pycryptodome/pymongo dep rule from `C-code-001`.

### Q4b: Commit anonymized real-network fixture?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) One canonical sanitized fixture in `samples/fixtures/api_dump_home_office.json` | Used by tests for regression. User-supplied fixtures stay gitignored under `tests/fixtures/`. | ✓ |
| (b) No fixtures in repo; document regeneration only | All fixtures user-supplied. | |
| (c) All fixtures in repo | Higher review/diff burden. | |

**User's choice:** (a)
**Notes:** Fixture must be sanitized through `sanitize()`, hostnames/MACs/IPs anonymized beyond standard sanitizer scope, <200 KB ideal.

---

## Area 5 — Sanitization DRY Fix Scope

### Q5: When to extract `src/sanitizer.py`?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) Now, as a small standalone task | First task of the phase. Both `unifi_audit.py` and `parser.py` import from it. Eliminates leak-via-divergence risk immediately. ~30 min of work. | ✓ |
| (b) Folded into the enhanced-module wiring task | Done lazily as part of D-01. | |
| (c) Defer to Phase 4 prep | CONCERNS.md says "before Phase 4". | |

**User's choice:** (a)
**Notes:** Sequenced before D-01 (enhanced module wiring) so the adapter doesn't have to think about which sanitization path to use. Bonus: `findings_enhanced.py` can also `import` from `sanitizer.py` if it ever needs to.

---

## Area 6 — Coverage-Gap Surfacing in Phase 1 Output

### Q6: How does the report communicate undetectable items?

| Option | Description | Selected |
|--------|-------------|----------|
| (a) Each undetectable finding becomes a `status="unknown"` Finding | Float-to-top + `intent_question` populated + `recommendation` pointing to Phase 2 wizard. Honest, visible, structurally consistent — primes Phase 2 wizard inputs. | ✓ |
| (b) Dedicated "Limitations of API-only audit" section | Free-text section at end of report. | |
| (c) Silent | Phase 2 fills gap later, no Phase 1 surfacing. | |

**User's choice:** (a)
**Notes:** Reuses the locked `Finding` schema (`C-finding-001`) — no new output structure. The `intent_question` field on these `unknown` Findings is a structured handoff to Phase 2's wizard.

---

## Claude's Discretion (Areas Not Asked, Planner Has Flexibility)

- Exact directory layout for `tests/` (e.g., `tests/unit/` vs flat `tests/`)
- Specific multipliers in the `WEIGHTS` dict
- Adapter implementation style (function vs class)
- Naming of the always-top constant list (e.g., `ALWAYS_TOP_FINDING_IDS`)
- Pytest configuration details (`pyproject.toml` vs `pytest.ini`)
- Whether to add a `--profile` CLI flag in addition to `UNIFI_PROFILE` env var

## Deferred Ideas (Not Scope-Crept Into Phase 1)

- Auto profile inference → Phase 2
- MFA / default credentials / mgmt-plane WAN-reachable detection → surfaced as `unknown` Findings in Phase 1, resolved in Phase 2 wizard
- Tier-aware report rendering (Guided / Standard / Pro voices) → Phase 2
- `UNIFI_USE_CLOUD=true` validation → Phase 3 (Site Manager)
- Wire `findings_enhanced.py` into `parser.py` for backup mode → Phase 4 (already enabled by D-01)
- CVE database integration → backlog
- Configurable network request timeout → backlog
- Full schema-version response matrix for `_extract_list` → backlog

---

*Discussion log: 2026-04-25*
