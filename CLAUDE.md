# Context for Claude Code

This file is for Claude Code sessions. It summarizes project-specific conventions, constraints, and decisions so an agent can pick up work without re-deriving them.

## What we're building

A security posture advisor for Ubiquiti UniFi networks. It does three things:

1. **Connects** to a UniFi deployment (via official API, with backup-file as specialist fallback)
2. **Audits** the current configuration against industry best practices
3. **Interviews** the user for intent and context that isn't in the config

Output: a prioritized findings report with current state, recommendations, and confirm-intent questions per finding.

## Absolute constraints (do not violate)

These are structural properties, not toggleable settings. See `docs/05-credential-handling.md` for full detail.

1. **Credentials never leave the user's machine.** No telemetry, no cloud relay, no logging of secrets.
2. **No credential input via CLI args, chat messages, or URL parameters.** Environment variables, config files (600 perms), OS keychain, or interactive terminal prompts only.
3. **All outputs are sanitized.** PSKs, shared secrets, admin passwords become length + sha256 fingerprints. Never raw values.
4. **Read-only by default.** Write support requires explicit opt-in per action with a preview-then-confirm flow.
5. **Official API paths preferred.** X-API-KEY (Network Integration or Site Manager). Cookie-based auth only as a legacy fallback with a loud warning.
6. **Backup-file mode must be offline.** No network access during parsing.
7. **Default expiration on throwaway keys: shortest available** (currently 1 day in Ubiquiti's UI).

## Tier system (three audiences, one wizard)

Every user-facing question or finding has three voices:

- **Guided** - plain language, analogies, no jargon. For novices.
- **Standard** - feature names, moderate technical depth. For prosumers/tinkerers.
- **Pro** - exact config, control IDs, CVE refs. For engineers/architects.

Routing is based on a skills-check question, not pure self-assessment. The user can switch tiers any time.

## Data sources (in order of preference)

1. **Network Integration API** (local, X-API-KEY) - primary. Greatest depth of info, smallest trust boundary.
2. **Site Manager API** (cloud, X-API-KEY) - fallback. Use when CGNAT or MSP multi-site is needed.
3. **Unified API Key with Cloud Connector** - same key, both surfaces, as of April 2026.
4. **Backup file (`.unf` / `.unifi`)** - specialist mode. Airgap, forensic, MSP handoff, historical review.
5. **User answers** - only for what the first four cannot answer (intent, goals, non-UniFi devices, process).
6. **Classic cookie API** - DO NOT USE as primary. Requires disabling MFA on a local admin account; we flagged this as an anti-pattern.

## Finding data model

Every finding is a structured dataclass with these fields:

```python
@dataclass
class Finding:
    id: str              # e.g., "SEG-001"
    section: str         # questionnaire section (e.g., "Segmentation")
    severity: str        # info | low | medium | high | critical
    status: str          # ok | gap | recommendation | unknown
    title: str
    current_state: str   # plain-English; what we found
    recommendation: str | None
    intent_question: str | None  # "Is this what you intended?"
    evidence: dict       # raw (sanitized) supporting data
    maps_to: dict        # {nist_csf, cis_v8, zt_tenet, ...}
    effort: str          # quick | medium | project
    impact: str          # low | medium | high
```

All findings roll up to a prioritized remediation backlog, ranked by `(impact × user_priority_weight) / effort_hours`.

## Always-float-to-top findings (regardless of score)

- No MFA on any admin account
- Management plane reachable from WAN
- Flat network with multiple device classes (IoT + work + personal) on one VLAN
- Default credentials anywhere
- Firmware more than two majors behind with known advisories
- PPTP or any deprecated-crypto VPN enabled

## Out of scope for phase 1

- Apply mode (write operations)
- Drift monitoring over time
- Continuous/scheduled audits
- Multi-site aggregation beyond listing
- Protect/Access app audits (Network only for phase 1)

## Code conventions

- Python 3.9+
- Stdlib + `requests` + `pycryptodome` + `pymongo` only for phase 1-4 (minimal deps)
- All modules importable standalone
- No framework lock-in (no Django, no FastAPI for core - just functions and dataclasses)
- `requests.Session` for connection reuse, verify SSL where certs allow
- Type hints everywhere
- Docstrings on every public function and module

## Key decisions made during design

See `DECISIONS.md` for the full log. High points:

- **Pivot from backup-first to API-first.** API-key auth (post-July-2024 MFA rollout) is the officially supported path and doesn't require the MFA-less admin tradeoff. Backup mode is now specialist.
- **Do not build a competing MCP server.** Integrate with `sirkirby/unifi-mcp` when live-state queries are needed. Our value-add is the skills/prompts that teach an agent how to remediate our findings using their tools.
- **Every question needs optional free-text.** Button/select answers miss critical nuance (we learned this from our own walkthrough testing).
- **"Not sure" is a first-class answer type** with three resolution paths: guided helper, auto-check, or defer.
- **Cross-answer tension detection is a real engine requirement.** Individual findings miss compound risks.

## If something is unclear

- Design philosophy and reasoning: `docs/01-design-philosophy.md`
- API auth tradeoffs: `docs/02-api-strategy.md`
- What the backup format contains: `docs/04-backup-file-strategy.md`
- Why we don't write our own MCP: `docs/06-mcp-strategy.md`
- Where coverage gaps are: `docs/07-coverage-analysis.md`
- What's been decided and why: `DECISIONS.md`

## Testing fixtures we need

For Phase 1 validation:
- At least one real UniFi Network backup file (single-site `.unf`)
- At least one JSON dump from a live API run (can be generated via `src/unifi_audit.py`)
- A set of anonymized profiles across scales: home single-AP, home-office multi-AP, small business, simulated regulated environment

Profile labels used in code: `home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`.

## When adding a new finding

1. Add the finding logic to `src/findings_enhanced.py` or create a new module
2. Add the corresponding questionnaire item (current-state detection + intent question) to `QUESTIONNAIRE.md`
3. Map to at least one control framework (NIST CSF, CIS v8, or Zero Trust tenet)
4. Decide severity, effort, impact
5. Note which profiles it applies to (home profile shouldn't get enterprise retention recommendations)
