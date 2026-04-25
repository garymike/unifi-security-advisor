# Constraints Intel

Synthesized from SPEC sources: CLAUDE.md, docs/05-credential-handling.md, QUESTIONNAIRE.md.

CLAUDE.md and docs/05-credential-handling.md interlock: CLAUDE.md cites docs/05- as authoritative for credential handling. Where both speak to a constraint, docs/05- carries the structural detail and CLAUDE.md provides the summary that bind into code conventions and the data model.

---

## C-cred-001: Credentials never leave the user's machine

- source: CLAUDE.md "Absolute constraints" #1, docs/05-credential-handling.md "Core principle"
- type: nfr (security boundary)
- status: structural property, not a toggleable setting
- statement: No telemetry, no cloud relay, no logging of secrets. Credentials enter the tool, never leave it. The tool processes authentication material locally, uses it to make API calls from the user's own machine, and produces sanitized output that is safe to share, copy, or transmit.

## C-cred-002: Allowed credential input channels

- source: docs/05-credential-handling.md "Input channels for credentials" + CLAUDE.md #2
- type: nfr (input contract)
- allowed:
  - Environment variables (e.g., `UNIFI_API_KEY`)
  - Config files with mode 600 or equivalent permissions
  - OS keychain / credential store (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux)
  - Interactive password prompt that reads directly from terminal (not echoed, not logged)
- prohibited:
  - Command-line arguments (visible in process lists, shell history)
  - Chat messages or web form fields that transmit to any remote service
  - Clipboard managers (most sync to cloud)
  - URL parameters or query strings
  - Any field that might be logged, cached, or transmitted as part of normal operation

## C-cred-003: Credential storage lifecycle

- source: docs/05-credential-handling.md "Storage"
- type: nfr (memory hygiene)
- statement: No long-term storage of credentials by the tool itself. If caching is needed for a single audit run, hold in process memory only; zero memory on process exit where possible. Never write credentials to temp files, log files, or analysis output.

## C-cred-004: Credential transmission scope

- source: docs/05-credential-handling.md "Transmission"
- type: api-contract / nfr (network boundary)
- statement: The tool may transmit the credential only to the UniFi controller (via the official API endpoint). It must not transmit credentials to any other endpoint, including the tool's own telemetry or update servers.
- TLS: Certificate validation must be enforced; no "ignore SSL errors" mode for credential-bearing connections.

## C-cred-005: Output sanitization is mandatory

- source: docs/05-credential-handling.md "Output", CLAUDE.md "Absolute constraints" #3
- type: nfr (output contract)
- statement: Generated reports, JSON outputs, state files, and diagnostic dumps must never include credentials. This includes API keys, admin passwords, PSKs, RADIUS shared secrets, SSH keys, and session tokens.
- mechanism: PSKs, shared secrets, admin passwords become length + sha256 fingerprints. Never raw values.
- ordering: Sanitization must happen BEFORE any data crosses a trust boundary (including before being written to disk in user-data directories that might be shared).
- raw-output escape hatch: If a user requests raw/unsanitized output, it must require an explicit flag, a clear warning, and write to a protected location.
- detailed sanitization rules (from docs/04-backup-file-strategy.md "Sanitization rules"; informational, since DOC):
  - PSKs, passphrases, shared secrets → `{"length": N, "fingerprint": sha256[:12]}`
  - Admin password hashes → exclude entirely
  - WAN IPs → keep (in-config and useful)
  - Public IPs of remote VPN peers → redact to `/24`
  - MAC addresses → keep (broadcast anyway, needed for findings)
  - Device serial numbers → keep (needed for EOL lookup)
  - Client hostnames → keep but flag as PII (user can opt to redact for MSP sharing)

## C-cred-006: Chat-bridged input validation

- source: docs/05-credential-handling.md "Input validation for chat-bridged modes"
- type: nfr (input filter)
- statement: If the tool is used via chat (e.g., Claude reading the tool's output and discussing findings), it must detect credential-shaped strings in any chat-supplied input and reject them.
- detection patterns: UniFi API key format, base64-encoded high-entropy strings of likely token length, strings prefixed with common credential markers (`Bearer`, `X-API-Key:`, `sk-`, etc.).
- action on detection: reject the input, do not process, return an error explaining that credentials must be provided via environment variables or config files.

## C-cred-007: Key revocation guidance

- source: docs/05-credential-handling.md "Revocation support"
- type: nfr (operability)
- statement: The tool should make it easy for the user to know what key is being used (name, last 4 chars, site scope, expiration). The tool should never be the only record of a key; the user's Ubiquiti account is authoritative. On detected errors that might indicate compromise (unusual API errors, rate limiting from unexpected sources), guide the user to revoke immediately rather than retrying.

## C-cred-008: Audit trail of API calls

- source: docs/05-credential-handling.md "Audit trail"
- type: nfr (observability)
- statement: The tool should log its own API calls with timestamps to a user-controlled location (not cloud). Logs show what calls were made but never the credential itself. Lets a user verify after the fact that the tool only did what it claimed to do.

## C-cred-009: Default key expiration

- source: CLAUDE.md "Absolute constraints" #7
- type: nfr (defaults)
- statement: Default expiration on throwaway keys is the shortest available (currently 1 day in Ubiquiti's UI as of April 2026).

## C-write-001: Read-only by default; writes require explicit opt-in

- source: CLAUDE.md "Absolute constraints" #4
- type: behavioral contract
- statement: Read-only by default. Write support requires explicit opt-in per action with a preview-then-confirm flow.
- reinforced by: docs/01-design-philosophy.md ("Makes only GET requests by default; writes require explicit per-action opt-in"), docs/06-mcp-strategy.md (sirkirby MCP design pattern: read-only default, preview-then-confirm for mutations).

## C-data-001: Data source preference order

- source: CLAUDE.md "Data sources (in order of preference)"
- type: api-contract (data acquisition strategy)
- order:
  1. Network Integration API (local, X-API-KEY) — primary. Greatest depth of info, smallest trust boundary.
  2. Site Manager API (cloud, X-API-KEY) — fallback. Use when CGNAT or MSP multi-site is needed.
  3. Unified API Key with Cloud Connector — same key, both surfaces, as of April 2026.
  4. Backup file (`.unf` / `.unifi`) — specialist mode. Airgap, forensic, MSP handoff, historical review.
  5. User answers — only for what the first four cannot answer (intent, goals, non-UniFi devices, process).
  6. Classic cookie API — DO NOT USE as primary. Requires disabling MFA on a local admin account; flagged as anti-pattern.
- reinforced by: D-007 (ADR), docs/02-api-strategy.md, docs/03-site-manager-vs-network-integration.md.

## C-api-001: Official API paths preferred

- source: CLAUDE.md "Absolute constraints" #5
- type: api-contract
- statement: X-API-KEY (Network Integration or Site Manager) preferred. Cookie-based auth only as a legacy fallback with a loud warning.

## C-backup-001: Backup-file mode must be offline

- source: CLAUDE.md "Absolute constraints" #6, docs/04-backup-file-strategy.md "Design principles" #1
- type: nfr (network boundary)
- statement: No network access during parsing.

## C-tier-001: Three tiers, one wizard

- source: CLAUDE.md "Tier system", QUESTIONNAIRE.md tier-voicing schema
- type: behavioral contract
- statement: Every user-facing question or finding has three voices:
  - Guided — plain language, analogies, no jargon. For novices.
  - Standard — feature names, moderate technical depth. For prosumers/tinkerers.
  - Pro — exact config, control IDs, CVE refs. For engineers/architects.
- routing: skills-check question, not pure self-assessment. User can switch tiers any time.

## C-finding-001: Finding data model (canonical schema)

- source: CLAUDE.md "Finding data model"
- type: schema
- statement: Every finding is a structured dataclass.

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

- ranking: All findings roll up to a prioritized remediation backlog, ranked by `(impact × user_priority_weight) / effort_hours`.
- reinforced by: docs/04-backup-file-strategy.md "Finding data model" (identical schema).

## C-finding-002: Always-float-to-top findings

- source: CLAUDE.md "Always-float-to-top findings (regardless of score)", QUESTIONNAIRE.md "Always-float-to-top findings"
- type: behavioral contract (finding override)
- statement: Surface these to the top of any report when detected, regardless of overall scoring:
  1. No MFA on any admin account
  2. Management plane reachable from WAN
  3. Flat network with multiple device classes (IoT + work + personal) on one VLAN
  4. Default credentials anywhere
  5. Firmware more than two majors behind with known advisories
  6. PPTP or any deprecated-crypto VPN enabled

## C-questionnaire-001: Question metadata schema

- source: QUESTIONNAIRE.md "Question metadata template"
- type: schema
- statement: Every question is authored with the following metadata:

```yaml
id: Q5.3
section: Segmentation
text_guided: "..."
text_standard: "..."
text_pro: "..."
answer_type: single_select   # or multi_select, free_text, etc.
options: [yes, no, partial, unknown]
source: API                  # or API+confirm, API+enrich, User-only
unknown_resolution: guided_helper  # or auto_check, defer
free_text_allowed: true
maps_to:
  unifi_feature: ...
  nist_csf: ...
  cis_v8: ...
  zt_tenet: ...
risk_class: [...]
weight: N
profile_applicability: [home, home_office, small_business, regulated_*]
remediation:
  yes: null
  no: "..."
  partial: "..."
  unknown: "..."
```

- consequence: Every multi-select must include "+ Other (specify)" (D-004); every question must include optional clarification free-text; "not sure" is a first-class option with one of three resolution paths (D-005).

## C-questionnaire-002: Question source taxonomy

- source: QUESTIONNAIRE.md
- type: api-contract (data routing)
- statement: Each question's `source` is one of:
  - API — fully derivable from the API response
  - API+confirm — API gives the value; user confirms intent
  - API+enrich — API gives partial data; user adds non-UniFi context
  - User-only — only answerable by the user (intent, goals, non-UniFi devices, process)

## C-questionnaire-003: Section structure

- source: QUESTIONNAIRE.md "Section 0" through "Section 14"
- type: schema (questionnaire surface)
- sections:
  - Section 0: Profile and calibration (sets tier routing and unlocks compliance branches)
  - Section 1: Environment and intent
  - Section 2: Hardware and topology
  - Section 3: Internet and WAN
  - Section 4: Admin and identity (highest-leverage)
  - Section 5: Segmentation and trust zones
  - Section 6: Wi-Fi
  - Section 6.5: Wireless tuning (added per coverage analysis, docs/07/08)
  - Section 7: Firewall and threat detection
  - Section 8: Remote access
  - Section 9: Logging, detection, response
  - Section 10: Backup, recovery, resilience
  - Section 11: Physical security
  - Section 12: Firmware and lifecycle
  - Section 13: Operational capacity
  - Section 14: Compliance branch (conditional on Section 0.5; HIPAA / PCI / GLBA / FERPA / NERC CIP / CMMC)

## C-questionnaire-004: Control framework mappings

- source: QUESTIONNAIRE.md "Maps to" column + CLAUDE.md (every finding maps to at least one framework)
- type: schema
- frameworks supported:
  - NIST CSF (e.g., PR.AC-5, PR.PT-4)
  - CIS v8 (e.g., 12.2, 12.5)
  - Zero Trust tenets (e.g., per-session-access-decisions)
  - UniFi feature names (e.g., `client_device_isolation`)

## C-code-001: Code conventions

- source: CLAUDE.md "Code conventions"
- type: nfr (development standards)
- statement:
  - Python 3.9+
  - Stdlib + `requests` + `pycryptodome` + `pymongo` only for phase 1-4 (minimal deps)
  - All modules importable standalone
  - No framework lock-in (no Django, no FastAPI for core — just functions and dataclasses)
  - `requests.Session` for connection reuse, verify SSL where certs allow
  - Type hints everywhere
  - Docstrings on every public function and module

## C-profile-001: Profile labels

- source: CLAUDE.md "Testing fixtures we need" / Profile labels
- type: schema
- labels: `home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`
- usage: `profile_applicability` field on every question; profile-aware scoring weights and finding severity (e.g., home profile shouldn't get enterprise retention recommendations).

## C-precedence-001: Design conflict precedence (philosophical)

- source: docs/01-design-philosophy.md "When designs conflict"
- type: nfr (decision-making policy)
- order (when designs conflict, resolve in this order):
  1. Safety — never weaken the user's security posture
  2. Honesty — never claim we audited something we couldn't see
  3. Usefulness — prefer a partial answer with caveats over no answer
  4. Simplicity — fewer questions, fewer dependencies, fewer modes
  5. Aesthetic preferences — last
- consequence: If a feature would require weakening security to enable, cut the feature. If a finding can't be honestly assessed, mark it `unknown` rather than guess. If two designs are equally honest and useful, pick the simpler one.

---

## Constraint type breakdown

- nfr: 14 (security, network, observability, defaults, code conventions, decision policy)
- api-contract: 4 (data preference, API path preference, transmission scope, question source taxonomy)
- schema: 5 (Finding dataclass, question metadata, section structure, framework mappings, profile labels)
- behavioral contract: 3 (read-only default, tier system, always-float-to-top)
