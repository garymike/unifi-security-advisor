# Backup-File Mode: Specification

Phase 1 of the Ubiquiti Security Advisor. Analyzes a UniFi Network controller backup file (`.unf`) entirely offline and produces a structured findings report.

---

## Design principles

1. **No network.** The parser never calls out. Runs locally, processes a file, writes a report.
2. **No secret exposure.** WPA keys, PSKs, RADIUS secrets, and API keys are hashed or redacted in all output. Raw-dump mode exists but requires an explicit flag and prints a warning.
3. **Deterministic.** Same backup in, same report out. No time-of-analysis surprises.
4. **Portable.** Single-file Python executable with minimal dependencies. MSPs can run it on the client's machine and hand back a report, without ever transmitting the backup.
5. **Report, not verdict.** Output explains what was found, what it means, and recommended intent-confirmation questions. It does not auto-apply anything.

---

## File format, confirmed

A `.unf` file is:
1. AES-128-CBC encrypted blob (static key and IV, both public in UniFi source)
2. Decrypts to a standard ZIP archive
3. ZIP contains `db.gz` (gzipped BSON MongoDB dump) and a few metadata files
4. BSON dump contains the UniFi Network controller database

Public decryption keys (hex):
- Key: `626379616e676b6d6c756f686d617273` (ASCII: `bcyangkmluohmars`)
- IV:  `75626e74656e74657270726973656170` (ASCII: `ubntenterpriseap`)

These keys are reverse-engineered from the UniFi source and used by every existing open-source tool in this space. We're not breaking anything; users have legitimate access to their own backups.

Newer console-level `.unifi` backups exist (UniFi OS consoles such as Cloud Gateway Fiber; the full System Backup includes PostgreSQL for UCore alongside the Network app data). **Now supported** in the TypeScript CLI path — see "Console-level `.unifi` format" below.

### Console-level `.unifi` format (UniFi OS consoles)

Reverse-engineered live against a real Cloud Gateway Fiber backup and implemented in `src/audit/parseUnifiOsConsoleBackup.ts`, wired as a fallback in `parseBackupNodejs` (the classic `.unf` path is tried first, unchanged). It differs from the classic format in every layer:

1. **AES-256-CBC** (not AES-128), static key `e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f` (hex), with the **IV embedded in the first 16 bytes of the file** (not a static IV). Ciphertext is the remainder.
2. Decrypts to a **gzip'd TAR archive** (not a ZIP), containing `backup/network/`, `backup/ucore/` (UCore PostgreSQL data), `backup/uos/`, `backup/users/`.
3. `backup/network/db.gz`, once extracted and gunzipped, is a **marker-based BSON stream**: a `{ collection, __cmd, ... }` marker document precedes a run of untagged data documents belonging to that collection until the next marker — unlike the classic format's per-document collection tagging.

Both formats produce the same `Collections` shape, so `normalizeBackup()` and every finding module consume them identically. Scope this round is the Network app data in `db.gz`; UCore PostgreSQL (`pg_dump` custom format) and the Rust/Tauri desktop path are deferred until a consumer needs them.

---

## MongoDB collections of interest

| Collection | What we learn |
|---|---|
| `device` | All adopted devices: gateways, switches, APs. Model, firmware, adoption state, SSH config, LED/location hints |
| `networkconf` | Networks/VLANs: subnet, gateway, DHCP config, DNS, VLAN ID, purpose (corporate/guest/VLAN-only), isolation toggle |
| `wlanconf` | WLANs/SSIDs: security mode, WPA version, PSK (hashed in our output), hidden flag, VLAN mapping, guest policy, band, client isolation, PMF, PPSK entries |
| `firewallrule` | Legacy firewall rules: ruleset, action, sources/destinations, state, enabled |
| `firewallgroup` | IP/port groups referenced by rules |
| `portforward` | All port forwards: source, destination, protocol, enabled |
| `routing` | Static routes, policy routes |
| `setting` | System-wide settings blob. Crucially includes `mgmt` (UPnP, remote access, SSH auth keys), `super_identity`, `usg`, `auto_speedtest`, `country`, `connectivity`, `dpi`, `threat_management` |
| `account` / `admin` | Admin users, auth method, role |
| `alarm` | Triggered alarms (last N) - tells us what the controller has been detecting |
| `user` | Known client devices with fingerprint, note, fixed IP assignments |
| `usergroup` | Bandwidth/access policies |
| `dashboard` | Widget state (low value) |
| `event` | Historical events (truncated in backup, but gives recent signal) |

Newer UniFi OS versions may include OON (Object-Oriented Network policies) in their own collection; parser handles both schemas.

---

## What backup-file mode answers vs what it can't

### Fully answerable from backup

All of these come directly from the collections above:

- Device inventory, models, firmware versions
- All networks/VLANs, their configuration, and which clients are on which
- All WLANs, security modes, isolation state, VLAN mapping
- All firewall rules (legacy and OON), groups, directions covered
- All port forwards and NAT rules
- UPnP state
- DNS configuration per network
- Admin accounts with auth methods
- SSH enablement state per device
- IDS/IPS configuration (threat_management setting)
- Auto-update settings
- Geo-IP and content filtering rules
- VPN server config (WireGuard/OpenVPN/L2TP)
- Backup schedule/retention config
- Country/timezone/system identity
- Client inventory with fingerprints and labels
- Connected devices, last-seen state at backup time

### Partially answerable from backup

- **MFA on cloud admin**: not in backup (lives in Ubiquiti SSO). User must confirm manually or check account.ui.com.
- **WPA password strength**: we can see the *length* and fingerprint the PSK, but not display it. Report gives "PSK length: 16 chars, entropy estimate: high" not the password itself.
- **Current CyberSecure subscription**: backup has a flag but live status is authoritative.
- **Remote access via Site Manager / Teleport**: enabled flag is in backup, but Teleport user list lives in the cloud.
- **Content filtering category lists**: in backup, but whether feeds are current depends on live state.

### Not answerable from backup (still require user input)

- Intent, goals, priorities, fears (Section 0, 1)
- Non-UniFi devices (NAS, Firewalla, Home Assistant, smart home hubs, printers)
- Physical placement of gear
- Process questions: has a restore been tested, is there a runbook, break-glass account documented
- Compliance obligations
- Migration context ("I used to have segmentation on my old router")
- Future plans

These become the remaining user questions. For our sample walkthrough user, that's roughly 15-20 questions instead of 60.

---

## Parser architecture

```
┌─────────────────┐
│   .unf file     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐    pycryptodome
│   decrypt.py    │◄── AES-128-CBC, static key/IV
└────────┬────────┘
         │ .zip blob
         ▼
┌─────────────────┐    stdlib
│   extract.py    │◄── zipfile → gzip → pymongo/bson
└────────┬────────┘
         │ list[dict] per collection
         ▼
┌─────────────────┐
│   sanitize.py   │◄── hash/redact secrets before any output
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   findings/     │◄── one module per questionnaire section
│  ├ admin.py     │    each produces a list[Finding]
│  ├ segmentation │
│  ├ firewall.py  │
│  ├ wifi.py      │
│  ├ remote.py    │
│  ├ firmware.py  │
│  └ backup.py    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    report.py    │── Markdown + JSON output
└─────────────────┘
         │
         ▼
┌─────────────────┐
│  gap_questions  │── Questions user still needs to answer
│      .md        │    (things not in backup)
└─────────────────┘
```

### Finding data model

```python
@dataclass
class Finding:
    id: str                      # e.g. "SEG-001"
    section: str                 # questionnaire section
    severity: str                # info | low | medium | high | critical
    status: str                  # ok | gap | recommendation | unknown
    title: str                   # short headline
    current_state: str           # plain-English description of what we found
    recommendation: str | None   # what we suggest, if anything
    intent_question: str | None  # "Is this what you intended?" prompt
    evidence: dict               # raw/sanitized data supporting the finding
    maps_to: dict                # CIS, NIST CSF, etc.
    effort: str                  # quick | medium | project
    impact: str                  # low | medium | high
```

### Sanitization rules

- PSKs, passphrases, shared secrets: replace with `{"length": N, "fingerprint": sha256[:12]}`
- Admin password hashes: exclude entirely
- IP addresses on WAN: keep (they're in the config and useful)
- Public IPs of remote peers (VPN): redact to `/24`
- MAC addresses: keep (needed for findings, and are broadcast anyway)
- Device serial numbers: keep (needed for EOL lookup)
- Client hostnames: keep but flag as PII (user can opt to redact for MSP sharing)

---

## CLI interface

```bash
# Analyze a backup
usa analyze backup.unf

# With redaction for sharing with an MSP
usa analyze backup.unf --redact-pii --out report.md

# Dump raw (after confirmation)
usa dump backup.unf --unsafe-include-secrets  # explicit opt-in

# Just generate the gap-questions doc without the full report
usa questions backup.unf
```

Python API:

```python
from unifi_security_advisor import analyze

result = analyze("backup.unf", profile="home_office")
print(result.summary)
for finding in result.findings:
    ...
result.save_report("report.md")
```

---

## Output

Three artifacts per run:

1. **`report.md`** - Findings ordered by severity and section, with current-state, recommendation, and intent-question for each. Sanitized by default.
2. **`gap_questions.md`** - The user-only questions that couldn't be answered from the backup. Scoped to the user's profile.
3. **`state.json`** - Machine-readable structured output. For the MCP server later, for diffing against future runs, for apply-mode later.

---

## What comes later (explicit non-goals for phase 1)

- **No MCP yet.** Deferred to phase 3+.
- **No live-fetch fallback.** If the backup lacks something, we ask the user; we don't call an API.
- **No apply mode.** Read-only analysis only.
- **No drift monitoring.** Single-snapshot analysis. Diff-over-time is phase 2+.
- **No UI.** CLI only for phase 1. Web UI is a phase 2 story.
- ~~**No .unifi console backup.** Single-site .unf only.~~ **Done** — UniFi OS console `.unifi` backups are now decrypted and parsed by the TypeScript CLI (see "Console-level `.unifi` format" above).
- **No auto-apply of findings.** User reads report, acts manually.

---

## Phase 1 milestones

| M | Deliverable | Size |
|---|---|---|
| M1 | Decrypt + extract + BSON → dict. Handles multiple backup versions. | ~200 LOC |
| M2 | Sanitizer. Redacts all secret classes above. | ~100 LOC |
| M3 | Findings modules for sections 2-8. One module per section, each returns `list[Finding]`. | ~800 LOC |
| M4 | Findings modules for sections 9-12. | ~400 LOC |
| M5 | Report generator (markdown + JSON). | ~200 LOC |
| M6 | Gap-question generator (profile-aware). | ~150 LOC |
| M7 | CLI and Python API. Docs. Basic test fixtures. | ~200 LOC |
| M8 | Test suite against anonymized sample backups (3 profiles minimum). | Depends |

Estimated total: ~2000 LOC plus tests. Two to three weeks for a single engineer.
