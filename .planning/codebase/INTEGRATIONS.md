# External Integrations

**Analysis Date:** 2026-04-25

## APIs & External Services

**Ubiquiti Network Integration API (Local):**
- Primary data source for Phase 1 audit
- URL pattern: `https://{console}/proxy/network/integration/v1/`
- Auth: X-API-KEY header (generated in Network app → Control Plane → Integrations)
- Scope: Device inventory, WLANs, firewall, port forwards, networks, VPN, traffic routes
- Endpoints probed:
  - `/proxy/network/integration/v1/info` - Controller metadata
  - `/proxy/network/integration/v1/sites` - List of sites
  - `/proxy/network/integration/v1/sites/{site_id}/devices` - Device inventory
  - `/proxy/network/integration/v1/sites/{site_id}/clients` - Connected clients
  - `/proxy/network/integration/v1/sites/{site_id}/wlans` - SSID/VLAN configuration
  - `/proxy/network/integration/v1/sites/{site_id}/firewall-policies` - Firewall rules
  - `/proxy/network/integration/v1/sites/{site_id}/firewall-zones` - Zone-Based Firewall
  - `/proxy/network/integration/v1/sites/{site_id}/port-forwards` - Port forwarding rules
  - `/proxy/network/integration/v1/sites/{site_id}/vpn-configs` - VPN server config
  - `/proxy/network/integration/v1/sites/{site_id}/networks` - Networks/VLANs
  - `/proxy/network/integration/v1/sites/{site_id}/traffic-routes` - Policy-based routing
- Implementation: `src/unifi_audit.py` lines 71-86 (endpoint list), lines 223-269 (UniFiClient class)
- Version requirement: 9.3.43+ (graceful 404 handling for older versions)
- Rate limiting: Gentle throttling (0.1s sleep between site-scoped calls, line 335)

**Ubiquiti Site Manager API (Cloud):**
- Fallback for users behind CGNAT or requiring multi-site fleet view
- URL: `https://api.ui.com/v1/`
- Auth: X-API-KEY header (generated at unifi.ui.com → Settings → API Keys)
- Endpoints (Phase 1):
  - `https://api.ui.com/v1/hosts` - Connected hosts/devices
  - `https://api.ui.com/v1/sites` - List of sites
  - `https://api.ui.com/v1/devices` - Device inventory
- Enabled via `UNIFI_USE_CLOUD=true` environment variable
- Implementation: `src/unifi_audit.py` lines 89-93 (cloud endpoint list), lines 242-243 (URL routing)
- SSL verification: Enabled by default for cloud (safer than local self-signed)
- Status: Phase 3 (scaffolded, needs validation with real unified key)

## Data Storage

**Databases:**
- **UniFi Network Controller (MongoDB)**
  - Connection: Local TCP/443 via UniFi controller's internal MongoDB (not directly accessible)
  - Access method: Via Network Integration API proxy (official)
  - Alternative: Direct BSON parsing from backup file (`src/parser.py` for Phase 4)
  - Collections used by findings:
    - `device` - AP/gateway/switch inventory
    - `networkconf` - VLAN definitions
    - `wlanconf` - SSID configuration
    - `firewallrule`, `firewallgroup` - Firewall rules
    - `portforward` - Port forwarding
    - `routing` - Static/policy routes
    - `setting` - System-wide settings (VPN, UPnP, remote access, SSH, threat management)
    - `account` / `admin` - Admin user accounts
    - `user` - Known clients/devices
    - `alarm`, `event` - Historical alerts and events
  - Details in `docs/04-backup-file-strategy.md` lines 36-54

**File Storage:**
- Local filesystem only
- Output directory: `./audit_output/` (created by script)
  - `raw_sanitized.json` - Sanitized API responses
  - `findings.json` - Structured findings (Finding dataclass as JSON)
  - `report.md` - Human-readable markdown report
  - `audit.log` - Timestamped audit trail (no secrets)
- Backup file input (Phase 4): `.unf` (single-site) or `.unifi` (console-level)
- No cloud storage, no telemetry persistence

**Caching:**
- None. Each audit run fetches fresh data from the controller.

## Authentication & Identity

**Auth Provider:**
- Custom X-API-KEY authentication (Ubiquiti's official approach)
- Two key types supported:
  1. **Network Integration API Key** (local, generated in Network app)
  2. **Site Manager API Key** (cloud, generated at unifi.ui.com)
- Third-party option (not recommended per CLAUDE.md D-007):
  - Classic cookie-based auth (local admin + session cookie) - legacy fallback only

**Implementation:**
- `src/unifi_audit.py` line 120-155: `load_config()` loads key from `UNIFI_API_KEY` env var only
- `src/unifi_audit.py` line 231-234: X-API-KEY header set in session headers
- Key security:
  - Never logged (sanitized in exception text, line 258)
  - Held in memory only for the run duration
  - Never transmitted except to the specified UniFi endpoint
  - Required per CLAUDE.md constraint: no CLI args, no chat, env var only

## Monitoring & Observability

**Error Tracking:**
- None (no telemetry, no cloud relay)
- Local logging only

**Logs:**
- Audit trail in `audit_output/audit.log`
- Implementation: `src/unifi_audit.py` line 162-176 (setup_logger)
- Logged events:
  - Script start/mode/settings (line 636-642)
  - Each API GET request URL (line 253)
  - Response status codes (line 261)
  - 404/403 endpoint unavailability (lines 288-306)
  - Module failures (line 371)
- Security: API key never logged, exception text scrubbed (line 258)

## CI/CD & Deployment

**Hosting:**
- Not applicable for Phase 1. Tool runs locally on user's machine.
- Future (Phase 5+): Optional cloud-hosted wizard frontend (not yet designed)

**CI Pipeline:**
- No automated CI configured yet
- Manual validation workflow documented in ROADMAP.md (working checklist, lines 99-106)
- Future: Integration tests against real/sample networks

## Environment Configuration

**Required Environment Variables:**
- `UNIFI_API_KEY` - API key (no default; script exits if not set)
- `UNIFI_HOST` - For local mode (required unless `UNIFI_USE_CLOUD=true`)

**Optional Environment Variables:**
- `UNIFI_USE_CLOUD` - "true"/"1"/"yes" to use Site Manager API (default: false)
- `UNIFI_VERIFY_SSL` - "true"/"false" to override SSL verification (default: true for cloud, false for local)
- `UNIFI_PROFILE` - Scoring profile for recommendations (default: `home_office`)

**Secrets Location:**
- Environment variables: Standard approach (secure in shell history on Unix systems)
- OS keychain: Recommended for production (future consideration)
- Config files with 600 permissions: Acceptable if needed (future)
- **NEVER:** CLI arguments, environment files, logs, output files, chat

## Webhooks & Callbacks

**Incoming:**
- None. Tool is read-only, pull-based.

**Outgoing:**
- None. No telemetry, no cloud relay, no third-party notifications.

## Backup Format Specifications

**`.unf` Format (Single-Site Backup):**
- Structure: AES-128-CBC encrypted ZIP archive
- Encryption keys (public, static, in UniFi source):
  - Key: `626379616e676b6d6c756f686d617273` (hex) = "bcyangkmluohmars" (ASCII)
  - IV: `75626e74656e74657270726973656170` (hex) = "ubntenterpriseap" (ASCII)
- Decryption: `src/parser.py` lines 45-64 (using pycryptodome)
- Decrypted contents: Standard ZIP
- ZIP contents: `db.gz` (gzipped BSON MongoDB dump) + metadata files
- BSON parsing: `src/parser.py` lines 67-94 (using pymongo)
- Collection extraction: BSON documents routed by collection name
- Usage: Phase 4 (future); Phase 1 uses live API instead
- Reference: `docs/04-backup-file-strategy.md` lines 17-30

**`.unifi` Format (Console-Level Backup):**
- Newer format for multi-site/UCore deployments
- Contains multiple `.unf` site backups + PostgreSQL dumps
- Out of scope for Phase 1; Phase 1.5 or later
- Reference: `docs/04-backup-file-strategy.md` line 31

## Data Flow Security Model

**Phase 1 (Live API Audit):**
1. User sets environment variables with API key locally
2. Script reads key from env (never CLI, never chat)
3. Script connects directly to UniFi controller on same LAN or via cloud API
4. Script fetches config data (read-only GET requests)
5. Script sanitizes response in-memory:
   - PSKs, passwords, shared secrets → length + SHA256 fingerprint (12-char)
   - See SECRET_FIELD_NAMES in `src/unifi_audit.py` line 183-188
6. Sanitization function: `src/unifi_audit.py` lines 205-216 (recursive deep sanitization)
7. Script writes three output files:
   - `raw_sanitized.json` - API responses with all secrets redacted
   - `findings.json` - Structured Finding objects (no secrets)
   - `report.md` - Human-readable findings (no secrets)
8. User deletes API key from Site Manager UI
9. Outputs are safe to share (no secrets in any file)
- Implementation detail: Sanitization happens before any file write (line 646-657 in main())

**Phase 4 (Backup-File Mode):**
1. User runs script offline with local `.unf` backup file
2. Script decrypts `.unf` in-memory (never extracts decrypted ZIP to disk)
3. Script parses BSON collections from ZIP
4. Same sanitization rules apply (secrets → fingerprints)
5. Script outputs sanitized findings
6. Original backup file remains unchanged
- Security: No network access during parsing (fully offline)
- Reference: `docs/04-backup-file-strategy.md` line 9 ("No network")

## API Key Lifecycle

**Generation:**
- Site Manager: unifi.ui.com → Site Manager → API Keys → Create New
- Network Integration: UniFi Network app → Control Plane → Integrations → Create API Key
- Recommended expiration: 1 day (shortest available in UI)
- Scopes: Network application required; Site Manager and Protect optional
- Reference: `AUDIT_QUICKSTART.md` lines 11-19

**Revocation:**
- Manual delete in Site Manager API Keys list (recommended)
- Auto-expiration if 1-day TTL chosen (belt-and-suspenders)
- Reference: `AUDIT_QUICKSTART.md` lines 60-66

## Compliance & Security Posture

**Constraints Enforced (from CLAUDE.md):**
1. ✓ Credentials never leave the user's machine
2. ✓ No credential input via CLI args (env var only)
3. ✓ All outputs are sanitized (secrets → fingerprints)
4. ✓ Read-only by default (GET requests only)
5. ✓ Official API paths preferred (Network Integration API as primary)
6. ✓ Backup-file mode is offline (no network access)
7. ✓ Throwaway keys with shortest expiration

**Threat Model:**
- If API key is compromised: Limited to read-only access to configuration data (no write endpoints enabled yet)
- If output files are leaked: No secrets, safe to share
- If script is intercepted: Runs locally, no network eavesdropping concerns
- If backup is leaked: Secrets already redacted before output; original .unf file is encrypted

---

*Integration audit: 2026-04-25*
