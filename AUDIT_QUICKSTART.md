# UniFi Audit Script - Quick Start

Local audit runner. Your API key stays on your machine.

## Prerequisites

- Python 3.9+ installed
- Network connectivity to your UniFi console (for local mode) or to `api.ui.com` (for cloud mode)
- `requests` library: `pip install requests`

## Generate a throwaway API key

1. Go to https://unifi.ui.com → Site Manager → API Keys → **Create New API Key**
2. Configure:
   - **Name:** `audit-{today-date}` (something you'll recognize to revoke)
   - **Expiration:** shortest option available (1 day preferred, 1 week max)
   - **Scopes:** check **UniFi Applications → Network** (minimum). Add Site Manager and Protect if desired.
   - **Sites:** scope to just the site you want audited
3. **Copy the key once.** It won't be shown again. Do not paste it into chat, email, clipboard managers, or anywhere else.

## Run the audit

### Option A: Local (recommended for single site)

```bash
# In a terminal
export UNIFI_API_KEY='<paste-key-here>'
export UNIFI_HOST='192.168.1.1'          # your gateway IP
# UNIFI_VERIFY_SSL defaults to false for local (self-signed certs)

python3 unifi_audit.py
```

### Option B: Cloud (Site Manager via api.ui.com)

```bash
export UNIFI_API_KEY='<paste-key-here>'
export UNIFI_USE_CLOUD=true
# UNIFI_VERIFY_SSL defaults to true for cloud

python3 unifi_audit.py
```

### Optional environment variables

- `UNIFI_PROFILE` - one of `home`, `home_office`, `small_business`, `regulated_hipaa`, `regulated_pci`. Tunes retention recommendations. Default: `home_office`.
- `UNIFI_VERIFY_SSL` - `true` or `false`. Override default.

## After the audit finishes

Output files in `./audit_output/`:

- `report.md` - Human-readable findings with recommendations
- `findings.json` - Machine-readable findings (same data, structured)
- `raw_sanitized.json` - All API responses, secrets already redacted
- `audit.log` - Timestamped log of what API calls were made (no secrets in log)

**All four files are safe to share** - they contain no secrets, no API keys, no plaintext passwords.

## Now revoke the key

1. Go to https://unifi.ui.com → Site Manager → API Keys
2. Find the key by the name you gave it
3. Delete it

Key should have auto-expired anyway if you picked the shortest option, but manual revoke is a belt-and-suspenders habit worth keeping.

## Troubleshooting

### "Missing dependency. Run: pip install requests"
Install Python's requests library: `pip install requests`

### 403 Forbidden errors
The API key doesn't have the right scope for that endpoint. Regenerate the key with broader scopes (check the UniFi Applications → Network box).

### 404 on several endpoints
Your Network app is older than 9.3.43. The script handles this gracefully and just audits what's available, but findings coverage will be reduced.

### SSL certificate errors
UniFi consoles use self-signed certs by default. The script disables SSL verification for local mode by default. If you've installed a real cert (e.g., Let's Encrypt) and want strict verification, set `UNIFI_VERIFY_SSL=true`.

### "All endpoint requests failed"
Check:
- `UNIFI_HOST` is reachable: `ping <host>` or `curl -k https://<host>`
- You're on the same network as the console (for local mode)
- Port 443 is open to the gateway from where you're running the script

## What the script does NOT do

- Does not make any changes (read-only, GET requests only)
- Does not transmit your key anywhere except to the specified UniFi endpoint
- Does not phone home, no telemetry, no update check
- Does not include secrets in any output file
- Does not include the API key in log messages (even in error text)

## What to do with the report

Once you have `report.md`, you can:

- Paste it (or sections of it) into a chat with Claude to discuss prioritization and remediation
- Share it with an MSP or consultant (no secrets, safe to forward)
- Archive it as compliance evidence of your audit
- Re-run the audit later and diff the `findings.json` files to track progress
