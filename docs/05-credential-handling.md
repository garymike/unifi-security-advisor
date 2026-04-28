# Credential Handling Requirements

Non-negotiable design requirements for the Ubiquiti Security Advisor. These are structural properties, not user-toggleable settings.

## Core principle

**Credentials enter the tool. They never leave it.**

The tool processes authentication material locally, uses it to make API calls from the user's own machine, and produces sanitized output that is safe to share, copy, or transmit.

## Specific requirements

### Input channels for credentials

Allowed:
- Environment variables (e.g., `UNIFI_API_KEY`)
- Config files with appropriate permissions (mode 600 or equivalent)
- OS keychain / credential store (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux)
- Interactive password prompt that reads directly from terminal (not echoed, not logged)

Prohibited:
- Command-line arguments (visible in process lists, shell history)
- Chat messages or web form fields that transmit to any remote service
- Clipboard managers (most sync to cloud)
- URL parameters or query strings
- Any field that might be logged, cached, or transmitted as part of normal operation

### Storage

- No long-term storage of credentials by the tool itself
- If caching is needed (for a single audit run), hold in process memory only
- Zero the memory on process exit where possible
- Never write credentials to temp files, log files, or analysis output

### Transmission

- The tool may transmit the credential only to the UniFi controller (via the official API endpoint)
- The tool must not transmit credentials to any other endpoint, including the tool's own telemetry or update servers
- TLS certificate validation must be enforced; no "ignore SSL errors" mode for credential-bearing connections

### Output

- Generated reports, JSON outputs, state files, and diagnostic dumps must never include credentials
- This includes API keys, admin passwords, PSKs, RADIUS shared secrets, SSH keys, and session tokens
- Sanitization must happen **before** any data crosses a trust boundary (including before being written to disk in user-data directories that might be shared)
- If a user requests raw/unsanitized output, it must require an explicit flag, a clear warning, and write to a protected location

### Input validation for chat-bridged modes

If the tool is ever used via chat (e.g., Claude reading the tool's output and discussing findings), an additional guard:

- The tool must detect credential-shaped strings in any input it receives from chat
- Detection patterns: UniFi API key format, base64-encoded high-entropy strings of likely token length, strings prefixed with common credential markers (`Bearer`, `X-API-Key:`, `sk-`, etc.)
- On detection: reject the input, do not process, return an error explaining that credentials must be provided via environment variables or config files
- This protects users who misunderstand the interface

### Revocation support

- The tool should make it easy for the user to know what key is being used (name, last 4 chars, site scope, expiration)
- The tool should never be the only record of a key; the user's Ubiquiti account is authoritative
- On detected errors that might indicate compromise (unusual API errors, rate limiting from unexpected sources), the tool should guide the user to revoke immediately rather than retrying

### Audit trail

- The tool should log its own API calls with timestamps (to a user-controlled location, not cloud)
- Logs should show what calls were made but never the credential itself
- This lets a user verify after the fact that the tool only did what it claimed to do

## What this means in practice

A user should be able to:
1. Generate a short-lived, narrowly-scoped API key in the Ubiquiti UI
2. Export it to an environment variable or config file on their machine
3. Run the tool locally
4. Receive a sanitized report they can freely share with an MSP, paste into a chat with Claude for analysis, or archive for compliance
5. Revoke the key
6. Have confidence that no part of steps 2-5 exposed the key to anyone other than their own machine and their own UniFi controller

A user must NOT be able to:
- Accidentally paste a key into a chat input and have the tool attempt to use it
- Generate a report that contains the key or other secrets
- Inadvertently commit the key by running the tool in a directory synced to cloud storage

## Rationale

A security audit tool that requires the user to weaken their security posture to use it has an inverted threat model. The tool should be at least as careful with credentials as it advises the user to be.
