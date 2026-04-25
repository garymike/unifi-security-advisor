# Site Manager API vs Network Integration API

Short version: they're not competing feature sets. They target different use cases. Your guess had them inverted.

---

## The one-line summary

| API | Purpose | Scope |
|---|---|---|
| **Site Manager API** | Fleet monitoring across many sites | Breadth (all sites, aggregate health) |
| **Network Integration API** | Detailed management of one site | Depth (firewall, WLANs, port forwards, devices, clients) |

If you think of it as UniFi's version of "console vs cluster-wide view," Site Manager is cluster-wide, Network Integration is per-console.

---

## Feature comparison (today, April 2026)

### Site Manager API (cloud, `api.ui.com/v1/`)

**What it's good at:**
- List all hosts (consoles) owned by the account
- List sites per host
- List devices across sites (MAC, model, status, firmware, adoption state)
- ISP health metrics across sites (latency, packet loss, uptime)
- Aggregate performance data across deployments
- Works from anywhere with an internet connection
- Works through CGNAT, dynamic IP, any network topology

**What it's limited at:**
- No granular config (firewall rules, specific WLAN settings)
- No port forward details
- No per-client details beyond counts
- No VLAN / network configuration
- Read-only today; writes coming

**Tool-count sense check:** enuno's MCP documents Site Manager as "basic site listing and querying tools" that operate at the "account level." That's the bucket: breadth, not depth.

### Network Integration API (local, `{console}/proxy/network/integration/v1/`)

**What it's good at:**
- Full firewall policy management (zones, policies, policy ordering, zone-based firewall)
- Port forwards, traffic routes, NAT
- All networks / VLANs with full config
- All WLANs with security modes, guest policies, isolation, VLAN mapping
- Per-client details (fixed IP, user group, usage)
- Device config, port profiles, radio settings
- QoS and traffic shaping
- Most of the things our findings modules need

**What it's limited at:**
- One site at a time; no aggregation
- Requires direct network path (or the new Cloud Connector)
- Does NOT include UniFi OS-level settings (those live above the Network app)

### The new wrinkle: Cloud Connector (April 2026)

Ubiquiti's April 2026 release notes introduced a **Cloud Connector** that lets Site Manager API keys proxy requests to the Network Integration API via Ubiquiti's cloud. The URL pattern is:

```
https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration/v1/...
```

This is important: it means a Site Manager API key can now reach the Network Integration endpoints via a cloud-routed path, without needing a local network path. So the "which one gives me depth" question has a new answer: **either**, once you enable Cloud Connector on the console.

This essentially resolves the CGNAT problem that made Site Manager the fallback choice.

---

## Security posture comparison

You're right that both are **low-risk relative to the old cookie-auth pattern**. But they're not identical. Here's where they differ.

### Shared strengths (both APIs)

- X-API-KEY header auth; no cookies, no session state
- Key generation requires an authenticated admin logged into the UI
- Keys are scoped to the account/site they were generated from
- Keys are revocable in the UI independently of admin credentials
- No MFA tradeoff; key generation works with MFA enabled
- Rate-limited to prevent abuse
- TLS in transit

### Site Manager API (cloud)

**Where trust lives:** Ubiquiti cloud (`api.ui.com`) + your account's SSO posture.

**Attack surface if key is leaked:**
- Read access to your entire fleet's metadata (devices, sites, health)
- With Cloud Connector: proxied access to Network Integration endpoints on all consoles linked to the key

**Mitigations:**
- Key tied to your Ubiquiti SSO account; compromise of SSO account also compromises the key
- Protected by whatever you've done on SSO (MFA, password hygiene)
- Ubiquiti controls the cloud path; trust in Ubiquiti's infrastructure required

**Implicit trust requirement:** You're trusting Ubiquiti's cloud to not be compromised, to not log your config, and to proxy your requests honestly.

### Network Integration API (local)

**Where trust lives:** Local console only. No cloud proxy (unless you route through Cloud Connector).

**Attack surface if key is leaked:**
- Full read/write (as scoped) to the single console/site the key was generated on
- Does NOT expose other sites or fleet-wide data
- Attacker needs network path to the console to use the key (LAN access, VPN, or port exposure)

**Mitigations:**
- Key is useless without network reachability to the console
- Console is behind your own firewall; compromise requires two things (key + network position)
- No external infrastructure involved

**Implicit trust requirement:** Just your own network boundary and console hardening.

### Net: which is "more secure"

For most users, roughly equivalent. But the tradeoffs split:

| Concern | Site Manager | Network Integration |
|---|---|---|
| Dependency on Ubiquiti cloud integrity | Yes | No (unless using Cloud Connector) |
| Works if SSO account compromised | No (single point of failure) | Yes (key is independent) |
| Blast radius of a leaked key | Broader (fleet or account) | Narrower (one console) |
| Requires network path to use | No | Yes |
| Attack chain for exploitation | 1 step (use key) | 2 steps (key + network access) |

**For a solo home user with one console:** the Network Integration key has slightly better isolation, and a leaked key is less useful without LAN access.

**For an MSP with 50 sites:** the Site Manager key is operationally essential; Network Integration keys per-site would be a management nightmare.

**For compliance-sensitive environments:** Network Integration is cleaner because the trust boundary is entirely yours. The Site Manager API brings a third party (Ubiquiti cloud) into the audit scope.

---

## Which to choose for our security advisor tool

This changes our phase-1 implementation choice.

### For the audit tool specifically

**Primary: Network Integration API** (local, X-API-KEY).

Reasons:
1. Our findings modules need firewall details, WLAN config, port forwards, VLAN structure. Site Manager API doesn't expose these.
2. Trust boundary stays with the user. Security tools should minimize third-party trust.
3. Blast radius is smaller if the tool or its storage is compromised (key is useful for one console, not a whole fleet).
4. No Ubiquiti cloud dependency; the tool works even if Ubiquiti is having an outage.

**Fallback: Site Manager API with Cloud Connector**

Use only when:
- User has multiple sites and wants fleet-wide audit (MSP use case)
- User is behind CGNAT / no viable LAN path
- User explicitly prefers cloud-routed for their own reasons

**Not primary** for solo/small deployments because it trades the user's clean local trust boundary for a feature they don't need (aggregation).

### Practical: many tools support both

sirkirby's MCP, Art-of-WiFi's clients, and the uchkunr reference implementation all support all three auth methods. We'd do the same: implement Network Integration first as the default, offer Site Manager as the "I don't have local access" option.

---

## Where your intuition was right

> *"I would imagine they're effectively the same low risk."*

Yes, relative to the old cookie-auth pattern they are. Both are a major improvement over what came before, and the differences between them are second-order. The big security jump happened when Ubiquiti introduced API keys at all; choosing between the two is optimization, not a major risk decision.

> *"Site Manager is more ubiquitous for all users."*

Also partly right. Every user with a UI.com account has Site Manager access available by default. Generating a Network Integration key requires an extra step (log into the local Network app, navigate to Integrations, create key). So Site Manager is more "reachable" in that sense.

But "more ubiquitous" and "more feature-filled" came apart in how Ubiquiti designed these. They chose to put the depth in the local API.

---

## Quick reference

| Question | Answer |
|---|---|
| Which has more features for single-site management? | Network Integration |
| Which has more features for multi-site fleet? | Site Manager |
| Which requires less network configuration to use? | Site Manager |
| Which has a smaller trust boundary? | Network Integration |
| Which has Ubiquiti's official write support first? | Unknown; both are on the roadmap |
| Which does sirkirby/unifi-mcp primarily use? | Network Integration (experimental API key path) with cookie fallback |
| Which should our audit tool default to? | Network Integration |
| Which should we offer as an alternative? | Site Manager (for CGNAT / MSP scenarios) |
