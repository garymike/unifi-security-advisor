# UniFi API Best Practices and Decryption Ethics

Authoritative answers based on Ubiquiti's current documentation.

---

## Important correction to my earlier advice

In the MCP analysis, I conflated two different things and gave you incorrect guidance. Setting the record straight:

### What I said earlier (partly wrong)

> *"MCP's full value requires the same MFA-less local admin we flagged as a weakness."*

### What's actually true

There are **three** authentication methods for the UniFi Network API, not two:

1. **Classic cookie-session auth** (the thing I was warning about; requires MFA-less local admin)
2. **Network Application API Key** (official, released after Ubiquiti enforced MFA on cloud accounts in July 2024; does NOT require an MFA-less admin account)
3. **Site Manager API Key** (official, cloud-routed, X-API-KEY)

I was treating all local auth as "the MFA-less admin problem." The new API-key path (option 2) is officially supported, uses X-API-KEY headers, and has no MFA tradeoff. The sirkirby MCP server does support this path as "experimental, read-only." The cookie path is there for legacy/full-feature reasons, not because it's the recommended method.

This changes the decision calculus significantly.

---

## Ubiquiti's recommended API paths (2026)

Per Ubiquiti's official docs (developer.ui.com and help.ui.com):

### Site Manager API
- **URL:** `https://api.ui.com/v1/`
- **Auth:** X-API-KEY header (generated at unifi.ui.com → API or Settings → API Keys)
- **Scope:** Read-only as of now, write endpoints coming
- **Rate limit:** Documented (approximately 10,000 req/min)
- **Use case:** Multi-site fleet management, works through CGNAT, no direct network path needed
- **Ubiquiti's framing:** *"empowers developers to programmatically monitor and manage UniFi deployments at scale"*

### Network Application API (local)
- **URL:** `https://{console}/proxy/network/integration/v1/`
- **Auth:** X-API-KEY, generated in the Network app under Control Plane → Integrations
- **Scope:** Broader than Site Manager; covers devices, clients, firewall, WLANs, port forwards, traffic routes, etc.
- **Use case:** Direct local integration, single-site, detailed config access
- **Ubiquiti's framing:** Per-application API running locally on each site

### Application-specific APIs
- Each UniFi app (Access, Protect, Talk) has its own local API
- Access API has its own docs: https://developer.ui.com/unifi-api/access
- Protect API is less formally documented, mostly community-reversed

### The old path (local admin + cookie)
- Still works for legacy reasons
- Required only when you need endpoints not yet covered by the official API
- Ubiquiti has NOT deprecated it, but is clearly steering new integrations toward API keys
- **Key quote from Art-of-WiFi docs:** *"When Ubiquiti enforced MFA on cloud (UI.com) accounts in July 2024, automated integrations broke."* The API-key paths are the replacement.

---

## Ubiquiti's authoritative recommendation (paraphrased from their docs)

> *"If you have a stable direct connection to the controller, use an API Key (local) or local admin. If you don't (CGNAT, dynamic IP, no port forwards), use Site Manager API Key."*

Translated to a decision tree:

```
Does the analyzer run on the same LAN as the UniFi console?
│
├── Yes ──► Network Application API Key (X-API-KEY, local)
│           │
│           └── Highest feature coverage, lowest latency
│
└── No ───► Is the console reachable via a public IP or DDNS?
            │
            ├── Yes, consistently ──► Could use either; Site Manager is simpler
            │
            └── No (CGNAT, dynamic) ──► Site Manager API Key (cloud-routed)
                                         │
                                         └── Read-only today, works through NAT
```

---

## Why this is a better path than I originally framed

1. **No MFA tradeoff.** API keys are their own auth primitive. Generating one doesn't require disabling MFA on any account.
2. **Revocable without credential rotation.** Delete the key in the UI, it's dead. Rotating an admin password is a bigger operation.
3. **Scoped to API use.** Key isn't valid for logging into the web UI or mobile app. Compromise of the key gives API access only, not admin UI access.
4. **Officially supported.** Part of Ubiquiti's documented roadmap, with write endpoints arriving. Not a community workaround.
5. **Fits the security-tool narrative.** A tool that says "use our tool, here's the Ubiquiti-recommended auth method" is more defensible than one that says "use our tool, and also disable MFA on an admin account."

---

## Is backup decryption "hacking around" an API?

Honest answer: it's in a gray zone that's useful to understand clearly.

### What's definitively true

1. **Ubiquiti has never published a decryption tool or documented the format.** They've never said "here's how to read your backups." That's a choice.
2. **The keys are static, hardcoded in the UniFi source, and trivially extractable.** They've been public since at least 2017. Zhangyoufu's repo (the canonical OSS decryptor) is 7+ years old with 200+ stars.
3. **Ubiquiti has not taken action against the community tools.** They could have: changed keys, added real asymmetric crypto, issued DMCA takedowns, sued. They've done none of these. Whether that's indifference, implicit tolerance, or just deprioritization is unclear, but the practical reality is that these tools have been public for years without Ubiquiti acting.
4. **The user owns the backup of their own system.** There's no serious copyright or access-control question about a user reading their own data.
5. **Ubiquiti does NOT recommend, endorse, or support backup decryption.** There's no mention in their docs. It's a pure community practice.

### The honest positioning

- **API access:** Officially supported, documented, recommended, and the direction Ubiquiti is actively investing in.
- **Backup decryption:** Tolerated community practice. Not endorsed, not prohibited, works reliably but carries no support warranty.

### What this means for our tool

A security-audit product aimed at professional users (financial services, medical, critical infrastructure) should prefer the **officially supported** path as its primary mode. Relying on reverse-engineered format parsing as the primary interface sends the wrong signal, even if it works fine technically.

The backup-file mode still has legitimate use cases:
- Airgapped or sensitive networks where no API connection is desired
- MSP forensic handoff (audit a file, don't access the network)
- Historical config review (compare a backup from 6 months ago to today)
- Compliance evidence preservation ("here's the config as of audit date X")
- Analysis after a potential compromise (don't trust the live controller)

But it should be positioned as an **alternative** or **specialist** mode, not the primary path.

---

## Revised recommended architecture

Primary:  **Network Application API Key**
Secondary: **Site Manager API Key** (for remote/CGNAT scenarios)
Specialist: **Backup-file mode** (airgap, forensic, historical, MSP)
Avoid: **Local admin + cookie auth** (unless legacy deployment requires it)

### Mode selection UX

```
┌─────────────────────────────────────────────────────────┐
│ How should the advisor connect to your UniFi network?   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ● Directly, on the same network (recommended)          │
│    Uses a Network Application API key. We'll walk you   │
│    through creating one. Read-only. No admin account    │
│    needed. Officially supported.                        │
│                                                         │
│  ○ Through the Ubiquiti cloud (unifi.ui.com)            │
│    Uses a Site Manager API key. Good if you're not on   │
│    the same network as the console. Read-only.          │
│                                                         │
│  ○ Backup file only (airgapped / MSP mode)              │
│    Upload a .unf or .unifi backup. Nothing connects     │
│    over the network. Uses community tools to read the   │
│    file. Full posture audit, no live state.             │
│                                                         │
│  ○ I'm not sure, help me choose                          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Revised phase roadmap

This is a meaningful restructure from what we had. Primary path is now API-key based.

### Phase 1: Network Application API Key (local) integration
- **3-4 weeks**
- Read-only audit using X-API-KEY
- Covers 90% of findings modules we've already designed
- Officially supported auth path
- First shipping product

### Phase 2: Intent interview wizard
- **2-3 weeks**
- Consumes phase 1 output + asks gap questions
- Still no writes, no MCP

### Phase 3: Site Manager API Key fallback
- **2 weeks**
- For users behind CGNAT / no direct LAN access
- Subset of findings (Site Manager API has less than Network)

### Phase 4: Backup-file mode as specialist option
- **3-4 weeks**
- All the parser work we've already drafted
- Positioned as "airgap / MSP / forensic" mode, not primary
- Still valuable but not the default

### Phase 5: MCP integration (optional)
- **2-3 weeks**
- Integrate with sirkirby/unifi-mcp or build our own thin wrapper
- Enables interactive remediation: "apply this fix"
- User provides their own API key; we don't store it

### Phase 6: Write mode + apply
- **4-6 weeks**
- Uses official write endpoints as they become available
- Preview-then-confirm for every change (matching MCP community norms)

### Phase 7: Continuous drift monitoring
- **ongoing**

---

## Answering your specific questions directly

### "What are the best recommended best practice methods to use the UniFi APIs?"

The authoritative Ubiquiti hierarchy:

1. **Network Application API Key** for local integrations (generated in Network app → Settings → Control Plane → Integrations)
2. **Site Manager API Key** for cloud/remote integrations (generated at unifi.ui.com → API or Settings → API Keys)
3. **Local admin credentials** only for legacy/compatibility or when you specifically need endpoints the official API does not yet expose

All three use HTTPS. API keys use the `X-API-KEY` header. Neither of the first two options requires disabling MFA anywhere.

### "Is there an easy method to choose this implementation path?"

Yes. Single question: *"Can the machine running the tool reach the UniFi console directly on the LAN?"*

- Yes → Network Application API Key
- No → Site Manager API Key (cloud-routed)

Both are officially supported. Pick based on network topology, not based on any feature or security tradeoff.

### "Does Ubiquiti recommend decrypting the backups at all, or is this hacking?"

- **Recommend:** No. Never have.
- **Hacking:** Not really. "Hacking" implies bypassing a security control or access restriction. The backups belong to the user, the keys have been public for years, Ubiquiti knows and has taken no action. The better framing is **reverse-engineered, unofficial, community-supported**.
- **Position for a security tool:** Use it when the use case calls for it (airgap, forensic, MSP handoff, historical review). Don't make it the primary path. The API-key approach is the officially-supported method and it's what a mature security tool should default to.

The backup mode isn't "wrong" to support. It's just not the front door.
