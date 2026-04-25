# Backup-File vs MCP: Long-Term Path Analysis

After implementing the coverage fixes, here's how the two approaches compare, and why I think a **hybrid** is the right long-term answer.

---

## What sirkirby/unifi-mcp actually provides

It's a mature multi-app MCP suite:

- **Network app MCP** - 166 tools, stable, covers devices, clients, firewall, WLANs, networks, port forwards, etc.
- **Protect app MCP** - 38 tools, beta, cameras and events
- **Access app MCP** - doors, credentials, visitors, policies
- Relay sidecar via Cloudflare Worker for cloud-side agents (no inbound ports)

### Security posture (important, since this is a security tool)

- **Credentials stay local.** Username/password used to authenticate directly with the local controller. Not transmitted to any external service (except optionally through the user's own Cloudflare Worker).
- **Read-only by default.** Write operations (`create`/`update`/`delete`) are disabled out-of-the-box and require explicit opt-in per category.
- **Preview-then-confirm for all mutations.** Two-step pattern; no blind changes.
- **Policy gates via env vars** for hard boundaries.
- **API key auth supported as experimental read-only.** Subset of tools.
- **No database/cache/sessions stored locally.**

That's a solid design, and it's roughly the same threat model our backup-file approach was optimizing for, just with a different tradeoff surface.

### What it uses for auth

Two modes:
1. **X-API-KEY** (the official Network Integration API path). Read-only, experimental, subset of tools. This is the path we wanted to prefer.
2. **Local admin username/password** via `/api/auth/login` + cookie session. This is what enables the full tool surface, **including write operations**. Same mechanism as the Classic API we explicitly wanted to avoid.

This matters: the MCP's full value requires the same MFA-less local admin we flagged as a weakness in the initial design discussion.

---

## Comparison

| Dimension | Backup-file mode | MCP (sirkirby) |
|---|---|---|
| **Credentials needed** | None (backup file only) | Local admin username/password for full feature set; API key for read subset |
| **MFA tradeoff** | No weakening | Requires MFA-less local admin for full tool surface |
| **Network access to controller** | None | Required; machine running MCP must reach controller on LAN |
| **Real-time data** | No, snapshot at backup time | Yes, live state |
| **Sees current traffic/alarms** | No (backups don't include events/traffic) | Yes |
| **Sees Protect/Access app state** | Requires `.unifi` decryption; UCore PostgreSQL | Yes, via dedicated MCP servers |
| **Can enact changes** | No (analysis only) | Yes, with opt-in and confirm step |
| **Works airgapped/offline** | Yes | No |
| **Shareable with MSP without granting access** | Yes (redacted backup file) | No |
| **Change-over-time analysis** | Yes (compare two backups) | Yes (poll over time) |
| **Works without UniFi cloud account** | Yes | Yes (local auth) |
| **Requires gear to be running/healthy** | No | Yes |
| **Forensics after compromise** | Yes (backup is an artifact) | Limited (attacker may have altered current state) |

---

## When each is better

### Backup-file wins when:
- The user is paranoid/regulated and doesn't want any new auth paths
- The deployment is an MSP audit (client hands over backup, MSP returns report)
- The analysis is about posture/config hygiene, not live troubleshooting
- The network is down or degraded (can still analyze historical config)
- Change-over-time is the point (compare backups across months)
- The backup file is the forensic artifact of interest (before/after compromise)

### MCP wins when:
- The user wants remediation help, not just analysis
- Questions involve current state, not just config: "what's connected right now," "any active IDS alerts," "which clients are on 2.4 GHz"
- The workflow is interactive: detect → discuss → apply → verify
- The user is comfortable granting local admin access
- Protect/Access app state needs to be audited alongside Network
- A natural-language agent is driving (Claude Desktop, Claude Code)

---

## Gaps in each, relative to our design

### What backup-file cannot answer (real gaps)

1. **Current MFA status** on the Ubiquiti SSO account (lives in cloud, not backup)
2. **CyberSecure subscription state** (licensing, lives in cloud)
3. **Current traffic patterns** (not persisted in backup)
4. **Live IDS/IPS alerts** (not in backup)
5. **Teleport user list and last-active** (lives in cloud)
6. **Device uptime, current firmware state vs reported state** (backup has last-known)
7. **Session/login activity** (not in backup)
8. **Known-vulnerable firmware cross-reference** (doable offline if we ship an advisory database; better with a live feed)

### What MCP cannot answer (or answers riskier)

1. **Historical posture** (what was the config 6 months ago?) - unless the MCP polls and stores, which it doesn't
2. **Offline/airgap review** (obvious)
3. **MSP-style handoff without granting access**
4. **Situations where the controller is compromised** (MCP is asking the compromised system about itself - bad forensic practice)

---

## Recommendation: hybrid, with backup-file as primary

The right long-term architecture is **both**, with clear divisions of labor:

### Backup-file: the posture engine (primary)

- Static config audit
- Compliance evidence ("here's what was configured on date X")
- Historical drift ("here's what changed between backup A and backup B")
- Redacted sharing for MSP audits
- Works without any live connection
- Ships first, lowest risk, highest portability

### MCP: the runtime companion (secondary, opt-in)

- Live state questions the backup can't answer (the 8 gaps above)
- Interactive remediation ("apply this change")
- Real-time validation ("did my fix take effect")
- Opt-in only, with a clear explanation of the MFA tradeoff
- User controls credentials and scopes

### Division of labor in the wizard

```
                    ┌──────────────────┐
                    │  User starts     │
                    │  wizard          │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Always: upload  │
                    │  .unf/.unifi     │
                    │  backup          │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Full posture    │
                    │  analysis runs   │
                    │  on backup       │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Generate gap    │
                    │  questions       │
                    └────────┬─────────┘
                             │
             ┌───────────────┼───────────────┐
             │                               │
             ▼                               ▼
  ┌─────────────────────┐       ┌──────────────────────┐
  │  User answers       │       │  Optional: connect   │
  │  intent questions   │       │  MCP for live gaps   │
  │  in wizard          │       │  (skip if uncomfort- │
  │                     │       │  able)               │
  └─────────┬───────────┘       └──────────┬───────────┘
            │                              │
            └──────────────┬───────────────┘
                           │
                  ┌────────▼─────────┐
                  │  Full report     │
                  │  + prioritized   │
                  │  backlog         │
                  └──────────────────┘
                           │
                  ┌────────▼─────────┐
                  │  Optional: MCP   │
                  │  applies fixes   │
                  │  with preview/   │
                  │  confirm         │
                  └──────────────────┘
```

### What this means for our roadmap

**Phase 1** (current): backup-file parser + findings modules. No change.

**Phase 2** (next): intent-interview wizard. Takes parser JSON + asks gap questions. Still no network/MCP.

**Phase 3** (optional add-on): MCP integration as opt-in. **Do NOT build our own MCP server.** Integrate with `sirkirby/unifi-mcp` as the upstream, which is further along, community-maintained, and well-designed. Our contribution becomes:

- **Skills/prompts** on top of their tools. The sirkirby repo already ships "agent skills" - we add domain-specific skills for security-posture workflows.
- **Our report format** as a schema their tools can reference (so Claude can say "for finding SEG-001, call unifi_list_networks to verify").
- **A CLI/wrapper** that bridges the backup-file findings to live-MCP remediation: "you have finding X, want me to open the MCP and fix it?"

**Phase 4** (later): drift monitoring. Pairs well with both modes. Backup-snapshot comparison is primary; MCP polling is optional for real-time.

### What NOT to build

- **Our own Network MCP server.** sirkirby has 166 tools and a mature project. Duplication.
- **A live-state scraper bolted onto the backup parser.** Keeps the offline mode pure; live state goes through MCP only.
- **Anything that requires the MFA-less local admin by default.** MCP path must be opt-in with clear disclosure.

---

## Concrete next steps

1. **Keep building Phase 1.** Finish `.unifi` decryption so we can validate against your production file. Complete stub modules.
2. **Write MCP-bridge skills for sirkirby/unifi-mcp.** Short documents that teach Claude how to use their tools to address each of our finding IDs. E.g., "finding FW-001 (IDS/IPS disabled)" maps to their `unifi_get_threat_management` read tool + `unifi_update_threat_management` write tool.
3. **Prototype the hybrid wizard.** Accept either/both inputs (backup file, MCP connection). Parser always runs if backup provided; MCP augments the gap questions with live answers when connected.
4. **Decide on branding/relationship.** Our project can be a companion/overlay to sirkirby, or we just document the integration pattern. Either way, avoid competing.

---

## One caveat on the MCP path

The MCP auth model (local admin + cookie session) is the same Classic API pattern we flagged at the start. It's what the MCP needs to be useful, but it does mean we can't honestly tell users "use our tool, keep all your MFA intact." We'd need to frame it as: "for the live/apply features, you're trading some admin-surface hardening for agent-driven remediation."

That's not necessarily wrong; lots of users will take that trade. But the wizard should make it explicit, not slip it in. One way: require the user to create a **dedicated local MCP admin account** with a strong password stored in a password manager, separate from their daily-use cloud admin. Then the MCP account is scoped-purpose, and compromise of it does not compromise the cloud account.
