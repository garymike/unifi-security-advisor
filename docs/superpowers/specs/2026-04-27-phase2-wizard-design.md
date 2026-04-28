# Phase 2: Intent-Interview Wizard Design

**Date:** 2026-04-27  
**Status:** Approved  
**Scope:** Tauri desktop app + CLI, TypeScript rewrite of audit core, SQLite persistence, profile inference, tier routing, gap question wizard, report generation

---

## Summary

Phase 2 delivers the intent-interview wizard: a Tauri desktop app that runs the audit, infers the deployment profile, routes the user to the right experience tier (Guided / Standard / Pro), asks targeted gap questions for findings that need user intent to complete, and produces a merged report. The CLI remains a first-class mode using the same TypeScript audit core.

---

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Interface | Tauri v2 desktop + CLI | Secure, lightweight (~10MB), system webview, no bundled Chromium |
| Audit language | TypeScript (full rewrite from Python) | No cross-language boundary; audit logic is HTTP + JSON + rules — maps cleanly |
| Persistence | SQLite via @tauri-apps/plugin-sql | Queryable, file-on-disk, sets up Phase 7 drift comparison; Tauri-native, no native addon |
| Tier routing | Pre-wizard prompt after audit runs | Avoids onboarding friction; tier is per-session, not permanent |
| Profile detection | Infer from audit data + confirm | Reduces questions; user corrects if wrong |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Tauri Desktop App                  │
│                                                      │
│  ┌──────────────┐    IPC     ┌────────────────────┐  │
│  │  Svelte UI   │◄──────────►│   Rust shell       │  │
│  │  (frontend)  │            │  (window, fs, OS   │  │
│  └──────────────┘            │   keychain bridge) │  │
│         │                    └────────────────────┘  │
│         │ import                                      │
│  ┌──────▼──────────────────────────────────────┐     │
│  │         TypeScript audit core               │     │
│  │  src/audit/    src/wizard/    src/db/        │     │
│  └─────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────┘

CLI mode:  src/cli.ts  ──► same audit core, stdout report
```

### Tech Stack

- **Tauri v2** — Rust shell, system webview (Edge on Windows, WebKit on macOS/Linux)
- **Svelte 5** — Tauri's recommended frontend, minimal bundle
- **TypeScript** — all audit logic, wizard orchestration, DB queries
- **@tauri-apps/plugin-sql** — Tauri's first-party SQLite plugin; runs queries via Tauri IPC, no Node.js native addon required

### Credential Handling

Unchanged from existing rules (`docs/05-credential-handling.md`). API key read from environment variable (CLI mode) or Tauri-managed secure store (desktop). Rust shell handles OS keychain bridge. Key never written to SQLite or any output file.

---

## Directory Structure

```
src/
  audit/
    types.ts          # NormalizedSite, Finding interfaces
    normalize.ts      # normalize(raw) → NormalizedSite[]
    sanitize.ts       # sanitize(), fingerprint()
    client.ts         # UniFiClient (fetch-based, read-only)
    findings/
      segmentation.ts
      wifi.ts
      firewall.ts
      remoteAccess.ts
      devices.ts
      wirelessTuning.ts
      firewallThreats.ts
      firmware.ts
      logging.ts
      backup.ts
      apiCoverage.ts
    analyze.ts        # analyze() pipeline, float-top, profile scoring
    constants.ts      # ALWAYS_TOP_PREDICATES, PROFILE_OVERRIDES, EOL_MODELS
  wizard/
    orchestrator.ts   # question ordering, tier routing, "not sure" logic
    tiers.ts          # tier rendering helpers
  db/
    schema.ts         # CREATE TABLE statements
    queries.ts        # typed query functions
  ui/                 # Svelte components
  cli.ts              # CLI entry point
```

---

## TypeScript Data Model

### `Finding` Interface

```typescript
interface Finding {
  id: string;
  section: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  status: 'ok' | 'gap' | 'recommendation' | 'unknown';
  title: string;
  currentState: string;
  recommendation: string | null;
  intentQuestion: string | null;
  evidence: Record<string, unknown>;
  mapsTo: Record<string, string>;
  effort: 'quick' | 'medium' | 'project';
  impact: 'low' | 'medium' | 'high';
  floatTop?: boolean;           // set by analyze() post-pass
  tiers?: {
    guided?: { currentState?: string; recommendation?: string; intentQuestion?: string };
    pro?:    { currentState?: string; recommendation?: string; intentQuestion?: string };
  };
}
```

Tier overrides are optional. The base strings serve as Standard tier. Guided and Pro overrides are added progressively — not required at launch for every finding.

### `NormalizedSite` Interface

```typescript
interface NormalizedSite {
  siteId: string;
  siteName: string;
  devices: Record<string, unknown>[];
  clients: Record<string, unknown>[];
  wlans: Record<string, unknown>[];
  networks: Record<string, unknown>[];
  portForwards: Record<string, unknown>[];
  vpnConfigs: Record<string, unknown>[];
  firewallPolicies: Record<string, unknown>[];
  firewallZones: Record<string, unknown>[];
  trafficRoutes: Record<string, unknown>[];
  profile: string;
  apiGaps: string[];
}
```

---

## SQLite Schema

```sql
CREATE TABLE runs (
  id          TEXT PRIMARY KEY,   -- uuid
  timestamp   TEXT NOT NULL,
  host        TEXT,               -- sanitized (no key)
  profile     TEXT,
  tier        TEXT,               -- guided | standard | pro
  site_count  INTEGER
);

CREATE TABLE findings (
  id              TEXT NOT NULL,
  run_id          TEXT NOT NULL REFERENCES runs(id),
  section         TEXT,
  severity        TEXT,
  status          TEXT,
  title           TEXT,
  current_state   TEXT,
  recommendation  TEXT,
  intent_question TEXT,
  evidence        TEXT,           -- JSON blob
  maps_to         TEXT,           -- JSON blob
  effort          TEXT,
  impact          TEXT,
  float_top       INTEGER DEFAULT 0
);

CREATE TABLE answers (
  run_id      TEXT NOT NULL REFERENCES runs(id),
  finding_id  TEXT NOT NULL,
  answer      TEXT,               -- structured JSON (yes/no/partial/na)
  free_text   TEXT,
  tier        TEXT,
  answered_at TEXT,
  PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE sites (
  run_id      TEXT NOT NULL REFERENCES runs(id),
  site_id     TEXT,
  site_name   TEXT,
  api_gaps    TEXT                -- JSON array of endpoint names
);
```

---

## Wizard Session Flow

```
1. Audit runs → findings stored to SQLite
        │
        ▼
2. Profile inference screen
   "Looks like a home office setup (2 sites, 4 APs, mixed device types).
    Is that right?"
   [Yes]  [No, pick one ▼]  ← dropdown: home | home_office | small_business |
                                         regulated_hipaa | regulated_pci
        │
        ▼
3. Skills-check prompt  (pre-wizard, not a finding question)
   "Do you know what a VLAN is?"
   [Yes, I use them]      → pro
   [I've heard of them]   → standard
   [No / not sure]        → guided
   User can change tier at any point via settings icon.
        │
        ▼
4. Gap questions  (one screen per qualifying finding)
   Ordered: float-top first, then by severity
   Each screen shows:
     - Current state (tier-appropriate voice)
     - Recommendation (tier-appropriate)
     - Intent question as prompt
     - Answer buttons: [Yes] [No] [Partially] [Not applicable]
     - "Not sure" button → expands inline (see below)
     - Optional free-text: "Anything to add or clarify?"
        │
        ▼
5. Final report screen
   Prioritized backlog, exportable markdown + JSON
```

### "Not Sure" Resolution Paths

When the user clicks "Not sure" on a question, the question expands inline to show three options:

1. **Guided helper** — "Here's exactly where to find this in your controller: Settings → …" — static text per finding, links to UniFi docs where available
2. **Auto-check** — "Want me to look this up? I'll make one read-only API call." — consent prompt, runs the specific check immediately and pre-fills the answer
3. **Defer** — "Mark for later" — skips for now; finding flagged as `unknown` / unresolved in the final report

---

## Question Orchestration

```typescript
// wizard/orchestrator.ts
function getQuestionQueue(findings: Finding[]): Finding[] {
  return findings
    .filter(f => f.intentQuestion !== null)
    .filter(f => f.status === 'gap' || f.status === 'recommendation')
    .sort((a, b) => {
      if (a.floatTop && !b.floatTop) return -1;
      if (!a.floatTop && b.floatTop) return 1;
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
}
```

### Answer → Finding Status Mapping

| Answer | Effect on finding |
|--------|-------------------|
| Yes (intended) | `status → ok`, deprioritized in backlog |
| No | Recommendation promoted; effort/impact unchanged |
| Partially | Recommendation shown with nuance note |
| Not applicable | Finding excluded from backlog |
| Defer | `status → unknown`, flagged as unresolved |
| Free-text | Appended to `evidence`, visible in report |

---

## CLI Mode

`src/cli.ts` is the CLI entry point. It imports the same audit core (`client.ts`, `analyze.ts`, etc.) and outputs the same sanitized markdown + JSON report as today's Python script.

- API key read from `UNIFI_API_KEY` environment variable
- Profile read from `UNIFI_PROFILE` environment variable; defaults to `home_office` if unset
- No wizard interaction — CLI produces the raw findings report only; gap questions are skipped and findings with `intentQuestion` are emitted as-is
- No SQLite write in CLI mode unless `--save` flag is passed (saves run to local DB for later review in the desktop app)

The wizard is desktop-only for Phase 2.

---

## Profile Inference

Profile is inferred from audit data using heuristics (device count, network count, VLAN patterns). The inferred profile is shown to the user for confirmation before the skills-check. The inferred profile sets the initial scoring weights and recommendation voices for the session.

Heuristic examples (to be refined against real audit data):
- 1 site, ≤ 3 APs, ≤ 2 networks → `home`
- 1 site, 3–6 APs, ≥ 3 networks → `home_office`
- 1–2 sites, > 6 APs, ≥ 4 networks → `small_business`
- Any site with explicit HIPAA/PCI VLAN naming patterns → prompt for regulated profile

---

## Out of Scope for Phase 2

- Multi-site MSP workflows (Phase 3)
- Backup-file mode wizard integration (Phase 4)
- MCP remediation skill mapping (Phase 5)
- Apply / write mode (Phase 6)
- Drift monitoring (Phase 7)
- Protect / Access app findings
- Telemetry or opt-in metrics
