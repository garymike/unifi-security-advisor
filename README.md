# UniFi Security Advisor

A security posture advisor for Ubiquiti UniFi networks. Works with tech-illiterate novices through seasoned professionals as a QA tool for network setup.

## What this project is

An opinionated audit engine and guided wizard that evaluates a UniFi deployment against industry security best practices (NIST CSF 2.0, CIS Controls v8, Zero Trust principles) and Ubiquiti's own recommendations, then produces prioritized, actionable findings.

**Design principles:**

- **Discovery-first.** Don't ask users to remember config; detect the current state and ask them to confirm intent.
- **Progressive disclosure.** Same underlying questions, three voices: Guided (novice), Standard (prosumer), Pro (engineer).
- **Credentials in, never out.** Tool reads credentials locally, produces sanitized output safe to share.
- **Officially-supported paths first.** Primary integration via Ubiquiti's Network Integration API with X-API-KEY. Backup-file parsing exists as a specialist mode for airgap/forensic/MSP use.
- **Biomimetic framing.** Layered compartments (segmentation), graduated immune response (scoring), mycelial redundancy (alert correlation) as organizing metaphors.

## Project status

**Phase 1 (in progress):** Live API audit script via Network Integration API.

See `ROADMAP.md` for the full phase plan and current working checklist.

## Repository structure

```
unifi-security-advisor/
├── README.md                    # This file
├── CLAUDE.md                    # Context for Claude Code
├── ROADMAP.md                   # Phase plan + working checklist
├── DECISIONS.md                 # Key design decisions with rationale
├── QUESTIONNAIRE.md             # Full consolidated questionnaire
│
├── docs/
│   ├── 01-design-philosophy.md
│   ├── 02-api-strategy.md
│   ├── 03-site-manager-vs-network-integration.md
│   ├── 04-backup-file-strategy.md
│   ├── 05-credential-handling.md
│   ├── 06-mcp-strategy.md
│   ├── 07-coverage-analysis.md
│   └── 08-questionnaire-addendum.md
│
├── src/
│   ├── unifi_audit.py           # Phase 1: live API audit
│   ├── parser.py                # Phase 4: backup-file parser skeleton
│   ├── findings_enhanced.py     # Enhanced findings modules
│   └── inspect_backup.py        # Safe backup inspector
│
├── samples/
│   ├── walkthrough-responses.md
│   ├── sample-report.md
│   └── sample-gap-questions.md
│
└── AUDIT_QUICKSTART.md          # User-facing quickstart
```

## Quick starts

- **To run an audit against your network:** see `AUDIT_QUICKSTART.md`
- **To understand the design:** read `docs/01-design-philosophy.md`, then `DECISIONS.md`
- **To continue development:** read `CLAUDE.md`, then `ROADMAP.md`
- **To see the full questionnaire:** `QUESTIONNAIRE.md`

## Why this exists

UniFi's built-in UI tells users *how* to configure things but not *whether their configuration is good*. Existing community audit tools are either (a) raw rule-dumpers without prioritization, or (b) general-purpose network scanners that don't understand UniFi's specific patterns (ZBF vs legacy, Teleport vs VPN, PPSK, etc.).

This tool aims to close that gap: domain-aware, opinionated, tier-appropriate, and focused on measurable risk reduction over feature toggling.

## Non-goals

- Not a replacement for professional penetration testing
- Not a runtime IDS/IPS (UniFi has its own)
- Not a config-management tool (not Terraform/Pulumi for UniFi)
- Not a substitute for Ubiquiti's own Update Manager or security advisories
