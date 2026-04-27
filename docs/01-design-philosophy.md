# Design Philosophy

The principles that guide every decision in this project. When in doubt, return here.

## Core thesis

UniFi's built-in UI tells users *how* to configure things but not *whether their configuration is good*. This tool closes that gap by being:

1. **Discovery-first.** Detect current state before asking the user anything.
2. **Tier-aware.** Same content, three voices, routed by skills not self-assessment.
3. **Intent-confirming.** Ask "is this what you wanted?" not "do you have X?"
4. **Officially-supported by default.** Use Ubiquiti's documented APIs, not reverse-engineered shortcuts.
5. **Credential-respecting.** A security tool that requires weakening security to use it has an inverted threat model.
6. **Biomimetic.** Layered compartments (segmentation), graduated immune response (scoring), mycelial redundancy (alert correlation) as organizing metaphors that make complex security concepts intuitive.

## Discovery-first

Old pattern: *"Do you have IDS/IPS enabled?"* → user guesses → "Not sure"

New pattern: *"IDS/IPS is currently disabled. Your gateway can run it at 2.5 Gbps. Want it on?"* → user confirms intent → no guessing

Three benefits:
- No guessing (current state is factual, not recalled)
- Conversation shifts to intent, not quiz
- Education happens at the moment of decision

Where this fails: questions about intent, goals, fears, priorities, compliance, non-UniFi devices, physical placement, and process. These stay user-only because no API or backup can answer them.

## Three tiers, one wizard

Every user-facing question/finding has three voices:

| Tier | Audience | Voice |
|---|---|---|
| Guided | Novice, non-technical | Plain language, analogies, yes/no |
| Standard | Prosumer, IT-literate | Named features, moderate jargon |
| Pro | Engineer, architect | Exact config, control IDs, CVE refs |

Tier routing uses a skills-check question, not self-assessment. (We learned this from our walkthrough: a self-described "tinkerer" might still not know what a VLAN is.)

## Intent-confirming

Findings explain three things:
1. **Current state** in plain language
2. **Recommendation** tailored to the user's profile
3. **Intent question** so the user can correct us

Example:
> *Found:* Wi-Fi on UCG Fiber uses WPA2/WPA3 mixed.
> *Recommend:* WPA3-only for main SSID; keep WPA2 for an IoT-only SSID where cheap devices need it.
> *Confirm intent:* Do any clients on this SSID require WPA2-only?

The intent question matters most. It's how a security tool stops being a checklist and starts being a partner.

## Credentials in, never out

Structural property, not policy. The tool:
- Reads credentials only from environment variables, config files (mode 600), OS keychain, or interactive terminal prompts
- Never accepts credentials from CLI args, chat messages, URL parameters, or web forms that transmit elsewhere
- Sanitizes all secrets to length-and-fingerprint before any output
- Makes only GET requests by default; writes require explicit per-action opt-in

A security audit tool that requires the user to weaken their security posture to use it has an inverted threat model. We refuse to be that.

## Officially-supported paths first

The hierarchy:
1. Network Integration API (local X-API-KEY) - primary
2. Site Manager API (cloud X-API-KEY) - fallback for CGNAT/multi-site
3. Backup file (.unf/.unifi) - specialist mode for airgap, forensic, MSP handoff
4. Classic cookie auth - **avoid**, requires MFA-less local admin

Backup decryption is tolerated by Ubiquiti (keys public for 7+ years, no enforcement action) but not endorsed. Use it for the use cases it's actually best for, not as the default.

## Biomimetic framing

Three patterns from natural systems organize how we think about security architecture:

### Layered compartments (cell walls, organ systems)

Segmentation isn't just "VLANs are good." It's the principle that complex organisms survive because a problem in one compartment doesn't immediately compromise the whole. A compromised IoT bulb shouldn't reach a NAS.

### Graduated immune response (innate vs adaptive immunity)

Scoring isn't binary pass/fail. Innate responses (basic checks like default passwords, MFA) are universal. Adaptive responses (context-specific tuning based on environment, threat profile, regulatory needs) layer on top. The advisor mirrors this.

### Mycelial redundancy (fungal networks, distributed signaling)

Detection isn't single high-sensitivity rules that generate fatigue. Multiple low-cost signals combine into confident detections. Cross-answer tension detection (e.g., "high availability needs" + "single WAN" + "no tested restore") produces compound findings, not just three separate bullets.

## What we are not

- A penetration testing tool (no exploitation, no active probing)
- A runtime IDS/IPS (UniFi has its own)
- A config-management tool (no Terraform/Pulumi for UniFi)
- A substitute for Ubiquiti's Update Manager or security advisories
- A general-purpose network scanner (UniFi-specific awareness is the whole point)

## When designs conflict

Order of precedence:
1. **Safety:** never weaken the user's security posture
2. **Honesty:** never claim we audited something we couldn't see
3. **Usefulness:** prefer a partial answer with caveats over no answer
4. **Simplicity:** fewer questions, fewer dependencies, fewer modes
5. **Aesthetic preferences:** last

If a feature would require weakening security to enable, cut the feature. If a finding can't be honestly assessed, mark it unknown rather than guess. If two designs are equally honest and useful, pick the simpler one.
