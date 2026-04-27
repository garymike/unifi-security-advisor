# Remaining Questions

The backup analysis covered your UniFi configuration. These remaining questions are things the backup cannot tell us, because they concern your intent, your process, or devices outside UniFi.

Profile detected from analysis: **Home + work from home, solo admin, small deployment, no regulations**.

Estimated time: 10-15 minutes.

---

## About what matters to you

1. **Priorities.** Rank top to bottom, what matters most?
   - Family privacy (photos, messages, cameras)
   - Work data and files
   - Keeping the internet working (uptime)
   - Smart home reliability

2. **What keeps you up at night?** Pick up to three:
   - Identity theft / account compromise
   - Someone watching cameras or listening through speakers
   - Ransomware locking files
   - Smart home controlled by someone else
   - Work files stolen or leaked
   - Family seeing inappropriate content

3. **Downtime tolerance.** If the internet went down unexpectedly, what actually breaks?
   - Nothing important, I can wait hours
   - Annoying within minutes
   - Work calls drop, video streams stop
   - I don't actually know until it happens

---

## About devices not visible to UniFi

The backup doesn't know about anything outside your UniFi controller. Please list:

4. **Storage devices (NAS).** The analysis detected 3 devices that look like NAS. Please confirm:
   - How many NAS units?
   - What's on them? (family photos, work files, media, backups, mixed)
   - Any of them accessible from the internet? (if yes, how)
   - Backed up somewhere off-site? (cloud, another physical location, no)

5. **Smart home / automation hub.** You mentioned plans for a Home Assistant box:
   - Existing or planned?
   - Will it need to talk to IoT devices across VLANs?
   - What protocols? (Zigbee, Z-Wave, Matter, Wi-Fi-only)
   - Will it be exposed remotely?

6. **Third-party security gear.** You mentioned a Firewalla:
   - Currently inline, passive (span), or unused?
   - If you re-add it, where in the path? (before UniFi, after, span-only)
   - What specific feature are you hoping it provides that UniFi doesn't?

7. **Other admin surfaces.** Anything else with a login we should know about?
   - Cable/fiber modem (ISP-provided) - is it in bridge mode?
   - Printer with web admin
   - Smart home bridges (Hue, SmartThings, HomeKit hubs)
   - Personal server, Plex, Unraid, Proxmox, etc.

---

## About your process

8. **Have you ever restored from a backup to prove it works?**
   - Yes, in the last 12 months
   - Yes but over a year ago
   - No, never had to
   - No, and I'd be nervous to try

9. **If you suspected a device was compromised right now, what would you do?**
   - Isolate it via UniFi UI (I know where to click)
   - I'd figure it out
   - I'd Google it
   - I'd ask someone

10. **Break-glass admin.** We flagged this as a top finding (no local admin). If you add one, where will you store its password?
    - Password manager (shared with cloud account, risk: same compromise)
    - Password manager on a device I always have (e.g., phone biometric)
    - Physical paper in a safe or safe-deposit box
    - Not sure yet

11. **MFA on your Ubiquiti cloud account.** We can't see this from the backup. Can you check https://account.ui.com/security right now and confirm?
    - Yes, MFA is on (app or hardware key)
    - Yes, SMS only (weaker, still something)
    - No, just password
    - I will check right now

---

## About remote access

12. **How do you reach your network when away from home?**
    - UniFi mobile app (via Site Manager)
    - A VPN I set up (WireGuard, Teleport, other)
    - I don't access it remotely
    - I open a port when I need to (please stop)

13. **Does anyone else need remote access?** (family members working remotely, etc.)

---

## About automation and time

14. **How many hours per week can you realistically spend on network ops?**
    - Less than 1
    - 1-3
    - 3-10
    - I'd rather spend more but life

15. **Comfort with automation.**
    - Happy to write scripts, use APIs
    - Prefer clicking through UIs
    - I want it to just work
    - Interested in learning

---

## About the future

16. **Anything planned in the next 6-12 months that should inform the design?**
    - Adding cameras
    - Starting a business
    - Hosting something public
    - Moving
    - Nothing planned, but I like knowing my options

17. **Is there anything in the report you disagreed with or want to push back on?**
    - (Free text)

---

## What happens with these answers

Once submitted, the advisor will:
1. Re-rank the findings by your actual priorities (not the generic defaults)
2. Generate a remediation backlog ordered by (your-priority-weight × impact) / effort
3. Produce a target-state design for segmentation including the NAS, Firewalla, and Home Assistant plans
4. Schedule a re-check in 30 days to confirm completed items stick

Your answers never leave your machine unless you explicitly share the report.
