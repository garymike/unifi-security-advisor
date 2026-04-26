"""Smoke script invoked by Plan 05 Task 2's verify command."""
import sys
sys.path.insert(0, "src")
import unifi_audit
from profile_weights import score_finding, KNOWN_PROFILES, get_weight, WEIGHTS, DEFAULT_WEIGHT

# Imports succeeded — check that unifi_audit re-exports score_finding and KNOWN_PROFILES
assert hasattr(unifi_audit, "score_finding")
assert hasattr(unifi_audit, "KNOWN_PROFILES")

# Cell math
assert get_weight("home", "Logging") == 0.4
assert get_weight("regulated_hipaa", "Logging") == 2.0
assert get_weight("home", "Bogus") == DEFAULT_WEIGHT

# Profile cross-product coverage
profiles = {"home", "home_office", "small_business", "regulated_hipaa", "regulated_pci"}
sections = {"Segmentation", "Wi-Fi", "Firewall", "Remote access", "Admin",
            "Wireless tuning", "Firmware", "Logging", "Backup", "Risk correlation"}
missing = []
for p in profiles:
    for s in sections:
        if (p, s) not in WEIGHTS:
            missing.append((p, s))
assert not missing, f"{len(missing)} cells missing: {missing[:5]}..."

# score_finding with regulated_hipaa Logging high/quick = (3*2.0)/2 = 3.0
class F:
    impact = "high"
    effort = "quick"
    section = "Logging"
assert abs(score_finding(F(), "regulated_hipaa") - 3.0) < 0.001

print(f"OK — {len(WEIGHTS)} weight cells; coverage complete")
