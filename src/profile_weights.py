"""Profile-aware scoring weights for the UniFi Security Advisor.

Each (profile, section) key maps to a float multiplier applied during finding
prioritisation in ``analyze()``.  The formula is::

    score = (impact_score * weight) / effort_hours

**Multiplier semantics:**

- ``1.0``   — baseline; this section is weighted normally for this profile
- ``> 1.0`` — amplify; surface these findings higher in the report for this profile
- ``< 1.0`` — suppress; push these findings lower (they are less relevant here)

**Profiles** (per C-profile-001):

- ``home``             — residential, single operator, no compliance obligation
- ``home_office``      — small WFH setup; baseline profile (default)
- ``small_business``   — SMB with staff; operational continuity matters
- ``regulated_hipaa``  — healthcare / HIPAA; 6-year retention, admin controls critical
- ``regulated_pci``    — PCI DSS in scope; segmentation and firewall are cornerstones

**Sections** (from questionnaire and module output):

- Segmentation, Wi-Fi, Firewall, Remote access, Admin, Wireless tuning,
  Firmware, Logging, Backup, Risk correlation

The ``Audit scope`` meta-section (api_coverage finding) is intentionally omitted
from the explicit table; it falls back to ``DEFAULT_WEIGHT`` (1.0) for all profiles —
it is informational regardless of operator context.

Phase 1 ships with a static table (D-05).  Phase 2 will allow per-operator
weight overrides via the wizard.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Weight table — 5 profiles × 10 sections = 50 explicit cells
# ---------------------------------------------------------------------------

WEIGHTS: dict[tuple[str, str], float] = {
    # --- home: suppress enterprise-only recommendations ---
    ("home", "Logging"):           0.4,
    ("home", "Backup"):            0.7,
    ("home", "Firmware"):          1.0,
    ("home", "Segmentation"):      1.2,
    ("home", "Wireless tuning"):   0.8,
    ("home", "Firewall"):          1.0,
    ("home", "Remote access"):     1.0,
    ("home", "Admin"):             1.0,
    ("home", "Wi-Fi"):             1.0,
    ("home", "Risk correlation"):  1.0,

    # --- home_office: baseline ---
    ("home_office", "Logging"):           0.7,
    ("home_office", "Backup"):            1.0,
    ("home_office", "Firmware"):          1.0,
    ("home_office", "Segmentation"):      1.2,
    ("home_office", "Wireless tuning"):   1.0,
    ("home_office", "Firewall"):          1.0,
    ("home_office", "Remote access"):     1.2,
    ("home_office", "Admin"):             1.0,
    ("home_office", "Wi-Fi"):             1.0,
    ("home_office", "Risk correlation"):  1.0,

    # --- small_business: raise operational sections ---
    ("small_business", "Logging"):           1.2,
    ("small_business", "Backup"):            1.3,
    ("small_business", "Firmware"):          1.2,
    ("small_business", "Segmentation"):      1.5,
    ("small_business", "Wireless tuning"):   1.0,
    ("small_business", "Firewall"):          1.3,
    ("small_business", "Remote access"):     1.3,
    ("small_business", "Admin"):             1.3,
    ("small_business", "Wi-Fi"):             1.0,
    ("small_business", "Risk correlation"):  1.2,

    # --- regulated_hipaa: 6-year retention; raise admin/segmentation ---
    ("regulated_hipaa", "Logging"):           2.0,
    ("regulated_hipaa", "Backup"):            1.8,
    ("regulated_hipaa", "Firmware"):          1.5,
    ("regulated_hipaa", "Segmentation"):      2.0,
    ("regulated_hipaa", "Wireless tuning"):   1.2,
    ("regulated_hipaa", "Firewall"):          1.8,
    ("regulated_hipaa", "Remote access"):     1.8,
    ("regulated_hipaa", "Admin"):             2.0,
    ("regulated_hipaa", "Wi-Fi"):             1.2,
    ("regulated_hipaa", "Risk correlation"):  1.5,

    # --- regulated_pci: cornerstone is segmentation + firewall ---
    ("regulated_pci", "Logging"):            1.8,
    ("regulated_pci", "Backup"):             1.8,
    ("regulated_pci", "Firmware"):           1.8,
    ("regulated_pci", "Segmentation"):       2.5,
    ("regulated_pci", "Wireless tuning"):    1.5,
    ("regulated_pci", "Firewall"):           2.5,
    ("regulated_pci", "Remote access"):      2.0,
    ("regulated_pci", "Admin"):              2.5,
    ("regulated_pci", "Wi-Fi"):              2.0,
    ("regulated_pci", "Risk correlation"):   2.0,
}

# Default weight returned for any (profile, section) pair not explicitly in WEIGHTS.
# Using 1.0 means an unknown pair is never amplified or suppressed — neutral.
DEFAULT_WEIGHT: float = 1.0

# Sections also covered by api_coverage meta finding ("Audit scope") — default 1.0 for all
# profiles via DEFAULT_WEIGHT fallthrough; intentional omission from explicit table.

# ---------------------------------------------------------------------------
# Known profiles — used by unifi_audit.py:load_config to reject typos
# ---------------------------------------------------------------------------

KNOWN_PROFILES: frozenset[str] = frozenset({
    "home",
    "home_office",
    "small_business",
    "regulated_hipaa",
    "regulated_pci",
})

# ---------------------------------------------------------------------------
# Impact / effort look-up tables
# ---------------------------------------------------------------------------

IMPACT_SCORES: dict[str, int] = {"high": 3, "medium": 2, "low": 1}
EFFORT_HOURS: dict[str, int] = {"quick": 2, "medium": 8, "project": 40}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_weight(profile: str, section: str) -> float:
    """Return the weight multiplier for a (profile, section) pair.

    Returns ``DEFAULT_WEIGHT`` (1.0) for any pair not present in ``WEIGHTS``.
    This includes unknown profiles and unknown sections — callers never need to
    guard against KeyError.

    Args:
        profile: Operator profile string (e.g. ``"home_office"``).
        section: Finding section string (e.g. ``"Logging"``).

    Returns:
        Float multiplier.  Always > 0.
    """
    return WEIGHTS.get((profile, section), DEFAULT_WEIGHT)


def score_finding(finding: object, profile: str) -> float:
    """Compute the prioritisation score for a Finding under a profile.

    Higher score means higher rank (sort descending in ``analyze()``).

    Formula::

        score = (impact_score * profile_weight) / effort_hours

    Args:
        finding: Any object with ``.impact``, ``.effort``, and ``.section``
                 string attributes (duck-typed — no hard Finding import here).
                 Missing or unrecognised attribute values fall back to medium
                 defaults so this function never raises.
        profile: Operator profile string.  Unknown profiles produce
                 ``DEFAULT_WEIGHT`` via ``get_weight``.

    Returns:
        Float score; never raises on unknown impact / effort / profile / section.
    """
    impact = IMPACT_SCORES.get(getattr(finding, "impact", "medium"), 2)
    effort = EFFORT_HOURS.get(getattr(finding, "effort", "medium"), 8)
    weight = get_weight(profile, getattr(finding, "section", ""))
    return (impact * weight) / effort
