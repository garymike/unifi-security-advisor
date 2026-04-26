"""
Compound finding rules for the cross-answer tension detection pass.

D-003 LOCKED implementation; module location per D-04.
These are pure functions over list[Finding] — one rule per compound risk.
Each rule takes (findings: list, profile: str) and returns Finding | None.

Rules run AFTER individual finding modules (baseline + enhanced), BEFORE the
final severity sort in analyze(). A failing rule does not abort the audit
(caller wraps each rule in try/except).

Source: D-003 (LOCKED); decision log .planning/intel/decisions.md
"""
from __future__ import annotations

from typing import Any


def _has_finding_id(findings: list, prefix: str) -> bool:
    """Return True if any finding's id starts with the given prefix.

    Args:
        findings: List of Finding objects.
        prefix: ID prefix to search for (e.g. ``"SEG-001"``).

    Returns:
        True if at least one finding's id starts with prefix.
    """
    return any(f.id.startswith(prefix) for f in findings)


def _get_finding(findings: list, prefix: str) -> Any | None:
    """Return the first finding whose id starts with prefix, or None.

    Args:
        findings: List of Finding objects.
        prefix: ID prefix to search for.

    Returns:
        First matching Finding, or None if not found.
    """
    return next((f for f in findings if f.id.startswith(prefix)), None)


def correlate_priority_mismatch(findings: list, profile: str) -> Any | None:
    """Compound: port-forwards present + no VPN configured = exposure-as-remote-access path.

    Fires when: port-forward findings (FW-*) exist AND VPN-missing findings
    (VPN-MISSING-*) exist. In Phase 1 this is the conservative proxy for the
    downtime-sensitivity / single-WAN condition — additional questionnaire data
    is not available from the API alone.

    Args:
        findings: Current list of Finding objects produced by individual modules.
        profile: Audit profile string (e.g. ``"home_office"``). Accepted for
            uniform signature; not used in Phase 1.

    Returns:
        A CORR-PRIORITY-001 Finding if the trigger condition is met, else None.
    """
    has_pf = _has_finding_id(findings, "FW-") and _has_finding_id(findings, "VPN-MISSING")
    if not has_pf:
        return None
    from unifi_audit import Finding
    return Finding(
        id="CORR-PRIORITY-001",
        section="Risk correlation",
        severity="high",
        status="recommendation",
        title="Port-forwards without VPN suggest exposure-as-remote-access path",
        current_state=(
            "Port forwards are active and no VPN is configured. If any forward is for "
            "your own remote access (not a public service), this exposes services "
            "unnecessarily. Combined with high network availability needs, this is a "
            "compounded risk."
        ),
        recommendation=(
            "Set up WireGuard VPN and replace remote-access port forwards. "
            "Reserve port forwards for services that must be publicly accessible."
        ),
        intent_question="Are port forwards for your own remote access, or for public-facing services?",
        maps_to={"cis_v8": "4.4", "nist_csf": "PR.AC-3"},
        effort="medium",
        impact="high",
    )


def correlate_keys_to_kingdom(findings: list, profile: str) -> Any | None:
    """Compound: remote access exposed + MFA status unknown = keys-to-kingdom risk.

    Fires when: MFA-unknown finding (MFA-*) is present AND remote access is
    exposed (either VPN-MISSING-* or FW-*). If an attacker reaches a management
    interface and admin accounts lack MFA, they have a path to full network control.

    Args:
        findings: Current list of Finding objects produced by individual modules.
        profile: Audit profile string. Accepted for uniform signature; not used.

    Returns:
        A CORR-KEYS-001 Finding if the trigger condition is met, else None.
    """
    mfa_unknown = _has_finding_id(findings, "MFA-")
    remote_exposed = _has_finding_id(findings, "VPN-MISSING") or _has_finding_id(findings, "FW-")
    if not (mfa_unknown and remote_exposed):
        return None
    from unifi_audit import Finding
    return Finding(
        id="CORR-KEYS-001",
        section="Risk correlation",
        severity="critical",
        status="unknown",
        title="Remote access exposed + MFA status unknown = keys-to-kingdom risk",
        current_state=(
            "Services are reachable from the internet and admin MFA status cannot be "
            "confirmed from the API. If admin accounts lack MFA, an attacker who "
            "reaches a management interface has a path to full network control."
        ),
        recommendation=(
            "1. Confirm MFA is enabled on all admin accounts (see Ubiquiti account settings). "
            "2. If admin UIs are reachable from WAN, restrict to VPN-only. "
            "3. Enable MFA now if not already configured."
        ),
        intent_question="Is MFA enabled on all accounts with admin access to this network?",
        maps_to={"cis_v8": "6.3", "nist_csf": "PR.AC-7"},
        effort="quick",
        impact="high",
    )


def correlate_pivot_path(findings: list, profile: str) -> Any | None:
    """Compound: flat network (SEG-001) present = lateral pivot path risk.

    Fires when: a flat-network finding (SEG-001-*) is present. Without VLAN
    segmentation a compromised IoT device can reach NAS or work machines directly.

    Args:
        findings: Current list of Finding objects produced by individual modules.
        profile: Audit profile string. Accepted for uniform signature; not used.

    Returns:
        A CORR-PIVOT-001 Finding if the trigger condition is met, else None.
    """
    flat_net = _has_finding_id(findings, "SEG-001")
    if not flat_net:
        return None
    from unifi_audit import Finding
    return Finding(
        id="CORR-PIVOT-001",
        section="Risk correlation",
        severity="high",
        status="unknown",
        title="Flat network with likely mixed device classes — pivot path risk",
        current_state=(
            "The network has no VLAN segmentation. If NAS devices, IoT devices, or "
            "work machines share the same broadcast domain, a compromised IoT device "
            "can reach your data directly."
        ),
        recommendation=(
            "Segment IoT, NAS/file-share, and work devices into separate VLANs with "
            "Zone-Based Firewall rules. IoT VLAN should not be able to reach NAS VLAN."
        ),
        intent_question="Do IoT devices (cameras, smart home) share the same network as your NAS or work computers?",
        maps_to={"cis_v8": "12.2", "nist_csf": "PR.AC-5"},
        effort="project",
        impact="high",
    )


# Registry: add new compound rules here.
# _correlate_findings() in unifi_audit.py iterates this list; each rule is
# called with (findings, profile) and wrapped in try/except.
CORRELATION_RULES = [
    correlate_priority_mismatch,
    correlate_keys_to_kingdom,
    correlate_pivot_path,
]
