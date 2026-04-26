"""Smoke script invoked by Plan 04 Task 1's verify command."""
import sys
import logging
sys.path.insert(0, "src")
import unifi_audit

# Constant exists with 6 entries
assert isinstance(unifi_audit.ALWAYS_TOP_FINDING_IDS, frozenset)
expected = {"VPN-PPTP-001", "SEG-001", "FW-EOL-001",
            "MFA-UNKNOWN-001", "CRED-DEFAULT-001", "WAN-MGMT-001"}
assert unifi_audit.ALWAYS_TOP_FINDING_IDS == expected, \
    f"ALWAYS_TOP_FINDING_IDS mismatch: {unifi_audit.ALWAYS_TOP_FINDING_IDS}"

# 3 unknowns
unknowns = unifi_audit._emit_unknown_always_top()
assert len(unknowns) == 3
assert {u.id for u in unknowns} == {"MFA-UNKNOWN-001", "CRED-DEFAULT-001", "WAN-MGMT-001"}
assert all(u.status == "unknown" for u in unknowns)
assert all(u.intent_question for u in unknowns)

# _apply_float_top
F = unifi_audit.Finding
sample = [
    F(id="WIFI-x", section="W", severity="low", status="gap", title="t", current_state="c"),
    F(id="SEG-001-default", section="S", severity="high", status="gap", title="t", current_state="c"),
    F(id="LOG-1", section="L", severity="info", status="gap", title="t", current_state="c"),
    F(id="VPN-PPTP-001", section="R", severity="critical", status="gap", title="t", current_state="c"),
]
reordered = unifi_audit._apply_float_top(sample)
assert reordered[0].id == "SEG-001-default", f"first: {reordered[0].id}"
assert reordered[1].id == "VPN-PPTP-001", f"second: {reordered[1].id}"
print("OK — float_top smoke")
