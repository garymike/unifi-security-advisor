"""Smoke script invoked by Plan 03 Task 2's verify command."""
import sys
import logging
sys.path.insert(0, "src")
import unifi_audit

# Verify _correlate_findings exists
assert hasattr(unifi_audit, "_correlate_findings"), "_correlate_findings not added to unifi_audit"

# Construct a findings list that triggers correlate_pivot_path
flat = unifi_audit.Finding(
    id="SEG-001-default", section="Segmentation", severity="high", status="gap",
    title="Flat network", current_state="...",
)
logger = logging.getLogger("test")
logger.addHandler(logging.NullHandler())
new = unifi_audit._correlate_findings([flat], "home_office", logger)
assert any(f.id == "CORR-PIVOT-001" for f in new), \
    f"Expected CORR-PIVOT-001, got {[f.id for f in new]}"
print(f"OK — correlation produced: {[f.id for f in new]}")
