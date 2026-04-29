import sys, os, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models import Finding
import unifi_audit

_logger = logging.getLogger("test")
_logger.addHandler(logging.NullHandler())

def _make_finding(fid, severity="medium"):
    return Finding(
        id=fid, section="Test", severity=severity,
        status="gap", title=fid, current_state="x",
    )

def test_pptp_finding_floats_above_medium():
    pptp = _make_finding("VPN-PPTP-001", "critical")
    medium = _make_finding("SOME-OTHER-001", "medium")
    result = unifi_audit._sort_findings([medium, pptp])
    assert result[0].id == "VPN-PPTP-001"

def test_seg001_floats_above_low():
    seg = _make_finding("SEG-001-default", "high")
    low = _make_finding("WIFI-x-WPA", "low")
    result = unifi_audit._sort_findings([low, seg])
    assert result[0].id == "SEG-001-default"

def test_non_float_top_sorted_by_severity():
    high = _make_finding("HIGH-001", "high")
    low = _make_finding("LOW-001", "low")
    medium = _make_finding("MED-001", "medium")
    result = unifi_audit._sort_findings([low, medium, high])
    assert [f.id for f in result] == ["HIGH-001", "MED-001", "LOW-001"]

def test_two_float_top_sorted_among_themselves():
    pptp = _make_finding("VPN-PPTP-001", "critical")
    seg = _make_finding("SEG-001-x", "high")
    low = _make_finding("LOW-001", "low")
    result = unifi_audit._sort_findings([low, seg, pptp])
    ids = [f.id for f in result]
    assert ids[0] == "VPN-PPTP-001"
    assert ids[1] == "SEG-001-x"
    assert ids[2] == "LOW-001"

def test_mfa_finding_floats():
    mfa = _make_finding("MFA-ADMIN-001", "critical")
    low = _make_finding("LOW-001", "low")
    result = unifi_audit._sort_findings([low, mfa])
    assert result[0].id == "MFA-ADMIN-001"

def test_seg_mgmt_wan_floats():
    mgmt = _make_finding("SEG-MGMT-WAN", "high")
    low = _make_finding("LOW-001", "low")
    result = unifi_audit._sort_findings([low, mgmt])
    assert result[0].id == "SEG-MGMT-WAN"

def test_cred_default_floats():
    cred = _make_finding("CRED-DEFAULT-001", "high")
    low = _make_finding("LOW-001", "low")
    result = unifi_audit._sort_findings([low, cred])
    assert result[0].id == "CRED-DEFAULT-001"

def test_fw_eol_high_floats():
    eol = _make_finding("FW-EOL-001", "high")
    low = _make_finding("LOW-001", "low")
    result = unifi_audit._sort_findings([low, eol])
    assert result[0].id == "FW-EOL-001"

def test_fw_eol_critical_floats():
    eol = _make_finding("FW-EOL-001", "critical")
    low = _make_finding("LOW-001", "low")
    result = unifi_audit._sort_findings([low, eol])
    assert result[0].id == "FW-EOL-001"

def test_home_profile_log_fwd_is_low():
    f = _make_finding("LOG-FWD-001", "medium")
    result = unifi_audit._apply_profile_overrides([f], "home")
    assert result[0].severity == "low"

def test_regulated_hipaa_log_fwd_is_high():
    f = _make_finding("LOG-FWD-001", "medium")
    result = unifi_audit._apply_profile_overrides([f], "regulated_hipaa")
    assert result[0].severity == "high"

def test_regulated_hipaa_bak001_is_critical():
    f = _make_finding("BAK-001", "high")
    result = unifi_audit._apply_profile_overrides([f], "regulated_hipaa")
    assert result[0].severity == "critical"

def test_unknown_finding_id_unchanged():
    f = _make_finding("SOME-UNKNOWN-999", "medium")
    result = unifi_audit._apply_profile_overrides([f], "regulated_hipaa")
    assert result[0].severity == "medium"

def test_unknown_profile_unchanged():
    f = _make_finding("LOG-FWD-001", "medium")
    result = unifi_audit._apply_profile_overrides([f], "nonexistent_profile")
    assert result[0].severity == "medium"
