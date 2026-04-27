import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from normalize import NormalizedSite
from findings_enhanced import find_wireless_tuning, find_remote_access

def _site(**kwargs) -> NormalizedSite:
    """Build a minimal NormalizedSite for testing."""
    defaults = dict(
        site_id="test", site_name="Test",
        devices=[], clients=[], wlans=[], networks=[],
        port_forwards=[], vpn_configs=[], firewall_policies=[],
        firewall_zones=[], traffic_routes=[], settings={},
        profile="home_office", api_gaps=[],
    )
    defaults.update(kwargs)
    return NormalizedSite(**defaults)


# --- find_wireless_tuning ---

def test_high_tx_power_emits_finding():
    site = _site(devices=[{
        "type": "uap", "mac": "aa:bb:cc", "name": "AP1",
        "radio_table": [{"radio": "na", "tx_power_mode": "high"}],
    }])
    findings = find_wireless_tuning(site)
    ids = [f.id for f in findings]
    assert "RF-aa:bb:cc-na-TX" in ids

def test_auto_tx_power_no_finding():
    site = _site(devices=[{
        "type": "uap", "mac": "aa:bb:cc", "name": "AP1",
        "radio_table": [{"radio": "na", "tx_power_mode": "auto"}],
    }])
    findings = find_wireless_tuning(site)
    assert not any(f.id.endswith("-TX") for f in findings)

def test_24ghz_active_emits_finding():
    site = _site(
        devices=[{"type": "uap", "mac": "aa", "radio_table": [{"radio": "ng"}]}],
        clients=[{"radio": "ng"}, {"radio": "na"}],
    )
    ids = [f.id for f in find_wireless_tuning(site)]
    assert "RF-BAND-24GHZ" in ids

def test_rogueap_unknown_when_no_settings():
    site = _site()  # settings={}
    findings = find_wireless_tuning(site)
    rogue = [f for f in findings if f.id == "RF-ROGUE-001"]
    assert rogue
    assert rogue[0].status == "unknown"

def test_rogueap_gap_when_disabled_in_settings():
    site = _site(settings={"rogueap": {"report_rogue": False}})
    findings = find_wireless_tuning(site)
    rogue = [f for f in findings if f.id == "RF-ROGUE-001"]
    assert rogue
    assert rogue[0].status == "gap"

def test_wpa3_without_pmf_emits_finding():
    site = _site(wlans=[{
        "name": "Secure", "enabled": True,
        "wpa_mode": "wpa3", "pmf_mode": "disabled",
    }])
    ids = [f.id for f in find_wireless_tuning(site)]
    assert "RF-PMF-Secure" in ids

def test_wpa3_with_pmf_required_no_finding():
    site = _site(wlans=[{
        "name": "Secure", "enabled": True,
        "wpa_mode": "wpa3", "pmf_mode": "required",
    }])
    ids = [f.id for f in find_wireless_tuning(site)]
    assert "RF-PMF-Secure" not in ids


# --- find_remote_access ---

def test_pptp_vpn_emits_critical():
    site = _site(vpn_configs=[{"type": "pptp", "enabled": True}])
    findings = find_remote_access(site)
    pptp = [f for f in findings if f.id == "VPN-PPTP-001"]
    assert pptp
    assert pptp[0].severity == "critical"

def test_wireguard_emits_ok():
    site = _site(vpn_configs=[{"type": "wireguard", "enabled": True}])
    ids = {f.id: f for f in find_remote_access(site)}
    assert "VPN-WG-OK" in ids
    assert ids["VPN-WG-OK"].status == "ok"

def test_port_forwards_no_vpn_emits_high():
    site = _site(
        port_forwards=[{"enabled": True, "dst_port": "22"}],
        vpn_configs=[],
    )
    findings = find_remote_access(site)
    missing = [f for f in findings if f.id == "VPN-MISSING-001"]
    assert missing
    assert missing[0].severity == "high"

def test_port_forwards_with_wireguard_no_missing_vpn_finding():
    site = _site(
        port_forwards=[{"enabled": True, "dst_port": "80"}],
        vpn_configs=[{"type": "wireguard", "enabled": True}],
    )
    ids = [f.id for f in find_remote_access(site)]
    assert "VPN-MISSING-001" not in ids

def test_l2tp_only_emits_recommendation():
    site = _site(vpn_configs=[{"type": "l2tp", "enabled": True}])
    findings = find_remote_access(site)
    l2tp = [f for f in findings if f.id == "VPN-L2TP-001"]
    assert l2tp
    assert l2tp[0].severity == "medium"

def test_l2tp_plus_wireguard_no_l2tp_finding():
    site = _site(vpn_configs=[
        {"type": "l2tp", "enabled": True},
        {"type": "wireguard", "enabled": True},
    ])
    ids = [f.id for f in find_remote_access(site)]
    assert "VPN-L2TP-001" not in ids


def test_rogueap_no_finding_when_enabled_in_settings():
    site = _site(settings={"rogueap": {"report_rogue": True}})
    findings = find_wireless_tuning(site)
    rogue = [f for f in findings if f.id == "RF-ROGUE-001"]
    assert not rogue

def test_wlan_without_enabled_key_treated_as_active():
    # enabled key absent → default True → WLAN is processed
    site = _site(wlans=[{
        "name": "NoFlag", "wpa_mode": "wpa3", "pmf_mode": "disabled",
        # no "enabled" key
    }])
    ids = [f.id for f in find_wireless_tuning(site)]
    assert "RF-PMF-NoFlag" in ids
