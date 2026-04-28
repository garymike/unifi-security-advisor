import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from normalize import normalize_api, NormalizedSite, _extract_list

CLEAN_ONE_SITE = {
    "_endpoints_probed": [], "_errors": [], "_site_count": 1,
    "site_default": {
        "_meta": {"desc": "Home", "name": "default"},
        "devices":          {"data": [{"mac": "aa:bb:cc", "type": "ugw"}]},
        "clients":          {"data": []},
        "wlans":            {"data": [{"name": "HomeNet", "enabled": True}]},
        "networks":         {"data": [{"name": "LAN", "purpose": "corporate"}]},
        "port_forwards":    {"data": []},
        "vpn_configs":      {"data": []},
        "firewall_policies":{"data": []},
        "firewall_zones":   {"data": []},
        "traffic_routes":   {"data": []},
    },
}

def test_returns_one_site():
    assert len(normalize_api(CLEAN_ONE_SITE, "home_office")) == 1

def test_site_id():
    assert normalize_api(CLEAN_ONE_SITE, "home_office")[0].site_id == "default"

def test_site_name_from_desc():
    assert normalize_api(CLEAN_ONE_SITE, "home_office")[0].site_name == "Home"

def test_wlans_unpacked():
    site = normalize_api(CLEAN_ONE_SITE, "home_office")[0]
    assert len(site.wlans) == 1
    assert site.wlans[0]["name"] == "HomeNet"

def test_devices_unpacked():
    site = normalize_api(CLEAN_ONE_SITE, "home_office")[0]
    assert site.devices[0]["mac"] == "aa:bb:cc"

def test_empty_input():
    assert normalize_api({}, "home") == []

def test_profile_set():
    site = normalize_api(CLEAN_ONE_SITE, "regulated_hipaa")[0]
    assert site.profile == "regulated_hipaa"

def test_api_gaps_tracks_missing_collections():
    clean = {"site_s1": {"_meta": {"name": "s1"}, "devices": {"data": []}}}
    site = normalize_api(clean, "home")[0]
    assert "wlans" in site.api_gaps
    assert "devices" not in site.api_gaps

def test_settings_empty_in_api_mode():
    site = normalize_api(CLEAN_ONE_SITE, "home")[0]
    assert site.settings == {}

def test_extract_list_data_key():
    assert _extract_list({"data": [1, 2]}) == [1, 2]

def test_extract_list_plain_list():
    assert _extract_list([1, 2]) == [1, 2]

def test_extract_list_none():
    assert _extract_list(None) == []

def test_extract_list_items_key():
    assert _extract_list({"items": ["a", "b"]}) == ["a", "b"]
