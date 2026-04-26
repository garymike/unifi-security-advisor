"""_extract_list and _extract_sites shape-variant coverage."""
from __future__ import annotations

import logging

import pytest

from unifi_audit import _extract_list, _extract_sites


@pytest.mark.parametrize("envelope_key", ["data", "items", "results"])
def test_extract_list_handles_known_envelopes(envelope_key):
    response = {envelope_key: [{"a": 1}, {"b": 2}]}
    assert _extract_list(response) == [{"a": 1}, {"b": 2}]


def test_extract_list_bare_list():
    assert _extract_list([{"a": 1}]) == [{"a": 1}]


def test_extract_list_none_returns_none():
    assert _extract_list(None) is None


def test_extract_list_unknown_shape_logs_warning(caplog):
    caplog.set_level(logging.WARNING, logger="unifi_audit")
    result = _extract_list({"foobar": [{"a": 1}]})
    assert result is None
    assert any("Keys present" in rec.message for rec in caplog.records), \
        f"No 'Keys present' warning emitted; records: {[r.message for r in caplog.records]}"


def test_extract_list_empty_dict_no_warning(caplog):
    caplog.set_level(logging.WARNING, logger="unifi_audit")
    result = _extract_list({})
    assert result is None
    # Empty dict should not emit a warning (no keys to report)
    assert not any("Keys present" in rec.message for rec in caplog.records)


@pytest.mark.parametrize("envelope_key", ["data", "sites", "items"])
def test_extract_sites_handles_known_envelopes(envelope_key):
    response = {envelope_key: [{"id": "s1"}, {"id": "s2"}]}
    assert _extract_sites(response) == [{"id": "s1"}, {"id": "s2"}]


def test_extract_sites_bare_list():
    assert _extract_sites([{"id": "s1"}]) == [{"id": "s1"}]


def test_extract_sites_unknown_returns_empty():
    assert _extract_sites({"foobar": []}) == []
    assert _extract_sites(None) == []
    assert _extract_sites("not a dict") == []
