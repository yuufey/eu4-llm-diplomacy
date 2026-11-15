"""Boundary tests for the defender tier projection DTO."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.religion_defender import NativeReligionDefenderSource
from bridge.tests import test_information_religion_defender_source as source_fixture


KNOWN_TIER = {
    "status": "known",
    "level": 3,
    "same_faith_country_count": 17,
    "range_from": 0,
    "range_to_exclusive": None,
}
UNKNOWN_TIER = {
    "status": "unknown",
    "reason": "RELIGION_DEFENDER_TIER_UNAVAILABLE",
}


def _value(tier=None):
    return {
        "defender_country": "FRA",
        "is_target_defender": False,
        "tier": deepcopy(KNOWN_TIER if tier is None else tier),
    }


@pytest.mark.parametrize(("count", "start", "upper"), [
    (0, 0, None),
    (2048, -2147483648, 2147483647),
])
def test_known_tier_accepts_inclusive_start_open_or_exclusive_upper(
        count, start, upper):
    tier = {
        "status": "known",
        "level": -2147483648,
        "same_faith_country_count": count,
        "range_from": start,
        "range_to_exclusive": upper,
    }

    projected = NativeReligionDefenderSource._public_value(_value(tier), "ENG")

    assert projected["tier"] == tier
    assert set(projected) == {"defender_country", "is_target_defender", "tier"}


def test_unknown_tier_is_an_exact_safe_projection_and_deep_copy():
    original = _value(UNKNOWN_TIER)

    projected = NativeReligionDefenderSource._public_value(original, "ENG")
    projected["tier"]["reason"] = "caller mutation"

    assert original["tier"] == UNKNOWN_TIER
    assert projected["tier"] != original["tier"]


def test_known_holder_stays_known_partial_when_tier_is_unknown(tmp_path, monkeypatch):
    report = source_fixture._defender_report("ENG", tier=UNKNOWN_TIER)
    source, base, _, _, _ = source_fixture._make_source(
        tmp_path, monkeypatch, target="ENG", report=report,
    )

    result = source.read(source_fixture._defender_query("ENG"), base.context())
    field = result["fields"]["defender"]

    assert field["status"] == "known"
    assert field["partial"] is True and field["complete"] is False
    assert field["value"]["defender_country"] == "FRA"
    assert field["value"]["is_target_defender"] is False
    assert field["value"]["tier"] == UNKNOWN_TIER
    assert "value" in field


@pytest.mark.parametrize("tier", [
    {"status": "unknown", "reason": "PRIVATE_POINTER_0x123456789abcdef0"},
    {"status": "unknown", "reason": "RELIGION_DEFENDER_TIER_UNAVAILABLE", "address": "0x1234"},
    {"status": "unknown"},
])
def test_unknown_tier_requires_exact_fixed_reason(tier):
    with pytest.raises(ValueError):
        NativeReligionDefenderSource._public_value(_value(tier), "ENG")


@pytest.mark.parametrize("tier", [
    {"status": "known", "level": 3, "same_faith_country_count": 17,
     "range_from": 0},
    {**KNOWN_TIER, "status": "partial"},
])
def test_known_tier_requires_exact_shape_and_status(tier):
    with pytest.raises(ValueError):
        NativeReligionDefenderSource._public_value(_value(tier), "ENG")


def test_legacy_holder_value_without_tier_is_rejected():
    value = _value()
    del value["tier"]

    with pytest.raises(ValueError):
        NativeReligionDefenderSource._public_value(value, "ENG")


@pytest.mark.parametrize(("key", "bad_value"), [
    ("level", True),
    ("level", 2147483648),
    ("level", -2147483649),
    ("same_faith_country_count", True),
    ("same_faith_country_count", -1),
    ("same_faith_country_count", 2049),
    ("range_from", False),
    ("range_from", 2147483648),
    ("range_to_exclusive", False),
    ("range_to_exclusive", 0),
    ("range_to_exclusive", 2147483648),
])
def test_tier_signed_integer_and_count_bounds_reject_invalid_values(key, bad_value):
    tier = deepcopy(KNOWN_TIER)
    tier[key] = bad_value

    with pytest.raises(ValueError):
        NativeReligionDefenderSource._public_value(_value(tier), "ENG")


@pytest.mark.parametrize(("count", "start", "upper"), [
    (2, 3, 5),
    (5, 0, 5),
    (0, 1, None),
])
def test_tier_interval_must_include_same_faith_country_count(count, start, upper):
    tier = {
        "status": "known",
        "level": 1,
        "same_faith_country_count": count,
        "range_from": start,
        "range_to_exclusive": upper,
    }

    with pytest.raises(ValueError):
        NativeReligionDefenderSource._public_value(_value(tier), "ENG")


def test_known_tier_does_not_leak_extra_address_fields():
    value = _value()
    value["tier"]["native_address"] = "0x123456789abcdef0"

    with pytest.raises(ValueError):
        NativeReligionDefenderSource._public_value(value, "ENG")
