import struct

import pytest

from bridge.information import opinion_decay_memory as m
from bridge.information.opinion_decay import GAPS, NativeOpinionDecaySource
from bridge.tests import test_information_opinion_modifiers_memory as fixture_memory


@pytest.mark.parametrize("current,suppressed", [(-999, 0), (0, 1), (999, 1)])
def test_values_truncated_to_zero_are_known_before_suppression_or_factor(current, suppressed):
    result = m.yearly_contribution(
        current,
        1250,
        suppressed,
        {"status": "unknown", "reason": "OPINION_DECAY_FACTOR_UNKNOWN"},
    )
    assert result == {
        "status": "known",
        "raw": 0,
        "basis": "tooltip_current_value_truncated_to_zero",
    }


def test_negative_small_value_does_not_read_country_or_pair_factor(monkeypatch):
    reader, _, target = fixture_memory.fixture()
    definition = bytearray(reader.segments[fixture_memory.DEFINITION])
    definition.extend(b"\0" * (0x5C - len(definition)))
    struct.pack_into("<i", definition, 0x58, 1250)
    reader.segments[fixture_memory.DEFINITION] = definition
    reader.patch(fixture_memory.OBJECT + 0x20, struct.pack("<i", -999))

    def unexpected_factor_read(*args, **kwargs):
        raise AssertionError("sub-unit current value must skip country and pair readers")

    monkeypatch.setattr(m, "_country_factor", unexpected_factor_read)
    row = m._snapshot(
        reader,
        fixture_memory.BASE,
        fixture_memory.OBJECT,
        0,
        int(target["country_pointer"], 0),
        target["slot"],
    )
    assert row["status"] == "known"
    assert row["factor"] == {"status": "not_required"}
    assert row["current_opinion_raw"] == -999


@pytest.mark.parametrize(
    "current,factor,expected_status,expected_raw",
    [
        (-1000, {"status": "unknown", "reason": "OPINION_DECAY_FACTOR_UNKNOWN"}, "unknown", None),
        (-1000, {"status": "known", "country_modifier_raw": 0, "pair_modifier_raw": 0}, "known", 1000),
        (1000, {"status": "not_required"}, "known", -1000),
    ],
)
def test_exactly_one_point_boundary_keeps_the_existing_large_value_path(
    current, factor, expected_status, expected_raw
):
    result = m.yearly_contribution(current, 1000, 0, factor)
    assert result["status"] == expected_status
    if expected_raw is None:
        assert result["reason"] == "OPINION_DECAY_FACTOR_UNKNOWN"
    else:
        assert result["raw"] == expected_raw
        assert result["basis"] == "derived_native_tooltip_yearly_contribution"


@pytest.mark.parametrize(
    "current,base_yearly,factor,expected_raw",
    [
        (-50000, 2000, {"status": "known", "country_modifier_raw": 250, "pair_modifier_raw": 0}, 2500),
        (9000, 1000, {"status": "not_required"}, -1000),
    ],
)
def test_magnitudes_outside_the_gate_preserve_existing_projection(
    current, base_yearly, factor, expected_raw
):
    result = m.yearly_contribution(current, base_yearly, 0, factor)
    assert result == {
        "status": "known",
        "raw": expected_raw,
        "basis": "derived_native_tooltip_yearly_contribution",
    }


def test_default_leaf_uses_v4_profile_loader_version_and_gap_list():
    assert m.PROFILE_FILE.name == "opinion-decay-memory-1374-v5-sampling-r1.json"
    assert m.PROFILE_ID == "opinion-decay-memory-1374-v5"
    assert m.SCHEMA == "information.opinion_decay_capture.v4"
    profile = m._load_profile()
    assert profile["profile_id"] == m.PROFILE_ID
    assert profile["profile_version"] == 5
    assert "SMALL_VALUE_CALLER_GATE_UNRESOLVED" not in GAPS
    assert "SMALL_VALUE_CALLER_GATE_UNRESOLVED" not in (
        NativeOpinionDecaySource(object()).catalog()[0]["fields"]["decay"]["gaps"]
    )
