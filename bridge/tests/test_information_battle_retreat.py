"""Fail-closed observer-owned retreat projection tests over v10 wire values."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.battle_retreat import project_retreat
from bridge.tests.test_information_battle_end_state_projection import (
    _known_v9,
    _raw_naval_base8,
)
from bridge.tests.test_information_battle_end_state_wire import _base7, _known
from work import information_battle_end_state_wire as end_state_wire
from work import information_battle_retreat_wire as retreat_wire


def _ref(tag: str, generation: int = 0) -> int:
    return int.from_bytes(
        tag.encode("ascii") + generation.to_bytes(5, "little"), "little",
    )


def _base(kind: int) -> bytes:
    if kind == 1:
        return _base7()
    if kind == 2:
        return _raw_naval_base8()
    raise ValueError("unsupported test kind")


def _wire10(*, kind: int = 1, gates=(0, 0), units=None,
            initial_unit_count: int | None = None,
            end_state: str = "known", capture_source: str | None = None):
    base = _base(kind)
    if end_state == "known":
        base_v9 = _known_v9(base, gates)
    elif end_state == "unknown":
        base_v9 = end_state_wire.encode(base, {"state": "unknown"})
    else:
        raise ValueError("unsupported test end-state")
    decoded_v9 = end_state_wire.decode(base_v9)
    context = decoded_v9["context"]
    observation = decoded_v9["observation"]
    winner = observation["summary"]["control_byte"]
    loser = 1 - winner
    observer_ref = context["sides"][loser]["participants"]["full_refs"][0]
    if units is None:
        units = [{
            "ordinal": 0,
            "owner_full_ref": observer_ref,
            "raw_flags": [0, 1, 1, 255],
        }]
    else:
        units = deepcopy(units)
        opponent_ref = context["sides"][1 - loser]["participants"]["full_refs"][0]
        for unit in units:
            if unit.get("owner_full_ref") == "$observer":
                unit["owner_full_ref"] = observer_ref
            elif unit.get("owner_full_ref") == "$opponent":
                unit["owner_full_ref"] = opponent_ref
    if initial_unit_count is None:
        initial_unit_count = max((unit["ordinal"] + 1 for unit in units), default=0)
    snapshot = {
        "state": "known",
        "sequence": observation["sequence"],
        "raw_date": observation["result"]["raw_date"],
        "kind": context["kind"],
        "losing_combat_side": loser,
        "initial_unit_count": initial_unit_count,
        "units": units,
    }
    if capture_source is not None:
        snapshot['capture_source'] = capture_source
    decoded = retreat_wire.decode(retreat_wire.encode(base_v9, snapshot))
    refs_by_side = [side["participants"]["full_refs"] for side in context["sides"]]
    mapping = [
        next(index for index, refs in enumerate(refs_by_side)
             if side["country"] in refs)
        for side in observation["result"]["sides"]
    ]
    return decoded, mapping, observer_ref, loser


def _known_value(*, observer: str, side: int, count: int) -> dict:
    return {
        "observer": observer,
        "combat_side_index": side,
        "retreating": True,
        "observed_unit_count": count,
        "count_is_lower_bound": True,
        "unit": "native_army_or_fleet_objects",
        "scope": "observer_owned_units_at_regular_battle_end",
        "identity_scope": "captured_operation_not_persistent_unit_id",
        "destinations": {
            "status": "unknown", "reason": "RETREAT_DESTINATION_NOT_CAPTURED",
            "partial": True, "complete": False,
        },
        "arrival": {
            "status": "unknown", "reason": "RETREAT_ARRIVAL_NOT_CAPTURED",
            "partial": True, "complete": False,
        },
    }


def _all_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _all_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _all_keys(child)


@pytest.mark.parametrize(("kind", "observer_tag"), [(1, "FRA"), (2, "ATJ")])
def test_land_and_naval_project_only_positive_observer_owned_state(kind, observer_tag):
    decoded, mapping, observer_ref, loser = _wire10(kind=kind)
    before = deepcopy(decoded)

    result = project_retreat(decoded, mapping, observer_ref)

    assert decoded == before
    assert result == {
        "status": "known",
        "value": _known_value(observer=observer_tag, side=loser, count=1),
        "partial": True,
        "complete": False,
    }
    assert observer_tag not in repr(result["value"]["destinations"])
    assert not ({"owner_full_ref", "raw_flags", "ordinal",
                 "initial_unit_count", "units"} & set(_all_keys(result)))


def test_foreign_unit_flag_bytes_do_not_change_own_value_and_205_is_not_interpreted():
    low_flags = [0, 0, 0, 0]
    high_flags = [255, 255, 255, 255]
    outputs = []
    for foreign_flags in (low_flags, high_flags):
        decoded, mapping, observer_ref, loser = _wire10(units=[
            {"ordinal": 0, "owner_full_ref": "$observer",
             "raw_flags": [0, 1, 1, foreign_flags[3]]},
            {"ordinal": 1, "owner_full_ref": "$opponent",
             "raw_flags": foreign_flags},
        ], initial_unit_count=2)
        outputs.append(project_retreat(decoded, mapping, observer_ref))
        assert outputs[-1]["status"] == "known"
        assert outputs[-1]["value"]["observed_unit_count"] == 1
        assert outputs[-1]["value"]["combat_side_index"] == loser
    assert outputs[0] == outputs[1]


def test_same_side_ally_is_not_counted_as_observer_owned_unit():
    decoded, mapping, observer_ref, loser = _wire10(units=[
        {"ordinal": 0, "owner_full_ref": "$observer", "raw_flags": [0, 1, 1, 0]},
        {"ordinal": 1, "owner_full_ref": _ref("ENG", 23), "raw_flags": [0, 1, 1, 0]},
    ], initial_unit_count=2)
    decoded["context"]["sides"][loser]["participants"]["full_refs"].append(
        _ref("ENG", 23),
    )

    result = project_retreat(decoded, mapping, observer_ref)

    assert result["status"] == "known"
    assert result["value"]["observed_unit_count"] == 1
    assert result["value"]["combat_side_index"] == loser
    assert "ENG" not in repr(result)


def test_owner_with_same_tag_but_different_generation_is_not_the_observer():
    decoded, mapping, observer_ref, _loser = _wire10(units=[{
        "ordinal": 0,
        "owner_full_ref": "$observer",
        "raw_flags": [0, 1, 1, 0],
    }], initial_unit_count=1)
    decoded["retreat"]["units"][0]["owner_full_ref"] = observer_ref ^ (1 << 24)

    result = project_retreat(decoded, mapping, observer_ref)

    assert result == {
        "status": "unknown", "reason": "OWN_RETREAT_NOT_OBSERVED",
        "partial": True, "complete": False,
    }


def test_foreign_retreat_returns_constant_before_reading_unit_snapshot():
    decoded, mapping, observer_ref, loser = _wire10()
    winner_side_ref = decoded["context"]["sides"][1 - loser]["participants"]["full_refs"][0]
    decoded["retreat"]["units"] = object()
    decoded["retreat"]["initial_unit_count"] = object()

    result = project_retreat(decoded, mapping, winner_side_ref)

    assert result == {
        "status": "unknown", "reason": "FOREIGN_RETREAT_VISIBILITY_UNVERIFIED",
        "partial": True, "complete": False,
    }


def test_no_own_observations_never_becomes_known_zero_or_false():
    decoded, mapping, observer_ref, _loser = _wire10(
        units=[{"ordinal": 0, "owner_full_ref": _ref("ENG", 2),
                "raw_flags": [0, 1, 1, 0]}],
        initial_unit_count=1,
    )
    result = project_retreat(decoded, mapping, observer_ref)

    assert result == {
        "status": "unknown", "reason": "OWN_RETREAT_NOT_OBSERVED",
        "partial": True, "complete": False,
    }
    assert "value" not in result


def test_inconsistent_own_flags_are_unknown_and_overrun_conflict_is_explicit():
    decoded, mapping, observer_ref, loser = _wire10(units=[{
        "ordinal": 0, "owner_full_ref": "$observer", "raw_flags": [0, 0, 1, 0],
    }], initial_unit_count=1)
    result = project_retreat(decoded, mapping, observer_ref)
    assert result["status"] == "unknown"
    assert result["reason"] == "OWN_RETREAT_STATE_UNVERIFIED"

    conflicting, mapping, observer_ref, loser = _wire10(gates=(0, 1))
    assert conflicting["end_state"]["raw_gates"][loser] == 1
    conflict = project_retreat(conflicting, mapping, observer_ref)
    assert conflict == {
        "status": "unknown", "reason": "RETREAT_OVERRUN_CONFLICT",
        "partial": True, "complete": False,
    }


def test_unknown_end_state_does_not_block_independent_positive_retreat_input():
    decoded, mapping, observer_ref, loser = _wire10(end_state="unknown")

    result = project_retreat(decoded, mapping, observer_ref)

    assert result["status"] == "known"
    assert result["value"]["combat_side_index"] == loser
    assert result["value"]["retreating"] is True


def test_legacy_wire1_through9_without_retreat_stays_unknown():
    base_v9 = _known_v9(_base7(), (0, 1))
    decoded = end_state_wire.decode(base_v9)

    assert "retreat" not in decoded and "wire10" not in decoded
    assert project_retreat(decoded, [1, 0], _ref("FRA")) == {
        "status": "unknown", "reason": "RETREAT_NOT_CAPTURED",
        "partial": True, "complete": False,
    }


@pytest.mark.parametrize(("mutation", "mapping_change"), [
    ("wire_version", None),
    ("wire_base_version", None),
    ("wire9_version", None),
    ("sequence", None),
    ("date", None),
    ("kind", None),
    ("context_kind_bool", None),
    ("participant_incomplete", None),
    ("participant_duplicate", None),
    ("participant_cross_side_duplicate", None),
    ("participant_bad_tag", None),
    ("representative_member", None),
    ("outcome_flag", None),
    (None, [0, 0]),
    (None, [True, 0]),
])
def test_wire_identity_mapping_participant_and_outcome_tampering_is_rejected(
    mutation, mapping_change,
):
    decoded, mapping, observer_ref, _loser = _wire10()
    mapping = mapping if mapping_change is None else mapping_change
    if mutation == "wire_version":
        decoded["wire10"]["version"] = True
    elif mutation == "wire_base_version":
        decoded["wire10"]["base_version"] = 10
    elif mutation == "wire9_version":
        decoded["wire9"]["version"] = 8
    elif mutation == "sequence":
        decoded["retreat"]["sequence"] += 1
    elif mutation == "date":
        decoded["retreat"]["raw_date"] += 1
    elif mutation == "kind":
        decoded["retreat"]["kind"] = 2
    elif mutation == "context_kind_bool":
        decoded["context"]["kind"] = True
    elif mutation == "participant_incomplete":
        decoded["context"]["sides"][1]["participants"]["complete"] = False
    elif mutation == "participant_duplicate":
        refs = decoded["context"]["sides"][1]["participants"]["full_refs"]
        refs.append(refs[0])
    elif mutation == "participant_cross_side_duplicate":
        decoded["context"]["sides"][1]["participants"]["full_refs"].append(
            decoded["context"]["sides"][0]["participants"]["full_refs"][0],
        )
    elif mutation == "participant_bad_tag":
        refs = decoded["context"]["sides"][1]["participants"]["full_refs"]
        refs[0] = int.from_bytes(b"fr!" + b"\0" * 5, "little")
    elif mutation == "representative_member":
        decoded["observation"]["result"]["sides"][0]["country"] = _ref("ZZZ")
    elif mutation == "outcome_flag":
        decoded["observation"]["result"]["flag108"] ^= 1

    result = project_retreat(decoded, mapping, observer_ref)

    assert result["status"] == "unknown"
    assert result["complete"] is False and result["partial"] is True
    assert "value" not in result


@pytest.mark.parametrize("mutation", [
    "initial_count_over_bound", "observed_exceeds_initial", "ordinal_duplicate",
    "ordinal_unsorted", "ordinal_out_of_range", "owner_not_integer",
    "flags_wrong_length", "flag_bool", "flag_out_of_byte",
])
def test_malformed_own_snapshot_is_unknown_without_throwing(mutation):
    decoded, mapping, observer_ref, _loser = _wire10()
    retreat = decoded["retreat"]
    if mutation == "initial_count_over_bound":
        retreat["initial_unit_count"] = 129
    elif mutation == "observed_exceeds_initial":
        retreat["initial_unit_count"] = 0
    elif mutation == "ordinal_duplicate":
        first = deepcopy(retreat["units"][0])
        retreat["units"].append(first)
        retreat["initial_unit_count"] = 2
    elif mutation == "ordinal_unsorted":
        retreat["units"] = [
            {"ordinal": 1, "owner_full_ref": observer_ref, "raw_flags": [0, 1, 1, 0]},
            {"ordinal": 0, "owner_full_ref": observer_ref, "raw_flags": [0, 1, 1, 0]},
        ]
        retreat["initial_unit_count"] = 2
    elif mutation == "ordinal_out_of_range":
        retreat["units"][0]["ordinal"] = retreat["initial_unit_count"]
    elif mutation == "owner_not_integer":
        retreat["units"][0]["owner_full_ref"] = True
    elif mutation == "flags_wrong_length":
        retreat["units"][0]["raw_flags"] = [0, 1, 1]
    elif mutation == "flag_bool":
        retreat["units"][0]["raw_flags"][0] = False
    elif mutation == "flag_out_of_byte":
        retreat["units"][0]["raw_flags"][3] = 256

    result = project_retreat(decoded, mapping, observer_ref)

    assert result["status"] == "unknown"
    assert result["reason"] == "BATTLE_RETREAT_SNAPSHOT_INVALID"
    assert result["complete"] is False and result["partial"] is True


@pytest.mark.parametrize("decoded", [None, [], object(), {}, {"wire10": None}])
def test_malformed_outer_values_do_not_escape_exceptions(decoded):
    result = project_retreat(decoded, [0, 1], _ref("FRA"))
    assert isinstance(result, dict)
    assert result["status"] == "unknown"
    assert result["complete"] is False


@pytest.mark.parametrize('kind', [1, 2])
def test_unit_removal_state_keeps_its_own_source_scope(kind):
    decoded, mapping, observer_ref, _loser = _wire10(kind=kind, capture_source='unit_removal_state')
    projected = project_retreat(decoded, mapping, observer_ref)
    assert projected['status'] == 'known'
    assert projected['value']['scope'] == 'observer_owned_units_before_combat_removal'
    assert projected['value']['retreating'] is True
    assert projected['value']['count_is_lower_bound'] is True
    assert projected['value']['destinations']['status'] == 'unknown'


@pytest.mark.parametrize('source', [None, 'regular', 'other', True])
def test_unit_removal_extension_requires_matching_source(source):
    decoded, mapping, observer_ref, _loser = _wire10(capture_source='unit_removal_state')
    if source is None:
        decoded['retreat'].pop('capture_source')
    else:
        decoded['retreat']['capture_source'] = source
    projected = project_retreat(decoded, mapping, observer_ref)
    assert projected['status'] == 'unknown'
    assert projected['reason'] == 'BATTLE_RETREAT_SOURCE_INVALID'


def test_unit_removal_source_cannot_be_claimed_by_a_v1_envelope():
    decoded, mapping, observer_ref, _loser = _wire10()
    decoded['retreat']['capture_source'] = 'unit_removal_state'
    projected = project_retreat(decoded, mapping, observer_ref)
    assert projected['status'] == 'unknown'
    assert projected['reason'] == 'BATTLE_RETREAT_SOURCE_INVALID'


def test_unit_removal_flags_still_require_verified_retreat_state():
    decoded, mapping, observer_ref, _loser = _wire10(capture_source='unit_removal_state')
    decoded['retreat']['units'][0]['raw_flags'][1] = 0
    projected = project_retreat(decoded, mapping, observer_ref)
    assert projected['status'] == 'unknown'
    assert projected['reason'] == 'OWN_RETREAT_STATE_UNVERIFIED'


@pytest.mark.parametrize('kind', [1, 2])
@pytest.mark.parametrize('observer_side', ['winner', 'loser'])
def test_uncaptured_retreat_is_inapplicable_after_verified_native_overrun(kind, observer_side):
    base = _base(kind)
    initial = end_state_wire.decode(_known_v9(base, (0, 0)))
    winner = initial['observation']['summary']['control_byte']
    loser = 1 - winner
    gates = [0, 0]
    gates[loser] = 1
    decoded = retreat_wire.decode(retreat_wire.encode(
        _known_v9(base, gates), {'state': 'unknown'}))
    refs = [side['participants']['full_refs'] for side in decoded['context']['sides']]
    mapping = [next(index for index, side_refs in enumerate(refs)
                    if side['country'] in side_refs)
               for side in decoded['observation']['result']['sides']]
    observer_ref = refs[winner if observer_side == 'winner' else loser][0]
    original = deepcopy(decoded)

    assert project_retreat(decoded, mapping, observer_ref) == {
        'status': 'not_applicable',
        'reason': 'RETREAT_NOT_APPLICABLE_AFTER_NATIVE_OVERRUN',
        'basis': 'native_combat_side_overrun_marker',
        'scope': 'whole_combat_side',
        'combat_side_index': loser,
    }
    assert decoded == original


@pytest.mark.parametrize('mutation', [
    'no_overrun', 'winner_marked', 'both_marked', 'foreign_observer',
    'bad_mapping', 'incomplete_participants', 'malformed_retreat', 'bad_wire',
])
def test_uncaptured_retreat_does_not_hide_missing_or_invalid_evidence(mutation):
    decoded, mapping, observer_ref, loser = _wire10()
    decoded['retreat'] = {'status': 'unknown', 'reason': 'RETREAT_NOT_CAPTURED'}
    decoded['end_state']['raw_gates'][loser] = 1
    if mutation == 'no_overrun':
        decoded['end_state']['raw_gates'][loser] = 0
    elif mutation == 'winner_marked':
        decoded['end_state']['raw_gates'] = [1, 0] if loser == 1 else [0, 1]
    elif mutation == 'both_marked':
        decoded['end_state']['raw_gates'] = [1, 1]
    elif mutation == 'foreign_observer':
        observer_ref = _ref('ZZZ')
    elif mutation == 'bad_mapping':
        mapping = [0, 0]
    elif mutation == 'incomplete_participants':
        decoded['context']['sides'][loser]['participants']['complete'] = False
    elif mutation == 'malformed_retreat':
        decoded['retreat']['unexpected'] = True
    elif mutation == 'bad_wire':
        decoded['wire10']['trailing_bytes'] = 1
    assert project_retreat(decoded, mapping, observer_ref)['status'] == 'unknown'

