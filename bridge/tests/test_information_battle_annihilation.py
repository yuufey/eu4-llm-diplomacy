"""Fail-closed tests for the copied naval overrun marker projection."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.battle_annihilation import project_annihilation


def _ref(tag: str) -> int:
    return int.from_bytes(tag.encode("ascii") + b"\0" * 5, "little")


def _decoded(*, kind=2, winner=0, flag108=0, gates=(0, 1), remaining=None):
    refs = [[_ref("FRA"), _ref("ENG")], [_ref("POR"), _ref("GBR")]]
    results = [{"country": refs[1][0]}, {"country": refs[0][0]}]
    naval_sides = [{"raw_gate": gate} for gate in gates]
    if remaining is not None:
        for side, counts in zip(naval_sides, remaining):
            side["remaining_counts"] = list(counts)
    return {
        "context": {
            "kind": kind,
            "sides": [{
                "present": True,
                "participants": {"complete": True, "full_refs": list(side_refs)},
            } for side_refs in refs],
        },
        "observation": {
            "summary": {"control_byte": winner},
            "result": {"flag108": flag108, "sides": results},
        },
        "naval": {"sides": naval_sides},
    }


def test_losing_side_overrun_marker_is_positive_whole_side_annihilation_and_input_is_unchanged():
    decoded = _decoded()
    before = deepcopy(decoded)

    result = project_annihilation(decoded, [1, 0], _ref("FRA"))

    assert decoded == before
    assert result["status"] == "known" and result["complete"] is False
    value = result["value"]
    assert value["basis"] == "native_combat_side_overrun_marker"
    assert value["scope"] == "whole_combat_side"
    assert value["classification_scope"] == "native_overrun_path_only"
    assert value["complete"] is False
    assert value["sides"] == [
        {
            "combat_side_index": 0,
            "participants": ["FRA", "ENG"],
            "native_overrun": {"status": "known", "value": False},
            "annihilated": {
                "status": "unknown", "reason": "NON_OVERRUN_ANNIHILATION_PATHS_UNRESOLVED",
            },
        },
        {
            "combat_side_index": 1,
            "participants": ["POR", "GBR"],
            "native_overrun": {"status": "known", "value": True},
            "annihilated": {"status": "known", "value": True},
        },
    ]


def test_zero_marker_stays_unknown_even_if_copied_remaining_counts_are_zero():
    decoded = _decoded(gates=(0, 0), remaining=((0, 0, 0, 0), (0, 0, 0, 0)))

    result = project_annihilation(decoded, [1, 0], _ref("FRA"))

    assert result["status"] == "known"
    loser = result["value"]["sides"][1]
    assert loser["native_overrun"] == {"status": "known", "value": False}
    assert loser["annihilated"] == {
        "status": "unknown", "reason": "NON_OVERRUN_ANNIHILATION_PATHS_UNRESOLVED",
    }
    assert all(side["annihilated"].get("value") is not False
               for side in result["value"]["sides"])


@pytest.mark.parametrize("mutation", ["land", "extension_missing", "participants_incomplete"])
def test_non_naval_or_incomplete_evidence_is_unknown(mutation):
    decoded = _decoded(kind=1 if mutation == "land" else 2)
    if mutation == "extension_missing":
        decoded.pop("naval")
    elif mutation == "participants_incomplete":
        decoded["context"]["sides"][1]["participants"]["complete"] = False

    result = project_annihilation(decoded, [1, 0], _ref("FRA"))

    assert result["status"] == "unknown"
    assert "value" not in result


@pytest.mark.parametrize("mapping", [[0, 1], [1, 1], [False, 1]])
def test_wrong_duplicate_or_boolean_side_mapping_is_unknown(mapping):
    result = project_annihilation(_decoded(), mapping, _ref("FRA"))

    assert result["status"] == "unknown"
    assert "value" not in result


@pytest.mark.parametrize(("gates", "reason"), [
    ((1, 0), "NAVAL_OVERRUN_WINNER_SIDE_MARKED"),
    ((1, 1), "NAVAL_OVERRUN_MARKERS_CONFLICT"),
])
def test_winner_overrun_or_dual_overrun_markers_are_unknown(gates, reason):
    result = project_annihilation(_decoded(gates=gates), [1, 0], _ref("FRA"))

    assert result == {"status": "unknown", "reason": reason}


@pytest.mark.parametrize("bad_gate", [True, 2, -1])
def test_non_byte_or_non_binary_overrun_marker_is_unknown(bad_gate):
    result = project_annihilation(_decoded(gates=(0, bad_gate)), [1, 0], _ref("FRA"))

    assert result == {"status": "unknown", "reason": "NAVAL_OVERRUN_MARKER_INVALID"}


def test_winner_flag_mapping_conflict_and_nonparticipant_observer_are_unknown():
    inconsistent = project_annihilation(_decoded(flag108=1), [1, 0], _ref("FRA"))
    absent_observer = project_annihilation(_decoded(), [1, 0], _ref("SWE"))

    assert inconsistent["status"] == "unknown"
    assert absent_observer["status"] == "unknown"
    assert "value" not in inconsistent and "value" not in absent_observer
