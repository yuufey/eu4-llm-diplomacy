"""Observer-relative phrases remain separate from unresolved WINORLOSE text."""
from copy import deepcopy

import pytest

from bridge.information.battle_outcome_composition import project_outcome_text_composition
from bridge.tests.test_information_battle_outcome_text import _decoded, _field
from bridge.tests.test_information_battles import (
    _full_ref, battle_topic_query, event_id, make_source,
)
from work import information_battle_name_sources_wire as base_wire


def _mapping(decoded):
    result_sides = decoded["observation"]["result"]["sides"]
    combat_sides = decoded["context"]["sides"]
    return [next(index for index, side in enumerate(combat_sides)
                 if result["country"] in side["participants"]["full_refs"])
            for result in result_sides]


def _configure(decoded, *, winner, observer_side, result_order=(0, 1)):
    result = decoded["observation"]["result"]
    original = deepcopy(result["sides"])
    result["sides"] = [original[index] for index in result_order]
    mapping = _mapping(decoded)
    assert sorted(mapping) == [0, 1]
    decoded["observation"]["summary"]["control_byte"] = winner
    result["flag108"] = 1 if mapping[0] == winner else 0
    observer_ref = decoded["context"]["sides"][observer_side]["participants"]["full_refs"][0]
    return mapping, observer_ref


def _phrase_literals(decoded):
    decoded["outcome_text"]["text_fields"]["YOU_WON"] = _field(b"Victory")
    decoded["outcome_text"]["text_fields"]["YOU_LOST"] = _field(b"Defeat")
    decoded["outcome_text"]["text_fields"]["RESULT_WON"] = _field(b"Combat side 0 won")
    decoded["outcome_text"]["text_fields"]["RESULT_LOSS"] = _field(b"Combat side 0 lost")
    decoded["outcome_text"]["text_fields"]["OTHERRESULT"] = _field(b"MALICIOUS_OTHERRESULT")
    decoded["outcome_text"]["text_fields"]["MESSENGER"] = _field(b"MALICIOUS_MESSENGER")


@pytest.mark.parametrize("winner,observer_side,result_order,phrase,outcome", [
    (0, 0, (0, 1), "YOU_WON", "victory"),
    (0, 1, (0, 1), "YOU_LOST", "defeat"),
    (1, 1, (1, 0), "YOU_WON", "victory"),
    (1, 0, (1, 0), "YOU_LOST", "defeat"),
])
def test_observer_phrase_and_land_parameters_follow_combat_sides(
        winner, observer_side, result_order, phrase, outcome):
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    mapping, observer_ref = _configure(
        decoded, winner=winner, observer_side=observer_side,
        result_order=result_order,
    )
    result = project_outcome_text_composition(
        decoded, mapping=mapping, observer_ref=observer_ref,
    )

    assert result["status"] == "known"
    assert result["observer_outcome"] == outcome
    assert result["winning_combat_side_index"] == winner
    assert result["observer_base_phrase"]["status"] == "known"
    assert result["observer_base_phrase"]["key"] == phrase
    assert result["observer_base_phrase"]["text"] == ("Victory" if phrase == "YOU_WON" else "Defeat")
    assert result["observer_base_phrase"]["basis"] == "same_event_zero_argument_cached_template"

    parameters = result["land_format_parameters"]
    assert parameters["RESULT"]["combat_side_index"] == 0
    assert parameters["RESULT"]["source_role"] == "format_parameter"
    assert parameters["OTHERRESULT"]["combat_side_index"] == 1
    assert parameters["OTHERRESULT"]["source_role"] == "format_parameter"
    assert parameters["RESULT"]["key"] == ("RESULT_WON" if winner == 0 else "RESULT_LOSS")
    assert parameters["OTHERRESULT"]["key"] == ("RESULT_WON" if winner == 1 else "RESULT_LOSS")

    assert result["winorlose"]["status"] == "unknown"
    assert result["winorlose"]["reason"] == "SCORE_APPEND_PREDICATE_AND_FORMAT_UNRESOLVED"
    assert result["winorlose"]["candidate_if_not_appended"]["text"] == result["observer_base_phrase"]["text"]
    assert result["winorlose"]["candidate_if_appended"]["condition"] == 'append_condition == true'
    assert result["messenger"]["status"] == "known"
    assert result["messenger"]["key"] == "MESSAGE_HEAD_MIL"
    assert result["messenger"]["window_title_verified"] is False
    assert "MALICIOUS_OTHERRESULT" not in repr(result)
    assert "MALICIOUS_MESSENGER" not in repr(result)
    assert result["ignored_legacy_parameter_name_probes"] == ["OTHERRESULT", "MESSENGER"]
    assert result["not_raw_text"] is True
    for flag in ("native_formatter_invoked", "native_branch_selection_verified",
                 "native_line1_verified", "full_display_complete", "complete"):
        assert result[flag] is False


@pytest.mark.parametrize("location", ["summary", "result_flag"])
def test_bool_winner_representations_are_rejected(location):
    _, _, _, decoded = _decoded()
    mapping, observer_ref = _configure(decoded, winner=0, observer_side=0)
    if location == "summary":
        decoded["observation"]["summary"]["control_byte"] = bool(
            decoded["observation"]["summary"]["control_byte"])
    else:
        decoded["observation"]["result"]["flag108"] = bool(
            decoded["observation"]["result"]["flag108"])
    result = project_outcome_text_composition(
        decoded, mapping=mapping, observer_ref=observer_ref,
    )
    assert result["status"] == "unknown"


def test_conflicting_winner_representations_and_wrong_mapping_stay_unknown():
    _, _, _, decoded = _decoded()
    mapping, observer_ref = _configure(decoded, winner=0, observer_side=0)
    decoded["observation"]["result"]["flag108"] = 0 if mapping[0] == 0 else 1
    assert project_outcome_text_composition(
        decoded, mapping=mapping, observer_ref=observer_ref,
    )["status"] == "unknown"

    _, _, _, decoded = _decoded()
    mapping, observer_ref = _configure(decoded, winner=0, observer_side=0)
    assert project_outcome_text_composition(
        decoded, mapping=[None, None], observer_ref=observer_ref,
    )["status"] == "unknown"


def test_repeated_full_ref_across_sides_and_nonparticipant_are_not_composed():
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    mapping, observer_ref = _configure(decoded, winner=0, observer_side=0)
    duplicated = decoded["context"]["sides"][0]["participants"]["full_refs"][0]
    decoded["context"]["sides"][1]["participants"]["full_refs"].append(duplicated)
    assert project_outcome_text_composition(
        decoded, mapping=mapping, observer_ref=observer_ref,
    )["status"] == "unknown"

    _, _, _, decoded = _decoded()
    mapping, _ = _configure(decoded, winner=0, observer_side=0)
    absent_observer = int(_full_ref("XYZ"), 16)
    assert project_outcome_text_composition(
        decoded, mapping=mapping, observer_ref=absent_observer,
    )["status"] == "unknown"


@pytest.mark.parametrize("raw,state,expected,reason", [
    (b"", "known", "known", None),
    (b"$COUNTRY$ wins", "known", "unknown", "OUTCOME_TEMPLATE_REQUIRES_UNSUPPORTED_FORMATTING_OR_CODEC"),
    (b"$VAL|=+$", "known", "unknown", "OUTCOME_TEMPLATE_REQUIRES_UNSUPPORTED_FORMATTING_OR_CODEC"),
    (b"\x10", "known", "unknown", "OUTCOME_TEMPLATE_REQUIRES_UNSUPPORTED_FORMATTING_OR_CODEC"),
    (b"", "absent", "unknown", "OUTCOME_TEMPLATE_CACHE_ABSENT"),
])
def test_phrase_formatting_is_zero_argument_and_preserves_unknown_inputs(raw, state, expected, reason):
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    mapping, observer_ref = _configure(decoded, winner=0, observer_side=0)
    decoded["outcome_text"]["text_fields"]["YOU_WON"] = _field(raw, state=state)
    result = project_outcome_text_composition(decoded, mapping=mapping,
                                              observer_ref=observer_ref)
    phrase = result["observer_base_phrase"]
    assert phrase["status"] == expected
    if expected == "known":
        assert phrase["text"] == "" and phrase["raw_hex"] == ""
    else:
        assert phrase["reason"] == reason


def test_naval_parameters_and_invalid_same_event_group_remain_unknown():
    _, _, _, decoded = _decoded()
    _phrase_literals(decoded)
    mapping, observer_ref = _configure(decoded, winner=0, observer_side=0)
    decoded["context"]["kind"] = 2
    decoded["outcome_text"]["kind"] = 2
    naval = project_outcome_text_composition(decoded, mapping=mapping,
                                             observer_ref=observer_ref)
    assert naval["status"] == "known"
    assert naval["naval_format_parameters"]["status"] == "unknown"
    assert naval["naval_format_parameters"]["reason"] == "NAVAL_PARAMETER_TEMPLATES_NOT_CAPTURED"
    assert "land_format_parameters" not in naval

    _, _, _, decoded = _decoded()
    decoded["outcome_text"]["sequence"] += 1
    assert project_outcome_text_composition(decoded)["status"] == "unknown"

    _, _, _, decoded = _decoded(failed=True)
    assert project_outcome_text_composition(decoded)["status"] == "unknown"

    _, _, _, decoded = _decoded()
    decoded["outcome_text"]["text_fields"]["language"] = _field(state="unknown")
    assert project_outcome_text_composition(decoded)["status"] == "unknown"

    _, _, _, decoded = _decoded()
    mapping, observer_ref = _configure(decoded, winner=0, observer_side=0)
    decoded["context"]["sides"][1]["participants"]["complete"] = False
    assert project_outcome_text_composition(
        decoded, mapping=mapping, observer_ref=observer_ref,
    )["status"] == "unknown"


def test_old_v11_does_not_gain_outcome_composition():
    _, base, _, _ = _decoded()
    decoded = base_wire.decode(base)
    result = project_outcome_text_composition(decoded)
    assert result["status"] == "unknown"
    assert result["reason"] == "OUTCOME_COMPOSITION_SAME_EVENT_INPUTS_UNKNOWN"
    assert "observer_base_phrase" not in result


def test_nonparticipant_receives_no_battle_composition_event(tmp_path):
    fixture, _, _, _ = _decoded()
    source, *_ = make_source(tmp_path, fixture=fixture, observer="XYZ",
                             observer_ref=_full_ref("XYZ"), message_ids=("228",))
    query = battle_topic_query("B04", ["details"],
                               selected_event=event_id(fixture, "228"))
    direct = source.read(query, source.context())
    assert direct["fields"]["details"]["status"] != "known"
    assert source.poll_events(source.context(), None)["events"] == []
