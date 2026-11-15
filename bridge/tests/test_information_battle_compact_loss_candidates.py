"""Offline tests for derived land compact-loss text candidates.

Fixtures reuse the recorded FRA battle identity/template base but attach only
synthetic DCTX compact templates and formatter-container pairs. The results
are candidate strings, not proof that a widget was selected or displayed.
"""

from __future__ import annotations

from copy import deepcopy

from bridge.information.battle_compact_loss_candidates import (
    project_compact_loss_candidates,
)
from bridge.tests.test_information_battle_body_candidate import _decoded_v7
from bridge.tests.test_information_battle_display_context_integration import (
    _v7_fixture,
)
from bridge.tests.test_information_battles import (
    battle_topic_query,
    event_id,
    make_source,
)
from work import information_battle_display_context_wire as display_wire


def _pairs(*items: tuple[bytes, bytes]) -> list[dict]:
    return [
        {"key_raw_hex": key.hex(), "value_raw_hex": value.hex()}
        for key, value in items
    ]


def _synthetic_land_decoded(*, template: bytes = b"$NUMBER$",
                            pairs: list[dict] | None = None,
                            layout_raw: int = 0,
                            compact_state: str = "observed") -> dict:
    decoded, _payload = _decoded_v7(title=b"PARIS", template=b"$NAME$")
    assert decoded["context"]["kind"] == 1
    assert decoded["display_context"]["battle_kind"] == 1
    decoded["display_context"]["layout_raw"] = layout_raw
    if compact_state == "observed":
        decoded["display_context"]["fields"]["compact_losses_template"] = {
            "state": "observed", "raw_hex": template.hex(),
        }
    else:
        decoded["display_context"]["fields"]["compact_losses_template"] = {
            "state": compact_state,
        }
    selected_pairs = pairs if pairs is not None else _pairs(
        (b"OURLOST", b"our copied $NAME$ value"),
        (b"ENEMYLOST", b"enemy copied value"),
        (b"COUNTRY", b"ENG"),
    )
    decoded["message_template"] = {
        "source_kind": "formatter_container_before_cleanup",
        "message_metadata_present": False,
        "raw_container_word_10": 0x10203040,
        "raw_container_flag_14": 0x91,
        "pair_count": len(selected_pairs),
        "pairs": deepcopy(selected_pairs),
    }
    return decoded


def _controls(result: dict) -> dict[str, dict]:
    return {item["template_key"]: item for item in result["controls"]}


def _assert_false_candidate_flags(item: dict) -> None:
    assert item["not_raw_text"] is True
    assert item["native_formatter_invoked"] is False
    assert item["native_widget_text_verified"] is False
    assert item["complete"] is False
    assert item["full_display_complete"] is False
    assert item["runtime_popup_verified"] is False
    assert item["visibility_verified"] is False


def test_literal_compact_template_still_requires_a_unique_copied_control_node():
    decoded = _synthetic_land_decoded(template=b"losses", pairs=_pairs((b"ENEMYLOST", b"7")))
    controls = _controls(project_compact_loss_candidates(decoded))
    assert controls["OURLOST"]["status"] == "unknown"
    assert controls["ENEMYLOST"]["status"] == "known"
    assert controls["ENEMYLOST"]["decoded"]["value"] == "losses"
    assert controls["ENEMYLOST"]["replacement_count"] == 0
    _assert_false_candidate_flags(controls["ENEMYLOST"])


def _assert_unknown_control(item: dict) -> None:
    assert item["status"] == "unknown"
    assert isinstance(item.get("reason"), str)
    assert item["reason"].startswith("COMPACT_LOSS_CANDIDATE_")
    _assert_false_candidate_flags(item)


def _assert_unknown_result(result: dict) -> None:
    assert result["status"] == "unknown"
    assert isinstance(result.get("reason"), str)
    assert result["reason"].startswith("COMPACT_LOSS_CANDIDATE_")
    _assert_false_candidate_flags(result)


def test_plain_number_template_uses_two_copied_values_without_recursive_expansion():
    decoded = _synthetic_land_decoded(
        template=b"Losses: $NUMBER$ / $NUMBER$",
    )
    pairs_before = deepcopy(decoded["message_template"]["pairs"])
    context_before = deepcopy(decoded["context"])

    result = project_compact_loss_candidates(decoded)

    assert result["status"] == "known"
    controls = _controls(result)
    assert (controls["OURLOST"]["widget"],
            controls["OURLOST"]["combat_side_index"]) == ("OurLost", 0)
    assert (controls["ENEMYLOST"]["widget"],
            controls["ENEMYLOST"]["combat_side_index"]) == ("EnemyLost", 1)
    assert controls["OURLOST"]["decoded"] == {
        "status": "known", "value": "Losses: our copied $NAME$ value / our copied $NAME$ value",
    }
    assert controls["ENEMYLOST"]["decoded"] == {
        "status": "known", "value": "Losses: enemy copied value / enemy copied value",
    }
    assert controls["OURLOST"]["input_raw_hex"] == b"our copied $NAME$ value".hex()
    assert controls["ENEMYLOST"]["input_raw_hex"] == b"enemy copied value".hex()
    assert controls["OURLOST"]["replacement_count"] == 2
    assert controls["ENEMYLOST"]["replacement_count"] == 2
    assert controls["OURLOST"]["input_basis"] == (
        "same_event_copied_String32_not_recomputed_loss_total"
    )
    for control in controls.values():
        _assert_false_candidate_flags(control)
        assert control["configured_layout_condition"] is True
        assert "raw_text" not in control
    # The unused COUNTRY pair stays as copied; observer FRA does not replace it.
    assert decoded["message_template"]["pairs"] == pairs_before
    assert decoded["context"] == context_before
    assert controls["OURLOST"]["input_pair_index"] == 0
    assert controls["ENEMYLOST"]["input_pair_index"] == 1


def test_layout_one_still_returns_candidates_without_claiming_widget_selection():
    result = project_compact_loss_candidates(_synthetic_land_decoded(
        template=b"$NUMBER$", layout_raw=1,
    ))

    controls = _controls(result)
    assert controls["OURLOST"]["status"] == "known"
    assert controls["ENEMYLOST"]["status"] == "known"
    assert controls["OURLOST"]["configured_layout_condition"] is False
    assert controls["ENEMYLOST"]["configured_layout_condition"] is False
    for control in controls.values():
        _assert_false_candidate_flags(control)


def test_each_control_handles_a_missing_or_duplicate_key_independently():
    missing_our = _synthetic_land_decoded(
        pairs=_pairs((b"ENEMYLOST", b"enemy value")),
    )
    missing_controls = _controls(project_compact_loss_candidates(missing_our))
    _assert_unknown_control(missing_controls["OURLOST"])
    assert missing_controls["ENEMYLOST"]["status"] == "known"

    duplicate_our = _synthetic_land_decoded(
        pairs=_pairs(
            (b"OURLOST", b"first"),
            (b"OURLOST", b"second"),
            (b"ENEMYLOST", b"enemy value"),
        ),
    )
    duplicate_controls = _controls(project_compact_loss_candidates(duplicate_our))
    _assert_unknown_control(duplicate_controls["OURLOST"])
    assert duplicate_controls["ENEMYLOST"]["status"] == "known"


def test_bad_codec_nul_and_oversized_input_only_invalidate_that_control():
    for bad_value in (b"\x10\xe3", b"bad\x00value", b"A" * 8193):
        decoded = _synthetic_land_decoded(
            pairs=_pairs(
                (b"OURLOST", bad_value),
                (b"ENEMYLOST", b"valid"),
            ),
        )
        controls = _controls(project_compact_loss_candidates(decoded))
        _assert_unknown_control(controls["OURLOST"])
        assert controls["ENEMYLOST"]["status"] == "known"


def test_missing_template_wrong_identity_wrong_definition_and_numeric_modifier_unknown():
    _assert_unknown_result(project_compact_loss_candidates(
        _synthetic_land_decoded(compact_state="unknown"),
    ))

    identity_mismatch = _synthetic_land_decoded()
    identity_mismatch["display_context"]["raw_date"] += 1
    _assert_unknown_result(project_compact_loss_candidates(identity_mismatch))

    wrong_definition = _synthetic_land_decoded()
    wrong_definition["display_context"]["fields"]["definition_key"][
        "raw_hex"
    ] = b"NAVALBATTLEOVER".hex()
    _assert_unknown_result(project_compact_loss_candidates(wrong_definition))

    numeric_modifier = _synthetic_land_decoded(
        template=b"Losses: $NUMBER|COMMA$",
    )
    _assert_unknown_result(project_compact_loss_candidates(numeric_modifier))


def test_naval_event_is_unavailable_for_land_compact_candidates():
    decoded = _synthetic_land_decoded()
    decoded["context"]["kind"] = 2
    decoded["display_context"]["battle_kind"] = 2
    decoded["display_context"]["fields"]["definition_key"][
        "raw_hex"
    ] = b"NAVALBATTLEOVER".hex()

    result = project_compact_loss_candidates(decoded)

    assert result["status"] == "unavailable"
    assert result["reason"] == "COMPACT_LOSS_CANDIDATE_LAND_ONLY"
    _assert_false_candidate_flags(result)


def test_land_v7_public_details_exposes_compact_candidate_without_promoting_it(tmp_path):
    fixture, _payload_v6, payload_v7 = _v7_fixture()
    decoded = display_wire.decode(payload_v7)
    assert decoded["context"]["kind"] == 1
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("159",),
    )
    query = battle_topic_query(
        "B04", ["details"], selected_event=event_id(fixture, "159"),
    )
    result = source.read(query, source.context())
    details = result["fields"]["details"]["value"]

    assert result["source"]["projection_version"] == 30
    candidates = details["display_context"]["compact_loss_candidates"]
    assert candidates["status"] == "unknown"
    _assert_false_candidate_flags(candidates)
    assert "raw_text" not in candidates

