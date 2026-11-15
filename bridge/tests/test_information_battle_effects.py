"""Direct B03 effect projections for recorded land and naval observations."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from bridge.information.battle_effects import project_effects
from work.information_battle_naval_wire import decode


FIXTURES = Path(__file__).parent / "fixtures"


def capture(name: str) -> tuple[dict, dict]:
    fixture = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    raw = bytes.fromhex(fixture["payload_hex"])
    assert hashlib.sha256(raw).hexdigest() == fixture["provenance"]["payload_sha256"]
    return fixture, decode(raw)


def test_real_atj_v3_effects_keep_zero_capture_and_result_side_direction():
    fixture, decoded = capture("information_battle_naval_seq3_live_v3_1374.json")
    projected = project_effects(
        decoded, fixture["expected_mapping"], int(fixture["recorded_observer_ref"], 16),
    )

    captured = projected["ships_captured"]
    assert captured["status"] == "known"
    assert captured["value"]["unit"] == "ships"
    assert captured["value"]["scale"] == 1
    assert captured["value"]["total"] == 0
    assert captured["value"]["by_unit"] == {
        "heavy_ship": 0, "light_ship": 0, "galley": 0, "transport": 0,
    }
    assert captured["value"]["unclassified_type_count"] == 0
    assert captured["value"]["unit_breakdown_complete"] is True
    assert captured["value"]["capturing_side"] == {
        "status": "known",
        "value": {"combat_side_index": 1, "participants": ["MLC"]},
    }

    prestige = projected["prestige"]
    assert prestige["status"] == "known"
    assert prestige["value"]["scale"] == 1000
    assert [(side["participants"], side["raw"], side["display_numeric"])
            for side in prestige["value"]["sides"]] == [
        (["ATJ"], -130, "-0.13"),
        (["MLC"], 130, "+0.13"),
    ]
    assert projected["army_tradition"] == {
        "status": "unsupported",
        "reason": "NAVAL_TRADITION_IS_NOT_ARMY_TRADITION",
    }


def test_real_fra_v2_land_effects_keep_tradition_and_prestige_in_combat_order():
    fixture, decoded = capture("information_battle_FRA_live_v2_1374.json")
    projected = project_effects(
        decoded, [1, 0], int(fixture["recorded_observer_ref"], 16),
    )

    assert [(side["participants"], side["raw"])
            for side in projected["army_tradition"]["value"]["sides"]] == [
        (["HOL"], 640),
        (["FRA", "FOI", "AUV"], 1002),
    ]
    assert [(side["participants"], side["raw"])
            for side in projected["prestige"]["value"]["sides"]] == [
        (["HOL"], -320),
        (["FRA", "FOI", "AUV"], 320),
    ]
    assert projected["ships_captured"] == {
        "status": "unsupported",
        "reason": "SHIPS_CAPTURED_REQUIRES_NAVAL_BATTLE",
    }


def test_synthetic_naval_capture_rows_count_repeated_and_unknown_types():
    _fixture, decoded = capture("information_battle_naval_seq3_live_v3_1374.json")
    synthetic = deepcopy(decoded)
    # The NAVL rows are synthetic extension data for this arithmetic contract;
    # the base observation remains the real ATJ/MLC v3 capture.
    synthetic["naval"] = {
        "row_types": [3, 4, 5, 5, 6, 99],
        "sides": deepcopy(decoded["naval"]["sides"]),
    }
    projected = project_effects(
        synthetic, [1, 0], int("010001be004a5441", 16),
    )

    value = projected["ships_captured"]["value"]
    assert value["total"] == 6
    assert value["by_unit"] == {
        "heavy_ship": 1, "light_ship": 1, "galley": 2, "transport": 1,
    }
    assert value["unclassified_type_count"] == 1
    assert value["unit_breakdown_complete"] is False
    assert value["capturing_side"] == {
        "status": "known",
        "value": {"combat_side_index": 1, "participants": ["MLC"]},
    }


def test_v2_and_v3_without_naval_extension_keep_capture_gap_explicit():
    fixture, decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    v2 = project_effects(decoded, [1, 0], int(fixture["recorded_observer_ref"], 16))
    assert v2["ships_captured"] == {
        "status": "unsupported",
        "reason": "CAPTURED_SHIP_ROWS_NOT_CAPTURED",
    }
    assert v2["army_tradition"] == {
        "status": "unsupported",
        "reason": "NAVAL_TRADITION_IS_NOT_ARMY_TRADITION",
    }

    missing = deepcopy(decoded)
    missing["wire"] = dict(missing["wire"], version=3, naval_present=False)
    missing["naval"] = None
    v3 = project_effects(missing, [1, 0], int(fixture["recorded_observer_ref"], 16))
    assert v3["ships_captured"] == {
        "status": "unknown",
        "reason": "NAVAL_EXTENSION_CAPTURE_UNAVAILABLE",
    }
    assert v3["army_tradition"] == v2["army_tradition"]
    assert v3["prestige"]["status"] == "known"


def test_effect_display_uses_integer_truncation_and_preserves_negative_zero_text():
    fixture, decoded = capture("information_battle_FRA_live_v2_1374.json")
    boundary = deepcopy(decoded)
    boundary["observation"]["summary"]["raw_i32"] = [
        999, 1000, -1, 1002, 0, 0, 0, 0, 0, 0, 0,
    ]
    projected = project_effects(
        boundary, [1, 0], int(fixture["recorded_observer_ref"], 16),
    )

    tradition = projected["army_tradition"]["value"]["sides"]
    assert [(side["raw"], side["amount_decimal"], side["display_numeric"])
            for side in tradition] == [
        (999, "0.999", "+0.9"),
        (1000, "1.000", "+1.0"),
    ]
    prestige = projected["prestige"]["value"]["sides"]
    assert [(side["raw"], side["amount_decimal"], side["display_numeric"])
            for side in prestige] == [
        (-1, "-0.001", "-0.00"),
        (1002, "1.002", "+1.00"),
    ]


def test_real_atj_v3_war_score_uses_winner_result_slot_and_signed_combat_pair():
    fixture, decoded = capture("information_battle_naval_seq3_live_v3_1374.json")
    projected = project_effects(
        decoded, fixture["expected_mapping"], int(fixture["recorded_observer_ref"], 16),
    )

    score = projected["war_score"]
    assert score["status"] == "known"
    assert score["value"]["unit"] == "war_score"
    assert score["value"]["scale"] == 1000
    assert score["value"]["quantity"] == "result_window_side_operand"
    assert score["value"]["basis"] == "native_result_window_score_operands"
    assert score["value"]["display_presence"] == "unverified"
    assert score["value"]["components"] == {
        "winner_result_side_index": 0,
        "winner_integer_bonus": 0,
        "summary_fixed_point": 250,
    }
    assert [(side["participants"], side["raw"], side["amount_decimal"],
             side["display_numeric"])
            for side in score["value"]["sides"]] == [
        (["ATJ"], -250, "-0.250", "-0.25"),
        (["MLC"], 250, "0.250", "+0.25"),
    ]


def test_real_fra_v2_war_score_sign_comes_from_summary_winner():
    fixture, decoded = capture("information_battle_FRA_live_v2_1374.json")
    score = project_effects(
        decoded, [1, 0], int(fixture["recorded_observer_ref"], 16),
    )["war_score"]

    assert score["status"] == "known"
    assert score["value"]["components"] == {
        "winner_result_side_index": 0,
        "winner_integer_bonus": 0,
        "summary_fixed_point": 540,
    }
    assert [side["raw"] for side in score["value"]["sides"]] == [-540, 540]
    assert [side["participants"] for side in score["value"]["sides"]] == [
        ["HOL"], ["FRA", "FOI", "AUV"],
    ]


def test_synthetic_war_score_reads_nonzero_winner_bonus_after_result_reorder():
    _fixture, decoded = capture("information_battle_naval_seq3_live_v3_1374.json")
    synthetic = deepcopy(decoded)
    # Result side 0 is the winner while mapping [1, 0] reverses result and
    # combat order.  The other result slot is deliberately a distractor.
    synthetic["observation"]["result"]["sides"][0]["raw_fields"][8] = 2
    synthetic["observation"]["result"]["sides"][1]["raw_fields"][8] = 99
    score = project_effects(
        synthetic, [1, 0], int("010001be004a5441", 16),
    )["war_score"]

    assert score["status"] == "known"
    assert score["value"]["components"]["winner_result_side_index"] == 0
    assert score["value"]["components"]["winner_integer_bonus"] == 2
    assert score["value"]["components"]["summary_fixed_point"] == 250
    assert [side["raw"] for side in score["value"]["sides"]] == [-2250, 2250]


def test_war_score_overflow_or_outcome_mismatch_only_invalidates_war_score():
    fixture, decoded = capture("information_battle_naval_seq3_live_v3_1374.json")
    overflow = deepcopy(decoded)
    overflow["observation"]["result"]["sides"][0]["raw_fields"][8] = 2_147_484
    overflow_projected = project_effects(
        overflow, [1, 0], int(fixture["recorded_observer_ref"], 16),
    )
    assert overflow_projected["war_score"] == {
        "status": "unknown", "reason": "BATTLE_SCORE_OPERAND_OVERFLOW",
    }
    assert overflow_projected["prestige"]["status"] == "known"
    assert overflow_projected["ships_captured"] == decoded_effects_capture_zero(
        fixture, decoded,
    )

    inconsistent = deepcopy(decoded)
    inconsistent["observation"]["result"]["flag108"] = 0
    inconsistent_projected = project_effects(
        inconsistent, [1, 0], int(fixture["recorded_observer_ref"], 16),
    )
    assert inconsistent_projected["war_score"] == {
        "status": "unknown", "reason": "BATTLE_OUTCOME_INCONSISTENT",
    }
    captured = inconsistent_projected["ships_captured"]
    assert captured["status"] == "known"
    assert captured["value"]["total"] == 0
    assert captured["value"]["capturing_side"] == {
        "status": "unknown", "reason": "BATTLE_OUTCOME_INCONSISTENT",
    }


def decoded_effects_capture_zero(fixture: dict, decoded: dict) -> dict:
    """Return the real ATJ capture field for isolation assertions."""
    return project_effects(
        decoded, fixture["expected_mapping"], int(fixture["recorded_observer_ref"], 16),
    )["ships_captured"]
