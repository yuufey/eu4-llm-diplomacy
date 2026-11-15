"""Check land projections against real captures and native rounding rules."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from bridge.information.battle_values import project_forces, project_land_forces, project_outcome
from work.information_battle_context_wire import decode


FIXTURES = Path(__file__).parent / "fixtures"


def capture(name):
    fixture = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    raw = bytes.fromhex(fixture["payload_hex"])
    assert hashlib.sha256(raw).hexdigest() == fixture["provenance"]["payload_sha256"]
    return decode(raw)


def naval_extension(decoded, *, row_types=(3, 4, 5, 6),
                    raw_losses=None, gates=(0, 0), control=0,
                    initial_fields=None):
    """Attach a synthetic naval-loss extension to an existing recorded payload.

    The base payload remains the real recorded seq4 observation.  Only the
    optional extension is synthetic, so these tests exercise projection math
    without presenting the result as an additional native capture.
    """
    result = deepcopy(decoded)
    row_types = list(row_types)
    if raw_losses is None:
        raw_losses = [[0, 0, 0, 0], [0, 0, 0, 0]]
    assert all(len(values) == 4 for values in raw_losses)
    result["observation"]["summary"]["control_byte"] = control
    if initial_fields is not None:
        for side, values in zip(result["observation"]["result"]["sides"], initial_fields):
            side["raw_fields"][3:7] = list(values)
    result["naval"] = {
        "row_types": row_types,
        "sides": [
            {"raw_loss_i32": list(raw_losses[0]), "raw_gate": gates[0]},
            {"raw_loss_i32": list(raw_losses[1]), "raw_gate": gates[1]},
        ],
    }
    return result


def test_real_paris_capture_keeps_multicountry_side_totals_separate_from_fra():
    projected = project_land_forces(capture("information_battle_FRA_live_v2_1374.json"))
    initial = projected["initial_forces"]["value"]
    losses = projected["losses"]["value"]
    remaining = projected["remaining_forces"]["value"]
    assert initial["sides"][0]["by_unit"] == {"infantry": 7000, "cavalry": 2000, "artillery": 0}
    assert initial["sides"][1]["participants"] == ["FRA", "FOI", "AUV"]
    assert initial["sides"][1]["by_unit"] == {"infantry": 34000, "cavalry": 6928, "artillery": 0}
    assert [s["component_sum"] for s in losses["sides"]] == [4638, 1806]
    assert [s["component_sum"] for s in remaining["sides"]] == [4362, 39122]
    assert initial["scope"] == "whole_combat_side"
    assert initial["runtime_popup_verified"] is False
    assert losses["aggregate_display"]["status"] == "known"
    assert [s["count"]["value"] for s in losses["aggregate_display"]["value"]["sides"]] == [4638, 1806]


def test_real_vij_capture_keeps_zero_remaining_without_inventing_a_result_flag():
    projected = project_land_forces(capture("information_battle_live_v2_1374.json"))
    remaining = projected["remaining_forces"]["value"]["sides"]
    assert [side["component_sum"] for side in remaining] == [13493, 0]
    assert set(projected) == {"initial_forces", "losses", "remaining_forces", "unit_breakdown"}


def test_remaining_uses_native_division_of_each_operand_before_subtraction():
    # This is an arithmetic boundary derived from the captured shape, not a
    # second real battle. (2001-1999)/1000 would incorrectly produce zero.
    decoded = capture("information_battle_live_v2_1374.json")
    decoded["context"]["sides"][0]["raw_fields"] = [2001, 0, 0, 1999, 0, 0]
    value = project_land_forces(decoded)["remaining_forces"]["value"]
    assert value["sides"][0]["by_unit"]["infantry"] == 1


def test_naval_and_inconsistent_land_counts_preserve_explicit_gaps():
    decoded = capture("information_battle_live_v2_1374.json")
    naval = deepcopy(decoded)
    naval["context"]["kind"] = 2
    assert all(field["status"] == "unsupported" for field in project_land_forces(naval).values())
    decoded["context"]["sides"][0]["raw_fields"][3] = 10638001
    assert all(field["status"] == "unknown" for field in project_land_forces(decoded).values())


def test_real_captures_project_winner_from_control_and_result_direction():
    cases = [
        (
            "information_battle_live_v2_1374.json",
            [0, 1],
            int("0100023c004a4956", 16),
            {
                "combat_side_index": 0,
                "result_side_index": 0,
                "representative": "VIJ",
                "participants": ["VIJ"],
                "scope": "whole_combat_side",
                "observer_outcome": "victory",
                "basis": "native_combat_end_direction",
                "runtime_popup_verified": False,
            },
        ),
        (
            "information_battle_FRA_live_v2_1374.json",
            [1, 0],
            int("0100007a00415246", 16),
            {
                "combat_side_index": 1,
                "result_side_index": 0,
                "representative": "FRA",
                "participants": ["FRA", "FOI", "AUV"],
                "scope": "whole_combat_side",
                "observer_outcome": "victory",
                "basis": "native_combat_end_direction",
                "runtime_popup_verified": False,
            },
        ),
    ]
    for filename, mapping, observer_ref, expected in cases:
        assert project_outcome(capture(filename), mapping, observer_ref) == {
            "status": "known", "value": expected,
        }


def test_outcome_mapping_or_direction_mismatch_is_unknown_without_guessing():
    decoded = capture("information_battle_FRA_live_v2_1374.json")
    observer_ref = int("0100007a00415246", 16)
    assert project_outcome(decoded, [None, None], observer_ref) == {
        "status": "unknown", "reason": "OUTCOME_SIDE_MAPPING_UNRESOLVED",
    }
    assert project_outcome(decoded, [0, 0], observer_ref) == {
        "status": "unknown", "reason": "OUTCOME_SIDE_MAPPING_UNRESOLVED",
    }

    inconsistent = deepcopy(decoded)
    inconsistent["observation"]["result"]["flag108"] = 0
    assert project_outcome(inconsistent, [1, 0], observer_ref) == {
        "status": "unknown", "reason": "BATTLE_OUTCOME_INCONSISTENT",
    }

    noncanonical = deepcopy(decoded)
    noncanonical["observation"]["result"]["flag108"] = 2
    outcome = project_outcome(noncanonical, [1, 0], observer_ref)
    assert outcome["status"] == "unknown"
    assert "value" not in outcome
    assert outcome.get("reason")


def test_recorded_naval_seq4_observer_on_losing_side_is_defeat():
    fixture = json.loads(
        (FIXTURES / "information_battle_naval_seq4_recorded_v2_1374.json")
        .read_text(encoding="utf-8")
    )
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    observer_ref = int(fixture["recorded_observer_ref"], 16)
    assert fixture["mode"] == "recorded"
    assert fixture["provenance"]["source_mode"] == "sealed_recorded_stream"
    assert fixture["expected_mapping"] == [1, 0]
    outcome = project_outcome(decoded, fixture["expected_mapping"], observer_ref)
    assert outcome == {
        "status": "known",
        "value": {
            "combat_side_index": 0,
            "result_side_index": 1,
            "representative": "JMB",
            "participants": ["JMB"],
            "scope": "whole_combat_side",
            "observer_outcome": "defeat",
            "basis": "native_combat_end_direction",
            "runtime_popup_verified": False,
        },
    }


def test_recorded_naval_seq4_projects_initial_ship_counts_in_combat_order():
    fixture = json.loads(
        (FIXTURES / "information_battle_naval_seq4_recorded_v2_1374.json")
        .read_text(encoding="utf-8")
    )
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    projected = project_forces(decoded, fixture["expected_mapping"])

    initial = projected["initial_forces"]
    assert initial["status"] == "known"
    assert initial["value"] == {
        "unit": "ships",
        "scale": 1,
        "scope": "whole_combat_side",
        "basis": "native_result_start_counts_gui_mapping",
        "runtime_popup_verified": False,
        "sides": [
            {
                "combat_side_index": 0,
                "participants": ["JMB"],
                "by_unit": {"heavy_ship": 0, "light_ship": 0, "galley": 8, "transport": 6},
                "component_sum": 14,
            },
            {
                "combat_side_index": 1,
                "participants": ["SAK"],
                "by_unit": {"heavy_ship": 0, "light_ship": 3, "galley": 0, "transport": 0},
                "component_sum": 3,
            },
        ],
    }

    breakdown = projected["unit_breakdown"]
    assert breakdown == {
        "status": "known",
        "value": {
            "unit": "ships",
            "scale": 1,
            "scope": "whole_combat_side",
            "basis": "native_result_start_counts_gui_mapping",
            "runtime_popup_verified": False,
            "available_phases": ["initial"],
            "unavailable_phases": ["lost", "remaining"],
            "sides": [
                {
                    "combat_side_index": 0,
                    "participants": ["JMB"],
                    "units": {
                        "heavy_ship": {"initial": 0},
                        "light_ship": {"initial": 0},
                        "galley": {"initial": 8},
                        "transport": {"initial": 6},
                    },
                },
                {
                    "combat_side_index": 1,
                    "participants": ["SAK"],
                    "units": {
                        "heavy_ship": {"initial": 0},
                        "light_ship": {"initial": 3},
                        "galley": {"initial": 0},
                        "transport": {"initial": 0},
                    },
                },
            ],
        },
    }
    assert projected["losses"] == {
        "status": "unsupported",
        "reason": "NAVAL_LOSS_FIELDS_NOT_CAPTURED",
    }
    assert projected["remaining_forces"] == {
        "status": "unsupported",
        "reason": "NAVAL_REMAINING_FIELDS_NOT_CAPTURED",
    }


def test_v3_without_naval_extension_keeps_initial_but_marks_loss_fields_unknown():
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    mapping = [1, 0]
    v2 = project_forces(decoded, mapping)
    assert v2["losses"] == {
        "status": "unsupported", "reason": "NAVAL_LOSS_FIELDS_NOT_CAPTURED",
    }
    assert v2["remaining_forces"] == {
        "status": "unsupported", "reason": "NAVAL_REMAINING_FIELDS_NOT_CAPTURED",
    }

    # This models a decoded v3 envelope whose optional NAVL block was not
    # captured.  The real initial result lanes remain usable; only the v3
    # loss/remaining claims become explicitly unknown.
    missing = deepcopy(decoded)
    missing["wire"] = dict(missing["wire"], version=3, naval_present=False)
    missing["naval"] = None
    projected = project_forces(missing, mapping)
    assert projected["initial_forces"] == v2["initial_forces"]
    assert projected["unit_breakdown"] == v2["unit_breakdown"]
    assert projected["losses"] == {
        "status": "unknown", "reason": "NAVAL_EXTENSION_CAPTURE_UNAVAILABLE",
    }
    assert projected["remaining_forces"] == {
        "status": "unknown", "reason": "NAVAL_EXTENSION_CAPTURE_UNAVAILABLE",
    }


def test_naval_mapping_and_negative_initial_counts_keep_explicit_gaps():
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")

    unresolved = project_forces(decoded, [None, None])
    assert unresolved["initial_forces"] == {
        "status": "unknown", "reason": "NAVAL_SIDE_MAPPING_UNRESOLVED",
    }
    assert unresolved["unit_breakdown"] == {
        "status": "unknown", "reason": "NAVAL_SIDE_MAPPING_UNRESOLVED",
    }
    assert unresolved["losses"] == {
        "status": "unsupported", "reason": "NAVAL_LOSS_FIELDS_NOT_CAPTURED",
    }
    assert unresolved["remaining_forces"] == {
        "status": "unsupported", "reason": "NAVAL_REMAINING_FIELDS_NOT_CAPTURED",
    }

    inconsistent = deepcopy(decoded)
    inconsistent["observation"]["result"]["sides"][1]["raw_fields"][3] = -1
    negative = project_forces(inconsistent, [1, 0])
    assert negative["initial_forces"] == {
        "status": "unknown", "reason": "NAVAL_INITIAL_COUNTS_INCONSISTENT",
    }
    assert negative["unit_breakdown"] == {
        "status": "unknown", "reason": "NAVAL_INITIAL_COUNTS_INCONSISTENT",
    }
    assert negative["losses"] == {
        "status": "unsupported", "reason": "NAVAL_LOSS_FIELDS_NOT_CAPTURED",
    }
    assert negative["remaining_forces"] == {
        "status": "unsupported", "reason": "NAVAL_REMAINING_FIELDS_NOT_CAPTURED",
    }


def test_project_forces_keeps_land_projection_unchanged():
    decoded = capture("information_battle_live_v2_1374.json")
    assert project_forces(decoded, [0, 1]) == project_land_forces(decoded)


def test_synthetic_naval_loss_projection_preserves_direction_and_repeated_rows():
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    # Both synthetic result sides have nonzero starts so a losing row can
    # reach zero without making the remaining projection invalid.
    synthetic_initials = ((4, 3, 2, 1), (4, 3, 2, 1))
    projected = project_forces(
        naval_extension(
            decoded, row_types=(3, 4, 5, 5, 6),
            initial_fields=synthetic_initials,
        ),
        [1, 0],
    )

    losses = {
        side["combat_side_index"]: side
        for side in projected["losses"]["value"]["sides"]
    }
    # summary.control_byte=0 makes combat side 0 the winner.  With zero raw
    # loss, the row quantities therefore add on the winner and subtract on
    # the loser, independently of result-side order.
    assert losses[0]["by_unit"]["galley"] > 0
    assert losses[1]["by_unit"]["light_ship"] < 0
    assert projected["losses"]["value"]["quantity"] == "net_ship_change"
    assert projected["losses"]["value"]["sign_convention"] == (
        "negative_loss_positive_gain"
    )

    one_row = naval_extension(
        decoded, row_types=(3, 4, 5, 6), initial_fields=synthetic_initials,
    )
    one = project_forces(one_row, [1, 0])["losses"]["value"]["sides"]
    one_by_side = {side["combat_side_index"]: side for side in one}
    assert losses[0]["by_unit"]["galley"] > one_by_side[0]["by_unit"]["galley"]

    # Type 99 is outside the four supported ship rows.  A large raw value on
    # it must not affect any projected component.
    ignored = naval_extension(
        decoded,
        row_types=(3, 4, 5, 6, 99),
        raw_losses=[[0, 0, 0, 0], [0, 0, 0, 0]],
        initial_fields=synthetic_initials,
    )
    assert project_forces(ignored, [1, 0])["losses"]["value"]["sides"] == one


def test_synthetic_naval_gate_forces_zero_remaining_and_initial_is_retained():
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    # Only the light-ship row is present, so the real SAK losing side reaches
    # zero instead of producing an unrelated negative remaining count.
    projected = project_forces(
        naval_extension(decoded, row_types=(4,), gates=(1, 0)), [1, 0],
    )
    initial = {
        side["combat_side_index"]: side
        for side in projected["initial_forces"]["value"]["sides"]
    }
    losses = {
        side["combat_side_index"]: side
        for side in projected["losses"]["value"]["sides"]
    }
    remaining = {
        side["combat_side_index"]: side
        for side in projected["remaining_forces"]["value"]["sides"]
    }
    assert losses[0]["by_unit"] == {
        "heavy_ship": 0, "light_ship": 0, "galley": -8, "transport": -6,
    }
    assert remaining[0]["by_unit"] == {
        "heavy_ship": 0, "light_ship": 0, "galley": 0, "transport": 0,
    }
    assert initial[0]["by_unit"] == {
        "heavy_ship": 0, "light_ship": 0, "galley": 8, "transport": 6,
    }

    breakdown = projected["unit_breakdown"]["value"]
    assert breakdown["available_phases"] == ["initial", "net_change", "remaining"]
    assert breakdown["unavailable_phases"] == []
    assert breakdown["sides"][0]["units"]["galley"] == {
        "initial": 8, "net_change": -8, "remaining": 0,
    }


def test_synthetic_naval_invalid_remaining_or_i32_keeps_initial_and_gaps_only_loss_fields():
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    negative_remaining = naval_extension(
        decoded,
        row_types=(3, 4, 5, 6),
        raw_losses=[[0, 0, 20_000, 0], [0, 0, 0, 0]],
    )
    projected = project_forces(negative_remaining, [1, 0])
    assert projected["initial_forces"]["status"] == "known"
    assert projected["losses"] == {
        "status": "unknown", "reason": "NAVAL_FORCE_COUNTS_INCONSISTENT",
    }
    assert projected["remaining_forces"] == {
        "status": "unknown", "reason": "NAVAL_FORCE_COUNTS_INCONSISTENT",
    }

    i32_overflow = naval_extension(
        decoded,
        row_types=(3, 4, 5, 6),
        raw_losses=[[2_147_483_648, 0, 0, 0], [0, 0, 0, 0]],
    )
    overflow_projected = project_forces(i32_overflow, [1, 0])
    assert overflow_projected["initial_forces"]["status"] == "known"
    assert overflow_projected["losses"] == {
        "status": "unknown", "reason": "NAVAL_FORCE_COUNTS_INCONSISTENT",
    }
    assert overflow_projected["remaining_forces"] == {
        "status": "unknown", "reason": "NAVAL_FORCE_COUNTS_INCONSISTENT",
    }


def test_synthetic_naval_invalid_outcome_control_does_not_invent_net_change():
    decoded = capture("information_battle_naval_seq4_recorded_v2_1374.json")
    projected = project_forces(
        naval_extension(
            decoded, row_types=(3, 4, 5, 6), control=2,
            initial_fields=((4, 3, 2, 1), (4, 3, 2, 1)),
        ),
        [1, 0],
    )
    assert projected["initial_forces"]["status"] == "known"
    assert projected["losses"] == {
        "status": "unknown", "reason": "NAVAL_OUTCOME_CONTROL_UNRESOLVED",
    }
    assert projected["remaining_forces"] == {
        "status": "unknown", "reason": "NAVAL_OUTCOME_CONTROL_UNRESOLVED",
    }
