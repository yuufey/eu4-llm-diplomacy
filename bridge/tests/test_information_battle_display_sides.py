"""Narrow regression tests for formatter OUR/ENEMY side identity.

The real batch-33 land seq3 and naval seq8 container records deliberately
exercise both observer labels.  The tests keep result-side reordering and
copied participant vectors explicit. Battle roles follow the fixed-build
combat schema, while popup layout retains its own unknown status.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.battle_display import project_display
from bridge.information.battle_display_sides import PROVENANCE
from bridge.information.battle_text import project_template
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battles import (
    battle_topic_query,
    event_id,
    make_source,
)
from work.information_battle_template_wire import decode


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "bridge" / "tests" / "fixtures"
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
LAND_FIXTURE = "information_battle_FRA_live_container_v4_1374.json"
NAVAL_FIXTURE = "information_battle_naval_seq8_live_container_v4_1374.json"


def _load(name: str) -> tuple[dict, dict, dict]:
    fixture = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    raw = bytes.fromhex(fixture["payload_hex"])
    assert fixture["mode"] == "recorded"
    assert fixture["provenance"]["real_capture"] is True
    assert fixture["provenance"]["synthetic_extension"] is False
    assert fixture["provenance"]["game_sha256"] == GAME_SHA256
    assert hashlib.sha256(raw).hexdigest() == fixture["provenance"]["payload_sha256"]
    decoded = decode(raw)
    template = project_template(decoded)
    assert template["status"] == "known"
    return fixture, decoded, template


def _tag(full_ref: int) -> str:
    return int(full_ref).to_bytes(8, "little")[:3].decode("ascii")


def _derived_mapping(decoded: dict) -> list[int]:
    """Derive result-index -> raw combat-side mapping from full refs."""
    context_sides = decoded["context"]["sides"]
    result_sides = decoded["observation"]["result"]["sides"]
    mapping = []
    for result_side in result_sides:
        candidates = [
            index for index, combat_side in enumerate(context_sides)
            if result_side["country"] in combat_side["participants"]["full_refs"]
        ]
        assert len(candidates) == 1
        mapping.append(candidates[0])
    assert sorted(mapping) == [0, 1]
    return mapping


def _expected_side_identity(decoded: dict, observer_ref: int | None) -> dict:
    context_sides = decoded["context"]["sides"]
    mapping = _derived_mapping(decoded)
    combat_to_result = {combat: result for result, combat in enumerate(mapping)}
    sides = []
    observer_sides = []
    for combat_index, combat_side in enumerate(context_sides):
        refs = combat_side["participants"]["full_refs"]
        if observer_ref is not None and observer_ref in refs:
            observer_sides.append(combat_index)
        sides.append({
            "template_label": "OUR" if combat_index == 0 else "ENEMY",
            "combat_side_index": combat_index,
            "participants": [_tag(ref) for ref in refs],
            "participant_full_refs": [f"{int(ref):016x}" for ref in refs],
            "result_side_index": {
                "status": "known", "value": combat_to_result[combat_index],
            },
            "observer_participated": (
                observer_ref in refs if observer_ref is not None else None
            ),
        })
    observer_label = (
        {"status": "known", "value": "OUR" if observer_sides[0] == 0 else "ENEMY"}
        if len(observer_sides) == 1
        else {"status": "unknown", "reason": "TEMPLATE_OBSERVER_SIDE_UNRESOLVED"}
    )
    return {
        "status": "known",
        "value": {
            "basis": "native_formatter_combat_sides_with_copied_participants",
            "binding_provenance": dict(PROVENANCE),
            "scope": "whole_combat_side",
            "sides": sides,
            "observer_template_label": observer_label,
            "attack_defend_roles": {
                "status": "known", "value": {"attacker": 0, "defender": 1},
            },
        },
    }


def _controls(display: dict) -> dict[str, dict]:
    assert display["status"] == "known"
    return {item["template_key"]: item for item in display["value"]["controls"]}


@pytest.mark.parametrize("name", [LAND_FIXTURE, NAVAL_FIXTURE])
def test_real_formatter_sides_copy_participants_and_reverse_result_mapping(name: str) -> None:
    fixture, decoded, template = _load(name)
    observer_ref = int(fixture["recorded_observer_ref"], 16)
    mapping = _derived_mapping(decoded)
    assert mapping == [1, 0]

    display = project_display(
        decoded, template, mapping=mapping, observer_ref=observer_ref,
    )
    side_identity = display["value"]["side_identity"]
    assert side_identity == _expected_side_identity(decoded, observer_ref)
    assert [side["template_label"] for side in side_identity["value"]["sides"]] == [
        "OUR", "ENEMY",
    ]
    assert [side["result_side_index"]["value"]
            for side in side_identity["value"]["sides"]] == [1, 0]


def test_observer_label_is_unknown_without_observer_ref_but_sides_remain_known() -> None:
    _fixture, decoded, template = _load(LAND_FIXTURE)
    display = project_display(decoded, template, mapping=[1, 0])
    side_identity = display["value"]["side_identity"]
    assert side_identity["status"] == "known"
    assert side_identity["value"]["observer_template_label"] == {
        "status": "unknown", "reason": "TEMPLATE_OBSERVER_SIDE_UNRESOLVED",
    }
    assert all(
        side["observer_participated"] is None
        for side in side_identity["value"]["sides"]
    )


def test_inconsistent_provided_mapping_keeps_participants_and_unknowns_result_index() -> None:
    fixture, decoded, template = _load(LAND_FIXTURE)
    observer_ref = int(fixture["recorded_observer_ref"], 16)
    display = project_display(
        decoded, template, mapping=[0, 1], observer_ref=observer_ref,
    )
    side_identity = display["value"]["side_identity"]
    assert side_identity["status"] == "known"
    for side, source_side in zip(
        side_identity["value"]["sides"], decoded["context"]["sides"], strict=True,
    ):
        assert side["result_side_index"] == {
            "status": "unknown", "reason": "RESULT_SIDE_MAPPING_UNRESOLVED",
        }
        assert side["participants"] == [
            _tag(ref) for ref in source_side["participants"]["full_refs"]
        ]


def _make_incomplete(decoded: dict) -> None:
    decoded["context"]["sides"][0]["participants"]["complete"] = False


def _make_cross_side_duplicate(decoded: dict) -> None:
    first = decoded["context"]["sides"][0]["participants"]["full_refs"][0]
    refs = decoded["context"]["sides"][1]["participants"]["full_refs"]
    refs.append(first)
    decoded["context"]["sides"][1]["participants"]["count"] = len(refs)


def _make_invalid_ref(decoded: dict) -> None:
    decoded["context"]["sides"][0]["participants"]["full_refs"][0] = 0


@pytest.mark.parametrize(
    "mutate", [_make_incomplete, _make_cross_side_duplicate, _make_invalid_ref],
    ids=["incomplete", "cross_side_duplicate", "invalid_ref"],
)
def test_unresolved_context_only_downgrades_identity_and_keeps_display_text(
    mutate,
) -> None:
    fixture, decoded, template = _load(LAND_FIXTURE)
    malformed = deepcopy(decoded)
    mutate(malformed)
    display = project_display(
        malformed,
        project_template(malformed),
        mapping=[1, 0],
        observer_ref=int(fixture["recorded_observer_ref"], 16),
    )
    assert display["value"]["side_identity"] == {
        "status": "unknown", "reason": "TEMPLATE_SIDE_CONTEXT_UNRESOLVED",
    }
    assert _controls(display)["OURPRESTIGE"]["display_text"] == {
        "status": "known", "value": "§G+0.20",
    }


@pytest.mark.parametrize(
    ("name", "unit_keys"),
    [
        (
            LAND_FIXTURE,
            [
                "OURCAVSTART", "OURINFSTART", "OURARTSTART",
                "OURCAVLOST", "OURINFLOST", "OURARTLOST", "OURLOST",
                "OURCAVEND", "OURINFEND", "OURARTEND",
                "ENEMYCAVSTART", "ENEMYINFSTART", "ENEMYARTSTART",
                "ENEMYCAVLOST", "ENEMYINFLOST", "ENEMYARTLOST", "ENEMYLOST",
                "ENEMYCAVEND", "ENEMYINFEND", "ENEMYARTEND",
            ],
        ),
        (
            NAVAL_FIXTURE,
            [
                "OURCAVSTART", "OURINFSTART", "OURARTSTART", "OURTRANSSTART",
                "OURCAVLOST", "OURINFLOST", "OURARTLOST", "OURTRANSLOST",
                "OURCAVEND", "OURINFEND", "OURARTEND", "OURTRANSEND",
                "ENEMYCAVSTART", "ENEMYINFSTART", "ENEMYARTSTART", "ENEMYTRANSSTART",
                "ENEMYCAVLOST", "ENEMYINFLOST", "ENEMYARTLOST", "ENEMYTRANSLOST",
                "ENEMYCAVEND", "ENEMYINFEND", "ENEMYARTEND", "ENEMYTRANSEND",
            ],
        ),
    ],
)
def test_control_side_binding_whitelist_matches_formatter_combat_side(
    name: str, unit_keys: list[str],
) -> None:
    fixture, decoded, template = _load(name)
    observer_ref = int(fixture["recorded_observer_ref"], 16)
    display = project_display(
        decoded, template, mapping=[1, 0], observer_ref=observer_ref,
    )
    controls = _controls(display)
    known_keys = set(unit_keys) | {
        "OURLEADER", "ENEMYLEADER", "OURLEADERICON", "ENEMYLEADERICON",
        "OURFIRE", "OURSHOCK", "OURMANEUVER",
        "ENEMYFIRE", "ENEMYSHOCK", "ENEMYMANEUVER",
        "OURPRESTIGE", "OURTRADITION", "OUREXHAUSTION",
        "ENEMYPRESTIGE", "ENEMYTRADITION", "ENEMYEXHAUSTION",
    }
    known_keys.update(key for key in ("OURSIEGE", "ENEMYSIEGE") if key in controls)
    for key in known_keys:
        binding = controls[key]["side_binding"]
        assert binding["status"] == "known"
        value = binding["value"]
        expected_label = "OUR" if key.startswith("OUR") else "ENEMY"
        assert value == {
            "template_label": expected_label,
            "combat_side_index": 0 if expected_label == "OUR" else 1,
            "scope": "whole_combat_side",
            "basis": "fixed1374_formatter_input",
        }

    for key in set(controls) - known_keys:
        assert controls[key]["side_binding"] == {
            "status": "unknown", "reason": "CONTROL_SIDE_BINDING_UNRESOLVED",
        }


@pytest.mark.parametrize(
    ("name", "observer", "message_id"),
    [(LAND_FIXTURE, "FRA", "3"), (NAVAL_FIXTURE, "KEL", "8")],
)
def test_public_b04_query_report_subscription_and_b02_keep_side_identity(
    tmp_path: Path, name: str, observer: str, message_id: str,
) -> None:
    fixture, decoded, template = _load(name)
    observer_ref = int(fixture["recorded_observer_ref"], 16)
    mapping = _derived_mapping(decoded)
    expected_display = project_display(
        decoded, template, mapping=mapping, observer_ref=observer_ref,
    )
    expected_identity = expected_display["value"]["side_identity"]
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer=observer, message_ids=(message_id,),
    )
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    selected = event_id(fixture, message_id)
    b04_query = battle_topic_query("B04", ["details"], selected_event=selected)
    try:
        direct = service.query(f"sides-query-{message_id}", queries=[b04_query])
        direct_item = direct["items"][0]
        assert direct_item["source"]["projection_version"] == 30
        assert direct_item["fields"]["details"]["value"]["display"]["value"]["side_identity"] == expected_identity

        b02 = source.read(
            battle_topic_query("B02", ["initial_forces"], selected_event=selected),
            source.context(),
        )
        assert b02["source"]["projection_version"] == 30
        b02_sides = {
            side["combat_side_index"]: side["participants"]
            for side in b02["fields"]["initial_forces"]["value"]["sides"]
        }
        for side in expected_identity["value"]["sides"]:
            assert side["participants"] == b02_sides[side["combat_side_index"]]

        # The asymmetric real start quantities stay attached to the same
        # combat side as the formatter inputs.  Naval CAV/INF/ART/TRANS are
        # the four native result slots; land uses its three named unit types.
        initial_sides = {
            side["combat_side_index"]: side
            for side in b02["fields"]["initial_forces"]["value"]["sides"]
        }
        display_controls = _controls(expected_display)
        if decoded["context"]["kind"] == 1:
            unit_keys = {
                "OUR": [("OURCAVSTART", "cavalry"),
                        ("OURINFSTART", "infantry"),
                        ("OURARTSTART", "artillery")],
                "ENEMY": [("ENEMYCAVSTART", "cavalry"),
                          ("ENEMYINFSTART", "infantry"),
                          ("ENEMYARTSTART", "artillery")],
            }
        else:
            unit_keys = {
                "OUR": [("OURCAVSTART", "heavy_ship"),
                        ("OURINFSTART", "light_ship"),
                        ("OURARTSTART", "galley"),
                        ("OURTRANSSTART", "transport")],
                "ENEMY": [("ENEMYCAVSTART", "heavy_ship"),
                          ("ENEMYINFSTART", "light_ship"),
                          ("ENEMYARTSTART", "galley"),
                          ("ENEMYTRANSSTART", "transport")],
            }
        for side in expected_identity["value"]["sides"]:
            for key, unit in unit_keys[side["template_label"]]:
                binding = display_controls[key]["side_binding"]["value"]
                assert binding["combat_side_index"] == side["combat_side_index"]
                text = display_controls[key]["display_text"]
                assert text["status"] == "known"
                assert int(text["value"].replace(",", "")) == initial_sides[
                    side["combat_side_index"]
                ]["by_unit"][unit]

        report = tools.call(
            "information_manage_report",
            {
                "request_id": f"sides-report-{message_id}",
                "operation": "create",
                "config": {
                    "name": f"batch33 side identity {message_id}",
                    "detail": "full",
                    "queries": [b04_query],
                },
            },
        )["report"]
        tools.call(
            "information_manage_subscription",
            {
                "request_id": f"sides-subscription-{message_id}",
                "operation": "create",
                "config": {
                    "name": f"batch33 side identity events {message_id}",
                    "kind": "event",
                    "report_id": report["id"],
                    "enabled": True,
                    "binding": {
                        "session_id": fixture["provenance"]["session_id"],
                        "observer": observer,
                        "game_version": "1.37.4",
                        "game_sha256": GAME_SHA256,
                    },
                    "event": {"types": ["battle_observation"]},
                },
            },
        )
        tick = tools.call("information_tick", {"view": "full"})
        assert len(tick["results"]) == 1
        event_item = tick["results"][0]["items"][0]
        assert event_item["source"]["projection_version"] == 30
        assert event_item["fields"]["details"]["value"]["display"]["value"]["side_identity"] == expected_identity
        assert tools.call("information_tick", {"view": "full"})["results"] == []
    finally:
        service.close()
