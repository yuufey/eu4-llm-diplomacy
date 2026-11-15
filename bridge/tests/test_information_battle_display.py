"""Narrow regression tests for the fixed-build battle display bindings.

The land seq3 and naval seq8 payloads are the real batch-33 container
fixtures.  These tests inspect copied GUI inputs and public service delivery;
popup rendering remains independently unverified. Battle roles use the
fixed-build combat schema and copied participant identities.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.battle_display import project_display
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
    return fixture, decoded, project_display(decoded, template)


def _controls(display: dict) -> dict[str, dict]:
    assert display["status"] == "known"
    return {item["template_key"]: item for item in display["value"]["controls"]}


def _pair(template: dict, key: str) -> dict:
    return next(
        item for item in template["value"]["pairs"]
        if item["key"].get("value") == key
    )


@pytest.mark.parametrize(
    ("name", "expected_kind", "expected_unbound", "checks"),
    [
        (
            LAND_FIXTURE,
            "land",
            [0, 1, 2, 3, 4, 29, 30],
            {
                "OURCAVSTART": ("Our_unit_type_1_1_text", 11, "4,000"),
                "OURLEADER": ("OurLeader", 23, "托马斯 亨克尔"),
                "OURPRESTIGE": ("our_prestige", 5, "§G+0.20"),
            },
        ),
        (
            NAVAL_FIXTURE,
            "naval",
            [0, 1, 2, 3, 4, 23, 24, 29, 35, 37, 38],
            {
                "OURTRANSSTART": ("Our_unit_type_1_4_text", 14, "0"),
                "OURTRANSLOST": ("Our_unit_type_2_4_text", 18, "0"),
                "OURTRANSEND": ("Our_unit_type_3_4_text", 22, "0"),
                "ENEMYTRANSSTART": ("Enemy_unit_type_4_1_text", 42, "7"),
                "ENEMYLEADER": ("EnemyLeader", 31, "修罗 埃米尔"),
            },
        ),
    ],
)
def test_real_batch33_bindings_keep_ordered_inputs_and_direct_text(
    name: str, expected_kind: str, expected_unbound: list[int], checks: dict,
) -> None:
    _fixture, decoded, display = _load(name)
    value = display["value"]
    controls = _controls(display)

    assert value["battle_type"] == expected_kind
    assert value["unbound_pair_indexes"] == expected_unbound
    assert value["selected_layout"] == {
        "status": "unknown", "reason": "RUNTIME_LAYOUT_NOT_CAPTURED",
    }
    assert value["side_identity"]["status"] == "known"
    assert value["side_identity"]["value"]["observer_template_label"] == {
        "status": "unknown", "reason": "TEMPLATE_OBSERVER_SIDE_UNRESOLVED",
    }
    assert value["side_identity"]["value"]["attack_defend_roles"] == {
        "status": "known", "value": {"attacker": 0, "defender": 1},
    }
    assert value["full_display_complete"] is False
    assert value["runtime_popup_verified"] is False

    pairs_by_index = {
        pair["index"]: pair
        for pair in project_template(decoded)["value"]["pairs"]
    }
    for key, (widget, pair_index, text) in checks.items():
        control = controls[key]
        assert control.get("widget", control.get("control_path")) == widget
        assert len(control["inputs"]) == 1
        input_item = control["inputs"][0]
        assert input_item["pair_index"] == pair_index
        assert input_item["value_raw_hex"] == pairs_by_index[pair_index]["value_raw_hex"]
        assert input_item["decoded"] == {"status": "known", "value": text}
        assert control["display_text"] == {"status": "known", "value": text}

    for control in value["controls"]:
        assert "template_key" in control
        assert "value_kind" in control
        assert "layout" in control
        assert "widget" in control or "control_path" in control
        assert isinstance(control["inputs"], list)
        for input_item in control["inputs"]:
            assert set(input_item) == {"pair_index", "value_raw_hex", "decoded"}
            assert input_item["pair_index"] in pairs_by_index
        if "condition" in control:
            assert isinstance(control["condition"], str)

    provenance = value["binding_provenance"]
    assert provenance["game_version"] == "1.37.4"
    assert provenance["exe_sha256"] == GAME_SHA256


def test_real_fixtures_keep_missing_title_capture_unknown_and_non_text_controls() -> None:
    _land_fixture, _land_decoded, land_display = _load(LAND_FIXTURE)
    _naval_fixture, _naval_decoded, naval_display = _load(NAVAL_FIXTURE)

    land = _controls(land_display)
    naval = _controls(naval_display)
    assert land["WINORLOSE"]["display_text"] == {
        "status": "unknown", "reason": "TEMPLATE_KEY_NOT_CAPTURED",
    }
    assert naval["WINORLOSE"]["display_text"] == {
        "status": "unknown", "reason": "TEMPLATE_KEY_NOT_CAPTURED",
    }
    assert naval["CAPTURE"]["display_text"] == {
        "status": "unknown", "reason": "TEMPLATE_KEY_NOT_CAPTURED",
    }

    assert land["ENEMYLOST"]["value_kind"] == "formatted_text"
    assert land["ENEMYLOST"]["inputs"][0]["decoded"] == {
        "status": "known", "value": "-3,000",
    }
    assert land["ENEMYLOST"]["display_text"] == {
        "status": "unsupported", "reason": "CONTROL_FORMAT_OUTPUT_NOT_CAPTURED",
    }
    assert land["OURFIRE"]["display_text"] == {
        "status": "unsupported", "reason": "CONTROL_INPUT_IS_NOT_FINAL_TEXT",
    }
    assert land["OURLEADERICON"]["display_text"] == {
        "status": "unsupported", "reason": "CONTROL_INPUT_IS_NOT_FINAL_TEXT",
    }
    assert land["OURFLAG"]["control_path"] == [
        "our_side_shield_list", "diplo_shield_item", "shield",
    ]
    assert land["OURFLAG"]["display_text"] == {
        "status": "unsupported", "reason": "CONTROL_INPUT_IS_NOT_FINAL_TEXT",
    }
    assert land["OURLEADER"]["condition"] == "definition_field_0x5c != 0"


def test_display_preserves_empty_text_duplicate_occurrences_and_bad_raw_text() -> None:
    _fixture, decoded, _display = _load(LAND_FIXTURE)
    template = project_template(decoded)
    controls = _controls(project_display(decoded, template))

    # Empty native text is a known direct string and remains visible as empty.
    assert controls["ENEMYLEADER"]["inputs"][0]["decoded"] == {
        "status": "known", "value": "",
    }
    assert controls["ENEMYLEADER"]["display_text"] == {
        "status": "known", "value": "",
    }

    duplicate_template = deepcopy(template)
    duplicate = deepcopy(_pair(duplicate_template, "OURLEADER"))
    duplicate["index"] = max(
        pair["index"] for pair in duplicate_template["value"]["pairs"]
    ) + 1
    duplicate_template["value"]["pairs"].append(duplicate)
    duplicate_control = _controls(project_display(decoded, duplicate_template))["OURLEADER"]
    assert [item["pair_index"] for item in duplicate_control["inputs"]] == [23, 47]
    assert duplicate_control["inputs"][0]["value_raw_hex"] == "105862106c9a10af652010a84e104b51121453"
    assert duplicate_control["inputs"][1]["value_raw_hex"] == duplicate_control["inputs"][0]["value_raw_hex"]
    assert duplicate_control["display_text"] == {
        "status": "unknown", "reason": "DUPLICATE_TEMPLATE_KEY_EFFECT_UNRESOLVED",
    }

    bad_template = deepcopy(template)
    bad = _pair(bad_template, "OURLEADER")
    bad["value_raw_hex"] = "10e3"
    bad["value"] = {"status": "unknown", "reason": "BATTLE_TEXT_DECODE_FAILED"}
    bad_control = _controls(project_display(decoded, bad_template))["OURLEADER"]
    assert bad_control["inputs"] == [{
        "pair_index": 23,
        "value_raw_hex": "10e3",
        "decoded": {"status": "unknown", "reason": "BATTLE_TEXT_DECODE_FAILED"},
    }]
    assert bad_control["display_text"] == {
        "status": "unknown", "reason": "BATTLE_TEXT_DECODE_FAILED",
    }


@pytest.mark.parametrize(
    ("name", "observer", "message_id"),
    [(LAND_FIXTURE, "FRA", "3"), (NAVAL_FIXTURE, "KEL", "8")],
)
def test_information_service_query_report_subscription_share_display_projection9(
    tmp_path: Path, name: str, observer: str, message_id: str,
) -> None:
    fixture, decoded, _display_without_observer = _load(name)
    expected_display = project_display(
        decoded,
        project_template(decoded),
        observer_ref=int(fixture["recorded_observer_ref"], 16),
    )
    source, _primary, fixture, _stream_db, _payload = make_source(
        tmp_path,
        fixture=fixture,
        observer=observer,
        message_ids=(message_id,),
    )
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    selected = event_id(fixture, message_id)
    query = battle_topic_query(
        "B04", ["details", "raw_text"], selected_event=selected,
    )
    try:
        direct = service.query(f"display-query-{message_id}", queries=[query])
        direct_item = direct["items"][0]
        assert direct_item["source"]["projection_version"] == 30
        assert direct_item["fields"]["details"]["value"]["display"] == expected_display
        assert direct_item["fields"]["raw_text"] == {
            "status": "unknown", "reason": "NATIVE_LINE1_NOT_CAPTURED_BY_LEGACY_WIRE",
            "unit": "native_text_sections",
        }

        report = tools.call(
            "information_manage_report",
            {
                "request_id": f"display-report-{message_id}",
                "operation": "create",
                "config": {
                    "name": f"batch33 display {message_id}",
                    "detail": "full",
                    "queries": [query],
                },
            },
        )["report"]
        tools.call(
            "information_manage_subscription",
            {
                "request_id": f"display-subscription-{message_id}",
                "operation": "create",
                "config": {
                    "name": f"batch33 display events {message_id}",
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
        assert event_item["fields"]["details"]["value"]["display"] == expected_display
        assert event_item["fields"]["raw_text"] == {
            "status": "unknown", "reason": "NATIVE_LINE1_NOT_CAPTURED_BY_LEGACY_WIRE",
            "unit": "native_text_sections",
        }
        assert tools.call("information_tick", {"view": "full"})["results"] == []
    finally:
        service.close()
