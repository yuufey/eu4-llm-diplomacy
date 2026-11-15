"""Narrow offline regression for the v27 formatter-container captures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battles import (
    battle_topic_query,
    event_id,
    make_source,
)
from bridge.information.battle_text import project_template
from work.information_battle_template_wire import decode as decode_template


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "bridge" / "tests" / "fixtures"
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
FIRST_KEYS = [
    "4d4f4e415243484e414d45",
    "46554c4c4d4f4e415243484e414d45",
    "434f554e545259",
    "4d4f4e415243485449544c45",
    "41435455414c4d4f4e415243485449544c45",
]


def _load_fixture(name: str) -> dict:
    fixture = json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
    assert fixture["mode"] == "recorded"
    assert fixture["provenance"]["game_version"] == "1.37.4"
    assert fixture["provenance"]["game_sha256"] == GAME_SHA256
    assert fixture["provenance"]["real_capture"] is True
    assert fixture["provenance"]["synthetic_extension"] is False
    assert fixture["provenance"]["template_present"] is True
    assert fixture["context_date"] == 56557728
    return fixture


def _tags(full_refs: list[int]) -> list[str]:
    return [int(ref).to_bytes(8, "little")[:3].decode("ascii") for ref in full_refs]


@pytest.mark.parametrize(
    ("name", "pair_count", "result_tags"),
    [
        (
            "information_battle_FRA_live_container_v4_1374.json",
            47,
            ["FRA", "HSA"],
        ),
        (
            "information_battle_naval_seq8_live_container_v4_1374.json",
            51,
            ["PSA", "KEL"],
        ),
    ],
)
def test_real_container_fixtures_are_exact_v4_and_keep_ordered_por_payload(
    name: str, pair_count: int, result_tags: list[str]
) -> None:
    fixture = _load_fixture(name)
    raw = bytes.fromhex(fixture["payload_hex"])
    assert hashlib.sha256(raw).hexdigest() == fixture["provenance"]["payload_sha256"]

    decoded = decode_template(raw)
    assert decoded["wire"]["version"] == 4
    assert decoded["wire"]["extension_version"] == 2
    assert decoded["wire"]["template_present"] is True
    message = decoded["message_template"]
    assert message["source_kind"] == "formatter_container_before_cleanup"
    assert message["message_metadata_present"] is False
    assert message["auxiliary_text_hex"] is None
    assert message["pair_count"] == pair_count
    assert [pair["key_raw_hex"] for pair in message["pairs"][:5]] == FIRST_KEYS
    assert _tags([side["country"] for side in decoded["observation"]["result"]["sides"]]) == result_tags

    projected = project_template(decoded)
    assert projected["status"] == "known"
    value = projected["value"]
    assert value["source_kind"] == "formatter_container_before_cleanup"
    assert value["message_metadata_present"] is False
    assert value["pair_count"] == pair_count
    assert value["auxiliary_text"] == {
        "status": "unsupported",
        "reason": "MESSAGE_METADATA_NOT_CAPTURED",
    }
    assert [pair["key_raw_hex"] for pair in value["pairs"]] == [
        pair["key_raw_hex"] for pair in message["pairs"]
    ]
    assert value["pairs"][0]["value"] == {"status": "known", "value": "阿方索 V"}
    assert value["pairs"][1]["value"] == {
        "status": "known", "value": "阿方索 V 德 阿维斯"
    }
    assert value["pairs"][2]["value"] == {"status": "known", "value": "葡萄牙"}


def test_fra_query_report_subscription_share_seq3_container_record(tmp_path: Path) -> None:
    fixture = _load_fixture("information_battle_FRA_live_container_v4_1374.json")
    source, _primary, _fixture, _stream_db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("3",)
    )
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    selected = event_id(fixture, "3")
    query = battle_topic_query("B04", ["details"], selected_event=selected)
    try:
        direct = service.query("fra-container-query", queries=[query])
        direct_item = direct["items"][0]
        assert direct_item["source"]["payload_sha256"] == fixture["provenance"]["payload_sha256"]
        direct_template = direct_item["fields"]["details"]["value"]["message_template"]
        assert direct_template["status"] == "known"
        assert direct_template["value"]["pair_count"] == 47
        assert direct_template["value"]["message_metadata_present"] is False
        assert direct_template["value"]["auxiliary_text"] == {
            "status": "unsupported",
            "reason": "MESSAGE_METADATA_NOT_CAPTURED",
        }

        report = tools.call(
            "information_manage_report",
            {
                "request_id": "fra-container-report-create",
                "operation": "create",
                "config": {
                    "name": "seq3 FRA formatter container",
                    "detail": "full",
                    "queries": [query],
                },
            },
        )["report"]
        assert report["queries"][0]["parameters"]["event_id"] == selected

        tools.call(
            "information_manage_subscription",
            {
                "request_id": "fra-container-subscription-create",
                "operation": "create",
                "config": {
                    "name": "seq3 FRA formatter container events",
                    "kind": "event",
                    "report_id": report["id"],
                    "enabled": True,
                    "binding": {
                        "session_id": fixture["provenance"]["session_id"],
                        "observer": "FRA",
                        "game_version": "1.37.4",
                        "game_sha256": GAME_SHA256,
                    },
                    "event": {"types": ["battle_observation"]},
                },
            },
        )
        tick = tools.call("information_tick", {"view": "full"})
        assert len(tick["results"]) == 1
        result = tick["results"][0]
        assert result["event"]["event_id"] == selected
        assert result["items"][0]["source"]["payload_sha256"] == fixture["provenance"]["payload_sha256"]
        result_template = result["items"][0]["fields"]["details"]["value"]["message_template"]
        assert result_template["status"] == "known"
        assert result_template["value"]["pair_count"] == 47
    finally:
        service.close()


def test_naval_seq8_container_pairs_mapping_and_public_projection(tmp_path: Path) -> None:
    fixture = _load_fixture("information_battle_naval_seq8_live_container_v4_1374.json")
    source, _primary, _fixture, _stream_db, _payload = make_source(
        tmp_path, fixture=fixture, observer="KEL", message_ids=("8",)
    )
    selected = event_id(fixture, "8")

    details_result = source.read(
        battle_topic_query("B04", ["details"], selected_event=selected), source.context()
    )
    details = details_result["fields"]["details"]["value"]["message_template"]
    assert details["status"] == "known"
    assert details["value"]["source_kind"] == "formatter_container_before_cleanup"
    assert details["value"]["pair_count"] == 51
    assert details["value"]["message_metadata_present"] is False
    assert details["value"]["auxiliary_text"] == {
        "status": "unsupported",
        "reason": "MESSAGE_METADATA_NOT_CAPTURED",
    }
    assert [pair["key_raw_hex"] for pair in details["value"]["pairs"][:5]] == FIRST_KEYS

    b01 = source.read(
        battle_topic_query("B01", ["sides", "battle_type"], selected_event=selected),
        source.context(),
    )
    sides = b01["fields"]["sides"]["value"]
    assert [side["representative"] for side in sides] == ["PSA", "KEL"]
    assert [side["combat_side_index"] for side in sides] == [1, 0]
    assert [side["observer_participated"] for side in sides] == [False, True]
    assert b01["fields"]["battle_type"] == {"status": "known", "value": "naval"}

    b02 = source.read(
        battle_topic_query(
            "B02",
            ["initial_forces", "losses", "remaining_forces", "unit_breakdown"],
            selected_event=selected,
        ),
        source.context(),
    )
    initial = b02["fields"]["initial_forces"]["value"]["sides"]
    assert [side["participants"] for side in initial] == [["KEL"], ["PSA"]]
    assert initial[0]["by_unit"] == {
        "galley": 0,
        "heavy_ship": 0,
        "light_ship": 3,
        "transport": 0,
    }
    assert initial[1]["by_unit"] == {
        "galley": 9,
        "heavy_ship": 0,
        "light_ship": 0,
        "transport": 7,
    }
    losses = b02["fields"]["losses"]["value"]["sides"]
    assert losses[0]["by_unit"]["light_ship"] == -3
    assert losses[1]["by_unit"]["light_ship"] == 0
    remaining = b02["fields"]["remaining_forces"]["value"]["sides"]
    assert remaining[0]["component_sum"] == 0
    assert remaining[1]["component_sum"] == 16
