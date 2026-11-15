"""Offline v8 raw-ingest and public battle adapter integration."""
from __future__ import annotations

from copy import deepcopy
import hashlib

from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_display_context_integration import (
    _v7_fixture,
)
from bridge.tests.test_information_battles import (
    battle_topic_query,
    event_id,
    make_source,
)
from work import information_battle_display_context_wire as display_wire
from work import information_battle_name_handoff_wire as name_wire
from work.ingest_information_battle_raw_live import (
    _decode_payload,
    ingest_live_raw,
)
from work.test_ingest_information_battle_raw_live import (
    Fixture as RawFixture,
    fragment_line,
)


GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)


def _v8_fixture() -> tuple[dict, bytes, bytes]:
    fixture, _payload_v6, payload_v7 = _v7_fixture()
    decoded = display_wire.decode(payload_v7)
    observation = decoded["observation"]
    result = observation["result"]
    snapshot = {
        "state": "known",
        "sequence": observation["sequence"],
        "raw_date": result["raw_date"],
        "kind": decoded["context"]["kind"],
        "raw_bytes": b"NAME",
    }
    payload_v8 = name_wire.encode(payload_v7, snapshot)
    result_fixture = deepcopy(fixture)
    result_fixture["payload_hex"] = payload_v8.hex()
    result_fixture["provenance"]["payload_sha256"] = hashlib.sha256(
        payload_v8
    ).hexdigest()
    result_fixture["provenance"]["real_capture"] = False
    result_fixture["provenance"]["synthetic_extension"] = True
    result_fixture["provenance"]["source_mode"] = (
        "synthetic_v8_name_handoff_over_v7_display_context"
    )
    result_fixture["synthetic_name_handoff_extension"] = True
    return result_fixture, payload_v7, payload_v8


def _details_query(selected: str) -> dict:
    return battle_topic_query("B04", ["details", "raw_text"],
                               selected_event=selected)


def test_v8_raw_ingest_reopen_and_b04_query_report_event_preserve_raw_text(
        tmp_path,
):
    fixture, payload_v7, payload_v8 = _v8_fixture()
    version, decoded = _decode_payload(payload_v8)
    assert version == 8
    assert decoded["wire8"]["version"] == 8
    assert decoded["name_handoff"]["raw_hex"] == b"NAME".hex()

    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    raw_fixture = RawFixture(
        raw_root,
        log_body=fragment_line(payload_v8, message_id=81, sequence=1, index=0),
    )
    first = ingest_live_raw(
        raw_fixture.installation,
        raw_fixture.database,
        raw_fixture.output("first.json"),
    )
    assert first["status"] == "passed"
    assert first["source"]["payload_dispatch"]["supported_observation_versions"] == list(range(1, 16))
    assert first["messages"][0]["decode"]["status"] == "decoded_raw_name_handoff"
    assert first["messages"][0]["raw_payload_hex"] == payload_v8.hex()
    assert first["messages"][0]["decode"]["value"]["name_handoff"]["source_name"] == (
        "owned_name_handoff"
    )

    reopened = ingest_live_raw(
        raw_fixture.installation,
        raw_fixture.database,
        raw_fixture.output("reopen.json"),
    )
    assert reopened["status"] == "passed"
    assert reopened["transport"]["received_count"] == first["transport"]["received_count"] == 1
    assert reopened["messages"][0]["payload_sha256"] == first["messages"][0]["payload_sha256"]
    assert reopened["messages"][0]["decode"]["value"]["name_handoff"]["raw_hex"] == "4e414d45"

    selected = event_id(fixture, "81")
    v7_fixture = deepcopy(fixture)
    v7_fixture["payload_hex"] = payload_v7.hex()
    v7_fixture["provenance"]["payload_sha256"] = hashlib.sha256(
        payload_v7
    ).hexdigest()
    v7_dir = tmp_path / "v7-source"
    v7_dir.mkdir()
    v7_source, _v7_primary, _v7_fixture_value, _v7_db, _v7_payload = make_source(
        v7_dir,
        fixture=v7_fixture,
        observer="FRA",
        message_ids=("81",),
    )
    v7_result = v7_source.read(_details_query(selected), v7_source.context())

    v8_dir = tmp_path / "v8-source"
    v8_dir.mkdir()
    source, _primary, _fixture_value, _stream_db, _stored_payload = make_source(
        v8_dir,
        fixture=fixture,
        observer="FRA",
        message_ids=("81",),
    )
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    try:
        direct = source.read(_details_query(selected), source.context())
        details = direct["fields"]["details"]["value"]
        assert details["name_handoff"]["state"] == "known"
        assert details["name_handoff"]["raw_hex"] == "4e414d45"
        assert details["name_handoff"]["source_name"] == "owned_name_handoff"
        assert direct["fields"]["raw_text"] == v7_result["fields"]["raw_text"]
        assert direct["source"]["name"] == "IBOW.v8"
        assert direct["source"]["projection_version"] == 30
        service_raw_text = {
            **direct["fields"]["raw_text"],
            "unit": "native_text_sections",
        }

        queried = service.query(
            "v8-name-query", queries=[_details_query(selected)]
        )["items"][0]
        assert queried["fields"]["details"]["value"]["name_handoff"] == (
            details["name_handoff"]
        )
        assert queried["fields"]["raw_text"] == service_raw_text

        report = tools.call("information_manage_report", {
            "request_id": "v8-name-report",
            "operation": "create",
            "config": {
                "name": "v8 name handoff",
                "detail": "full",
                "queries": [battle_topic_query("B04", ["details", "raw_text"])],
            },
        })["report"]
        subscription = tools.call("information_manage_subscription", {
            "request_id": "v8-name-event",
            "operation": "create",
            "config": {
                "name": "v8 name handoff event",
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
        })["subscription"]
        assert subscription["state"] == "active"
        tick = tools.call("information_tick", {"view": "full"})
        assert len(tick["results"]) == 1
        delivered = tick["results"][0]
        assert delivered["items"][0]["fields"]["details"]["value"]["name_handoff"] == (
            details["name_handoff"]
        )
        assert delivered["items"][0]["fields"]["raw_text"] == service_raw_text
        assert delivered["complete"] is False
    finally:
        service.close()
