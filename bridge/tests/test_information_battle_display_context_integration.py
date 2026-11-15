"""Offline v7 display-context integration through the public battle adapter."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import struct

import pytest

from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_native_text import _v6_fixture
from bridge.tests.test_information_battles import (
    battle_topic_query,
    event_id,
    make_source,
)
from work import information_battle_display_context_wire as display_wire
from work import information_battle_native_text_wire as native_wire
from work.ingest_information_battle_raw_live import RawIngestError, _decode_payload


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def _v7_fixture(*, sequence_delta: int = 0) -> tuple[dict, bytes, bytes]:
    fixture, _base_v5, payload_v6 = _v6_fixture()
    base = native_wire.decode(payload_v6)
    observation = base["observation"]
    result = observation["result"]
    kind = base["context"]["kind"]
    key = {1: b"LANDBATTLEOVER", 2: b"NAVALBATTLEOVER"}[kind]
    snapshot = {
        "state": "observed",
        "capture_stage": 3,
        "failure": 0,
        "sequence": observation["sequence"] + sequence_delta,
        "raw_date": result["raw_date"],
        "battle_kind": kind,
        "popup_kind_raw": 0,
        "layout_raw": 1,
        "button_flag_raw": 1,
        "fields": {
            "definition_key": {"state": "observed", "raw_bytes": key},
            "language": {"state": "observed", "raw_bytes": b"l_english"},
            "body_template": {"state": "observed", "raw_bytes": b"$NAME$"},
            "button1": {"state": "observed", "raw_bytes": b"OK"},
            "button2": {"state": "observed", "raw_bytes": b""},
            "button3": {"state": "absent"},
            "compact_losses_template": {"state": "unknown"},
        },
    }
    payload_v7 = display_wire.encode(payload_v6, snapshot)
    result_fixture = deepcopy(fixture)
    result_fixture["payload_hex"] = payload_v7.hex()
    result_fixture["context_date"] = max(
        int(result_fixture["context_date"]), result["raw_date"],
    )
    provenance = result_fixture["provenance"]
    provenance["payload_sha256"] = hashlib.sha256(payload_v7).hexdigest()
    provenance["real_capture"] = False
    provenance["synthetic_extension"] = True
    provenance["source_mode"] = "synthetic_v7_context_over_recorded_fra_v6"
    result_fixture["synthetic_display_context_extension"] = True
    return result_fixture, payload_v6, payload_v7


def _query(selected: str) -> dict:
    return battle_topic_query("B04", ["details", "raw_text"], selected_event=selected)


def test_fra_v7_context_flows_through_query_event_subscription_and_legacy6_shape(tmp_path):
    fixture, payload_v6, payload_v7 = _v7_fixture()
    selected = event_id(fixture, "74")

    legacy_fixture = deepcopy(fixture)
    legacy_fixture["payload_hex"] = payload_v6.hex()
    legacy_dir = tmp_path / "legacy-v6"
    legacy_dir.mkdir()
    legacy_source, _primary, _fixture, _db, _payload = make_source(
        legacy_dir, fixture=legacy_fixture, observer="FRA", message_ids=("74",),
    )
    legacy_result = legacy_source.read(_query(selected), legacy_source.context())
    legacy_service = InformationService(
        legacy_source, tmp_path / "legacy-information.sqlite3",
    )
    try:
        legacy_item = legacy_service.query("fra-v6-query", queries=[_query(selected)])["items"][0]
    finally:
        legacy_service.close()

    v7_dir = tmp_path / "v7"
    v7_dir.mkdir()
    source, _primary, fixture, _stream_db, stored_payload = make_source(
        v7_dir, fixture=fixture, observer="FRA", message_ids=("74",),
    )
    assert stored_payload == payload_v7
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    provenance = fixture["provenance"]
    try:
        queried = service.query("fra-v7-query", queries=[_query(selected)])
        item = queried["items"][0]
        v7_result = item
        legacy_details = legacy_result["fields"]["details"]["value"]
        v7_details = v7_result["fields"]["details"]["value"]
        v7_direct = source.read(_query(selected), source.context())
        v7_direct_details = v7_direct["fields"]["details"]["value"]
        context = v7_details["display_context"]

        assert item["source"]["name"] == "IBOW.v7"
        assert item["source"]["projection_version"] == 30
        assert item["source"]["payload_sha256"] == hashlib.sha256(payload_v7).hexdigest()
        assert context["status"] == "known"
        assert context["state"] == "observed"
        assert context["battle_kind"] in (1, 2)
        assert context["popup_kind_raw"] == 0
        assert context["matches_formatter_kind"] is False
        assert context["text_fields"]["body_template"]["decoded"] == {
            "status": "known", "value": "$NAME$",
        }
        assert context["text_fields"]["button2"]["decoded"] == {
            "status": "known", "value": "",
        }
        assert context["text_fields"]["button3"]["status"] == "absent"
        assert context["full_display_complete"] is False
        assert context["runtime_popup_verified"] is False
        assert context["visibility_verified"] is False

        assert "display_context" not in legacy_details
        assert legacy_result["fields"]["raw_text"] == v7_direct["fields"]["raw_text"]
        assert legacy_item["fields"]["raw_text"] == v7_result["fields"]["raw_text"]
        assert legacy_details["native_text"] == v7_details["native_text"]
        comparable_v7_details = dict(v7_direct_details)
        del comparable_v7_details["display_context"]
        del comparable_v7_details["display_composition"]
        assert comparable_v7_details.pop("result_text")["content_scope"] == "configured_result_text_sections"
        assert comparable_v7_details == legacy_details

        sides = source.read(
            battle_topic_query("B01", ["sides"], selected_event=selected),
            source.context(),
        )["fields"]["sides"]["value"]
        assert len(sides) == 2
        assert all(side["participants_complete"] is True for side in sides)
        assert any(
            side["observer_participated"] is True and "FRA" in side["participants"]
            for side in sides
        )

        report = tools.call("information_manage_report", {
            "request_id": "fra-v7-display-report",
            "operation": "create",
            "config": {
                "name": "FRA v7 display-context report",
                "detail": "full",
                "queries": [battle_topic_query("B04", ["details", "raw_text"])],
            },
        })["report"]
        subscription = tools.call("information_manage_subscription", {
            "request_id": "fra-v7-display-subscription",
            "operation": "create",
            "config": {
                "name": "FRA v7 battle event delivery",
                "kind": "event",
                "report_id": report["id"],
                "enabled": True,
                "binding": {
                    "session_id": provenance["session_id"],
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
        assert delivered["event"]["event_id"] == selected
        participants = delivered["event"]["payload"]["participant_countries"]
        assert "FRA" in participants
        assert delivered["items"][0]["fields"]["details"]["value"]["display_context"] == context
        assert delivered["items"][0]["fields"]["raw_text"] == item["fields"]["raw_text"]
        assert delivered["complete"] is False
    finally:
        service.close()


def test_v7_context_identity_mismatch_is_local_and_raw_ingest_rejects_bad_frame(tmp_path):
    fixture, payload_v6, payload_v7 = _v7_fixture(sequence_delta=1)
    selected = event_id(fixture, "75")
    legacy_fixture = deepcopy(fixture)
    legacy_fixture["payload_hex"] = payload_v6.hex()
    legacy_dir = tmp_path / "legacy-v6"
    legacy_dir.mkdir()
    legacy_source, _primary, _fixture, _db, _payload = make_source(
        legacy_dir, fixture=legacy_fixture, observer="FRA", message_ids=("75",),
    )
    legacy = legacy_source.read(_query(selected), legacy_source.context())

    v7_dir = tmp_path / "v7"
    v7_dir.mkdir()
    source, _primary, fixture, _db, _payload = make_source(
        v7_dir, fixture=fixture, observer="FRA", message_ids=("75",),
    )
    mismatch = source.read(_query(selected), source.context())
    assert mismatch["fields"]["details"]["status"] == "known"
    mismatch_details = mismatch["fields"]["details"]["value"]
    assert mismatch_details["display_context"]["status"] == "unknown"
    assert mismatch_details["display_context"]["reason"] == (
        "DISPLAY_CONTEXT_EVENT_IDENTITY_MISMATCH"
    )
    comparable_mismatch_details = dict(mismatch_details)
    del comparable_mismatch_details["display_context"]
    assert comparable_mismatch_details.pop("display_composition")["status"] == "unknown"
    assert comparable_mismatch_details.pop("result_text")["status"] == "unknown"
    assert comparable_mismatch_details == legacy["fields"]["details"]["value"]
    assert mismatch["fields"]["raw_text"] == legacy["fields"]["raw_text"]
    assert mismatch["fields"]["details"]["value"]["message_template"]["status"] == "known"
    assert native_wire.decode(payload_v6)["wire6"]["version"] == 6

    version, decoded = _decode_payload(payload_v7)
    assert version == 7
    assert decoded["wire7"]["version"] == 7

    malformed = bytearray(payload_v7)
    base_length = struct.unpack_from("<I", malformed, 6)[0]
    extension = 10 + base_length
    body = extension + 10
    first_field_id = body + display_wire.FIXED_BODY_BYTES
    malformed[first_field_id] = 2
    with pytest.raises(RawIngestError, match="v7_payload_rejected:field_id_or_order_mismatch"):
        _decode_payload(bytes(malformed))
