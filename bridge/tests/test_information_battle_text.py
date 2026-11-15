"""Public projections for the recorded v4 message-template extension.

These tests use the existing recorded v3 payload and a clearly synthetic BTXT
envelope.  They verify that copied native inputs remain bounded, ordered and
raw while the public layer applies the explicitly configured EU4 escape codec.
They do not claim a rendered popup or a live game observation.
"""

from __future__ import annotations

from copy import deepcopy
import struct

from bridge.information.battle_text import project_template
from bridge.information import InformationService
from bridge.tests.test_information_battles import (
    event_id,
    load_naval_fixture,
    make_source,
    make_naval_v3_payload,
    battle_topic_query,
)
from bridge.information.tools import InformationTools
from work.information_battle_naval_wire import decode as decode_naval
from work.information_battle_template_wire import decode as decode_template


CHINESE_KEY = bytes.fromhex("10e389103e6510fa8b10fc6610955e")


def _message_body(*, native_date: int, pairs: list[tuple[bytes, bytes]],
                  auxiliary: bytes = b"", flag_8c: int = 0xa1,
                  flag_8d: int = 0x5e, header_word: int = 0xfeedbeef,
                  header_flag: int = 0x7a) -> bytes:
    body = struct.pack(
        "<iBBIBII", native_date, flag_8c, flag_8d, header_word,
        header_flag, len(pairs), len(auxiliary),
    ) + auxiliary
    for key, value in pairs:
        body += struct.pack("<I", len(key)) + key
        body += struct.pack("<I", len(value)) + value
    return body


def _v4_frame(base_v3: bytes, *, native_date: int, pairs: list[tuple[bytes, bytes]],
              auxiliary: bytes = b"", present: bool = True) -> bytes:
    result = b"IBOW" + struct.pack("<HI", 4, len(base_v3)) + base_v3
    if not present:
        return result + b"\x00"
    body = _message_body(native_date=native_date, pairs=pairs, auxiliary=auxiliary)
    return (result + b"\x01BTXT" + struct.pack("<HI", 1, len(body)) + body)


def _v4_container_frame(base_v3: bytes, *, raw_word: int,
                        raw_flag: int,
                        pairs: list[tuple[bytes, bytes]]) -> bytes:
    body = struct.pack("<BIBI", 2, raw_word, raw_flag, len(pairs))
    for key, value in pairs:
        body += struct.pack("<I", len(key)) + key
        body += struct.pack("<I", len(value)) + value
    return (b"IBOW" + struct.pack("<HI", 4, len(base_v3)) + base_v3
            + b"\x01BTXT" + struct.pack("<HI", 2, len(body)) + body)


def _synthetic_v4(*, date_delta: int = 0, pairs=None) -> tuple[dict, bytes, bytes]:
    fixture = load_naval_fixture()
    base = make_naval_v3_payload(fixture)
    decoded = decode_naval(base)
    raw_date = decoded["observation"]["result"]["raw_date"]
    if pairs is None:
        pairs = [
            (CHINESE_KEY, b"good"),
            (b"duplicate", CHINESE_KEY),
            (b"duplicate", b"last"),
        ]
    payload = _v4_frame(
        base, native_date=raw_date + date_delta, pairs=pairs,
        auxiliary=CHINESE_KEY,
    )
    v4_fixture = deepcopy(fixture)
    v4_fixture["payload_hex"] = payload.hex()
    return v4_fixture, base, payload


def _template_from_payload(payload: bytes) -> dict:
    decoded = decode_template(payload)
    assert decoded["wire"]["version"] == 4
    return decoded


def test_project_template_preserves_order_duplicates_rawhex_and_explicit_codec():
    fixture, _base, payload = _synthetic_v4()
    decoded = _template_from_payload(payload)
    projected = project_template(decoded)

    assert projected["status"] == "known"
    value = projected["value"]
    assert value["basis"] == "copied_native_message_template_inputs"
    assert value["full_display_complete"] is False
    assert value["runtime_popup_verified"] is False
    assert [pair["index"] for pair in value["pairs"]] == [0, 1, 2]
    assert [pair["key_raw_hex"] for pair in value["pairs"]] == [
        CHINESE_KEY.hex(), b"duplicate".hex(), b"duplicate".hex(),
    ]
    assert value["pairs"][0]["key"] == {
        "status": "known", "value": "解放诺曼底",
    }
    assert value["pairs"][1]["value"] == {
        "status": "known", "value": "解放诺曼底",
    }
    assert value["pairs"][2]["value"] == {
        "status": "known", "value": "last",
    }
    assert value["auxiliary_text"]["raw_hex"] == CHINESE_KEY.hex()
    assert value["auxiliary_text"]["decoded"] == {
        "status": "known", "value": "解放诺曼底",
    }
    assert fixture["mode"] == "recorded"


def test_bad_field_codec_is_unknown_without_erasing_raw_bytes():
    _fixture, _base, payload = _synthetic_v4(
        pairs=[(b"good", b"ok"), (b"bad", bytes.fromhex("10e3"))],
    )
    decoded = _template_from_payload(payload)
    projected = project_template(decoded)
    pairs = projected["value"]["pairs"]
    assert pairs[0]["value"] == {"status": "known", "value": "ok"}
    assert pairs[1]["value"] == {
        "status": "unknown", "reason": "BATTLE_TEXT_DECODE_FAILED",
    }
    assert pairs[1]["value_raw_hex"] == "10e3"


def test_formatter_container_projection_keeps_metadata_unavailable_and_order():
    fixture, base, _payload = _synthetic_v4()
    base_decoded = decode_naval(base)
    payload = _v4_container_frame(
        base,
        raw_word=0x10203040,
        raw_flag=0x91,
        pairs=[(CHINESE_KEY, b"value"), (CHINESE_KEY, b"last")],
    )
    decoded = _template_from_payload(payload)
    projected = project_template(decoded)

    assert projected["status"] == "known"
    value = projected["value"]
    assert value["source_kind"] == "formatter_container_before_cleanup"
    assert value["message_metadata_present"] is False
    assert value["native_date"] is None
    assert value["raw_flag_8c"] is None
    assert value["raw_flag_8d"] is None
    assert value["raw_container_word_10"] == 0x10203040
    assert value["raw_container_flag_14"] == 0x91
    assert value["pair_count"] == 2
    assert [pair["index"] for pair in value["pairs"]] == [0, 1]
    assert [pair["key_raw_hex"] for pair in value["pairs"]] == [
        CHINESE_KEY.hex(), CHINESE_KEY.hex(),
    ]
    assert value["pairs"][0]["key"] == {
        "status": "known", "value": "解放诺曼底",
    }
    assert value["auxiliary_text"] == {
        "status": "unsupported", "reason": "MESSAGE_METADATA_NOT_CAPTURED",
    }
    assert value["basis"] == (
        "copied_native_formatter_container_before_cleanup"
    )
    assert value["full_display_complete"] is False
    assert value["runtime_popup_verified"] is False
    assert base_decoded["observation"]["result"]["raw_date"] != 0
    assert fixture["mode"] == "recorded"


def test_template_date_mismatch_is_unknown_without_changing_base_observation(tmp_path):
    fixture, base, payload = _synthetic_v4(date_delta=1)
    decoded_base = decode_naval(base)
    decoded = _template_from_payload(payload)
    assert decoded_base["observation"]["result"]["raw_date"] != (
        decoded["message_template"]["native_date"]
    )
    assert project_template(decoded) == {
        "status": "unknown", "reason": "MESSAGE_TEMPLATE_DATE_MISMATCH",
    }
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="SAK", message_ids=("4",),
    )
    base_result = source.read(
        battle_topic_query(
            "B01", ["name"], selected_event=event_id(fixture, "4"),
        ),
        source.context(),
    )
    template_result = source.read(
        battle_topic_query(
            "B04", ["details"], selected_event=event_id(fixture, "4"),
        ),
        source.context(),
    )
    assert base_result["fields"]["name"]["status"] == "known"
    assert template_result["fields"]["details"]["value"]["message_template"] == {
        "status": "unknown", "reason": "MESSAGE_TEMPLATE_DATE_MISMATCH",
    }


def test_absent_v4_is_unknown_but_legacy_v3_is_unsupported():
    _fixture, base, payload = _synthetic_v4()
    absent = decode_template(_v4_frame(
        base, native_date=decode_naval(base)["observation"]["result"]["raw_date"],
        pairs=[], present=False,
    ))
    legacy = decode_naval(base)
    assert project_template(absent) == {
        "status": "unknown", "reason": "MESSAGE_TEMPLATE_CAPTURE_UNAVAILABLE",
    }
    assert project_template(legacy) == {
        "status": "unsupported", "reason": "MESSAGE_TEMPLATE_NOT_CAPTURED",
    }


def test_absent_v4_preserves_embedded_v3_force_and_effect_semantics(tmp_path):
    fixture, base, _payload = _synthetic_v4()
    legacy_fixture = deepcopy(fixture)
    legacy_fixture["payload_hex"] = base.hex()
    absent_fixture = deepcopy(fixture)
    absent_fixture["payload_hex"] = _v4_frame(
        base, native_date=decode_naval(base)["observation"]["result"]["raw_date"],
        pairs=[], present=False,
    ).hex()
    legacy_dir = tmp_path / "legacy"
    absent_dir = tmp_path / "absent"
    legacy_dir.mkdir()
    absent_dir.mkdir()
    legacy_source, _primary, legacy_fixture, _db, _raw = make_source(
        legacy_dir, fixture=legacy_fixture, observer="SAK", message_ids=("4",),
    )
    absent_source, _primary, absent_fixture, _db, _raw = make_source(
        absent_dir, fixture=absent_fixture, observer="SAK", message_ids=("4",),
    )
    for topic, fields in (
        ("B02", ["initial_forces", "losses", "remaining_forces", "unit_breakdown"]),
        ("B03", ["ships_captured", "war_score", "prestige", "army_tradition"]),
    ):
        legacy = legacy_source.read(
            battle_topic_query(topic, fields, selected_event=event_id(legacy_fixture, "4")),
            legacy_source.context(),
        )
        absent = absent_source.read(
            battle_topic_query(topic, fields, selected_event=event_id(absent_fixture, "4")),
            absent_source.context(),
        )
        assert absent["fields"] == legacy["fields"]


def test_information_service_query_and_event_tick_deduplicate_v4_template(tmp_path):
    fixture, _base, payload = _synthetic_v4()
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture={**fixture, "payload_hex": payload.hex()},
        observer="SAK", message_ids=("4",),
    )
    service = InformationService(source, tmp_path / "information.sqlite3")
    tools = InformationTools(service)
    selected = event_id(fixture, "4")
    try:
        query = battle_topic_query("B04", ["details"], selected_event=selected)
        query_result = service.query("v4-template-query", queries=[query])
        details = query_result["items"][0]["fields"]["details"]["value"]
        assert details["message_template"]["status"] == "known"
        assert details["message_template"]["value"]["pairs"][0]["key"]["value"] == "解放诺曼底"

        report = tools.call("information_manage_report", {
            "request_id": "v4-template-report",
            "operation": "create",
            "config": {"name": "v4 template", "detail": "full",
                       "queries": [battle_topic_query("B04", ["details"])]},
        })["report"]
        tools.call("information_manage_subscription", {
            "request_id": "v4-template-subscription",
            "operation": "create",
            "config": {"name": "v4 template events", "kind": "event",
                       "report_id": report["id"], "enabled": True,
                       "binding": {"session_id": fixture["provenance"]["session_id"],
                                   "observer": "SAK", "game_version": "1.37.4",
                                   "game_sha256": fixture["provenance"]["game_sha256"]},
                       "event": {"types": ["battle_observation"]}},
        })
        first = tools.call("information_tick", {"view": "full"})
        assert len(first["results"]) == 1
        event_details = first["results"][0]["items"][0]["fields"]["details"]["value"]
        assert event_details["message_template"]["status"] == "known"
        assert event_details["message_template"]["value"]["pair_count"] == 3
        assert tools.call("information_tick", {"view": "full"})["results"] == []
    finally:
        service.close()


def test_real_live_v4_absent_template_public_b04_keeps_actual_mapping(tmp_path):
    """Use the first v4 live payload without claiming a captured template."""
    import hashlib
    import json
    from pathlib import Path

    fixture_path = (Path(__file__).resolve().parent / "fixtures" /
                    "information_battle_naval_seq1_live_v4_1374.json")
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    raw = bytes.fromhex(fixture["payload_hex"])
    assert fixture["mode"] == "recorded"
    assert len(raw) == 543
    assert hashlib.sha256(raw).hexdigest() == (
        "80063f6b37602119af477b9b51c3ca9d9266043cb5b0f6cb060c774163bc2f3d"
    )
    provenance = fixture["provenance"]
    assert provenance["real_capture"] is True
    assert provenance["synthetic_extension"] is False
    assert provenance["session_id"] == "34612-1dd651a75345a76"
    assert provenance["installation"] == "f14c1e223384cd48"
    assert fixture["context_date"] == 56556888
    assert fixture["recorded_observer_ref"] == "010001be004a5441"
    assert fixture["expected_template_present"] is False

    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="ATJ", message_ids=("1",)
    )
    selected = event_id(fixture, "1")
    details_result = source.read(
        battle_topic_query("B04", ["details"], selected_event=selected),
        source.context(),
    )
    assert details_result["source"]["name"] == "IBOW.v4"
    assert details_result["source"]["projection_version"] == 30
    details = details_result["fields"]["details"]["value"]
    assert details["message_template"] == {
        "status": "unknown",
        "reason": "MESSAGE_TEMPLATE_CAPTURE_UNAVAILABLE",
    }

    sides_result = source.read(
        battle_topic_query("B01", ["sides"], selected_event=selected),
        source.context(),
    )
    sides = sides_result["fields"]["sides"]["value"]
    assert [side["representative"] for side in sides] == ["MLC", "ATJ"]
    assert [side["combat_side_index"] for side in sides] == [1, 0]
    assert sides[1]["participants"] == ["ATJ", "KED", "JMB"]
