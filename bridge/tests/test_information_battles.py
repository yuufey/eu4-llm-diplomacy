"""Offline bridge tests for the recorded battle-observation adapter.

The fixture is a recorded 358-byte IBOW v2 payload.  These tests construct
only the two durable rows consumed by ``BattleObservationAdapter``; they do
not run capture, transport, game, or native code.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.battles import BattleInformationSource
from bridge.information.catalog import list_topics
from bridge.information.tools import InformationTools
from work.information_battle_naval_wire import decode as decode_naval_wire
from work.information_battle_template_wire import decode as decode_template_wire
from work.information_battle_war_identity_wire import (
    BINDING_FLAGS as WAR_IDENTITY_BINDING_FLAGS,
    EXTENSION_MAGIC as WAR_IDENTITY_EXTENSION_MAGIC,
    STATUS_ABSENT as WAR_IDENTITY_ABSENT,
    STATUS_BOUND as WAR_IDENTITY_BOUND,
    STATUS_INVALID as WAR_IDENTITY_INVALID,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "bridge" / "tests" / "fixtures" / "information_battle_live_v2_1374.json"
FRA_FIXTURE_PATH = ROOT / "bridge" / "tests" / "fixtures" / "information_battle_FRA_live_v2_1374.json"
NAVAL_FIXTURE_PATH = ROOT / "bridge" / "tests" / "fixtures" / "information_battle_naval_seq4_recorded_v2_1374.json"
LIVE_V3_FIXTURE_PATH = ROOT / "bridge" / "tests" / "fixtures" / "information_battle_naval_seq3_live_v3_1374.json"
LIVE_V4_FIXTURE_PATH = ROOT / "bridge" / "tests" / "fixtures" / "information_battle_FRA_live_container_v4_1374.json"
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def load_fixture() -> dict:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["mode"] == "recorded"
    assert len(bytes.fromhex(fixture["payload_hex"])) == 358
    assert fixture["provenance"]["game_sha256"] == GAME_SHA256
    return fixture


def load_fra_fixture() -> dict:
    fixture = json.loads(FRA_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["mode"] == "recorded"
    assert len(bytes.fromhex(fixture["payload_hex"])) == 495
    assert fixture["provenance"]["game_sha256"] == GAME_SHA256
    assert fixture["recorded_observer_ref"] == "0100007a00415246"
    return fixture


def load_naval_fixture() -> dict:
    fixture = json.loads(NAVAL_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["mode"] == "recorded"
    assert len(bytes.fromhex(fixture["payload_hex"])) == 391
    assert fixture["provenance"]["game_sha256"] == GAME_SHA256
    assert fixture["recorded_observer_ref"] == "010002fc004b4153"
    assert fixture["expected_mapping"] == [1, 0]
    return fixture


def load_live_v3_fixture() -> dict:
    fixture = json.loads(LIVE_V3_FIXTURE_PATH.read_text(encoding="utf-8"))
    raw = bytes.fromhex(fixture["payload_hex"])
    assert fixture["mode"] == "recorded"
    assert fixture["provenance"]["source_mode"] == "live_natural_capture"
    assert fixture["provenance"]["real_capture"] is True
    assert fixture["provenance"]["synthetic_extension"] is False
    assert len(raw) == 464
    assert hashlib.sha256(raw).hexdigest() == fixture["provenance"]["payload_sha256"]
    decoded = decode_naval_wire(raw)
    assert decoded["wire"]["version"] == 3
    assert decoded["naval"]["sides"][0]["raw_gate"] == 1
    assert decoded["observation"]["sequence"] == 3
    return fixture


def make_naval_v3_payload(fixture: dict) -> bytes:
    """Wrap the real seq4 v2 payload with a clearly synthetic NAVL block."""
    base = bytes.fromhex(fixture["payload_hex"])
    body = b"".join((
        struct.pack("<I", 1),
        struct.pack("<i", 4),
        struct.pack("<4iB", 0, 0, 1000, 1000, 0),
        struct.pack("<4iB", 0, 1000, 0, 0, 0),
    ))
    return b"".join((
        b"IBOW", struct.pack("<H", 3), struct.pack("<I", len(base)), base,
        struct.pack("<B", 1), b"NAVL", struct.pack("<H", 1),
        struct.pack("<I", len(body)), body,
    ))


def _full_ref(tag: str, suffix: bytes = b"") -> str:
    raw = tag.encode("ascii") + suffix + b"\0" * (5 - len(suffix))
    assert len(raw) == 8
    return f"{int.from_bytes(raw, 'little'):016x}"


class RecordedPrimary:
    """Small recorded primary source; it does not synthesize a world id."""

    event_types: tuple[str, ...] = ()

    def __init__(self, fixture: dict, *, observer: str = "VIJ") -> None:
        provenance = fixture["provenance"]
        self.current = {
            "status": "ready",
            "complete": True,
            "session_id": provenance["session_id"],
            "observer": observer,
            "game_version": "1.37.4",
            "game_sha256": provenance["game_sha256"],
            "game_date": fixture["context_date"],
            "game_day": fixture["context_date"] // 24,
            "mode": "recorded",
        }
        self.poll_calls: list[object] = []

    def context(self) -> dict:
        return deepcopy(self.current)

    def catalog(self) -> list[dict]:
        return list_topics()

    def validate_query(self, query: dict) -> dict:
        return deepcopy(query)

    def read(self, query: dict, context: dict) -> dict:
        return {
            "fields": {field: {"status": "unavailable", "reason": "PRIMARY_UNUSED"}
                       for field in query.get("fields", [])},
            "complete": False,
            "source": {"name": "RecordedPrimary", "mode": "recorded"},
        }

    def poll_events(self, context: dict, cursor) -> dict:
        self.poll_calls.append(cursor)
        return {"events": [], "cursor": cursor, "complete": True, "gaps": []}


class PrimaryWithEvents(RecordedPrimary):
    event_types = ("primary_observation",)

    def poll_events(self, context: dict, cursor) -> dict:
        self.poll_calls.append(cursor)
        if cursor == "primary-1":
            return {"events": [], "cursor": "primary-1", "complete": True, "gaps": []}
        return {
            "events": [{
                "event_id": "primary-observation-1",
                "event_type": "primary_observation",
                "session_id": context["session_id"],
                "observer": context["observer"],
                "complete": True,
                "payload": {},
            }],
            "cursor": "primary-1",
            "complete": True,
            "gaps": [],
        }


class HistoryPrimary(RecordedPrimary):
    """Primary owns non-battle H01 fields in the mixed-source test."""

    def read(self, query: dict, context: dict) -> dict:
        fields = {}
        for field in query.get("fields", []):
            if field == "snapshot_changes":
                fields[field] = {"status": "known", "value": {"from_primary": True}}
            else:
                fields[field] = {"status": "unavailable", "reason": "PRIMARY_UNUSED"}
        return {"fields": fields, "complete": all(item["status"] == "known" for item in fields.values()),
                "source": {"name": "HistoryPrimary", "mode": "recorded"}}


class CompleteHistoryPrimary(RecordedPrimary):
    """Primary fixture whose legacy H01 fields are all complete."""

    def read(self, query: dict, context: dict) -> dict:
        fields = {
            field: {"status": "known", "value": {"primary": field}}
            for field in query.get("fields", [])
        }
        return {
            "fields": fields,
            "complete": True,
            "source": {"name": "CompleteHistoryPrimary", "mode": "recorded"},
        }


def binding_for(fixture: dict, *, observer_ref: str | None = None, mode: str = "recorded",
                process_creation_filetime: int | str | None = None) -> dict:
    provenance = fixture["provenance"]
    binding = {
        "session_id": provenance["session_id"],
        "installation": provenance["installation"],
        "generation": provenance["generation"],
        "game_sha256": provenance["game_sha256"],
        "observer_ref": observer_ref or fixture["recorded_observer_ref"],
        "mode": mode,
    }
    if process_creation_filetime is not None:
        binding["process_creation_filetime"] = process_creation_filetime
    return binding


def create_stream_db(path: Path, fixture: dict, message_ids: tuple[str, ...] = ("1",)) -> bytes:
    payload = bytes.fromhex(fixture["payload_hex"])
    provenance = fixture["provenance"]
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE fragment_groups (
                group_id INTEGER PRIMARY KEY,
                installation TEXT NOT NULL,
                world_generation TEXT NOT NULL,
                message_id TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE complete_messages (
                group_id INTEGER PRIMARY KEY,
                payload BLOB NOT NULL,
                payload_sha256 TEXT NOT NULL,
                total_bytes INTEGER NOT NULL
            );
            """
        )
        for group_id, message_id in enumerate(message_ids, 1):
            connection.execute(
                "INSERT INTO fragment_groups VALUES(?,?,?,?,?,?)",
                (group_id, provenance["installation"], provenance["generation"],
                 message_id, len(payload), "complete"),
            )
            connection.execute(
                "INSERT INTO complete_messages VALUES(?,?,?,?)",
                (group_id, sqlite3.Binary(payload), payload_sha256, len(payload)),
            )
        connection.commit()
    finally:
        connection.close()
    return payload


def make_source(tmp_path: Path, fixture: dict | None = None, *, observer_ref: str | None = None,
                observer: str = "VIJ", primary_cls=RecordedPrimary,
                message_ids: tuple[str, ...] = ("1",),
                process_creation_filetime: int | str | None = None):
    fixture = fixture or load_fixture()
    stream_db = tmp_path / "battle-stream.sqlite3"
    payload = create_stream_db(stream_db, fixture, message_ids)
    primary = primary_cls(fixture, observer=observer)
    source = BattleInformationSource(
        primary, stream_db,
        binding_for(fixture, observer_ref=observer_ref,
                    process_creation_filetime=process_creation_filetime),
    )
    return source, primary, fixture, stream_db, payload


def _splitmix64_for_test(value: int) -> int:
    mask = (1 << 64) - 1
    value = (value + 0x9E3779B97F4A7C15) & mask
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & mask
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & mask
    return (value ^ (value >> 31)) & mask


def _war_identity_fixture(*, status: int = WAR_IDENTITY_BOUND,
                          reason: int = 0, flags: int = WAR_IDENTITY_BINDING_FLAGS,
                          creation: int = 132456789, raw_date: int | None = None,
                          pair: tuple[int, int] | None = None,
                          war_id: bytes | None = None) -> dict:
    fixture = json.loads(LIVE_V4_FIXTURE_PATH.read_text(encoding="utf-8"))
    base = bytes.fromhex(fixture["payload_hex"])
    decoded = decode_template_wire(base)
    result = decoded["observation"]["result"]
    raw_date = result["raw_date"] if raw_date is None else raw_date
    pair = tuple(side["country"] for side in result["sides"]) if pair is None else pair
    if war_id is None and status == WAR_IDENTITY_BOUND:
        war_id = f"war_{_splitmix64_for_test(creation):016x}_00000001".encode("ascii")
    war_id = b"" if war_id is None else war_id
    body = struct.pack("<BBIQiQQB", status, reason, flags, creation, raw_date,
                       pair[0], pair[1], len(war_id)) + war_id
    wrapped = (b"IBOW" + struct.pack("<HI", 5, len(base)) + base
               + WAR_IDENTITY_EXTENSION_MAGIC + body)
    fixture["payload_hex"] = wrapped.hex()
    fixture["context_date"] = max(int(fixture["context_date"]), int(raw_date))
    return fixture


def event_id(fixture: dict, message_id: str = "1") -> str:
    provenance = fixture["provenance"]
    return f"battle-observation:{provenance['installation']}:{provenance['generation']}:{message_id}"


def contains_key(value, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(contains_key(item, key) for item in value)
    return False


def battle_query(fields: list[str], *, selected_event: str | None = None) -> dict:
    return {
        "topic": "B01",
        "object": {"type": "battle"},
        "fields": fields,
        "parameters": {} if selected_event is None else {"event_id": selected_event},
    }


def battle_topic_query(topic: str, fields: list[str], *, selected_event: str | None = None) -> dict:
    return {
        "topic": topic,
        "object": {"type": "battle"},
        "fields": fields,
        "parameters": {} if selected_event is None else {"event_id": selected_event},
    }


def test_recorded_direct_participant_exposes_chinese_b01_and_b04_as_partial(tmp_path):
    source, _primary, fixture, _db, _payload = make_source(tmp_path)
    context = source.context()
    selected = event_id(fixture)

    b01 = source.read(
        battle_query(
            ["event_id", "battle_type", "name", "location", "end_date",
             "sides", "commanders", "war_id", "winner"],
            selected_event=selected,
        ),
        context,
    )
    assert b01["complete"] is False
    assert b01["fields"]["name"] == {"status": "known", "value": "蒂鲁吉拉帕利"}
    assert b01["fields"]["battle_type"] == {"status": "known", "value": "land"}
    assert b01["fields"]["war_id"] == {
        "status": "not_applicable", "reason": "REBEL_BATTLE_WITHOUT_WAR",
    }
    assert b01["fields"]["winner"] == {
        "status": "known",
        "value": {
            "combat_side_index": 0,
            "result_side_index": 0,
            "representative": "VIJ",
            "participants": ["VIJ"],
            "scope": "whole_combat_side",
            "observer_outcome": "victory",
            "basis": "native_combat_end_direction",
            "runtime_popup_verified": False,
        },
    }
    assert b01["source"]["projection_version"] == 30

    b04 = source.read(
        {
            "topic": "B04",
            "object": {"type": "battle"},
            "fields": ["details", "record_order", "deduplication", "completeness", "gaps", "raw_text"],
            "parameters": {"event_id": selected},
        },
        context,
    )
    assert b04["complete"] is False
    assert b04["fields"]["details"]["status"] == "known"
    assert b04["fields"]["raw_text"] == {
        "status": "unknown",
        "reason": "NATIVE_LINE1_NOT_CAPTURED_BY_LEGACY_WIRE",
    }
    details = b04["fields"]["details"]["value"]
    for forbidden in (
        "context", "war_members", "physical_player_ref", "physical_player_full_ref",
        "country", "country_raw_hex",
    ):
        assert not contains_key(details, forbidden)
    assert contains_key(details, "side_result_raw_i32")


def _history_query(topic: str, fields: list[str], obj: dict, **parameters) -> dict:
    return {"topic": topic, "object": obj, "fields": fields, "parameters": parameters}


def test_h01_battle_sequence_is_bounded_and_has_stable_cursor(tmp_path):
    source, _primary, fixture, _db, _payload = make_source(tmp_path, message_ids=("1", "2"))
    context = source.context()
    first = source.read(
        _history_query("H01", ["battle_sequence"], {"type": "country", "country": "VIJ"}, limit=1),
        context,
    )
    assert first["complete"] is False
    page = first["fields"]["battle_sequence"]["value"]
    assert [item["event_id"] for item in page["event_refs"]] == [event_id(fixture, "1")]
    assert page["event_refs"][0]["war_id"] == {
        "status": "not_applicable", "reason": "REBEL_BATTLE_WITHOUT_WAR",
    }
    assert page["coverage"]["gaps"]
    assert page["next_cursor"] == event_id(fixture, "1")

    second = source.read(
        _history_query("H01", ["battle_sequence"], {"type": "country", "country": "VIJ"},
                       after_event_id=page["next_cursor"], limit=1),
        context,
    )
    second_page = second["fields"]["battle_sequence"]["value"]
    assert [item["event_id"] for item in second_page["event_refs"]] == [event_id(fixture, "2")]
    # The look-ahead row makes the final page explicitly terminal.
    assert second_page["next_cursor"] is None


def test_h01_other_fields_remain_owned_by_primary(tmp_path):
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=load_fixture(), primary_cls=HistoryPrimary,
    )
    result = source.read(
        _history_query("H01", ["snapshot_changes", "battle_sequence"],
                       {"type": "country", "country": "VIJ"}, limit=4),
        source.context(),
    )
    assert result["fields"]["snapshot_changes"] == {
        "status": "known", "value": {"from_primary": True},
    }
    assert result["fields"]["battle_sequence"]["status"] == "known"
    assert result["source"]["primary"]["name"] == "HistoryPrimary"


def test_h01_legacy_fields_only_remain_primary_and_complete(tmp_path):
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=load_fixture(), primary_cls=CompleteHistoryPrimary,
    )
    legacy_fields = [
        "snapshot_changes", "relationship_changes", "military_changes",
        "war_score_changes", "resource_changes",
    ]
    result = source.read(
        _history_query(
            "H01", legacy_fields,
            {"type": "session", "session_id": fixture["provenance"]["session_id"]},
        ),
        source.context(),
    )
    assert result["complete"] is True
    assert result["source"] == {
        "name": "CompleteHistoryPrimary", "mode": "recorded",
    }
    assert all(result["fields"][field]["status"] == "known" for field in legacy_fields)
    assert all(result["fields"][field]["value"] == {"primary": field}
               for field in legacy_fields)


@pytest.mark.parametrize(
    "unsupported_parameters",
    [
        {"request_id": "request-1"},
        {"case": "case-1"},
        {"event_type": "other-battle-event"},
    ],
)
def test_h01_unsupported_history_filters_are_explicitly_unavailable(
    tmp_path, unsupported_parameters,
):
    source, _primary, _fixture, _db, _payload = make_source(tmp_path)
    result = source.read(
        _history_query(
            "H01", ["battle_sequence"], {"type": "country", "country": "VIJ"},
            **unsupported_parameters,
        ),
        source.context(),
    )
    assert result["fields"]["battle_sequence"] == {
        "status": "unavailable", "reason": "BATTLE_HISTORY_FILTER_NOT_SUPPORTED",
    }
    assert result["complete"] is False


def test_fra_b01_uses_full_ref_bijection_and_b02_keeps_combat_side_raw_totals(tmp_path):
    fixture = load_fra_fixture()
    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("9",),
    )
    selected = event_id(fixture, "9")
    b01 = source.read(
        battle_topic_query("B01", ["sides", "commanders", "winner"], selected_event=selected),
        source.context(),
    )
    sides = b01["fields"]["sides"]["value"]
    commanders = b01["fields"]["commanders"]["value"]
    assert [side["combat_side_index"] for side in sides] == [1, 0]
    assert [commander["combat_side_index"] for commander in commanders] == [1, 0]
    assert sides[0]["participants"] == ["FRA", "FOI", "AUV"]
    assert sides[1]["participants"] == ["HOL"]

    winner = b01["fields"]["winner"]
    assert winner == {
        "status": "known",
        "value": {
            "combat_side_index": 1,
            "result_side_index": 0,
            "representative": "FRA",
            "participants": ["FRA", "FOI", "AUV"],
            "scope": "whole_combat_side",
            "observer_outcome": "victory",
            "basis": "native_combat_end_direction",
            "runtime_popup_verified": False,
        },
    }

    b02 = source.read(
        battle_topic_query(
            "B02", ["initial_forces", "losses", "remaining_forces"],
            selected_event=selected,
        ),
        source.context(),
    )
    values = b02["fields"]
    by_side = {
        item["combat_side_index"]: item
        for item in values["initial_forces"]["value"]["sides"]
    }
    assert by_side[1]["component_sum"] == 40928
    by_side = {
        item["combat_side_index"]: item
        for item in values["losses"]["value"]["sides"]
    }
    assert by_side[1]["component_sum"] == 1806
    by_side = {
        item["combat_side_index"]: item
        for item in values["remaining_forces"]["value"]["sides"]
    }
    assert by_side[1]["component_sum"] == 39122
    assert values["losses"]["value"]["aggregate_display"]["status"] == "known"


def test_recorded_naval_b01_winner_and_b02_initial_forces_are_public_together(tmp_path):
    fixture = load_naval_fixture()
    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="SAK", message_ids=("4",),
    )
    selected = event_id(fixture, "4")
    b01 = source.read(
        battle_topic_query("B01", ["battle_type", "winner"], selected_event=selected),
        source.context(),
    )
    assert b01["fields"]["battle_type"] == {"status": "known", "value": "naval"}
    assert b01["fields"]["winner"] == {
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

    b02 = source.read(
        battle_topic_query(
            "B02", ["initial_forces", "unit_breakdown", "losses", "remaining_forces"],
            selected_event=selected,
        ),
        source.context(),
    )
    assert b02["complete"] is False
    assert b02["source"]["projection_version"] == 30
    assert b02["fields"]["initial_forces"] == {
        "status": "known",
        "value": {
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
        },
    }
    assert b02["fields"]["unit_breakdown"]["status"] == "known"
    assert b02["fields"]["losses"] == {
        "status": "unsupported", "reason": "NAVAL_LOSS_FIELDS_NOT_CAPTURED",
    }
    assert b02["fields"]["remaining_forces"] == {
        "status": "unsupported", "reason": "NAVAL_REMAINING_FIELDS_NOT_CAPTURED",
    }


def test_information_service_naval_b02_uses_battle_type_units_metadata(tmp_path):
    fixture = load_naval_fixture()
    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="SAK", message_ids=("4",),
    )
    service = InformationService(source, tmp_path / "naval-metadata-service.sqlite3")
    try:
        topic = next(item for item in service.discover()["topics"] if item["topic_id"] == "B02")
        fields = topic["fields"]
        for field in ("initial_forces", "losses", "remaining_forces", "unit_breakdown"):
            assert fields[field]["units_by_battle_type"] == {"land": "men", "naval": "ships"}
            assert "unit" not in fields[field]
            assert fields[field]["naval_loss_semantics"] == (
                "net_change_negative_loss_positive_gain"
            )

        query = battle_topic_query(
            "B02", ["initial_forces", "unit_breakdown", "losses", "remaining_forces"],
            selected_event=event_id(fixture, "4"),
        )
        result = service.query("naval-b02-metadata-query", queries=[query])
        assert result["trigger"] == "manual"
        assert result["status"] == "partial"
        item = result["items"][0]
        assert item["fields"]["initial_forces"]["value"]["unit"] == "ships"
        assert item["fields"]["unit_breakdown"]["value"]["unit"] == "ships"
        assert item["fields"]["losses"] == {
            "status": "unsupported",
            "reason": "NAVAL_LOSS_FIELDS_NOT_CAPTURED",
            "scale": 1,
        }
        assert item["fields"]["remaining_forces"] == {
            "status": "unsupported",
            "reason": "NAVAL_REMAINING_FIELDS_NOT_CAPTURED",
            "scale": 1,
        }
        for field in (item["fields"]["losses"], item["fields"]["remaining_forces"]):
            assert "unit" not in field
            assert field.get("unit") != "men"
    finally:
        service.close()


def test_information_service_decodes_synthetic_v3_naval_b02_extension(tmp_path):
    fixture = load_naval_fixture()
    # The base is the real recorded seq4 v2 payload; only this NAVL block is
    # hand-packed for a decoder/service contract test and is not a new capture.
    v3_fixture = deepcopy(fixture)
    v3_fixture["payload_hex"] = make_naval_v3_payload(fixture).hex()
    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=v3_fixture, observer="SAK", message_ids=("4",),
    )
    service = InformationService(source, tmp_path / "naval-v3-service.sqlite3")
    try:
        query = battle_topic_query(
            "B02", ["initial_forces", "losses", "remaining_forces", "unit_breakdown"],
            selected_event=event_id(fixture, "4"),
        )
        result = service.query("naval-v3-b02-query", queries=[query])
        assert result["status"] == "partial"
        assert result["complete"] is False
        item = result["items"][0]
        assert item["complete"] is False
        assert item["source"]["projection_version"] == 30

        initial = {
            side["combat_side_index"]: side
            for side in item["fields"]["initial_forces"]["value"]["sides"]
        }
        assert item["fields"]["initial_forces"]["value"]["unit"] == "ships"
        assert initial[0]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 0, "galley": 8, "transport": 6,
        }
        assert initial[1]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 3, "galley": 0, "transport": 0,
        }

        losses = {
            side["combat_side_index"]: side
            for side in item["fields"]["losses"]["value"]["sides"]
        }
        assert item["fields"]["losses"]["value"]["basis"] == (
            "native_naval_result_template_integer_operands"
        )
        assert item["fields"]["losses"]["value"]["quantity"] == "net_ship_change"
        assert item["fields"]["losses"]["value"]["sign_convention"] == (
            "negative_loss_positive_gain"
        )
        assert losses[0]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 1, "galley": -1, "transport": -1,
        }
        assert losses[1]["by_unit"] == {
            "heavy_ship": 0, "light_ship": -2, "galley": 0, "transport": 0,
        }

        remaining = {
            side["combat_side_index"]: side
            for side in item["fields"]["remaining_forces"]["value"]["sides"]
        }
        assert item["fields"]["remaining_forces"]["value"]["basis"] == (
            "native_naval_result_template_integer_operands"
        )
        assert remaining[0]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 1, "galley": 7, "transport": 5,
        }
        assert remaining[1]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 1, "galley": 0, "transport": 0,
        }

        breakdown = item["fields"]["unit_breakdown"]["value"]
        assert breakdown["available_phases"] == ["initial", "net_change", "remaining"]
        assert breakdown["unavailable_phases"] == []
        assert breakdown["sides"][0]["units"]["light_ship"] == {
            "initial": 0, "net_change": 1, "remaining": 1,
        }
    finally:
        service.close()


def test_real_live_v3_naval_b02_query_exposes_reordered_net_values(tmp_path):
    fixture = load_live_v3_fixture()
    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="ATJ", message_ids=("3",),
    )
    service = InformationService(source, tmp_path / "real-v3-service.sqlite3")
    try:
        query = battle_topic_query(
            "B02", ["initial_forces", "losses", "remaining_forces", "unit_breakdown"],
            selected_event=event_id(fixture, "3"),
        )
        result = service.query("real-v3-naval-b02-query", queries=[query])
        assert result["status"] == "partial"
        assert result["complete"] is False

        item = result["items"][0]
        assert item["complete"] is False
        assert item["source"]["name"] == "IBOW.v3"
        assert item["source"]["projection_version"] == 30

        initial = {
            side["combat_side_index"]: side
            for side in item["fields"]["initial_forces"]["value"]["sides"]
        }
        assert item["fields"]["initial_forces"]["value"]["unit"] == "ships"
        assert initial[0] == {
            "combat_side_index": 0,
            "participants": ["ATJ"],
            "by_unit": {"heavy_ship": 0, "light_ship": 3, "galley": 0, "transport": 0},
            "component_sum": 3,
        }
        assert initial[1] == {
            "combat_side_index": 1,
            "participants": ["MLC"],
            "by_unit": {"heavy_ship": 0, "light_ship": 0, "galley": 15, "transport": 9},
            "component_sum": 24,
        }

        losses = {
            side["combat_side_index"]: side
            for side in item["fields"]["losses"]["value"]["sides"]
        }
        assert item["fields"]["losses"]["value"]["unit"] == "ships"
        assert item["fields"]["losses"]["value"]["basis"] == (
            "native_naval_result_template_integer_operands"
        )
        assert item["fields"]["losses"]["value"]["quantity"] == "net_ship_change"
        assert item["fields"]["losses"]["value"]["sign_convention"] == (
            "negative_loss_positive_gain"
        )
        assert losses[0]["by_unit"] == {
            "heavy_ship": 0, "light_ship": -3, "galley": 0, "transport": 0,
        }
        assert losses[0]["component_sum"] == -3
        assert losses[1]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 0, "galley": 0, "transport": 0,
        }
        assert losses[1]["component_sum"] == 0

        remaining = {
            side["combat_side_index"]: side
            for side in item["fields"]["remaining_forces"]["value"]["sides"]
        }
        assert remaining[0]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 0, "galley": 0, "transport": 0,
        }
        assert remaining[0]["component_sum"] == 0
        assert remaining[1]["by_unit"] == {
            "heavy_ship": 0, "light_ship": 0, "galley": 15, "transport": 9,
        }
        assert remaining[1]["component_sum"] == 24

        breakdown = item["fields"]["unit_breakdown"]["value"]
        assert breakdown["available_phases"] == ["initial", "net_change", "remaining"]
        assert breakdown["unavailable_phases"] == []
        assert breakdown["sides"][0]["participants"] == ["ATJ"]
        assert breakdown["sides"][0]["units"]["light_ship"] == {
            "initial": 3, "net_change": -3, "remaining": 0,
        }
        assert breakdown["sides"][1]["participants"] == ["MLC"]
        assert breakdown["sides"][1]["units"]["galley"] == {
            "initial": 15, "net_change": 0, "remaining": 15,
        }
    finally:
        service.close()


def test_information_service_b03_query_exposes_effects_metadata_without_unproven_fields(tmp_path):
    fixture = load_live_v3_fixture()
    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="ATJ", message_ids=("3",),
    )
    service = InformationService(source, tmp_path / "real-v3-b03-service.sqlite3")
    try:
        topic = next(item for item in service.discover()["topics"] if item["topic_id"] == "B03")
        assert set(topic["fields"]) == {
            "annihilation", "retreat", "ships_captured", "war_score",
            "prestige", "army_tradition", "naval_tradition", "war_exhaustion",
        }
        assert topic["fields"]["ships_captured"]["unit"] == "ships"
        assert topic["fields"]["ships_captured"]["scale"] == 1
        assert topic["fields"]["ships_captured"]["units_by_battle_type"] == {"naval": "ships"}
        assert topic["fields"]["prestige"]["unit"] == "prestige"
        assert topic["fields"]["prestige"]["scale"] == 1000
        assert topic["fields"]["war_score"]["coverage"] == "partial"
        assert topic["fields"]["war_score"]["unit"] == "war_score"
        assert topic["fields"]["war_score"]["scale"] == 1000
        assert topic["fields"]["war_score"]["units_by_battle_type"] == {
            "land": "war_score", "naval": "war_score",
        }
        assert topic["fields"]["army_tradition"]["unit"] == "army_tradition"
        assert topic["fields"]["army_tradition"]["scale"] == 1000
        assert topic["fields"]["annihilation"]["coverage"] == "partial"
        assert topic["fields"]["retreat"]["coverage"] == "partial"
        assert topic["fields"]["retreat"]["known_false_supported"] is False

        query = battle_topic_query(
            "B03", ["ships_captured", "prestige", "army_tradition", "war_score",
                    "annihilation", "retreat"],
            selected_event=event_id(fixture, "3"),
        )
        result = service.query("real-v3-b03-query", queries=[query])
        assert result["status"] == "partial"
        assert result["complete"] is False
        item = result["items"][0]
        assert item["complete"] is False
        assert item["source"]["projection_version"] == 30
        assert set(item["fields"]) == {
            "ships_captured", "prestige", "army_tradition", "war_score",
            "annihilation", "retreat",
        }
        assert item["fields"]["ships_captured"]["value"]["total"] == 0
        assert item["fields"]["ships_captured"]["value"]["unit"] == "ships"
        assert item["fields"]["ships_captured"]["value"]["scale"] == 1
        assert item["fields"]["prestige"]["value"]["unit"] == "prestige"
        assert item["fields"]["prestige"]["value"]["scale"] == 1000
        assert item["fields"]["war_score"]["status"] == "known"
        assert item["fields"]["war_score"]["value"]["unit"] == "war_score"
        assert item["fields"]["war_score"]["value"]["scale"] == 1000
        assert item["fields"]["war_score"]["value"]["display_presence"] == "unverified"
        assert [side["raw"] for side in item["fields"]["war_score"]["value"]["sides"]] == [
            -250, 250,
        ]
        assert item["fields"]["army_tradition"] == {
            "status": "unsupported",
            "reason": "NAVAL_TRADITION_IS_NOT_ARMY_TRADITION",
            "unit": "army_tradition",
            "scale": 1000,
        }
        annihilation = item["fields"]["annihilation"]
        assert annihilation["status"] == "known"
        assert annihilation["complete"] is False
        assert annihilation["value"]["basis"] == "native_combat_side_overrun_marker"
        assert annihilation["value"]["sides"][0] == {
            "combat_side_index": 0,
            "participants": ["ATJ"],
            "native_overrun": {"status": "known", "value": True},
            "annihilated": {"status": "known", "value": True},
        }
        assert annihilation["value"]["sides"][1] == {
            "combat_side_index": 1,
            "participants": ["MLC"],
            "native_overrun": {"status": "known", "value": False},
            "annihilated": {
                "status": "unknown",
                "reason": "NON_OVERRUN_ANNIHILATION_PATHS_UNRESOLVED",
            },
        }
        assert item["fields"]["retreat"] == {
            "status": "unknown",
            "reason": "RETREAT_NOT_CAPTURED",
            "partial": True,
            "complete": False,
        }
    finally:
        service.close()


def test_inconsistent_winner_keeps_other_b01_fields_known(tmp_path, monkeypatch):
    """An outcome mismatch must not poison the rest of a captured record."""

    from bridge.information import battles as battle_module
    from work.information_battle_context_wire import decode

    source, _primary, fixture, _db, payload = make_source(
        tmp_path, fixture=load_fra_fixture(), observer="FRA", message_ids=("9",),
    )
    altered = decode(payload)
    altered["observation"]["result"]["flag108"] = 0
    monkeypatch.setattr(battle_module, "decode", lambda _raw: deepcopy(altered))
    result = source.read(
        battle_topic_query("B01", ["winner", "name"], selected_event=event_id(fixture, "9")),
        source.context(),
    )
    assert result["fields"]["winner"] == {
        "status": "unknown", "reason": "BATTLE_OUTCOME_INCONSISTENT",
    }
    assert result["fields"]["name"] == {"status": "known", "value": "巴黎"}


def test_history_future_date_keeps_resumable_opaque_cursor(tmp_path):
    source, primary, fixture, _db, _payload = make_source(
        tmp_path, message_ids=("1", "2"),
    )
    primary.current["game_date"] = fixture["captured_date"] - 1
    query = _history_query(
        "H01", ["battle_sequence"], {"type": "country", "country": "VIJ"},
        limit=1,
    )
    before_date = source.read(query, source.context())
    page = before_date["fields"]["battle_sequence"]["value"]
    assert page["event_refs"] == []
    assert page["coverage"]["gaps"][-1]["reason"] == "BATTLE_CONTEXT_DATE_BEHIND"
    cursor = page["next_cursor"]
    assert isinstance(cursor, str) and cursor.startswith("battle-page:")
    assert "battle-observation:" not in cursor
    assert before_date["coverage"]["next_cursor"] == cursor

    primary.current["game_date"] = fixture["captured_date"]
    after_date = source.read(
        _history_query(
            "H01", ["battle_sequence"], {"type": "country", "country": "VIJ"},
            after_event_id=cursor, limit=1,
        ),
        source.context(),
    )
    recovered = after_date["fields"]["battle_sequence"]["value"]
    assert [item["event_id"] for item in recovered["event_refs"]] == [
        event_id(fixture, "1"),
    ]


def test_h01_fra_multinational_participation_is_retained_as_event_reference(tmp_path):
    fixture = load_fra_fixture()
    source, _primary, _fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", message_ids=("9",),
    )
    result = source.read(
        _history_query("H01", ["battle_sequence"], {"type": "country", "country": "FRA"}, limit=64),
        source.context(),
    )
    refs = result["fields"]["battle_sequence"]["value"]["event_refs"]
    assert len(refs) == 1
    assert refs[0]["event_id"].endswith(":9")
    assert set(refs[0]["participant_countries"]) >= {"FRA", "HOL", "FOI", "AUV"}
    assert refs[0]["war_id"] == {"status": "unknown", "reason": "WAR_ID_UNRESOLVED"}


def test_w03_battle_losses_keeps_event_reference_and_partial_land_components(tmp_path):
    source, _primary, fixture, _db, _payload = make_source(tmp_path)
    result = source.read(
        _history_query("W03", ["battle_losses"], {"type": "country", "country": "VIJ"}, limit=4),
        source.context(),
    )
    w03_catalog = next(item for item in source.catalog() if item["topic_id"] == "W03")
    assert w03_catalog["status"] == "available"
    assert w03_catalog["fields"]["battle_losses"]["coverage"] == "partial"
    w03 = result["fields"]["battle_losses"]
    assert w03["status"] == "known"
    refs = w03["value"]["event_refs"]
    assert [item["event_id"] for item in refs] == [event_id(fixture)]
    assert refs[0]["losses"]["status"] == "known"
    value = refs[0]["losses"]["value"]
    assert [side["component_sum"] for side in value["sides"]] == [145, 2000]
    assert value["aggregate_display"]["status"] == "known"
    assert not contains_key(refs[0], "units")
    assert refs[0]["war_id"]["status"] == "not_applicable"


def test_w03_unknown_war_selection_is_explicit_and_not_ignored(tmp_path):
    source, _primary, _fixture, _db, _payload = make_source(tmp_path)
    result = source.read(
        _history_query("W03", ["battle_losses"],
                       {"type": "war", "war_id": "captured-war-1"}, limit=4),
        source.context(),
    )
    assert result["fields"]["battle_losses"] == {
        "status": "unavailable", "reason": "WAR_ID_UNRESOLVED",
    }


def test_history_fields_are_queryable_through_information_service(tmp_path):
    source, _primary, fixture, _db, _payload = make_source(tmp_path)
    service = InformationService(source, tmp_path / "history-service.sqlite3")
    try:
        result = service.query("history-query", queries=[
            _history_query("H01", ["snapshot_changes", "battle_sequence"],
                           {"type": "country", "country": "VIJ"}, limit=64),
            _history_query("W03", ["battle_losses"],
                           {"type": "country", "country": "VIJ"}, limit=64),
        ])
        assert len(result["items"]) == 2
        assert result["items"][0]["fields"]["battle_sequence"]["status"] == "known"
        assert result["items"][0]["fields"]["snapshot_changes"]["status"] == "unavailable"
        assert result["items"][1]["fields"]["battle_losses"]["status"] == "known"
        assert result["items"][1]["complete"] is False
    finally:
        service.close()


@pytest.mark.parametrize(
    ("observer_ref", "observer"),
    [
        (_full_ref("FRA"), "FRA"),
        (_full_ref("VIJ", b"\x01"), "VIJ"),
    ],
)
def test_nonparticipant_or_same_tag_different_fullref_cannot_bypass_scope(
    tmp_path, observer_ref: str, observer: str,
):
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, observer_ref=observer_ref, observer=observer,
    )
    context = source.context()
    selected = event_id(fixture)

    polled = source.poll_events(context, None)
    assert polled["events"] == []
    read = source.read(
        battle_query(["event_id", "name"], selected_event=selected),
        context,
    )
    assert read["complete"] is False
    assert read["fields"]["name"]["status"] == "unavailable"
    assert read["fields"]["name"]["reason"] == "BATTLE_RECORD_NOT_AVAILABLE_IN_OBSERVER_SCOPE"


def test_session_scope_mismatch_rejects_record_without_id_bypass(tmp_path):
    source, _primary, fixture, _db, _payload = make_source(tmp_path)
    bad_context = dict(source.context(), session_id="different-recorded-session")
    selected = event_id(fixture)

    polled = source.poll_events(bad_context, None)
    assert polled["events"] == []
    assert any(gap["reason"] == "BATTLE_OBSERVER_BINDING_MISMATCH" for gap in polled["gaps"])
    read = source.read(battle_query(["name"], selected_event=selected), bad_context)
    assert read["fields"]["name"]["status"] == "unavailable"


def test_information_tools_event_subscription_persists_and_restart_has_no_duplicate(tmp_path):
    source, _primary, fixture, stream_db, _payload = make_source(tmp_path)
    service_db = tmp_path / "information.sqlite3"
    service = InformationService(source, service_db)
    tools = InformationTools(service)
    provenance = fixture["provenance"]
    query = battle_query(["event_id", "battle_type", "name", "war_id"])
    binding = {
        "session_id": provenance["session_id"],
        "observer": "VIJ",
        "game_version": "1.37.4",
        "game_sha256": provenance["game_sha256"],
    }
    try:
        report = tools.call("information_manage_report", {
            "request_id": "battle-report",
            "operation": "create",
            "config": {"name": "recorded battle", "queries": [query], "detail": "full"},
        })["report"]
        subscription = tools.call("information_manage_subscription", {
            "request_id": "battle-subscription",
            "operation": "create",
            "config": {
                "name": "recorded battle events",
                "kind": "event",
                "report_id": report["id"],
                "enabled": True,
                "binding": binding,
                "event": {"types": ["battle_observation"]},
            },
        })["subscription"]
        assert subscription["state"] == "active"
        with pytest.raises(InformationError) as error:
            tools.call("information_manage_subscription", {
                "request_id": "battle-actor-filter-subscription",
                "operation": "create",
                "config": {
                    "name": "must not infer battle role",
                    "kind": "event",
                    "report_id": report["id"],
                    "enabled": True,
                    "binding": binding,
                    "event": {"types": ["battle_observation"], "actors": ["VIJ"]},
                },
            })
        assert error.value.code == "unsupported_event_filter"

        first = tools.call("information_tick", {})
        assert len(first["results"]) == 1
        result = tools.call("information_get_result", {
            "result_id": first["results"][0]["result_id"], "view": "full"})
        assert result["event"]["event_id"] == event_id(fixture)
        assert "actor" not in result["event"]["payload"]
        assert "recipient" not in result["event"]["payload"]
        assert set(result["event"]["payload"]["participant_countries"]) == {"VIJ", "REB"}
        assert result["items"][0]["fields"]["name"]["value"] == "蒂鲁吉拉帕利"
        assert result["items"][0]["fields"]["war_id"] == {
            "status": "not_applicable", "reason": "REBEL_BATTLE_WITHOUT_WAR",
        }
        assert result["complete"] is False
    finally:
        service.close()

    restarted_source = BattleInformationSource(
        RecordedPrimary(fixture), stream_db, binding_for(fixture),
    )
    restarted = InformationService(restarted_source, service_db)
    try:
        second = InformationTools(restarted).call("information_tick", {})
        assert second["results"] == []
        assert len(restarted.list_results()["results"]) == 1
    finally:
        restarted.close()


def test_same_payload_with_different_message_ids_remains_two_observations(tmp_path):
    source, _primary, fixture, _db, payload = make_source(tmp_path, message_ids=("1", "2"))
    polled = source.poll_events(source.context(), None)
    assert len(polled["events"]) == 2
    assert [event["event_id"] for event in polled["events"]] == [event_id(fixture, "1"), event_id(fixture, "2")]
    assert polled["events"][0]["source"]["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert polled["events"][0]["event_id"] != polled["events"][1]["event_id"]


def test_primary_and_battle_events_merge_with_independent_cursors(tmp_path):
    source, primary, fixture, _db, _payload = make_source(
        tmp_path, primary_cls=PrimaryWithEvents,
    )
    first = source.poll_events(source.context(), None)
    assert {event["event_type"] for event in first["events"]} == {
        "primary_observation", "battle_observation",
    }
    assert first["cursor"]["primary"] == "primary-1"
    assert first["cursor"]["battle"]["after"] == 1
    assert primary.poll_calls == [None]

    second = source.poll_events(source.context(), first["cursor"])
    assert second["events"] == []
    assert second["cursor"]["primary"] == "primary-1"
    assert second["cursor"]["battle"]["after"] == 1
    assert primary.poll_calls == [None, "primary-1"]


def test_battle_cursor_binding_mismatch_is_rejected_without_advancing(tmp_path):
    source, _primary, _fixture, _db, _payload = make_source(tmp_path)
    context = source.context()
    bad_cursor = {"primary": None, "battle": {"binding": "wrong-binding", "after": 0}}

    polled = source.poll_events(context, bad_cursor)
    assert polled["events"] == []
    assert polled["cursor"] == bad_cursor
    assert polled["complete"] is False
    assert any(
        "CURSOR" in gap["reason"] and "MISMATCH" in gap["reason"]
        for gap in polled["gaps"]
    )


def test_future_record_is_rejected_without_advancing_battle_cursor(tmp_path):
    source, primary, fixture, _db, _payload = make_source(tmp_path)
    primary.current["game_date"] = fixture["captured_date"] - 1
    cursor = {"primary": None, "battle": {"binding": source.battles.binding_id, "after": 0}}

    polled = source.poll_events(source.context(), cursor)
    assert polled["events"] == []
    assert polled["cursor"]["battle"]["after"] == 0
    assert polled["complete"] is False


def test_from_config_resolves_relative_database_and_missing_database_is_not_created(tmp_path):
    fixture = load_fixture()
    existing_db = tmp_path / "existing.sqlite3"
    create_stream_db(existing_db, fixture)
    config_path = tmp_path / "battle-stream.json"
    config_path.write_text(json.dumps({
        "schema": "EU4-BATTLE-STREAM/1",
        "database": "existing.sqlite3",
        "binding": binding_for(fixture),
    }), encoding="utf-8")
    configured = BattleInformationSource.from_config(RecordedPrimary(fixture), config_path)
    assert configured.battles.database == existing_db.resolve()

    missing_db = tmp_path / "missing.sqlite3"
    missing_config = tmp_path / "missing-config.json"
    missing_config.write_text(json.dumps({
        "schema": "EU4-BATTLE-STREAM/1",
        "database": "missing.sqlite3",
        "binding": binding_for(fixture),
    }), encoding="utf-8")
    missing = BattleInformationSource.from_config(RecordedPrimary(fixture), missing_config)
    assert not missing_db.exists()
    polled = missing.poll_events(missing.context(), None)
    assert not missing_db.exists()
    assert any(gap["reason"] == "BATTLE_EVENT_EVENT_SOURCE_UNAVAILABLE"
               or gap["reason"] == "BATTLE_EVENT_SOURCE_UNAVAILABLE"
               for gap in polled["gaps"])


@pytest.mark.parametrize("serial", [1, 257, 0xFFFFFFFF])
def test_v5_bound_war_identity_is_public_only_after_session_and_pair_guards(tmp_path, serial):
    war_id = f"war_05a3310ae47dd2bb_{serial:08x}"
    fixture = _war_identity_fixture(war_id=war_id.encode("ascii"))
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA", process_creation_filetime=132456789,
    )
    result = source.read(
        battle_query(["war_id"], selected_event=event_id(fixture)),
        source.context(),
    )
    assert result["fields"]["war_id"] == {
        "status": "known", "value": war_id,
    }
    assert result["source"]["war_identity_scope"] == "observer_session"
    assert result["source"]["war_registry"] == "shared_native_peace_registry"

    details = source.read(
        battle_topic_query("B04", ["details"], selected_event=event_id(fixture)),
        source.context(),
    )["fields"]["details"]["value"]
    identity = details["war_identity"]
    assert identity["process_creation_filetime"] == 132456789
    assert identity["pair_full_refs"] == [
        int.from_bytes(b"FRA\x00z\x00\x00\x01", "little"),
        int.from_bytes(b"HSA\x00\x9c\x02\x00\x01", "little"),
    ]
    assert "pointer" not in json.dumps(identity).lower()


@pytest.mark.parametrize(
    ("fixture_kwargs", "binding_creation", "expected_reason"),
    [
        ({"status": WAR_IDENTITY_ABSENT, "reason": 2, "flags": 0,
          "creation": 0, "pair": (0, 0)}, 132456789, "WAR_ID_CONTEXT_UNAVAILABLE"),
        ({"status": WAR_IDENTITY_INVALID, "reason": 5, "flags": 0xFEED,
          "creation": 4242, "pair": (1, 2)}, 132456789, "WAR_ID_ASSOCIATION_CHANGED"),
        ({}, 132456790, "WAR_ID_PROCESS_CREATION_MISMATCH"),
        ({"pair": (72060463080362824, 72058118028218950)}, 132456789,
         "WAR_ID_RESULT_PAIR_MISMATCH"),
        ({"war_id": b"war_0000000000000000_00000001"}, 132456789,
         "WAR_ID_EPOCH_MISMATCH"),
        ({"war_id": b"war_05a3310ae47dd2bb_00000000"}, 132456789,
         "WAR_ID_SUFFIX_OUT_OF_RANGE"),
    ],
)
def test_v5_identity_failures_keep_war_id_unknown(tmp_path, fixture_kwargs,
                                                  binding_creation, expected_reason):
    fixture = _war_identity_fixture(**fixture_kwargs)
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA",
        process_creation_filetime=binding_creation,
    )
    result = source.read(
        battle_query(["war_id"], selected_event=event_id(fixture)),
        source.context(),
    )
    assert result["fields"]["war_id"] == {"status": "unknown", "reason": expected_reason}


def test_v5_bound_identity_without_creation_binding_stays_unknown(tmp_path):
    fixture = _war_identity_fixture()
    source, _primary, fixture, _db, _payload = make_source(
        tmp_path, fixture=fixture, observer="FRA",
    )
    result = source.read(
        battle_query(["war_id"], selected_event=event_id(fixture)),
        source.context(),
    )
    assert result["fields"]["war_id"] == {
        "status": "unknown", "reason": "WAR_ID_PROCESS_CREATION_UNAVAILABLE",
    }
