"""Offline raw-text projection checks through ingestion and the B04 query route.

The v5 battle base is an existing recorded fixture.  Native-text extension
values and transport frames are synthetic contract inputs; they are not live
qualification evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
import zlib

from bridge.information.battle_ingest import LiveBattleIngestor
from bridge.information.battle_native_text import project_raw_text
from bridge.information.battles import BattleInformationSource
from bridge.tests.test_information_battle_ingest import (
    GENERATION as INGEST_GENERATION,
    INSTALLATION as INGEST_INSTALLATION,
    SESSION as INGEST_SESSION,
    _fixture as make_ingest_installation,
)
from bridge.tests.test_information_battles import (
    RecordedPrimary,
    _war_identity_fixture,
    battle_topic_query,
    binding_for,
    event_id,
)
from work.information_battle_native_text_wire import encode as encode_v6
from work.information_battle_reassembly import (
    FRAGMENT_CAPACITY_BYTES,
    build_fragment_payload,
)
from work.information_battle_war_identity_wire import decode as decode_v5


def _snapshot(base_date: int, *, state: str, raw: bytes = b"",
              date_delta: int = 0) -> dict:
    raw_hex = raw.hex() if state == "observed" else ""
    return {
        "definition_key": {
            "state": "observed", "source": "message_metadata",
            "raw_hex": "4c414e44424154544c454f564552",
        },
        "auxiliary_text": {
            "state": "observed", "source": "message_metadata", "raw_hex": "",
        },
        "title_helper_candidate": {
            "state": "observed", "source": "title_helper_candidate",
            "raw_hex": "424154544c455f4f465f5041524953",
        },
        "line1_text": {
            "state": state, "source": "native_line1", "raw_hex": raw_hex,
        },
        "native_date": {"state": "observed", "value": base_date + date_delta},
        "raw_flags": {
            "state": "observed", "raw_flag_8c": 0xA1, "raw_flag_8d": 0x5E,
        },
    }


def _wire_payload(base: bytes, *, state: str, raw: bytes = b"",
                  date_delta: int = 0) -> bytes:
    base_date = decode_v5(base)["observation"]["result"]["raw_date"]
    return encode_v6(
        base,
        _snapshot(base_date, state=state, raw=raw, date_delta=date_delta),
    )


def _append_frames(log_path: Path, payloads: dict[str, bytes]) -> None:
    installation = f"{int(INGEST_INSTALLATION):016x}"
    generation = f"{int(INGEST_GENERATION):016x}"
    lines = [f"EU4_OWNED_BATTLE_WIRE_V1 {installation} {generation}\n".encode("ascii")]
    attempt_sequence = 1
    for message_id, payload in enumerate(payloads.values(), start=1):
        whole_crc32 = zlib.crc32(payload) & 0xFFFFFFFF
        for fragment_index, offset in enumerate(range(0, len(payload), FRAGMENT_CAPACITY_BYTES)):
            data = payload[offset:offset + FRAGMENT_CAPACITY_BYTES]
            fragment = build_fragment_payload(
                installation=installation,
                world_generation=generation,
                message_id=message_id,
                total_bytes=len(payload),
                fragment_index=fragment_index,
                data=data,
                whole_crc32=whole_crc32,
            )
            record = {
                "event": "information_owned_battle_record",
                "wire_version": 1,
                "installation": installation,
                "world_generation": generation,
                "attempt_sequence": str(attempt_sequence),
                "payload_encoding": "hex",
                "payload_bytes": len(fragment),
                "payload_hex": fragment.hex(),
            }
            lines.append((json.dumps(record, separators=(",", ":")) + "\n").encode("ascii"))
            attempt_sequence += 1
    log_path.write_bytes(b"".join(lines))


def test_synthetic_wire6_raw_text_survives_ingest_adapter_and_query(tmp_path, monkeypatch):
    fixture = _war_identity_fixture()
    fixture["provenance"]["session_id"] = INGEST_SESSION
    fixture["provenance"]["installation"] = f"{int(INGEST_INSTALLATION):016x}"
    fixture["provenance"]["generation"] = f"{int(INGEST_GENERATION):016x}"
    base = bytes.fromhex(fixture["payload_hex"])

    cases = {
        "known": _wire_payload(base, state="observed", raw=b"A battle report line."),
        "empty": _wire_payload(base, state="observed", raw=b""),
        "unknown": _wire_payload(base, state="unknown"),
        "absent": _wire_payload(base, state="absent"),
        "codec-failed": _wire_payload(base, state="observed", raw=b"\x10\xe3"),
        "date-mismatch": _wire_payload(
            base, state="observed", raw=b"wrong-date bytes", date_delta=1,
        ),
        "legacy": base,
    }

    installation_path = make_ingest_installation(tmp_path)
    _append_frames(installation_path.parent / "information-battle-raw.jsonl", cases)
    database = tmp_path / "raw-ingestion.sqlite3"
    monkeypatch.setattr("bridge.information.battle_ingest.COALESCE_SECONDS", 0.0)
    ingestor = LiveBattleIngestor(installation_path, database, expected_binding={
        "session_id": INGEST_SESSION,
        "installation": fixture["provenance"]["installation"],
        "generation": fixture["provenance"]["generation"],
    })
    try:
        ingestion = ingestor.refresh()
        assert ingestion["status"] == "advanced"
        assert ingestion["reassembly"]["poll"]["completed"] == len(cases)
    finally:
        ingestor.close()

    primary = RecordedPrimary(fixture, observer="FRA")
    binding = binding_for(fixture, observer_ref=fixture["recorded_observer_ref"])
    source = BattleInformationSource(primary, database, binding)
    topic = next(topic for topic in source.catalog() if topic["topic_id"] == "B04")
    assert topic["status"] == "available"
    assert topic["visibility"] == "direct_participant"
    assert topic["context_scope"] == "event_scope"
    assert topic["fields"]["raw_text"]["coverage"] == "partial"
    assert topic["fields"]["raw_text"]["unit"] == "native_text_sections"
    assert topic["fields"]["raw_text"]["complete"] is False
    assert "仅逐场记录" in topic["fields"]["raw_text"]["description"]

    expected_unknown_reasons = {
        "unknown": "NATIVE_LINE1_UNKNOWN",
        "absent": "NATIVE_LINE1_ABSENT",
        "codec-failed": "NATIVE_LINE1_DECODE_FAILED",
        "date-mismatch": "NATIVE_TEXT_DATE_MISMATCH",
        "legacy": "NATIVE_LINE1_NOT_CAPTURED_BY_LEGACY_WIRE",
    }
    for case_index, case in enumerate(cases, start=1):
        result = source.read(
            battle_topic_query(
                "B04", ["raw_text", "details", "completeness"],
                selected_event=event_id(fixture, str(case_index)),
            ),
            source.context(),
        )
        assert result["complete"] is False
        assert result["source"]["complete"] is False
        raw_text = result["fields"]["raw_text"]
        details = result["fields"]["details"]["value"]
        completeness = result["fields"]["completeness"]["value"]
        assert completeness["business_complete"] is False
        assert completeness["full_display_complete"] is False
        assert completeness["own_participation_verified"] is True
        assert completeness["native_visibility_verified"] is False
        assert details["display"]["value"]["full_display_complete"] is False
        assert details["display"]["value"]["runtime_popup_verified"] is False
        assert details["display"]["value"]["missing_sections"] == (
            ["title", "button_text", "actual_layout_and_visibility"]
            if case in ("known", "empty") else
            ["title", "Line1", "button_text", "actual_layout_and_visibility"]
        )

        if case in ("known", "empty"):
            expected_text = "A battle report line." if case == "known" else ""
            expected_raw = expected_text.encode("ascii").hex()
            assert raw_text == {
                "status": "known",
                "value": {
                    "sections": [{
                        "section": "Line1", "text": expected_text,
                        "raw_hex": expected_raw, "source": "native_line1",
                    }],
                    "unit": "native_text_sections",
                    "basis": "wire6_native_line1",
                    "partial": True,
                    "complete": False,
                    "missing_sections": [
                        "title", "button_text", "actual_layout_and_visibility",
                    ],
                    "business_complete": False,
                    "full_display_complete": False,
                    "native_visibility_verified": False,
                },
            }
            native = details["native_text"]["line1_text"]
            assert native["status"] == "known"
            assert native["raw_hex"] == expected_raw
            assert native["decoded"] == {"status": "known", "value": expected_text}
        else:
            assert raw_text == {
                "status": "unknown",
                "reason": expected_unknown_reasons[case],
            }
            if case == "codec-failed":
                native = details["native_text"]["line1_text"]
                assert native["status"] == "unknown"
                assert native["raw_hex"] == "10e3"
            elif case == "date-mismatch":
                native_text = details["native_text"]
                assert native_text["status"] == "unknown"
                assert native_text["reason"] == "NATIVE_TEXT_DATE_MISMATCH"
                assert native_text["line1_text"]["raw_hex"] == b"wrong-date bytes".hex()
            elif case == "legacy":
                assert "native_text" not in details
                assert "message_template" in details


def test_missing_line1_projection_is_explicitly_unknown():
    assert project_raw_text({"metadata": {}}, wire_version=6) == {
        "status": "unknown", "reason": "NATIVE_LINE1_FIELD_MISSING",
    }
