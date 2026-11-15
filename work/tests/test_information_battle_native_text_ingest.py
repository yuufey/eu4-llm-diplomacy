"""Synthetic v6 checked-log ingestion, persistence and rejection checks."""
from pathlib import Path

import pytest

from work.ingest_information_battle_raw_live import (
    RawIngestError, _decode_payload, ingest_live_raw,
)
from work.information_battle_native_text_wire import encode
from work.test_ingest_information_battle_raw_live import (
    Fixture, fragment_line, war_identity_v5_payload,
)


def payload() -> bytes:
    return encode(war_identity_v5_payload(), {
        "definition_key": {"state": "observed", "source": "message_metadata",
                           "raw_hex": b"LANDBATTLEOVER".hex()},
        "auxiliary_text": {"state": "observed", "source": "message_metadata",
                           "raw_hex": ""},
    })


def test_v6_checked_log_reopens_without_duplicate_and_keeps_raw_text_partial(tmp_path: Path):
    raw = payload()
    fixture = Fixture(tmp_path, log_body=fragment_line(raw, 71, 1, 0))
    first = ingest_live_raw(fixture.installation, fixture.database,
                            fixture.output("native-first.json"))
    item = first["messages"][0]
    assert first["status"] == "passed"
    assert item["decode"]["status"] == "decoded_raw_native_text"
    assert item["decode"]["wire_version"] == 6
    assert bytes.fromhex(item["raw_payload_hex"]) == raw
    text = item["decode"]["value"]["native_text"]
    assert text["text_fields"]["definition_key"]["raw_hex"] == b"LANDBATTLEOVER".hex()
    assert text["text_fields"]["auxiliary_text"]["status"] == "known"
    assert text["text_fields"]["auxiliary_text"]["raw_hex"] == ""
    assert text["complete"] is False
    assert item["battle_complete"] is False
    assert item["public_identity"]["war_id"] is None
    second = ingest_live_raw(fixture.installation, fixture.database,
                             fixture.output("native-reopen.json"))
    assert second["status"] == "passed"
    assert second["tailer"]["cursor"]["offset"] == first["tailer"]["cursor"]["offset"]
    assert len(second["messages"]) == 1
    assert second["messages"][0]["payload_sha256"] == item["payload_sha256"]


def test_v6_nested_base_rejected_before_identity_is_exported():
    raw = bytearray(payload())
    raw[10:14] = b"BAD!"
    with pytest.raises(RawIngestError, match="v6_payload_rejected"):
        _decode_payload(bytes(raw))


def test_v5_dispatch_remains_identical():
    from work.information_battle_war_identity_wire import decode
    raw = war_identity_v5_payload()
    version, value = _decode_payload(raw)
    assert version == 5
    assert value == decode(raw)
