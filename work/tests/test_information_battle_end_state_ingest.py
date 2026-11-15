"""Bounded ingestion tests for IBOW v9 raw end-state payloads."""
from __future__ import annotations

import hashlib
import struct

import pytest

from bridge.tests.test_information_battle_end_state_wire import _base7, _known
from work import information_battle_end_state_wire as wire
from work import ingest_information_battle_raw_live as ingest


def _v9_payload(gates=(0, 1)) -> bytes:
    base = _base7()
    return wire.encode(base, _known(base, gates))


def test_ingest_dispatches_v9_and_keeps_exact_raw_payload_bytes():
    payload = _v9_payload((0, 1))
    message = {
        "group_id": 1,
        "message_id": "9",
        "payload": payload,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_bytes": len(payload),
        "total_bytes": len(payload),
        "transport_complete": True,
    }
    version, decoded = ingest._decode_payload(payload)
    item = ingest._message_report(
        message,
        group={"received_count": 1, "fragment_count": 1, "status": "complete"},
        index=0,
    )

    assert version == 9
    assert decoded["wire9"]["version"] == 9
    assert decoded["end_state"] == {"status": "known", "raw_gates": [0, 1]}
    assert item["raw_payload_hex"] == payload.hex()
    assert bytes.fromhex(item["raw_payload_hex"]) == payload
    assert item["decode"]["wire_version"] == 9
    assert item["decode"]["value"]["end_state"] == decoded["end_state"]


@pytest.mark.parametrize("mutation,reason", [
    ("identity", "end_state_identity_mismatch"),
    ("trailing", "extension_length_mismatch"),
])
def test_ingest_rejects_bad_v9_identity_or_trailing_bytes(mutation, reason):
    payload = bytearray(_v9_payload())
    if mutation == "identity":
        base_bytes = struct.unpack_from("<I", payload, 6)[0]
        body = wire.OUTER_HEADER_BYTES + base_bytes + wire.EXTENSION_HEADER_BYTES
        payload[body] ^= 1  # Change copied sequence, keeping the base untouched.
        payload = bytes(payload)
    else:
        payload = bytes(payload) + b"\x00"

    with pytest.raises(ingest.RawIngestError, match=reason):
        ingest._decode_payload(payload)
