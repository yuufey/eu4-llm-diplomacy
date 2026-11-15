"""Narrow offline tests for the IBOW v8/NHND value-only extension."""
from __future__ import annotations

from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import information_battle_display_context_wire as v7_wire
from work import information_battle_name_handoff_wire as wire
from bridge.tests.test_information_battle_display_context_wire import (
    _observed_snapshot,
    _v6_base,
)


def _base7() -> bytes:
    base6 = _v6_base()
    return v7_wire.encode(base6, _observed_snapshot(base6))


def _identity(base7: bytes) -> dict[str, int]:
    decoded = v7_wire.decode(base7)
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
    }


def _known(base7: bytes, raw: bytes = b"NAME", **overrides) -> dict:
    snapshot = {"state": "known", **_identity(base7), "raw_bytes": raw}
    snapshot.update(overrides)
    return snapshot


def _offsets(frame: bytes) -> tuple[int, int]:
    base_bytes = struct.unpack_from("<I", frame, 6)[0]
    extension = 10 + base_bytes
    return extension, extension + wire.EXTENSION_HEADER_BYTES


def _mutate(frame: bytes, offset: int, value: bytes) -> bytes:
    result = bytearray(frame)
    result[offset:offset + len(value)] = value
    return bytes(result)


def test_known_roundtrip_embeds_exact_v7_and_keeps_value_only_semantics():
    base7 = _base7()
    frame = wire.encode(base7, _known(base7))
    decoded = wire.decode(frame)
    original = v7_wire.decode(base7)

    for key, value in original.items():
        assert decoded[key] == value
    assert decoded["wire8"] == {
        "version": 8,
        "bytes": len(frame),
        "base_v7_version": 7,
        "base_v7_bytes": len(base7),
        "extension_magic": "NHND",
        "extension_version": 1,
        "extension_bytes": wire.FIXED_BODY_BYTES + 4,
        "trailing_bytes": 0,
    }
    handoff = decoded["name_handoff"]
    assert handoff["raw_hex"] == b"NAME".hex()
    assert handoff["source"] == handoff["source_name"] == wire.SOURCE_NAME
    assert handoff["semantic_role"] == "logical_name_constructor_input"
    assert handoff["not_raw_text"] is True
    assert handoff["not_line1"] is True
    assert _any_completion_guard(handoff) is False
    assert "raw_text" not in handoff


def _any_completion_guard(value: dict) -> bool:
    """Keep the assertion readable without inventing a display claim."""
    return any(value[key] for key in (
        "complete", "full_display_complete", "runtime_popup_verified",
        "visibility_verified",
    ))


def test_unknown_is_canonical_zero_and_does_not_require_base_identity():
    base7 = _base7()
    frame = wire.encode(base7, {"state": "unknown"})
    decoded = wire.decode(frame)
    assert decoded["name_handoff"]["state"] == "unknown"
    assert decoded["name_handoff"]["sequence"] == 0
    assert decoded["name_handoff"]["raw_date"] == 0
    assert decoded["name_handoff"]["kind"] == 0
    assert decoded["name_handoff"]["raw_hex"] is None

    with pytest.raises(wire.NameHandoffWireError):
        wire.encode(base7, {"state": "unknown", "sequence": 1})


def test_known_name_survives_unknown_display_context_and_dctx_mismatch_is_rejected():
    base6 = _v6_base()
    unknown_base7 = v7_wire.encode(
        base6,
        {"state": "unknown", "failure": 1},
    )
    frame = wire.encode(unknown_base7, _known(unknown_base7))
    assert wire.decode(frame)["name_handoff"]["state"] == "known"
    assert wire.decode(frame)["display_context"]["state"] == "unknown"

    mismatched = v7_wire.encode(
        base6,
        _observed_snapshot(base6, sequence=_identity(unknown_base7)["sequence"] + 1),
    )
    with pytest.raises(wire.NameHandoffWireError, match="display_context_identity"):
        wire.encode(mismatched, {"state": "unknown"})


def test_known_identity_is_checked_on_encode_and_decode():
    base7 = _base7()
    bad = _known(base7, sequence=_identity(base7)["sequence"] + 1)
    with pytest.raises(wire.NameHandoffWireError, match="identity"):
        wire.encode(base7, bad)

    frame = wire.encode(base7, _known(base7))
    _, body = _offsets(frame)
    tampered = _mutate(frame, body + 4, struct.pack("<Q", 999999))
    with pytest.raises(wire.NameHandoffWireError, match="identity"):
        wire.decode(tampered)


def test_v1_through_v7_decode_is_delegated_unchanged():
    base7 = _base7()
    assert wire.decode(base7) == v7_wire.decode(base7)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda frame, extension, body: _mutate(frame, extension, b"BAD!"),
        lambda frame, extension, body: _mutate(frame, extension + 4, struct.pack("<H", 2)),
        lambda frame, extension, body: _mutate(frame, body + 2, struct.pack("<H", 1)),
        lambda frame, extension, body: _mutate(
            frame, body + 20, struct.pack("<I", wire.MAX_VALUE_BYTES + 1)
        ),
    ],
)
def test_malformed_extension_is_rejected_without_relaxing_bounds(mutation):
    base7 = _base7()
    frame = wire.encode(base7, _known(base7))
    extension, body = _offsets(frame)
    with pytest.raises(wire.NameHandoffWireError):
        wire.decode(mutation(frame, extension, body))


def test_value_limit_nul_and_input_ambiguity_are_strict():
    base7 = _base7()
    maximum = wire.encode(base7, _known(base7, raw=b"x" * wire.MAX_VALUE_BYTES))
    assert wire.decode(maximum)["name_handoff"]["length"] == wire.MAX_VALUE_BYTES
    with pytest.raises(wire.NameHandoffWireError):
        wire.encode(base7, _known(base7, raw=b"x" * (wire.MAX_VALUE_BYTES + 1)))
    with pytest.raises(wire.NameHandoffWireError, match="embedded_nul"):
        wire.encode(base7, _known(base7, raw=b"NA\x00ME"))
    with pytest.raises(wire.NameHandoffWireError, match="ambiguous"):
        wire.encode(base7, _known(base7, raw_bytes=b"NAME", raw_hex="4e414d45"))
    with pytest.raises(wire.NameHandoffWireError, match="length"):
        wire.encode(base7, _known(base7, length=3))


def test_public_decode_retains_raw_bytes_only_and_never_claims_line1():
    base7 = _base7()
    decoded = wire.decode(wire.encode(base7, _known(base7, raw=b"\xff\xfe")))
    handoff = decoded["name_handoff"]
    assert handoff["raw_hex"] == "fffe"
    assert handoff["length"] == 2
    assert handoff["complete"] is False
    assert handoff["full_display_complete"] is False
    assert handoff["runtime_popup_verified"] is False
    assert handoff["visibility_verified"] is False
    assert "raw_text" not in handoff
    assert "line1" not in handoff
