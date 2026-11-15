"""Strict offline tests for the IBOW v9/EOST wire extension."""
from __future__ import annotations

import struct

import pytest

from work import information_battle_display_context_wire as v7_wire
from work import information_battle_end_state_wire as wire
from work import information_battle_name_handoff_wire as v8_wire
from bridge.tests.test_information_battle_display_context_wire import (
    _observed_snapshot,
    _v6_base,
)


def _base7() -> bytes:
    base6 = _v6_base()
    return v7_wire.encode(base6, _observed_snapshot(base6))


def _base8(base7: bytes | None = None) -> bytes:
    return v8_wire.encode(base7 or _base7(), {"state": "unknown"})


def _identity(base: bytes) -> dict[str, int]:
    decoded = v7_wire.decode(base) if struct.unpack_from("<H", base, 4)[0] == 7 else v8_wire.decode(base)
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
    }


def _known(base: bytes, gates=(0, 255), **overrides) -> dict:
    snapshot = {"state": "known", **_identity(base), "raw_gates": list(gates)}
    snapshot.update(overrides)
    return snapshot


def _offsets(frame: bytes) -> tuple[int, int]:
    base_bytes = struct.unpack_from("<I", frame, 6)[0]
    extension = wire.OUTER_HEADER_BYTES + base_bytes
    return extension, extension + wire.EXTENSION_HEADER_BYTES


def _mutate(frame: bytes, offset: int, value: bytes) -> bytes:
    result = bytearray(frame)
    result[offset:offset + len(value)] = value
    return bytes(result)


def test_known_v7_roundtrip_preserves_base_and_raw_gate_bytes():
    base = _base7()
    frame = wire.encode(base, _known(base, (0, 255)))
    decoded = wire.decode(frame)
    original = v7_wire.decode(base)

    for key, value in original.items():
        assert decoded[key] == value
    assert frame[wire.OUTER_HEADER_BYTES:wire.OUTER_HEADER_BYTES + len(base)] == base
    assert decoded["wire9"] == {
        "version": 9,
        "bytes": len(frame),
        "base_version": 7,
        "base_bytes": len(base),
        "extension_magic": "EOST",
        "extension_version": 1,
        "extension_bytes": 16,
        "trailing_bytes": 0,
    }
    assert decoded["end_state"] == {"status": "known", "raw_gates": [0, 255]}
    assert decoded["complete"] is False
    _extension, body = _offsets(frame)
    assert frame[body + 14:body + 16] == bytes((0, 255))


def test_known_v8_roundtrip_preserves_all_v8_fields_and_uses_base_version_8():
    base = _base8()
    frame = wire.encode(base, _known(base, (255, 1)))
    decoded = wire.decode(frame)
    original = v8_wire.decode(base)

    for key, value in original.items():
        assert decoded[key] == value
    assert decoded["wire9"]["base_version"] == 8
    assert decoded["end_state"] == {"status": "known", "raw_gates": [255, 1]}


def test_unknown_snapshot_is_canonical_zero_without_mutating_input():
    base = _base7()
    snapshot = {"state": "unknown", "raw_gates": [255, 2], "sequence": 77}
    before = dict(snapshot)
    frame = wire.encode(base, snapshot)
    assert snapshot == before
    _extension, body = _offsets(frame)
    assert frame[body:body + 16] == bytes(16)
    assert wire.decode(frame)["end_state"] == {
        "status": "unknown", "reason": "END_STATE_NOT_CAPTURED",
    }


def test_unknown_state_can_wrap_either_allowed_base_version():
    for base in (_base7(), _base8()):
        decoded = wire.decode(wire.encode(base, {"state": "unknown"}))
        assert decoded["wire9"]["base_version"] in (7, 8)
        assert decoded["end_state"] == {
            "status": "unknown", "reason": "END_STATE_NOT_CAPTURED",
        }


def test_known_identity_must_match_base_exactly():
    base = _base8()
    for key, value in (("sequence", _identity(base)["sequence"] + 1),
                       ("raw_date", _identity(base)["raw_date"] + 1),
                       ("kind", 3 - _identity(base)["kind"])):
        with pytest.raises(wire.EndStateWireError, match="identity_mismatch"):
            wire.encode(base, _known(base, **{key: value}))


@pytest.mark.parametrize("gates", [(True, 0), (-1, 0), (0, 256), (1,), (1, 2, 3)])
def test_known_raw_gate_shape_and_byte_range_are_strict(gates):
    base = _base7()
    with pytest.raises(wire.EndStateWireError):
        wire.encode(base, _known(base, gates))


@pytest.mark.parametrize("bad_base", [b"", b"IBOW\x09\x00", b"IBOW\x06\x00", b"not-wire"])
def test_base_versions_other_than_v7_or_v8_are_rejected(bad_base):
    with pytest.raises(wire.EndStateWireError):
        wire.encode(bad_base, {"state": "unknown"})


def test_recursive_v9_base_is_rejected():
    base = _base7()
    frame = wire.encode(base, {"state": "unknown"})
    with pytest.raises(wire.EndStateWireError, match="embedded_base_version_unsupported"):
        wire.encode(frame, {"state": "unknown"})


def test_encoder_rejects_oversized_input_and_invalid_state_without_output():
    with pytest.raises(wire.EndStateWireError, match="wire_size_over_bound"):
        wire.encode(bytes(wire.MAX_WIRE_BYTES + 1), {"state": "unknown"})
    with pytest.raises(wire.EndStateWireError, match="invalid_snapshot_state"):
        wire.encode(_base7(), {"state": "missing"})
    with pytest.raises(wire.EndStateWireError, match="invalid_snapshot_state"):
        wire.encode(_base7(), {"state": []})


def test_unknown_and_known_wire_decoders_reject_noncanonical_extensions():
    base = _base7()
    unknown = wire.encode(base, {"state": "unknown"})
    _extension, body = _offsets(unknown)
    for offset, value in ((body, b"\x01"), (body + 8, b"\x01"),
                          (body + 12, b"\x01"), (body + 14, b"\x01")):
        assert not wire.validate(_mutate(unknown, offset, value))

    known = wire.encode(base, _known(base, (0, 1)))
    assert not wire.validate(_mutate(known, body + 13, b"\x02"))
    assert not wire.validate(_mutate(known, body, b"\x00"))


@pytest.mark.parametrize("mutation", [
    "magic", "version", "base_length", "extension_magic", "extension_version",
    "extension_length", "trailing_byte",
])
def test_outer_and_extension_corruption_is_rejected(mutation):
    base = _base7()
    frame = wire.encode(base, _known(base))
    extension, _body = _offsets(frame)
    if mutation == "magic":
        bad = _mutate(frame, 0, b"NOPE")
    elif mutation == "version":
        bad = _mutate(frame, 4, struct.pack("<H", 8))
    elif mutation == "base_length":
        bad = _mutate(frame, 6, struct.pack("<I", len(base) + 1))
    elif mutation == "extension_magic":
        bad = _mutate(frame, extension, b"NOPE")
    elif mutation == "extension_version":
        bad = _mutate(frame, extension + 4, struct.pack("<H", 2))
    elif mutation == "extension_length":
        bad = _mutate(frame, extension + 6, struct.pack("<I", 15))
    else:
        bad = frame + b"\x00"
    assert not wire.validate(bad)


def test_known_end_state_identity_tampering_is_rejected():
    base = _base7()
    frame = wire.encode(base, _known(base))
    _extension, body = _offsets(frame)
    corrupted = _mutate(frame, body, struct.pack("<Q", _identity(base)["sequence"] + 1))
    with pytest.raises(wire.EndStateWireError, match="end_state_identity_mismatch"):
        wire.decode(corrupted)


def test_non_v9_v1_through_v8_frames_delegate_and_keep_original_shapes():
    base6 = _v6_base()
    base7 = _base7()
    base8 = _base8(base7)
    for old_frame in (base6, base7, base8):
        assert wire.decode(old_frame) == v8_wire.decode(old_frame)


def test_compatibility_error_aliases_and_bound_are_exported():
    assert issubclass(wire.EndStateWireError, ValueError)
    assert wire.NameHandoffWireError is v8_wire.NameHandoffWireError
    assert wire.DisplayContextWireError is v8_wire.DisplayContextWireError
    assert wire.MAX_WIRE_BYTES == v8_wire.MAX_WIRE_BYTES


def test_known_end_state_output_is_deterministic():
    base = _base7()
    snapshot = _known(base, (17, 254))
    assert wire.encode(base, snapshot) == wire.encode(base, snapshot)
