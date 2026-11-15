"""Strict offline tests for the IBOW v10/RETR wire extension."""
from __future__ import annotations

import struct

import pytest

from work import information_battle_display_context_wire as v7_wire
from work import information_battle_end_state_wire as v9_wire
from work import information_battle_name_handoff_wire as v8_wire
from work import information_battle_retreat_wire as wire
from bridge.tests.test_information_battle_end_state_wire import (
    _base7,
    _base8,
)
from bridge.tests.test_information_battle_display_context_wire import _v6_base


def _base9(base: bytes | None = None) -> bytes:
    return v9_wire.encode(base or _base7(), {"state": "unknown"})


def _identity9(base: bytes) -> dict[str, int]:
    decoded = v9_wire.decode(base)
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
    }


def _known(base: bytes, **overrides) -> dict:
    snapshot = {
        "state": "known",
        **_identity9(base),
        "losing_combat_side": 1,
        "initial_unit_count": 4,
        "units": [
            {
                "ordinal": 0,
                "owner_full_ref": 0x0102030405060708,
                "raw_flags": [201, 203, 204, 205],
            },
            {
                "ordinal": 3,
                "owner_full_ref": 0,
                "raw_flags": [0, 1, 254, 255],
            },
        ],
    }
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


def _frame(base: bytes | None = None, **overrides) -> bytes:
    base = base or _base9()
    return wire.encode(base, _known(base, **overrides))


def test_known_v7_roundtrip_keeps_every_v9_base_field_and_raw_flags():
    base = _base9(_base7())
    frame = _frame(base)
    decoded = wire.decode(frame)
    original = v9_wire.decode(base)

    for key, value in original.items():
        assert decoded[key] == value
    assert decoded["wire10"] == {
        "version": 10,
        "bytes": len(frame),
        "base_version": 9,
        "base_bytes": len(base),
        "extension_magic": "RETR",
        "extension_version": 1,
        "extension_bytes": 48,
        "trailing_bytes": 0,
    }
    assert decoded["retreat"] == {
        "status": "known",
        "sequence": _identity9(base)["sequence"],
        "raw_date": _identity9(base)["raw_date"],
        "kind": _identity9(base)["kind"],
        "combat_side_index": 1,
        "initial_unit_count": 4,
        "units": [
            {
                "ordinal": 0,
                "owner_full_ref": 0x0102030405060708,
                "raw_flags": [201, 203, 204, 205],
            },
            {
                "ordinal": 3,
                "owner_full_ref": 0,
                "raw_flags": [0, 1, 254, 255],
            },
        ],
    }
    _extension, body = _offsets(frame)
    assert struct.unpack_from("<QiBBBBHH", frame, body) == (
        _identity9(base)["sequence"], _identity9(base)["raw_date"],
        _identity9(base)["kind"], 1, 1, 0, 4, 2,
    )
    assert frame[body + wire.FIXED_BODY_BYTES:body + wire.FIXED_BODY_BYTES + wire.UNIT_BYTES] == struct.pack(
        "<HQBBBB", 0, 0x0102030405060708, 201, 203, 204, 205
    )
    assert "capture_source" not in decoded["retreat"]


def test_unit_removal_state_uses_v2_and_adds_source_only_to_v2_decode():
    base = _base9()
    snapshot = _known(base)
    regular = wire.encode(base, snapshot)
    explicit_regular = wire.encode(base, {**snapshot, "capture_source": "regular"})
    assert explicit_regular == regular

    frame = wire.encode(base, {**snapshot, "capture_source": "unit_removal_state"})
    extension, body = _offsets(frame)
    assert struct.unpack_from("<H", frame, extension + 4)[0] == 2
    assert frame[body + 15] == 1
    decoded = wire.decode(frame)
    assert decoded["wire10"]["extension_version"] == 2
    assert decoded["retreat"] == {
        "status": "known",
        "sequence": _identity9(base)["sequence"],
        "raw_date": _identity9(base)["raw_date"],
        "kind": _identity9(base)["kind"],
        "combat_side_index": 1,
        "initial_unit_count": 4,
        "units": snapshot["units"],
        "capture_source": "unit_removal_state",
    }
    assert "capture_source" not in wire.decode(regular)["retreat"]


@pytest.mark.parametrize("capture_source", ["unknown", "Unit_Removal_State", 1, None])
def test_known_encoder_rejects_unknown_capture_source(capture_source):
    base = _base9()
    with pytest.raises(wire.RetreatWireError, match="invalid_capture_source"):
        wire.encode(base, _known(base, capture_source=capture_source))


def test_known_v8_roundtrip_and_zero_observed_is_known_not_false():
    base = _base9(_base8())
    decoded = wire.decode(wire.encode(base, _known(
        base, initial_unit_count=0, units=[], losing_combat_side=0,
    )))
    assert decoded["wire9"]["base_version"] == 8
    assert decoded["retreat"] == {
        "status": "known",
        "sequence": _identity9(base)["sequence"],
        "raw_date": _identity9(base)["raw_date"],
        "kind": _identity9(base)["kind"],
        "combat_side_index": 0,
        "initial_unit_count": 0,
        "units": [],
    }


def test_unknown_is_canonical_twenty_zero_bytes_and_preserves_input():
    base = _base9()
    snapshot = {
        "state": "unknown",
        "capture_source": "ignored_for_unknown_state",
        "sequence": 77,
        "losing_combat_side": 1,
        "units": [{"ordinal": 0, "owner_full_ref": 0, "raw_flags": [1, 2, 3, 4]}],
    }
    before = dict(snapshot)
    frame = wire.encode(base, snapshot)
    extension, body = _offsets(frame)
    assert struct.unpack_from("<H", frame, extension + 4)[0] == 1
    assert frame[body:body + wire.FIXED_BODY_BYTES] == bytes(wire.FIXED_BODY_BYTES)
    assert snapshot == before
    assert wire.decode(frame)["retreat"] == {
        "status": "unknown", "reason": "RETREAT_NOT_CAPTURED",
    }


def test_versions_one_through_nine_delegate_without_shape_changes():
    base6 = _v6_base()
    base7 = _base7()
    base8 = _base8(base7)
    base9 = v9_wire.encode(base7, {"state": "unknown"})
    for old_frame in (base6, base7, base8, base9):
        assert wire.decode(old_frame) == v9_wire.decode(old_frame)


def test_recursive_v10_base_is_rejected():
    base = _base9()
    frame = _frame(base)
    with pytest.raises(wire.RetreatWireError, match="embedded_base_is_not_v9"):
        wire.encode(frame, {"state": "unknown"})


@pytest.mark.parametrize("bad_base", [b"", b"IBOW\x09\x00", b"IBOW\x0b\x00", b"not-wire"])
def test_encoder_accepts_only_a_complete_wire9_base(bad_base):
    with pytest.raises(wire.RetreatWireError):
        wire.encode(bad_base, {"state": "unknown"})


@pytest.mark.parametrize("mutation", [
    "identity", "side", "reserved", "initial", "unsorted", "duplicate",
    "ordinal", "extension_version", "extension_magic", "extension_length",
    "trailing",
])
def test_known_or_framing_corruption_is_rejected(mutation):
    base = _base9()
    frame = _frame(base)
    extension, body = _offsets(frame)
    if mutation == "identity":
        bad = _mutate(frame, body, struct.pack("<Q", _identity9(base)["sequence"] + 1))
    elif mutation == "side":
        bad = _mutate(frame, body + 14, b"\x02")
    elif mutation == "reserved":
        bad = _mutate(frame, body + 15, b"\x01")
    elif mutation == "initial":
        bad = _mutate(frame, body + 16, struct.pack("<H", 129))
    elif mutation == "unsorted":
        bad = _mutate(frame, body + wire.FIXED_BODY_BYTES, struct.pack("<H", 3))
    elif mutation == "duplicate":
        bad = _mutate(
            frame,
            body + wire.FIXED_BODY_BYTES + wire.UNIT_BYTES,
            struct.pack("<H", 0),
        )
    elif mutation == "ordinal":
        bad = _mutate(frame, body + wire.FIXED_BODY_BYTES, struct.pack("<H", 4))
    elif mutation == "extension_version":
        bad = _mutate(frame, extension + 4, struct.pack("<H", 2))
    elif mutation == "extension_magic":
        bad = _mutate(frame, extension, b"NOPE")
    elif mutation == "extension_length":
        bad = _mutate(frame, extension + 6, struct.pack("<I", 31))
    else:
        bad = frame + b"\x00"
    assert not wire.validate(bad)
    with pytest.raises(wire.RetreatWireError):
        wire.decode(bad)


def test_unknown_body_rejects_any_nonzero_field_and_extra_entry():
    base = _base9()
    frame = wire.encode(base, {"state": "unknown"})
    _extension, body = _offsets(frame)
    assert not wire.validate(_mutate(frame, body + 8, b"\x01"))
    bad = bytearray(frame)
    extension = _offsets(frame)[0]
    bad[extension + 6:extension + 10] = struct.pack("<I", 34)
    bad.extend(b"\x00" * wire.UNIT_BYTES)
    assert not wire.validate(bytes(bad))


def test_count_and_ordinal_constraints_are_strict_in_encoder():
    base = _base9()
    cases = [
        {"initial_unit_count": 129},
        {"initial_unit_count": 1},
        {"initial_unit_count": 2, "units": [
            {"ordinal": 1, "owner_full_ref": 0, "raw_flags": [0, 0, 0, 0]},
            {"ordinal": 0, "owner_full_ref": 0, "raw_flags": [0, 0, 0, 0]},
        ]},
        {"initial_unit_count": 2, "units": [
            {"ordinal": 2, "owner_full_ref": 0, "raw_flags": [0, 0, 0, 0]},
        ]},
        {"initial_unit_count": 2, "units": [
            {"ordinal": 0, "owner_full_ref": 0, "raw_flags": [0, 0, 0]},
        ]},
    ]
    for overrides in cases:
        with pytest.raises(wire.RetreatWireError):
            wire.encode(base, _known(base, **overrides))


def test_flag_bytes_are_opaque_and_combat_side_alias_is_consistent():
    base = _base9()
    snapshot = _known(
        base,
        combat_side_index=0,
        losing_combat_side=0,
        units=[{
            "ordinal": 0,
            "owner_full_ref": 0,
            "raw_flags": [0, 127, 128, 255],
        }],
    )
    decoded = wire.decode(wire.encode(base, snapshot))
    assert decoded["retreat"]["units"] == [
        {
            "ordinal": 0,
            "owner_full_ref": 0,
            "raw_flags": [0, 127, 128, 255],
        },
    ]
    with pytest.raises(wire.RetreatWireError, match="ambiguous_combat_side"):
        wire.encode(base, {**snapshot, "combat_side_index": 1})


@pytest.mark.parametrize("owner_full_ref", [True, -1, 1 << 64])
def test_owner_full_ref_requires_an_unsigned_u64(owner_full_ref):
    base = _base9()
    with pytest.raises(wire.RetreatWireError, match="owner_full_ref_out_of_range"):
        wire.encode(base, _known(base, units=[{
            "ordinal": 0,
            "owner_full_ref": owner_full_ref,
            "raw_flags": [0, 0, 0, 0],
        }]))


def test_unknown_extension_version_and_trailing_bytes_are_not_tolerated():
    base = _base9()
    frame = _frame(base)
    extension, _body = _offsets(frame)
    bad_version = _mutate(frame, extension + 4, struct.pack("<H", 9))
    assert not wire.validate(bad_version)
    with pytest.raises(wire.RetreatWireError, match="extension_version_mismatch"):
        wire.decode(bad_version)
    assert not wire.validate(frame + b"\x00")


def test_v2_requires_known_state_and_the_unit_removal_source_marker():
    base = _base9()
    known = wire.encode(base, _known(base, capture_source="unit_removal_state"))
    extension, body = _offsets(known)
    bad_marker = _mutate(known, body + 15, b"\x00")
    assert not wire.validate(bad_marker)
    with pytest.raises(wire.RetreatWireError, match="extension_version_capture_source_mismatch"):
        wire.decode(bad_marker)

    unknown = wire.encode(base, {"state": "unknown"})
    extension, _body = _offsets(unknown)
    bad_unknown_version = _mutate(unknown, extension + 4, struct.pack("<H", 2))
    assert not wire.validate(bad_unknown_version)
    with pytest.raises(wire.RetreatWireError, match="extension_version_capture_source_mismatch"):
        wire.decode(bad_unknown_version)


def test_compatibility_exports_and_unchanged_size_bound():
    assert issubclass(wire.RetreatWireError, ValueError)
    assert wire.EndStateWireError is v9_wire.EndStateWireError
    assert wire.NameHandoffWireError is v8_wire.NameHandoffWireError
    assert wire.DisplayContextWireError is v7_wire.DisplayContextWireError
    assert wire.MAX_WIRE_BYTES == v9_wire.MAX_WIRE_BYTES
    with pytest.raises(wire.RetreatWireError, match="wire_size_over_bound"):
        wire.encode(bytes(wire.MAX_WIRE_BYTES + 1), {"state": "unknown"})


def test_decode_rejects_overbound_multidimensional_memoryview_before_flattening():
    backing = bytearray(wire.MAX_WIRE_BYTES + 1)
    view = memoryview(backing).cast("B", shape=(1, len(backing)))
    with pytest.raises(wire.RetreatWireError, match="wire_size_over_bound"):
        wire.decode(view)
    with pytest.raises(wire.RetreatWireError, match="wire_size_over_bound"):
        wire.encode(view, {"state": "unknown"})


def test_decode_accepts_typed_and_multidimensional_memoryviews():
    base = _base9()
    frame = _frame(base)
    assert len(frame) % 2 == 0
    typed = memoryview(bytearray(frame)).cast("H")
    multidimensional = memoryview(bytearray(frame)).cast(
        "B", shape=(1, len(frame))
    )
    expected = wire.decode(frame)
    assert bytes(typed) == frame
    assert bytes(multidimensional) == frame
    assert wire.decode(typed) == expected
    assert wire.decode(multidimensional) == expected


def test_legal_memoryview_of_wire9_keeps_old_delegate_shape():
    base = _base9()
    view = memoryview(bytearray(base)).cast("H")
    assert wire.decode(view) == v9_wire.decode(base)

