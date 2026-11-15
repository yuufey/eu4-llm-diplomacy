"""IBOW v14/IFMT strict wrapper checks against the immutable v13 frame."""
from __future__ import annotations

import struct

import pytest

from work import information_battle_independent_line_wire as wire
from work import information_battle_outcome_tail_wire as base_wire
from bridge.tests.test_information_battle_outcome_tail_wire import _frame as _base13


def _field(state: str, raw: bytes = b"") -> dict:
    return {"state": state, "raw_hex": raw.hex(), "length": len(raw)}


def _snapshot(base13: bytes | None = None, *, kind: int | None = None,
              mode: int = 1) -> dict:
    base13 = base13 or _base13()
    decoded = base_wire.decode(base13)
    actual_kind = decoded["context"]["kind"]
    kind = actual_kind if kind is None else kind
    definition_key = b"LANDBATTLEOVER" if kind == 1 else b"NAVALBATTLEOVER"
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": kind,
        "state": "known",
        "failure": 0,
        "transform_mode": mode,
        "flags": 15,
        "text_fields": {
            "language": _field("known", b"l_english"),
            "definition_key": _field("known", definition_key),
            "body_template": _field("known", b"$NAME$"),
            "name_input": _field("known", b"native-input"),
            "output": _field("known", b"Formatted battle line"),
        },
    }


def _unknown_snapshot(base13: bytes | None = None, *, flags: int = 8,
                      failure: int = 3) -> dict:
    snapshot = _snapshot(base13)
    snapshot.update(state="unknown", failure=failure, transform_mode=0, flags=flags)
    snapshot["text_fields"] = {
        label: _field("unknown") for label in wire.FIELD_ORDER
    }
    return snapshot


def _frame(base13: bytes | None = None, *, kind: int | None = None,
           mode: int = 1) -> bytes:
    base13 = base13 or _base13()
    return wire.encode(base13, _snapshot(base13, kind=kind, mode=mode))


def _offsets(frame: bytes) -> tuple[int, int]:
    base_size = struct.unpack_from("<I", frame, 6)[0]
    extension = wire.OUTER_HEADER_BYTES + base_size
    return extension, extension + wire.EXTENSION_HEADER_BYTES


@pytest.mark.parametrize("mode", [1, 2])
def test_known_frame_embeds_complete_v13_without_changing_older_fields(mode):
    kind = 1
    base13 = _base13()
    original = base_wire.decode(base13)
    frame = _frame(base13, kind=kind, mode=mode)
    assert wire.validate(frame)
    decoded = wire.decode(frame)
    assert decoded["wire13"] == original["wire13"]
    for key, value in original.items():
        if key not in ("wire14", "independent_line"):
            assert decoded[key] == value
    assert decoded["wire14"] == {
        "version": 14, "base_version": 13, "source": "owned_independent_line",
    }
    line = decoded["independent_line"]
    assert (line["sequence"], line["raw_date"], line["kind"]) == (
        original["observation"]["sequence"],
        original["observation"]["result"]["raw_date"], kind,
    )
    assert (line["state"], line["failure"], line["transform_mode"], line["flags"]) == (
        "known", 0, mode, 15,
    )
    assert list(line["text_fields"]) == list(wire.FIELD_ORDER)
    assert line["text_fields"]["body_template"] == _field("known", b"$NAME$")
    extension, body = _offsets(frame)
    assert frame[4:6] == struct.pack("<H", 14)
    assert frame[10:10 + len(base13)] == base13
    assert frame[extension:extension + 4] == b"IFMT"
    assert struct.unpack_from("<I", frame, extension + 6)[0] == len(frame) - body
    assert struct.unpack_from("<QiBBBBB", frame, body) == (
        line["sequence"], line["raw_date"], kind, 1, 0, mode, 15,
    )


@pytest.mark.parametrize("flags", [0, 1, 8, 9, 15])
def test_unknown_frames_allow_preinvocation_guard_flag(flags):
    base13 = _base13()
    snapshot = _unknown_snapshot(base13, flags=flags)
    frame = wire.encode(base13, snapshot)
    line = wire.decode(frame)["independent_line"]
    assert line["state"] == "unknown"
    assert line["failure"] == snapshot["failure"]
    assert line["transform_mode"] == 0
    assert line["flags"] == flags
    assert all(item == _field("unknown") for item in line["text_fields"].values())


@pytest.mark.parametrize("mutation", [
    "sequence_bool", "raw_date_bool", "kind_bool", "failure_bool",
    "transform_bool", "flags_bool", "sequence_mismatch", "date_mismatch",
    "kind_mismatch", "unknown_key", "field_unknown_key", "field_length_bool",
    "bad_state",
    "bad_language", "bad_definition_key", "bad_template", "known_nul",
    "known_mixed_state", "known_flags", "failure_high", "unknown_failure_zero",
    "unknown_transform", "unknown_mixed_state", "unknown_return_without_invoke",
    "unknown_destroy_without_invoke", "definition_key_overlong", "text_overlong",
])
def test_invalid_snapshots_are_rejected(mutation):
    base13 = _base13()
    snapshot = _snapshot(base13)
    if mutation == "sequence_bool":
        snapshot["sequence"] = True
    elif mutation == "raw_date_bool":
        snapshot["raw_date"] = True
    elif mutation == "kind_bool":
        snapshot["kind"] = True
    elif mutation == "failure_bool":
        snapshot["failure"] = True
    elif mutation == "transform_bool":
        snapshot["transform_mode"] = True
    elif mutation == "flags_bool":
        snapshot["flags"] = True
    elif mutation == "sequence_mismatch":
        snapshot["sequence"] += 1
    elif mutation == "date_mismatch":
        snapshot["raw_date"] += 1
    elif mutation == "kind_mismatch":
        snapshot["kind"] = 2
        snapshot["text_fields"]["definition_key"] = _field(
            "known", b"NAVALBATTLEOVER",
        )
    elif mutation == "unknown_key":
        snapshot["extra"] = 1
    elif mutation == "field_unknown_key":
        snapshot["text_fields"]["output"]["extra"] = 1
    elif mutation == "field_length_bool":
        snapshot["text_fields"]["output"]["length"] = True
    elif mutation == "bad_state":
        snapshot["state"] = True
    elif mutation == "bad_language":
        snapshot["text_fields"]["language"] = _field("known", b"English")
    elif mutation == "bad_definition_key":
        snapshot["text_fields"]["definition_key"] = _field("known", b"NAVALBATTLEOVER")
    elif mutation == "bad_template":
        snapshot["text_fields"]["body_template"] = _field("known", b"$COUNTRY$")
    elif mutation == "known_nul":
        snapshot["text_fields"]["name_input"] = _field("known", b"A\x00B")
    elif mutation == "known_mixed_state":
        snapshot["text_fields"]["name_input"] = _field("unknown")
    elif mutation == "known_flags":
        snapshot["flags"] = 14
    elif mutation == "failure_high":
        snapshot["failure"] = 13
    elif mutation == "unknown_failure_zero":
        snapshot = _unknown_snapshot(base13, failure=0)
    elif mutation == "unknown_transform":
        snapshot = _unknown_snapshot(base13)
        snapshot["transform_mode"] = 1
    elif mutation == "unknown_mixed_state":
        snapshot = _unknown_snapshot(base13)
        snapshot["text_fields"]["output"] = _field("known", b"")
    elif mutation == "unknown_return_without_invoke":
        snapshot = _unknown_snapshot(base13, flags=2)
    elif mutation == "unknown_destroy_without_invoke":
        snapshot = _unknown_snapshot(base13, flags=4)
    elif mutation == "definition_key_overlong":
        snapshot["text_fields"]["definition_key"] = _field("known", b"x" * 65)
    else:
        snapshot["text_fields"]["output"] = _field("known", b"x" * 8193)
    with pytest.raises(wire.IndependentLineWireError):
        wire.encode(base13, snapshot)


def test_decoder_rejects_corrupt_lengths_trailing_bytes_and_noncanonical_fields():
    frame = _frame()
    extension, body = _offsets(frame)
    base_size = struct.unpack_from("<I", frame, 6)[0]
    bad_base = bytearray(frame[10:10 + base_size])
    bad_base[0] ^= 1
    bad_base_frame = bytearray(frame)
    bad_base_frame[10:10 + base_size] = bad_base

    bad_extension_length = bytearray(frame)
    struct.pack_into("<I", bad_extension_length, extension + 6,
                     struct.unpack_from("<I", frame, extension + 6)[0] + 1)
    bad_extension_version = bytearray(frame)
    struct.pack_into("<H", bad_extension_version, extension + 4, 2)
    trailing_body = bytearray(frame + b"\x00")
    struct.pack_into("<I", trailing_body, extension + 6,
                     struct.unpack_from("<I", frame, extension + 6)[0] + 1)
    truncated_field = bytearray(frame)
    # First field length is larger than the remaining body.
    struct.pack_into("<H", truncated_field,
                     body + wire.FIXED_BODY_BYTES + 1, 0xFFFF)
    language_start = body + wire.FIXED_BODY_BYTES + wire.TEXT_HEADER_BYTES
    truncated_field[language_start] = 0
    bad_field_state = bytearray(frame)
    bad_field_state[body + wire.FIXED_BODY_BYTES] = 2
    bad_flags = bytearray(frame)
    bad_flags[body + 16] = 14
    bad_nul = bytearray(frame)
    bad_nul[language_start] = 0
    invalids = [
        frame + b"\x00", bytes(bad_extension_length),
        bytes(bad_extension_version), bytes(trailing_body), bytes(truncated_field),
        bytes(bad_field_state), bytes(bad_flags), bytes(bad_nul), bytes(bad_base_frame),
        frame[:extension] + b"NOPE" + frame[extension + 4:],
    ]
    for invalid in invalids:
        assert not wire.validate(invalid)
        with pytest.raises(wire.IndependentLineWireError):
            wire.decode(invalid)
    bad_outer_version = bytearray(frame)
    struct.pack_into("<H", bad_outer_version, 4, 13)
    assert not wire.validate(bad_outer_version)


def test_bytearray_memoryview_and_legacy_v13_delegation():
    frame = _frame()
    assert wire.decode(bytearray(frame))["wire14"]["version"] == 14
    assert wire.decode(memoryview(frame))["independent_line"]["state"] == "known"
    base13 = _base13()
    assert wire.decode(base13) == base_wire.decode(base13)
    assert wire.decode(memoryview(base13)) == base_wire.decode(base13)
