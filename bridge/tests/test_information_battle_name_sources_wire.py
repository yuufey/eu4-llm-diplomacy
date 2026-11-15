"""Strict offline tests for the IBOW v11/NSRC wire extension."""
from __future__ import annotations

import struct

import pytest

from work import information_battle_name_sources_wire as wire
from work import information_battle_retreat_wire as v10_wire
from work.tests.test_information_battle_retreat_wire import (
    _base9,
    _known as _known_retreat,
)
from bridge.tests.test_information_battle_display_context_wire import _v6_base
from bridge.tests.test_information_battle_end_state_wire import _base7, _base8


def _base10(base: bytes | None = None) -> bytes:
    base = base or _base9()
    return v10_wire.encode(base, _known_retreat(base))


def _field(state: str, raw: bytes = b"") -> dict:
    return {"state": state, "raw_hex": raw.hex(), "length": len(raw)}


def _snapshot(base: bytes | None = None, **overrides) -> dict:
    base = base or _base10()
    decoded = v10_wire.decode(base)
    snapshot = {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
        "raw_failure": 0,
        "prefix_failure": 0,
        "transform_mode": 1,
        "text_fields": {
            "owner_name": _field("known", b"POR"),
            "global_name": _field("known", b"Portugal"),
            "battle_of_template": _field("known", b"{0} vs {1}"),
            "language": _field("known", b"l_english"),
        },
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
    base = base or _base10()
    return wire.encode(base, _snapshot(base, **overrides))


def test_roundtrip_embeds_complete_v10_and_all_four_raw_fields():
    base = _base10()
    frame = _frame(base)
    decoded = wire.decode(frame)
    source = decoded["name_sources"]
    base_identity = v10_wire.decode(base)
    assert decoded["wire11"] == {
        "version": 11,
        "source": "owned_name_sources",
    }
    assert source["sequence"] == base_identity["observation"]["sequence"]
    assert source["raw_date"] == base_identity["observation"]["result"]["raw_date"]
    assert source["kind"] == base_identity["context"]["kind"]
    assert source["raw_failure"] == 0
    assert source["prefix_failure"] == 0
    assert source["transform_mode"] == 1
    assert source["text_fields"] == {
        "owner_name": _field("known", b"POR"),
        "global_name": _field("known", b"Portugal"),
        "battle_of_template": _field("known", b"{0} vs {1}"),
        "language": _field("known", b"l_english"),
    }
    original = v10_wire.decode(base)
    for key, value in original.items():
        assert decoded[key] == value
    assert frame[wire.OUTER_HEADER_BYTES:wire.OUTER_HEADER_BYTES + len(base)] == base
    extension, body = _offsets(frame)
    assert frame[extension:extension + 4] == b"NSRC"
    assert struct.unpack_from("<HI", frame, extension + 4) == (
        1, len(frame) - body,
    )
    assert struct.unpack_from("<QiBBHB", frame, body) == (
        source["sequence"], source["raw_date"], source["kind"], 0, 0, 1,
    )


def test_unknown_raw_group_keeps_known_prefix_group_and_absent_template():
    base = _base10()
    snapshot = _snapshot(base)
    snapshot["raw_failure"] = 12
    snapshot["text_fields"]["owner_name"] = _field("unknown")
    snapshot["text_fields"]["global_name"] = _field("unknown")
    snapshot["text_fields"]["battle_of_template"] = _field("absent")
    snapshot["prefix_failure"] = 0
    snapshot["transform_mode"] = 2
    fields_before = dict(snapshot["text_fields"])
    decoded = wire.decode(wire.encode(base, snapshot))["name_sources"]
    assert decoded["raw_failure"] == 12
    assert decoded["prefix_failure"] == 0
    assert decoded["transform_mode"] == 2
    assert decoded["text_fields"] == fields_before


def test_known_empty_text_is_distinct_from_absent_template():
    base = _base10()
    snapshot = _snapshot(base)
    snapshot["text_fields"]["owner_name"] = _field("known", b"")
    snapshot["text_fields"]["battle_of_template"] = _field("absent")
    decoded = wire.decode(wire.encode(base, snapshot))["name_sources"]
    assert decoded["text_fields"]["owner_name"] == _field("known", b"")
    assert decoded["text_fields"]["battle_of_template"] == _field("absent")


def test_transform_mode_defaults_to_unknown_for_encoder_snapshots():
    base = _base10()
    snapshot = _snapshot(base)
    del snapshot["transform_mode"]
    decoded = wire.decode(wire.encode(base, snapshot))["name_sources"]
    assert decoded["transform_mode"] == 0


def test_both_groups_can_be_unknown_canonically():
    base = _base10()
    snapshot = _snapshot(base)
    snapshot.update(raw_failure=1, prefix_failure=9, transform_mode=0)
    snapshot["text_fields"] = {
        name: _field("unknown") for name in wire.TEXT_FIELDS
    }
    decoded = wire.decode(wire.encode(base, snapshot))["name_sources"]
    assert decoded["raw_failure"] == 1
    assert decoded["prefix_failure"] == 9
    assert decoded["transform_mode"] == 0
    assert all(item == _field("unknown")
               for item in decoded["text_fields"].values())


def test_decode_rejects_unknown_field_with_nonempty_wire_bytes():
    frame = _frame()
    _extension, body = _offsets(frame)
    # Owner name starts after the 17-byte scalar header; leave its length/data
    # intact while changing the state to canonical unknown.
    bad = _mutate(frame, body + 17, b"\x00")
    with pytest.raises(wire.NameSourcesWireError, match="noncanonical_owner_name_unknown"):
        wire.decode(bad)


def test_versions_one_through_ten_delegate_without_shape_changes():
    base6 = _v6_base()
    base7 = _base7()
    base8 = _base8(base7)
    base9 = _base9(base7)
    base10 = _base10(base9)
    for old_frame in (base6, base7, base8, base9, base10):
        assert wire.decode(old_frame) == v10_wire.decode(old_frame)


@pytest.mark.parametrize("bad_base", [b"", b"IBOW\x0a\x00", b"IBOW\x0c\x00", b"not-wire"])
def test_encoder_accepts_only_a_complete_wire10_base(bad_base):
    with pytest.raises(wire.NameSourcesWireError):
        wire.encode(bad_base, _snapshot())


@pytest.mark.parametrize("mutation", [
    "identity", "raw_failure", "prefix_failure", "transform_mode",
    "field_state", "extension_magic", "extension_version",
    "extension_length", "trailing",
])
def test_corrupt_identity_groups_states_or_framing_are_rejected(mutation):
    base = _base10()
    frame = _frame(base)
    extension, body = _offsets(frame)
    if mutation == "identity":
        bad = _mutate(frame, body, struct.pack(
            "<Q", struct.unpack_from("<Q", frame, body)[0] + 1,
        ))
    elif mutation == "raw_failure":
        bad = _mutate(frame, body + 13, b"\x01")
    elif mutation == "prefix_failure":
        bad = _mutate(frame, body + 14, struct.pack("<H", 1))
    elif mutation == "transform_mode":
        bad = _mutate(frame, body + 16, b"\x03")
    elif mutation == "field_state":
        bad = _mutate(frame, body + 17, b"\x03")
    elif mutation == "extension_magic":
        bad = _mutate(frame, extension, b"NOPE")
    elif mutation == "extension_version":
        bad = _mutate(frame, extension + 4, struct.pack("<H", 2))
    elif mutation == "extension_length":
        bad = _mutate(frame, extension + 6, struct.pack("<I", 28))
    else:
        bad = frame + b"\x00"
    assert not wire.validate(bad)
    with pytest.raises(wire.NameSourcesWireError):
        wire.decode(bad)


def test_encoder_rejects_group_mismatch_identity_mismatch_and_unknown_keys():
    base = _base10()
    snapshot = _snapshot(base)
    invalid = []
    bad_group = dict(snapshot)
    bad_group["raw_failure"] = 1
    invalid.append(bad_group)
    bad_identity = dict(snapshot)
    bad_identity["sequence"] += 1
    invalid.append(bad_identity)
    invalid.append({**snapshot, "extra": 1})
    bad_fields = dict(snapshot)
    bad_fields["text_fields"] = {
        **snapshot["text_fields"], "extra": _field("unknown"),
    }
    invalid.append(bad_fields)
    bad_text = dict(snapshot)
    bad_text["text_fields"] = {
        **snapshot["text_fields"],
        "owner_name": {**snapshot["text_fields"]["owner_name"], "extra": 0},
    }
    invalid.append(bad_text)
    for item in invalid:
        with pytest.raises(wire.NameSourcesWireError):
            wire.encode(base, item)


@pytest.mark.parametrize("field,raw", [
    ("owner_name", b"A\x00B"),
    ("global_name", b"\x00"),
    ("battle_of_template", b"x" * (wire.MAX_TEXT_BYTES + 1)),
    ("language", b"x" * (wire.MAX_LANGUAGE_BYTES + 1)),
    ("language", b"english"),
    ("language", b"l_bad-tag"),
])
def test_text_bytes_nul_bounds_and_language_format_are_strict(field, raw):
    base = _base10()
    snapshot = _snapshot(base)
    snapshot["text_fields"][field] = _field("known", raw)
    with pytest.raises(wire.NameSourcesWireError):
        wire.encode(base, snapshot)


@pytest.mark.parametrize("key,value", [
    ("sequence", True),
    ("sequence", 0),
    ("raw_date", True),
    ("raw_date", -1),
    ("kind", True),
    ("kind", 3),
    ("raw_failure", True),
    ("prefix_failure", True),
    ("transform_mode", True),
])
def test_encoder_rejects_bool_for_numeric_fields(key, value):
    base = _base10()
    snapshot = _snapshot(base)
    snapshot[key] = value
    with pytest.raises(wire.NameSourcesWireError):
        wire.encode(base, snapshot)


def test_known_text_length_is_strict_and_absent_only_applies_to_template():
    base = _base10()
    snapshot = _snapshot(base)
    snapshot["text_fields"]["owner_name"] = {
        **_field("known", b"POR"), "length": True,
    }
    with pytest.raises(wire.NameSourcesWireError):
        wire.encode(base, snapshot)
    snapshot = _snapshot(base)
    snapshot["text_fields"]["owner_name"] = _field("absent")
    with pytest.raises(wire.NameSourcesWireError):
        wire.encode(base, snapshot)


def test_size_bound_and_memoryview_decode_match_v10_contract():
    assert wire.MAX_WIRE_BYTES == v10_wire.MAX_WIRE_BYTES
    base = _base10()
    frame = _frame(base)
    assert wire.decode(memoryview(bytearray(frame))) == wire.decode(frame)
    with pytest.raises(wire.NameSourcesWireError, match="wire_size_over_bound"):
        wire.decode(memoryview(bytearray(wire.MAX_WIRE_BYTES + 1)))
