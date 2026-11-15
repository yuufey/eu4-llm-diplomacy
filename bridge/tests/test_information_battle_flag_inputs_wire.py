"""Strict IBOW v15/FLAG checks using retained bases and synthetic extensions."""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import struct

import pytest

from bridge.information.battle_body_candidate import project_body_candidate
from bridge.information.battle_display_context import project_display_context
from bridge.tests.test_information_battle_independent_line import fixture14
from work import information_battle_independent_line_wire as v14
from work import information_battle_outcome_tail_wire as v13
from work import information_battle_flag_inputs_wire as wire


@lru_cache(maxsize=1)
def _naval_base14() -> bytes:
    """Build a synthetic v14 wrapper over the retained naval v13 base."""
    path = Path(__file__).parent / "fixtures/information_battle_independent_line_base13_naval.bin"
    base13 = path.read_bytes()
    decoded = v13.decode(base13)
    context = project_display_context(decoded)
    candidate = project_body_candidate(decoded)
    assert context["battle_kind"] == 2 and candidate["status"] == "known"
    text = context["text_fields"]
    values = {
        "language": bytes.fromhex(text["language"]["raw_hex"]),
        "definition_key": bytes.fromhex(text["definition_key"]["raw_hex"]),
        "body_template": bytes.fromhex(text["body_template"]["raw_hex"]),
        "name_input": bytes.fromhex(candidate["raw_hex"]),
        "output": bytes.fromhex(candidate["raw_hex"]),
    }
    transform_mode = decoded["name_sources"]["transform_mode"]
    snapshot = {
        "sequence": context["sequence"],
        "raw_date": context["raw_date"],
        "kind": 2,
        "state": "known",
        "failure": 0,
        "transform_mode": transform_mode,
        "flags": 15,
        "text_fields": {
            name: {"state": "known", "raw_hex": raw.hex(), "length": len(raw)}
            for name, raw in values.items()
        },
    }
    return v14.encode(base13, snapshot)


@lru_cache(maxsize=2)
def _base14(*, naval: bool = False) -> bytes:
    if naval:
        return _naval_base14()
    _fixture, _base13, payload14 = fixture14()
    # fixture14 produces an explicitly synthetic IFMT extension over a retained
    # land base; that complete v14 payload is the unchanged v15 embedded base.
    return payload14


def _snapshot(base14: bytes, *, state: str = "known",
              entries: list[dict] | None = None, failure: int | None = None) -> dict:
    decoded = v14.decode(base14)
    default_failure = 3 if state == "unknown" else 0
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
        "state": state,
        "failure": default_failure if failure is None else failure,
        "entries": [] if entries is None else deepcopy(entries),
    }


def _entry(pair_index: int, side: int, mode: int, *,
           country_ref: int = 0, rebel_raw: int = 0) -> dict:
    return {
        "pair_index": pair_index,
        "side": side,
        "mode": mode,
        "country_ref": country_ref,
        "rebel_raw": rebel_raw,
    }


def _country_ref() -> int:
    # Structurally valid FRA plus a nonzero high byte; no party-range check.
    return (0x42 << 56) | int.from_bytes(b"FRA", "little")


def _frame(base14: bytes | None = None, *, state: str = "known",
           entries: list[dict] | None = None, failure: int | None = None,
           naval: bool = False) -> bytes:
    base14 = _base14(naval=naval) if base14 is None else base14
    return wire.encode(base14, _snapshot(
        base14, state=state, entries=entries, failure=failure,
    ))


def _offsets(frame: bytes) -> tuple[int, int]:
    base_size = struct.unpack_from("<I", frame, 6)[0]
    extension = wire.OUTER_HEADER_BYTES + base_size
    return extension, extension + wire.EXTENSION_HEADER_BYTES


def test_known_entries_roundtrip_numeric_country_and_rebel_without_changing_base():
    base14 = _base14()
    original = v14.decode(base14)
    entries = [
        _entry(0, 0, 1),
        _entry(7, 1, 2, country_ref=_country_ref()),
        _entry(127, 0, 3, rebel_raw=0xFFFFFFFF),
    ]
    frame = _frame(base14, entries=entries)
    assert wire.validate(frame)
    decoded = wire.decode(memoryview(frame))
    assert decoded["wire15"] == {
        "version": 15, "base_version": 14, "source": "owned_flag_inputs",
    }
    assert decoded["flag_inputs"] == _snapshot(base14, entries=entries)
    for key, value in original.items():
        assert decoded[key] == value
    extension, body = _offsets(frame)
    assert frame[:4] == b"IBOW" and struct.unpack_from("<H", frame, 4)[0] == 15
    assert frame[10:10 + len(base14)] == base14
    assert frame[extension:extension + 4] == b"FLAG"
    assert struct.unpack_from("<I", frame, extension + 6)[0] == len(frame) - body
    assert struct.unpack_from("<QiBBBH", frame, body) == (
        decoded["flag_inputs"]["sequence"], decoded["flag_inputs"]["raw_date"],
        1, 1, 0, 3,
    )
    assert wire.decode(bytearray(frame))["flag_inputs"]["entries"] == entries


def test_known_empty_unknown_and_naval_not_applicable_roundtrip():
    land = _base14()
    empty_known = _frame(land)
    assert wire.decode(empty_known)["flag_inputs"] == _snapshot(land)

    unknown = _frame(land, state="unknown", failure=8)
    assert wire.decode(unknown)["flag_inputs"] == _snapshot(
        land, state="unknown", failure=8,
    )

    naval = _base14(naval=True)
    not_applicable = _frame(naval, state="not_applicable")
    assert wire.decode(not_applicable)["flag_inputs"] == _snapshot(
        naval, state="not_applicable",
    )
    assert wire.decode(naval) == v14.decode(naval)


@pytest.mark.parametrize("mutation", [
    "sequence_bool", "raw_date_bool", "kind_bool", "failure_bool",
    "sequence_mismatch", "date_mismatch", "kind_mismatch", "snapshot_extra",
    "entries_tuple", "entry_extra", "pair_index_bool", "pair_index_high",
    "side_bool", "side_high", "mode_bool", "mode_high", "country_ref_bool",
    "rebel_raw_bool", "rebel_raw_high", "state_bad", "failure_high",
    "unknown_failure_zero", "unknown_failure_high", "unknown_entries",
    "known_naval", "known_failure", "not_applicable_land",
    "not_applicable_failure", "not_applicable_entries", "duplicate_order",
    "descending_order", "count_high", "numeric_nonzero_country",
    "numeric_nonzero_rebel", "country_zero", "country_bad_chars",
    "country_fourth_nonzero", "country_high_zero", "country_rebel_nonzero",
    "rebel_country_nonzero",
])
def test_invalid_snapshots_are_rejected(mutation):
    base14 = _base14(naval=mutation == "known_naval")
    entries = [_entry(0, 0, 1)]
    snapshot = _snapshot(base14, entries=entries)
    if mutation == "sequence_bool":
        snapshot["sequence"] = True
    elif mutation == "raw_date_bool":
        snapshot["raw_date"] = True
    elif mutation == "kind_bool":
        snapshot["kind"] = True
    elif mutation == "failure_bool":
        snapshot["failure"] = True
    elif mutation == "sequence_mismatch":
        snapshot["sequence"] += 1
    elif mutation == "date_mismatch":
        snapshot["raw_date"] += 1
    elif mutation == "kind_mismatch":
        snapshot["kind"] = 2
    elif mutation == "snapshot_extra":
        snapshot["extra"] = 1
    elif mutation == "entries_tuple":
        snapshot["entries"] = tuple(snapshot["entries"])
    elif mutation == "entry_extra":
        snapshot["entries"][0]["extra"] = 1
    elif mutation == "pair_index_bool":
        snapshot["entries"][0]["pair_index"] = True
    elif mutation == "pair_index_high":
        snapshot["entries"][0]["pair_index"] = 128
    elif mutation == "side_bool":
        snapshot["entries"][0]["side"] = False
    elif mutation == "side_high":
        snapshot["entries"][0]["side"] = 2
    elif mutation == "mode_bool":
        snapshot["entries"][0]["mode"] = True
    elif mutation == "mode_high":
        snapshot["entries"][0]["mode"] = 4
    elif mutation == "country_ref_bool":
        snapshot["entries"][0]["country_ref"] = True
    elif mutation == "rebel_raw_bool":
        snapshot["entries"][0]["rebel_raw"] = True
    elif mutation == "rebel_raw_high":
        snapshot["entries"][0]["rebel_raw"] = 1 << 32
    elif mutation == "state_bad":
        snapshot["state"] = 3
    elif mutation == "failure_high":
        snapshot["failure"] = 9
    elif mutation == "unknown_failure_zero":
        snapshot.update(state="unknown", failure=0, entries=[])
    elif mutation == "unknown_failure_high":
        snapshot.update(state="unknown", failure=9, entries=[])
    elif mutation == "unknown_entries":
        snapshot.update(state="unknown", failure=2)
    elif mutation == "known_naval":
        snapshot["state"] = "known"
        snapshot["entries"] = []
    elif mutation == "known_failure":
        snapshot["failure"] = 1
    elif mutation == "not_applicable_land":
        snapshot.update(state="not_applicable", entries=[])
    elif mutation == "not_applicable_failure":
        snapshot.update(state="not_applicable", failure=1, entries=[])
    elif mutation == "not_applicable_entries":
        snapshot.update(state="not_applicable", entries=entries)
    elif mutation == "duplicate_order":
        snapshot["entries"] = [_entry(3, 0, 1), _entry(3, 1, 1)]
    elif mutation == "descending_order":
        snapshot["entries"] = [_entry(4, 0, 1), _entry(3, 1, 1)]
    elif mutation == "count_high":
        snapshot["entries"] = [_entry(i, 0, 1) for i in range(129)]
    elif mutation == "numeric_nonzero_country":
        snapshot["entries"][0]["country_ref"] = _country_ref()
    elif mutation == "numeric_nonzero_rebel":
        snapshot["entries"][0]["rebel_raw"] = 1
    elif mutation == "country_zero":
        snapshot["entries"] = [_entry(0, 0, 2)]
    elif mutation == "country_bad_chars":
        snapshot["entries"] = [_entry(0, 0, 2, country_ref=(0x42 << 56) | 1)]
    elif mutation == "country_fourth_nonzero":
        snapshot["entries"] = [_entry(0, 0, 2,
                                      country_ref=_country_ref() | (1 << 24))]
    elif mutation == "country_high_zero":
        snapshot["entries"] = [_entry(0, 0, 2,
                                      country_ref=int.from_bytes(b"FRA", "little"))]
    elif mutation == "country_rebel_nonzero":
        snapshot["entries"] = [_entry(0, 0, 2,
                                      country_ref=_country_ref(), rebel_raw=1)]
    else:
        snapshot["entries"] = [_entry(0, 0, 3, country_ref=1)]
    with pytest.raises(wire.FlagInputsWireError):
        wire.encode(base14, snapshot)


@pytest.mark.parametrize("damage", [
    "outer_magic", "outer_version", "base_size", "truncated_base",
    "truncated_extension_header", "extension_magic", "extension_version",
    "extension_length", "trailing_body", "truncated_entries", "identity",
    "unknown_state", "failure_high", "duplicate_order", "pair_index_high",
    "side_high", "mode_high", "numeric_noncanonical", "country_structure",
    "not_applicable_with_entries", "oversized_input",
])
def test_decoder_rejects_invalid_headers_lengths_identity_and_entries(damage):
    entries = [_entry(0, 0, 1), _entry(1, 1, 2, country_ref=_country_ref())]
    frame = bytearray(_frame(entries=entries))
    extension, body = _offsets(frame)
    if damage == "outer_magic":
        frame[0] ^= 1
    elif damage == "outer_version":
        struct.pack_into("<H", frame, 4, 14)
    elif damage == "base_size":
        struct.pack_into("<I", frame, 6, 0xFFFFFFFF)
    elif damage == "truncated_base":
        struct.pack_into("<I", frame, 6, len(frame))
    elif damage == "truncated_extension_header":
        frame = frame[:extension + 4]
    elif damage == "extension_magic":
        frame[extension:extension + 4] = b"NOPE"
    elif damage == "extension_version":
        struct.pack_into("<H", frame, extension + 4, 2)
    elif damage == "extension_length":
        struct.pack_into("<I", frame, extension + 6,
                         struct.unpack_from("<I", frame, extension + 6)[0] + 1)
    elif damage == "trailing_body":
        frame.append(0)
        struct.pack_into("<I", frame, extension + 6,
                         struct.unpack_from("<I", frame, extension + 6)[0] + 1)
    elif damage == "truncated_entries":
        struct.pack_into("<H", frame, body + 15, 3)
    elif damage == "identity":
        struct.pack_into("<Q", frame, body, struct.unpack_from("<Q", frame, body)[0] + 1)
    elif damage == "unknown_state":
        frame[body + 12] = 3
    elif damage == "failure_high":
        frame[body + 13] = 9
    elif damage == "duplicate_order":
        struct.pack_into("<H", frame, body + wire.FIXED_BODY_BYTES + wire.ENTRY_BYTES, 0)
    elif damage == "pair_index_high":
        struct.pack_into("<H", frame, body + wire.FIXED_BODY_BYTES, 128)
    elif damage == "side_high":
        frame[body + wire.FIXED_BODY_BYTES + 2] = 2
    elif damage == "mode_high":
        frame[body + wire.FIXED_BODY_BYTES + 3] = 4
    elif damage == "numeric_noncanonical":
        struct.pack_into("<Q", frame, body + wire.FIXED_BODY_BYTES + 4, _country_ref())
    elif damage == "country_structure":
        struct.pack_into("<Q", frame,
                         body + wire.FIXED_BODY_BYTES + wire.ENTRY_BYTES + 4, 1)
    elif damage == "not_applicable_with_entries":
        frame = bytearray(_frame(_base14(naval=True), state="not_applicable"))
        extension, body = _offsets(frame)
        frame.extend(struct.pack("<HBBQI", 0, 0, 1, 0, 0))
        struct.pack_into("<I", frame, extension + 6,
                         struct.unpack_from("<I", frame, extension + 6)[0] + wire.ENTRY_BYTES)
        struct.pack_into("<H", frame, body + 15, 1)
    else:
        frame = bytearray(wire.MAX_WIRE_BYTES + 1)
    invalid = bytes(frame)
    assert not wire.validate(invalid)
    with pytest.raises(ValueError):
        wire.decode(invalid)


def test_error_type_and_exact_v14_identity_metadata():
    assert issubclass(wire.FlagInputsWireError, ValueError)
    assert wire.FlagInputsWireError is not v14.IndependentLineWireError
    assert wire.SOURCE == "owned_flag_inputs"
    assert wire.VERSION == 15 and wire.BASE_VERSION == 14
