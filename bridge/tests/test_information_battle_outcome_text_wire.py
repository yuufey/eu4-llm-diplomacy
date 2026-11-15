"""Strict offline tests for the IBOW v12/OCTX wire extension."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from work import information_battle_name_sources_wire as base_wire
from work import information_battle_outcome_text_wire as wire


ROOT = Path(__file__).resolve().parents[2]
BASE_PATH = ROOT / (
    "work/runtime/information-battle-name-sources-20261107-221-001/"
    "validation-003/known11.bin"
)
BASE_SHA256 = "36ea1a4c83cf6153fe33e10a823cb53dc97eebf3e5311870db63f364d54b453b"


def _base11() -> bytes:
    # This is a fixed synthetic v11 base frame, not a newly captured event.
    raw = BASE_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BASE_SHA256
    assert struct.unpack_from("<H", raw, 4)[0] == 11
    return raw


def _field(state: str, raw: bytes = b"") -> dict:
    return {"state": state, "raw_hex": raw.hex(), "length": len(raw)}


def _known_snapshot(base: bytes | None = None) -> dict:
    base = base or _base11()
    decoded = base_wire.decode(base)
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
        "failure": 0,
        "text_fields": {
            "language": _field("known", b"l_english"),
            "ALLIES_WON": _field("known", b""),
            "ALLIES_LOST": _field("absent"),
            "YOU_WON": _field("known", b"$COUNTRY$ won"),
            "YOU_LOST": _field("known", b""),
            "RESULT_WON": _field("known", b"won"),
            "RESULT_LOSS": _field("absent"),
            "OTHERRESULT": _field("known", b"other"),
            "WARSCORE_FROM_BATTLE": _field("known", b"+1.00"),
            "MESSAGE_HEAD_MIL": _field("known", b"mil head"),
            "MESSENGER": _field("known", b"messenger"),
        },
    }


def _unknown_snapshot(base: bytes | None = None) -> dict:
    base = base or _base11()
    decoded = base_wire.decode(base)
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
        "failure": 9,
        "text_fields": {name: _field("unknown") for name in wire.FIELD_ORDER},
    }


def _frame(base: bytes | None = None, snapshot: dict | None = None) -> bytes:
    base = base or _base11()
    return wire.encode(base, snapshot if snapshot is not None else _known_snapshot(base))


def _offsets(frame: bytes) -> tuple[int, int]:
    base_size = struct.unpack_from("<I", frame, 6)[0]
    extension = wire.OUTER_HEADER_BYTES + base_size
    return extension, extension + wire.EXTENSION_HEADER_BYTES


def test_known_and_unknown_frames_embed_the_complete_v11_base():
    base = _base11()
    base_decoded = base_wire.decode(base)
    known = wire.encode(base, _known_snapshot(base))
    unknown = wire.encode(base, _unknown_snapshot(base))
    assert wire.validate(known) and wire.validate(unknown)

    decoded = wire.decode(known)
    for key, value in base_decoded.items():
        assert decoded[key] == value
    assert decoded["wire12"] == {"version": 12, "source": "owned_outcome_text"}
    assert decoded["outcome_text"] == {
        **{key: _known_snapshot(base)[key]
           for key in ("sequence", "raw_date", "kind", "failure")},
        "text_fields": _known_snapshot(base)["text_fields"],
    }
    base_size = struct.unpack_from("<I", known, 6)[0]
    assert known[wire.OUTER_HEADER_BYTES:wire.OUTER_HEADER_BYTES + base_size] == base
    extension, body = _offsets(known)
    assert known[extension:extension + 4] == b"OCTX"
    assert struct.unpack_from("<HI", known, extension + 4) == (
        1, len(known) - body,
    )
    source = decoded["outcome_text"]
    assert struct.unpack_from("<QiBH", known, body) == (
        source["sequence"], source["raw_date"], source["kind"], 0,
    )
    text_start = body + wire.FIXED_BODY_BYTES
    assert known[text_start] == wire.STATE_IDS["known"]
    # The next two fields are known empty and absent, respectively.
    allies_won = text_start + wire.TEXT_HEADER_BYTES + len(b"l_english")
    assert known[allies_won:allies_won + 3] == b"\x01\x00\x00"
    allies_lost = allies_won + wire.TEXT_HEADER_BYTES
    assert known[allies_lost:allies_lost + 3] == b"\x02\x00\x00"

    unknown_decoded = wire.decode(unknown)["outcome_text"]
    assert unknown_decoded["failure"] == 9
    assert all(item == _field("unknown")
               for item in unknown_decoded["text_fields"].values())
    assert wire.decode(base) == base_decoded


def test_old_versions_delegate_to_the_name_source_decoder(monkeypatch):
    calls = []

    def sentinel(data):
        calls.append(data)
        return {"legacy": data}

    monkeypatch.setattr(base_wire, "decode", sentinel)
    for version in range(1, 12):
        frame = b"IBOW" + struct.pack("<H", version) + b"legacy-bytes"
        assert wire.decode(frame) == {"legacy": frame}
    assert calls == [
        b"IBOW" + struct.pack("<H", version) + b"legacy-bytes"
        for version in range(1, 12)
    ]


@pytest.mark.parametrize("mutation", [
    "sequence", "raw_date", "kind", "failure", "language_absent",
    "mixed_failure_group", "unknown_key", "NUL", "language_format",
    "overlong_text", "text_length_bool", "field_unknown_key",
])
def test_invalid_snapshot_metadata_fields_and_groups_are_rejected(mutation):
    base = _base11()
    snapshot = _known_snapshot(base)
    if mutation == "sequence":
        snapshot["sequence"] += 1
    elif mutation == "raw_date":
        snapshot["raw_date"] += 1
    elif mutation == "kind":
        snapshot["kind"] = 3
    elif mutation == "failure":
        snapshot["failure"] = True
    elif mutation == "language_absent":
        snapshot["text_fields"]["language"] = _field("absent")
    elif mutation == "mixed_failure_group":
        snapshot["failure"] = 1
    elif mutation == "unknown_key":
        snapshot["extra"] = 1
    elif mutation == "NUL":
        snapshot["text_fields"]["YOU_WON"] = _field("known", b"A\x00B")
    elif mutation == "language_format":
        snapshot["text_fields"]["language"] = _field("known", b"l_bad-tag")
    elif mutation == "overlong_text":
        snapshot["text_fields"]["MESSENGER"] = _field("known", b"x" * (wire.MAX_TEXT_BYTES + 1))
    elif mutation == "text_length_bool":
        snapshot["text_fields"]["YOU_WON"]["length"] = True
    else:
        snapshot["text_fields"]["FAKE"] = _field("known", b"x")
    with pytest.raises(wire.OutcomeTextWireError):
        wire.encode(base, snapshot)


@pytest.mark.parametrize("key,value", [
    ("sequence", True), ("raw_date", True), ("raw_date", -1),
    ("kind", True), ("failure", True), ("failure", 10),
])
def test_bool_and_out_of_range_integer_values_are_rejected(key, value):
    snapshot = _known_snapshot()
    snapshot[key] = value
    with pytest.raises(wire.OutcomeTextWireError):
        wire.encode(_base11(), snapshot)


def test_wire_rejects_wrong_event_trailing_data_and_bad_extension_lengths():
    frame = _frame()
    extension, body = _offsets(frame)
    mutations = [
        frame + b"\x00",
        frame[:extension] + b"NOPE" + frame[extension + 4:],
        frame[:extension + 6] + struct.pack("<I", len(frame) - body - 1)
        + frame[extension + 10:],
        frame[:body] + struct.pack("<Q", struct.unpack_from("<Q", frame, body)[0] + 1)
        + frame[body + 8:],
    ]
    for bad in mutations:
        assert not wire.validate(bad)
        with pytest.raises(wire.OutcomeTextWireError):
            wire.decode(bad)


def test_encoder_rejects_a_total_frame_over_the_unchanged_base_bound(monkeypatch):
    base = _base11()
    assert wire.MAX_WIRE_BYTES == base_wire.MAX_WIRE_BYTES
    snapshot = _known_snapshot(base)
    monkeypatch.setattr(wire, "MAX_WIRE_BYTES", len(base))
    with pytest.raises(wire.OutcomeTextWireError, match="wire_size_over_bound"):
        wire.encode(base, snapshot)


def test_cpp_and_python_known_and_unknown_frames_match_byte_for_byte(tmp_path):
    requested = os.environ.get("EU4_CXX", "").strip()
    compiler = shutil.which(requested) if requested else None
    compiler = compiler or shutil.which("g++") or shutil.which("clang++")
    assert compiler, "C++ compiler is required for the cross-language wire test"
    source = ROOT / "work/native/tests/information-battle-outcome-text-wire-test.cpp"
    executable = tmp_path / ("outcome_text_wire_test.exe" if os.name == "nt"
                             else "outcome_text_wire_test")
    compiled = subprocess.run(
        [compiler, "-std=c++17", str(source), "-o", str(executable)],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr

    base = _base11()
    known_path = tmp_path / "cpp-known.bin"
    unknown_path = tmp_path / "cpp-unknown.bin"
    run = subprocess.run(
        [str(executable), str(BASE_PATH), str(known_path), str(unknown_path)],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    cpp_known = known_path.read_bytes()
    cpp_unknown = unknown_path.read_bytes()
    assert cpp_known == wire.encode(base, _known_snapshot(base))
    assert cpp_unknown == wire.encode(base, _unknown_snapshot(base))
    assert wire.decode(cpp_known)["outcome_text"] == wire.decode(
        wire.encode(base, _known_snapshot(base))
    )["outcome_text"]
    assert wire.decode(cpp_unknown)["outcome_text"] == wire.decode(
        wire.encode(base, _unknown_snapshot(base))
    )["outcome_text"]
