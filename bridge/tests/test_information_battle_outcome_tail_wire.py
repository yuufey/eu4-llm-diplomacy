"""IBOW v13/SCTX wire checks against the immutable v12 base codec."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from work import information_battle_outcome_text_wire as base_wire
from work import information_battle_outcome_tail_wire as wire
from bridge.tests.test_information_battle_outcome_text_wire import (
    _base11, _field, _known_snapshot,
)


ROOT = Path(__file__).resolve().parents[2]


def _base12() -> bytes:
    base11 = _base11()
    return base_wire.encode(base11, _known_snapshot(base11))


def _snapshot(base12: bytes | None = None, *, failed: bool = False) -> dict:
    base12 = base12 or _base12()
    decoded = base_wire.decode(base12)
    failure = 8 if failed else 0
    return {
        "sequence": decoded["observation"]["sequence"],
        "raw_date": decoded["observation"]["result"]["raw_date"],
        "kind": decoded["context"]["kind"],
        "failure": failure,
        "reserved_slots": [0, 0, 0] if failed else [-7, 0, -7],
        "text_fields": ({name: _field("unknown") for name in wire.FIELD_ORDER}
                        if failed else {
                            "language": _field("known", b"l_english"),
                            "COMBAT_FLEE": _field("known", b""),
                            "COMBAT_TRIUMPH": _field("absent"),
                            "COMBAT_WINNERTYPE_OUR": _field("known", b"our"),
                            "COMBAT_WINNERTYPE_THEIR": _field("known", b"their"),
                        }),
    }


def _frame(base12: bytes | None = None, *, failed: bool = False) -> bytes:
    base12 = base12 or _base12()
    return wire.encode(base12, _snapshot(base12, failed=failed))


def _body_offset(frame: bytes) -> tuple[int, int]:
    base_size = struct.unpack_from("<I", frame, 6)[0]
    extension = wire.OUTER_HEADER_BYTES + base_size
    return extension, extension + wire.EXTENSION_HEADER_BYTES


def test_known_and_failed_frames_embed_complete_v12_and_parse_order_slots():
    base12 = _base12()
    original = base_wire.decode(base12)
    known = _frame(base12)
    failed = _frame(base12, failed=True)
    assert wire.validate(known) and wire.validate(failed)

    decoded = wire.decode(known)
    assert decoded["wire12"] == original["wire12"]
    assert decoded["wire13"] == {"version": 13, "source": "owned_outcome_tail"}
    tail = decoded["outcome_tail"]
    assert (tail["sequence"], tail["raw_date"], tail["kind"]) == (
        original["observation"]["sequence"],
        original["observation"]["result"]["raw_date"],
        original["context"]["kind"],
    )
    assert tail["failure"] == 0
    assert tail["reserved_slots"] == [-7, 0, -7]
    assert list(tail["text_fields"]) == list(wire.FIELD_ORDER)
    assert tail["text_fields"]["COMBAT_FLEE"] == _field("known", b"")
    assert tail["text_fields"]["COMBAT_TRIUMPH"] == _field("absent")

    extension, body = _body_offset(known)
    assert known[4:6] == struct.pack("<H", 13)
    assert known[10:10 + len(base12)] == base12
    assert known[extension:extension + 4] == b"SCTX"
    assert struct.unpack_from("<I", known, extension + 6)[0] == len(known) - body
    assert struct.unpack_from("<QiBHiii", known, body) == (
        tail["sequence"], tail["raw_date"], tail["kind"], 0, -7, 0, -7,
    )
    assert known[body + wire.FIXED_BODY_BYTES] == wire.STATE_IDS["known"]

    failed_tail = wire.decode(failed)["outcome_tail"]
    assert failed_tail["failure"] == 8
    assert failed_tail["reserved_slots"] == [0, 0, 0]
    assert all(item["state"] == "unknown" and item["length"] == 0
               for item in failed_tail["text_fields"].values())


def test_versions_one_through_twelve_delegate_to_v12_unchanged(monkeypatch):
    calls = []

    def sentinel(data):
        calls.append(data)
        return {"legacy": data}

    monkeypatch.setattr(base_wire, "decode", sentinel)
    frames = [b"IBOW" + struct.pack("<H", version) + b"legacy bytes"
              for version in range(1, 13)]
    assert [wire.decode(frame) for frame in frames] == [
        {"legacy": frame} for frame in frames
    ]
    assert calls == frames


@pytest.mark.parametrize("mutation", [
    "sequence", "raw_date", "kind", "failure_high", "reserved_count",
    "reserved_bool", "reserved_range", "failed_reserved", "language_absent",
    "mixed_failed_group", "bad_language", "text_nul", "overlong_text",
])
def test_invalid_v13_snapshots_are_rejected(mutation):
    base12 = _base12()
    snapshot = _snapshot(base12)
    if mutation == "sequence":
        snapshot["sequence"] += 1
    elif mutation == "raw_date":
        snapshot["raw_date"] += 1
    elif mutation == "kind":
        snapshot["kind"] = 3
    elif mutation == "failure_high":
        snapshot["failure"] = 10
    elif mutation == "reserved_count":
        snapshot["reserved_slots"] = [1, 2]
    elif mutation == "reserved_bool":
        snapshot["reserved_slots"][0] = True
    elif mutation == "reserved_range":
        snapshot["reserved_slots"][0] = 1 << 31
    elif mutation == "failed_reserved":
        snapshot["failure"] = 1
        snapshot["reserved_slots"] = [-1, 0, 0]
        snapshot["text_fields"] = {
            name: _field("unknown") for name in wire.FIELD_ORDER
        }
    elif mutation == "language_absent":
        snapshot["text_fields"]["language"] = _field("absent")
    elif mutation == "mixed_failed_group":
        snapshot["failure"] = 1
    elif mutation == "bad_language":
        snapshot["text_fields"]["language"] = _field("known", b"English")
    elif mutation == "text_nul":
        snapshot["text_fields"]["COMBAT_FLEE"] = _field("known", b"A\x00B")
    else:
        snapshot["text_fields"]["COMBAT_WINNERTYPE_THEIR"] = _field(
            "known", b"x" * (wire.MAX_TEXT_BYTES + 1))
    with pytest.raises(wire.OutcomeTailWireError):
        wire.encode(base12, snapshot)


def test_wire_rejects_malformed_base12_and_outer_framing():
    frame = _frame()
    extension, body = _body_offset(frame)
    base_size = struct.unpack_from("<I", frame, 6)[0]
    broken_base12 = bytearray(frame[10:10 + base_size])
    inner_size = struct.unpack_from("<I", broken_base12, 6)[0]
    base12_extension = 10 + inner_size
    broken_base12[base12_extension] ^= 1
    bad = bytearray(frame)
    bad[10:10 + base_size] = broken_base12
    mutations = [
        frame + b"\x00",
        frame[:extension] + b"NOPE" + frame[extension + 4:],
        frame[:body] + struct.pack("<Q", struct.unpack_from("<Q", frame, body)[0] + 1)
        + frame[body + 8:],
        bytes(bad),
    ]
    for invalid in mutations:
        assert not wire.validate(invalid)
        with pytest.raises(wire.OutcomeTailWireError):
            wire.decode(invalid)


def test_cpp_and_python_known_and_failed_frames_match_byte_for_byte(tmp_path):
    requested = os.environ.get("EU4_CXX", "").strip()
    compiler = shutil.which(requested) if requested else None
    compiler = compiler or shutil.which("g++") or shutil.which("clang++")
    assert compiler, "C++ compiler is required for the cross-language wire test"
    source = ROOT / "work/native/tests/information-battle-outcome-tail-wire-test.cpp"
    executable = tmp_path / ("outcome_tail_wire_test.exe" if os.name == "nt"
                             else "outcome_tail_wire_test")
    compiled = subprocess.run(
        [compiler, "-std=c++17", str(source), "-o", str(executable)],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr

    base12_path = tmp_path / "base12.bin"
    known_path = tmp_path / "cpp-known13.bin"
    failed_path = tmp_path / "cpp-failed13.bin"
    base12_path.write_bytes(_base12())
    run = subprocess.run(
        [str(executable), str(base12_path), str(known_path), str(failed_path)],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    cpp_known = known_path.read_bytes()
    cpp_failed = failed_path.read_bytes()
    assert cpp_known == wire.encode(_base12(), _snapshot(_base12()))
    assert cpp_failed == wire.encode(_base12(), _snapshot(_base12(), failed=True))
    assert wire.decode(cpp_known)["outcome_tail"] == wire.decode(
        wire.encode(_base12(), _snapshot(_base12()))
    )["outcome_tail"]

