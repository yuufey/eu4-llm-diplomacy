"""Focused v5 WARI decoder tests.

The bound case wraps a real archived v4 battle frame.  The tests exercise the
wire boundary only; they do not access EU4, a process, REA, or a native call.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct

import pytest

from work.information_battle_observation_wire import decode as decode_v1
from work.information_battle_template_wire import decode as decode_v4
from work.information_battle_war_identity_wire import (
    BINDING_FLAGS,
    EXTENSION_MAGIC,
    IDENTITY_FIXED_BYTES,
    MAX_WAR_ID_BYTES,
    STATUS_ABSENT,
    STATUS_BOUND,
    STATUS_INVALID,
    WarIdentityWireError,
    decode,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "bridge" / "tests" / "fixtures"
REAL_V4 = FIXTURES / "information_battle_FRA_live_container_v4_1374.json"


def _fixture_payload(name: str) -> bytes:
    record = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return bytes.fromhex(record["payload_hex"])


def _bound_id() -> bytes:
    value = b"war_0123456789abcdef_01234567"
    assert len(value) == MAX_WAR_ID_BYTES
    return value


def _full_ref(tag: bytes, marker: int) -> int:
    assert len(tag) == 3
    return int.from_bytes(tag + bytes((marker, 1, 0, 0, 0)), "little")


def _identity_body(*, status: int, reason: int = 0,
                   binding_flags: int = 0, creation: int = 0,
                   raw_date: int = 0, pair: tuple[int, int] = (0, 0),
                   war_id: bytes = b"") -> bytes:
    return (struct.pack("<BBIQiQQB", status, reason, binding_flags,
                        creation, raw_date, pair[0], pair[1], len(war_id))
            + war_id)


def _wrap_v5(base: bytes, body: bytes) -> bytes:
    return (b"IBOW" + struct.pack("<HI", 5, len(base)) + base
            + EXTENSION_MAGIC + body)


def _real_v4() -> tuple[bytes, dict]:
    raw = _fixture_payload(REAL_V4.name)
    return raw, decode_v4(raw)


def test_real_v4_wrapper_decodes_bound_identity_and_preserves_base() -> None:
    base, old = _real_v4()
    raw_date = old["observation"]["result"]["raw_date"]
    refs = (_full_ref(b"FRA", 1), _full_ref(b"ORL", 2))
    body = _identity_body(
        status=STATUS_BOUND,
        binding_flags=BINDING_FLAGS,
        creation=132_456_789,
        raw_date=raw_date,
        pair=refs,
        war_id=_bound_id(),
    )
    wrapped = _wrap_v5(base, body)
    decoded = decode(wrapped)

    assert decode(base) == old
    assert decoded["schema"] == "information_battle_war_identity_wire_v5"
    assert decoded["wire"]["version"] == 5
    assert decoded["wire"]["base_v4_bytes"] == len(base)
    assert decoded["wire"]["extension_magic"] == "WARI"
    assert decoded["wire"]["extension_bytes"] == IDENTITY_FIXED_BYTES + 29
    assert decoded["observation"] == old["observation"]
    assert decoded["context"] == old["context"]
    assert decoded["message_template"] == old["message_template"]
    assert decoded["war_identity"] == {
        "status": "bound",
        "reason": 0,
        "binding_flags": BINDING_FLAGS,
        "process_creation_filetime": 132_456_789,
        "raw_date": raw_date,
        "pair_full_refs": list(refs),
        "war_id": _bound_id().decode("ascii"),
        "identity_scope": "observer_session",
    }
    base_length = struct.unpack_from("<I", wrapped, 6)[0]
    assert wrapped[10 + base_length:14 + base_length] == b"WARI"


def test_legacy_v1_and_v2_shapes_are_delegated_unchanged() -> None:
    v1 = _fixture_payload("information_battle_live_v2_1374.json")
    # The fixture is v2; its embedded v1 is obtained from the v2 length field.
    v1_length = struct.unpack_from("<I", v1, 6)[0]
    inner = v1[10:10 + v1_length]
    assert decode(inner) == decode_v1(inner)
    assert "war_identity" not in decode(inner)

    v2 = _fixture_payload("information_battle_FRA_live_v2_1374.json")
    expected = decode_v4(v2)
    actual = decode(v2)
    assert actual == expected
    assert "war_identity" not in actual


def test_absent_and_invalid_identity_are_explicit_and_id_free() -> None:
    base, old = _real_v4()
    raw_date = old["observation"]["result"]["raw_date"]
    absent = decode(_wrap_v5(
        base,
        _identity_body(status=STATUS_ABSENT, reason=2),
    ))
    assert absent["war_identity"]["status"] == "absent"
    assert absent["war_identity"]["war_id"] is None
    assert absent["war_identity"]["reason"] == 2

    invalid = decode(_wrap_v5(
        base,
        _identity_body(status=STATUS_INVALID, reason=5,
                       binding_flags=0xfeed, creation=4_242,
                       raw_date=raw_date, pair=(1, 2)),
    ))
    assert invalid["war_identity"]["status"] == "invalid"
    assert invalid["war_identity"]["war_id"] is None
    assert invalid["war_identity"]["pair_full_refs"] == [1, 2]


@pytest.mark.parametrize("mutate", [
    lambda body, date: _identity_body(
        status=STATUS_BOUND, binding_flags=0, creation=1,
        raw_date=date, pair=(_full_ref(b"FRA", 1), _full_ref(b"ORL", 2)),
        war_id=_bound_id()),
    lambda body, date: _identity_body(
        status=STATUS_BOUND, reason=1, binding_flags=BINDING_FLAGS,
        creation=1, raw_date=date,
        pair=(_full_ref(b"FRA", 1), _full_ref(b"ORL", 2)),
        war_id=_bound_id()),
    lambda body, date: _identity_body(
        status=STATUS_BOUND, binding_flags=BINDING_FLAGS, creation=0,
        raw_date=date, pair=(_full_ref(b"FRA", 1), _full_ref(b"ORL", 2)),
        war_id=_bound_id()),
    lambda body, date: _identity_body(
        status=STATUS_BOUND, binding_flags=BINDING_FLAGS, creation=1,
        raw_date=date + 1, pair=(_full_ref(b"FRA", 1), _full_ref(b"ORL", 2)),
        war_id=_bound_id()),
    lambda body, date: _identity_body(
        status=STATUS_BOUND, binding_flags=BINDING_FLAGS, creation=1,
        raw_date=date, pair=(_full_ref(b"FRA", 1), _full_ref(b"FRA", 1)),
        war_id=_bound_id()),
    lambda body, date: _identity_body(
        status=STATUS_BOUND, binding_flags=BINDING_FLAGS, creation=1,
        raw_date=date, pair=(_full_ref(b"FRA", 1), _full_ref(b"ORL", 2)),
        war_id=_bound_id()[:-1]),
])
def test_bound_guard_failures_are_rejected(mutate) -> None:
    base, old = _real_v4()
    body = mutate(b"", old["observation"]["result"]["raw_date"])
    with pytest.raises(WarIdentityWireError):
        decode(_wrap_v5(base, body))


def test_malformed_extension_and_non_v4_base_are_rejected() -> None:
    base, old = _real_v4()
    date = old["observation"]["result"]["raw_date"]
    good = _wrap_v5(base, _identity_body(
        status=STATUS_BOUND, binding_flags=BINDING_FLAGS, creation=1,
        raw_date=date, pair=(_full_ref(b"FRA", 1), _full_ref(b"ORL", 2)),
        war_id=_bound_id()))

    with pytest.raises(WarIdentityWireError):
        decode(good[: -1])
    bad_magic = bytearray(good)
    base_length = struct.unpack_from("<I", good, 6)[0]
    bad_magic[10 + base_length:14 + base_length] = b"NOPE"
    with pytest.raises(WarIdentityWireError):
        decode(bytes(bad_magic))

    v3 = _fixture_payload("information_battle_naval_seq3_live_v3_1374.json")
    nested = b"IBOW" + struct.pack("<HI", 5, len(v3)) + v3
    nested += EXTENSION_MAGIC + _identity_body(status=STATUS_ABSENT)
    with pytest.raises(WarIdentityWireError):
        decode(nested)
