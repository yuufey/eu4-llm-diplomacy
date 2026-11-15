"""Offline strict-contract tests for the IBOW v6 native-text envelope."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.information_battle_native_text_wire import (
    EXTENSION_MAGIC,
    NativeTextWireError,
    decode,
    decode_envelope,
    encode,
    encode_envelope,
    validate_base_v5,
)
from work.information_battle_war_identity_wire import (
    WarIdentityWireError,
    decode as decode_legacy,
)


FIXTURE = ROOT / "bridge" / "tests" / "fixtures" / (
    "information_battle_FRA_live_container_v4_1374.json"
)


def _v4_payload() -> bytes:
    return bytes.fromhex(json.loads(FIXTURE.read_text(encoding="utf-8"))["payload_hex"])


def _v5_payload() -> bytes:
    v4 = _v4_payload()
    identity = struct.pack("<BBIQiQQB", 0, 2, 0, 0, 0, 0, 0, 0)
    return b"IBOW" + struct.pack("<HI", 5, len(v4)) + v4 + b"WARI" + identity


def _snapshot(*, raw: bytes = b"title\xff", empty_aux: bool = True) -> dict:
    return {
        "definition_key": {"state": "observed", "raw_hex": b"def".hex()},
        "auxiliary_text": {
            "state": "observed",
            "raw_hex": (b"" if empty_aux else b"aux").hex(),
        },
        "title_helper_candidate": {"state": "observed", "raw_hex": raw.hex()},
        "line1_text": {"state": "absent"},
        "native_date": {"state": "observed", "value": -1455113},
        "raw_flags": {"state": "observed", "raw_8c": 0xA1, "raw_8d": 0x5E},
    }


def _offsets(frame: bytes) -> dict[str, int]:
    base_bytes = struct.unpack_from("<I", frame, 6)[0]
    extension = 10 + base_bytes
    body = extension + 10
    return {"base": 10, "base_bytes": base_bytes, "extension": extension,
            "body": body, "first_entry": body + 16}


def test_v6_preserves_v5_and_distinguishes_observed_empty_from_absent() -> None:
    base = _v5_payload()
    assert validate_base_v5(base)
    frame = encode(base, _snapshot())
    envelope = decode_envelope(frame)
    decoded = decode(frame)

    assert envelope["schema"] == "information_battle_native_text_envelope_v6"
    assert envelope["wire"]["version"] == 6
    assert envelope["wire"]["base_v5_bytes"] == len(base)
    assert envelope["wire"]["extension_magic"] == "NTXT"
    assert envelope["base_v5_payload_hex"] == base.hex()
    assert decoded["schema"] == "information_battle_native_text_wire_v6"
    assert decoded["wire"]["version"] == 5
    assert decoded["wire6"] == envelope["wire"]
    assert decoded["base_v5_payload_hex"] == base.hex()
    fields = envelope["text_fields"]
    assert fields["definition_key"] == {
        "status": "known", "state": "observed",
        "source": "message_metadata", "raw_hex": b"def".hex(),
    }
    assert fields["auxiliary_text"]["status"] == "known"
    assert fields["auxiliary_text"]["raw_hex"] == ""
    assert fields["title_helper_candidate"]["raw_hex"] == b"title\xff".hex()
    assert fields["line1_text"]["status"] == "absent"
    assert envelope["message_metadata"]["native_date"]["value"] == -1455113
    assert decoded["native_text"]["text_fields"] == fields
    assert decoded["native_text"]["message_metadata"] == envelope["message_metadata"]
    legacy = decode_legacy(base)
    for key, value in legacy.items():
        if key != "schema":
            assert decoded[key] == value
    assert decoded["complete"] is False
    assert decoded["native_text"]["full_display_complete"] is False


def test_unknown_and_absent_metadata_are_not_zero_known_values() -> None:
    base = _v5_payload()
    snapshot = {name: {"state": "unknown"} for name in (
        "definition_key", "auxiliary_text", "title_helper_candidate", "line1_text")}
    snapshot.update({
        "native_date": {"state": "absent"},
        "raw_flags": {"state": "unknown"},
    })
    decoded = decode_envelope(encode(base, snapshot))
    assert all(value["status"] == "unknown" for value in decoded["text_fields"].values()
               if value["state"] == "unknown")
    assert decoded["message_metadata"]["native_date"] == {
        "status": "absent", "state": "absent", "value": None,
    }
    assert decoded["message_metadata"]["raw_flags"]["raw_flag_8c"] is None


@pytest.mark.parametrize("mutator", [
    lambda frame, o: frame + b"\x00",
    lambda frame, o: frame[:o["extension"] + 4] + b"\x02\x00" + frame[o["extension"] + 6:],
    lambda frame, o: frame[:o["body"]] + b"\x01\x00" + frame[o["body"] + 2:],
    lambda frame, o: frame[:o["body"] + 6] + b"\x03" + frame[o["body"] + 7:],
    lambda frame, o: frame[:o["first_entry"] + 2] + b"\x03" + frame[o["first_entry"] + 3:],
])
def test_strict_extension_flags_version_source_and_trailing(mutator) -> None:
    frame = encode(_v5_payload(), _snapshot())
    with pytest.raises(NativeTextWireError):
        decode(mutator(frame, _offsets(frame)))


def test_strict_entry_state_length_and_base_mismatch() -> None:
    frame = encode(_v5_payload(), _snapshot())
    offsets = _offsets(frame)
    first = offsets["first_entry"]

    # The first field is observed with a one-byte value.  Marking it unknown
    # without removing the byte must fail rather than silently dropping data.
    unknown_with_bytes = bytearray(frame)
    unknown_with_bytes[first + 1] = 0
    with pytest.raises(NativeTextWireError):
        decode(bytes(unknown_with_bytes))

    bad_base = bytearray(frame)
    bad_base[offsets["base"]] = ord("X")
    with pytest.raises(NativeTextWireError):
        decode(bytes(bad_base))

    bad_length = bytearray(frame)
    struct.pack_into("<I", bad_length, offsets["extension"] + 6,
                     struct.unpack_from("<I", frame, offsets["extension"] + 6)[0] + 1)
    with pytest.raises(NativeTextWireError):
        decode(bytes(bad_length))


def test_encoder_rejects_source_mismatch_bounds_and_invalid_hex() -> None:
    base = _v5_payload()
    bad_source = _snapshot()
    bad_source["title_helper_candidate"]["source"] = "message_metadata"
    with pytest.raises(NativeTextWireError):
        encode(base, bad_source)

    too_long = _snapshot(raw=b"x" * 8193)
    with pytest.raises(NativeTextWireError):
        encode(base, too_long)

    key_too_long = _snapshot()
    key_too_long["definition_key"]["raw_hex"] = (b"k" * 257).hex()
    with pytest.raises(NativeTextWireError):
        encode(base, key_too_long)

    bad_hex = _snapshot()
    bad_hex["title_helper_candidate"]["raw_hex"] = "not-hex"
    with pytest.raises(NativeTextWireError):
        encode(base, bad_hex)

    unobserved_bytes = _snapshot()
    unobserved_bytes["line1_text"] = {"state": "absent", "raw_hex": "00"}
    with pytest.raises(NativeTextWireError):
        encode(base, unobserved_bytes)


def test_raw_non_utf8_is_preserved_without_text_semantics() -> None:
    decoded = decode_envelope(encode(_v5_payload(), _snapshot(raw=b"\xff\xfe\x00")))
    assert decoded["text_fields"]["title_helper_candidate"]["raw_hex"] == "fffe00"
    assert "value" not in decoded["text_fields"]["title_helper_candidate"]
    assert decoded["full_display_complete"] is False


def test_v6_does_not_delegate_old_v5_as_v6_or_accept_nested_base() -> None:
    frame = encode(_v5_payload(), _snapshot())
    with pytest.raises(NativeTextWireError):
        encode(frame, _snapshot())
    with pytest.raises(WarIdentityWireError):
        decode(frame[:4] + struct.pack("<H", 5) + frame[6:])


def test_legacy_versions_delegate_unchanged_and_malformed_v4_is_not_complete_v5() -> None:
    base = _v5_payload()
    assert decode(base) == decode_legacy(base)

    # A 10-byte v4 header has no payload and is only useful for testing the
    # framing-only helper.  The public encoder/decoder must reject it.
    empty_v4 = b"IBOW" + struct.pack("<HI", 4, 0)
    identity = struct.pack("<BBIQiQQB", 0, 2, 0, 0, 0, 0, 0, 0)
    malformed_v5 = (
        b"IBOW" + struct.pack("<HI", 5, len(empty_v4)) + empty_v4
        + b"WARI" + identity
    )
    assert validate_base_v5(malformed_v5) is False
    framing_only = encode_envelope(malformed_v5, _snapshot())
    envelope = decode_envelope(framing_only)
    assert envelope["base_v5_payload_hex"] == malformed_v5.hex()
    with pytest.raises(NativeTextWireError):
        encode(malformed_v5, _snapshot())
    with pytest.raises(NativeTextWireError):
        decode(framing_only)


def test_v6_composition_retains_template_context_naval_and_war_identity() -> None:
    base = _v5_payload()
    legacy = decode_legacy(base)
    composed = decode(encode(base, _snapshot()))
    for key in ("observation", "context", "naval", "message_template",
                "war_identity"):
        assert composed[key] == legacy[key]
    assert composed["wire"] == legacy["wire"]
    assert composed["native_text"]["complete"] is False
