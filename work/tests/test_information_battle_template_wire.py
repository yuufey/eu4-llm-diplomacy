"""Offline contract tests for the pointer-free IBOW version-4 envelope."""

from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest

from work.information_battle_naval_wire import decode as decode_naval
from work.information_battle_template_wire import (
    CONTAINER_EXTENSION_VERSION,
    EXTENSION_MAGIC,
    EXTENSION_VERSION,
    MAX_ARENA_BYTES,
    MAX_AUXILIARY_TEXT_BYTES,
    MAX_KEY_BYTES,
    MAX_PAIRS,
    MAX_VALUE_BYTES,
    MAX_WIRE_BYTES,
    TemplateWireError,
    decode,
)


ROOT = Path(__file__).resolve().parents[2]
V3_FIXTURE = ROOT / "bridge" / "tests" / "fixtures" / (
    "information_battle_naval_seq3_live_v3_1374.json"
)
V2_FIXTURE = ROOT / "bridge" / "tests" / "fixtures" / (
    "information_battle_naval_seq4_recorded_v2_1374.json"
)


def fixture_payload(path: Path) -> bytes:
    return bytes.fromhex(json.loads(path.read_text(encoding="utf-8"))["payload_hex"])


def message_body(
        *, native_date: int = -1455113, flag_8c: int = 0xa1,
        flag_8d: int = 0x5e, header_word: int = 0xfeedbeef,
        header_flag: int = 0x7a, auxiliary: bytes = b"\x00\xff\x80A",
        pairs: list[tuple[bytes, bytes]] | None = None,
) -> bytes:
    values = [] if pairs is None else pairs
    body = struct.pack(
        "<iBBIBII", native_date, flag_8c, flag_8d, header_word,
        header_flag, len(values), len(auxiliary),
    ) + auxiliary
    for key, value in values:
        body += struct.pack("<I", len(key)) + key
        body += struct.pack("<I", len(value)) + value
    return body


def container_body(
        *, raw_word: int = 0x10203040, raw_flag: int = 0x91,
        pairs: list[tuple[bytes, bytes]] | None = None,
) -> bytes:
    values = [] if pairs is None else pairs
    body = struct.pack("<BIBI", 2, raw_word, raw_flag, len(values))
    for key, value in values:
        body += struct.pack("<I", len(key)) + key
        body += struct.pack("<I", len(value)) + value
    return body


def frame(base: bytes, *, present: int = 1, body: bytes | None = None,
          magic: bytes = EXTENSION_MAGIC,
          extension_version: int = EXTENSION_VERSION,
          extension_length: int | None = None) -> bytes:
    result = (b"IBOW" + struct.pack("<HI", 4, len(base)) + base
              + bytes((present,)))
    if not present:
        return result
    extension = message_body() if body is None else body
    length = len(extension) if extension_length is None else extension_length
    return (result + magic + struct.pack("<HI", extension_version, length)
            + extension)


class TemplateWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base_v3 = fixture_payload(V3_FIXTURE)
        cls.base_v2 = fixture_payload(V2_FIXTURE)

    def test_absent_preserves_complete_v3_root_and_has_no_template(self) -> None:
        encoded = frame(self.base_v3, present=0)
        decoded = decode(encoded)
        direct = decode_naval(self.base_v3)

        self.assertEqual(decoded["schema"], "information_battle_template_wire_v4")
        self.assertEqual(decoded["wire"]["version"], 4)
        self.assertEqual(decoded["wire"]["base_v3_version"], 3)
        self.assertEqual(decoded["wire"]["base_v3_bytes"], len(self.base_v3))
        self.assertFalse(decoded["wire"]["template_present"])
        self.assertIsNone(decoded["message_template"])
        for key, value in direct.items():
            if key not in {"schema", "wire"}:
                self.assertEqual(decoded[key], value)
        self.assertEqual(decode(self.base_v3), direct)

    def test_present_keeps_raw_scalars_pair_order_duplicates_and_bytes(self) -> None:
        body = message_body(
            auxiliary=b"\x00\xff\x80A",
            pairs=[
                (b"k\x00\x80", b"\x00v\xfe"),
                (b"k\x00\x80", b"one\x00"),
            ],
        )
        decoded = decode(frame(self.base_v3, body=body))
        message = decoded["message_template"]
        self.assertIsInstance(message, dict)
        assert isinstance(message, dict)
        self.assertEqual(message["native_date"], -1455113)
        self.assertEqual(message["raw_flag_8c"], 0xa1)
        self.assertEqual(message["raw_flag_8d"], 0x5e)
        self.assertEqual(message["raw_header_word_20"], 0xfeedbeef)
        self.assertEqual(message["raw_header_flag_24"], 0x7a)
        self.assertEqual(message["auxiliary_text_hex"], "00ff8041")
        self.assertEqual(message["pair_count"], 2)
        self.assertEqual(message["pairs"], [
            {"key_raw_hex": "6b0080", "value_raw_hex": "0076fe"},
            {"key_raw_hex": "6b0080", "value_raw_hex": "6f6e6500"},
        ])

    def test_formatter_container_extension_keeps_container_inputs_only(self) -> None:
        decoded = decode(frame(
            self.base_v3,
            body=container_body(pairs=[(b"k\x00", b"v"), (b"k\x00", b"last")]),
            extension_version=CONTAINER_EXTENSION_VERSION,
        ))
        message = decoded["message_template"]
        self.assertEqual(decoded["wire"]["extension_version"], 2)
        self.assertEqual(message, {
            "source_kind": "formatter_container_before_cleanup",
            "message_metadata_present": False,
            "native_date": None,
            "raw_flag_8c": None,
            "raw_flag_8d": None,
            "auxiliary_text_hex": None,
            "raw_container_word_10": 0x10203040,
            "raw_container_flag_14": 0x91,
            "pair_count": 2,
            "pairs": [
                {"key_raw_hex": "6b00", "value_raw_hex": "76"},
                {"key_raw_hex": "6b00", "value_raw_hex": "6c617374"},
            ],
        })

    def test_formatter_container_rejects_noncanonical_source_and_trailing(self) -> None:
        valid = frame(
            self.base_v3,
            body=container_body(pairs=[(b"k", b"v")]),
            extension_version=CONTAINER_EXTENSION_VERSION,
        )
        source_start = 10 + int.from_bytes(valid[6:10], "little") + 1 + 10
        invalid_source = bytearray(valid)
        invalid_source[source_start] = 1
        with self.assertRaises(TemplateWireError):
            decode(bytes(invalid_source))
        with self.assertRaises(TemplateWireError):
            decode(valid + b"\x00")

    def test_v2_and_v3_inputs_delegate_without_v4_keys(self) -> None:
        self.assertEqual(decode(self.base_v3), decode_naval(self.base_v3))
        self.assertEqual(decode(self.base_v2), decode_naval(self.base_v2))
        self.assertNotIn("message_template", decode(self.base_v3))
        self.assertNotIn("message_template", decode(self.base_v2))

    def test_field_and_arena_limits_are_value_only(self) -> None:
        boundary = message_body(
            auxiliary=b"a" * MAX_AUXILIARY_TEXT_BYTES,
            pairs=[(b"k" * MAX_KEY_BYTES, b"v" * MAX_VALUE_BYTES)],
        )
        message = decode(frame(self.base_v3, body=boundary))["message_template"]
        assert isinstance(message, dict)
        self.assertEqual(len(bytes.fromhex(message["auxiliary_text_hex"])),
                         MAX_AUXILIARY_TEXT_BYTES)
        self.assertEqual(len(bytes.fromhex(message["pairs"][0]["key_raw_hex"])),
                         MAX_KEY_BYTES)
        self.assertEqual(len(bytes.fromhex(message["pairs"][0]["value_raw_hex"])),
                         MAX_VALUE_BYTES)

        maximum = message_body(
            pairs=[(bytes((65 + i % 26,)), bytes((48 + i % 10,)))
                   for i in range(MAX_PAIRS)],
        )
        maximum_message = decode(frame(self.base_v3, body=maximum))["message_template"]
        assert isinstance(maximum_message, dict)
        self.assertEqual(maximum_message["pair_count"], MAX_PAIRS)
        self.assertEqual(maximum_message["pairs"][0],
                         {"key_raw_hex": "41", "value_raw_hex": "30"})
        self.assertEqual(maximum_message["pairs"][-1],
                         {"key_raw_hex": "58", "value_raw_hex": "37"})

        overflow_pairs = [(b"", b"v" * MAX_VALUE_BYTES) for _ in range(8)]
        overflow_body = message_body(
            auxiliary=b"a" * MAX_AUXILIARY_TEXT_BYTES,
            pairs=overflow_pairs,
        )
        self.assertGreater(
            MAX_AUXILIARY_TEXT_BYTES + 8 * MAX_VALUE_BYTES,
            MAX_ARENA_BYTES,
        )
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3, body=overflow_body))

    def test_strict_envelope_and_length_rejections(self) -> None:
        valid = frame(self.base_v3, body=message_body(pairs=[(b"k", b"v")]))
        with self.assertRaises(TemplateWireError):
            decode(valid + b"\x00")
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3, present=2))
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3, magic=b"NOPE"))
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3, extension_version=2))
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3, extension_length=len(message_body()) + 1))

        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3,
                         body=message_body(pairs=[(b"k", b"v")] * (MAX_PAIRS + 1))))
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3,
                         body=message_body(pairs=[(b"k" * (MAX_KEY_BYTES + 1), b"")])))
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3,
                         body=message_body(pairs=[(b"", b"v" * (MAX_VALUE_BYTES + 1))])))
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v3,
                         body=message_body(auxiliary=b"a" * (MAX_AUXILIARY_TEXT_BYTES + 1))))

        nested = frame(valid, present=0)
        with self.assertRaises(TemplateWireError):
            decode(nested)
        with self.assertRaises(TemplateWireError):
            decode(frame(self.base_v2, present=0))
        with self.assertRaises(TemplateWireError):
            decode(b"X" * (MAX_WIRE_BYTES + 1))


if __name__ == "__main__":
    unittest.main()
