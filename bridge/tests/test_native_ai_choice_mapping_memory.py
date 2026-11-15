"""Literal fake-memory tests for the pinned B23 AI-choice mapping proof."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import native_ai_choice_mapping_memory as mapping


GAME_BASE = 0x140000000
DLL_BASE = 0x7FFA07C70000
HOOK_POINTER = DLL_BASE + 0x56850
NATIVE_TRUE_POINTER = GAME_BASE + 0x8F440
ASSET_PATH = (Path(__file__).resolve().parents[1]
              / "information/profiles/native-ai-choice-hook-v33.json")
ASSET_SHA256 = "4efce12378fa3b7fc0a72911243c12b9c2af0ee26b33de6c72b14c3402aa807f"


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: value for offset, value in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            return bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped bytes") from exc


def _asset() -> dict:
    raw = ASSET_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ASSET_SHA256
    return json.loads(raw.decode("utf-8"))


def _hook_image() -> tuple[MemoryImage, dict]:
    asset = _asset()
    image = MemoryImage()
    image.put(DLL_BASE, bytes.fromhex(asset["dos_prefix_hex"]))
    image.put(DLL_BASE + 0x80, bytes.fromhex(asset["coff_prefix_hex"]))
    image.put(DLL_BASE + 0x98, bytes.fromhex(asset["optional_header_magic_hex"]))
    image.put_u32(DLL_BASE + 0xD0, 0xD49000)
    image.put(DLL_BASE + 0x56850, bytes.fromhex(asset["body_hex"]))
    image.put_u64(DLL_BASE + 0xD34560, GAME_BASE)
    image.put_u64(DLL_BASE + 0x72C0B8, NATIVE_TRUE_POINTER)
    image.put(NATIVE_TRUE_POINTER, b"\xB0\x01\xC3")
    return image, asset


def _proof(image: MemoryImage, pointer: int = HOOK_POINTER) -> dict:
    return mapping.read_mapping(common._Trace(image), GAME_BASE, pointer, phase="before")


def test_stock_native_true_mapping_reads_only_the_three_byte_stub():
    image = MemoryImage()
    image.put(NATIVE_TRUE_POINTER, b"\xB0\x01\xC3")
    trace = common._Trace(image)

    proof = mapping.read_mapping(trace, GAME_BASE, NATIVE_TRUE_POINTER, phase="before")

    assert proof["schema"] == "information.native_ai_choice_mapping_memory.v1"
    assert proof["mode"] == "native_true"
    assert proof["game_base"] == hex(GAME_BASE)
    assert proof["actual_pointer"] == hex(NATIVE_TRUE_POINTER)
    assert proof["predicate_body_hex"] == "b001c3"
    assert proof["asset_sha256"] == ASSET_SHA256
    assert [row[1] for row in image.reads] == [3]
    assert trace.summary()["calls"] == 1
    assert trace.summary()["bytes_requested"] == 3


def test_pinned_gui_forwarding_hook_matches_header_body_and_original_pointer():
    image, asset = _hook_image()
    trace = common._Trace(image)

    proof = mapping.read_mapping(trace, GAME_BASE, HOOK_POINTER, phase="before")

    assert proof["mode"] == "installed_observer_gui_forwarding"
    assert proof["module_base"] == hex(DLL_BASE)
    assert proof["actual_pointer"] == hex(HOOK_POINTER)
    assert proof["module_size_of_image"] == 0xD49000
    assert proof["body_rva"] == "0x56850"
    assert proof["body_length"] == 1167
    assert proof["body_raw_hex"] == asset["body_hex"]
    assert proof["body_matches_pinned_asset"] is True
    assert proof["body_sha256"] == "51c57947e41feb61d935cb04c2bd6cc007f326fc9dc94c3d9b78cd990c29f24d"
    assert proof["observed_game_base"] == hex(GAME_BASE)
    assert proof["saved_original_pointer"] == hex(NATIVE_TRUE_POINTER)
    assert proof["saved_original_body_hex"] == "b001c3"
    assert proof["whole_loaded_dll_hash_verified"] is False
    assert proof["proof_scope"] == (
        "guarded_EF2B00_GUI_caller_only; AI_turn_hold_path_not_in_scope")
    body_reads = [row for row in image.reads if "hook_body_" in row[2]]
    assert [row[1] for row in body_reads] == [1024, 143]
    assert trace.summary()["max_single_read_bytes"] == 1024
    assert trace.summary()["bytes_requested"] <= 64 * 1024
    assert trace.summary()["calls"] <= 128


@pytest.mark.parametrize("damage", [
    "body", "dos", "coff", "magic", "size_image", "game_base_global",
    "saved_original_pointer", "saved_original_body", "unaligned_pointer",
    "unsupported_pointer",
])
def test_unrecognized_hook_or_pointer_fails_closed(damage: str):
    image, _asset_value = _hook_image()
    pointer = HOOK_POINTER
    if damage == "body":
        image.put(HOOK_POINTER + 5, b"\x00")
    elif damage == "dos":
        image.put(DLL_BASE, b"\x00")
    elif damage == "coff":
        image.put(DLL_BASE + 0x80, b"\x00")
    elif damage == "magic":
        image.put(DLL_BASE + 0x98, b"\x00\x00")
    elif damage == "size_image":
        image.put_u32(DLL_BASE + 0xD0, 0xD48000)
    elif damage == "game_base_global":
        image.put_u64(DLL_BASE + 0xD34560, GAME_BASE + 0x1000)
    elif damage == "saved_original_pointer":
        image.put_u64(DLL_BASE + 0x72C0B8, NATIVE_TRUE_POINTER + 8)
    elif damage == "saved_original_body":
        image.put(NATIVE_TRUE_POINTER, b"\x31\x00\xC3")
    elif damage == "unaligned_pointer":
        pointer = HOOK_POINTER + 1
    else:
        pointer = GAME_BASE + 0x8F448

    with pytest.raises(common._Unknown):
        _proof(image, pointer)


def test_helper_uses_the_permission_trace_budget_instead_of_a_private_reader():
    image = MemoryImage()
    image.put(NATIVE_TRUE_POINTER, b"\xB0\x01\xC3")
    image.put(GAME_BASE + 0x10000, b"\x00" * 128)
    trace = common._Trace(image)
    for index in range(128):
        trace.exact(GAME_BASE + 0x10000 + index, 1, f"budget.fill.{index}")

    with pytest.raises(common._Unknown, match="READ_BUDGET_EXCEEDED"):
        mapping.read_mapping(trace, GAME_BASE, NATIVE_TRUE_POINTER, phase="after")
    assert trace.summary()["calls"] == 128
