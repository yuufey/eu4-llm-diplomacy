"""Offline synthetic-memory tests for the foreign military permission leaf."""
from __future__ import annotations

import json

import pytest

from bridge.information import foreign_military_visibility_memory as memory


BASE = 0x140000000
DB = 0x6000000000
TABLE = 0x6100000000
WORLD = 0x6200000000
SETTINGS = 0x6300000000
COUNTRY_BASE = 0x6400000000
NODE_BASE = 0x6500000000
RECORD_BASE = 0x6600000000
DATE = 56_564_448
OBSERVER_SLOT = 189
TARGET_SLOT = 300


def _fullref(tag: str, slot: int, generation: int = 0x1234) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.error_at: set[int] = set()
        self.short_at: set[int] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + index: byte for index, byte in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic underlying read error")
        try:
            raw = bytes(self.data[address + index] for index in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped read") from exc
        return raw[:-1] if address in self.short_at else raw


def _binding(tag: str, slot: int, pointer: int, generation: int = 0x1234) -> dict:
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + 0x20),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(TABLE + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _environment(public_a: int = 0, public_b: int = 0,
                 *, game_date: int = DATE) -> tuple[MemoryImage, dict, dict]:
    image = MemoryImage()
    observer_pointer = COUNTRY_BASE + OBSERVER_SLOT * 0x1000
    target_pointer = COUNTRY_BASE + TARGET_SLOT * 0x1000
    observer = _binding("FRA", OBSERVER_SLOT, observer_pointer)
    target = _binding("ENG", TARGET_SLOT, target_pointer, generation=0x2345)

    # Targeted database slot echoes used by the shared country-binding helper.
    image.put_u64(BASE + 0x233D8B0, DB)
    image.put_u64(DB + 0x118, TABLE)
    image.put_i32(DB + 0x124, TARGET_SLOT + 1)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, observer_pointer)
    image.put_u64(TABLE + TARGET_SLOT * 8, target_pointer)
    image.put_u64(observer_pointer + 0x20, _fullref("FRA", OBSERVER_SLOT))
    image.put_u64(target_pointer + 0x20, _fullref("ENG", TARGET_SLOT, 0x2345))

    image.put_u64(BASE + memory.WORLD_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + memory.WORLD_SETTINGS_OFFSET, SETTINGS)
    image.put_i32(SETTINGS + memory.PUBLIC_OPTIONS_OFFSET, public_a)
    image.put_i32(SETTINGS + memory.PUBLIC_OPTIONS_SECOND_OFFSET, public_b)
    image.put_i32(WORLD + memory.WORLD_DATE_OFFSET, game_date)
    return image, observer, target


def _put_entry(image: MemoryImage, index: int, record_ref: int,
               expiry: int = DATE + 1, *, next_index: int | None = None) -> tuple[int, int]:
    node = NODE_BASE + index * 0x100
    record = RECORD_BASE + index * 0x100
    next_node = 0 if next_index is None else NODE_BASE + next_index * 0x100
    image.put_u64(node + memory.NODE_RECORD_POINTER_OFFSET, record)
    image.put_u64(node + memory.NODE_NEXT_POINTER_OFFSET, next_node)
    image.put_u64(record + memory.RECORD_OBSERVER_FULLREF_OFFSET, record_ref)
    image.put_i32(record + memory.RECORD_EXPIRY_DATE_OFFSET, expiry)
    return node, record


def _run(image: MemoryImage, observer: dict, target: dict) -> dict:
    return memory.read_permission(image, BASE, observer, target)


def test_public_options_fast_path_does_not_read_timed_list_or_date():
    image, observer, target = _environment(public_a=0, public_b=0)

    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["admitted"] is True
    assert result["mode"] == "public_options"
    labels = [label for _address, _size, label in image.reads]
    assert "target.timed_entry_head" not in labels
    assert "world.game_date" not in labels
    assert result["raw_inputs"]["budget"]["calls"] == len(image.reads)
    assert result["raw_inputs"]["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)


def test_active_timed_entry_uses_exact_observer_reference_and_strict_date_comparison():
    image, observer, target = _environment(public_a=1)
    node, _record = _put_entry(image, 0, _fullref("FRA", OBSERVER_SLOT), DATE + 1)
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, node)

    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["admitted"] is True
    assert result["mode"] == "active_timed_entry"
    assert result["raw_inputs"]["game_date"]["value"] == DATE
    assert result["raw_inputs"]["timed_entries"][0]["expiry_date"]["value"] == DATE + 1


def test_expiry_equal_to_date_is_false_and_first_matching_entry_wins():
    image, observer, target = _environment(public_b=1)
    first, _ = _put_entry(image, 0, _fullref("FRA", OBSERVER_SLOT), DATE,
                          next_index=1)
    _put_entry(image, 1, _fullref("FRA", OBSERVER_SLOT), DATE + 100)
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, first)

    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["mode"] == "expired_timed_entry"
    assert len(result["raw_inputs"]["timed_entries"]) == 1
    assert not any(label == "timed_node[1].record_fullref" for _, _, label in image.reads)


def test_nonmatching_chain_returns_no_timed_entry_without_reading_date_or_expiry():
    image, observer, target = _environment(public_a=1)
    head, _ = _put_entry(image, 0, _fullref("POR", 190), next_index=1)
    _put_entry(image, 1, _fullref("HAB", 191))
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, head)

    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["mode"] == "no_timed_entry"
    labels = [label for _, _, label in image.reads]
    assert "world.game_date" not in labels
    assert "timed_node[0].expiry_date" not in labels
    assert "timed_node[1].expiry_date" not in labels


def test_null_chain_is_known_false_without_date_read():
    image, observer, target = _environment(public_a=1)
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, 0)

    result = _run(image, observer, target)

    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["mode"] == "no_timed_entry"
    assert not any(label == "world.game_date" for _, _, label in image.reads)


def test_first_matching_slot_with_wrong_generation_is_unknown_and_not_overridden():
    image, observer, target = _environment(public_a=1)
    head, _ = _put_entry(image, 0, _fullref("FRA", OBSERVER_SLOT, 0x3456),
                         next_index=1)
    _put_entry(image, 1, _fullref("FRA", OBSERVER_SLOT, 0x1234), DATE + 50)
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, head)

    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == "MATCHED_OBSERVER_FULLREF_MISMATCH"
    assert result["reason"].isupper()
    assert len(result["private_inputs"]["timed_entries"]) == 1
    assert not any(label == "world.game_date" for _, _, label in image.reads)
    assert not any(label == "timed_node[1].record_fullref" for _, _, label in image.reads)


def test_cycle_and_node_limit_fail_unknown_not_false():
    image, observer, target = _environment(public_a=1)
    first, _ = _put_entry(image, 0, _fullref("POR", 190), next_index=0)
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, first)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "TIMED_LIST_CYCLE"
    assert result["reason"].isupper()

    image, observer, target = _environment(public_a=1)
    for index in range(memory.MAX_NODES + 1):
        _put_entry(image, index, _fullref("POR", 190),
                   next_index=index + 1 if index < memory.MAX_NODES else None)
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, NODE_BASE)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "TIMED_LIST_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    ("head", "record", "expected"),
    [
        (0x10, None, "TIMED_NODE_POINTER_INVALID"),
        (NODE_BASE, 0x10, "TIMED_RECORD_POINTER_INVALID"),
    ],
)
def test_invalid_timed_node_or_record_pointer_is_unknown(head: int, record: int | None,
                                                          expected: str):
    image, observer, target = _environment(public_a=1)
    if record is None:
        image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET,
                      head)
    else:
        image.put_u64(head + memory.NODE_RECORD_POINTER_OFFSET, record)
        image.put_u64(head + memory.NODE_NEXT_POINTER_OFFSET, 0)
        image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET,
                      head)

    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == expected
    assert result["reason"].isupper()
    assert not any(label == "world.game_date" for _, _, label in image.reads)


def test_live_binding_generation_change_is_unknown():
    image, observer, target = _environment(public_a=0)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, int(observer["country_pointer"], 0))
    image.put_u64(int(observer["country_pointer"], 0) + 0x20,
                  _fullref("FRA", OBSERVER_SLOT, 0x2222))

    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_BINDING_DATABASE_MISMATCH"
    assert result["reason"].isupper()


@pytest.mark.parametrize("failure", ["short", "error"])
def test_required_rpm_failure_is_unknown_with_failed_operand(failure: str):
    image, observer, target = _environment(public_a=1)
    image.put_u64(int(target["country_pointer"], 0) + memory.TARGET_TIMED_HEAD_OFFSET, 0)
    settings_address = SETTINGS + memory.PUBLIC_OPTIONS_OFFSET
    if failure == "short":
        image.short_at.add(settings_address)
    else:
        image.error_at.add(settings_address)

    result = _run(image, observer, target)

    assert result["status"] == "unknown"
    assert result["reason"] == "READ_FAILED"
    assert result["reason"].isupper()
    assert result["private_inputs"]["reads"][-1]["status"] == "failed"


def test_observer_must_be_fra_and_binding_boolean_is_rejected_before_rpm():
    image, observer, target = _environment()
    bad_observer = _binding("ENG", OBSERVER_SLOT,
                            int(observer["country_pointer"], 0))
    result = _run(image, bad_observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_NOT_FRA"
    assert image.reads == []

    image, observer, target = _environment()
    bad_observer = dict(observer)
    bad_observer["slot"] = True
    result = _run(image, bad_observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_BINDING_INVALID"
    assert image.reads == []


def test_binding_alias_and_module_base_invalid_are_fail_closed():
    image, observer, target = _environment()
    aliased_target = _binding("ENG", TARGET_SLOT, int(observer["country_pointer"], 0))
    result = memory.read_permission(image, BASE, observer, aliased_target)
    assert result["status"] == "unknown"
    assert result["reason"] == "BINDING_ALIAS"
    assert image.reads == []

    result = memory.read_permission(image, True, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "MODULE_BASE_INVALID"
    assert image.reads == []


def test_budget_failure_is_unknown_and_json_roundtrip_preserves_bool_types(monkeypatch):
    image, observer, target = _environment(public_a=0)
    original_limit = memory.MAX_TOTAL_BYTES
    monkeypatch.setattr(memory, "MAX_TOTAL_BYTES", 16)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "READ_BUDGET_EXCEEDED"
    assert result["reason"].isupper()

    monkeypatch.setattr(memory, "MAX_TOTAL_BYTES", original_limit)
    image, observer, target = _environment(public_a=0)
    result = _run(image, observer, target)
    decoded = json.loads(json.dumps(result))
    assert decoded == result
    assert type(decoded["admitted"]) is bool
    assert decoded["mode"] == "public_options"

