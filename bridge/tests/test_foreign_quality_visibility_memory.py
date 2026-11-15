"""Offline fake-memory tests for the quality-ledger visibility leaf."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import foreign_quality_visibility_memory as memory
from bridge.information import country_ledger_membership_memory as ledger_membership


BASE = 0x140000000
DB = 0x6000000000
TABLE = 0x6100000000
WORLD = 0x6200000000
OPTIONS = 0x6300000000
COUNTRIES = 0x6400000000
CAPITAL = 0x6500000000
BITSET = 0x6600000000
COUNTRY_CANDIDATES = 0x6700000000
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
        self.data.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic memory read error")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped read") from exc
        return raw[:-1] if address in self.short_at else raw


def _binding(tag: str, slot: int, pointer: int, generation: int = 0x1234) -> dict:
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + memory.COUNTRY_FULLREF_OFFSET),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(TABLE + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _environment(*, option: int = 0, observer_generation: int = 0x1234,
                 target_slot: int = TARGET_SLOT, capital_flags: int = 0,
                 observer_slot: int = OBSERVER_SLOT) -> tuple[MemoryImage, dict, dict]:
    image = MemoryImage()
    observer_ptr = COUNTRIES + observer_slot * 0x1000
    target_ptr = COUNTRIES + target_slot * 0x1000
    observer = _binding("FRA", observer_slot, observer_ptr, observer_generation)
    target = _binding("ENG", target_slot, target_ptr, 0x2345)

    image.put_u64(BASE + memory.DATABASE_GLOBAL_RVA, DB)
    image.put_u64(DB + memory.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DB + memory.DATABASE_COUNT_OFFSET, max(observer_slot, target_slot) + 1)
    image.put_u64(TABLE + observer_slot * 8, observer_ptr)
    image.put_u64(TABLE + target_slot * 8, target_ptr)
    image.put_u64(observer_ptr + memory.COUNTRY_FULLREF_OFFSET,
                  _fullref("FRA", observer_slot, observer_generation))
    image.put_u64(target_ptr + memory.COUNTRY_FULLREF_OFFSET,
                  _fullref("ENG", target_slot, 0x2345))

    image.put_u64(BASE + memory.WORLD_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + ledger_membership.WORLD_COUNTRY_POINTERS_OFFSET,
                  COUNTRY_CANDIDATES)
    image.put_i32(WORLD + ledger_membership.WORLD_COUNTRY_COUNT_OFFSET, 2)
    image.put(COUNTRY_CANDIDATES,
              observer_ptr.to_bytes(8, "little") + target_ptr.to_bytes(8, "little"))
    image.put_u64(WORLD + memory.WORLD_OPTIONS_POINTER_OFFSET, OPTIONS)
    image.put_u32(OPTIONS + memory.OPTIONS_QUALITY_INDEX * memory.OPTIONS_U32_STRIDE,
                  option)
    image.put(BASE + memory.WORLD_PAGE_ENABLE_RVA, b"\x01")
    image.put(BASE + memory.WORLD_PAGE_TLS_RVA, b"\x00")
    for index, (_name, rva) in enumerate(memory.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(BASE + rva, -10 - index)

    image.put_u64(target_ptr + memory.COUNTRY_CAPITAL_OFFSET, CAPITAL)
    image.put(CAPITAL + memory.CAPITAL_QUALITY_FLAGS_OFFSET,
              bytes([capital_flags & 0xFF]))
    image.put_u64(CAPITAL + memory.CAPITAL_OBSERVER_BITSET_OFFSET, BITSET)
    word = 1 << (observer_slot & 31)
    image.put_u32(BITSET + (observer_slot >> 5) * 4, word)
    return image, observer, target


def _run(image: MemoryImage, observer: dict, target: dict) -> dict:
    return memory.read_permission(image, BASE, observer, target)


def test_option_17_is_read_from_world_2150_pointer_and_not_world_2160():
    image, observer, target = _environment(option=0)
    # A distracting pointer at +0x2160 must not be used as the options base.
    image.put_u64(WORLD + 0x2160, 0x6700000000)
    result = _run(image, observer, target)
    labels = [label for _address, _size, label in image.reads]
    assert result["status"] == "known" and result["admitted"] is True
    assert "world.quality_options_pointer" in labels
    assert "options.quality_option_17_u32" in labels
    assert not any(address == WORLD + 0x2160 for address, _size, _label in image.reads)
    assert result["raw_inputs"]["gates"]["outer"]["option_index"] == 0x17
    assert result["raw_inputs"]["budget"]["bytes_requested"] == sum(
        size for _address, size, _label in image.reads)


def test_option_nonzero_is_a_known_denial_without_quality_resource_reads():
    image, observer, target = _environment(option=9)
    result = _run(image, observer, target)
    assert result["status"] == "known" and result["admitted"] is False
    assert result["reason"] == "OUTER_QUALITY_GATE_DENIED"
    assert memory.validate_permission(result)
    assert not any(label.startswith("quality.") for _, _, label in image.reads)
    assert "relation" not in " ".join(label for _, _, label in image.reads)


def test_observer_byte6_seven_short_circuits_option_read_but_not_global_page_gate():
    image, observer, target = _environment(option=123, observer_generation=0x1207)
    result = _run(image, observer, target)
    labels = [label for _address, _size, label in image.reads]
    assert result["status"] == "known" and result["admitted"] is True
    assert result["raw_inputs"]["gates"]["outer"]["selected_branch"] == "observer_byte6_is_7"
    assert "world.quality_options_pointer" not in labels
    assert "options.quality_option_17_u32" not in labels
    assert "quality.global_page_enable_u8" in labels


@pytest.mark.parametrize(("enable", "tls"), [(0, 0), (1, 1), (0, 1)])
def test_global_page_gate_requires_known_positive_and_other_states_are_unknown(
        enable: int, tls: int):
    image, observer, target = _environment()
    image.put(BASE + memory.WORLD_PAGE_ENABLE_RVA, bytes([enable]))
    image.put(BASE + memory.WORLD_PAGE_TLS_RVA, bytes([tls]))
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["admitted"] is None
    assert result["reason"] == "GLOBAL_PAGE_GATE_REQUIRES_TLS"
    assert not any(label.startswith("target.capital") for _, _, label in image.reads)


def test_page_and_outer_positive_without_relation_counter_bypass_uses_capital_bitset():
    image, observer, target = _environment(capital_flags=0x10)
    observer_ptr = int(observer["country_pointer"], 0)
    image.put_u64(observer_ptr + 0x1510, 0x6700000000)
    image.put_i32(0x6700000000 + TARGET_SLOT * 0x48 + 0x14, 999)
    result = _run(image, observer, target)
    assert result["status"] == "known" and result["admitted"] is True
    labels = [label for _address, _size, label in image.reads]
    assert "target.capital.quality_observer_bitset_word_u32" in labels
    assert not any("relation" in label for label in labels)
    assert result["basis"] == "native_quality_ledger_visibility_predicate_projected"
    assert result["actual_UI_observed"] is False


@pytest.mark.parametrize(("bit", "expected"), [(0, False), (1, True)])
def test_capital_fallback_discovery_bit_controls_projected_permission(bit: int,
                                                                      expected: bool):
    image, observer, target = _environment(capital_flags=0x10)
    observer_slot = observer["slot"]
    image.put_u32(BITSET + (observer_slot >> 5) * 4,
                  bit << (observer_slot & 31))
    result = _run(image, observer, target)
    assert result["status"] == "known"
    assert result["admitted"] is expected
    assert memory.validate_permission(result)
    if expected:
        assert result["reason"] is None
    else:
        assert result["reason"] == "CAPITAL_OBSERVER_BIT_CLEAR"


def test_special_target_slot_is_denied_before_capital_or_relation_reads():
    image, observer, target = _environment(target_slot=TARGET_SLOT)
    image.put_i32(BASE + memory.SPECIAL_TARGET_SLOT_RVAS[1][1], TARGET_SLOT)
    result = _run(image, observer, target)
    assert result["status"] == "known" and result["admitted"] is False
    assert result["reason"] == "TARGET_SPECIAL_SLOT_DENIED"
    assert memory.validate_permission(result)
    assert not any(label.startswith("target.capital") for _, _, label in image.reads)
    assert not any("relation" in label for _, _, label in image.reads)


def test_live_fullref_generation_mismatch_is_unknown():
    image, observer, target = _environment()
    image.put_u64(int(target["country_pointer"], 0) + memory.COUNTRY_FULLREF_OFFSET,
                  _fullref("ENG", TARGET_SLOT, 0x9876))
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "TARGET_FULLREF_MISMATCH"
    assert result["raw_inputs"]["reads"][-1]["label"] == "bindings.target.fullref"
    assert memory.validate_permission(result)


def test_bad_binding_fullref_is_rejected_before_any_rpm_read():
    image, observer, target = _environment()
    bad = deepcopy(observer)
    bad["fullref_raw_hex"] = "00" * 8
    result = _run(image, bad, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_BINDING_INVALID"
    assert image.reads == []


def test_observer_slot_outside_bounded_bitmap_range_is_rejected_without_guessing_extent():
    image, observer, target = _environment()
    bad = deepcopy(observer)
    # A signed -1 slot encoded in the fullref cannot be confused with slot 189.
    bad["fullref"] = hex((0x1234 << 48) | (0xFFFF << 32)
                         | int.from_bytes(b"FRA", "little"))
    bad["fullref_raw_hex"] = int(bad["fullref"], 0).to_bytes(8, "little").hex()
    bad["slot"] = 0xFFFF
    result = _run(image, bad, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_BINDING_INVALID"
    assert image.reads == []


@pytest.mark.parametrize("failure", ["short", "error"])
def test_required_read_failure_stays_unknown_with_bounded_trace(failure: str):
    image, observer, target = _environment()
    address = OPTIONS + memory.OPTIONS_QUALITY_INDEX * memory.OPTIONS_U32_STRIDE
    (image.short_at if failure == "short" else image.error_at).add(address)
    result = _run(image, observer, target)
    assert result["status"] == "unknown" and result["admitted"] is None
    assert result["reason"] == "READ_FAILED:options.quality_option_17_u32"
    assert result["raw_inputs"]["reads"][-1]["status"] == "failed"
    assert memory.validate_permission(result)


def test_budget_is_enforced_and_budget_rejection_is_preserved_in_trace(monkeypatch):
    image, observer, target = _environment()
    monkeypatch.setattr(memory, "MAX_READ_CALLS", 2)
    result = _run(image, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "READ_BUDGET_EXCEEDED"
    assert result["raw_inputs"]["budget"]["calls"] == 2
    assert result["raw_inputs"]["reads"][-1]["status"] == "rejected"


def test_permission_trace_roundtrips_json_replays_and_validator_rejects_type_tampering():
    image, observer, target = _environment(capital_flags=0x10)
    result = _run(image, observer, target)
    assert result["status"] == "known" and result["admitted"] is True
    assert memory.validate_permission(result)

    loaded = json.loads(json.dumps(result))
    assert memory.validate_permission(loaded)

    class Replay:
        def __init__(self, rows):
            self.rows = list(rows)
            self.index = 0

        def read(self, address, size, label):
            row = self.rows[self.index]
            self.index += 1
            assert row["address"] == hex(address)
            assert row["size"] == size
            assert row["label"] == label
            assert row["status"] == "ok"
            return bytes.fromhex(row["raw_hex"])

    replayed = memory.read_permission(Replay(loaded["raw_inputs"]["reads"]),
                                      BASE, observer, target)
    assert replayed == loaded

    bad_bool = deepcopy(loaded)
    bad_bool["admitted"] = 1
    assert not memory.validate_permission(bad_bool)
    bad_value = deepcopy(loaded)
    first_decoded = next(row for row in bad_value["raw_inputs"]["reads"]
                         if row.get("decode") == "u32")
    first_decoded["value"] = True
    assert not memory.validate_permission(bad_value)
    bad_hex = deepcopy(loaded)
    bad_hex["raw_inputs"]["reads"][0]["raw_hex"] = "xyz"
    assert not memory.validate_permission(bad_hex)
    bad_gate = deepcopy(loaded)
    bad_gate["raw_inputs"]["gates"]["outer"]["option_value"] = 1
    assert not memory.validate_permission(bad_gate)
    coordinated_flags_address = deepcopy(loaded)
    capital_gate = coordinated_flags_address["raw_inputs"]["gates"]["target_capital"]
    flags_read = next(row for row in coordinated_flags_address["raw_inputs"]["reads"]
                      if row.get("label") == "target.capital.quality_flags_u8")
    wrong_flags_address = hex(int(capital_gate["flags_address"], 16) + 4)
    capital_gate["flags_address"] = wrong_flags_address
    flags_read["address"] = wrong_flags_address
    assert not memory.validate_permission(coordinated_flags_address)


def test_invalid_reader_and_module_base_fail_closed_without_calls():
    result = memory.read_permission(None, BASE, {}, {})
    assert result["status"] == "unknown"
    assert result["reason"] == "OBSERVER_BINDING_INVALID"
    assert memory.validate_permission(result)

    image, observer, target = _environment()
    result = memory.read_permission(image, True, observer, target)
    assert result["status"] == "unknown"
    assert result["reason"] == "MODULE_BASE_INVALID"
    assert image.reads == []
    assert memory.validate_permission(result)


def test_valid_database_target_missing_from_world_candidates_is_denied_before_quality_reads():
    image, observer, target = _environment()
    observer_pointer = int(observer["country_pointer"], 16)
    image.put_u64(WORLD + ledger_membership.WORLD_COUNTRY_POINTERS_OFFSET,
                  COUNTRY_CANDIDATES)
    image.put_i32(WORLD + ledger_membership.WORLD_COUNTRY_COUNT_OFFSET, 1)
    image.put(COUNTRY_CANDIDATES, observer_pointer.to_bytes(8, "little"))

    result = _run(image, observer, target)
    assert result["status"] == "known"
    assert result["admitted"] is False
    assert result["reason"] == "TARGET_NOT_LEDGER_CANDIDATE"
    assert result["raw_inputs"]["ledger_membership"]["status"] == "known"
    assert result["raw_inputs"]["ledger_membership"]["member"] is False
    assert not any(label.startswith("quality.")
                   or label.startswith("options.quality_option")
                   or label.startswith("target.capital.")
                   for _address, _size, label in image.reads)
    assert memory.validate_permission(result)


def test_permission_validator_rejects_membership_index_target_and_array_tampering():
    image, observer, target = _environment()
    result = _run(image, observer, target)
    assert result["status"] == "known" and result["admitted"] is True
    assert memory.validate_permission(result)

    bad_index = deepcopy(result)
    bad_index["raw_inputs"]["ledger_membership"]["matching_indices"] = [0]
    assert not memory.validate_permission(bad_index)

    bad_target = deepcopy(result)
    membership = bad_target["raw_inputs"]["ledger_membership"]
    membership["target"]["fullref"] = hex(int(membership["target"]["fullref"], 16) ^ (1 << 48))
    assert not memory.validate_permission(bad_target)

    bad_array = deepcopy(result)
    membership = bad_array["raw_inputs"]["ledger_membership"]
    chunk = next(row for row in membership["raw_inputs"]["reads"]
                 if "array_chunk" in row["label"])
    raw = bytearray.fromhex(chunk["raw_hex"])
    raw[8:16] = (COUNTRIES + 999 * 0x1000).to_bytes(8, "little")
    chunk["raw_hex"] = raw.hex()
    assert not memory.validate_permission(bad_array)

