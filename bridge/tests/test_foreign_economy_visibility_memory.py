"""Offline fake-memory tests for the distinct economy-page permission leaf."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import country_ledger_membership_memory as ledger
from bridge.information import foreign_economy_visibility_memory as memory
from bridge.information import foreign_quality_visibility_memory as quality


BASE = 0x140000000
DB = 0x6000000000
TABLE = 0x6100000000
WORLD = 0x6200000000
OPTIONS = 0x6300000000
COUNTRIES = 0x6400000000
CAPITAL = 0x6500000000
BITSET = 0x6600000000
COUNTRY_ROWS = 0x6700000000
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
        "country_fullref_address": hex(pointer + quality.COUNTRY_FULLREF_OFFSET),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(TABLE + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _environment(*, page_option: int = 0, target_in_world: bool = True,
                 special_slot_index: int | None = None, capital_flags: int = quality.QUALITY_FLAG_BIT,
                 discovered: bool = True, include_options: bool = True,
                 include_capital: bool = True, global_enable: int | None = None,
                 tls_state: int | None = None) -> tuple[MemoryImage, dict, dict]:
    image = MemoryImage()
    observer_ptr = COUNTRIES + OBSERVER_SLOT * 0x1000
    target_ptr = COUNTRIES + TARGET_SLOT * 0x1000
    observer = _binding("FRA", OBSERVER_SLOT, observer_ptr)
    target = _binding("ENG", TARGET_SLOT, target_ptr, 0x2345)

    image.put_u64(BASE + quality.DATABASE_GLOBAL_RVA, DB)
    image.put_u64(DB + quality.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DB + quality.DATABASE_COUNT_OFFSET, TARGET_SLOT + 1)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, observer_ptr)
    image.put_u64(TABLE + TARGET_SLOT * 8, target_ptr)
    image.put_u64(observer_ptr + quality.COUNTRY_FULLREF_OFFSET,
                  _fullref("FRA", OBSERVER_SLOT))
    image.put_u64(target_ptr + quality.COUNTRY_FULLREF_OFFSET,
                  _fullref("ENG", TARGET_SLOT, 0x2345))

    image.put_u64(BASE + quality.WORLD_GLOBAL_RVA, WORLD)
    candidates = [observer_ptr, target_ptr] if target_in_world else [observer_ptr]
    image.put_u64(WORLD + ledger.WORLD_COUNTRY_POINTERS_OFFSET, COUNTRY_ROWS)
    image.put_i32(WORLD + ledger.WORLD_COUNTRY_COUNT_OFFSET, len(candidates))
    image.put(COUNTRY_ROWS, b"".join(pointer.to_bytes(8, "little") for pointer in candidates))

    if include_options:
        image.put_u64(WORLD + quality.WORLD_OPTIONS_POINTER_OFFSET, OPTIONS)
        image.put_i32(OPTIONS + quality.OPTIONS_QUALITY_INDEX * quality.OPTIONS_U32_STRIDE,
                      page_option)
    if global_enable is not None:
        image.put(BASE + quality.WORLD_PAGE_ENABLE_RVA, bytes([global_enable & 0xFF]))
    if tls_state is not None:
        image.put(BASE + quality.WORLD_PAGE_TLS_RVA, bytes([tls_state & 0xFF]))

    for index, (_name, rva) in enumerate(quality.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(BASE + rva, -10 - index)
    if special_slot_index is not None:
        _name, special_rva = quality.SPECIAL_TARGET_SLOT_RVAS[special_slot_index]
        image.put_i32(BASE + special_rva, TARGET_SLOT)

    if include_capital:
        image.put_u64(target_ptr + quality.COUNTRY_CAPITAL_OFFSET, CAPITAL)
        image.put(CAPITAL + quality.CAPITAL_QUALITY_FLAGS_OFFSET,
                  bytes([capital_flags & 0xFF]))
        image.put_u64(CAPITAL + quality.CAPITAL_OBSERVER_BITSET_OFFSET, BITSET)
        word = (1 << (OBSERVER_SLOT & 31)) if discovered else 0
        image.put_u32(BITSET + (OBSERVER_SLOT >> 5) * quality.OBSERVER_BITSET_WORD_STRIDE, word)
    return image, observer, target


def _run(image: MemoryImage, observer: dict, target: dict, page: str) -> dict:
    return memory.read_permission(image, BASE, observer, target, page=page)


def _labels(image: MemoryImage) -> list[str]:
    return [label for _address, _size, label in image.reads]


def test_income_page_positive_permission_roundtrips_and_replays_real_trace():
    image, observer, target = _environment()
    result = _run(image, observer, target, memory.INCOME_PAGE)

    assert result["status"] == "known" and result["admitted"] is True
    assert result["mode"] == "capital_discovery_bitmap"
    assert result["complete"] is False and result["actual_UI_observed"] is False
    assert result["raw_inputs"]["entry_gate"]["mode"] == "option_index17"
    assert result["raw_inputs"]["entry_gate"]["value"] == 0
    assert result["raw_inputs"]["ledger_membership"]["member"] is True
    assert len(result["raw_inputs"]["special_target_slots"]) == 3
    assert result["raw_inputs"]["discovery"]["bit"] == (OBSERVER_SLOT & 31)
    assert "economy.income_option_index17" in _labels(image)
    assert "economy.special_target_a" in _labels(image)
    assert "economy.target_capital_flags" in _labels(image)
    assert "economy.discovery_word" in _labels(image)
    assert "quality.global_page_enable_u8" not in _labels(image)
    assert "quality.global_tls_state_u8" not in _labels(image)
    assert memory.validate_permission(result, page=memory.INCOME_PAGE)

    saved = json.loads(json.dumps(result))
    assert memory.validate_permission(saved, page=memory.INCOME_PAGE)


def test_income_option_denial_stops_before_candidate_and_financial_page_reads():
    image, observer, target = _environment(page_option=1)
    result = _run(image, observer, target, memory.INCOME_PAGE)

    assert result["status"] == "known" and result["admitted"] is False
    assert result["reason"] == "INCOME_COMPARISON_OPTION_BLOCKED"
    labels = _labels(image)
    assert "economy.income_option_index17" in labels
    assert not any(label.startswith("ledger_membership.") for label in labels)
    assert not any(label.startswith("economy.special_target_") for label in labels)
    assert not any(label.startswith("economy.target_capital") or label.startswith("economy.discovery")
                   for label in labels)
    assert "quality.global_page_enable_u8" not in labels
    assert "quality.global_tls_state_u8" not in labels
    assert memory.validate_permission(result, page=memory.INCOME_PAGE)


def test_income_requires_current_world_candidate_membership_for_valid_db_binding():
    image, observer, target = _environment(target_in_world=False)
    result = _run(image, observer, target, memory.INCOME_PAGE)

    assert result["status"] == "known" and result["admitted"] is False
    assert result["reason"] == "TARGET_NOT_LEDGER_CANDIDATE"
    assert result["raw_inputs"]["ledger_membership"]["status"] == "known"
    assert result["raw_inputs"]["ledger_membership"]["member"] is False
    labels = _labels(image)
    assert any(label.startswith("ledger_membership.array_chunk") for label in labels)
    assert not any(label.startswith("economy.special_target_") for label in labels)
    assert "economy.target_capital" not in labels
    assert memory.validate_permission(result, page=memory.INCOME_PAGE)


def test_income_special_target_slot_denies_before_capital_and_discovery_reads():
    image, observer, target = _environment(special_slot_index=1)
    result = _run(image, observer, target, memory.INCOME_PAGE)

    assert result["status"] == "known" and result["admitted"] is False
    assert result["reason"] == "SPECIAL_TARGET_SLOT"
    assert len(result["raw_inputs"]["special_target_slots"]) == 3
    labels = _labels(image)
    assert "economy.special_target_b" in labels
    assert not any(label.startswith("economy.target_capital") or label.startswith("economy.discovery")
                   for label in labels)
    assert memory.validate_permission(result, page=memory.INCOME_PAGE)


def test_income_hidden_capital_discovery_denies_after_flag_and_bitmap_reads():
    image, observer, target = _environment(capital_flags=quality.QUALITY_FLAG_BIT, discovered=False)
    result = _run(image, observer, target, memory.INCOME_PAGE)

    assert result["status"] == "known" and result["admitted"] is False
    assert result["reason"] == "TARGET_CAPITAL_NOT_DISCOVERED"
    assert result["raw_inputs"]["discovery"]["flags"] == quality.QUALITY_FLAG_BIT
    assert result["raw_inputs"]["discovery"]["word"] == 0
    assert memory.validate_permission(result, page=memory.INCOME_PAGE)


def test_live_fullref_mismatch_is_unknown_and_never_admits():
    image, observer, target = _environment()
    target_pointer = int(target["country_pointer"], 16)
    image.put_u64(target_pointer + quality.COUNTRY_FULLREF_OFFSET,
                  _fullref("ENG", TARGET_SLOT, 0x2346))
    result = _run(image, observer, target, memory.INCOME_PAGE)

    assert result["status"] == "unknown" and result["admitted"] is None
    assert result["reason"] == "TARGET_FULLREF_MISMATCH"
    assert result["complete"] is False and result["actual_UI_observed"] is False
    assert not memory.validate_permission(result, page=memory.INCOME_PAGE)


def test_permission_validator_rejects_trace_candidate_and_metadata_tampering():
    image, observer, target = _environment()
    result = _run(image, observer, target, memory.INCOME_PAGE)
    assert result["status"] == "known" and result["admitted"] is True
    assert memory.validate_permission(result, page=memory.INCOME_PAGE)

    bad_trace = deepcopy(result)
    bad_trace["raw_inputs"]["reads"][0]["raw_hex"] = "00" * bad_trace["raw_inputs"]["reads"][0]["size"]
    assert not memory.validate_permission(bad_trace, page=memory.INCOME_PAGE)

    bad_candidate = deepcopy(result)
    bad_candidate["raw_inputs"]["ledger_membership"]["matching_indices"] = [0]
    assert not memory.validate_permission(bad_candidate, page=memory.INCOME_PAGE)

    bad_binding = deepcopy(result)
    bad_binding["target_binding"]["fullref"] = hex(int(target["fullref"], 16) ^ (1 << 48))
    assert not memory.validate_permission(bad_binding, page=memory.INCOME_PAGE)

    bad_metadata = deepcopy(result)
    bad_metadata["basis"] = "other"
    assert not memory.validate_permission(bad_metadata, page=memory.INCOME_PAGE)

    bad_complete = deepcopy(result)
    bad_complete["complete"] = True
    assert not memory.validate_permission(bad_complete, page=memory.INCOME_PAGE)

    bad_bool = deepcopy(result)
    bad_bool["admitted"] = 1
    assert not memory.validate_permission(bad_bool, page=memory.INCOME_PAGE)

    bad_decoded_type = deepcopy(result)
    bad_decoded_type["raw_inputs"]["entry_gate"]["value"] = False
    assert not memory.validate_permission(bad_decoded_type, page=memory.INCOME_PAGE)


def test_loans_page_is_only_an_active_candidate_and_ignores_income_quality_and_capital_gates():
    image, observer, target = _environment(
        page_option=1, include_options=False, include_capital=False,
        global_enable=0, tls_state=0,
    )
    result = _run(image, observer, target, memory.LOANS_PAGE)

    assert result["status"] == "known" and result["admitted"] is True
    assert result["mode"] == "observer_lent_loans_candidate"
    assert result["raw_inputs"]["ledger_membership"]["member"] is True
    labels = _labels(image)
    assert any(label.startswith("ledger_membership.") for label in labels)
    assert not any("option_index17" in label for label in labels)
    assert not any(label.startswith("economy.special_target_") for label in labels)
    assert not any(label.startswith("economy.target_capital") or label.startswith("economy.discovery")
                   for label in labels)
    assert "quality.global_page_enable_u8" not in labels
    assert "quality.global_tls_state_u8" not in labels
    assert memory.validate_permission(result, page=memory.LOANS_PAGE)
    assert not memory.validate_permission(result, page=memory.INCOME_PAGE)


def test_loans_page_still_requires_an_active_world_candidate():
    image, observer, target = _environment(target_in_world=False, include_options=False,
                                           include_capital=False, global_enable=0, tls_state=0)
    result = _run(image, observer, target, memory.LOANS_PAGE)

    assert result["status"] == "known" and result["admitted"] is False
    assert result["reason"] == "TARGET_NOT_LEDGER_CANDIDATE"
    labels = _labels(image)
    assert not any("option_index17" in label for label in labels)
    assert not any(label.startswith("economy.target_capital") for label in labels)
    assert memory.validate_permission(result, page=memory.LOANS_PAGE)


@pytest.mark.parametrize("page", [None, "income", "quality", "observer_lent_loans_candidate"])
def test_invalid_page_fails_closed(page: str | None):
    image, observer, target = _environment()
    result = memory.read_permission(image, BASE, observer, target, page=page)
    assert result["status"] == "unknown" and result["admitted"] is None
    assert result["reason"] == "ECONOMY_PAGE_INVALID"
    assert not memory.validate_permission(result)

