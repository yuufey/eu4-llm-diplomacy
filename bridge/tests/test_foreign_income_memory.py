"""Fake-memory tests for the private foreign income cache leaf."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import foreign_economy_visibility_memory as permission_memory
from bridge.information import foreign_income_memory as memory
from bridge.information import foreign_quality_visibility_memory as common


BASE = 0x140000000
DB = 0x6000000000
TABLE = 0x6100000000
WORLD = 0x6200000000
OPTIONS = 0x6300000000
COUNTRY_ARRAY = 0x6400000000
CAPITAL = 0x6500000000
COUNTRIES = 0x6600000000
OBSERVER_SLOT = 122
TARGET_SLOT = 46

VISIBLE = (
    (0, "INCOMETAX"), (1, "INCOMEPROD"), (2, "INCOMETRADE"),
    (3, "INCOMEGOLD"), (4, "INCOMETARRIFFS"), (5, "INCOMEVASSAL"),
    (6, "INCOMEHARBORFEES"), (7, "INCOMESUBS"), (8, "INCOME_WAR_REPARATION"),
    (12, "SPOILS_OF_WAR_ECOVIEW"), (15, "CONDOTTIERI"),
    (16, "KNOWLEDGE_SHARING"), (17, "INC_BLOCKADES"), (18, "INC_LOOTING"),
)
TOTAL_TERMS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16, 17, 18)
LEGACY_ELEVEN_TERMS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 15)


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

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic memory read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("unmapped synthetic memory") from exc
        return raw[:-1] if address in self.short_at else raw


def _binding(tag: str, slot: int, pointer: int, generation: int) -> dict:
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


def _make_image(values: tuple[int, ...] | list[int], *, option: int = 0,
                target_in_candidates: bool = True):
    assert len(values) == 19
    image = MemoryImage()
    observer_pointer = COUNTRIES + OBSERVER_SLOT * 0x1000
    target_pointer = COUNTRIES + TARGET_SLOT * 0x1000
    observer = _binding("FRA", OBSERVER_SLOT, observer_pointer, 0x1234)
    target = _binding("ENG", TARGET_SLOT, target_pointer, 0x2345)

    image.put_u64(BASE + common.DATABASE_GLOBAL_RVA, DB)
    image.put_u64(DB + common.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DB + common.DATABASE_COUNT_OFFSET, max(OBSERVER_SLOT, TARGET_SLOT) + 1)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, observer_pointer)
    image.put_u64(TABLE + TARGET_SLOT * 8, target_pointer)
    image.put_u64(observer_pointer + common.COUNTRY_FULLREF_OFFSET,
                  _fullref("FRA", OBSERVER_SLOT, 0x1234))
    image.put_u64(target_pointer + common.COUNTRY_FULLREF_OFFSET,
                  _fullref("ENG", TARGET_SLOT, 0x2345))

    image.put_u64(BASE + common.WORLD_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + common.WORLD_OPTIONS_POINTER_OFFSET, OPTIONS)
    image.put_i32(OPTIONS + common.OPTIONS_QUALITY_INDEX * common.OPTIONS_U32_STRIDE,
                  option)
    candidate_pointers = [observer_pointer]
    if target_in_candidates:
        candidate_pointers.append(target_pointer)
    image.put_u64(WORLD + 0x1D08, COUNTRY_ARRAY if candidate_pointers else 0)
    image.put_i32(WORLD + 0x1D14, len(candidate_pointers))
    if candidate_pointers:
        image.put(COUNTRY_ARRAY,
                  b"".join(pointer.to_bytes(8, "little") for pointer in candidate_pointers))
    for index, (_name, rva) in enumerate(common.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(BASE + rva, -10 - index)
    image.put_u64(target_pointer + common.COUNTRY_CAPITAL_OFFSET, CAPITAL)
    image.put(CAPITAL + common.CAPITAL_QUALITY_FLAGS_OFFSET, b"\x00")

    cache_address = target_pointer + memory.COUNTRY_INCOME_CACHE_OFFSET
    cache_raw = b"".join(value.to_bytes(4, "little", signed=True) for value in values)
    image.put(cache_address, cache_raw)
    return image, observer, target, cache_address, values


def _make_permission(image: MemoryImage, observer: dict, target: dict,
                     *, page: str = permission_memory.INCOME_PAGE) -> dict:
    permission = permission_memory.read_permission(image, BASE, observer, target, page=page)
    assert permission_memory.validate_permission(permission, page=page)
    return permission


def _run(image: MemoryImage, target: dict, permission: dict,
         fields=memory.FIELDS, *, base=BASE):
    return memory.read_fields(image, base, target, fields, permission=permission)


def _wrap_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _amount(value: int) -> dict:
    return {"value": value, "raw": value, "unit": "ducats", "scale": 1000,
            "period": "month", "reference": "previous_month"}


def test_real_income_permission_and_one_cache_read_project_exact_total_and_14_categories():
    values = [10 * (index + 1) for index in range(19)]
    image, observer, target, cache_address, values = _make_image(values)
    permission = _make_permission(image, observer, target)
    assert permission["status"] == "known" and permission["admitted"] is True
    assert permission["page"] == permission_memory.INCOME_PAGE
    image.reads.clear()

    result = _run(image, target, permission)
    assert set(result) == set(memory.FIELDS)
    assert len(image.reads) == 1
    assert image.reads[0] == (cache_address, 76,
                              "income.previous_month_i32_categories_0_18")

    expected_total = _wrap_i32(sum(values[index] for index in TOTAL_TERMS))
    expected_legacy_eleven = sum(values[index] for index in LEGACY_ELEVEN_TERMS)
    income = result[memory.FIELD_INCOME]
    assert income["status"] == "known" and income["partial"] is True
    assert income["complete"] is False
    assert income["unit"] == "ducats" and income["scale"] == 1000
    assert income["period"] == "month" and income["reference"] == "previous_month"
    value = income["value"]
    assert value["native_ledger_total"] == _amount(expected_total)
    assert expected_total != expected_legacy_eleven
    categories = value["visible_categories"]
    assert [(item["index"], item["localization_key"]) for item in categories] == list(VISIBLE)
    assert [item["amount"] for item in categories] == [_amount(values[index]) for index, _ in VISIBLE]
    assert sum(item["amount"]["value"] for item in categories) != expected_total
    assert 14 not in [item["index"] for item in categories]
    assert value["total_includes_additional_native_terms"] is True

    assert result[memory.FIELD_REPARATIONS]["value"]["received_previous_month"] == _amount(values[8])
    assert result[memory.FIELD_SUBSIDIES]["value"]["received_previous_month"] == _amount(values[7])
    for field in (memory.FIELD_REPARATIONS, memory.FIELD_SUBSIDIES):
        nested = result[field]["value"]
        assert nested["current_payment_obligations"]["status"] == "unknown"
        assert nested["active_contracts"]["status"] == "unknown"
        assert "value" not in nested["current_payment_obligations"]
        assert "value" not in nested["active_contracts"]
    json.dumps(result, ensure_ascii=False)


def test_negative_amounts_and_low32_sum_overflow_keep_native_signed_i32():
    values = [0] * 19
    values[0] = 0x7FFFFFFF
    values[1] = 1
    values[8] = -23
    values[12] = 23
    image, observer, target, _address, values = _make_image(values)
    permission = _make_permission(image, observer, target)
    image.reads.clear()
    result = _run(image, target, permission)
    assert result[memory.FIELD_INCOME]["value"]["native_ledger_total"] == _amount(-0x80000000)
    assert result[memory.FIELD_REPARATIONS]["value"]["received_previous_month"] == _amount(-23)
    assert result[memory.FIELD_INCOME]["value"]["visible_categories"][0]["amount"] == _amount(0x7FFFFFFF)


def test_zero_received_is_known_and_does_not_imply_no_payment_obligation():
    values = [0] * 19
    image, observer, target, _address, _values = _make_image(values)
    permission = _make_permission(image, observer, target)
    image.reads.clear()
    result = _run(image, target, permission, (memory.FIELD_REPARATIONS, memory.FIELD_SUBSIDIES))
    for field in (memory.FIELD_REPARATIONS, memory.FIELD_SUBSIDIES):
        value = result[field]["value"]
        assert value["received_previous_month"] == _amount(0)
        assert value["current_payment_obligations"]["status"] == "unknown"
        assert value["active_contracts"]["status"] == "unknown"


def test_one_short_cache_read_withdraws_requested_fields():
    values = [index - 9 for index in range(19)]
    image, observer, target, cache_address, _values = _make_image(values)
    permission = _make_permission(image, observer, target)
    image.reads.clear()
    image.short_at.add(cache_address)
    result = _run(image, target, permission)
    assert len(image.reads) == 1
    assert all(result[field]["status"] == "unknown" for field in memory.FIELDS)
    assert all(result[field]["reason"] == "INCOME_CACHE_READ_FAILED" for field in memory.FIELDS)
    assert all(result[field]["raw_inputs"]["reads"][-1]["status"] == "failed"
               for field in memory.FIELDS)


@pytest.mark.parametrize("kind", ["denied", "unknown", "forged", "wrong_page",
                                   "wrong_module", "wrong_target"])
def test_invalid_or_denied_permission_never_reads_income_cache(kind: str):
    values = [index for index in range(19)]
    image, observer, target, cache_address, _values = _make_image(
        values, option=(1 if kind == "denied" else 0))
    if kind == "wrong_page":
        permission = _make_permission(image, observer, target,
                                      page=permission_memory.LOANS_PAGE)
    elif kind == "unknown":
        permission = permission_memory.read_permission(
            image, True, observer, target, page=permission_memory.INCOME_PAGE)
        assert permission["status"] == "unknown"
    else:
        permission = _make_permission(image, observer, target)
    if kind == "forged":
        permission = deepcopy(permission)
        permission["admitted"] = 1
    if kind == "wrong_module":
        base = BASE + 0x1000
    else:
        base = BASE
    if kind == "wrong_target":
        other_pointer = COUNTRIES + 47 * 0x1000
        other = _binding("BUR", 47, other_pointer, 0x2346)
        target = other
    image.reads.clear()

    result = _run(image, target, permission, base=base)
    assert all(result[field]["status"] == "unknown" for field in memory.FIELDS)
    assert image.reads == []
    assert not any(address == cache_address for address, _size, _label in image.reads)


def test_target_absent_from_world_country_candidates_denies_before_income_read():
    values = [5] * 19
    image, observer, target, cache_address, _values = _make_image(
        values, target_in_candidates=False)
    permission = _make_permission(image, observer, target)
    assert permission["status"] == "known" and permission["admitted"] is False
    image.reads.clear()
    result = _run(image, target, permission)
    assert all(result[field]["status"] == "unknown" for field in memory.FIELDS)
    assert image.reads == []
    assert not any(address == cache_address for address, _size, _label in image.reads)


def test_unrequested_and_unsupported_fields_do_not_touch_memory():
    values = [0] * 19
    image, observer, target, _address, _values = _make_image(values)
    permission = _make_permission(image, observer, target)
    image.reads.clear()
    assert _run(image, target, permission, ()) == {}
    assert image.reads == []
    unsupported = _run(image, target, permission, ("F03.debt",))
    assert unsupported["F03.debt"]["status"] == "unknown"
    assert unsupported["F03.debt"]["reason"] == "FIELD_UNSUPPORTED"
    assert image.reads == []


def test_bad_binding_and_request_shape_fail_without_resource_reads():
    values = [0] * 19
    image, observer, target, _address, _values = _make_image(values)
    permission = _make_permission(image, observer, target)
    image.reads.clear()
    bad_target = deepcopy(target)
    bad_target["fullref_raw_hex"] = "00" * 8
    result = _run(image, bad_target, permission)
    assert all(result[field]["status"] == "unknown" for field in memory.FIELDS)
    assert image.reads == []
    malformed = memory.read_fields(image, BASE, target, "F03.income", permission=permission)
    assert set(malformed) == {memory.FIELD_INCOME}
    assert malformed[memory.FIELD_INCOME]["status"] == "unknown"
    assert malformed[memory.FIELD_INCOME]["reason"] == "FIELDS_SHAPE_INVALID"
    assert image.reads == []
