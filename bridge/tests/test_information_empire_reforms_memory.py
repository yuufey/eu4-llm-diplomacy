from __future__ import annotations

from bridge.information import empire_memory as base_memory
from bridge.information import empire_reforms_memory as memory
from bridge.tests.test_information_empire_memory import BASE, WORLD, make_image


REFORM_TABLE = 0x61000000
OBJECT_BASE = 0x62000000
STRING_BASE = 0x63000000
HRE = WORLD + base_memory.HRE_OFFSET


def _u32(value: int, *, signed=False) -> bytes:
    return int(value).to_bytes(4, "little", signed=signed)


def _u64(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def add_reforms(image, values=(), *, storage=None, capacity=None, raw_values=None):
    """Build independent literal bytes; object offsets are not derived from the reader."""
    values = list(values)
    storage = list(storage or ["inline"] * len(values))
    raw_values = list(raw_values or [value.encode("ascii") for value in values])
    assert len(storage) == len(raw_values) == len(values)
    image.put(HRE + 0x28, _u64(REFORM_TABLE if values else 0))
    image.put(HRE + 0x34, _u32(len(values), signed=True))
    for index, (kind, raw_id) in enumerate(zip(storage, raw_values)):
        obj = OBJECT_BASE + index * 0x100
        image.put(REFORM_TABLE + index * 8, _u64(obj))
        chosen_capacity = capacity if capacity is not None else (15 if kind == "inline" else 63)
        image.put(obj + 0x28, _u64(chosen_capacity))
        if kind == "inline":
            raw = raw_id + b"\0"
            image.put(obj + 0x10, raw.ljust(16, b"\0")[:16])
        else:
            data = STRING_BASE + index * 0x200
            image.put(obj + 0x10, _u64(data))
            image.put(data, (raw_id + b"\0").ljust(129, b"\0")[:129])
    return image


def test_reform_reader_handles_inline_and_heap_string32_without_length_member():
    image = add_reforms(make_image(), ["hofgericht", "reichskammergericht"],
                        storage=["inline", "heap"])
    state = memory.read_state(image, BASE)

    assert state["schema"] == memory.SCHEMA
    assert state["status"] == "known"
    assert state["emperor"]["tag"] == "HAB"
    assert [row["tag"] for row in state["electors"]] == ["BOH", "BRA"]
    assert state["reforms"]["status"] == "known"
    assert state["reforms"]["value"] == ["hofgericht", "reichskammergericht"]
    assert [row["storage"] for row in state["reforms"]["entries"]] == ["inline", "heap"]
    assert all(row["nul_terminated"] is True for row in state["reforms"]["entries"])
    assert state["reforms"]["length_member_read"] is False
    forbidden = {HRE + 0x18, HRE + 0x500, OBJECT_BASE + 0x20,
                 OBJECT_BASE + 0x100 + 0x20}
    assert all(int(row["address"], 16) not in forbidden for row in image.read_log)
    assert state["read_budget"]["bytes_requested"] <= base_memory.MAX_READ_BYTES


def test_valid_zero_count_is_known_empty_and_old_fields_remain_known():
    state = memory.read_state(add_reforms(make_image()), BASE)
    assert state["status"] == "known"
    assert state["reforms"]["status"] == "known"
    assert state["reforms"]["value"] == []
    assert state["reforms"]["count"] == 0
    assert state["emperor"]["tag"] == "HAB"
    assert [row["tag"] for row in state["electors"]] == ["BOH", "BRA"]


def test_bad_count_and_table_pointer_only_make_reforms_unknown():
    image = add_reforms(make_image())
    image.put(HRE + 0x34, _u32(-1, signed=True))
    state = memory.read_state(image, BASE)
    assert state["status"] == "known"
    assert state["reforms"]["status"] == "unknown"
    assert state["reforms"]["reason"] == "EMPIRE_REFORMS_COUNT_OUT_OF_RANGE"
    assert "value" not in state["reforms"]
    assert state["emperor"]["tag"] == "HAB"

    image = add_reforms(make_image(), ["one"])
    image.put(HRE + 0x28, _u64(0))
    state = memory.read_state(image, BASE)
    assert state["reforms"]["status"] == "unknown"
    assert state["reforms"]["reason"] == "EMPIRE_REFORMS_TABLE_COUNT_MISMATCH"
    assert "value" not in state["reforms"]


def test_count_bound_pointer_id_and_duplicate_fail_closed():
    image = add_reforms(make_image())
    image.put(HRE + 0x34, _u32(memory.MAX_REFORMS + 1, signed=True))
    assert memory.read_state(image, BASE)["reforms"]["reason"] == "EMPIRE_REFORMS_COUNT_OUT_OF_RANGE"

    image = add_reforms(make_image(), ["one"])
    image.put(REFORM_TABLE, _u64(0))
    assert memory.read_state(image, BASE)["reforms"]["status"] == "unknown"

    image = add_reforms(make_image(), ["same", "same"])
    result = memory.read_state(image, BASE)
    assert result["reforms"]["reason"] == "EMPIRE_REFORMS_DUPLICATE_ID"
    assert "value" not in result["reforms"]


def test_invalid_ascii_and_missing_nul_are_unknown_without_partial_values():
    image = add_reforms(make_image(), ["unused"], raw_values=[b"bad\xff"])
    result = memory.read_state(image, BASE)
    assert result["reforms"]["reason"] == "EMPIRE_REFORMS_STRING_NOT_ASCII"
    assert "value" not in result["reforms"]

    image = add_reforms(make_image(), ["unused"], raw_values=[b"A" * 16])
    result = memory.read_state(image, BASE)
    assert result["reforms"]["reason"] == "EMPIRE_REFORMS_STRING_NUL_NOT_FOUND"
    assert "value" not in result["reforms"]
