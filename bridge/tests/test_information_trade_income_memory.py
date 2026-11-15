from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import country_resources_memory as crm
from bridge.information import trade_income_memory as memory


MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x200000000
MANAGER = 0x200001000
VECTOR = 0x200002000
GAME = 0x200003000
PROVINCE_BASE = 0x200100000
TABLE_ONE = 0x200200000
TABLE_TWO = 0x200210000
DEF_ONE = 0x200300000
DEF_NULL = 0x200301000
DEF_TWO = 0x200302000
VTABLE_ONE = 0x200310000
VTABLE_NULL = 0x200311000
VTABLE_TWO = 0x200312000
RUNTIME_ONE = 0x200400000
RUNTIME_TWO = 0x200410000


class Reader:
    def __init__(self, data: dict[tuple[int, int], bytes]):
        self.data = data
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        value = self.data.get((address, size))
        if value is None:
            raise AssertionError(f"unexpected read: {label} {address:#x} {size}")
        return value


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def _profile() -> dict:
    return {
        "profile_id": "trade-income-memory-1374",
        "game_version": "1.37.4",
        "executable": {"sha256": memory.EXPECTED_EXE_SHA256},
        "source_index": {
            "source_index_id": "trade-source-index-1374",
            "path": "work/runtime/trade-source-index.json",
            "sha256": "c" * 64,
        },
        "layout": {
            "manager_global_rva": "0x100",
            "vector_begin_offset": "0x0",
            "vector_end_offset": "0x8",
            "vector_stride": 8,
            "max_definitions": 1024,
            "definition_predicate_slot": "0x40",
            "predicate_true_rva": "0x8f440",
            "predicate_false_rva": "0x8f450",
            "definition_key_offset": "0x10",
            "string_size": 32,
            "string_length_offset": 16,
            "string_capacity_offset": 24,
            "string_inline_capacity": 16,
            "max_key_length": 128,
            "definition_center_offset": "0xdc",
            "max_center": 32767,
            "game_global_rva": "0x200",
            "province_base_offset": "0x1ca8",
            "province_stride": "0x2e10",
            "province_trade_node_offset": "0xe8",
            "node_definition_offset": "0xa8",
            "country_fullref_offset": "0x20",
            "country_slot_offset": 4,
            "entry_table_offset": "0x18",
            "entry_stride": "0xc0",
            "entry_income_offset": "0x34",
            "entry_flags_offset": "0xac",
            "special_slot_global_rva": "0x300",
            "signed": True,
            "wrap_bits": 32,
        },
        "code_guards": [{"name": "graph", "rva": "0x400", "hex": "90c3"}],
    }


def _put(data: dict[tuple[int, int], bytes], address: int, payload: bytes) -> None:
    data[(address, len(payload))] = payload


def _build_reader() -> Reader:
    data: dict[tuple[int, int], bytes] = {}
    _put(data, MODULE_BASE + 0x400, bytes.fromhex("90c3"))
    _put(data, MODULE_BASE + 0x100, _qword(MANAGER))
    _put(data, MANAGER, _qword(VECTOR))
    _put(data, MANAGER + 8, _qword(VECTOR + 24))
    _put(data, VECTOR, _qword(DEF_ONE) + _qword(DEF_NULL) + _qword(DEF_TWO))
    _put(data, MODULE_BASE + 0x200, _qword(GAME))
    _put(data, GAME + 0x1CA8, _qword(PROVINCE_BASE))
    fullref = bytearray(b"FRA\0\0\0\0\0")
    fullref[4:6] = (7).to_bytes(2, "little", signed=True)
    _put(data, COUNTRY_POINTER + 0x20, bytes(fullref))
    _put(data, MODULE_BASE + 0x300, _i32(9))

    definitions = ((DEF_ONE, VTABLE_ONE, 1, b"alpha"), (DEF_TWO, VTABLE_TWO, 2, b"beta"))
    for definition, vtable, center, key in definitions:
        _put(data, definition, _qword(vtable))
        _put(data, vtable + 0x40, _qword(MODULE_BASE + 0x8F440))
        key_object = bytearray(32)
        key_object[:len(key)] = key
        key_object[len(key)] = 0
        key_object[16:24] = len(key).to_bytes(8, "little")
        key_object[24:32] = (15).to_bytes(8, "little")
        _put(data, definition + 0x10, bytes(key_object))
        _put(data, definition + 0xDC, _i32(center))
        province = PROVINCE_BASE + center * 0x2E10
        runtime = RUNTIME_ONE if center == 1 else RUNTIME_TWO
        table = TABLE_ONE if center == 1 else TABLE_TWO
        _put(data, province + 0xE8, _qword(runtime))
        _put(data, runtime + 0xA8, _qword(definition))
        _put(data, runtime + 0x18, _qword(table))
        entry = bytearray(0xC0)
        entry[0x34:0x38] = _i32(3813 if center == 1 else -17)
        if center == 1:
            entry[0xAC:0xAF] = bytes((0, 0, 1))
        else:
            entry[0xAC:0xAF] = bytes((1, 0, 1))
        _put(data, table + 7 * 0xC0, bytes(entry))

    _put(data, DEF_NULL, _qword(VTABLE_NULL))
    _put(data, VTABLE_NULL + 0x40, _qword(MODULE_BASE + 0x8F450))
    return Reader(data)


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    profile = _profile()
    monkeypatch.setattr(memory, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(memory, "_active_profile", lambda: profile)
    return profile


def test_reads_runtime_vector_skips_null_and_applies_eligibility(configured):
    reader = _build_reader()
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["country_slot"] == 7
    assert record["special_slot"] == 9
    assert record["graph"]["node_count"] == 3
    assert record["graph"]["placeholder_count"] == 1
    assert [node["node_id"] for node in record["nodes"]] == ["alpha", "beta"]
    assert record["nodes"][0]["eligible"] is True
    assert record["nodes"][0]["income_raw"] == 3813
    assert record["nodes"][1]["eligible"] is False
    assert record["nodes"][1]["cache_income_raw"] == -17
    assert record["nodes"][1]["income_raw"] == 0
    assert record["total_raw"] == 3813
    assert record["total_raw_hex"] == "e50e0000"
    assert memory.validate_record(record)


def test_profile_rejection_happens_before_reader_use(monkeypatch):
    reader = Reader({})

    def reject(*_args, **_kwargs):
        raise memory.ProfileError("profile rejected")

    monkeypatch.setattr(memory, "_active_profile", reject)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "unknown"
    assert reader.reads == []


def test_fullref_country_prefix_is_rejected_before_graph_walk(configured):
    reader = _build_reader()
    reader.data[(COUNTRY_POINTER + 0x20, 8)] = b"POR\0\x07\0\0\0"
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "unknown"
    assert "country_fullref_prefix_mismatch" in record["reason"]
    assert not any("definition_vector" in label for _a, _s, label in reader.reads)


def test_vector_definition_bound_rejects_before_definition_reads(configured, monkeypatch):
    profile = deepcopy(configured)
    profile["layout"]["max_definitions"] = 2
    monkeypatch.setattr(memory, "_active_profile", lambda: profile)
    reader = _build_reader()
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    assert record["status"] == "unknown"
    assert "vector_definition_count_out_of_bound" in record["reason"]
    assert not any("node[0].vtable" in label for _a, _s, label in reader.reads)


def test_bounded_reader_rejects_single_read_and_total_budget_overflow():
    reader = Reader({})
    budget = memory._Budget(reader)
    with pytest.raises(memory.ReadError, match="read_size_invalid"):
        budget.read(MODULE_BASE, memory.MAX_SINGLE_READ + 1, "too_large")
    budget.bytes_requested = memory.MAX_TOTAL_READ
    with pytest.raises(memory.ReadError, match="read_budget_exceeded"):
        budget.read(MODULE_BASE, 1, "over_budget")


def test_validation_rejects_raw_or_derived_tampering(configured):
    record = memory.read_fields(_build_reader(), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    changed = deepcopy(record)
    changed["nodes"][0]["cache_income_raw"] = 3814
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    changed["total_raw"] += 1
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    changed["nodes"][0]["node_id"] = changed["nodes"][1]["node_id"]
    assert not memory.validate_record(changed)


def test_validation_rejects_country_pointer_graph_and_node_address_tampering(configured):
    record = memory.read_fields(_build_reader(), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    changed = deepcopy(record)
    changed["country_fullref_raw_hex"] = "504f5200" + changed["country_fullref_raw_hex"][8:]
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    changed["special_slot_raw_hex"] = "00000000"
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    changed["graph"]["manager_raw_hex"] = "0000000000000000"
    assert not memory.validate_record(changed)

    changed = deepcopy(record)
    node = changed["nodes"][0]
    province = int(node["province_pointer"], 0) + changed["graph"]["node_count"]
    node["province_pointer"] = hex(province)
    node["province_pointer_raw_hex"] = memory._pointer_raw_hex(province)
    assert not memory.validate_record(changed)


def test_retraction_and_parent_cleanup_remove_trade_values(configured):
    record = memory.read_fields(_build_reader(), MODULE_BASE, COUNTRY_POINTER)
    retracted = memory.retract_record(record, "cleanup_failed")
    assert retracted["status"] == "unknown"
    assert retracted["nodes"] is None
    assert retracted["total_raw"] is None
    assert not memory.validate_record(retracted)

    report = crm._base_report(Path("C:/EU4"), "FRA", include_trade_income=True)
    report["trade_income"] = record
    report["before"] = {"values": {"administrative": 1}, "trade_income": record}
    report["after"] = {"values": {"administrative": 1}, "trade_income": record}
    crm._retract(report)
    assert report["trade_income"]["status"] == "unknown"
    assert report["before"]["trade_income"]["nodes"] is None
    assert report["after"]["trade_income"]["total_raw"] is None


def test_default_parent_report_does_not_request_trade_reader():
    report = crm._base_report(Path("C:/EU4"), "FRA")
    assert "include_trade_income" not in report["request"]
    assert "trade_income" not in report
