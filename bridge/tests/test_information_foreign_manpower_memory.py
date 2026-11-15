from __future__ import annotations

import json

from bridge.information import country_reference_memory
from bridge.information import foreign_manpower_memory as manpower
from bridge.information import foreign_military_visibility_memory as visibility


BASE = 0x140000000
DATABASE = 0x200000
TABLE = 0x300000
COUNTRY = 0x400000
OBSERVER_COUNTRY = 0x410000
SLOT = 5
TAG = "ENG"
OBSERVER_SLOT = 1


class Memory:
    def __init__(self):
        self.data: dict[int, int] = {}
        self.calls: list[tuple[int, int, str]] = []
        self.fail_address: int | None = None
        self.short_address: int | None = None

    def write(self, address: int, raw: bytes) -> None:
        for offset, byte in enumerate(raw):
            self.data[address + offset] = byte

    def write_u16(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(2, "little", signed=False))

    def write_i32(self, address: int, value: int) -> None:
        self.write(address, (value & 0xFFFFFFFF).to_bytes(4, "little"))

    def write_u64(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        if address == self.fail_address:
            raise OSError("synthetic bounded read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped address") from exc
        if address == self.short_address:
            return raw[:-1]
        return raw


def fullref(tag: str, slot: int) -> int:
    low32 = int.from_bytes(tag.encode("ascii") + b"\0", "little")
    return (1 << 56) | (1 << 48) | (slot << 32) | low32


def fixture(counts=(0, 0, 0), costs=(0, 0, 0), reserve=0):
    memory = Memory()
    expected_ref = fullref(TAG, SLOT)
    observer_ref = fullref("FRA", OBSERVER_SLOT)
    memory.write_u64(BASE + country_reference_memory.DATABASE_GLOBAL_RVA, DATABASE)
    memory.write_u64(DATABASE + country_reference_memory.DATABASE_TABLE_OFFSET, TABLE)
    memory.write_i32(DATABASE + country_reference_memory.DATABASE_TABLE_COUNT_OFFSET, SLOT + 1)
    memory.write(TABLE, bytes((SLOT + 1) * 8))
    memory.write_u64(TABLE + OBSERVER_SLOT * 8, OBSERVER_COUNTRY)
    memory.write_u64(TABLE + SLOT * 8, COUNTRY)
    memory.write_u64(COUNTRY + country_reference_memory.COUNTRY_FULLREF_OFFSET, expected_ref)
    memory.write_u64(OBSERVER_COUNTRY + country_reference_memory.COUNTRY_FULLREF_OFFSET,
                     observer_ref)

    pointers = (0x500000, 0x501000, 0x502000)
    for index, (count, cost) in enumerate(zip(counts, costs)):
        memory.write_u16(COUNTRY + manpower.MANPOWER_OFFSETS[index], count)
        if count:
            memory.write_u64(COUNTRY + manpower.DEFINITION_POINTER_OFFSETS[index], pointers[index])
            memory.write_i32(pointers[index] + manpower.DEFINITION_COST_OFFSET, cost)
    memory.write_i32(COUNTRY + manpower.RESERVE_OFFSET, reserve)

    scan = country_reference_memory.resolve_countries(memory.read, BASE, ["FRA", TAG])
    binding = scan["requested"][TAG]
    observer_binding = scan["requested"]["FRA"]

    def validation(row):
        return {
            "binding": row,
            "fullref_resolution": {
                "status": "known",
                "value": row["tag"],
                "raw_inputs": {
                    "country_pointer": row["country_pointer"],
                    "canonical_fullref": row["fullref"],
                },
            },
        }

    permission = {
        "schema": visibility.SCHEMA,
        "status": "known",
        "admitted": True,
        "mode": "fixture_only",
        "observer": {"tag": "FRA", "slot": OBSERVER_SLOT},
        "target": {"tag": TAG, "slot": SLOT},
        "raw_inputs": {
            "observer_binding": observer_binding,
            "target_binding": binding,
            "observer_binding_validation": validation(observer_binding),
            "target_binding_validation": validation(binding),
            "reads": [],
            "budget": {"calls": 0, "bytes_requested": 0},
        },
    }
    memory.calls.clear()
    return memory, binding, permission, pointers, expected_ref


def read_field(memory, binding, permission):
    return manpower.read_fields(memory, BASE, binding, (manpower.FIELD_ID,),
                                permission=permission)[manpower.FIELD_ID]


def install_world(memory, *, public_options=0, world_pointer=0x600000):
    settings = 0x610000
    memory.write_u64(BASE + visibility.WORLD_GLOBAL_RVA, world_pointer)
    if world_pointer:
        memory.write_u64(world_pointer + visibility.WORLD_SETTINGS_OFFSET, settings)
        memory.write_i32(settings + visibility.PUBLIC_OPTIONS_OFFSET, public_options)
        memory.write_i32(settings + visibility.PUBLIC_OPTIONS_SECOND_OFFSET, 0)
        memory.write_u64(COUNTRY + visibility.TARGET_TIMED_HEAD_OFFSET, 0)


def test_zero_counts_skip_definition_pointer_reads_and_are_not_cost_zero():
    memory, binding, permission, _, _ = fixture(counts=(0, 0, 0), reserve=57)
    field = read_field(memory, binding, permission)
    assert field["status"] == "known"
    assert field["value"] == {
        "reserve_raw": 57,
        "components": [
            {"count": 0, "definition_cost": {"status": "not_applicable"}, "contribution_raw": 0},
            {"count": 0, "definition_cost": {"status": "not_applicable"}, "contribution_raw": 0},
            {"count": 0, "definition_cost": {"status": "not_applicable"}, "contribution_raw": 0},
        ],
        "recruited_total_raw": 0,
        "total_raw": 57,
    }
    assert not any("definition_pointer_u64" in label or "definition_cost_i32" in label
                   for _, _, label in memory.calls)


def test_nonzero_components_keep_order_and_use_signed_definition_costs():
    memory, binding, permission, _, _ = fixture(counts=(2, 3, 1), costs=(11, -7, 10), reserve=100)
    field = read_field(memory, binding, permission)
    assert field["status"] == "known"
    assert field["value"] == {
        "reserve_raw": 100,
        "components": [
            {"count": 2, "definition_cost": {"status": "known", "raw": 11}, "contribution_raw": 22},
            {"count": 3, "definition_cost": {"status": "known", "raw": -7}, "contribution_raw": -21},
            {"count": 1, "definition_cost": {"status": "known", "raw": 10}, "contribution_raw": 10},
        ],
        "recruited_total_raw": 11,
        "total_raw": 111,
    }
    assert json.loads(json.dumps(field, ensure_ascii=False)) == field


def test_known_zero_definition_cost_differs_from_zero_count():
    memory, binding, permission, _, _ = fixture(counts=(0, 1, 0), costs=(0, 0, 0))
    field = read_field(memory, binding, permission)
    assert field["status"] == "known"
    first, middle, last = field["value"]["components"]
    assert first["definition_cost"] == {"status": "not_applicable"}
    assert middle["definition_cost"] == {"status": "known", "raw": 0}
    assert middle["contribution_raw"] == 0
    assert last["definition_cost"] == {"status": "not_applicable"}


def test_signed_i32_multiply_and_sum_wrap_at_low_32_bits():
    maximum = 0x7FFFFFFF
    minimum = -0x80000000
    memory, binding, permission, _, _ = fixture(
        counts=(2, 2, 0), costs=(maximum, maximum, 0), reserve=minimum)
    field = read_field(memory, binding, permission)
    assert field["status"] == "known"
    assert [part["contribution_raw"] for part in field["value"]["components"]] == [-2, -2, 0]
    assert field["value"]["recruited_total_raw"] == -4
    assert field["value"]["total_raw"] == 0x7FFFFFFC
    assert field["raw_inputs"]["calculation"]["arithmetic"] == "signed_i32_low32_wrap"


def test_not_admitted_is_invisible_and_performs_no_memory_reads():
    memory, binding, permission, _, _ = fixture(counts=(1, 0, 0), costs=(10, 0, 0))
    permission["admitted"] = False
    field = read_field(memory, binding, permission)
    assert field["status"] == "invisible"
    assert field["reason"] == "COUNTRY_VIEW_NOT_ADMITTED"
    assert "value" not in field
    assert memory.calls == []
    assert field["raw_inputs"]["permission"]["admitted"] is False


def test_unknown_and_non_boolean_permission_fail_closed_without_reads():
    memory, binding, permission, _, _ = fixture(counts=(1, 0, 0), costs=(10, 0, 0))
    permission["status"] = "unknown"
    permission["admitted"] = None
    permission["private_inputs"] = permission.pop("raw_inputs")
    field = read_field(memory, binding, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_VIEW_PERMISSION_UNKNOWN"
    assert memory.calls == []

    permission["status"] = "known"
    permission["admitted"] = 1
    field = read_field(memory, binding, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_VIEW_PERMISSION_INVALID"
    assert memory.calls == []


def test_permission_for_another_binding_is_rejected_before_resource_reads():
    memory, binding, permission, _, _ = fixture(counts=(1, 0, 0), costs=(10, 0, 0))
    permission["target"]["tag"] = "POR"
    field = read_field(memory, binding, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "COUNTRY_VIEW_PERMISSION_TARGET_MISMATCH"
    assert memory.calls == []


def test_target_table_fullref_revalidation_blocks_stale_binding():
    memory, binding, permission, _, expected_ref = fixture(counts=(1, 0, 0), costs=(10, 0, 0))
    memory.write_u64(COUNTRY + country_reference_memory.COUNTRY_FULLREF_OFFSET,
                     expected_ref ^ (1 << 40))
    field = read_field(memory, binding, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "TARGET_BINDING_REVALIDATION_FAILED"
    assert not any("foreign_manpower." in label for _, _, label in memory.calls)


def test_short_read_and_reader_exception_return_unknown_with_private_trace():
    memory, binding, permission, _, _ = fixture(counts=(0, 0, 0), reserve=7)
    memory.short_address = COUNTRY + manpower.RESERVE_OFFSET
    field = read_field(memory, binding, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "READ_FAILED"
    assert field["raw_inputs"]["read_log"][-1]["status"] == "failed"

    memory, binding, permission, _, _ = fixture(counts=(1, 0, 0), costs=(10, 0, 0))
    memory.fail_address = COUNTRY + manpower.MANPOWER_OFFSETS[0]
    field = read_field(memory, binding, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "READ_FAILED"
    assert field["raw_inputs"]["read_log"][-1]["error_type"] == "OSError"


def test_invalid_binding_and_unsupported_field_do_not_read_memory():
    memory, binding, permission, _, _ = fixture()
    bad = dict(binding)
    bad["slot"] += 1
    field = read_field(memory, bad, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "TARGET_BINDING_INVALID"
    assert memory.calls == []

    result = manpower.read_fields(memory, BASE, binding, ("F02.other",), permission=permission)
    assert result["F02.other"]["status"] == "unknown"
    assert result["F02.other"]["reason"] == "UNSUPPORTED_FIELD"
    assert memory.calls == []


def test_real_visibility_leaf_permission_chains_without_synthetic_binding():
    memory, binding, fixture_permission, _, _ = fixture(
        counts=(2, 0, 1), costs=(13, 0, -3), reserve=41)
    observer_binding = fixture_permission["raw_inputs"]["observer_binding"]
    install_world(memory)
    admitted = visibility.read_permission(memory, BASE, observer_binding, binding)
    assert admitted["schema"] == visibility.SCHEMA
    assert admitted["status"] == "known" and admitted["admitted"] is True
    assert admitted["target"] == {"tag": TAG, "slot": SLOT}
    assert admitted["raw_inputs"]["target_binding"]["fullref"] == binding["fullref"]
    field = read_field(memory, binding, admitted)
    assert field["status"] == "known"
    assert field["value"] == {
        "reserve_raw": 41,
        "components": [
            {"count": 2, "definition_cost": {"status": "known", "raw": 13},
             "contribution_raw": 26},
            {"count": 0, "definition_cost": {"status": "not_applicable"},
             "contribution_raw": 0},
            {"count": 1, "definition_cost": {"status": "known", "raw": -3},
             "contribution_raw": -3},
        ],
        "recruited_total_raw": 23,
        "total_raw": 64,
    }

    memory, binding, fixture_permission, _, _ = fixture(
        counts=(1, 0, 0), costs=(9, 0, 0))
    observer_binding = fixture_permission["raw_inputs"]["observer_binding"]
    install_world(memory, public_options=1)
    denied = visibility.read_permission(memory, BASE, observer_binding, binding)
    assert denied["status"] == "known" and denied["admitted"] is False
    calls_before = len(memory.calls)
    field = read_field(memory, binding, denied)
    assert field["status"] == "invisible"
    assert len(memory.calls) == calls_before

    memory, binding, fixture_permission, _, _ = fixture(
        counts=(1, 0, 0), costs=(9, 0, 0))
    observer_binding = fixture_permission["raw_inputs"]["observer_binding"]
    install_world(memory, world_pointer=0)
    unknown = visibility.read_permission(memory, BASE, observer_binding, binding)
    assert unknown["status"] == "unknown"
    calls_before = len(memory.calls)
    field = read_field(memory, binding, unknown)
    assert field["status"] == "unknown"
    assert len(memory.calls) == calls_before
