"""Pure signed-scalar projection tests for the bounded province leaf.

The in-memory reader fixture exercises only the three record-relative reads.
It does not open a process or establish province identity, visibility, or
two-pass consistency; those remain parent/backend responsibilities.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.province_scalar_memory import FIELD_ID, read_fields


MODULE_BASE = 0x140000000
RECORD_POINTER = 0x200000
PROVINCE_ID = 183
CURRENT_OFFSET = 0x428
LOWER_OFFSET = 0x2DF0
UPPER_OFFSET = 0x2DF4
ID_OFFSET = 0x20


def _i32(value):
    return value.to_bytes(4, "little", signed=True)


def make_binding(*, province_id=PROVINCE_ID, record_pointer=RECORD_POINTER):
    return {
        "province_id": province_id,
        "record_pointer": hex(record_pointer),
        "id_address": hex(record_pointer + ID_OFFSET),
        "id_raw_hex": int(province_id).to_bytes(4, "little", signed=True).hex(),
        "record_id": province_id,
    }


class Memory:
    def __init__(self, *, current, lower, upper, fail_index=None, failure="raise"):
        self.values = {
            RECORD_POINTER + CURRENT_OFFSET: _i32(current),
            RECORD_POINTER + LOWER_OFFSET: _i32(lower),
            RECORD_POINTER + UPPER_OFFSET: _i32(upper),
        }
        self.calls = []
        self.fail_index = fail_index
        self.failure = failure

    def read(self, address, size, label):
        self.calls.append((address, size, label))
        index = len(self.calls) - 1
        if index == self.fail_index:
            if self.failure == "raise":
                raise OSError("fixture read failure")
            if self.failure == "short":
                return self.values[address][:3]
            if self.failure == "wrong_type":
                return None
        assert size == 4
        return self.values[address]


def run(current, lower, upper, *, binding=None, memory=None, fields=None,
        module_base=MODULE_BASE):
    if memory is None:
        memory = Memory(current=current, lower=lower, upper=upper)
    result = read_fields(
        memory.read, module_base, binding or make_binding(),
        fields if fields is not None else [FIELD_ID])
    return result, memory


@pytest.mark.parametrize(("current", "lower", "upper", "effective", "display"), [
    (42000, 10000, 90000, 42000, 42000),
    (500, 1000, 90000, 1000, 1000),
    (120000, -1000, 70000, 70000, 70000),
    (-500, -1000, 1000, -500, 0),
    (10000, 10000, 20000, 10000, 10000),
    (20000, 10000, 20000, 20000, 20000),
    (120000, 1000, 150000, 120000, 120000),
    (2147483647, -2147483648, 2147483647, 2147483647, 2147483647),
    (-2147483648, -2147483648, 2147483647, -2147483648, 0),
])
def test_native_clamp_order_signed_values_and_display_floor(
        current, lower, upper, effective, display):
    result, memory = run(current, lower, upper)

    field = result[FIELD_ID]
    assert field["status"] == "known"
    assert field["value"] == display
    assert field["scale"] == 1000
    assert field["period"] == "current"
    assert field["partial"] is True
    assert field["complete"] is False
    raw = field["raw_inputs"]
    assert raw["record_pointer"] == hex(RECORD_POINTER)
    assert raw["lower_raw"] == lower
    assert raw["current_raw"] == current
    assert raw["upper_raw"] == upper
    assert raw["effective_raw"] == effective
    assert raw["effective_raw_hex"] == _i32(effective).hex()
    assert raw["lower_raw_hex"] == _i32(lower).hex()
    assert raw["current_raw_hex"] == _i32(current).hex()
    assert raw["upper_raw_hex"] == _i32(upper).hex()
    assert raw["lower_address"] == hex(RECORD_POINTER + LOWER_OFFSET)
    assert raw["current_address"] == hex(RECORD_POINTER + CURRENT_OFFSET)
    assert raw["upper_address"] == hex(RECORD_POINTER + UPPER_OFFSET)
    assert [(address, size) for address, size, _ in memory.calls] == [
        (RECORD_POINTER + LOWER_OFFSET, 4),
        (RECORD_POINTER + CURRENT_OFFSET, 4),
        (RECORD_POINTER + UPPER_OFFSET, 4),
    ]


@pytest.mark.parametrize(("current", "lower", "upper", "effective"), [
    (20000, 40000, 30000, 30000),
    (50000, 40000, 30000, 30000),
    (35000, 40000, 30000, 30000),
])
def test_reversed_bounds_keep_native_min_max_order_without_rejection(
        current, lower, upper, effective):
    result, _ = run(current, lower, upper)

    field = result[FIELD_ID]
    assert field["status"] == "known"
    assert field["raw_inputs"]["effective_raw"] == effective
    assert field["value"] == max(0, effective)


def test_unsupported_fields_are_unknown_without_reads_and_mixed_request_is_scoped():
    memory = Memory(current=25000, lower=0, upper=80000)
    unsupported = read_fields(memory.read, MODULE_BASE, make_binding(), ["G02.owner"])
    assert unsupported == {"G02.owner": {
        "status": "unknown", "reason": "field_not_supported", "scale": 1000,
        "period": "current", "partial": True, "complete": False,
    }}
    assert memory.calls == []

    mixed = read_fields(memory.read, MODULE_BASE, make_binding(), [FIELD_ID, "G02.controller"])
    assert mixed[FIELD_ID]["status"] == "known"
    assert mixed["G02.controller"]["status"] == "unknown"
    assert "value" not in mixed["G02.controller"]
    assert len(memory.calls) == 3


@pytest.mark.parametrize("fields", [
    None,
    FIELD_ID,
    {FIELD_ID: True},
    [FIELD_ID, FIELD_ID],
    [FIELD_ID, None],
])
def test_invalid_or_duplicate_selectors_do_not_read_memory(fields):
    memory = Memory(current=1, lower=0, upper=2)

    result = read_fields(memory.read, MODULE_BASE, make_binding(), fields)

    assert all(field["status"] == "unknown" for field in result.values())
    assert all("value" not in field and "raw_inputs" not in field
               for field in result.values())
    assert memory.calls == []


def _invalid_binding(binding, case):
    if case == "bool_id":
        binding["province_id"] = True
    elif case == "zero_id":
        binding["province_id"] = 0
        binding["record_id"] = 0
        binding["id_raw_hex"] = "00000000"
    elif case == "negative_id":
        binding["province_id"] = -1
        binding["record_id"] = -1
        binding["id_raw_hex"] = "ffffffff"
    elif case == "record_id_mismatch":
        binding["record_id"] = PROVINCE_ID + 1
    elif case == "bool_record_id":
        binding["record_id"] = True
    elif case == "pointer_not_text":
        binding["record_pointer"] = RECORD_POINTER
    elif case == "pointer_low":
        binding["record_pointer"] = "0x20"
        binding["id_address"] = hex(0x20 + ID_OFFSET)
    elif case == "pointer_unaligned":
        binding["record_pointer"] = hex(RECORD_POINTER + 1)
        binding["id_address"] = hex(RECORD_POINTER + 1 + ID_OFFSET)
    elif case == "pointer_above_user_range":
        binding["record_pointer"] = "0x800000000000"
    elif case == "id_address_mismatch":
        binding["id_address"] = hex(RECORD_POINTER + ID_OFFSET + 4)
    elif case == "id_raw_bad_shape":
        binding["id_raw_hex"] = "0xb7000000"
    elif case == "id_raw_mismatch":
        binding["id_raw_hex"] = "b6000000"
    elif case == "missing_id_raw":
        binding.pop("id_raw_hex")
    elif case == "extra_binding_key":
        binding["visibility"] = "visible"
    elif case == "pointer_address_overflow":
        high_record = 0x7FFFFFFFF000
        binding["record_pointer"] = hex(high_record)
        binding["id_address"] = hex(high_record + ID_OFFSET)
    else:
        raise AssertionError(case)
    return binding


@pytest.mark.parametrize("case", [
    "bool_id", "zero_id", "negative_id", "record_id_mismatch", "bool_record_id",
    "pointer_not_text", "pointer_low", "pointer_unaligned", "pointer_above_user_range",
    "id_address_mismatch", "id_raw_bad_shape", "id_raw_mismatch", "missing_id_raw",
    "extra_binding_key", "pointer_address_overflow",
])
def test_malformed_identity_binding_yields_unknown_without_memory_reads(case):
    memory = Memory(current=1000, lower=0, upper=2000)
    binding = _invalid_binding(make_binding(), case)

    result = read_fields(memory.read, MODULE_BASE, binding, [FIELD_ID])

    field = result[FIELD_ID]
    assert field["status"] == "unknown"
    assert "value" not in field
    assert "raw_inputs" not in field
    assert memory.calls == []


@pytest.mark.parametrize("module_base", [0, True, 0x20, "0x140000000"])
def test_invalid_module_base_yields_unknown_without_read(module_base):
    memory = Memory(current=1000, lower=0, upper=2000)

    result = read_fields(memory.read, module_base, make_binding(), [FIELD_ID])

    assert result[FIELD_ID]["status"] == "unknown"
    assert result[FIELD_ID]["reason"] == "module_base_invalid"
    assert "value" not in result[FIELD_ID]
    assert memory.calls == []


@pytest.mark.parametrize(("failure", "fail_index"), [
    ("raise", 0), ("raise", 1), ("raise", 2),
    ("short", 0), ("short", 1), ("short", 2),
    ("wrong_type", 0), ("wrong_type", 1), ("wrong_type", 2),
])
def test_each_short_or_failed_read_retracts_whole_scalar(failure, fail_index):
    memory = Memory(current=25000, lower=10000, upper=50000,
                    fail_index=fail_index, failure=failure)

    result = read_fields(memory.read, MODULE_BASE, make_binding(), [FIELD_ID])

    field = result[FIELD_ID]
    assert field["status"] == "unknown"
    assert "value" not in field
    assert "raw_inputs" not in field
    assert len(memory.calls) == fail_index + 1
    assert all(size == 4 for _, size, _ in memory.calls)


def test_non_callable_reader_fails_closed_without_fallback():
    result = read_fields(None, MODULE_BASE, make_binding(), [FIELD_ID])

    assert result[FIELD_ID]["status"] == "unknown"
    assert result[FIELD_ID]["reason"] == "reader_not_callable"
    assert "value" not in result[FIELD_ID]
