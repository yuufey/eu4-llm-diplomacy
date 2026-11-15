from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import country_resources_memory as crm
from bridge.information import monthly_economy_memory as memory


MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x200000000


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


def _put(payload: bytearray, offset: int, value: int) -> None:
    payload[offset:offset + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def _profile() -> dict:
    return {
        "profile_id": "monthly-economy-memory-1374",
        "game_version": "1.37.4",
        "executable": {"sha256": memory.EXPECTED_EXE_SHA256},
        "source_index": {
            "source_index_id": "monthly-source-index-1374",
            "path": "work/runtime/monthly-source-index.json",
            "sha256": "c" * 64,
        },
        "layout": {
            "income_offset": 0x770,
            "income_count": 19,
            "expense_offset": 0x7BC,
            "expense_count": 38,
            "payload_size": 228,
            "component_width": 4,
            "signed": True,
            "wrap_bits": 32,
            "income_indices": list(memory.INCOME_INDICES),
            "expense_indices": list(memory.EXPENSE_INDICES),
        },
        "code_guards": [
            {"name": "monthly_property", "rva": 0x1000, "hex": "aabbccdd"},
            {"name": "monthly_budget", "rva": 0x2000, "hex": "11223344"},
        ],
    }


def _reader(profile: dict, income: list[int] | None = None, expense: list[int] | None = None) -> Reader:
    income = list(income or [0] * memory.INCOME_COUNT)
    expense = list(expense or [0] * memory.EXPENSE_COUNT)
    payload = bytearray(memory.LEDGER_SIZE)
    for index, value in enumerate(income):
        _put(payload, index * 4, value)
    expense_start = memory.EXPENSE_OFFSET - memory.INCOME_OFFSET
    for index, value in enumerate(expense):
        _put(payload, expense_start + index * 4, value)
    data: dict[tuple[int, int], bytes] = {}
    for guard in profile["code_guards"]:
        raw = bytes.fromhex(guard["hex"])
        data[(MODULE_BASE + guard["rva"], len(raw))] = raw
    data[(COUNTRY_POINTER + memory.INCOME_OFFSET, memory.LEDGER_SIZE)] = bytes(payload)
    return Reader(data)


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch):
    profile = _profile()
    monkeypatch.setattr(memory, "EXPECTED_PROFILE_SHA256", "b" * 64)
    monkeypatch.setattr(memory, "_load_profile", lambda *args, **kwargs: profile)
    return profile


def test_reads_one_ledger_and_preserves_raw_arrays(configured):
    income = [1, 2, 3, 4, 5, 6, 7, 8, 9] + [0] * 10
    income[15] = 10
    income[16] = 11
    expense = [2] * memory.EXPENSE_COUNT
    reader = _reader(configured, income, expense)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["values"] == {
        "monthly_income": 66,
        "monthly_expenses": 46,
        "monthly_balance": 20,
    }
    assert record["income_slots"] == income
    assert record["expense_slots"] == expense
    assert len(record["raw_ledger_hex"]) == memory.LEDGER_SIZE * 2
    assert record["basis"] == memory.BASIS
    assert record["reference_period"] == "previous_month"
    assert record["period"] == "month"
    assert record["value_semantics"] == "previous_month_recurring_ledger"
    assert record["unit"] == "ducats"
    assert record["scale"] == 1000
    assert record["value_origin"] == "derived_from_copied_native_ledger"
    assert all(
        item["complete"] is False
        and item["value_origin"] == "derived_from_copied_native_ledger"
        and item["value_semantics"] == "previous_month_recurring_ledger"
        for item in record["fields"].values()
    )
    assert memory.validate_record(record)
    assert [label for _address, _size, label in reader.reads] == [
        "monthly_economy.code.monthly_property",
        "monthly_economy.code.monthly_budget",
        "monthly_economy.ledger",
    ]


def test_income_index12_nonzero_is_still_skipped(configured):
    income = [0] * memory.INCOME_COUNT
    income[12] = 12345
    record = memory.read_fields(_reader(configured, income), MODULE_BASE, COUNTRY_POINTER)
    assert record["values"]["monthly_income"] == 0

    income[0] = 1
    record = memory.read_fields(_reader(configured, income), MODULE_BASE, COUNTRY_POINTER)
    assert record["values"]["monthly_income"] == 1


def test_expense_uses_exactly_23_included_slots(configured):
    expense = [0] * memory.EXPENSE_COUNT
    for index in memory.EXPENSE_INDICES:
        expense[index] = 7
    expense[12] = 1000
    record = memory.read_fields(_reader(configured, expense=expense), MODULE_BASE, COUNTRY_POINTER)
    assert record["values"]["monthly_expenses"] == 7 * 23


def test_negative_zero_and_int32_accumulation_wrap(configured):
    income = [0] * memory.INCOME_COUNT
    income[0] = 0x7FFFFFFF
    income[1] = 1
    income[2] = -5
    expense = [0] * memory.EXPENSE_COUNT
    expense[0] = 1
    record = memory.read_fields(_reader(configured, income, expense), MODULE_BASE, COUNTRY_POINTER)
    assert record["values"] == {
        "monthly_income": 0x7FFFFFFB,
        "monthly_expenses": 1,
        "monthly_balance": 0x7FFFFFFA,
    }

    income[2] = 0
    expense[0] = 0
    record = memory.read_fields(_reader(configured, income, expense), MODULE_BASE, COUNTRY_POINTER)
    assert record["values"]["monthly_income"] == -0x80000000


def test_profile_failure_rejects_before_any_reader_use(monkeypatch):
    reader = Reader({})

    def reject(*_args, **_kwargs):
        raise memory.ProfileError("profile rejected")

    monkeypatch.setattr(memory, "_load_profile", reject)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert reader.reads == []


def test_guard_failure_rejects_before_ledger_read(configured):
    reader = _reader(configured)
    address, size, _label = reader.reads[0] if reader.reads else (MODULE_BASE + 0x1000, 4, "")
    reader.data[(address, size)] = b"\x00" * size

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert not any(label == "monthly_economy.ledger" for _a, _s, label in reader.reads)


def test_validation_rejects_payload_result_or_guard_tampering(configured):
    record = memory.read_fields(_reader(configured), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    payload_tampered = deepcopy(record)
    payload_tampered["raw_ledger_hex"] = "ff" * memory.LEDGER_SIZE
    assert not memory.validate_record(payload_tampered)

    value_tampered = deepcopy(record)
    value_tampered["values"]["monthly_income"] += 1
    assert not memory.validate_record(value_tampered)

    guard_tampered = deepcopy(record)
    guard_tampered["runtime_code_guard"]["checks"]["monthly_property"] = False
    assert not memory.validate_record(guard_tampered)


def test_parent_doublepass_compares_excluded_slot_payload(configured):
    first = memory.read_fields(_reader(configured), MODULE_BASE, COUNTRY_POINTER)
    second = deepcopy(first)
    payload = bytearray.fromhex(second["raw_ledger_hex"])
    expense_start = memory.EXPENSE_OFFSET - memory.INCOME_OFFSET
    _put(payload, expense_start + 12 * 4, 999)
    second["raw_ledger_hex"] = bytes(payload).hex()
    second["raw_payload_hex"] = second["raw_ledger_hex"]

    left = crm._compare_snapshot({"status": "observed", "monthly_economy": first})
    right = crm._compare_snapshot({"status": "observed", "monthly_economy": second})
    assert "$.monthly_economy.raw_ledger_hex" in crm._diff_paths(left, right)


def test_cleanup_retraction_cannot_validate_as_known(configured):
    record = memory.read_fields(_reader(configured), MODULE_BASE, COUNTRY_POINTER)
    retracted = memory.retract_record(record, "cleanup_failed")
    assert retracted["status"] == "unknown"
    assert retracted["raw_ledger_hex"] is None
    assert not memory.validate_record(retracted)


def test_parent_default_request_does_not_add_or_read_monthly(monkeypatch):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("monthly reader must not be called by default")

    monkeypatch.setattr(crm._monthly, "read_fields", unexpected)
    report = crm._base_report(Path("C:/EU4"), "FRA")
    assert "include_monthly_economy" not in report["request"]
    assert "monthly_economy" not in report
