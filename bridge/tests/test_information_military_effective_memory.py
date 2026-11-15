from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import military_effective_memory as memory


# Keep these addresses aligned with the other bounded child fixtures so a
# parent mixed-source test can reuse the helper without translating pointers.
MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x200000000
# The modifier object is embedded at country+0x28d0.  Its +0x58 values
# pointer is the separately allocated storage exercised by the fixture.
MODIFIER_OBJECT = COUNTRY_POINTER + memory.COUNTRY_MODIFIER_OBJECT_OFFSET
VALUES = 0x200110000
SPARSE_VALUES = 0x200120000
MANAGER = 0x200130000
PROCESSOR = 0x200140000


class BoundedReader:
    def __init__(self):
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: value for index, value in enumerate(raw)})

    def u8(self, address: int, value: int) -> None:
        self.put(address, bytes([value & 0xFF]))

    def u32(self, address: int, value: int) -> None:
        self.put(address, (int(value) & 0xFFFFFFFF).to_bytes(4, "little"))

    def i32(self, address: int, value: int) -> None:
        self.u32(address, value)

    def qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little"))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            return bytes(self.memory[address + index] for index in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected bounded read: {label} {address:#x} {size}") from exc


def _reader(
    *,
    dense: bool = True,
    modifier: int = 0,
    processor: bool = False,
    processor_values: dict[str, int] | None = None,
    flags: dict[str, int] | None = None,
    special: int = 0,
    state: int = 0,
    unsupported_vtable: bool = False,
) -> BoundedReader:
    profile = memory._load_profile()
    layout = memory._profile_layout(profile)
    reader = BoundedReader()
    for _name, rva, _end, raw in memory._profile_code_guards(profile):
        reader.put(MODULE_BASE + rva, raw)

    reader.i32(COUNTRY_POINTER + layout["country_cache_state_offset"], state)
    reader.u8(MODIFIER_OBJECT + layout["modifier_dense_flag_offset"], 1 if dense else 0)
    reader.qword(MODIFIER_OBJECT + layout["modifier_values_pointer_offset"], VALUES if dense else SPARSE_VALUES)

    if dense:
        reader.u32(MODIFIER_OBJECT + layout["modifier_sparse_count_offset"], 0)
        reader.i32(VALUES + layout["dense_modifier_value_offset"], modifier)
        for key, offset in memory.PROCESSOR_DENSE_OFFSETS.items():
            reader.i32(VALUES + offset, (processor_values or {}).get(key, 0))
    else:
        pairs = [(0x10, 1), (memory.MODIFIER_ID, modifier), (memory.MODIFIER_ID, modifier + 4)]
        reader.u32(MODIFIER_OBJECT + layout["modifier_sparse_count_offset"], len(pairs))
        for index, (key, value) in enumerate(pairs):
            reader.u32(SPARSE_VALUES + index * 8, key)
            reader.i32(SPARSE_VALUES + index * 8 + 4, value)

    reader.qword(MODULE_BASE + layout["modifier_database_global_rva"], MANAGER)
    slot_offset = layout["modifier_record_index"] * layout["modifier_record_stride"] + layout["modifier_processor_offset"]
    reader.qword(MANAGER + slot_offset, PROCESSOR if processor else 0)
    if processor:
        vtable = MODULE_BASE + layout["processor_vtable_rva"]
        if unsupported_vtable:
            vtable += 0x1000
        reader.qword(PROCESSOR, vtable)
        reader.qword(vtable + 8, MODULE_BASE + layout["processor_method_rva"])
        for key, rva in layout["global_flag_rvas"].items():
            reader.u8(MODULE_BASE + rva, (flags or {}).get(key, 0))
        reader.u8(MODULE_BASE + layout["special_flag_rva"], special)
    return reader


def test_dense_null_processor_is_known_partial_and_validates() -> None:
    reader = _reader(modifier=123)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["record_key"] == "military_effective"
    assert record["complete"] is False
    assert record["fields"]["discipline"] == {
        "status": "known",
        "complete": False,
        "value": 1123,
        "raw": 1123,
        "raw_hex": "63040000",
        "unit": "ratio",
        "scale": 1000,
        "period": "current",
        "basis": memory.BASIS,
        "value_origin": memory.VALUE_ORIGIN,
    }
    assert memory.validate_record(record)
    assert sum(size for _address, size, _label in reader.reads) <= memory.READ_BUDGET_BYTES


def test_sparse_uses_first_matching_entry() -> None:
    reader = _reader(dense=False, modifier=5)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["values"]["discipline"] == 1005
    assert record["observation"]["modifier"]["first_match_index"] == 1
    assert record["observation"]["modifier"]["modifier_raw"] == 5
    assert memory.validate_record(record)


def test_recognized_processor_with_disabled_gates_does_not_require_tls() -> None:
    values = {key: 5000 for key in memory.PROCESSOR_DENSE_OFFSETS}
    flags = {key: 1 for key in memory.GLOBAL_FLAG_RVAS}
    reader = _reader(processor=True, modifier=7, processor_values=values, flags=flags, special=0)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["observation"]["processor"]["thread_context_status"] == "not_required_zero_contribution"
    assert record["values"]["discipline"] == 1007
    assert memory.validate_record(record)


def test_recognized_processor_zero_contributions_are_known() -> None:
    reader = _reader(processor=True, modifier=7, processor_values={key: 0 for key in memory.PROCESSOR_DENSE_OFFSETS})
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["observation"]["processor"]["thread_context_status"] == "not_required_zero_contribution"
    assert memory.validate_record(record)


def test_enabled_nonzero_processor_contribution_stays_unknown_without_tls() -> None:
    reader = _reader(
        processor=True,
        processor_values={"0x102": 5000, "0x1bb": 0, "0x1d2": 0, "0x1c2": 0},
    )
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "MILITARY_PROCESSOR_THREAD_CONTEXT_UNAVAILABLE"
    assert record["fields"]["discipline"]["status"] == "unknown"
    assert record["observation"]["processor"]["thread_context_unknown_for"] == ["0x102"]
    assert record["values"] is None
    assert not memory.validate_record(record)


def test_unsupported_processor_vtable_does_not_fallback_to_base() -> None:
    reader = _reader(processor=True, modifier=12, unsupported_vtable=True)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "MILITARY_PROCESSOR_VTABLE_UNSUPPORTED"
    assert record["values"] is None


def test_calculating_cache_is_unknown() -> None:
    reader = _reader(state=1, modifier=44)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "MILITARY_CACHE_CALCULATING"
    assert record["values"] is None


def test_negative_overflow_is_wrapped_then_minimum_clamped() -> None:
    reader = _reader(modifier=-0x80000000)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["values"]["discipline"] == 10
    assert record["observation"]["effective_before_clamp"] < 0
    assert memory.validate_record(record)


def test_budget_is_reserved_before_a_failing_guard_read(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader()

    class TinyBudget(memory._ReadBudget):
        def __init__(self, _limit: int = memory.READ_BUDGET_BYTES):
            super().__init__(300)

    monkeypatch.setattr(memory, "_ReadBudget", TinyBudget)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert record["runtime_code_guard"]["bytes_reserved"] == 180
    assert record["observation"]["read_budget"]["bytes_reserved"] == 180


def test_real_validator_rejects_value_input_and_guard_tampering() -> None:
    record = memory.read_fields(_reader(modifier=15), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    value_tampered = deepcopy(record)
    value_tampered["values"]["discipline"] += 1
    assert not memory.validate_record(value_tampered)

    input_tampered = deepcopy(record)
    input_tampered["observation"]["modifier"]["modifier_raw"] = 16
    assert not memory.validate_record(input_tampered)

    guard_tampered = deepcopy(record)
    guard_tampered["runtime_code_guard"]["checks"]["discipline_helper_341850"] = False
    assert not memory.validate_record(guard_tampered)


def test_profile_rejection_does_not_touch_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = BoundedReader()

    def reject(*_args, **_kwargs):
        raise memory.ProfileError("profile rejected")

    monkeypatch.setattr(memory, "_load_profile", reject)
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"] == "static_contract_guard_failed"
    assert reader.reads == []


def test_retraction_cannot_validate_as_known() -> None:
    record = memory.read_fields(_reader(modifier=5), MODULE_BASE, COUNTRY_POINTER)
    retracted = memory.retract_record(record, "cleanup_failed")

    assert retracted["status"] == "unknown"
    assert retracted["fields"]["discipline"]["status"] == "unknown"
    assert not memory.validate_record(retracted)
