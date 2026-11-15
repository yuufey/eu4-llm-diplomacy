"""Offline tests for the qualified N05 processor bypass and raw storage helper."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import diplomats_total_memory as memory
from bridge.information import foreign_quality_memory as quality
from bridge.information import modifier_storage
from bridge.tests import test_information_diplomats_total_memory as memory_fixture
from bridge.tests import test_information_country_scale_development_memory as scale_fixture


BASE = memory_fixture.BASE
TARGET_PTR = memory_fixture.TARGET_PTR
MANAGER = memory_fixture.MANAGER
VALUES = memory_fixture.VALUES
PROCESSOR = 0x72000000
OTHER_PROCESSOR = 0x73000000
WRONG_VTABLE_RVA = memory.PROCESSOR_VTABLE_RVA + 0x100
WRONG_METHOD_RVA = memory.PROCESSOR_METHOD_RVA + 0x100


def _qword(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


def _processor_cell() -> int:
    return (MANAGER + memory.MODIFIER_ID * quality.MODIFIER_PROCESSOR_STRIDE
            + quality.MODIFIER_PROCESSOR_OFFSET)


def _install_processor(reader, *, vtable_rva: int = memory.PROCESSOR_VTABLE_RVA,
                       method_rva: int = memory.PROCESSOR_METHOD_RVA,
                       specific: int = 1, override: int = 0) -> None:
    reader.put(_processor_cell(), _qword(PROCESSOR))
    reader.put(PROCESSOR, _qword(BASE + vtable_rva))
    reader.put(BASE + vtable_rva + 8, _qword(BASE + method_rva))
    reader.put(BASE + memory.PROCESSOR_GLOBAL_FLAG_RVA, bytes([specific]))
    reader.put(BASE + memory.PROCESSOR_OVERRIDE_FLAG_RVA, bytes([override]))


def _field(reader, binding):
    return memory_fixture._read(reader, binding)[memory.FIELD]


@pytest.mark.parametrize(
    ("dense", "raw", "sparse_entries", "expected_index"),
    [
        (True, 2345, None, None),
        (True, -1750, None, None),
        (True, 0, None, None),
        (False, 2345, [(133, -88888), (34, 2345), (34, -9000), (159, 99000)], 1),
    ],
)
def test_exact_typed_processor_global_bypass_returns_raw_id_34_unchanged(
        dense, raw, sparse_entries, expected_index):
    reader, binding = memory_fixture._environment(
        dense=dense, modifier_raw=raw, sparse_entries=sparse_entries, processor=PROCESSOR)
    _install_processor(reader, specific=7, override=0)
    # A tempting unrelated dense entry must not replace this leaf's id 34 lookup.
    if dense:
        reader.put(VALUES + 220 * 8 + 4, _i32(912345))

    field = _field(reader, binding)

    assert field["status"] == "known"
    assert field["raw"] == field["value"] == raw
    assert field["raw_hex"] == _i32(raw).hex()
    assert field["scale"] == 1000
    inputs = field["raw_inputs"]["modifier_component"]["raw_inputs"]
    typed = inputs["typed_processor"]
    assert typed["vtable_rva"] == "0x1cc9238"
    assert typed["method_rva"] == "0x8f9d20"
    assert typed["flags"] == {"specific": 7, "override": 0}
    assert typed["thread_state_read"] is False
    assert typed["native_called"] is False
    assert typed["branch"] == "global_bypass_returns_input_unchanged"
    storage = inputs["raw_storage"]
    assert storage["status"] == "known"
    assert storage["raw_inputs"]["modifier_id"] == 34
    assert storage["raw_inputs"]["semantics"] == "raw_storage_only"
    if expected_index is not None:
        assert storage["raw_inputs"]["first_match_index"] == expected_index
        assert [entry["id"] for entry in storage["raw_inputs"]["entries_examined"]] == [133, 34]
    # The object stores its vtable pointer at PROCESSOR; method lookup reads vtable+8.
    assert PROCESSOR in [address for address, _, _ in reader.calls]
    assert BASE + memory.PROCESSOR_VTABLE_RVA + 8 in [address for address, _, _ in reader.calls]
    assert BASE + memory.PROCESSOR_GLOBAL_FLAG_RVA in [address for address, _, _ in reader.calls]
    assert BASE + memory.PROCESSOR_OVERRIDE_FLAG_RVA in [address for address, _, _ in reader.calls]
    assert all("220" not in label for _, _, label in reader.calls)
    if dense:
        assert all(address != VALUES + 220 * 8 + 4 for address, _, _ in reader.calls)


@pytest.mark.parametrize(
    ("specific", "override"),
    [(0, 0), (0, 1), (1, 1), (2, 9)],
)
def test_other_global_flag_combinations_are_unknown_without_storage_or_native_work(
        specific, override):
    reader, binding = memory_fixture._environment(processor=PROCESSOR)
    _install_processor(reader, specific=specific, override=override)

    field = _field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "DIPLOMATS_TOTAL_THREAD_CONTEXT_UNAVAILABLE"
    component = field["raw_inputs"]["modifier_component"]
    assert component["reason"] == "DIPLOMATS_TOTAL_THREAD_CONTEXT_UNAVAILABLE"
    typed = component["raw_inputs"]["typed_processor"]
    assert typed["flags"] == {"specific": specific, "override": override}
    assert typed["thread_state_read"] is False
    assert typed["native_called"] is False
    assert "raw_storage" not in component["raw_inputs"]
    assert not any(label.startswith("modifier_storage.") for _, _, label in reader.calls)


@pytest.mark.parametrize(
    ("vtable_rva", "method_rva"),
    [
        (WRONG_VTABLE_RVA, memory.PROCESSOR_METHOD_RVA),
        (memory.PROCESSOR_VTABLE_RVA, WRONG_METHOD_RVA),
    ],
)
def test_wrong_processor_vtable_or_method_remains_processor_present(vtable_rva, method_rva):
    reader, binding = memory_fixture._environment(processor=PROCESSOR)
    _install_processor(reader, vtable_rva=vtable_rva, method_rva=method_rva)

    field = _field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "MODIFIER_PROCESSOR_PRESENT"
    assert field["raw_inputs"]["modifier_component"]["reason"] == "MODIFIER_PROCESSOR_PRESENT"
    assert not any(label.startswith("modifier_storage.") for _, _, label in reader.calls)


class _ChangedAfterStorageReader(scale_fixture.FakeReader):
    """Present a changed value only on the post-storage stability read."""

    STORAGE_LABEL = "modifier_storage.diplomats_total.dense_value_i32"

    def __init__(self, change_address: int, changed_bytes: bytes):
        super().__init__()
        self.change_address = change_address
        self.changed_bytes = changed_bytes
        self.overrides: dict[tuple[int, int], bytes] = {}
        self.armed = True

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = super().read(address, size, label)
        if self.armed and label == self.STORAGE_LABEL:
            self.overrides[(self.change_address, len(self.changed_bytes))] = self.changed_bytes
            self.armed = False
        return self.overrides.get((address, size), raw)


@pytest.mark.parametrize(
    ("changed_address", "changed_bytes"),
    [
        (_processor_cell(), _qword(OTHER_PROCESSOR)),
        (PROCESSOR, _qword(BASE + WRONG_VTABLE_RVA)),
        (BASE + memory.PROCESSOR_VTABLE_RVA + 8, _qword(BASE + WRONG_METHOD_RVA)),
        (BASE + memory.PROCESSOR_GLOBAL_FLAG_RVA, b"\x00"),
        (BASE + memory.PROCESSOR_OVERRIDE_FLAG_RVA, b"\x01"),
    ],
)
def test_processor_change_after_storage_read_is_unknown(changed_address, changed_bytes):
    original_reader, binding = memory_fixture._environment(processor=PROCESSOR)
    _install_processor(original_reader)
    reader = _ChangedAfterStorageReader(changed_address, changed_bytes)
    reader.bytes.update(original_reader.bytes)

    field = _field(reader, binding)

    assert field["status"] == "unknown"
    assert field["reason"] == "DIPLOMATS_TOTAL_PROCESSOR_CHANGED"
    component = field["raw_inputs"]["modifier_component"]
    assert component["reason"] == "DIPLOMATS_TOTAL_PROCESSOR_CHANGED"
    assert component["raw_inputs"]["raw_storage"]["status"] == "known"
    assert reader.bytes == original_reader.bytes


def _raw_220(reader):
    before = deepcopy(reader.bytes)
    trace = quality._TraceReader(reader)
    result = modifier_storage.read_raw_modifier(
        trace, TARGET_PTR, 220, "diplomats", name="raw220")
    assert reader.bytes == before, "raw storage lookup must not write input memory"
    assert trace.calls == len(trace.reads)
    assert trace.bytes_requested == sum(row["size"] for row in trace.reads)
    assert all(size <= quality.MAX_SINGLE_READ_BYTES for _, size, _ in reader.calls)
    assert all(label.startswith("modifier_storage.raw220.") for _, _, label in reader.calls)
    return result, trace


def test_raw_helper_220_reads_dense_value_without_checking_processor():
    reader, _ = memory_fixture._environment(processor=PROCESSOR)
    reader.put(VALUES + 220 * 8 + 4, _i32(-4412))

    result, trace = _raw_220(reader)

    assert result["status"] == "known"
    assert result["raw"] == result["value"] == -4412
    assert result["raw_inputs"]["mode"] == "dense"
    assert result["raw_inputs"]["modifier_id"] == 220
    assert trace.calls == 4


def test_raw_helper_220_sparse_lookup_is_bounded_and_returns_first_match():
    entries = [(1, index) for index in range(2048)]
    entries.extend([(220, -1234), (220, 9999)])
    reader, _ = memory_fixture._environment(
        dense=False, sparse_entries=entries, processor=PROCESSOR)

    result, trace = _raw_220(reader)

    assert result["status"] == "known"
    assert result["raw"] == result["value"] == -1234
    inputs = result["raw_inputs"]
    assert inputs["mode"] == "sparse"
    assert inputs["first_match_index"] == 2048
    assert [row["id"] for row in inputs["entries_examined"][-2:]] == [1, 220]
    sparse_sizes = [row["size"] for row in trace.reads if "sparse_entries" in row["label"]]
    assert sparse_sizes == [quality.SPARSE_CHUNK_BYTES, 16]


def test_raw_helper_220_empty_sparse_is_default_zero_without_entry_read():
    reader, _ = memory_fixture._environment(
        dense=False, sparse_entries=[], processor=PROCESSOR)

    result, trace = _raw_220(reader)

    assert result["status"] == "known"
    assert result["raw"] == result["value"] == 0
    assert result["raw_inputs"]["mode"] == "sparse"
    assert result["raw_inputs"]["first_match_index"] is None
    assert not any("sparse_entries" in row["label"] for row in trace.reads)


@pytest.mark.parametrize(
    ("kind", "expected_reason"),
    [
        ("bad_pointer", "MODIFIER_VALUES_POINTER_INVALID"),
        ("over_count", "MODIFIER_COUNT_OUT_OF_RANGE"),
    ],
)
def test_raw_helper_220_rejects_bad_pointer_and_out_of_range_count(kind, expected_reason):
    if kind == "bad_pointer":
        reader, _ = memory_fixture._environment(values_pointer=0x10, processor=PROCESSOR)
    else:
        reader, _ = memory_fixture._environment(
            dense=False, sparse_entries=[], processor=PROCESSOR)
        count_address = (TARGET_PTR + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
                         + quality.MODIFIER_SPARSE_COUNT_OFFSET)
        reader.put(count_address, int(quality.MAX_SPARSE_ENTRIES + 1).to_bytes(4, "little"))

    result, trace = _raw_220(reader)

    assert result["status"] == "unknown"
    assert result["reason"] == expected_reason
    assert result["raw_inputs"]["modifier_id"] == 220
    assert not any("sparse_entries" in row["label"] for row in trace.reads)
