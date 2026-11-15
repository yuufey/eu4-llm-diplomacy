"""Bounded offline tests for the copied-input religious-unity getter.

The reader below is deliberately a byte-addressed fixture.  It supplies the
profile's code guards and only the object ranges needed by each case, so an
unwanted later read fails instead of silently becoming a fabricated value.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import religious_unity_memory as unity_memory
from bridge.information import InformationService
from bridge.tests.test_information_domestic_pressure import (
    FIELDS as LEGACY_FIELDS,
    _query as domestic_query,
    _report as domestic_report,
    _source as domestic_source,
)


MODULE_BASE = 0x100000000
COUNTRY = 0x200000000
DATABASE = 0x300000000
MODIFIER_VALUES = 0x400000000


def _profile():
    return unity_memory._load_profile()


def _layout():
    profile = _profile()
    return {key: int(value, 0) if isinstance(value, str) else int(value)
            for key, value in profile["layout"].items()}


def _put(memory: dict[int, int], address: int, data: bytes) -> None:
    memory.update({address + offset: value for offset, value in enumerate(data)})


def _put_int(memory: dict[int, int], address: int, value: int, *, size: int,
             signed: bool = False) -> None:
    _put(memory, address, int(value).to_bytes(size, "little", signed=signed))


class _BoundedReader:
    """A small fake RPM seam which rejects every unmapped byte read."""

    def __init__(self, memory: dict[int, int]):
        self.memory = memory
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if type(address) is not int or type(size) is not int or size < 0 or size > 65536:
            raise AssertionError(f"invalid bounded read: {address!r}, {size!r}")
        self.reads.append((address, size, label))
        missing = [address + offset for offset in range(size)
                   if address + offset not in self.memory]
        if missing:
            raise AssertionError(f"unmapped read {label}: {missing[0]:#x}")
        return bytes(self.memory[address + offset] for offset in range(size))


def _make_reader(
    *,
    province: int = 0,
    unity: int = 0,
    dense: bool = True,
    sparse_entries: list[tuple[int, int]] | None = None,
    sparse_count: int | None = None,
    special_flags: int = 0,
    special_base: int = 0,
    special_processor: int = 0,
    unity_processor: int = 0,
    cache_state: int = 0,
) -> _BoundedReader:
    """Build one profile-shaped country/database fixture."""
    profile = _profile()
    layout = _layout()
    memory: dict[int, int] = {}

    for item in profile["code_guards"]:
        _put(memory, MODULE_BASE + int(item["rva"], 0), bytes.fromhex(item["hex"]))

    _put_int(memory, COUNTRY + layout["country_cache_state_offset"], cache_state,
             size=4, signed=True)
    _put_int(memory, COUNTRY + layout["country_province_component_offset"], province,
             size=4, signed=True)

    header = COUNTRY + layout["country_modifier_object_offset"]
    header_size = max(
        layout["modifier_sparse_count_offset"] + 4,
        layout["modifier_values_pointer_offset"] + 8,
        layout["modifier_dense_flag_offset"] + 1,
    )
    _put(memory, header, bytes(header_size))
    memory[header + layout["modifier_dense_flag_offset"]] = 1 if dense else 0
    _put_int(memory, header + layout["modifier_values_pointer_offset"], MODIFIER_VALUES,
             size=8)
    entries = list(sparse_entries or [])
    count = len(entries) if sparse_count is None else sparse_count
    _put_int(memory, header + layout["modifier_sparse_count_offset"], count,
             size=4, signed=True)
    for index, (identifier, value) in enumerate(entries):
        _put_int(memory, MODIFIER_VALUES + index * 8, identifier, size=4)
        _put_int(memory, MODIFIER_VALUES + index * 8 + 4, value, size=4, signed=True)

    _put_int(memory, MODULE_BASE + layout["modifier_database_rva"], DATABASE, size=8)

    def record(identifier: int, processor: int, resolved_type: int | None = None) -> None:
        row = bytearray(layout["record_stride"])
        row[layout["record_processor_offset"]:layout["record_processor_offset"] + 8] = (
            int(processor).to_bytes(8, "little")
        )
        resolved = identifier if resolved_type is None else resolved_type
        row[layout["record_resolved_type_offset"]:layout["record_resolved_type_offset"] + 4] = (
            int(resolved).to_bytes(4, "little")
        )
        _put(memory, DATABASE + identifier * layout["record_stride"], bytes(row))

    special_id = layout["special_rule_id"]
    unity_id = layout["unity_modifier_id"]
    record(special_id, special_processor)
    record(unity_id, unity_processor)
    memory[DATABASE + special_id * layout["record_stride"] + layout["record_flags_offset"]] = special_flags

    if dense:
        _put_int(memory, MODIFIER_VALUES + special_id * layout["dense_entry_stride"]
                 + layout["dense_value_offset"], special_base, size=4, signed=True)
        _put_int(memory, MODIFIER_VALUES + unity_id * layout["dense_entry_stride"]
                 + layout["dense_value_offset"], unity, size=4, signed=True)
    return _BoundedReader(memory)


def _labels(reader: _BoundedReader) -> list[str]:
    return [label for _, _, label in reader.reads]


def _capture(reader: _BoundedReader) -> dict:
    return unity_memory.capture(reader, MODULE_BASE, COUNTRY)


def test_dense_value_is_unclamped_and_validation_recomputes_inputs() -> None:
    reader = _make_reader(province=2000, unity=3456)
    record = _capture(reader)

    assert record["status"] == "known"
    assert record["raw"] == 5456
    assert record["raw_hex"] == (5456).to_bytes(4, "little", signed=True).hex()
    assert record["unit"] == "fraction"
    assert record["scale"] == 1000
    assert record["calculation"]["upper_clamp"] is False
    assert record["calculation"]["inputs"]["province_component_raw"] == 2000
    assert record["calculation"]["inputs"]["unity_modifier"]["base_raw"] == 3456
    assert unity_memory.validate_record(record) is True

    altered = deepcopy(record)
    altered["raw"] = 1000
    assert unity_memory.validate_record(altered) is False
    altered = deepcopy(record)
    altered["calculation"]["code_guard"]["checks"]["effective_unity_getter"] = False
    assert unity_memory.validate_record(altered) is False
    assert unity_memory.validate_record({"status": "known", "raw": 1000}) is False


@pytest.mark.parametrize(
    ("entries", "expected", "expected_read"),
    [
        ([(0xA8, 111), (0xA8, 222)], 2111, "religious_unity.unity.sparse[0]"),
        ([(0x99, 777)], 2000, "religious_unity.unity.sparse[0]"),
    ],
)
def test_sparse_lookup_uses_first_match_and_zero_for_absent(
    entries: list[tuple[int, int]], expected: int, expected_read: str,
) -> None:
    reader = _make_reader(dense=False, province=2000, sparse_entries=entries)
    record = _capture(reader)

    assert record["status"] == "known"
    assert record["raw"] == expected
    assert expected_read in _labels(reader)
    if entries[0][0] == 0xA8:
        assert "religious_unity.unity.sparse[1]" not in _labels(reader)


def test_special_rule_forces_1000_and_false_flag_skips_special_value_read() -> None:
    forced_reader = _make_reader(
        province=9000, unity=8000, special_flags=0x40, special_base=1234,
    )
    forced = _capture(forced_reader)
    assert forced["status"] == "known"
    assert forced["raw"] == 1000
    forced_labels = _labels(forced_reader)
    assert "religious_unity.special.dense_value" in forced_labels
    assert "religious_unity.province_component" not in forced_labels
    assert "religious_unity.unity.record" not in forced_labels

    false_reader = _make_reader(province=7, unity=8, special_flags=0, special_base=999)
    false_flag = _capture(false_reader)
    assert false_flag["status"] == "known"
    assert false_flag["raw"] == 15
    assert "religious_unity.special.type_flags" in _labels(false_reader)
    assert "religious_unity.special.dense_value" not in _labels(false_reader)


@pytest.mark.parametrize(
    ("province", "unity", "expected"),
    [
        (-50, -60, 0),
        (2**31 - 1, 1, 0),
        (2**31 - 1, -1, 2**31 - 2),
    ],
)
def test_signed_addition_wraps_then_applies_only_lower_clamp(
    province: int, unity: int, expected: int,
) -> None:
    record = _capture(_make_reader(province=province, unity=unity))
    assert record["status"] == "known"
    assert record["raw"] == expected


@pytest.mark.parametrize(
    ("kwargs", "reason", "absent_label"),
    [
        ({"special_processor": 1}, "RELIGIOUS_UNITY_SPECIAL_PROCESSOR_UNSUPPORTED",
         "religious_unity.province_component"),
        ({"unity_processor": 1}, "RELIGIOUS_UNITY_VALUE_PROCESSOR_UNSUPPORTED",
         "religious_unity.unity.dense_value"),
        ({"cache_state": 1}, "RELIGIOUS_UNITY_CACHE_CALCULATING",
         "religious_unity.modifier_header"),
    ],
)
def test_processor_and_calculating_paths_fail_before_later_inputs(
    kwargs: dict, reason: str, absent_label: str,
) -> None:
    reader = _make_reader(province=10, unity=20, **kwargs)
    record = _capture(reader)
    assert record["status"] == "unknown"
    assert record["reason"] == reason
    assert absent_label not in _labels(reader)


def test_changed_code_guard_stops_before_any_country_input() -> None:
    reader = _make_reader()
    first = _profile()["code_guards"][0]
    address = MODULE_BASE + int(first["rva"], 0)
    reader.memory[address] ^= 0xFF

    record = _capture(reader)
    assert record["status"] == "unknown"
    assert record["reason"] == "RELIGIOUS_UNITY_CODE_CHANGED"
    assert all(label.startswith("religious_unity.code.") for label in _labels(reader))


def test_invalid_profile_is_rejected_before_reader_use(tmp_path: Path, monkeypatch) -> None:
    reader = _make_reader()
    bad_profile = tmp_path / "invalid-profile.json"
    bad_profile.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(unity_memory, "PROFILE_FILE", bad_profile)
    record = _capture(reader)
    assert record["status"] == "unknown"
    assert record["reason"] == "RELIGIOUS_UNITY_PROFILE_MISMATCH"
    assert reader.reads == []


def _report_with_unity(session, unity_record: dict) -> dict:
    report = domestic_report(session)
    report["field_results"]["religious_unity"] = deepcopy(unity_record)
    report["values"]["religious_unity"] = unity_record["raw"]
    for snapshot_name in ("before", "after"):
        report[snapshot_name]["field_results"]["religious_unity"] = deepcopy(unity_record)
    return report


class _Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_n04_single_mixed_default_and_periodic_paths_keep_unity_metadata(tmp_path: Path) -> None:
    reader = _make_reader(province=2000, unity=3456)
    unity_record = _capture(reader)
    assert unity_record["status"] == "known"

    source, base, _, calls = domestic_source(
        tmp_path,
        report=lambda session: _report_with_unity(session, unity_record),
    )
    single_query = domestic_query(["religious_unity"])
    single = source.read(single_query, base.context())
    value = single["fields"]["religious_unity"]
    assert value["status"] == "known"
    assert value["value"] == 5456
    assert value["basis"] == "native_getter_equivalent_from_copied_inputs"
    assert value["upper_clamp"] is False
    assert value["value_origin"] == "derived_from_copied_native_inputs"
    assert value["components"] == {
        "province_component_raw": 2000,
        "modifier_raw": 3456,
        "special_rule_forced": False,
    }
    assert calls[-1][2] == ["religious_unity"]

    mixed = source.read(domestic_query(["stability", "religious_unity"]), base.context())
    assert mixed["fields"]["stability"]["status"] == "known"
    assert mixed["fields"]["religious_unity"]["status"] == "known"
    assert calls[-1][2] == ["stability", "religious_unity"]

    default = source.read(domestic_query(), base.context())
    assert list(default["fields"]) == LEGACY_FIELDS
    assert calls[-1][2] == LEGACY_FIELDS

    clock = _Clock()
    service = InformationService(source, tmp_path / "unity-service.sqlite3", clock=clock)
    queried = service.query("unity-query", queries=[single_query])
    assert queried["items"][0]["fields"]["religious_unity"]["status"] == "known"
    report = service.manage_report(
        "unity-report", "create",
        config={"name": "unity", "queries": [single_query], "detail": "full"},
    )["report"]
    subscription = service.manage_subscription(
        "unity-subscription", "create",
        config={
            "name": "unity periodic", "kind": "periodic", "report_id": report["id"],
            "enabled": True,
            "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
        },
    )["subscription"]
    clock.now += 1
    tick = service.tick()
    assert tick["results"]
    periodic = tick["results"][0]
    assert periodic["items"][0]["fields"]["religious_unity"]["status"] == "known"
    assert periodic["subscription_id"] == subscription["id"]

