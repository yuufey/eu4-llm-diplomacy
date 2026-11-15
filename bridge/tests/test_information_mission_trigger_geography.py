"""Synthetic coverage for the reused loaded-area name map and vector reader."""
from __future__ import annotations

import pytest

from bridge.information import mission_condition_memory as condition_memory
from bridge.information import mission_trigger_geography as geography
from bridge.tests.test_information_mission_condition_memory import (
    _fnv1,
    _write_map_header,
)
from bridge.tests.test_information_mission_memory import FakeReader, write_string32


MODULE = 0x140000000
MANAGER = 0x700000
MAP = MANAGER + geography.AREA_MANAGER_NAME_MAP_OFFSET
SENTINEL = 0x710000
BUCKETS = 0x720000
NODE_BASE = 0x740000
VECTOR_BASE = 0x780000


class RecordingReader(FakeReader):
    def __init__(self, module_base: int = MODULE):
        super().__init__(module_base)
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        return super().read(address, size, label)


def _install_area_map(
    reader: RecordingReader,
    entries: list[tuple[str, int]],
) -> list[int]:
    reader.qword_put(reader.module_base + geography.AREA_MANAGER_SINGLETON_RVA, MANAGER)
    _write_map_header(reader, MAP, SENTINEL, len(entries), BUCKETS)
    grouped: dict[int, list[tuple[str, int, int]]] = {}
    nodes: list[int] = []
    for index, (name, area) in enumerate(entries):
        node = NODE_BASE + index * 0x3000
        nodes.append(node)
        bucket = _fnv1(name) & 7
        grouped.setdefault(bucket, []).append((name, area, node))
    for bucket, rows in grouped.items():
        reader.qword_put(BUCKETS + bucket * 16, rows[0][2])
        reader.qword_put(BUCKETS + bucket * 16 + 8, rows[-1][2])
        for index, (name, area, node) in enumerate(rows):
            previous = rows[index - 1][2] if index else SENTINEL
            following = rows[index + 1][2] if index + 1 < len(rows) else SENTINEL
            reader.qword_put(node, following)
            reader.qword_put(node + 8, previous)
            write_string32(reader, node, name, heap=len(name) >= 16)
            reader.qword_put(node + 0x30, area)
    return nodes


def _set_area_vector(reader: RecordingReader, area: int, ids: list[int]) -> tuple[int, int]:
    begin = VECTOR_BASE + (area & 0xFF000) * 2
    end = begin + len(ids) * 4
    reader.qword_put(area + geography.AREA_PROVINCE_VECTOR_OFFSET, begin)
    reader.qword_put(area + geography.AREA_PROVINCE_VECTOR_OFFSET + 8, end)
    for index, province_id in enumerate(ids):
        reader.dword_put(begin + index * 4, province_id, signed=True)
    return begin, end


def _base(entries: list[tuple[str, int]], vectors: dict[int, list[int] | None]):
    reader = RecordingReader()
    nodes = _install_area_map(reader, entries)
    for area, ids in vectors.items():
        if ids is None:
            reader.qword_put(area + geography.AREA_PROVINCE_VECTOR_OFFSET, 0)
            reader.qword_put(area + geography.AREA_PROVINCE_VECTOR_OFFSET + 8, 0)
        else:
            _set_area_vector(reader, area, ids)
    return reader, nodes


def _call(reader: RecordingReader, name: str = "iberia"):
    return geography.read_geographic_state(reader, reader.module_base, name)


def test_found_area_uses_shared_name_map_and_preserves_vector_order():
    area = 0x760000
    reader, _nodes = _base([("iberia", area)], {area: [10, 2, 407]})

    result = _call(reader)

    assert result == {
        "status": "known",
        "found": True,
        "province_ids": [10, 2, 407],
        "source": geography.SOURCE,
    }
    assert any("area_name_map.name[iberia]" in label for _address, _size, label in reader.reads)
    assert any(address == area + 0x88 and size == 16 for address, size, _label in reader.reads)


def test_only_exact_canonical_missing_is_known_absence():
    reader, _nodes = _base([], {})

    result = _call(reader, "not_loaded")

    assert result["status"] == "known"
    assert result["found"] is False
    assert result["province_ids"] == []


def test_found_area_with_null_or_equal_empty_vector_is_known_empty():
    area_null = 0x761000
    area_equal = 0x762000
    reader, _nodes = _base([("iberia", area_null), ("brittany", area_equal)],
                           {area_null: None})
    equal_pointer = VECTOR_BASE + 0x2000
    reader.qword_put(area_equal + 0x88, equal_pointer)
    reader.qword_put(area_equal + 0x90, equal_pointer)

    null_result = _call(reader, "iberia")
    equal_result = _call(reader, "brittany")

    assert null_result["status"] == equal_result["status"] == "known"
    assert null_result["found"] is equal_result["found"] is True
    assert null_result["province_ids"] == equal_result["province_ids"] == []


def test_invalid_name_and_manager_pointer_remain_unknown():
    reader, _nodes = _base([], {})

    non_ascii = _call(reader, "ibéria")
    invalid_manager_reader = RecordingReader()
    invalid_manager_reader.qword_put(
        invalid_manager_reader.module_base + geography.AREA_MANAGER_SINGLETON_RVA, 0
    )
    invalid_manager = _call(invalid_manager_reader)

    assert non_ascii["status"] == "unknown"
    assert non_ascii["reason"] == "geographic_name_invalid"
    assert invalid_manager["status"] == "unknown"
    assert invalid_manager["found"] is None


def test_invalid_area_map_and_null_mapped_value_are_unknown():
    bad_map_reader = RecordingReader()
    bad_map_reader.qword_put(bad_map_reader.module_base + geography.AREA_MANAGER_SINGLETON_RVA,
                             MANAGER)
    # Keep the manager pointer valid but leave the map header malformed.
    bad_map = _call(bad_map_reader)

    null_area_reader = RecordingReader()
    nodes = _install_area_map(null_area_reader, [("iberia", 0)])
    null_area = _call(null_area_reader)

    assert bad_map["status"] == "unknown"
    assert null_area["status"] == "unknown"
    assert null_area["found"] is None
    assert nodes


def test_duplicate_map_key_and_bad_chain_are_unknown():
    area_one, area_two = 0x763000, 0x764000
    duplicate_reader, _nodes = _base([("iberia", area_one), ("iberia", area_two)], {})
    duplicate = _call(duplicate_reader)

    broken_reader, nodes = _base([("iberia", area_one)], {area_one: [4]})
    broken_reader.qword_put(nodes[0] + 8, 0)
    broken = _call(broken_reader)

    assert duplicate["status"] == "unknown"
    assert "duplicate" in duplicate["reason"]
    assert broken["status"] == "unknown"
    assert broken["found"] is None


def test_vector_pointer_range_alignment_and_count_are_bounded():
    area = 0x765000
    reader, _nodes = _base([("iberia", area)], {})
    # Half-null pair.
    reader.qword_put(area + 0x88, 0)
    reader.qword_put(area + 0x90, VECTOR_BASE)
    half_null = _call(reader)

    # A non-null, 4-aligned but out-of-user-range begin pointer.
    reader.qword_put(area + 0x88, condition_memory.MAX_USER_ADDRESS + 4)
    reader.qword_put(area + 0x90, condition_memory.MAX_USER_ADDRESS + 8)
    invalid_range = _call(reader)

    # A valid-looking range that exceeds the 64 province cap.
    reader.qword_put(area + 0x88, VECTOR_BASE)
    reader.qword_put(area + 0x90, VECTOR_BASE + 65 * 4)
    over_count = _call(reader)

    # Endpoints must stay four-byte aligned, and the end must not precede begin.
    reader.qword_put(area + 0x88, VECTOR_BASE + 1)
    reader.qword_put(area + 0x90, VECTOR_BASE + 5)
    misaligned = _call(reader)
    reader.qword_put(area + 0x88, VECTOR_BASE + 8)
    reader.qword_put(area + 0x90, VECTOR_BASE + 4)
    reversed_range = _call(reader)

    assert (half_null["status"] == invalid_range["status"] == over_count["status"]
            == misaligned["status"] == reversed_range["status"] == "unknown")


def test_malformed_and_duplicate_province_ids_are_unknown_not_clipped():
    cases = ([1, 0], [-1], [65536], [3, 3])
    for index, ids in enumerate(cases):
        area = 0x766000 + index * 0x1000
        reader, _nodes = _base([("iberia", area)], {area: ids})
        result = _call(reader)
        assert result["status"] == "unknown"
        assert result["found"] is None
        assert result["province_ids"] == []


def test_reader_exception_is_unknown_never_verified_absence():
    area = 0x76A000

    class FailingReader(RecordingReader):
        def read(self, address: int, size: int, label: str) -> bytes:
            if label == "mission_condition.area_name_map.header":
                raise ValueError("simulated_read_failure")
            return super().read(address, size, label)

    reader = FailingReader()
    _install_area_map(reader, [("iberia", area)])
    result = _call(reader)

    assert result["status"] == "unknown"
    assert result["found"] is None
    assert "simulated_read_failure" in result["reason"]


def test_name_length_limit_is_enforced_without_map_walk():
    reader, _nodes = _base([], {})
    result = _call(reader, "a" * 257)

    assert result["status"] == "unknown"
    assert result["reason"] == "geographic_name_invalid"
    assert not reader.reads
