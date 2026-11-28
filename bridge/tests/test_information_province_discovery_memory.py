"""Offline contract tests for positive discovery membership reads."""
from __future__ import annotations

from typing import Callable

import pytest

from bridge.information import country_reference_memory as country_memory
from bridge.information import province_reference_memory as province_memory
from bridge.information import province_state_memory as state_memory
from bridge.information import province_discovery_memory as memory
from bridge.tests.test_information_province_state_memory import (
    BASES, DISCOVERY_BITS, FRA_SLOT, RECORDS, WORLD, _fullref, make_image,
)


def make_membership_image(values: tuple[bool, ...], *, base: int = BASES[0]):
    image = make_image(base=base)
    count = len(values) + 1
    image.put_u64(WORLD + province_memory.ARRAY_BEGIN_OFFSET, 0x5A00000000)
    image.put_u64(WORLD + province_memory.ARRAY_END_OFFSET,
                  0x5A00000000 + count * 8)
    image.put_u64(WORLD + province_memory.RECORDS_POINTER_OFFSET, RECORDS)
    image.put_i32(WORLD + 0x1DD0, 56_556_984)
    image.put(WORLD + 0x1E66, b"\x00")
    image.put(WORLD + 0x1E6F, b"\x00")
    image.put_u64(WORLD + 0x1E60, _fullref("ENG", 5))
    for province_id, discovered in enumerate(values, start=1):
        record = RECORDS + province_id * province_memory.RECORD_STRIDE
        image.put_i32(record + province_memory.RECORD_ID_OFFSET, province_id)
        bitset = DISCOVERY_BITS + province_id * 0x100
        image.put_u64(record + state_memory.DISCOVERY_BITSET_POINTER_OFFSET, bitset)
        image.put_u32(bitset + (FRA_SLOT >> 5) * 4,
                      (1 << FRA_SLOT) if discovered else 0)
    return image


class ChangeOnWordRead:
    def __init__(self, image, mutation: Callable[[], None], occurrence: int = 2):
        self.image = image
        self.mutation = mutation
        self.occurrence = occurrence
        self.seen = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == "province_state.discovery.word_u32":
            self.seen += 1
            if self.seen == self.occurrence:
                self.mutation()
        return self.image.read(address, size, label)


@pytest.mark.parametrize(
    "values,expected",
    [((True, False, True), [1, 3]), ((False, False, False), [])],
)
def test_stable_candidates_return_only_positive_ids_and_known_empty(values, expected):
    image = make_membership_image(values)
    result = memory.read_two_pass(image, BASES[0])

    assert result["status"] == "known"
    assert result["value"] == expected
    assert result["complete"] is False
    assert result["domain_complete"] is False
    assert result["scope"]["province_zero_semantics"] == "unknown"
    assert len(result["passes"]) == 2
    assert result["consistency"] == {"status": "stable", "changed_components": []}
    assert all(row["status"] == "known"
               for pass_row in result["passes"] for row in pass_row["candidates"])
    assert result["budget"]["calls"] == len(image.reads)
    assert result["budget"]["max_single_read"] <= 1024
    assert result["budget"]["calls"] <= 40_000
    assert result["budget"]["bytes_requested"] <= 512 * 1024
    assert sum(label == "country_reference.database_global"
               for _address, _size, label in image.reads) == 2
    assert not any(label.startswith("province_state.G02_")
                   for _address, _size, label in image.reads)


def test_human_count_does_not_deny_bound_observer_province_discovery():
    image = make_membership_image((True, False))
    image.put_i32(WORLD + 0xA60, 2)
    result = memory.read_two_pass(image, BASES[0])

    assert result["status"] == "known"
    assert result["value"] == [1]
    assert all(not row["admission"]["observer_nonplayer_role"]["verified"] for row in result["passes"])


def test_id_echo_mismatch_fails_closed_without_reading_other_province_fields():
    image = make_membership_image((True, False))
    record = RECORDS + 2 * province_memory.RECORD_STRIDE
    image.put_i32(record + province_memory.RECORD_ID_OFFSET, 9)
    result = memory.read_two_pass(image, BASES[0])

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"] == "PROVINCE_ID_ECHO_MISMATCH:2"
    assert not any(label.startswith("province_state.G02_")
                   for _address, _size, label in image.reads)


def test_invalid_bitmap_pointer_is_unknown_and_never_becomes_false_membership():
    image = make_membership_image((False,))
    record = RECORDS + province_memory.RECORD_STRIDE
    image.put_u64(record + state_memory.DISCOVERY_BITSET_POINTER_OFFSET, 0x7000)
    result = memory.read_two_pass(image, BASES[0])

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"] == "CANDIDATE_DISCOVERY_UNKNOWN"
    assert result["passes"][0]["candidates"] == [
        {"province_id": 1, "status": "unknown",
         "reason": "PROVINCE_DISCOVERY_POINTER_INVALID"}
    ]


def test_candidate_value_drift_between_passes_withdraws_the_whole_list():
    image = make_membership_image((True,))
    reader = ChangeOnWordRead(
        image,
        lambda: image.put_u32(DISCOVERY_BITS + 0x100 + (FRA_SLOT >> 5) * 4, 0),
    )
    result = memory.read_two_pass(reader, BASES[0])

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"] == "TWO_PASS_EVIDENCE_CHANGED"
    assert "candidates" in result["consistency"]["changed_components"]


def test_header_drift_within_one_pass_withdraws_the_whole_list():
    image = make_membership_image((True,))

    class ChangeHeaderAfterFirstWord:
        def __init__(self):
            self.seen = 0

        def read(self, address, size, label):
            raw = image.read(address, size, label)
            if label == "province_state.discovery.word_u32":
                self.seen += 1
                if self.seen == 1:
                    image.put_u64(WORLD + province_memory.ARRAY_END_OFFSET,
                                  0x5A00000000 + 3 * 8)
            return raw

    result = memory.read_two_pass(ChangeHeaderAfterFirstWord(), BASES[0])
    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"] == "HEADER_CHANGED_DURING_PASS"


def test_budget_preflight_stops_before_scanning_large_candidate_domain():
    image = make_membership_image((True,))
    image.put_u64(WORLD + province_memory.ARRAY_END_OFFSET,
                  0x5A00000000 + 6000 * 8)
    result = memory.read_two_pass(image, BASES[0])

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"] == "CANDIDATE_SCAN_EXCEEDS_CALL_BUDGET"
    assert not any(label.startswith("province_discovery.id[")
                   or label.startswith("province_state.discovery.")
                   for _address, _size, label in image.reads)
    assert result["budget"]["calls"] <= memory.MAX_READ_CALLS
    assert result["budget"]["bytes_requested"] <= memory.MAX_TOTAL_READ_BYTES


def test_module_and_observer_validation_are_read_free():
    image = make_membership_image((True,))
    assert memory.read_two_pass(image, BASES[0], observer="ENG")["reason"] == "OBSERVER_SCOPE_INVALID"
    assert memory.read_two_pass(image, BASES[0], observer=True)["reason"] == "OBSERVER_SCOPE_INVALID"
    assert memory.read_two_pass(image, 0x7000)["reason"] == "MODULE_BASE_INVALID"
    assert image.reads == []

