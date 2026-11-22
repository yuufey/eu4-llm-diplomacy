"""Offline tests for the private province core/claim candidate reader."""
from __future__ import annotations

from typing import Callable

import pytest

from bridge.information import country_reference_memory as country_memory
from bridge.information import country_view_admission_memory as admission
from bridge.information import province_reference_memory as province_memory
from bridge.information import province_interest_memory as memory
from bridge.information import province_state_memory as state_memory


BASE = 0x140000000
WORLD = 0x5000000000
DATABASE = 0x5100000000
TABLE = 0x5200000000
CONTROLLERS = 0x5300000000
COUNTRY_BASE = 0x5400000000
RELATION_TABLE = 0x5500000000
RELATION_OWNER = 0x5600000000
RELATION_COUNTERS = 0x5700000000
CAPITAL = 0x5800000000
CAPITAL_BITS = 0x5900000000
ARRAY_BEGIN = 0x5A00000000
RECORDS = 0x5B00000000
DISCOVERY_BITS = 0x5C00000000
CORE_DATA = 0x5D00000000
CLAIM_NODES = 0x5E00000000

COUNTRY_COUNT = 12
FRA_SLOT = 3
ENG_SLOT = 5
SWE_SLOT = 6
DEN_SLOT = 7
PROVINCE_ID = 1
PROVINCE_COUNT = 20
COUNTRY_TAG_SLOTS = {"FRA": FRA_SLOT, "ENG": ENG_SLOT,
                     "SWE": SWE_SLOT, "DEN": DEN_SLOT}


def _fullref(tag: str, slot: int, generation: int = 0x1200) -> int:
    low = int.from_bytes(tag.encode("ascii") + b"\x00", "little")
    return ((generation & 0xFFFF) << 48) | (slot << 32) | low


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_at: int | None = None
        self.error_at: int | None = None

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: byte
                          for offset, byte in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if self.error_at == address:
            raise OSError("synthetic read failure")
        raw = bytes(self.data.get(address + offset, 0) for offset in range(size))
        if self.short_at == address:
            return raw[:-1]
        return raw


class MutatingReader:
    def __init__(self, image: MemoryImage, trigger: str,
                 mutation: Callable[[], None], occurrence: int = 2) -> None:
        self.image = image
        self.trigger = trigger
        self.mutation = mutation
        self.occurrence = occurrence
        self.seen = 0
        self.mutated = False

    def read(self, address: int, size: int, label: str) -> bytes:
        if label == self.trigger:
            self.seen += 1
            if self.seen == self.occurrence:
                self.mutation()
                self.mutated = True
        return self.image.read(address, size, label)


def _province_record() -> int:
    return RECORDS + PROVINCE_ID * province_memory.RECORD_STRIDE


def _put_core_vector(image: MemoryImage, refs: list[int], *,
                     begin: int = CORE_DATA) -> None:
    record = _province_record()
    if refs:
        image.put_u64(record + memory.CORE_BEGIN_OFFSET, begin)
        image.put_u64(record + memory.CORE_END_OFFSET, begin + 8 * len(refs))
        for index, fullref in enumerate(refs):
            image.put_u64(begin + index * 8, fullref)
    else:
        image.put_u64(record + memory.CORE_BEGIN_OFFSET, 0)
        image.put_u64(record + memory.CORE_END_OFFSET, 0)


def _put_claim_chain(image: MemoryImage, refs: list[int], *,
                     head: int = CLAIM_NODES) -> list[int]:
    record = _province_record()
    if not refs:
        image.put_u64(record + memory.CLAIMS_HEAD_OFFSET, 0)
        return []
    nodes = [head + index * 0x100 for index in range(len(refs))]
    image.put_u64(record + memory.CLAIMS_HEAD_OFFSET, nodes[0])
    for index, (node, fullref) in enumerate(zip(nodes, refs)):
        image.put_u64(node, fullref)
        image.put(node + 8, b"opaque!!")  # Deliberately unread payload.
        image.put_u64(node + memory.CLAIMS_NEXT_OFFSET,
                      nodes[index + 1] if index + 1 < len(nodes) else 0)
    return nodes


def make_image(*, discovered: bool = True, admitted: bool = True,
               role_verified: bool = True) -> MemoryImage:
    image = MemoryImage()
    refs = {tag: _fullref(tag, slot) for tag, slot in COUNTRY_TAG_SLOTS.items()}
    country_pointers = {tag: COUNTRY_BASE + slot * 0x1000
                        for tag, slot in COUNTRY_TAG_SLOTS.items()}

    image.put_u64(BASE + country_memory.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + country_memory.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DATABASE + country_memory.DATABASE_TABLE_COUNT_OFFSET,
                  COUNTRY_COUNT)
    for tag, slot in COUNTRY_TAG_SLOTS.items():
        pointer = country_pointers[tag]
        image.put_u64(TABLE + slot * 8, pointer)
        image.put_u64(pointer + country_memory.COUNTRY_FULLREF_OFFSET, refs[tag])

    image.put_u64(BASE + province_memory.PROVINCE_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + province_memory.ARRAY_BEGIN_OFFSET, ARRAY_BEGIN)
    image.put_u64(WORLD + province_memory.ARRAY_END_OFFSET,
                  ARRAY_BEGIN + PROVINCE_COUNT * 8)
    image.put_u64(WORLD + province_memory.RECORDS_POINTER_OFFSET, RECORDS)
    record = _province_record()
    image.put_i32(record + province_memory.RECORD_ID_OFFSET, PROVINCE_ID)
    image.put_u64(record + memory.CORE_BEGIN_OFFSET, 0)
    image.put_u64(record + memory.CORE_END_OFFSET, 0)
    image.put_u64(record + memory.CLAIMS_HEAD_OFFSET, 0)

    image.put_i32(WORLD + 0xA60, 1 if role_verified else 2)
    image.put_u64(WORLD + 0x1D48, CONTROLLERS)
    image.put_i32(CONTROLLERS + FRA_SLOT * 4, 0 if role_verified else 1)

    fra = country_pointers["FRA"]
    image.put_u64(fra + admission.RELATION_TABLE_OFFSET, RELATION_TABLE)
    row = RELATION_TABLE + FRA_SLOT * admission.RELATION_ROW_STRIDE
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, refs["FRA"])
    image.put_u64(RELATION_OWNER + admission.RELATION_OWNER_COUNTERS_OFFSET,
                  RELATION_COUNTERS)
    counter = (RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
               + FRA_SLOT * admission.RELATION_COUNTER_STRIDE)
    image.put_i32(counter, 1 if admitted else 0)
    for index, (_name, rva) in enumerate(admission.SPECIAL_TARGET_SLOT_RVAS):
        image.put_i32(BASE + rva, -10 - index)
    if not admitted:
        image.put_u64(fra + admission.COUNTRY_CAPITAL_OFFSET, CAPITAL)
        image.put(CAPITAL + admission.CAPITAL_VIEW_FLAGS_OFFSET, b"\x10")
        image.put_u64(CAPITAL + admission.CAPITAL_OBSERVER_BITSET_OFFSET,
                      CAPITAL_BITS)
        image.put_u32(CAPITAL_BITS + (FRA_SLOT >> 5) * 4, 0)

    image.put_u64(record + state_memory.DISCOVERY_BITSET_POINTER_OFFSET,
                  DISCOVERY_BITS)
    word = 1 << FRA_SLOT if discovered else 0
    image.put_u32(DISCOVERY_BITS + (FRA_SLOT >> 5) * 4, word)
    return image


def _field(result: dict, field: str) -> dict:
    return result["targets"][0]["fields"][field]


def _labels(image: MemoryImage, prefix: str) -> list[str]:
    return [label for _, _, label in image.reads if label.startswith(prefix)]


def test_scoped_memberships_follow_the_selected_observers_discovery_and_fullref():
    image = make_image(discovered=False)
    ref = _fullref('TUR', ENG_SLOT)
    turkey = COUNTRY_BASE + ENG_SLOT * 0x1000
    image.put_u64(turkey + country_memory.COUNTRY_FULLREF_OFFSET, ref)
    image.put_u64(turkey + admission.RELATION_TABLE_OFFSET, RELATION_TABLE)
    row = RELATION_TABLE + ENG_SLOT * admission.RELATION_ROW_STRIDE
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, ref)
    image.put_i32(RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
                  + ENG_SLOT * admission.RELATION_COUNTER_STRIDE, 1)
    image.put_u32(DISCOVERY_BITS, 1 << ENG_SLOT)
    _put_core_vector(image, [ref])
    _put_claim_chain(image, [_fullref('SWE', SWE_SLOT)])
    scoped = memory.read_two_pass(image, BASE, PROVINCE_ID, observer='TUR', observer_scoped=True)
    assert _field(scoped, 'G01.cores')['value'] == ['TUR']
    assert _field(scoped, 'G01.claims')['value'] == ['SWE']
    french = memory.read_two_pass(image, BASE, PROVINCE_ID, observer='FRA', observer_scoped=True)
    assert _field(french, 'G01.cores')['status'] == 'unknown'


def test_reads_canonical_core_and_claim_tags_without_reading_node_payloads():
    image = make_image()
    _put_core_vector(image, [_fullref("FRA", FRA_SLOT), _fullref("ENG", ENG_SLOT)])
    nodes = _put_claim_chain(image, [_fullref("ENG", ENG_SLOT), _fullref("SWE", SWE_SLOT)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert result["schema"] == memory.SCHEMA
    assert result["status"] == "observed"
    assert result["consistency"]["status"] == "stable"
    assert _field(result, "G01.cores")["status"] == "known"
    assert _field(result, "G01.cores")["value"] == ["FRA", "ENG"]
    assert _field(result, "G01.claims")["status"] == "known"
    assert _field(result, "G01.claims")["value"] == ["ENG", "SWE"]
    assert _field(result, "G01.permanent_claims")["status"] == "unknown"
    assert _field(result, "G01.permanent_claims")["reason"] == (
        "PERMANENT_CLAIM_LAYOUT_NOT_CLOSED")
    assert all(not key.startswith("G02.") for key in result["targets"][0]["fields"])
    for phase in ("pass1", "pass2"):
        raw = result["pass_evidence"][phase]["fields_raw"]
        assert set(raw) == set(memory.FIELDS)
        assert all(not key.startswith("G02.") for key in raw)
    for node in nodes:
        assert not any(address >= node + 8 and address < node + 16
                       for address, _, _ in image.reads)
    assert _field(result, "G01.cores")["basis"] == (
        "province_core_fullref_vector_after_positive_discovery")


@pytest.mark.parametrize("field", ["G01.cores", "G01.claims"])
def test_null_empty_containers_are_known_empty_lists(field: str):
    image = make_image()
    selected = (field,)
    result = memory.read_two_pass(image, BASE, PROVINCE_ID, fields=selected)
    assert _field(result, field) == {
        "status": "known",
        "value": [],
        "basis": ("province_core_fullref_vector_after_positive_discovery"
                  if field == "G01.cores"
                  else "province_claim_fullref_chain_after_positive_discovery"),
        "raw_inputs": _field(result, field)["raw_inputs"],
    }
    assert _field(result, field)["raw_inputs"]["count"] == 0
    assert not _labels(image, "province_interest.cores.member")
    assert not _labels(image, "province_interest.claims.node")


def test_aligned_nonzero_equal_core_vector_is_known_empty():
    image = make_image()
    record = _province_record()
    image.put_u64(record + memory.CORE_BEGIN_OFFSET, CORE_DATA)
    image.put_u64(record + memory.CORE_END_OFFSET, CORE_DATA)
    _put_claim_chain(image, [_fullref("ENG", ENG_SLOT)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result, "G01.cores")["status"] == "known"
    assert _field(result, "G01.cores")["value"] == []
    assert _field(result, "G01.claims")["status"] == "known"
    assert _field(result, "G01.claims")["value"] == ["ENG"]
    assert not _labels(image, "province_interest.cores.member")


@pytest.mark.parametrize("pointer", [1, CORE_DATA + 1])
def test_equal_invalid_core_pointers_are_unknown_without_withdrawing_claims(
        pointer: int):
    image = make_image()
    record = _province_record()
    image.put_u64(record + memory.CORE_BEGIN_OFFSET, pointer)
    image.put_u64(record + memory.CORE_END_OFFSET, pointer)
    _put_claim_chain(image, [_fullref("ENG", ENG_SLOT)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result, "G01.cores")["status"] == "unknown"
    assert _field(result, "G01.cores")["reason"] == "CORE_VECTOR_POINTERS_INVALID"
    assert _field(result, "G01.claims")["status"] == "known"
    assert _field(result, "G01.claims")["value"] == ["ENG"]
    assert not _labels(image, "province_interest.cores.member")


def test_unresolved_claim_and_permanent_fields_do_not_read_or_withdraw_cores():
    image = make_image()
    _put_core_vector(image, [_fullref("FRA", FRA_SLOT)])
    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result, "G01.cores")["status"] == "known"
    assert _field(result, "G01.cores")["value"] == ["FRA"]
    assert _field(result, "G01.claims")["status"] == "known"
    assert _field(result, "G01.claims")["value"] == []
    assert _field(result, "G01.permanent_claims")["status"] == "unknown"
    assert not _labels(image, "province_interest.permanent")


def test_hidden_or_admission_denied_short_circuits_all_interest_reads():
    for image in (make_image(discovered=False), make_image(admitted=False),
                  make_image(role_verified=False)):
        _put_core_vector(image, [_fullref("FRA", FRA_SLOT)])
        _put_claim_chain(image, [_fullref("ENG", ENG_SLOT)])
        result = memory.read_two_pass(image, BASE, PROVINCE_ID)
        assert all(_field(result, field)["status"] == "unknown"
                   for field in memory.FIELDS)
        assert not _labels(image, "province_interest.")


@pytest.mark.parametrize("begin,end,reason", [
    (CORE_DATA + 1, CORE_DATA + 9, "CORE_VECTOR_POINTERS_INVALID"),
    (CORE_DATA + 8, CORE_DATA, "CORE_VECTOR_POINTERS_INVALID"),
    # With aligned begin/end pointers, the byte length is necessarily divisible
    # by eight. An unaligned endpoint is therefore rejected as a pointer error.
    (CORE_DATA, CORE_DATA + 7, "CORE_VECTOR_POINTERS_INVALID"),
    (0x7000, 0x7008, "CORE_VECTOR_POINTERS_INVALID"),
])
def test_malformed_core_vector_header_is_unknown_without_member_reads(
        begin: int, end: int, reason: str):
    image = make_image()
    record = _province_record()
    image.put_u64(record + memory.CORE_BEGIN_OFFSET, begin)
    image.put_u64(record + memory.CORE_END_OFFSET, end)
    _put_claim_chain(image, [_fullref("ENG", ENG_SLOT)])
    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result, "G01.cores")["status"] == "unknown"
    assert _field(result, "G01.cores")["reason"] == reason
    assert _field(result, "G01.claims")["status"] == "known"
    assert _field(result, "G01.claims")["value"] == ["ENG"]
    assert not _labels(image, "province_interest.cores.member")


def test_oversized_core_vector_is_not_truncated_or_partially_read():
    image = make_image()
    record = _province_record()
    image.put_u64(record + memory.CORE_BEGIN_OFFSET, CORE_DATA)
    image.put_u64(record + memory.CORE_END_OFFSET, CORE_DATA + (memory.MAX_MEMBERS + 1) * 8)
    result = memory.read_two_pass(image, BASE, PROVINCE_ID, fields=("G01.cores",))
    field = _field(result, "G01.cores")
    assert field["status"] == "unknown"
    assert field["reason"] == "CORE_VECTOR_COUNT_OUT_OF_RANGE"
    assert field["raw_inputs"]["count"] == memory.MAX_MEMBERS + 1
    assert "value" not in field
    assert not _labels(image, "province_interest.cores.member")


@pytest.mark.parametrize("bad_ref,reason", [
    (_fullref("ENG", COUNTRY_COUNT + 1), "CORE_MEMBER_FULLREF_INVALID"),
    (_fullref("ENG", ENG_SLOT, generation=0x1207), "CORE_MEMBER_FULLREF_INVALID"),
    (_fullref("ENG", ENG_SLOT, generation=0x0000), "CORE_MEMBER_FULLREF_INVALID"),
])
def test_noncanonical_core_fullref_rejects_entire_list(
        bad_ref: int, reason: str):
    image = make_image()
    _put_core_vector(image, [_fullref("FRA", FRA_SLOT), bad_ref])
    result = memory.read_two_pass(image, BASE, PROVINCE_ID, fields=("G01.cores",))
    field = _field(result, "G01.cores")
    assert field["status"] == "unknown"
    assert field["reason"] == reason
    assert "value" not in field
    assert len(field["raw_inputs"]["members"]) == 2


def test_duplicate_core_fullref_rejects_without_a_partial_value():
    image = make_image()
    ref = _fullref("ENG", ENG_SLOT)
    _put_core_vector(image, [ref, ref])
    result = memory.read_two_pass(image, BASE, PROVINCE_ID, fields=("G01.cores",))
    field = _field(result, "G01.cores")
    assert field["status"] == "unknown"
    assert field["reason"] == "DUPLICATE_CORE_FULLREF"
    assert "value" not in field


def test_claim_cycle_and_duplicate_tag_are_field_local_failures():
    image = make_image()
    _put_core_vector(image, [_fullref("FRA", FRA_SLOT)])
    nodes = _put_claim_chain(image, [_fullref("ENG", ENG_SLOT)])
    image.put_u64(nodes[0] + memory.CLAIMS_NEXT_OFFSET, nodes[0])
    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result, "G01.cores")["status"] == "known"
    assert _field(result, "G01.claims")["status"] == "unknown"
    assert _field(result, "G01.claims")["reason"] == "CLAIM_NODE_CYCLE"

    image = make_image()
    _put_core_vector(image, [_fullref("FRA", FRA_SLOT)])
    _put_claim_chain(image, [_fullref("ENG", ENG_SLOT), _fullref("ENG", ENG_SLOT)])
    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result, "G01.cores")["status"] == "known"
    assert _field(result, "G01.claims")["status"] == "unknown"
    assert _field(result, "G01.claims")["reason"] == "DUPLICATE_CLAIM_FULLREF"


def test_claim_next_pointer_cannot_reinterpret_opaque_node_payload():
    image = make_image()
    node = _put_claim_chain(image, [_fullref("ENG", ENG_SLOT)])[0]
    image.put_u64(node + memory.CLAIMS_NEXT_OFFSET, node + 8)

    result = memory.read_two_pass(image, BASE, PROVINCE_ID,
                                  fields=("G01.claims",))
    field = _field(result, "G01.claims")
    assert field["status"] == "unknown"
    assert field["reason"] == "CLAIM_NODE_RANGES_OVERLAP"
    assert not any(address == node + 8 for address, _, _ in image.reads)


def test_claim_link_drift_with_same_tags_retracts_claims_only():
    image = make_image()
    _put_core_vector(image, [_fullref("FRA", FRA_SLOT)])
    first_nodes = _put_claim_chain(image, [_fullref("ENG", ENG_SLOT),
                                          _fullref("SWE", SWE_SLOT)])
    alternate_nodes = _put_claim_chain(image, [_fullref("ENG", ENG_SLOT),
                                               _fullref("SWE", SWE_SLOT)],
                                       head=CLAIM_NODES + 0x10000)
    # The helper writes the province head each time; restore the original head
    # so the second-pass reader observes a real change caused by MutatingReader.
    image.put_u64(_province_record() + memory.CLAIMS_HEAD_OFFSET, first_nodes[0])
    reader = MutatingReader(
        image, "province_interest.claims.head_pointer",
        lambda: image.put_u64(_province_record() + memory.CLAIMS_HEAD_OFFSET,
                              alternate_nodes[0]))
    result = memory.read_two_pass(reader, BASE, PROVINCE_ID)

    assert reader.mutated
    assert result["consistency"]["status"] == "stable"
    assert _field(result, "G01.cores")["status"] == "known"
    assert _field(result, "G01.claims")["status"] == "unknown"
    assert _field(result, "G01.claims")["reason"] == "FIELD_RAW_DATA_CHANGED"
    assert _field(result, "G01.permanent_claims")["reason"] == (
        "PERMANENT_CLAIM_LAYOUT_NOT_CLOSED")
    assert first_nodes != alternate_nodes


def test_core_member_drift_retracts_cores_only():
    image = make_image()
    refs = [_fullref("FRA", FRA_SLOT), _fullref("ENG", ENG_SLOT)]
    _put_core_vector(image, refs)
    _put_claim_chain(image, [_fullref("SWE", SWE_SLOT)])

    def reorder() -> None:
        image.put_u64(CORE_DATA, refs[1])
        image.put_u64(CORE_DATA + 8, refs[0])

    reader = MutatingReader(
        image, "province_interest.cores.member[0].fullref", reorder)
    result = memory.read_two_pass(reader, BASE, PROVINCE_ID)
    assert reader.mutated
    assert result["consistency"]["status"] == "stable"
    assert _field(result, "G01.cores")["status"] == "unknown"
    assert _field(result, "G01.cores")["reason"] == "FIELD_RAW_DATA_CHANGED"
    assert _field(result, "G01.claims")["status"] == "known"
    assert _field(result, "G01.claims")["value"] == ["SWE"]


def test_invalid_field_scope_does_not_read_memory():
    image = MemoryImage()
    result = memory.read_two_pass(image, BASE, PROVINCE_ID,
                                  fields=("G01.cores", "G01.cores"))
    assert result["status"] == "unknown"
    assert result["errors"] == [{"code": "field_scope_invalid"}]
    assert all(_field(result, field)["status"] == "unknown" for field in memory.FIELDS)
    assert image.reads == []
