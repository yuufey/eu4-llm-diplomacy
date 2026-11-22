"""Offline tests for discovered-province owner/controller projections."""
from __future__ import annotations

from typing import Callable

import pytest

from bridge.information import country_reference_memory as country_memory
from bridge.information import country_view_admission_memory as admission
from bridge.information import foreign_country_memory as shared
from bridge.information import province_reference_memory as province_memory
from bridge.information import province_state_memory as memory


BASES = (0x140000000, 0x180000000)
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
    assert len(tag) == 3 and tag.isascii()
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
    """Apply a deterministic change just before the selected RPM read."""
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


def make_image(base: int = BASES[0], *, discovered: bool = True,
               admitted: bool = True, role_verified: bool = True,
               owner_ref: int | None = None, controller_ref: int | None = None) -> MemoryImage:
    image = MemoryImage()
    refs = {tag: _fullref(tag, slot) for tag, slot in COUNTRY_TAG_SLOTS.items()}
    country_pointers = {tag: COUNTRY_BASE + slot * 0x1000
                        for tag, slot in COUNTRY_TAG_SLOTS.items()}

    # Country manager and requested country records.
    image.put_u64(base + country_memory.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + country_memory.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DATABASE + country_memory.DATABASE_TABLE_COUNT_OFFSET, COUNTRY_COUNT)
    for tag, slot in COUNTRY_TAG_SLOTS.items():
        pointer = country_pointers[tag]
        image.put_u64(TABLE + slot * 8, pointer)
        image.put_u64(pointer + country_memory.COUNTRY_FULLREF_OFFSET, refs[tag])

    # Province world and indexed record array.
    image.put_u64(base + province_memory.PROVINCE_GLOBAL_RVA, WORLD)
    image.put_u64(WORLD + province_memory.ARRAY_BEGIN_OFFSET, ARRAY_BEGIN)
    image.put_u64(WORLD + province_memory.ARRAY_END_OFFSET,
                  ARRAY_BEGIN + PROVINCE_COUNT * 8)
    image.put_u64(WORLD + province_memory.RECORDS_POINTER_OFFSET, RECORDS)
    record = RECORDS + PROVINCE_ID * province_memory.RECORD_STRIDE
    image.put_i32(record + province_memory.RECORD_ID_OFFSET, PROVINCE_ID)

    # Admission's logical observer role is FRA Human1 / controller type0.
    image.put_i32(WORLD + 0xA60, 1 if role_verified else 2)
    image.put_u64(WORLD + 0x1D48, CONTROLLERS)
    image.put_i32(CONTROLLERS + FRA_SLOT * 4, 0 if role_verified else 1)

    # Known FRA self-admission through its relation-counter row.
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
        image.put_i32(base + rva, -10 - index)

    # If the relation-counter gate is false, use a known false capital fallback.
    if not admitted:
        image.put_u64(fra + admission.COUNTRY_CAPITAL_OFFSET, CAPITAL)
        image.put(CAPITAL + admission.CAPITAL_VIEW_FLAGS_OFFSET, b"\x10")
        image.put_u64(CAPITAL + admission.CAPITAL_OBSERVER_BITSET_OFFSET, CAPITAL_BITS)
        image.put_u32(CAPITAL_BITS + (FRA_SLOT >> 5) * 4, 0)

    # Discovery is the FRA slot's bit in the province's bitset.
    image.put_u64(record + memory.DISCOVERY_BITSET_POINTER_OFFSET, DISCOVERY_BITS)
    word = 1 << FRA_SLOT if discovered else 0
    image.put_u32(DISCOVERY_BITS + (FRA_SLOT >> 5) * 4, word)
    image.put_u64(record + memory.OWNER_FULLREF_OFFSET,
                  refs["ENG"] if owner_ref is None else owner_ref)
    image.put_u64(record + memory.CONTROLLER_FULLREF_OFFSET,
                  refs["SWE"] if controller_ref is None else controller_ref)
    return image


def _field(result: dict, name: str) -> dict:
    return result["targets"][0]["fields"][name]


def _field_address(field: str) -> int:
    offset = (memory.OWNER_FULLREF_OFFSET if field == "G02.owner"
              else memory.CONTROLLER_FULLREF_OFFSET)
    return RECORDS + PROVINCE_ID * province_memory.RECORD_STRIDE + offset


@pytest.mark.parametrize("base", BASES)
def test_two_pass_projects_only_canonically_bound_tags_when_discovery_bit_is_set(base: int):
    image = make_image(base=base)
    result = memory.read_two_pass(image, base, PROVINCE_ID)

    assert result["status"] == "observed"
    assert result["consistency"] == {"status": "stable", "shared_mismatch_paths": []}
    assert _field(result, "G02.owner")["status"] == "known"
    assert _field(result, "G02.owner")["value"] == "ENG"
    assert _field(result, "G02.controller")["status"] == "known"
    assert _field(result, "G02.controller")["value"] == "SWE"
    assert _field(result, "G02.owner")["basis"] == (
        "province_discovery_bit_one_canonical_country_fullref")
    assert result["observer"]["fullref"] == hex(_fullref("FRA", FRA_SLOT))
    assert result["targets"][0]["bindings_by_pass"]["pass1"]["province"]["province_id"] == 1
    assert result["targets"][0]["discovery_by_pass"]["pass1"]["value"] is True
    assert result["visibility"]["status"] == "unknown"
    assert result["complete"] is False
    assert result["public_export_ready"] is False
    assert result["budget"]["calls"] == len(image.reads)
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert max(size for _, size, _ in image.reads) <= shared.MAX_SINGLE_READ_BYTES


def make_turkish_image():
    image = make_image(discovered=False)
    ref = _fullref("TUR", ENG_SLOT)
    pointer = COUNTRY_BASE + ENG_SLOT * 0x1000
    image.put_u64(pointer + country_memory.COUNTRY_FULLREF_OFFSET, ref)
    image.put_u64(pointer + admission.RELATION_TABLE_OFFSET, RELATION_TABLE)
    row = RELATION_TABLE + ENG_SLOT * admission.RELATION_ROW_STRIDE
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, ref)
    image.put_i32(RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
                  + ENG_SLOT * admission.RELATION_COUNTER_STRIDE, 1)
    image.put_i32(CONTROLLERS + ENG_SLOT * 4, 0)
    image.put_u64(_field_address("G02.owner"), ref)
    image.put_u32(DISCOVERY_BITS, 1 << ENG_SLOT)
    return image


def test_configured_turkish_slot_uses_its_own_discovery_gate():
    image = make_turkish_image()
    turkey = memory.read_two_pass(image, BASES[0], PROVINCE_ID, observer="TUR", observer_scoped=True)
    france = memory.read_two_pass(image, BASES[0], PROVINCE_ID)
    assert _field(turkey, "G02.owner")["value"] == "TUR"
    assert _field(france, "G02.owner")["status"] == "unknown"


def test_clear_discovery_bit_stays_unknown_and_does_not_read_owner_or_controller():
    image = make_image(discovered=False)
    result = memory.read_two_pass(image.read, BASES[0], PROVINCE_ID)

    assert result["status"] == "observed"
    assert _field(result, "G02.owner")["status"] == "unknown"
    assert _field(result, "G02.owner")["reason"] == "PROVINCE_DISCOVERY_NOT_ESTABLISHED"
    assert _field(result, "G02.controller")["reason"] == "PROVINCE_DISCOVERY_NOT_ESTABLISHED"
    assert not any("province_state.G02_owner.province_fullref" == label
                   or "province_state.G02_controller.province_fullref" == label
                   for _, _, label in image.reads)
    assert result["visibility"]["status"] == "unknown"


@pytest.mark.parametrize("bitset,reason", [
    (0x7000, "PROVINCE_DISCOVERY_POINTER_INVALID"),
    (DISCOVERY_BITS + 1, "PROVINCE_DISCOVERY_POINTER_INVALID"),
    (RECORDS + PROVINCE_ID * province_memory.RECORD_STRIDE,
     "PROVINCE_DISCOVERY_POINTER_INVALID"),
])
def test_invalid_or_aliased_discovery_pointer_never_projects_fields(bitset: int, reason: str):
    image = make_image()
    image.put_u64(RECORDS + PROVINCE_ID * province_memory.RECORD_STRIDE
                  + memory.DISCOVERY_BITSET_POINTER_OFFSET, bitset)
    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID)
    assert result["status"] == "observed"
    assert result["targets"][0]["discovery_by_pass"]["pass1"]["reason"] == reason
    assert _field(result, "G02.owner")["status"] == "unknown"
    assert _field(result, "G02.controller")["status"] == "unknown"
    assert not any(label.startswith("province_state.G02_") for _, _, label in image.reads)


@pytest.mark.parametrize("role_verified,admitted,reason", [
    (False, True, "OBSERVER_ROLE_NOT_VERIFIED"),
    (True, False, "PROVINCE_SELF_ADMISSION_NOT_ESTABLISHED"),
])
def test_role_or_self_admission_failure_short_circuits_private_fields(
        role_verified: bool, admitted: bool, reason: str):
    image = make_image(role_verified=role_verified, admitted=admitted)
    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID)
    assert result["status"] == "observed"
    assert result["targets"][0]["discovery_by_pass"]["pass1"]["reason"] == reason
    assert _field(result, "G02.owner")["status"] == "unknown"
    assert _field(result, "G02.controller")["status"] == "unknown"
    assert not any(label.startswith("province_state.G02_") for _, _, label in image.reads)


@pytest.mark.parametrize("bad_ref,reason", [
    (_fullref("ENG", COUNTRY_COUNT + 1), "COUNTRY_FULLREF_SLOT_OUT_OF_RANGE"),
    (_fullref("ENG", ENG_SLOT, generation=0x1207), "COUNTRY_FULLREF_BYTE48_SEVEN"),
    (_fullref("ENG", ENG_SLOT, generation=0x0000), "COUNTRY_FULLREF_HIGH_BYTE_ZERO"),
    (((0x1200 << 48) | (ENG_SLOT << 32) | int.from_bytes(b"EN\x00X", "little")),
     "COUNTRY_FULLREF_TAG_INVALID"),
])
def test_bad_owner_reference_is_unknown_without_losing_independent_controller(
        bad_ref: int, reason: str):
    image = make_image(owner_ref=bad_ref)
    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID)
    assert _field(result, "G02.owner")["status"] == "unknown"
    assert _field(result, "G02.owner")["reason"] == reason
    assert _field(result, "G02.controller")["status"] == "known"
    assert _field(result, "G02.controller")["value"] == "SWE"


def test_full_reference_echo_mismatch_is_rejected_independently():
    image = make_image()
    owner_pointer = COUNTRY_BASE + ENG_SLOT * 0x1000
    image.put_u64(owner_pointer + country_memory.COUNTRY_FULLREF_OFFSET,
                  _fullref("ENG", ENG_SLOT, generation=0x1300))
    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID)
    assert _field(result, "G02.owner")["status"] == "unknown"
    assert _field(result, "G02.owner")["reason"] == "COUNTRY_FULLREF_ECHO_MISMATCH"
    assert _field(result, "G02.controller")["status"] == "known"


@pytest.mark.parametrize("field", memory.FIELDS)
def test_one_field_change_retracts_only_that_field(field: str):
    image = make_image()
    changed = _fullref("DEN", DEN_SLOT)
    reader = MutatingReader(
        image, "country_reference.database_global",
        lambda: image.put_u64(_field_address(field), changed))
    result = memory.read_two_pass(reader, BASES[0], PROVINCE_ID)

    assert reader.mutated
    other = "G02.controller" if field == "G02.owner" else "G02.owner"
    assert result["consistency"]["status"] == "stable"
    assert _field(result, field)["status"] == "unknown"
    assert _field(result, field)["reason"] == "FIELD_RAW_DATA_CHANGED"
    assert _field(result, other)["status"] == "known"


def test_unrelated_country_row_change_does_not_retract_requested_fields():
    image = make_image()
    unrelated_country = COUNTRY_BASE + DEN_SLOT * 0x1000
    changed_ref = _fullref("DEN", DEN_SLOT, generation=0x1300)
    reader = MutatingReader(
        image, "country_reference.database_global",
        lambda: image.put_u64(
            unrelated_country + country_memory.COUNTRY_FULLREF_OFFSET,
            changed_ref))
    result = memory.read_two_pass(reader, BASES[0], PROVINCE_ID)

    assert reader.mutated
    first_scan = result["pass_evidence"]["pass1"]["country_scan"]
    second_scan = result["pass_evidence"]["pass2"]["country_scan"]
    assert not shared._same_raw(first_scan, second_scan)
    assert result["consistency"]["status"] == "stable"
    assert _field(result, "G02.owner")["status"] == "known"
    assert _field(result, "G02.owner")["value"] == "ENG"
    assert _field(result, "G02.controller")["status"] == "known"
    assert _field(result, "G02.controller")["value"] == "SWE"


@pytest.mark.parametrize("kind", ["province_id", "role", "discovery"])
def test_shared_identity_role_or_discovery_change_retracts_both_fields(kind: str):
    image = make_image()
    if kind == "province_id":
        trigger = "country_reference.database_global"
        mutation = lambda: image.put_i32(
            RECORDS + PROVINCE_ID * province_memory.RECORD_STRIDE
            + province_memory.RECORD_ID_OFFSET, PROVINCE_ID + 1)
    elif kind == "role":
        trigger = "foreign_tech.role.observer_controller"
        mutation = lambda: image.put_i32(CONTROLLERS + FRA_SLOT * 4, 1)
    else:
        trigger = "province_state.discovery.word_u32"
        mutation = lambda: image.put_u32(DISCOVERY_BITS, 0)
    reader = MutatingReader(image, trigger, mutation)
    result = memory.read_two_pass(reader, BASES[0], PROVINCE_ID)

    assert reader.mutated
    assert result["status"] == "unknown"
    assert result["consistency"]["status"] == "changed"
    assert result["consistency"]["shared_mismatch_paths"]
    assert _field(result, "G02.owner")["reason"] == "SHARED_EVIDENCE_CHANGED"
    assert _field(result, "G02.controller")["reason"] == "SHARED_EVIDENCE_CHANGED"


@pytest.mark.parametrize("failure", ["short", "exception"])
def test_field_read_failure_is_local_to_that_field(failure: str):
    image = make_image()
    address = _field_address("G02.owner")
    if failure == "short":
        image.short_at = address
    else:
        image.error_at = address
    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID)

    assert _field(result, "G02.owner")["status"] == "unknown"
    assert _field(result, "G02.controller")["status"] == "known"
    assert result["visibility"]["status"] == "unknown"
    if failure == "exception":
        normalized = [item for item in result["errors"]
                      if item.get("code") == "reader_read_failed"]
        assert normalized
        assert all(item.get("error_type") == "ValueError" for item in normalized)


def test_shared_budget_is_enforced_and_bad_scope_inputs_do_not_read():
    image = make_image()
    original_limit = shared.MAX_TOTAL_READ_BYTES
    shared.MAX_TOTAL_READ_BYTES = 128
    try:
        bounded = memory.read_two_pass(image, BASES[0], PROVINCE_ID)
    finally:
        shared.MAX_TOTAL_READ_BYTES = original_limit
    assert bounded["status"] == "unknown"
    assert bounded["budget"]["bytes_requested"] <= 128
    assert bounded["budget"]["rejected_bytes"] > 0
    assert bounded["budget"]["limit_bytes"] == 128

    untouched = MemoryImage()
    wrong_observer = memory.read_two_pass(untouched, BASES[0], PROVINCE_ID,
                                          observer="POR")
    bad_id = memory.read_two_pass(untouched, BASES[0], True)
    bad_base = memory.read_two_pass(untouched, 0x7000, PROVINCE_ID)
    assert wrong_observer["errors"][0]["code"] == "observer_scope_invalid"
    assert bad_id["errors"][0]["code"] == "province_id_invalid"
    assert bad_base["errors"][0]["code"] == "module_base_invalid"
    assert untouched.reads == []


def test_custom_structured_field_is_retained_and_default_owner_scope_is_narrow():
    image = make_image()
    selected = ("G02.development",)
    calls = []

    def read_structured(limiter, module_base, province_binding, fields):
        calls.append((module_base, province_binding["province_id"], fields))
        return {"G02.development": {
            "status": "known",
            "value": {"raw": 27, "components": [12, 9, 6]},
            "basis": "pinned_leaf_fixture",
            "raw_inputs": {"raw_i32_hex": "1b000000"},
        }}

    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID,
                                  fields=selected, read_fields=read_structured)
    assert result["status"] == "observed"
    assert _field(result, "G02.development")["status"] == "known"
    assert _field(result, "G02.development")["value"] == {
        "raw": 27, "components": [12, 9, 6]}
    assert len(calls) == 2 and all(row[2] == selected for row in calls)
    assert set(result["pass_evidence"]["pass1"]["fields_raw"]) == set(selected)

    default_result = memory.read_two_pass(
        image, BASES[0], PROVINCE_ID, fields=("G02.owner", "G02.development"))
    assert _field(default_result, "G02.owner")["status"] == "known"
    assert _field(default_result, "G02.development")["status"] == "unknown"
    assert _field(default_result, "G02.development")["reason"] == "UNSUPPORTED_FIELD_READER"
    assert not any(label == "province_state.G02_controller.province_fullref"
                   for _, _, label in image.reads)


@pytest.mark.parametrize("fields", [
    (),
    ("G02.owner", "G02.owner"),
    tuple(f"G02.f{i}" for i in range(17)),
    ("S04.ruler",),
    ("G02.bad-key",),
    ("G02." + "x" * 125,),
    (True,),
])
def test_invalid_field_scope_is_rejected_without_reads(fields):
    image = MemoryImage()
    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID, fields=fields)
    assert result["errors"] == [{"code": "field_scope_invalid"}]
    assert image.reads == []
    assert result["budget"]["calls"] == 0


def test_callback_runs_only_after_role_admission_and_discovery_pass():
    image = make_image(admitted=False)
    calls = []

    def callback(limiter, module_base, province_binding, fields):
        calls.append(fields)
        return {field: {"status": "known", "value": {"unexpected": True}}
                for field in fields}

    result = memory.read_two_pass(
        image, BASES[0], PROVINCE_ID, fields=("G02.development",), read_fields=callback)
    assert calls == []
    assert _field(result, "G02.development")["status"] == "unknown"
    assert _field(result, "G02.development")["reason"] == "PROVINCE_SELF_ADMISSION_NOT_ESTABLISHED"
    assert not any("G02.development" in label for _, _, label in image.reads)


def test_callback_result_is_filtered_to_requested_field_ids():
    image = make_image()
    fields = ("G02.faith", "G02.name")

    def callback(_limiter, _base, _binding, requested):
        assert requested == fields
        return {
            "G02.faith": {"status": "known", "value": {"name": "Catholic", "icon": 1}},
            "G02.not_requested": {"status": "known", "value": "secret"},
        }

    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID,
                                  fields=fields, read_fields=callback)
    evidence = result["pass_evidence"]["pass1"]["fields_raw"]
    assert set(evidence) == set(fields)
    assert "G02.not_requested" not in result["targets"][0]["fields"]
    assert _field(result, "G02.faith")["value"] == {"name": "Catholic", "icon": 1}
    assert _field(result, "G02.name")["status"] == "unknown"
    assert _field(result, "G02.name")["reason"] == "FIELD_RESULT_MISSING"


def test_custom_field_change_retracts_only_changed_selected_field():
    image = make_image()
    fields = ("G02.development", "G02.mil_tech")
    count = 0

    def callback(_limiter, _base, _binding, requested):
        nonlocal count
        count += 1
        assert requested == fields
        return {
            "G02.development": {
                "status": "known", "value": {"base": 12, "total": 27 if count == 1 else 28},
                "raw_inputs": {"base_raw_hex": "0c000000", "total_raw_hex":
                               "1b000000" if count == 1 else "1c000000"}},
            "G02.mil_tech": {"status": "known", "value": 4,
                              "raw_inputs": {"raw_i32_hex": "04000000"}},
        }

    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID,
                                  fields=fields, read_fields=callback)
    assert count == 2 and result["consistency"]["status"] == "stable"
    assert _field(result, "G02.development")["status"] == "unknown"
    assert _field(result, "G02.development")["reason"] == "FIELD_RAW_DATA_CHANGED"
    assert _field(result, "G02.mil_tech")["status"] == "known"
    assert _field(result, "G02.mil_tech")["value"] == 4


def test_callback_reader_errors_are_normalized_and_budget_is_shared():
    image = make_image()
    fields = ("G02.development",)
    address = RECORDS + PROVINCE_ID * province_memory.RECORD_STRIDE
    image.error_at = address

    def callback(limiter, _base, _binding, requested):
        limiter.read(address, 4, "province_state.G02.development.raw_i32")
        return {field: {"status": "known", "value": 1} for field in requested}

    result = memory.read_two_pass(image, BASES[0], PROVINCE_ID,
                                  fields=fields, read_fields=callback)
    assert _field(result, "G02.development")["status"] == "unknown"
    assert _field(result, "G02.development")["reason"] == "FIELD_READER_FAILED"
    normalized = [row for row in result["errors"] if row.get("code") == "reader_read_failed"]
    assert normalized and all(row.get("error_type") == "ValueError" for row in normalized)
    assert result["budget"]["calls"] == len(image.reads)

    bad_callback = memory.read_two_pass(
        MemoryImage(), BASES[0], PROVINCE_ID,
        fields=fields, read_fields=object())
    assert bad_callback["errors"] == [{"code": "field_reader_invalid"}]
    assert bad_callback["budget"]["calls"] == 0
