from __future__ import annotations

from typing import Any

import pytest

from bridge.information import country_reference_memory as countries
from bridge.information import foreign_technology_memory as foreign
from bridge.information import military_quality_memory as technology


MODULE_BASE = 0x140000000
DATABASE = 0x6200000000
COUNTRY_TABLE = 0x6300000000
COUNTRY_BASE = 0x6400000000
TECH_MANAGER = 0x6500000000
TECH_BUCKETS = 0x6510000000
TECH_ITEM = 0x6520000000
TECH_DEFINITION = 0x6530000000
TECH_POINTER_BASE = 0x6600000000
TECH_VECTOR_BASE = 0x6700000000


def fullref(tag: str, slot: int, generation: int = 0) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryReader:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_label: str | None = None
        self.on_read = None
        self.label_counts: dict[str, int] = {}

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: value for index, value in enumerate(raw)})

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        self.label_counts[label] = self.label_counts.get(label, 0) + 1
        if self.on_read is not None:
            self.on_read(self, address, size, label, self.label_counts[label])
        raw = bytes(self.memory[address + index] for index in range(size))
        if self.short_label == label:
            return raw[:-1]
        return raw


def make_reader(
    entries: dict[str, tuple[int, int, int]],
    *,
    count: int = 310,
    technology_index: int = 3,
    vector_length: int = 5,
) -> tuple[MemoryReader, dict[str, dict[str, int]], dict[str, int]]:
    """Build country rows and independent per-country technology vectors."""
    profile = technology._active_profile()
    layout = technology._profile_layout(profile)
    image = MemoryReader()

    for _name, rva, _end, raw in technology._profile_code_guards(profile):
        image.put(MODULE_BASE + rva, raw)

    image.put_u64(MODULE_BASE + countries.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + countries.DATABASE_TABLE_OFFSET, COUNTRY_TABLE)
    image.put_i32(DATABASE + countries.DATABASE_TABLE_COUNT_OFFSET, count)
    image.put_u64(MODULE_BASE + layout["singleton_global_rva"], TECH_MANAGER)
    image.put_i32(TECH_MANAGER + layout["manager_bucket_count_offset"], 17)
    image.put_u64(TECH_MANAGER + layout["manager_buckets_offset"], TECH_BUCKETS)
    bucket_index = technology._hash_key(technology.TECHNOLOGY_KEY_BYTES) % 17
    image.put_u64(TECH_BUCKETS + bucket_index * layout["bucket_entry_stride"], TECH_ITEM)
    image.put_u64(TECH_ITEM + layout["chain_definition_offset"], TECH_DEFINITION)
    image.put_u64(TECH_ITEM + layout["chain_next_offset"], 0)
    image.put(
        TECH_DEFINITION + layout["definition_key_string_offset"],
        technology.TECHNOLOGY_KEY_BYTES + b"\0" * 8,
    )
    image.put_u64(TECH_DEFINITION + layout["definition_key_length_offset"], len(technology.TECHNOLOGY_KEY_BYTES))
    image.put_u64(TECH_DEFINITION + layout["definition_key_capacity_offset"], 15)
    image.put_i32(TECH_DEFINITION + layout["definition_index_offset"], technology_index)

    bindings: dict[str, dict[str, int]] = {}
    value_addresses: dict[str, int] = {}
    for tag, (slot, generation, level) in entries.items():
        if slot >= count:
            raise ValueError(f"fixture_slot_out_of_range:{tag}")
        country_pointer = COUNTRY_BASE + slot * 0x1000
        tech_pointer = TECH_POINTER_BASE + slot * 0x1000
        vector = TECH_VECTOR_BASE + slot * 0x1000
        ref = fullref(tag, slot, generation)
        image.put_u64(COUNTRY_TABLE + slot * 8, country_pointer)
        image.put_u64(country_pointer + countries.COUNTRY_FULLREF_OFFSET, ref)
        image.put_u64(country_pointer + layout["country_technology_pointer_offset"], tech_pointer)
        image.put_u64(tech_pointer + layout["technology_vector_begin_offset"], vector)
        image.put_u64(tech_pointer + layout["technology_vector_end_offset"], vector + vector_length * 4)
        for index in range(vector_length):
            item = level if index == technology_index else index + 1
            image.put_i32(vector + index * layout["technology_component_width"], item)
        bindings[tag] = {
            "slot": slot,
            "generation": generation,
            "fullref": ref,
            "country_pointer": country_pointer,
            "technology_pointer": tech_pointer,
            "vector": vector,
        }
        value_addresses[tag] = vector + technology_index * layout["technology_component_width"]

    for slot in range(count):
        if not any(binding["slot"] == slot for binding in bindings.values()):
            image.put_u64(COUNTRY_TABLE + slot * 8, 0)
    return image, bindings, value_addresses


def assert_visibility_never_public(result: dict[str, Any]) -> None:
    assert result["visibility"] == {
        "status": "unknown",
        "reason": "FOREIGN_TARGET_ADMISSION_NOT_VERIFIED",
        "complete": False,
        "public_export_ready": False,
    }
    assert result["basis"] == foreign.BASIS


def test_distinct_foreign_countries_keep_their_own_technology_and_fullrefs() -> None:
    image, fixture, _ = make_reader({
        "FRA": (189, 0x1234, 5),
        "ENG": (300, 0x4567, 9),
        "SWE": (301, 0x2222, 14),
    })

    result = foreign.read_two_pass(
        image, MODULE_BASE, "FRA", ["ENG", "SWE"],
        expected_refs={"FRA": fixture["FRA"]["fullref"], "ENG": fixture["ENG"]["fullref"]},
    )

    assert result["status"] == "observed"
    assert result["consistency"]["passed"] is True
    assert result["observer"]["fullref"] == hex(fixture["FRA"]["fullref"])
    values = {item["tag"]: item for item in result["targets"]}
    assert values["ENG"]["fullref"] == hex(fixture["ENG"]["fullref"])
    assert values["SWE"]["fullref"] == hex(fixture["SWE"]["fullref"])
    assert values["ENG"]["technology"]["value"] == 9
    assert values["ENG"]["technology"]["raw_hex"] == "09000000"
    assert values["SWE"]["technology"]["value"] == 14
    assert values["SWE"]["technology"]["raw_hex"] == "0e000000"
    assert values["ENG"]["technology"]["state"]["lookup"]["key"] == "mil_tech"
    assert values["ENG"]["technology"]["country_pointer"] != values["SWE"]["technology"]["country_pointer"]
    assert len(result["country_scans"]) == 2
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert result["budget"]["bytes_requested"] <= foreign.MAX_TOTAL_READ_BYTES
    assert_visibility_never_public(result)


def test_injected_admission_evidence_is_preserved_but_never_makes_visibility_public() -> None:
    image, _, _ = make_reader({"FRA": (189, 0x1234, 5), "ENG": (300, 0x4567, 9)})

    def admission_reader(_read, _module_base, bindings, observer, target):
        return {
            "status": "known",
            "admitted": True,
            "predicate_path": "SetCountryViewAdmission.selected_target",
            "raw_operands": {
                "observer_ref": bindings["requested"][observer]["fullref"],
                "target_ref": bindings["requested"][target]["fullref"],
            },
        }

    result = foreign.read_two_pass(
        image, MODULE_BASE, "FRA", ["ENG"], admission_reader=admission_reader
    )

    assert result["status"] == "observed"
    assert result["admission"]["status"] == "known"
    assert result["targets"][0]["admission_by_pass"]["pass1"]["admitted"] is True
    assert result["targets"][0]["admission_by_pass"]["pass2"]["raw_operands"] == result["targets"][0]["admission_by_pass"]["pass1"]["raw_operands"]
    assert_visibility_never_public(result)


def test_admission_operand_change_retracts_all_technology_values() -> None:
    image, _, _ = make_reader({"FRA": (189, 0x1234, 5), "ENG": (300, 0x4567, 9)})
    calls = 0

    def admission_reader(_read, _module_base, _bindings, _observer, _target):
        nonlocal calls
        calls += 1
        return {
            "status": "known",
            "admitted": calls == 1,
            "predicate_path": "SetCountryViewAdmission.selected_target",
            "raw_operands": {"selected": "first" if calls == 1 else "changed"},
        }

    result = foreign.read_two_pass(
        image, MODULE_BASE, "FRA", ["ENG"], admission_reader=admission_reader
    )

    assert result["status"] == "unknown"
    assert any(path.startswith("admission_by_tag.ENG") for path in result["consistency"]["mismatch_paths"])
    assert result["targets"][0]["technology"]["value"] is None
    assert result["admission"]["status"] == "unknown"
    assert_visibility_never_public(result)


def test_maximum_country_slots_and_eight_targets_are_bounded() -> None:
    entries = {"FRA": (189, 0x100, 4)}
    targets = ["AAA", "AAB", "AAC", "AAD", "AAE", "AAF", "AAG", "ZZZ"]
    slots = [300, 301, 302, 303, 304, 305, 306, 4095]
    for index, (tag, slot) in enumerate(zip(targets, slots), start=10):
        entries[tag] = (slot, index, index)
    image, fixture, _ = make_reader(entries, count=4096)

    result = foreign.read_two_pass(image, MODULE_BASE, "FRA", targets)

    assert result["status"] == "observed"
    assert len(result["targets"]) == 8
    assert next(item for item in result["targets"] if item["tag"] == "ZZZ")["bindings_by_pass"]["pass2"]["slot"] == 4095
    assert result["budget"]["bytes_requested"] <= foreign.MAX_TOTAL_READ_BYTES
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert_visibility_never_public(result)


@pytest.mark.parametrize("change", ["generation", "technology", "lookup", "vector"])
def test_changes_between_passes_retract_all_committed_values(change: str) -> None:
    image, fixture, value_addresses = make_reader({
        "FRA": (189, 0x1234, 5),
        "ENG": (300, 0x4567, 9),
    })
    profile = technology._active_profile()
    layout = technology._profile_layout(profile)
    target = fixture["ENG"]
    watched_address = {
        "generation": target["country_pointer"] + countries.COUNTRY_FULLREF_OFFSET,
        "technology": value_addresses["ENG"],
        "lookup": TECH_DEFINITION + layout["definition_index_offset"],
        "vector": target["technology_pointer"] + layout["technology_vector_end_offset"],
    }[change]
    watched_label = {
        "generation": "country_reference.database_global",
        "technology": "military_quality.technology.level",
        "lookup": "military_quality.definition.index",
        "vector": "military_quality.technology.vector_end",
    }[change]
    count = 0

    def mutate(memory: MemoryReader, address: int, _size: int, label: str, _label_count: int) -> None:
        nonlocal count
        if change == "generation":
            if label == watched_label:
                count += 1
                if count == 2:
                    memory.put_u64(watched_address, fullref("ENG", 300, 0x9999))
        elif address == watched_address and label == watched_label:
            count += 1
            if count == 2:
                if change == "technology":
                    memory.put_i32(watched_address, 99)
                elif change == "lookup":
                    memory.put_i32(watched_address, 2)
                elif change == "vector":
                    memory.put_u64(watched_address, target["vector"] + 16)

    image.on_read = mutate
    result = foreign.read_two_pass(image, MODULE_BASE, "FRA", ["ENG"])

    assert result["status"] == "unknown"
    assert result["consistency"]["passed"] is False
    assert result["consistency"]["mismatch_paths"]
    assert result["targets"][0]["technology"]["value"] is None
    assert result["targets"][0]["technology"]["raw_hex"] is None
    assert result["pass_evidence"][0]["technology_by_tag"]["ENG"]["status"] == "observed"
    assert_visibility_never_public(result)


def test_second_pass_code_guard_change_retracts_values() -> None:
    image, _, _ = make_reader({"FRA": (189, 0, 5), "ENG": (300, 0, 9)})
    name, rva, _end, expected = technology._profile_code_guards(technology._active_profile())[0]
    address = MODULE_BASE + rva
    seen = 0

    def mutate(memory: MemoryReader, read_address: int, _size: int, label: str, _label_count: int) -> None:
        nonlocal seen
        if label == f"military_quality.code.{name}" and read_address == address:
            seen += 1
            if seen == 2:
                changed = bytearray(expected)
                changed[0] ^= 1
                memory.put(address, bytes(changed))

    image.on_read = mutate
    result = foreign.read_two_pass(image, MODULE_BASE, "FRA", ["ENG"])

    assert result["status"] == "unknown"
    assert result["consistency"]["completed_passes"] == 2
    assert result["targets"][0]["technology"]["value"] is None
    assert any(error["code"] == "runtime_code_guard_failed" for error in result["errors"])
    assert_visibility_never_public(result)


def test_short_read_preserves_failure_reason_and_does_not_publish() -> None:
    image, _, _ = make_reader({"FRA": (189, 0, 5), "ENG": (300, 0, 9)})
    image.short_label = "country_reference.database_global"

    result = foreign.read_two_pass(image, MODULE_BASE, "FRA", ["ENG"])

    assert result["status"] == "unknown"
    assert result["errors"][0]["code"] == "country_resolution_failed"
    assert "short_or_invalid_read:country_reference.database_global" in result["errors"][0]["detail"]
    assert result["targets"][0]["technology"]["value"] is None
    assert_visibility_never_public(result)


def test_first_pass_guard_failure_stops_before_country_binding() -> None:
    image, _, _ = make_reader({"FRA": (189, 0, 5), "ENG": (300, 0, 9)})
    name, rva, _end, expected = technology._profile_code_guards(technology._active_profile())[0]
    damaged = bytearray(expected)
    damaged[0] ^= 1
    image.put(MODULE_BASE + rva, bytes(damaged))

    result = foreign.read_two_pass(image, MODULE_BASE, "FRA", ["ENG"])

    assert result["status"] == "unknown"
    assert result["errors"][0]["code"] == "runtime_code_guard_failed"
    assert result["country_scans"] == []
    assert not any(label.startswith("country_reference.") for _, _, label in image.reads)
    assert_visibility_never_public(result)


def test_missing_observer_and_expected_ref_conflicts_are_unknown() -> None:
    image, fixture, _ = make_reader({"ENG": (300, 0x55, 9)})
    missing = foreign.read_two_pass(image, MODULE_BASE, "FRA", ["ENG"])
    assert missing["status"] == "unknown"
    assert "requested_country_missing:FRA" in missing["errors"][0]["detail"]

    image, fixture, _ = make_reader({"FRA": (189, 0x1234, 5), "ENG": (300, 0x4567, 9)})
    conflict = foreign.read_two_pass(
        image, MODULE_BASE, "FRA", ["ENG"],
        expected_refs={"ENG": fullref("ENG", 300, 0x9999)},
    )
    assert conflict["status"] == "unknown"
    assert "expected_fullref_mismatch:ENG" in conflict["errors"][0]["detail"]
    assert_visibility_never_public(missing)
    assert_visibility_never_public(conflict)


@pytest.mark.parametrize(
    ("observer", "targets", "expected_refs", "code"),
    [
        ("FRA", [], None, "invalid_request"),
        ("FRA", ["ENG", "ENG"], None, "duplicate_target"),
        ("FRA", ["FRA"], None, "target_alias_observer"),
        ("FRA", ["eng"], None, "target_tag_invalid"),
        ("USA", ["ENG"], None, "observer_not_supported"),
        ("FRA", ["ENG"], {"ENG": fullref("FRA", 189)}, "expected_ref_tag_mismatch"),
        ("FRA", ["AAA", "AAB", "AAC", "AAD", "AAE", "AAF", "AAG", "AAH", "AAI"], None, "target_count_out_of_range"),
    ],
)
def test_bad_request_shapes_fail_before_memory_reads(observer, targets, expected_refs, code) -> None:
    image, _, _ = make_reader({"FRA": (189, 0, 5), "ENG": (300, 0, 9)})

    result = foreign.read_two_pass(
        image, MODULE_BASE, observer, targets, expected_refs=expected_refs
    )

    assert result["status"] == "unknown"
    assert any(error["code"] == code for error in result["errors"])
    assert image.reads == []
    assert_visibility_never_public(result)
