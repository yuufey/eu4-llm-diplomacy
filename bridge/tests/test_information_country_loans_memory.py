from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information import country_loans_memory as memory
from bridge.information import engine_dates


MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x6000000000
NODE_BASE = 0x7000000000
RECORD_BASE = 0x7100000000
VTABLE_BASE = MODULE_BASE + 0x1B66000
ENTRY_BASE = MODULE_BASE + 0x9A010


class BoundedReader:
    def __init__(self):
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_labels: set[str] = set()

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: value for index, value in enumerate(raw)})

    def qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def i32(self, address: int, value: int) -> None:
        self.put(address, (int(value) & 0xFFFFFFFF).to_bytes(4, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise AssertionError(f"planned bounded failure: {label}")
        try:
            return bytes(self.memory[address + index] for index in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected bounded read: {label} {address:#x} {size}") from exc


def _reader(records: list[dict[str, int]], *, cycle: bool = False, bad_head: int | None = None) -> BoundedReader:
    profile = memory._load_profile()
    layout = memory._profile_layout(profile)
    reader = BoundedReader()
    for _name, rva, _end, raw in memory._profile_code_guards(profile):
        reader.put(MODULE_BASE + rva, raw)
    head = bad_head if bad_head is not None else (NODE_BASE if records else 0)
    reader.qword(COUNTRY_POINTER + layout["country_loans_offset"], head)
    for index, item in enumerate(records):
        node = NODE_BASE + index * 0x1000
        record = RECORD_BASE + index * 0x1000
        vtable = VTABLE_BASE + index * 0x1000
        entry = ENTRY_BASE + index * 0x1000
        next_node = NODE_BASE + (index + 1) * 0x1000 if index + 1 < len(records) else 0
        if cycle and index == len(records) - 1:
            next_node = node
        reader.qword(node + layout["node_payload_offset"], record)
        reader.qword(node + layout["node_next_offset"], next_node)
        reader.qword(record + layout["loan_record_vtable_offset"], vtable)
        reader.qword(vtable + layout["vtable_guard_entry_offset"], entry)
        raw = (
            int(item.get("lender", 0)).to_bytes(8, "little", signed=False)
            + (int(item.get("interest", 0)) & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
            + (int(item.get("principal", 0)) & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
            + (int(item.get("due", 0)) & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        )
        reader.put(record + layout["lender_fullref_offset"], raw)
        if "special_flag" in item:
            reader.put(record + layout["special_flag_offset"], bytes([int(item["special_flag"]) & 0xFF]))
    return reader


def _records() -> list[dict[str, int]]:
    return [
        {"lender": 0, "interest": 5500, "principal": 123, "due": -7},
        {"lender": 0x0000007A00010002, "interest": -1250, "principal": -31, "due": 56557728},
    ]


def _archived_runtime_reader() -> tuple[BoundedReader, int, int, dict]:
    """Replay the independent raw sample through the production reader.

    The addresses and scalar bytes come from the archived two-pass sample.  We
    only provide those bytes to a bounded fake reader; the production child
    still loads and validates the pinned static profile and all runtime code
    guards.  This keeps the replay offline while exercising the same pointer,
    list, and provenance checks used for a live read.
    """
    root = Path(__file__).resolve().parents[2]
    sample_path = root / "work" / "runtime" / "information-country-records-20261027-001" / "native-loans-inputs-001.json"
    assert sample_path.stat().st_size <= 8 * 1024 * 1024
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    # The archived two-pass sample was captured against the immutable v1
    # profile.  The v2 reader replays its old 20-byte rows while preserving
    # the missing +0x36 discriminator as unknown.
    assert sample["profile"]["sha256"] == "8c3ab5ed8c72e859d2af6d1a8f689901de94243ca903c6af0a103ed32af9e481"
    first = sample["loan_inputs"][0]
    module_base = int(sample["module_base"]["va"], 0)
    country_pointer = int(first["country"]["country_pointer"]["va"], 0)
    profile = memory._load_profile()
    layout = memory._profile_layout(profile)
    reader = BoundedReader()
    for _name, rva, _end, raw in memory._profile_code_guards(profile):
        reader.put(module_base + rva, raw)

    container_address = country_pointer + layout["country_loans_offset"]
    reader.put(container_address, bytes.fromhex(first["container_head_raw_hex"]))
    for node in first["nodes"]:
        node_address = int(node["node_address"], 0)
        record_address = int(node["record_address"], 0)
        vtable_address = int.from_bytes(bytes.fromhex(node["record_vtable_pointer_raw_hex"]), "little")
        reader.put(node_address + layout["node_payload_offset"], bytes.fromhex(node["node_payload_raw_hex"]))
        reader.put(node_address + layout["node_next_offset"], bytes.fromhex(node["next_raw_hex"]))
        reader.put(record_address + layout["loan_record_vtable_offset"], bytes.fromhex(node["record_vtable_pointer_raw_hex"]))
        reader.put(vtable_address + layout["vtable_guard_entry_offset"], bytes.fromhex(node["vtable_entry_raw_hex"]))
        reader.put(record_address + layout["lender_fullref_offset"], bytes.fromhex(node["record_fields_raw_hex"]))
    return reader, module_base, country_pointer, sample


def test_archived_runtime_sample_replays_through_real_reader_and_validator() -> None:
    reader, module_base, country_pointer, sample = _archived_runtime_reader()

    record = memory.read_fields(reader, module_base, country_pointer)

    assert record["status"] == "observed"
    assert memory.validate_record(record)
    nodes = record["values"]["loans"]
    raw_nodes = sample["loan_inputs"][0]["nodes"]
    assert [node["record_fields_raw_hex"] for node in nodes] == [node["record_fields_raw_hex"] for node in raw_nodes]
    assert [node["principal_raw"] for node in nodes] == [node["principal_raw"] for node in raw_nodes]
    assert [node["interest_raw"] for node in nodes] == [node["interest_raw"] for node in raw_nodes]
    assert [node["due_raw"] for node in nodes] == [node["due_raw"] for node in raw_nodes]
    assert [node["principal_raw"] for node in nodes] == [128, 131, 131]
    assert [node["principal"]["value"] for node in nodes] == [128, 131, 131]
    assert [node["interest_raw"] for node in nodes] == [2000, 2000, 2000]
    assert [node["interest"]["value"] for node in nodes] == [2.0, 2.0, 2.0]
    assert [node["due_raw"] for node in nodes] == [56590344, 56593392, 56598528]
    assert [node["lender"]["raw_fullref_hex"] for node in nodes] == ["2d2d2d0000000000"] * 3
    assert record["static_contract_guard"]["status"] == "observed"
    assert record["runtime_code_guard"]["status"] == "observed"
    assert record["observation"]["node_count"] == sample["loan_inputs"][0]["node_count"] == 3
    assert sample["doublepass"]["performed"] is True
    assert sample["doublepass"]["consistent"] is True


def test_pinned_profile_and_empty_list_use_real_guards_and_validator() -> None:
    reader = _reader([])

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    assert record["fields"]["loans"]["status"] == "known"
    assert record["fields"]["loans"]["complete"] is False
    assert record["fields"]["loans"]["partial"] is True
    assert record["values"]["loans"] == []
    assert memory.validate_record(record)
    assert sum(size for _address, size, _label in reader.reads) <= memory.READ_BUDGET_BYTES


def test_real_reader_copies_order_and_closed_scalars_without_guessing_lender() -> None:
    reader = _reader(_records())

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    nodes = record["values"]["loans"]
    assert [node["principal"]["raw"] for node in nodes] == [123, -31]
    assert [node["principal_raw"] for node in nodes] == [123, -31]
    assert [node["amount_raw"] for node in nodes] == [123, -31]
    assert [node["principal"]["value"] for node in nodes] == [123, -31]
    assert [node["interest"]["value"] for node in nodes] == [5.5, -1.25]
    assert [node["interest_raw"] for node in nodes] == [5500, -1250]
    assert [node["due"]["raw"] for node in nodes] == [-7, 56557728]
    assert nodes[0]["lender"]["status"] == "unknown"
    assert nodes[0]["lender"]["raw_fullref"] == 0
    assert nodes[1]["lender"]["raw_fullref_hex"] == "020001007a000000"
    assert all(
        MODULE_BASE + 0x1B66000 <= int(node["record_vtable_pointer"], 0) < MODULE_BASE + 0x1FAFA00
        and MODULE_BASE + 0x1000 <= int(node["vtable_first_entry"], 0) < MODULE_BASE + 0x1B65E00
        for node in nodes
    )
    assert record["observation"]["node_count"] == 2
    assert memory.validate_record(record)


def test_optional_loaded_profile_argument_has_same_contract() -> None:
    profile = memory._load_profile()
    record = memory.read_fields(_reader(_records()[:1]), MODULE_BASE, COUNTRY_POINTER, profile=profile)

    assert record["status"] == "observed"
    assert memory.validate_record(record)


def test_v2_special_lender_discriminator_and_replayable_date_projection() -> None:
    reader = _reader(
        [
            {"lender": 0, "special_flag": 0, "interest": 2000, "principal": 10, "due": 43800024},
            {"lender": 0, "special_flag": 1, "interest": 2000, "principal": 11, "due": 43800000 + 365 * 24},
        ]
    )
    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "observed"
    nodes = record["values"]["loans"]
    assert [node["lender"]["mapping"] for node in nodes] == ["BANK", "ESTATE"]
    assert [node["lender"]["status"] for node in nodes] == ["known", "known"]
    assert all(node["due"]["complete"] is True for node in nodes)
    assert nodes[0]["due"]["calendar"]["day_index"] == 1
    assert nodes[0]["due"]["calendar"]["tick_of_day"] == 0
    assert nodes[0]["due"]["calendar"]["date"] == "0.1.2"
    assert nodes[1]["due"]["calendar"]["year_index"] == 1
    assert nodes[1]["due"]["calendar"]["day_of_year"] == 0
    assert nodes[1]["due"]["calendar"]["date"] == "1.1.1"
    assert memory.validate_record(record)


def test_v2_foreign_lender_publishes_tag_only_after_exact_table_fullref_match() -> None:
    # +0x27 (the eighth byte) selects the foreign branch while bytes 4:6
    # carry the signed database slot.  The low four bytes still carry ABC\0.
    lender = int.from_bytes(b"ABC\x00\x7a\x00\x00\x01", "little")
    reader = _reader([{"lender": lender, "interest": 2000, "principal": 12, "due": 43800000}])
    database = 0x6200000000
    table = 0x6300000000
    entry = 0x6400000000
    slot = 0x7A
    reader.qword(MODULE_BASE + memory.DATABASE_GLOBAL_RVA, database)
    reader.qword(database + memory.DATABASE_TABLE_OFFSET, table)
    reader.qword(table + slot * 8, entry)
    reader.qword(entry + memory.DATABASE_ENTRY_GATE_OFFSET, 1)
    reader.qword(entry + memory.DATABASE_ENTRY_FULLREF_OFFSET, lender)

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)
    node = record["values"]["loans"][0]
    assert node["lender"]["status"] == "known"
    assert node["lender"]["mapping"] == "ABC"
    assert node["foreign_resolution"]["country_tag_status"] == "matched_fullref"
    assert memory.validate_record(record)


def test_engine_date_projection_has_exact_negative_and_year_boundaries() -> None:
    assert engine_dates.project_engine_date(43800000)["day_index"] == 0
    before = engine_dates.project_engine_date(43800000 - 1)
    assert before["day_index"] == -1
    assert before["tick_of_day"] == 23
    year = engine_dates.project_engine_date(43800000 + 365 * 24)
    assert year["year_index"] == 1
    assert year["day_of_year"] == 0


def test_engine_date_projection_expands_fixed_months_and_signed32_boundaries() -> None:
    base = engine_dates.REFERENCE_RAW

    january_end = engine_dates.project_engine_date(base + 31 * 24 - 1)
    assert (january_end["month"], january_end["day"], january_end["date"]) == (1, 31, "0.1.31")
    assert january_end["tick_of_day"] == 23

    february_start = engine_dates.project_engine_date(base + 31 * 24)
    assert (february_start["month"], february_start["day"], february_start["date"]) == (2, 1, "0.2.1")

    february_end = engine_dates.project_engine_date(base + (31 + 28) * 24 - 1)
    assert (february_end["month"], february_end["day"]) == (2, 28)
    march_start = engine_dates.project_engine_date(base + (31 + 28) * 24)
    assert (march_start["month"], march_start["day"]) == (3, 1)

    year_end = engine_dates.project_engine_date(base + 365 * 24 - 1)
    assert (year_end["year_index"], year_end["month"], year_end["day"]) == (0, 12, 31)
    assert engine_dates.project_engine_date(base + 365 * 24)["date"] == "1.1.1"

    negative = engine_dates.project_engine_date(base - 1)
    assert (negative["year_index"], negative["month"], negative["day"], negative["date"]) == (-1, 12, 31, "-1.12.31")
    assert negative["month_day_status"] == engine_dates.MONTH_DAY_STATUS

    # The native leaf subtracts in a 32-bit register.  Keep this explicit so
    # a future refactor cannot silently revert to Python's unbounded integer
    # subtraction for DWORD values near the sign boundary.
    wrapped = engine_dates.project_engine_date(0xFFFFFFFF)
    expected_delta_unsigned = (0xFFFFFFFF - base) & 0xFFFFFFFF
    expected_delta = expected_delta_unsigned - 0x100000000
    assert wrapped["raw_unsigned"] == 0xFFFFFFFF
    assert wrapped["delta_ticks_unsigned"] == expected_delta_unsigned
    assert wrapped["delta_ticks"] == expected_delta
    assert 1 <= wrapped["month"] <= 12
    assert 1 <= wrapped["day"] <= 31


def test_bad_vtable_and_head_are_unknown_before_publishing_values() -> None:
    bad_vtable = _reader(_records()[:1])
    bad_vtable.qword(RECORD_BASE, 0)
    bad_record = memory.read_fields(bad_vtable, MODULE_BASE, COUNTRY_POINTER)
    assert bad_record["status"] == "unknown"
    assert bad_record["reason"] == "loan_record_vtable_invalid"
    assert bad_record["values"] is None

    external_vtable = _reader(_records()[:1])
    external_vtable.qword(RECORD_BASE, 0x7200000000)
    external_record = memory.read_fields(external_vtable, MODULE_BASE, COUNTRY_POINTER)
    assert external_record["status"] == "unknown"
    assert external_record["reason"] == "loan_record_vtable_invalid"

    bad_head = memory.read_fields(_reader([], bad_head=0x7), MODULE_BASE, COUNTRY_POINTER)
    assert bad_head["status"] == "unknown"
    assert bad_head["reason"] == "loan_container_head_invalid"


def test_cycle_and_node_limit_are_bounded() -> None:
    cycle_record = memory.read_fields(_reader(_records()[:1], cycle=True), MODULE_BASE, COUNTRY_POINTER)
    assert cycle_record["status"] == "unknown"
    assert cycle_record["reason"] == "loan_node_cycle_detected"
    assert cycle_record["observation"]["read_budget"]["bytes_reserved"] <= memory.READ_BUDGET_BYTES

    records = [{"lender": index, "interest": index, "principal": index, "due": index} for index in range(memory.MAX_NODES + 1)]
    too_many = memory.read_fields(_reader(records), MODULE_BASE, COUNTRY_POINTER)
    assert too_many["status"] == "unknown"
    assert too_many["reason"] == "loan_node_limit_exceeded"


def test_failed_reader_call_consumes_reserved_bytes() -> None:
    reader = _reader(_records()[:1])
    reader.fail_labels.add("country_loans.node_next")

    record = memory.read_fields(reader, MODULE_BASE, COUNTRY_POINTER)

    assert record["status"] == "unknown"
    assert record["reason"].startswith("read_failed:country_loans.node_next")
    budget = record["observation"]["read_budget"]
    guard_bytes = sum(len(raw) for _name, _rva, _end, raw in memory._profile_code_guards(memory._load_profile()))
    assert budget["bytes_reserved"] == guard_bytes + 8 + (8 + 8 + 8 + 20 + 1 + 8)
    assert record["observation"]["read_log"][-1]["status"] == "failed"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda item: item["values"]["loans"][0]["principal"].update(raw=124),
        lambda item: item["values"]["loans"][0]["lender"].update(raw_fullref=9),
        lambda item: item["observation"]["nodes"][0].update(record_address="0x7100009999"),
        lambda item: item.update(module_base="0x140001000"),
        lambda item: item["runtime_code_guard"]["checks"].update(country_writer_container=False),
    ],
)
def test_real_validator_rejects_raw_topology_and_guard_tampering(mutator) -> None:
    record = memory.read_fields(_reader(_records()[:1]), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    tampered = deepcopy(record)
    mutator(tampered)

    assert not memory.validate_record(tampered)


def test_retraction_cannot_validate_as_known() -> None:
    record = memory.read_fields(_reader(_records()[:1]), MODULE_BASE, COUNTRY_POINTER)
    assert memory.validate_record(record)

    retracted = memory.retract_record(record, "cleanup_failed")

    assert retracted["status"] == "unknown"
    assert retracted["fields"]["loans"]["status"] == "unknown"
    assert retracted["fields"]["loans"]["reason"] == "cleanup_failed"
    assert not memory.validate_record(retracted)
