from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import country_modifiers_memory as memory


ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_PATH = ROOT / "work" / "runtime" / "information-military-modifiers-20261027-001" / "native-modifier-inputs-002.json"
OLD_PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "country-modifiers-memory-1374.json"
OLD_PROFILE_SHA256 = "6cd3c0cf0c705b190741458e0359e6f4597ef11e847fbd41bc42533d2a34dc2f"


class ArchivedReader:
    """Bounded memory reconstructed only from the archived native raw reads."""

    def __init__(self) -> None:
        document = json.loads(ARCHIVE_PATH.read_text(encoding="utf-8"))
        snapshots = document["modifier_instances_inputs"]
        assert len(snapshots) == 2
        first = snapshots[0]["modifier_instances"]
        second = snapshots[1]["modifier_instances"]
        assert first["head"] == second["head"]
        assert [node["item_raw_hex"] for node in first["nodes"]] == [node["item_raw_hex"] for node in second["nodes"]]
        self.module_base = int(first["module_base"], 0)
        self.country_pointer = int(first["country_pointer"], 0)
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.archive_labels: set[str] = set()
        self.item_raws: dict[int, bytes] = {}
        self.item_read_limits: dict[int, int] = {}
        profile = memory._load_profile()
        for name, rva, _end, raw in memory._profile_code_guards(profile):
            # The archived probe sampled the writer guard.  The remaining
            # static guard bytes are pinned by the v2 profile and are inserted
            # as static evidence, never inferred from the fake fixture.
            self.put(self.module_base + rva, raw)
        for entry in first["reads"]:
            address = int(entry["va"], 0)
            raw = bytes.fromhex(entry["raw_hex"])
            self.put(address, raw)
            self.archive_labels.add(entry["label"])
            label = entry["label"]
            if label.startswith("item_") and label[5:].isdigit():
                self.item_raws[address] = raw

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + index: byte for index, byte in enumerate(raw)})

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label.startswith("country_modifiers.item_") and address in self.item_read_limits and size > self.item_read_limits[address]:
            raise AssertionError(f"read exceeded instance prefix: {label} {address:#x} {size}")
        try:
            return bytes(self.memory[address + index] for index in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected bounded read: {label} {address:#x} {size}") from exc


def _reader() -> ArchivedReader:
    return ArchivedReader()


def test_archived_two_pass_raw_replay_reads_instance_dates_flags_and_effects() -> None:
    reader = _reader()
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert record["status"] == "observed"
    values = record["values"]["modifiers"]
    assert [item["key"] for item in values] == ["papal_sanction_for_church_taxes", "shady_people"]
    assert values[0]["start_date_raw"] == 43808760
    assert values[0]["date_raw"] == 56685912
    assert values[0]["flags"] == {"ruler_modifier": 0, "parliament_modifier": 0, "permanent": 0, "hidden": 0}
    assert values[0]["effects"] == [
        {"index": 26, "selector": 10372, "raw": 150, "raw_hex": "96000000"},
        {"index": 6, "selector": 10327, "raw": -100, "raw_hex": "9cffffff"},
    ]
    assert values[1]["effects"] == [{"index": 100, "selector": 10591, "raw": 200, "raw_hex": "c8000000"}]
    assert memory.validate_record(record)
    assert {"node_1", "item_1", "definition_1", "effect_pair_1_0"}.issubset(reader.archive_labels)


def test_archived_definition_and_item_raw_are_not_mixed() -> None:
    reader = _reader()
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    node = record["observation"]["nodes"][0]
    item = bytes.fromhex(node["item_raw_hex"])
    definition = bytes.fromhex(node["raw"]["definition_prefix_raw_hex"])
    assert node["raw"]["item_start_date_raw_hex"] == item[0x40:0x44].hex()
    assert node["raw"]["item_date_raw_hex"] == item[0x44:0x48].hex()
    assert node["raw"]["item_flags_raw_hex"]["permanent"] == item[0x4A:0x4B].hex()
    assert node["raw"]["key_raw_hex"] == bytes.fromhex(node["definition"]["key_raw_hex"]).hex()
    assert definition[0:8] == (reader.module_base + memory.DEFINITION_VTABLE_RVA).to_bytes(8, "little")


def test_live_item_read_stays_within_the_0x50_byte_allocation_prefix() -> None:
    reader = _reader()
    live_prefix_bytes = {
        address + offset
        for address in reader.item_raws
        for offset in range(memory.LIVE_ITEM_PREFIX_WIDTH)
    }
    reader.item_read_limits = {address: memory.LIVE_ITEM_PREFIX_WIDTH for address in reader.item_raws}
    for address, raw in reader.item_raws.items():
        for offset in range(memory.LIVE_ITEM_PREFIX_WIDTH, len(raw)):
            byte_address = address + offset
            if byte_address not in live_prefix_bytes:
                reader.memory.pop(byte_address, None)

    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)

    assert record["status"] == "observed"
    assert memory.validate_record(record)
    item_reads = [(address, size, label) for address, size, label in reader.reads if label.startswith("country_modifiers.item_")]
    assert len(item_reads) == len(reader.item_raws)
    assert all(size == memory.LIVE_ITEM_PREFIX_WIDTH for _address, size, _label in item_reads)
    assert all(len(bytes.fromhex(node["item_raw_hex"])) == memory.LIVE_ITEM_PREFIX_WIDTH for node in record["observation"]["nodes"])


def test_legacy_0x80_byte_item_snapshot_remains_verifiable() -> None:
    reader = _reader()
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert record["status"] == "observed"

    nodes = record["observation"]["nodes"]
    projections = [
        record["observation"]["raw_projection"],
        record["raw_hex"][memory.FIELD_KEY],
        record["raw_bytes_hex"][memory.FIELD_KEY],
    ]
    added_read_bytes = 0
    for ordinal, node in enumerate(nodes):
        address = int(node["item_address"], 0)
        raw = reader.item_raws[address]
        assert len(raw) == memory.ITEM_WIDTH
        node["item_raw_hex"] = raw.hex()
        for projection in projections:
            projection[ordinal]["item_raw_hex"] = raw.hex()
        log_entry = next(
            entry for entry in record["observation"]["read_log"]
            if entry["label"] == f"country_modifiers.item_{ordinal}"
        )
        added_read_bytes += len(raw) - log_entry["size"]
        log_entry["size"] = len(raw)
        log_entry["raw_hex"] = raw.hex()
        log_entry["sha256"] = hashlib.sha256(raw).hexdigest()
    record["observation"]["read_budget"]["bytes_reserved"] += added_read_bytes

    assert memory.validate_record(record)


@pytest.mark.parametrize("width", [0x4F, 0x51, 0x7F, 0x81])
def test_item_snapshot_rejects_short_and_unrecognized_widths(width: int) -> None:
    reader = _reader()
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    node = deepcopy(record["observation"]["nodes"][0])
    node["item_raw_hex"] = "00" * width
    layout = memory._profile_layout(memory._load_profile())
    manager = int(record["observation"]["manager_pointer"], 0)

    assert not memory._validate_definition(node, layout, reader.module_base, manager)[0]
    invalid = deepcopy(record)
    invalid["observation"]["nodes"][0]["item_raw_hex"] = "00" * width
    assert not memory.validate_record(invalid)


def test_null_terminated_head_chain_and_cycle_boundary() -> None:
    reader = _reader()
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert record["observation"]["terminated"] is True
    assert record["observation"]["count_observed"] == 2

    cycle = _reader()
    first_node = int(cycle.module_base * 0 + 0x20050C69DE0)
    cycle.put(first_node + memory.NODE_NEXT_OFFSET, first_node.to_bytes(8, "little"))
    failed = memory.read_fields(cycle, cycle.module_base, cycle.country_pointer)
    assert failed["status"] == "unknown"
    assert failed["reason"] == "modifier_list_cycle_detected"


def test_bad_guard_rejects_before_head_or_manager_read() -> None:
    reader = _reader()
    profile = memory._load_profile()
    name, rva, _end, raw = next(item for item in memory._profile_code_guards(profile) if item[0] == "country_list_writer")
    bad = bytearray(raw)
    bad[0] ^= 0xFF
    reader.put(reader.module_base + rva, bytes(bad))
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert record["status"] == "unknown"
    assert record["reason"] == "runtime_code_guard_failed"
    assert not any("list_head" in label or "definition_manager_global" in label for _address, _size, label in reader.reads)


def test_validator_rejects_tampering_and_retraction() -> None:
    reader = _reader()
    record = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert memory.validate_record(record)
    tampered = deepcopy(record)
    tampered["values"]["modifiers"][0]["date_raw"] += 1
    assert not memory.validate_record(tampered)
    raw_tampered = deepcopy(record)
    raw_tampered["observation"]["nodes"][0]["item_raw_hex"] = "00" * memory.ITEM_WIDTH
    assert not memory.validate_record(raw_tampered)
    retracted = memory.retract_record(record, "cleanup_failed")
    assert retracted["status"] == "unknown"
    assert not memory.validate_record(retracted)


def test_profile_v1_is_preserved_and_v2_is_pinned() -> None:
    assert OLD_PROFILE_PATH.exists()
    assert hashlib.sha256(OLD_PROFILE_PATH.read_bytes()).hexdigest() == OLD_PROFILE_SHA256
    profile = memory._load_profile()
    assert profile["profile_id"] == "country-modifiers-memory-1374-v2"
    layout = memory._profile_layout(profile)
    assert layout["item_width"] == 0x80
    assert memory.ITEM_WIDTH == 0x80
    assert memory.LIVE_ITEM_PREFIX_WIDTH == 0x50
    assert "country_list_head_offset" in layout
    assert "header_count_offset" not in layout


def test_profile_failure_and_budget_are_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader()
    monkeypatch.setattr(memory, "_load_profile", lambda: (_ for _ in ()).throw(memory.ProfileError("rejected")))
    failed = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert failed["status"] == "unknown"
    assert reader.reads == []
    monkeypatch.undo()

    reader = _reader()
    class TinyBudget(memory._ReadBudget):
        def __init__(self, _limit: int = memory.READ_BUDGET_BYTES):
            super().__init__(800)
    monkeypatch.setattr(memory, "_ReadBudget", TinyBudget)
    failed = memory.read_fields(reader, reader.module_base, reader.country_pointer)
    assert failed["status"] == "unknown"
    assert failed["reason"] == "runtime_code_guard_failed"
    assert failed["observation"]["read_budget"]["bytes_reserved"] == 686
