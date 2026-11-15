from __future__ import annotations

import struct

import pytest

from bridge.information import province_node_allocation_memory as memory
from bridge.information import trade_value_memory


BASE = 0x140000000
RECORDS = 0x300000
RUNTIME = 0x600000
DEFINITION = 0x700000
NODE_VECTOR = 0x710000
BITSET = 0x720000
TABLE = 0x730000
PROVINCE_COUNT = 8
STRIDE = 0x2E10
FRA_SLOT = 3
ENG_SLOT = 5


def _q(value: int) -> bytes:
    return struct.pack("<Q", value)


def _i(value: int) -> bytes:
    return struct.pack("<i", value)


def _fullref(tag: str, slot: int, generation: int = 1) -> int:
    low = int.from_bytes(tag.encode("ascii") + b"\0", "little")
    return (generation << 56) | (slot << 32) | low


FRA_FULLREF = _fullref("FRA", FRA_SLOT)
ENG_FULLREF = _fullref("ENG", ENG_SLOT)


def _country_binding(tag: str, slot: int, fullref: int) -> dict[str, object]:
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(0x740000 + slot * 0x100),
        "fullref": hex(fullref),
        "fullref_raw_hex": _q(fullref).hex(),
    }


def _province_binding(province_id: int) -> dict[str, object]:
    record = RECORDS + province_id * STRIDE
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": _i(province_id).hex(),
    }


class FakeMemory:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_addresses: set[int] = set()
        self.overrides: list[tuple[str, int, bytes]] = []

    def write(self, address: int, data: bytes) -> None:
        for offset, byte in enumerate(data):
            self.bytes[address + offset] = byte

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        for prefix, override_address, override in self.overrides:
            if label.startswith(prefix) and address == override_address and len(override) == size:
                return override
        try:
            result = bytes(self.bytes[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError(f"unmapped:{address:#x}:{size}:{label}") from exc
        if address in self.short_addresses:
            return result[:-1]
        return result


def _identity(center: int, *, province_base: int = RECORDS) -> dict[str, object]:
    return {
        "manager_pointer": hex(0x750000),
        "definitions_begin": hex(0x751000),
        "definitions_end": hex(0x751008),
        "definition_count": 1,
        "definition_vector_raw_hex": _q(DEFINITION).hex(),
        "selected_definition": {"definition_pointer": hex(DEFINITION), "node_id": "node_test"},
        "province_base_pointer": hex(province_base),
        "selected_center_province_id": center,
        "runtime_pointer": hex(RUNTIME),
        "runtime_definition_pointer": hex(DEFINITION),
    }


def _install_find_node_stub(monkeypatch, *, center: int = 1, province_base: int = RECORDS):
    calls: list[str] = []

    def find_node(reader, base, node_id):
        calls.append(node_id)
        return {
            "status": "known",
            "node_id": node_id,
            "center_province_id": center,
            "runtime_pointer": hex(RUNTIME),
            "definition_pointer": hex(DEFINITION),
            "raw_inputs": {"identity": _identity(center, province_base=province_base)},
        }

    monkeypatch.setattr(trade_value_memory, "find_node", find_node)
    return calls


def make_fixture(
    monkeypatch,
    *,
    selected_id: int = 2,
    center_id: int = 1,
    member_ids: tuple[int, ...] = (1, 2, 3),
    controllers: dict[int, int] | None = None,
    owners: dict[int, int] | None = None,
    powers: dict[int, int] | None = None,
    discovered: dict[int, bool] | None = None,
    cache_value: int = 22,
    province_base: int = RECORDS,
):
    reader = FakeMemory()
    controllers = controllers or {}
    owners = owners or {}
    powers = powers or {}
    discovered = discovered or {}
    calls = _install_find_node_stub(monkeypatch, center=center_id, province_base=province_base)

    header = bytearray(0x30)
    key_obj = bytearray(32)
    node_key = b"node_test"
    key_obj[:len(node_key) + 1] = node_key + b"\0"
    struct.pack_into("<Q", key_obj, 0x10, len(node_key))
    struct.pack_into("<Q", key_obj, 0x18, 15)
    header[0x10:0x30] = key_obj
    reader.write(DEFINITION, header)
    reader.write(DEFINITION + 0x68, _q(NODE_VECTOR) + _q(NODE_VECTOR + len(member_ids) * 8))
    reader.write(NODE_VECTOR, b"".join(_q(RECORDS + pid * STRIDE) for pid in member_ids))

    selected_record = RECORDS + selected_id * STRIDE
    for province_id in set(member_ids) | {selected_id, center_id}:
        record = RECORDS + province_id * STRIDE
        reader.write(record + 0x20, _i(province_id))
        reader.write(record + 0xE8, _q(RUNTIME))
        bitset = BITSET + province_id * 0x100
        reader.write(record + 0x5E0, _q(bitset))
        controller = controllers.get(province_id, FRA_FULLREF)
        reader.write(record + 0x470, _q(controller))
        owner = owners.get(province_id, 1)
        reader.write(record + 0x46F, bytes([owner]))
        if owner:
            reader.write(record + 0x890, _i(powers.get(province_id, 0)))

    for province_id in member_ids:
        word = (1 << FRA_SLOT) if discovered.get(province_id, True) else 0
        reader.write(BITSET + province_id * 0x100, struct.pack("<I", word))

    reader.write(RUNTIME + 0xA8, _q(DEFINITION))
    reader.write(RUNTIME + 0x18, _q(TABLE))
    reader.write(RUNTIME + 0x24, _i(16))
    reader.write(TABLE + FRA_SLOT * 0xC0 + 0x28, _i(cache_value))

    province_scan = {
        "status": "observed",
        "header": {
            "records_pointer": hex(RECORDS),
            "count": PROVINCE_COUNT,
            "records_range": [hex(RECORDS), hex(RECORDS + PROVINCE_COUNT * STRIDE)],
        },
        "requested": {str(selected_id): _province_binding(selected_id)},
    }
    binding = _province_binding(selected_id)
    observer = _country_binding("FRA", FRA_SLOT, FRA_FULLREF)
    controller_tag = "FRA" if controllers.get(selected_id, FRA_FULLREF) == FRA_FULLREF else "ENG"
    controller_ref = FRA_FULLREF if controller_tag == "FRA" else ENG_FULLREF
    controller_slot = FRA_SLOT if controller_tag == "FRA" else ENG_SLOT
    controller_binding = _country_binding(controller_tag, controller_slot, controller_ref)
    return reader, binding, province_scan, observer, controller_binding, calls


def _component(args) -> dict[str, object]:
    reader, binding, scan, observer, controller, _calls = args
    return memory.read_fields(reader, BASE, binding, scan, observer, controller)[memory.FIELD]


def test_noncenter_member_binds_to_loaded_definition_and_uses_find_node_once_per_pass(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(1, 2, 3), powers={1: 5, 2: 7, 3: 10},
                        cache_value=22)
    field = _component(args)
    assert field["status"] == "known"
    value = field["value"]
    assert value["province_id"] == 2
    assert value["center_province_id"] == 1
    assert value["center_province_id"] != value["province_id"]
    assert value["node_id"] == "node_test"
    assert value["recipient_country"] == "FRA"
    assert value["contribution_raw"] == 7
    assert value["observer_contribution_raw"] == 7
    assert value["observed_observer_province_power_sum_raw"] == 22
    assert value["observer_sum_complete"] is True
    assert value["matches_observer_cache"] is True
    assert value["member_count"] == value["observed_member_count"] == 3
    assert args[-1] == ["node_test", "node_test"]


def test_non_fra_recipient_has_zero_observer_contribution_and_no_foreign_cache_read(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2, 3),
                        controllers={2: ENG_FULLREF, 3: FRA_FULLREF},
                        powers={2: -4, 3: 6}, cache_value=6)
    field = _component(args)
    assert field["status"] == "known"
    assert field["value"]["recipient_country"] == "ENG"
    assert field["value"]["contribution_raw"] == -4
    assert field["value"]["observer_contribution_raw"] == 0
    assert field["value"]["observed_observer_province_power_sum_raw"] == 6
    observer_cell = TABLE + FRA_SLOT * 0xC0 + 0x28
    foreign_cell = TABLE + ENG_SLOT * 0xC0 + 0x28
    addresses = [address for address, _size, _label in args[0].reads]
    assert observer_cell in addresses
    assert foreign_cell not in addresses


def test_owner_absent_is_zero_and_skips_province_trade_power_read(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), owners={2: 0}, powers={2: 91}, cache_value=0)
    field = _component(args)
    assert field["status"] == "known"
    assert field["value"]["owner_present"] is False
    assert field["value"]["contribution_raw"] == 0
    assert field["value"]["observer_contribution_raw"] == 0
    assert not any(address == RECORDS + 2 * STRIDE + 0x890 for address, _size, _label in args[0].reads)


def test_observer_sum_uses_signed_i32_wrap(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2, 3), powers={2: 0x7FFFFFFF, 3: 1},
                        cache_value=-(1 << 31))
    field = _component(args)
    assert field["status"] == "known"
    assert field["value"]["observed_observer_province_power_sum_raw"] == -(1 << 31)
    assert field["value"]["matches_observer_cache"] is True


def test_undiscovered_member_is_not_read_for_controller_owner_or_power(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2, 3), powers={2: 4, 3: 99},
                        discovered={2: True, 3: False}, cache_value=4)
    field = _component(args)
    assert field["status"] == "known"
    value = field["value"]
    assert value["observer_sum_complete"] is False
    assert value["matches_observer_cache"] is None
    assert value["observed_observer_province_power_sum_raw"] == 4
    assert value["observed_member_count"] == 1
    undiscovered = RECORDS + 3 * STRIDE
    forbidden = {undiscovered + 0x470, undiscovered + 0x46F, undiscovered + 0x890}
    assert not forbidden.intersection(address for address, _size, _label in args[0].reads)


def test_same_slot_different_fra_fullref_makes_sum_incomplete_without_reading_owner(monkeypatch):
    other_fra_ref = _fullref("FRA", FRA_SLOT, generation=2)
    args = make_fixture(monkeypatch, member_ids=(2, 3),
                        controllers={2: FRA_FULLREF, 3: other_fra_ref},
                        powers={2: 4, 3: 99}, cache_value=4)
    field = _component(args)
    assert field["status"] == "known"
    assert field["value"]["observer_sum_complete"] is False
    assert field["value"]["matches_observer_cache"] is None
    ambiguous = RECORDS + 3 * STRIDE
    assert not any(address in {ambiguous + 0x46F, ambiguous + 0x890}
                   for address, _size, _label in args[0].reads)


def test_cache_mismatch_is_a_known_result_with_false_match(monkeypatch):
    args = make_fixture(monkeypatch, powers={1: 5, 2: 7, 3: 10}, cache_value=21)
    field = _component(args)
    assert field["status"] == "known"
    assert field["value"]["matches_observer_cache"] is False
    assert field["value"]["observer_node_province_power_cache_raw"] == 21
    assert field["value"]["observed_observer_province_power_sum_raw"] == 22


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("member_id", "membership_id_invalid"),
        ("member_runtime", "member_runtime_mismatch"),
        ("duplicate_member", "membership_vector_invalid"),
        ("missing_selected", "selected_member_missing"),
        ("center_id", "center_identity_invalid"),
    ],
)
def test_member_and_center_structural_failures_are_unknown(monkeypatch, mutation, expected_reason):
    args = make_fixture(monkeypatch, member_ids=(1, 2, 3), powers={1: 5, 2: 7, 3: 10})
    reader = args[0]
    if mutation == "member_id":
        reader.write(RECORDS + 3 * STRIDE + 0x20, _i(4))
    elif mutation == "member_runtime":
        reader.write(RECORDS + 3 * STRIDE + 0xE8, _q(RUNTIME + 0x1000))
    elif mutation == "duplicate_member":
        reader.write(NODE_VECTOR, _q(RECORDS + STRIDE) + _q(RECORDS + 2 * STRIDE)
                     + _q(RECORDS + 2 * STRIDE))
    elif mutation == "missing_selected":
        reader.write(DEFINITION + 0x68, _q(NODE_VECTOR) + _q(NODE_VECTOR + 16))
        reader.write(NODE_VECTOR, _q(RECORDS + STRIDE) + _q(RECORDS + 3 * STRIDE))
    elif mutation == "center_id":
        reader.write(RECORDS + STRIDE + 0x20, _i(4))
    field = _component(args)
    assert field["status"] == "unknown"
    assert field["reason"] == expected_reason


def test_selected_controller_must_match_the_strict_binding(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2, 3), controllers={2: ENG_FULLREF, 3: FRA_FULLREF},
                        powers={2: 4, 3: 6})
    controller = _country_binding("FRA", FRA_SLOT, FRA_FULLREF)
    field = memory.read_fields(args[0], BASE, args[1], args[2], args[3], controller)[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "selected_controller_mismatch"


def test_bad_cache_count_blocks_table_read(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), powers={2: 4})
    args[0].write(RUNTIME + 0x24, _i(3))
    field = _component(args)
    assert field["status"] == "unknown"
    assert field["reason"] == "cache_header_invalid"
    assert not any(address == TABLE + FRA_SLOT * 0xC0 + 0x28
                   for address, _size, _label in args[0].reads)


def test_snapshot_drift_retracts_allocation(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), powers={2: 4}, cache_value=4)
    selected_power_address = RECORDS + 2 * STRIDE + 0x890
    args[0].overrides.append(("node_allocation.pass2.", selected_power_address, _i(5)))
    field = _component(args)
    assert field["status"] == "unknown"
    assert field["reason"] == "snapshot_drift"


def test_shared_read_budget_failure_is_unknown(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), powers={2: 4}, cache_value=4)

    def expensive_find_node(reader, base, node_id):
        args[0].write(0x760000, bytes(5000))
        for index in range(5000):
            reader.read(0x760000 + index, 1, "test.consume_budget")
        raise AssertionError("reader budget should stop the test graph walk")

    monkeypatch.setattr(trade_value_memory, "find_node", expensive_find_node)
    field = _component(args)
    assert field["status"] == "unknown"
    assert field["reason"] == "read_budget_exceeded"
    assert field["raw_inputs"]["read_budget"]["calls"] <= 4096


def test_invalid_observer_or_same_slot_generation_binding_is_rejected_without_reads(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), powers={2: 4})
    reader, binding, scan, observer, controller, _calls = args
    not_fra = _country_binding("ENG", ENG_SLOT, ENG_FULLREF)
    field = memory.read_fields(reader, BASE, binding, scan, not_fra, controller)[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "binding_invalid"
    assert reader.reads == []

    other_fra_ref = _fullref("FRA", FRA_SLOT, generation=2)
    other_generation = _country_binding("FRA", FRA_SLOT, other_fra_ref)
    field = memory.read_fields(reader, BASE, binding, scan, observer, other_generation)[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "binding_invalid"
    assert reader.reads == []


def test_candidate_definition_must_match_runtime_and_loaded_node(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), powers={2: 4})
    reader = args[0]
    _install_find_node_stub(monkeypatch, center=1)

    def mismatched(reader, base, node_id):
        return {
            "status": "known", "node_id": node_id, "center_province_id": 1,
            "runtime_pointer": hex(RUNTIME), "definition_pointer": hex(DEFINITION + 0x1000),
            "raw_inputs": {"identity": _identity(1)},
        }

    monkeypatch.setattr(trade_value_memory, "find_node", mismatched)
    field = _component(args)
    assert field["status"] == "unknown"
    assert field["reason"] == "node_identity_mismatch"


def test_nonmember_or_bad_definition_base_is_unknown(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), powers={2: 4}, province_base=RECORDS + 0x1000)
    field = _component(args)
    assert field["status"] == "unknown"
    assert field["reason"] == "province_base_mismatch"


def test_discovery_failure_never_reads_selected_ownership(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2,), powers={2: 4}, discovered={2: False})
    field = _component(args)
    assert field["status"] == "unknown"
    selected = RECORDS + 2 * STRIDE
    assert not any(address in {selected + 0x470, selected + 0x46F, selected + 0x890}
                   for address, _size, _label in args[0].reads)


def test_invalid_nonselected_controller_with_owner_absent_is_known_zero(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2, 3), controllers={2: FRA_FULLREF, 3: 0},
                        owners={2: 1, 3: 0}, powers={2: 4, 3: 99}, cache_value=4)
    field = _component(args)
    assert field["status"] == "known"
    value = field["value"]
    assert value["observer_sum_complete"] is True
    assert value["observed_observer_province_power_sum_raw"] == 4
    assert value["observed_member_count"] == 2
    assert value["matches_observer_cache"] is True
    invalid_member = RECORDS + 3 * STRIDE
    labels = [label for address, _size, label in args[0].reads
              if address == invalid_member + 0x46F]
    assert len(labels) == 2
    assert all("owner_high_byte_invalid_controller" in label for label in labels)
    assert not any(address == invalid_member + 0x890 for address, _size, _label in args[0].reads)
    assert all(row["observer_contribution_status"] == "known_owner_absent"
               for snapshot in field["raw_inputs"]["pass_summaries"]
               for row in snapshot["members"] if row["province_id"] == 3)


def test_invalid_nonselected_controller_with_owner_present_stays_incomplete_and_selected_invalid_rejects(monkeypatch):
    args = make_fixture(monkeypatch, member_ids=(2, 3), controllers={2: FRA_FULLREF, 3: 0},
                        owners={2: 1, 3: 1}, powers={2: 4, 3: 99}, cache_value=4)
    field = _component(args)
    assert field["status"] == "known"
    assert field["value"]["observer_sum_complete"] is False
    assert field["value"]["observed_observer_province_power_sum_raw"] == 4
    assert field["value"]["matches_observer_cache"] is None
    invalid_member = RECORDS + 3 * STRIDE
    assert any(address == invalid_member + 0x46F for address, _size, _label in args[0].reads)
    assert not any(address == invalid_member + 0x890 for address, _size, _label in args[0].reads)
    assert all(row["observer_contribution_status"] == "controller_invalid_owner_present"
               for snapshot in field["raw_inputs"]["pass_summaries"]
               for row in snapshot["members"] if row["province_id"] == 3)

    selected_args = make_fixture(monkeypatch, member_ids=(2,), controllers={2: 0},
                                 owners={2: 0}, powers={2: 99}, cache_value=0)
    selected_field = _component(selected_args)
    assert selected_field["status"] == "unknown"
    assert selected_field["reason"] == "selected_controller_invalid"
    selected = RECORDS + 2 * STRIDE
    assert not any(address in {selected + 0x46F, selected + 0x890}
                   for address, _size, _label in selected_args[0].reads)
