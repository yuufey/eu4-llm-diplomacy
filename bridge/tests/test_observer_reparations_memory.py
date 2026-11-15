"""Offline fake-memory tests for the private FRA reparations field adapter."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import bilateral_reparations_memory as leaf
from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import observer_reparations_memory as memory


BASE = 0x140000000
DATABASE = 0x6000000000
TABLE = 0x6100000000
WORLD = 0x6200000000
OBSERVER_SLOT = 19
TARGET_SLOT = 41
OBSERVER_POINTER = 0x50000000
TARGET_POINTER = 0x50001000
OBSERVER_ROWS = 0x6001000000
TARGET_ROWS = 0x6001100000
OBSERVER_OWNER = OBSERVER_POINTER + 0x14F8
TARGET_OWNER = TARGET_POINTER + 0x14F8
OBSERVER_ITEMS = 0x6001400000
TARGET_ITEMS = 0x6001500000
TREATY = 0x6001600000
DATE_RAW = 56_545_080
START_DATE = 56_545_080
END_DATE = 56_632_680


def _fullref(tag: str, slot: int, generation: int = 0x1234) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.error_at: set[int] = set()
        self.short_at: set[int] = set()
        self.mutate_after_read: tuple[str, int, bytes] | None = None

    def put(self, address: int, raw: bytes) -> None:
        self.data.update({address + offset: byte for offset, byte in enumerate(raw)})

    def put_u32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=False))

    def put_i32(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(4, "little", signed=True))

    def put_u64(self, address: int, value: int) -> None:
        self.put(address, value.to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.error_at:
            raise OSError("synthetic read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic unmapped bytes") from exc
        output = raw[:-1] if address in self.short_at else raw
        mutation = self.mutate_after_read
        if mutation is not None and mutation[0] == label:
            _label, mutation_address, mutation_bytes = mutation
            self.mutate_after_read = None
            self.put(mutation_address, mutation_bytes)
        return output


def _binding(tag: str, slot: int, pointer: int, generation: int) -> dict:
    fullref = _fullref(tag, slot, generation)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "country_fullref_address": hex(pointer + common.COUNTRY_FULLREF_OFFSET),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "table_entry_address": hex(TABLE + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
    }


def _put_vector(image: MemoryImage, owner: int, data_pointer: int,
                entries: list[tuple[int, int]], *, capacity: int | None = None) -> None:
    count = len(entries)
    actual_capacity = count if capacity is None else capacity
    vector = owner + leaf.OWNER_PAIR_VECTOR_OFFSET
    image.put_u64(vector + leaf.VECTOR_DATA_OFFSET,
                  data_pointer if actual_capacity else 0)
    image.put_i32(vector + leaf.VECTOR_CAPACITY_OFFSET, actual_capacity)
    image.put_i32(vector + leaf.VECTOR_COUNT_OFFSET, count)
    if count:
        raw = bytearray(count * leaf.VECTOR_ITEM_STRIDE)
        for index, (slot, pointer) in enumerate(entries):
            offset = index * leaf.VECTOR_ITEM_STRIDE
            raw[offset:offset + 4] = slot.to_bytes(4, "little", signed=True)
            raw[offset + 8:offset + 16] = pointer.to_bytes(8, "little", signed=False)
        image.put(data_pointer, bytes(raw))


def _put_relation(image: MemoryImage, observer: dict, target: dict) -> None:
    payer = int(observer["fullref"], 0)
    claimant = int(target["fullref"], 0)
    image.put_u64(TREATY, BASE + leaf.RELATION_TABLE_RVA)
    image.put_u32(TREATY + 8, leaf.RELATION_MARKER)
    image.put_u32(TREATY + 12, 0)
    image.put_u64(TREATY + leaf.RELATION_PAYER_OFFSET, payer)
    image.put_u64(TREATY + leaf.RELATION_CLAIMANT_OFFSET, claimant)
    image.put_i32(TREATY + leaf.RELATION_START_DATE_OFFSET, START_DATE)
    image.put_i32(TREATY + leaf.RELATION_END_DATE_OFFSET, END_DATE)


def _environment(*, present: bool = True) -> tuple[MemoryImage, dict, dict]:
    image = MemoryImage()
    observer = _binding("FRA", OBSERVER_SLOT, OBSERVER_POINTER, 0x1234)
    target = _binding("ENG", TARGET_SLOT, TARGET_POINTER, 0x2345)

    image.put_u64(BASE + common.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + common.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DATABASE + common.DATABASE_COUNT_OFFSET, TARGET_SLOT + 1)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, OBSERVER_POINTER)
    image.put_u64(TABLE + TARGET_SLOT * 8, TARGET_POINTER)
    image.put_u64(OBSERVER_POINTER + common.COUNTRY_FULLREF_OFFSET,
                  int(observer["fullref"], 0))
    image.put_u64(TARGET_POINTER + common.COUNTRY_FULLREF_OFFSET,
                  int(target["fullref"], 0))

    image.put_u64(BASE + memory.WORLD_GLOBAL_RVA, WORLD)
    image.put_i32(WORLD + memory.WORLD_DATE_OFFSET, DATE_RAW)

    observer_row = OBSERVER_ROWS + TARGET_SLOT * leaf.PAIR_ROW_STRIDE
    target_row = TARGET_ROWS + OBSERVER_SLOT * leaf.PAIR_ROW_STRIDE
    image.put_u64(OBSERVER_POINTER + leaf.COUNTRY_RELATION_ROWS_OFFSET, OBSERVER_ROWS)
    image.put_u64(TARGET_POINTER + leaf.COUNTRY_RELATION_ROWS_OFFSET, TARGET_ROWS)
    image.put_u64(observer_row + leaf.PAIR_OWNER_OFFSET, OBSERVER_OWNER)
    image.put_u64(observer_row + leaf.PAIR_SELF_FULLREF_OFFSET, int(observer["fullref"], 0))
    image.put_u64(observer_row + leaf.PAIR_OTHER_FULLREF_OFFSET, int(target["fullref"], 0))
    image.put_u64(target_row + leaf.PAIR_OWNER_OFFSET, TARGET_OWNER)
    image.put_u64(target_row + leaf.PAIR_SELF_FULLREF_OFFSET, int(target["fullref"], 0))
    image.put_u64(target_row + leaf.PAIR_OTHER_FULLREF_OFFSET, int(observer["fullref"], 0))
    _put_vector(image, OBSERVER_OWNER, OBSERVER_ITEMS,
                [(TARGET_SLOT, TREATY)] if present else [])
    _put_vector(image, TARGET_OWNER, TARGET_ITEMS,
                [(OBSERVER_SLOT, TREATY)] if present else [])
    if present:
        _put_relation(image, observer, target)
    return image, observer, target


def _permission(image: MemoryImage, observer: dict, target: dict) -> dict:
    return memory.read_permission(image, BASE, observer, target)


def test_permission_replays_exact_bytes_and_preserves_bound_world_date():
    image, observer, target = _environment()
    result = _permission(image, observer, target)
    assert result["schema"] == memory.SCHEMA
    assert result["basis"] == memory.BASIS
    assert result["scope"] == "observer_economy_bilateral_reparations"
    assert result["status"] == "known" and result["admitted"] is True
    assert result["raw_inputs"]["world"]["date_raw_i32"] == DATE_RAW
    assert result["raw_inputs"]["world"]["fresh_date_raw_i32"] == DATE_RAW
    assert [row["label"] for row in result["raw_inputs"]["pair_row_bindings"]] == [
        "observer_to_target", "target_to_observer"]
    assert result["raw_inputs"]["pair_row_bindings"][0]["owner"] == hex(OBSERVER_OWNER)
    assert result["raw_inputs"]["pair_row_bindings"][1]["owner"] == hex(TARGET_OWNER)
    assert result["raw_inputs"]["ordered_read_trace"]
    assert memory.validate_permission(result)
    assert memory.validate_permission(json.loads(json.dumps(result)))


@pytest.mark.parametrize(("direction", "corrupt"), [
    ("observer_to_target", "owner"),
    ("target_to_observer", "owner"),
    ("observer_to_target", "self_fullref"),
    ("target_to_observer", "other_fullref"),
])
def test_pair_row_permission_rejects_wrong_owner_or_refs_before_vector_or_contract_reads(
        direction: str, corrupt: str):
    image, observer, target = _environment(present=True)
    if direction == "observer_to_target":
        row_address = OBSERVER_ROWS + TARGET_SLOT * leaf.PAIR_ROW_STRIDE
        expected_owner = OBSERVER_OWNER
        expected_self = int(observer["fullref"], 0)
        expected_other = int(target["fullref"], 0)
    else:
        row_address = TARGET_ROWS + OBSERVER_SLOT * leaf.PAIR_ROW_STRIDE
        expected_owner = TARGET_OWNER
        expected_self = int(target["fullref"], 0)
        expected_other = int(observer["fullref"], 0)

    if corrupt == "owner":
        image.put_u64(row_address + leaf.PAIR_OWNER_OFFSET, expected_owner + 0x1000)
        reason = f"{direction.upper()}_PAIR_ROW_OWNER_MISMATCH"
    elif corrupt == "self_fullref":
        image.put_u64(row_address + leaf.PAIR_SELF_FULLREF_OFFSET, expected_self ^ 1)
        reason = f"{direction.upper()}_PAIR_ROW_FULLREF_MISMATCH"
    else:
        image.put_u64(row_address + leaf.PAIR_OTHER_FULLREF_OFFSET, expected_other ^ 1)
        reason = f"{direction.upper()}_PAIR_ROW_FULLREF_MISMATCH"

    permission = _permission(image, observer, target)
    assert permission["status"] == "unknown"
    assert permission["admitted"] is None
    assert permission["reason"] == reason
    assert memory.validate_permission(permission)
    labels = [label for _address, _size, label in image.reads]
    assert any(label == f"permission.pair.{direction}.row" for label in labels)
    assert "contract.relation_object" not in labels
    assert not any(".items[" in label for label in labels)

    before = len(image.reads)
    field = memory.read_fields(image, BASE, observer, target, [memory.FIELD],
                               permission=permission)[memory.FIELD]
    assert field["status"] == "unknown"
    assert len(image.reads) == before


def test_validator_rejects_bool_int_binding_date_extra_and_missing_trace_tampering():
    image, observer, target = _environment()
    result = _permission(image, observer, target)
    assert memory.validate_permission(result)

    changed = deepcopy(result)
    changed["admitted"] = 1
    assert not memory.validate_permission(changed)

    changed = deepcopy(result)
    changed["raw_inputs"]["request"]["target_binding"]["slot"] = TARGET_SLOT + 1
    assert not memory.validate_permission(changed)

    changed = deepcopy(result)
    changed["raw_inputs"]["world"]["date_raw_i32"] = DATE_RAW + 1
    assert not memory.validate_permission(changed)

    changed = deepcopy(result)
    changed["raw_inputs"]["request"]["module_base"] = BASE + 0x1000
    assert not memory.validate_permission(changed)

    changed = deepcopy(result)
    changed["raw_inputs"]["ordered_read_trace"].pop()
    assert not memory.validate_permission(changed)

    changed = deepcopy(result)
    changed["raw_inputs"]["ordered_read_trace"].append(
        deepcopy(result["raw_inputs"]["ordered_read_trace"][-1]))
    assert not memory.validate_permission(changed)

    changed = deepcopy(result)
    changed["unexpected"] = "not part of the permission schema"
    assert not memory.validate_permission(changed)

    changed = deepcopy(result)
    decoded = changed["raw_inputs"]["ordered_read_trace"][0]
    decoded["size"] = True
    assert not memory.validate_permission(changed)


def test_read_fields_reads_present_pair_only_after_fresh_matching_permission():
    image, observer, target = _environment(present=True)
    permission = _permission(image, observer, target)
    result = memory.read_fields(image, BASE, observer, target, [memory.FIELD],
                               permission=permission)
    field = result[memory.FIELD]
    assert field["status"] == "known"
    assert field["partial"] is True and field["complete"] is False
    assert field["unit"] == "bilateral_reparations_relation"
    assert field["value"]["status"] == "known"
    assert field["value"]["payer"]["tag"] == "FRA"
    assert field["value"]["claimant"]["tag"] == "ENG"
    assert field["value"]["date_window_contains_observed_date"] is True
    assert field["value"]["active_payment_obligation"]["status"] == "unknown"
    assert field["value"]["payment_amount"]["status"] == "unknown"
    assert "relation_flag_0x28" in field["value"]
    assert field["raw_inputs"]["state"]["complete_country_contracts"] is False
    labels = [label for _address, _size, label in image.reads]
    assert "world.fresh_date_i32" in labels
    assert "pair.observer_to_target.vector_header" in labels
    assert "contract.relation_object" in labels
    assert not any("0x28" in label for label in labels)


def test_absent_pair_is_known_only_for_the_requested_fra_target_pair():
    image, observer, target = _environment(present=False)
    permission = _permission(image, observer, target)
    result = memory.read_fields(image, BASE, observer, target, memory.FIELD,
                               permission=permission)
    field = result[memory.FIELD]
    assert field["status"] == "known"
    assert field["value"]["status"] == "absent"
    assert field["value"]["present"] is False
    assert field["value"]["scope"] == "explicit_observer_target_pair_only"
    assert field["raw_inputs"]["state"]["complete_country_contracts"] is False


def test_pair_vector_owner_must_match_economy_page_country_subobject():
    image, observer, target = _environment(present=True)
    permission = _permission(image, observer, target)
    observer_row = OBSERVER_ROWS + TARGET_SLOT * leaf.PAIR_ROW_STRIDE
    alternate_owner = OBSERVER_OWNER + 0x2000
    alternate_vector = alternate_owner + leaf.OWNER_PAIR_VECTOR_OFFSET
    image.put_u64(alternate_vector + leaf.VECTOR_DATA_OFFSET, OBSERVER_ITEMS)
    image.put_i32(alternate_vector + leaf.VECTOR_CAPACITY_OFFSET, 1)
    image.put_i32(alternate_vector + leaf.VECTOR_COUNT_OFFSET, 1)
    # Fresh permission sees the genuine row and then the fake changes the
    # owner before the leaf reads it. The post-leaf check must still reject.
    image.mutate_after_read = (
        "permission.pair.target_to_observer.row",
        observer_row + leaf.PAIR_OWNER_OFFSET,
        alternate_owner.to_bytes(8, "little"),
    )

    result = memory.read_fields(image, BASE, observer, target, [memory.FIELD],
                               permission=permission)
    field = result[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "PAIR_OWNER_NOT_ECONOMY_VECTOR"
    assert field["raw_inputs"]["state"]["status"] == "known"
    assert field["raw_inputs"]["state"]["contract"]["present"] is True


def test_leaf_unknown_is_not_promoted_to_a_known_contract():
    image, observer, target = _environment(present=True)
    permission = _permission(image, observer, target)
    # Corrupt the relation marker after permission; pair-row revalidation still
    # passes, while the real leaf must fail and the adapter must not preserve a
    # half contract.
    image.put_u32(TREATY + 8, leaf.RELATION_MARKER ^ 1)
    result = memory.read_fields(image, BASE, observer, target, [memory.FIELD],
                               permission=permission)
    field = result[memory.FIELD]
    assert field["status"] == "unknown"
    assert field["raw_inputs"]["state"]["status"] == "unknown"
    assert field["raw_inputs"]["state"]["contract"]["status"] == "unknown"


def test_invalid_permission_mismatched_binding_or_stale_date_never_enters_leaf():
    image, observer, target = _environment()
    permission = _permission(image, observer, target)
    before = len(image.reads)
    unknown_permission = deepcopy(permission)
    unknown_permission["admitted"] = True
    unknown_permission["status"] = "unknown"
    denied = memory.read_fields(image, BASE, observer, target, [memory.FIELD],
                                permission=unknown_permission)
    assert denied[memory.FIELD]["status"] == "unknown"
    assert len(image.reads) == before

    changed_target = _binding("SCO", TARGET_SLOT, TARGET_POINTER, 0x2345)
    mismatch = memory.read_fields(image, BASE, observer, changed_target,
                                  [memory.FIELD], permission=permission)
    assert mismatch[memory.FIELD]["status"] == "unknown"
    assert len(image.reads) == before

    image.put_i32(WORLD + memory.WORLD_DATE_OFFSET, DATE_RAW + 1)
    stale = memory.read_fields(image, BASE, observer, target, [memory.FIELD],
                               permission=permission)
    assert stale[memory.FIELD]["status"] == "unknown"
    assert stale[memory.FIELD]["reason"] == "REPARATIONS_PERMISSION_STALE"
    labels_after = [label for _address, _size, label in image.reads[before:]]
    assert not any(label.startswith("pair.") or label == "contract.relation_object"
                   for label in labels_after)


@pytest.mark.parametrize("bad_base", [True, 0x140000001])
def test_bad_base_permission_is_unknown_and_replayable(bad_base: int):
    image, observer, target = _environment()
    result = memory.read_permission(image, bad_base, observer, target)
    assert result["status"] == "unknown"
    assert image.reads == []
    assert memory.validate_permission(result)


def test_unknown_permission_from_short_read_is_valid_and_does_not_read_pair():
    image, observer, target = _environment()
    image.short_at.add(BASE + memory.WORLD_GLOBAL_RVA)
    permission = _permission(image, observer, target)
    assert permission["status"] == "unknown"
    assert memory.validate_permission(permission)
    before = len(image.reads)
    result = memory.read_fields(image, BASE, observer, target, [memory.FIELD],
                               permission=permission)
    assert result[memory.FIELD]["status"] == "unknown"
    assert len(image.reads) == before

