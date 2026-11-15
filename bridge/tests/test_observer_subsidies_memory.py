from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import bilateral_subsidies_memory as leaf
from bridge.information import foreign_quality_visibility_memory as common
from bridge.information import observer_subsidies_memory as memory


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
SUBSIDY = 0x6001600000
DATE_RAW = 56_545_080
LITERAL_NATIVE_ROW_STRIDE = 0x48


def _fullref(tag: str, slot: int, generation: int = 0x1234) -> int:
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.error_at: set[int] = set()
        self.short_at: set[int] = set()

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
        return raw[:-1] if address in self.short_at else raw


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
                entries: list[tuple[int, int]]) -> None:
    vector = owner + 0x108
    capacity = count = len(entries)
    image.put_u64(vector + 0x08, data_pointer if capacity else 0)
    image.put_i32(vector + 0x10, capacity)
    image.put_i32(vector + 0x14, count)
    if entries:
        raw = bytearray(count * 0x10)
        for index, (slot, pointer) in enumerate(entries):
            offset = index * 0x10
            raw[offset:offset + 4] = slot.to_bytes(4, "little", signed=True)
            raw[offset + 8:offset + 16] = pointer.to_bytes(8, "little", signed=False)
        image.put(data_pointer, bytes(raw))


def _put_row(image: MemoryImage, address: int, owner: int,
             self_ref: int, other_ref: int) -> None:
    image.put_u64(address, owner)
    image.put_u64(address + 8, self_ref)
    image.put_u64(address + 16, other_ref)


def _put_object(image: MemoryImage, observer: dict, target: dict, *,
                payer: str, amount: int, start: int, duration: int) -> None:
    image.put(SUBSIDY, bytes(0x48))
    image.put_u64(SUBSIDY, BASE + leaf.SUBSIDY_VTABLE_RVA)
    image.put_u32(SUBSIDY + 8, leaf.SUBSIDY_MARKER)
    image.put_u64(SUBSIDY + 0x10,
                  int(observer["fullref"], 0) if payer == "FRA"
                  else int(target["fullref"], 0))
    image.put_u64(SUBSIDY + 0x18,
                  int(target["fullref"], 0) if payer == "FRA"
                  else int(observer["fullref"], 0))
    image.put_i32(SUBSIDY + 0x20, start)
    image.put_i32(SUBSIDY + 0x40, amount)
    image.put_i32(SUBSIDY + 0x44, duration)


def _environment(*, target_tag: str = "ENG", present: bool = True,
                  payer: str = "FRA", amount: int = -2_500,
                  start: int = DATE_RAW, duration: int = 2) -> tuple[MemoryImage, dict, dict, dict]:
    image = MemoryImage()
    observer = _binding("FRA", OBSERVER_SLOT, OBSERVER_POINTER, 0x1234)
    target = _binding(target_tag, TARGET_SLOT, TARGET_POINTER, 0x2345)
    observer_ref = int(observer["fullref"], 0)
    target_ref = int(target["fullref"], 0)

    image.put_u64(BASE + common.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + common.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DATABASE + common.DATABASE_COUNT_OFFSET, TARGET_SLOT + 1)
    image.put_u64(TABLE + OBSERVER_SLOT * 8, OBSERVER_POINTER)
    image.put_u64(TABLE + TARGET_SLOT * 8, TARGET_POINTER)
    image.put_u64(OBSERVER_POINTER + common.COUNTRY_FULLREF_OFFSET, observer_ref)
    image.put_u64(TARGET_POINTER + common.COUNTRY_FULLREF_OFFSET, target_ref)

    image.put_u64(BASE + memory.WORLD_GLOBAL_RVA, WORLD)
    image.put_i32(WORLD + memory.WORLD_DATE_OFFSET, DATE_RAW)

    image.put_u64(OBSERVER_POINTER + leaf.SUBSIDY_RELATION_ROWS_OFFSET, OBSERVER_ROWS)
    image.put_u64(TARGET_POINTER + leaf.SUBSIDY_RELATION_ROWS_OFFSET, TARGET_ROWS)
    # Literal native layout: do not derive fixture addresses from leaf constants.
    observer_row = OBSERVER_ROWS + TARGET_SLOT * LITERAL_NATIVE_ROW_STRIDE
    target_row = TARGET_ROWS + OBSERVER_SLOT * LITERAL_NATIVE_ROW_STRIDE
    _put_row(image, observer_row, OBSERVER_OWNER, observer_ref, target_ref)
    _put_row(image, target_row, TARGET_OWNER, target_ref, observer_ref)
    _put_vector(image, OBSERVER_OWNER, OBSERVER_ITEMS,
                [(TARGET_SLOT, SUBSIDY)] if present else [])
    _put_vector(image, TARGET_OWNER, TARGET_ITEMS,
                [(OBSERVER_SLOT, SUBSIDY)] if present else [])
    if present:
        _put_object(image, observer, target, payer=payer, amount=amount,
                    start=start, duration=duration)
    return image, observer, target, {
        "observer_row": observer_row,
        "target_row": target_row,
        "observer_owner": OBSERVER_OWNER,
        "target_owner": TARGET_OWNER,
    }


def _permission(image: MemoryImage, observer: dict, target: dict) -> dict:
    return memory.read_permission(image, BASE, observer, target)


def _field(image: MemoryImage, observer: dict, target: dict,
           permission: dict, fields=memory.FIELD) -> dict:
    return memory.read_fields(image, BASE, observer, target, fields,
                              permission=permission)[memory.FIELD]


def test_permission_replays_ordered_pair_rows_and_world_date_without_vector_reads():
    image, observer, target, addresses = _environment()
    permission = _permission(image, observer, target)

    assert permission["schema"] == "information.observer_subsidies_memory.v1"
    assert permission["basis"] == "private_native_fra_own_fiscal_subsidy_pair"
    assert permission["scope"] == "observer_fiscal_bilateral_subsidies"
    assert permission["status"] == "known" and permission["admitted"] is True
    assert permission["partial"] is True and permission["complete"] is False
    assert permission["actual_UI_observed"] is False
    assert permission["raw_inputs"]["scope_evidence"]["does_not_establish"]
    assert permission["raw_inputs"]["world"]["date_raw_i32"] == DATE_RAW
    assert permission["raw_inputs"]["world"]["fresh_date_raw_i32"] == DATE_RAW
    rows = permission["raw_inputs"]["pair_row_bindings"]
    assert [row["row_address"] for row in rows] == [
        hex(OBSERVER_ROWS + TARGET_SLOT * 0x48),
        hex(TARGET_ROWS + OBSERVER_SLOT * 0x48),
    ]
    assert rows[0]["owner"] == hex(OBSERVER_OWNER)
    assert rows[1]["owner"] == hex(TARGET_OWNER)
    labels = [label for _address, _size, label in image.reads]
    assert not any("vector" in label or ".items[" in label
                   or label == "contract.relation_object" for label in labels)
    assert memory.validate_permission(permission)
    assert memory.validate_permission(json.loads(json.dumps(permission)))
    assert addresses["observer_row"] == OBSERVER_ROWS + TARGET_SLOT * 0x48


@pytest.mark.parametrize(("direction", "corrupt", "reason"), [
    ("observer_to_target", "owner", "OBSERVER_TO_TARGET_PAIR_ROW_OWNER_MISMATCH"),
    ("target_to_observer", "owner", "TARGET_TO_OBSERVER_PAIR_ROW_OWNER_MISMATCH"),
    ("observer_to_target", "self_ref", "OBSERVER_TO_TARGET_PAIR_ROW_FULLREF_MISMATCH"),
    ("target_to_observer", "other_ref", "TARGET_TO_OBSERVER_PAIR_ROW_FULLREF_MISMATCH"),
])
def test_permission_rejects_bad_owner_or_refs_before_any_vector_reads(
        direction: str, corrupt: str, reason: str):
    image, observer, target, addresses = _environment()
    row = addresses["observer_row"] if direction == "observer_to_target" else addresses["target_row"]
    expected_owner = OBSERVER_OWNER if direction == "observer_to_target" else TARGET_OWNER
    if corrupt == "owner":
        image.put_u64(row, expected_owner + 0x1000)
    elif corrupt == "self_ref":
        image.put_u64(row + 8, int(observer["fullref" if direction == "observer_to_target"
                                             else "fullref"], 0) ^ 1)
    else:
        image.put_u64(row + 16, int(observer["fullref" if direction == "target_to_observer"
                                             else "fullref"], 0) ^ 1)

    permission = _permission(image, observer, target)
    assert permission["status"] == "unknown"
    assert permission["reason"] == reason
    assert memory.validate_permission(permission)
    labels = [label for _address, _size, label in image.reads]
    assert not any("vector" in label or ".items[" in label
                   or label == "contract.relation_object" for label in labels)


def test_permission_validator_rejects_bool_int_and_ordered_trace_tampering():
    image, observer, target, _ = _environment()
    permission = _permission(image, observer, target)
    assert memory.validate_permission(permission)

    changed = deepcopy(permission)
    changed["admitted"] = 1
    assert not memory.validate_permission(changed)

    changed = deepcopy(permission)
    changed["raw_inputs"]["request"]["target_binding"]["slot"] = True
    assert not memory.validate_permission(changed)

    changed = deepcopy(permission)
    changed["raw_inputs"]["world"]["date_raw_i32"] = True
    assert not memory.validate_permission(changed)

    changed = deepcopy(permission)
    changed["raw_inputs"]["ordered_read_trace"][0]["size"] = True
    assert not memory.validate_permission(changed)

    changed = deepcopy(permission)
    changed["raw_inputs"]["ordered_read_trace"].pop()
    assert not memory.validate_permission(changed)

    changed = deepcopy(permission)
    changed["unexpected"] = "not part of permission schema"
    assert not memory.validate_permission(changed)


def test_irrelevant_request_has_zero_reads_even_without_valid_permission():
    image, observer, target, _ = _environment()
    assert memory.read_fields(image, BASE, observer, target, ["F03.income"],
                              permission=None) == {}
    assert image.reads == []


@pytest.mark.parametrize("stale_kind", ["owner", "date", "fullref"])
def test_stale_owner_date_or_ref_never_enters_subsidy_leaf(stale_kind: str):
    image, observer, target, addresses = _environment()
    permission = _permission(image, observer, target)
    assert permission["status"] == "known"
    before = len(image.reads)

    if stale_kind == "owner":
        image.put_u64(addresses["observer_row"], OBSERVER_OWNER + 0x1000)
    elif stale_kind == "date":
        image.put_i32(WORLD + memory.WORLD_DATE_OFFSET, DATE_RAW + 1)
    else:
        image.put_u64(OBSERVER_POINTER + common.COUNTRY_FULLREF_OFFSET,
                      int(observer["fullref"], 0) ^ 1)

    field = _field(image, observer, target, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "SUBSIDIES_PERMISSION_STALE"
    assert field["raw_inputs"]["state"] is None
    new_labels = [label for _address, _size, label in image.reads[before:]]
    assert not any("vector" in label or ".items[" in label
                   or label == "contract.relation_object" for label in new_labels)


def test_invalid_or_unknown_permission_does_not_read_vectors_or_contract():
    image, observer, target, _ = _environment()
    permission = _permission(image, observer, target)
    before = len(image.reads)

    changed = deepcopy(permission)
    changed["admitted"] = False
    denied = _field(image, observer, target, changed)
    assert denied["status"] == "unknown"
    assert denied["reason"] == "SUBSIDIES_PERMISSION_INVALID"
    assert len(image.reads) == before

    failed_image, observer, target, _ = _environment()
    failed_image.short_at.add(BASE + memory.WORLD_GLOBAL_RVA)
    unknown_permission = _permission(failed_image, observer, target)
    assert unknown_permission["status"] == "unknown"
    assert memory.validate_permission(unknown_permission)
    before = len(failed_image.reads)
    denied = _field(failed_image, observer, target, unknown_permission)
    assert denied["status"] == "unknown"
    assert denied["reason"] == "SUBSIDIES_PERMISSION_NOT_ADMITTED"
    assert len(failed_image.reads) == before


def test_logical_fra_observer_remains_distinct_from_physical_por():
    image, observer, por_target, _ = _environment(target_tag="POR", payer="FRA")
    permission = _permission(image, observer, por_target)
    assert permission["status"] == "known"
    assert permission["observer"]["tag"] == "FRA"
    assert permission["target"]["tag"] == "POR"
    assert permission["scope"] == "observer_fiscal_bilateral_subsidies"
    assert permission["raw_inputs"]["scope_evidence"]["physical_client_country_is_not_inferred"] is True

    physical_por = _binding("POR", OBSERVER_SLOT, 0x50002000, 0x4567)
    rejected = _permission(image, physical_por, por_target)
    assert rejected["status"] == "unknown"
    assert rejected["reason"] == "OBSERVER_MUST_BE_FRA"


@pytest.mark.parametrize("payer", ["FRA", "ENG"])
def test_known_dto_passes_signed_leaf_terms_and_current_capture_pair(payer: str):
    image, observer, target, _ = _environment(
        payer=payer, amount=-2_500, start=DATE_RAW - 24, duration=-3,
    )
    permission = _permission(image, observer, target)
    field = _field(image, observer, target, permission, [memory.FIELD])

    assert field["status"] == "known"
    assert field["basis"] == "private_native_fra_own_fiscal_subsidy_pair"
    assert field["partial"] is True and field["complete"] is False
    assert field["unit"] == "bilateral_subsidies_relation"
    assert field["scale"] == 1 and field["period"] == "current"
    contract = field["value"]
    assert contract["status"] == "known" and contract["present"] is True
    assert contract["payer"]["tag"] == payer
    assert contract["monthly_nominal_amount"]["raw"] == -2_500
    assert contract["monthly_nominal_amount"]["value"] == -2.5
    assert contract["start_date"]["raw"] == DATE_RAW - 24
    assert contract["duration_years"]["raw"] == -3
    assert contract["active_payment_obligation"]["status"] == "unknown"
    assert contract["relation_flag_0x28"]["status"] == "unknown"
    assert field["raw_inputs"]["permission"]["raw_inputs"]["world"]["date_raw_i32"] == DATE_RAW
    assert field["raw_inputs"]["state"]["complete_country_contracts"] is False


def test_absent_dto_is_pair_only_and_keeps_unknown_obligation():
    image, observer, target, _ = _environment(present=False)
    permission = _permission(image, observer, target)
    field = _field(image, observer, target, permission)

    assert field["status"] == "known"
    assert field["unit"] == "bilateral_subsidies_relation"
    assert field["scale"] == 1 and field["period"] == "current"
    assert field["value"]["status"] == "absent"
    assert field["value"]["present"] is False
    assert field["value"]["scope"] == "explicit_observer_target_pair_only"
    assert field["value"]["active_payment_obligation"]["status"] == "unknown"
    assert field["raw_inputs"]["state"]["complete_country_contracts"] is False


def test_leaf_unknown_is_not_promoted_to_known_wrapper():
    image, observer, target, _ = _environment()
    permission = _permission(image, observer, target)
    image.put_u32(SUBSIDY + 8, leaf.SUBSIDY_MARKER ^ 1)

    field = _field(image, observer, target, permission)
    assert field["status"] == "unknown"
    assert field["reason"] == "BILATERAL_SUBSIDIES_STATE_UNKNOWN"
    assert field["value"]["status"] == "unknown"
    assert field["raw_inputs"]["state"]["status"] == "unknown"


def test_non_fra_observer_and_same_fra_target_are_denied_before_reads():
    image, observer, target, _ = _environment()
    non_fra = _binding("POR", OBSERVER_SLOT, 0x50002000, 0x4567)
    permission = _permission(image, non_fra, target)
    assert permission["status"] == "unknown"
    assert permission["reason"] == "OBSERVER_MUST_BE_FRA"
    assert image.reads == []

    same = _binding("FRA", TARGET_SLOT, TARGET_POINTER, 0x2345)
    permission = _permission(image, observer, same)
    assert permission["status"] == "unknown"
    assert permission["reason"] == "TARGET_MUST_DIFFER_FROM_FRA"
    assert image.reads == []

