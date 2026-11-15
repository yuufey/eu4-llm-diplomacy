from __future__ import annotations

from bridge.information import country_reference_memory
from bridge.information import foreign_force_statistics_memory as forces
from bridge.information import foreign_military_visibility_memory as visibility


BASE = 0x140000000
DATABASE = 0x200000
TABLE = 0x300000
COUNTRY = 0x400000
OBSERVER_COUNTRY = 0x410000
TARGET_SLOT = 5
OBSERVER_SLOT = 1
TARGET_TAG = "ENG"

VT_LAND_RVA = 0x1C42540
VT_NAVY_RVA = 0x1CCA618
LAND_GROUP = 0x700000
NAVY_GROUP = 0x701000
LAND_NODE = 0x800000
NAVY_NODE = 0x801000

PROFILE = {
    "schema": forces.PROFILE_SCHEMA,
    "executable_sha256": forces.EXE_SHA256,
    "vtable_rvas": {
        "0x1c42540": {"slot_80": "0x8f440", "slot_88": "0x8f450"},
        "0x1cca618": {"slot_80": "0x8f450", "slot_88": "0x8f440"},
    },
    "method_guards": {
        "0x8f440": {"body_hex": "b001c3", "constant_boolean_return": True},
        "0x8f450": {"body_hex": "32c0c3", "constant_boolean_return": False},
    },
    "evidence_pins": [],
}


class Memory:
    def __init__(self):
        self.data: dict[int, int] = {}
        self.calls: list[tuple[int, int, str]] = []
        self.fail_address: int | None = None
        self.short_address: int | None = None

    def write(self, address: int, raw: bytes) -> None:
        for offset, byte in enumerate(raw):
            self.data[address + offset] = byte

    def write_u16(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(2, "little", signed=False))

    def write_i32(self, address: int, value: int) -> None:
        self.write(address, (value & 0xFFFFFFFF).to_bytes(4, "little"))

    def write_u64(self, address: int, value: int) -> None:
        self.write(address, value.to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        if address == self.fail_address:
            raise OSError("fixture read failure")
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("fixture unmapped address") from exc
        if address == self.short_address:
            return raw[:-1]
        return raw


def fullref(tag: str, slot: int) -> int:
    low32 = int.from_bytes(tag.encode("ascii") + b"\0", "little")
    return (1 << 56) | (1 << 48) | (slot << 32) | low32


def _install_vtable(memory: Memory, rva: int) -> None:
    row = PROFILE["vtable_rvas"][hex(rva)]
    memory.write_u64(BASE + rva + 0x80, BASE + int(row["slot_80"], 0))
    memory.write_u64(BASE + rva + 0x88, BASE + int(row["slot_88"], 0))


def _install_method_code(memory: Memory) -> None:
    for rva, row in PROFILE["method_guards"].items():
        memory.write(BASE + int(rva, 0), bytes.fromhex(row["body_hex"]))


def fixture(*, public_options: int = 0):
    memory = Memory()
    memory.write_u64(BASE + country_reference_memory.DATABASE_GLOBAL_RVA, DATABASE)
    memory.write_u64(DATABASE + country_reference_memory.DATABASE_TABLE_OFFSET, TABLE)
    memory.write_i32(DATABASE + country_reference_memory.DATABASE_TABLE_COUNT_OFFSET,
                     TARGET_SLOT + 1)
    memory.write(TABLE, bytes((TARGET_SLOT + 1) * 8))
    memory.write_u64(TABLE + OBSERVER_SLOT * 8, OBSERVER_COUNTRY)
    memory.write_u64(TABLE + TARGET_SLOT * 8, COUNTRY)
    memory.write_u64(COUNTRY + country_reference_memory.COUNTRY_FULLREF_OFFSET,
                     fullref(TARGET_TAG, TARGET_SLOT))
    memory.write_u64(OBSERVER_COUNTRY + country_reference_memory.COUNTRY_FULLREF_OFFSET,
                     fullref("FRA", OBSERVER_SLOT))

    scan = country_reference_memory.resolve_countries(
        memory.read, BASE, ["FRA", TARGET_TAG])
    observer_binding = scan["requested"]["FRA"]
    target_binding = scan["requested"][TARGET_TAG]

    world = 0x600000
    settings = 0x610000
    memory.write_u64(BASE + visibility.WORLD_GLOBAL_RVA, world)
    memory.write_u64(world + visibility.WORLD_SETTINGS_OFFSET, settings)
    memory.write_i32(settings + visibility.PUBLIC_OPTIONS_OFFSET, public_options)
    memory.write_i32(settings + visibility.PUBLIC_OPTIONS_SECOND_OFFSET, 0)
    memory.write_u64(COUNTRY + visibility.TARGET_TIMED_HEAD_OFFSET, 0)

    _install_vtable(memory, VT_LAND_RVA)
    _install_vtable(memory, VT_NAVY_RVA)
    _install_method_code(memory)
    permission = visibility.read_permission(
        memory, BASE, observer_binding, target_binding)
    memory.calls.clear()
    return memory, target_binding, observer_binding, permission


def install_group(memory: Memory, *, index: int, node: int, group: int,
                  vtable_rva: int, next_node: int,
                  vector_begin: int = 0, vector_count: int = 0,
                  record_values: tuple[int, ...] = ()) -> tuple[int, int]:
    memory.write_u64(node, group)
    memory.write_u64(node + 0x10, next_node)
    memory.write_u64(group, BASE + vtable_rva)
    begin = vector_begin if vector_count else 0
    end = begin + 8 * vector_count if vector_count else 0
    memory.write_u64(group + 0x30, begin)
    memory.write_u64(group + 0x38, end)
    if vector_count and vtable_rva == VT_LAND_RVA:
        for row, value in enumerate(record_values):
            pointer = 0xA00000 + index * 0x10000 + row * 0x1000
            memory.write_u64(begin + row * 8, pointer)
            memory.write_i32(pointer + forces.RECORD_STRENGTH_OFFSET, value)
    return begin, end


def install_two_groups(memory: Memory, *, land_values=(10, -3), navy_count=3,
                       navy_vector=0xB00000):
    land_count = len(land_values)
    install_group(memory, index=0, node=LAND_NODE, group=LAND_GROUP,
                  vtable_rva=VT_LAND_RVA, next_node=NAVY_NODE,
                  vector_begin=0x900000 if land_count else 0,
                  vector_count=land_count, record_values=tuple(land_values))
    install_group(memory, index=1, node=NAVY_NODE, group=NAVY_GROUP,
                  vtable_rva=VT_NAVY_RVA, next_node=0,
                  vector_begin=navy_vector if navy_count else 0,
                  vector_count=navy_count)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, LAND_NODE)


def call_fields(memory: Memory, binding, permission, fields=forces.FIELDS,
                profile=PROFILE):
    return forces.read_fields(memory, BASE, binding, fields,
                              permission=permission, predicate_profile=profile)


def _field_values(memory, binding, permission, fields=forces.FIELDS, profile=PROFILE):
    return call_fields(memory, binding, permission, fields, profile)


def test_real_visibility_permission_reads_soldier_sum_and_ship_count():
    memory, binding, _, permission = fixture()
    install_two_groups(memory, land_values=(10, -3), navy_count=3)
    fields = _field_values(memory, binding, permission)

    army = fields[forces.FIELD_ARMY]
    navy = fields[forces.FIELD_NAVY]
    assert army["status"] == navy["status"] == "known"
    assert (army["value"], army["raw"], army["record_count"], army["unit"], army["scale"]) == (
        7, 7, 2, "soldiers", 1)
    assert army["basis"] == "native_diplomacy_soldier_statistic"
    assert army["complete"] is False and army["partial"] is True
    assert army["raw_inputs"]["arithmetic"]["display_input_raw"] == 7000
    assert (navy["value"], navy["raw"], navy["unit"], navy["scale"]) == (3, 3, "ships", 1)
    assert navy["basis"] == "native_diplomacy_ship_statistic"
    assert navy["complete"] is False and navy["partial"] is True
    assert navy["raw_inputs"]["arithmetic"]["record_elements_read"] is False
    assert all("records" not in group for group in navy["raw_inputs"]["field_groups"])
    assert not any("navy.record" in label or "strength_i32" in label
                   and "group[1]" in label for _, _, label in memory.calls)
    assert any("strength_i32" in label for _, _, label in memory.calls)


def test_empty_chain_is_known_zero_after_permission_and_binding_revalidation():
    memory, binding, _, permission = fixture()
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, 0)
    fields = _field_values(memory, binding, permission)
    assert fields[forces.FIELD_ARMY]["status"] == "known"
    assert fields[forces.FIELD_ARMY]["value"] == 0
    assert fields[forces.FIELD_ARMY]["record_count"] == 0
    assert fields[forces.FIELD_NAVY]["status"] == "known"
    assert fields[forces.FIELD_NAVY]["value"] == 0
    assert memory.calls


def test_denied_or_unknown_permission_performs_no_leaf_memory_reads():
    memory, binding, observer, denied_unused = fixture(public_options=1)
    denied = visibility.read_permission(memory, BASE, observer, binding)
    assert denied["status"] == "known" and denied["admitted"] is False
    memory.calls.clear()
    result = _field_values(memory, binding, denied)
    assert result[forces.FIELD_ARMY]["status"] == "invisible"
    assert result[forces.FIELD_NAVY]["status"] == "invisible"
    assert memory.calls == []

    unknown = {"schema": visibility.SCHEMA, "status": "unknown", "admitted": None}
    result = _field_values(memory, binding, unknown)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_NAVY]["status"] == "unknown"
    assert memory.calls == []


def test_mismatched_permission_profile_and_invalid_binding_fail_before_memory_io():
    memory, binding, _, permission = fixture()
    bad_permission = dict(permission)
    bad_permission["target"] = {"tag": "POR", "slot": TARGET_SLOT}
    result = _field_values(memory, binding, bad_permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_NAVY]["status"] == "unknown"
    assert memory.calls == []

    bad_profile = dict(PROFILE)
    bad_profile["vtable_rvas"] = {"0x1c42540": {"slot_80": "0x8f450", "slot_88": "0x8f440"}}
    result = _field_values(memory, binding, permission, profile=bad_profile)
    assert result[forces.FIELD_ARMY]["reason"] == "PREDICATE_PROFILE_NOT_SUPPORTED"
    assert memory.calls == []

    bad_binding = dict(binding)
    bad_binding["slot"] += 1
    result = _field_values(memory, bad_binding, permission)
    assert result[forces.FIELD_ARMY]["reason"] == "TARGET_BINDING_INVALID"
    assert memory.calls == []


def test_unknown_vtable_and_rom_method_mismatch_are_unknown():
    memory, binding, _, permission = fixture()
    node, group = 0x820000, 0x830000
    install_group(memory, index=0, node=node, group=group, vtable_rva=0x1D00000,
                  next_node=0)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, node)
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "VTABLE_NOT_PROFILED"

    memory, binding, _, permission = fixture()
    install_group(memory, index=0, node=LAND_NODE, group=LAND_GROUP,
                  vtable_rva=VT_LAND_RVA, next_node=0, vector_count=0)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, LAND_NODE)
    memory.write(BASE + 0x8F440, b"\x32\xC0\xC3")
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "METHOD_ROM_GUARD_MISMATCH"


def test_wrong_method_pointer_for_profiled_slot_is_unknown():
    memory, binding, _, permission = fixture()
    install_group(memory, index=0, node=LAND_NODE, group=LAND_GROUP,
                  vtable_rva=VT_LAND_RVA, next_node=0, vector_count=0)
    memory.write_u64(BASE + VT_LAND_RVA + 0x80, BASE + 0x8F450)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, LAND_NODE)
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "METHOD_POINTER_NOT_PROFILED_FOR_SLOT"


def test_signed_low32_accumulation_and_display_multiplier_are_private_only():
    memory, binding, _, permission = fixture()
    install_two_groups(memory, land_values=(0x7FFFFFFF, 1), navy_count=1)
    result = _field_values(memory, binding, permission)
    army = result[forces.FIELD_ARMY]
    assert army["status"] == "known"
    assert army["value"] == army["raw"] == -0x80000000
    assert army["record_count"] == 2
    assert army["raw_inputs"]["arithmetic"]["display_input_raw"] == 0
    assert army["raw_inputs"]["arithmetic"]["display_input_raw_i32_hex"] == "0x00000000"

    memory, binding, _, permission = fixture()
    install_two_groups(memory, land_values=(0x400000,), navy_count=0)
    wrapped = _field_values(memory, binding, permission)[forces.FIELD_ARMY]["raw_inputs"]["arithmetic"]
    assert wrapped["display_input_raw"] == -100_663_296
    assert wrapped["display_input_raw_i32_hex"] == "0xfa000000"
    assert "display_input_raw" not in army


def test_navy_only_never_reads_army_vector_or_record_strength():
    memory, binding, _, permission = fixture()
    install_two_groups(memory, land_values=(12,), navy_count=4,
                       navy_vector=0xC00000)
    result = _field_values(memory, binding, permission, fields=(forces.FIELD_NAVY,))
    assert set(result) == {forces.FIELD_NAVY}
    assert result[forces.FIELD_NAVY]["status"] == "known"
    assert result[forces.FIELD_NAVY]["value"] == 4
    assert not any(".army.vector_" in label or "strength_i32" in label
                   for _, _, label in memory.calls)
    assert any(".navy.vector_begin" in label for _, _, label in memory.calls)


def test_army_field_raw_is_independent_of_navy_vector_changes():
    memory, binding, _, permission = fixture()
    install_two_groups(memory, land_values=(4, 6), navy_count=2,
                       navy_vector=0xD00000)
    first = _field_values(memory, binding, permission, fields=(forces.FIELD_ARMY,))[forces.FIELD_ARMY]
    memory.write_u64(NAVY_GROUP + forces.GROUP_VECTOR_BEGIN_OFFSET, 0xE00000)
    memory.write_u64(NAVY_GROUP + forces.GROUP_VECTOR_END_OFFSET, 0xE00000 + 8 * 3)
    second = _field_values(memory, binding, permission, fields=(forces.FIELD_ARMY,))[forces.FIELD_ARMY]
    assert first == second
    assert not any("group[1].navy.vector" in label for _, _, label in memory.calls)


def test_chain_cycle_and_duplicate_group_are_unknown_not_truncated():
    memory, binding, _, permission = fixture()
    install_group(memory, index=0, node=LAND_NODE, group=LAND_GROUP,
                  vtable_rva=VT_LAND_RVA, next_node=LAND_NODE, vector_count=0)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, LAND_NODE)
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "CHAIN_NEXT_CYCLE_OR_DUPLICATE"

    memory, binding, _, permission = fixture()
    second_node = 0x810000
    memory.write_u64(LAND_NODE, LAND_GROUP)
    memory.write_u64(LAND_NODE + 0x10, second_node)
    memory.write_u64(second_node, LAND_GROUP)
    memory.write_u64(second_node + 0x10, 0)
    memory.write_u64(LAND_GROUP, BASE + VT_LAND_RVA)
    memory.write_u64(LAND_GROUP + 0x30, 0)
    memory.write_u64(LAND_GROUP + 0x38, 0)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, LAND_NODE)
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_NAVY]["status"] == "unknown"
    assert result[forces.FIELD_NAVY]["reason"] == "DUPLICATE_GROUP_POINTER"


def test_duplicate_record_pointer_invalidates_army_but_keeps_independent_navy():
    memory, binding, _, permission = fixture()
    install_two_groups(memory, land_values=(1, 2), navy_count=2)
    vector_begin = 0x900000
    record = 0xA00000
    memory.write_u64(vector_begin + 0, record)
    memory.write_u64(vector_begin + 8, record)
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "DUPLICATE_RECORD_POINTER"
    assert result[forces.FIELD_NAVY]["status"] == "known"
    assert result[forces.FIELD_NAVY]["value"] == 2


def test_army_specific_read_failure_does_not_erase_known_navy_count():
    memory, binding, _, permission = fixture()
    install_two_groups(memory, land_values=(7,), navy_count=3)
    strength_address = 0xA00000 + forces.RECORD_STRENGTH_OFFSET
    memory.fail_address = strength_address
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "READ_FAILED"
    assert result[forces.FIELD_NAVY]["status"] == "known"
    assert result[forces.FIELD_NAVY]["value"] == 3


def test_revalidation_and_group_short_reads_fail_closed():
    memory, binding, _, permission = fixture()
    stale = int(binding["fullref"], 0) ^ (1 << 40)
    memory.write_u64(COUNTRY + country_reference_memory.COUNTRY_FULLREF_OFFSET, stale)
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "TARGET_BINDING_REVALIDATION_FAILED"

    memory, binding, _, permission = fixture()
    install_group(memory, index=0, node=LAND_NODE, group=LAND_GROUP,
                  vtable_rva=VT_LAND_RVA, next_node=0, vector_count=0)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, LAND_NODE)
    memory.short_address = LAND_NODE
    result = _field_values(memory, binding, permission)
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "READ_FAILED"


def test_node_limit_is_unknown_without_partial_success():
    memory, binding, _, permission = fixture()
    first_node = 0x820000
    group_base = 0x900000
    for index in range(forces.MAX_CHAIN_NODES + 1):
        node = first_node + index * 0x100
        group = group_base + index * 0x100
        next_node = node + 0x100 if index < forces.MAX_CHAIN_NODES else 0
        install_group(memory, index=index, node=node, group=group,
                      vtable_rva=VT_LAND_RVA, next_node=next_node, vector_count=0)
    memory.write_u64(COUNTRY + forces.COUNTRY_GROUP_HEAD_OFFSET, first_node)
    result = _field_values(memory, binding, permission, fields=(forces.FIELD_ARMY,))
    assert result[forces.FIELD_ARMY]["status"] == "unknown"
    assert result[forces.FIELD_ARMY]["reason"] == "CHAIN_NODE_LIMIT_EXCEEDED"


def test_unknown_field_does_not_trigger_memory_reads():
    memory, binding, _, permission = fixture()
    result = _field_values(memory, binding, permission, fields=("F02.other",))
    assert result["F02.other"]["status"] == "unknown"
    assert result["F02.other"]["reason"] == "UNSUPPORTED_FIELD"
    assert memory.calls == []
