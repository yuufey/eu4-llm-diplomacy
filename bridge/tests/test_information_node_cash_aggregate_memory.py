from __future__ import annotations

from copy import deepcopy
import struct

import pytest

from bridge.information import foreign_quality_memory as quality
from bridge.information import node_cash_aggregate_memory as memory
from bridge.information import trade_value_memory


BASE = 0x140000000
WORLD = 0x64000000
RECORDS = 0x300000
RUNTIME = 0x600000
DEFINITION = 0x700000
VECTOR = 0x710000
BITSETS = 0x720000
PROVINCE_VECTOR = 0x6F0000
MARKET = 0x730000
PRICES = 0x740000
MANAGER = 0x750000
DESCRIPTOR_KEYS = 0x760000
RESOURCE_BASE = 0x780000
OWNER_ENG = 0x800000
OWNER_POR = 0x820000
OWNER_VALUES_ENG = 0x900000
OWNER_VALUES_POR = 0x920000
PROVINCE_VALUES = 0xA00000
STRIDE = 0x2E10
COUNT = 8
FRA_SLOT = 3
NODE_ID = "node_test"
PRICE_INDEX = 3

DESCRIPTORS = {
    20: "trade_goods_size",
    21: "trade_goods_size_modifier",
    101: "trade_value",
    112: "trade_value_modifier",
    184: "global_trade_goods_size_modifier",
    491: "global_trade_goods_size",
}


def _q(value: int) -> bytes:
    return struct.pack("<Q", value)


def _i(value: int) -> bytes:
    return struct.pack("<i", value)


def _fullref(tag: str, slot: int, generation: int = 1) -> int:
    low = int.from_bytes(tag.encode("ascii") + b"\0", "little")
    return (generation << 56) | (slot << 32) | low


def _binding(tag: str, slot: int, pointer: int) -> dict[str, object]:
    ref = _fullref(tag, slot)
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "fullref": hex(ref),
        "fullref_raw_hex": _q(ref).hex(),
    }


class FakeMemory:
    def __init__(self) -> None:
        self.data: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.short_addresses: set[int] = set()
        self.drift_address: int | None = None

    def write(self, address: int, raw: bytes) -> None:
        for offset, byte in enumerate(raw):
            self.data[address + offset] = byte

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        try:
            raw = bytearray(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError(f"fixture_unmapped:{address:#x}:{size}:{label}") from exc
        if self.drift_address == address and ".stability." in label and raw:
            raw[0] ^= 1
        if address in self.short_addresses:
            return bytes(raw[:-1])
        return bytes(raw)


def _string32_inline(text: str) -> bytes:
    raw_text = text.encode("ascii")
    header = bytearray(32)
    header[:len(raw_text) + 1] = raw_text + b"\0"
    struct.pack_into("<Q", header, 0x10, len(raw_text))
    struct.pack_into("<Q", header, 0x18, 15)
    return bytes(header)


def _install_descriptor(reader: FakeMemory, index: int, key: str, processor: int = 0) -> int:
    address = MANAGER + index * 0x60
    encoded = key.encode("ascii")
    key_pointer = DESCRIPTOR_KEYS + index * 0x1000
    header = bytearray(32)
    struct.pack_into("<Q", header, 0, key_pointer)
    struct.pack_into("<Q", header, 0x10, len(encoded))
    struct.pack_into("<Q", header, 0x18, max(16, len(encoded)))
    raw = bytearray(0x60)
    raw[:32] = header
    struct.pack_into("<Q", raw, 0x40, processor)
    reader.write(address, bytes(raw))
    reader.write(key_pointer, encoded + b"\0")
    return address


def _install_dense(reader: FakeMemory, object_address: int, values_address: int,
                   values: dict[int, int]) -> None:
    reader.write(object_address + quality.MODIFIER_DENSE_FLAG_OFFSET, b"\x01")
    reader.write(object_address + quality.MODIFIER_VALUES_POINTER_OFFSET, _q(values_address))
    reader.write(object_address + quality.MODIFIER_SPARSE_COUNT_OFFSET, struct.pack("<I", 0))
    for index, value in values.items():
        reader.write(values_address + index * 8 + 4, _i(value))


def _allocation(member_ids: tuple[int, ...], center_id: int, selected_id: int,
                *, repeated_member: bool = False, node_id: str = NODE_ID) -> dict[str, object]:
    retained_ids = member_ids
    if repeated_member:
        retained_ids = (member_ids[0], member_ids[1], member_ids[1])
    vector = b"".join(_q(RECORDS + pid * STRIDE) for pid in retained_ids)
    begin = VECTOR
    header = _q(begin) + _q(begin + len(vector))
    row = {
        "candidate_runtime_pointer": hex(RUNTIME),
        "candidate_definition_pointer": hex(DEFINITION),
        "members": [
            {"province_id": pid, "record_pointer": hex(RECORDS + pid * STRIDE)}
            for pid in retained_ids
        ],
        "stable": {
            "definition_province_vector_header_raw_hex": header.hex(),
            "definition_province_vector_raw_hex": vector.hex(),
        },
    }
    return {
        "status": "known",
        "basis": "native_trade_node_province_component_reconstruction",
        "value": {
            "node_id": node_id,
            "center_province_id": center_id,
            "province_id": selected_id,
            "member_count": len(retained_ids),
        },
        "raw_inputs": {"pass_summaries": [deepcopy(row), deepcopy(row)]},
    }


def _install_country_stubs(monkeypatch: pytest.MonkeyPatch, bindings: list[dict[str, object]],
                           *, denied_tags: tuple[str, ...] = ()):
    by_ref = {item["fullref_raw_hex"]: item for item in bindings}
    rebind_calls: list[tuple[str, str]] = []
    admit_calls: list[str] = []

    def rebind(_limiter, _base, _scan, raw_ref, label):
        key = bytes(raw_ref).hex()
        rebind_calls.append((key, label))
        if key not in by_ref:
            raise ValueError("fixture_country_not_retained")
        return deepcopy(by_ref[key])

    def admit(_limiter, _base, _scan, binding):
        tag = binding["tag"]
        admit_calls.append(tag)
        return {
            "status": "known",
            "admitted": tag not in denied_tags,
            "observer_nonplayer_role": {"verified": True},
        }

    monkeypatch.setattr(memory._country, "_rebind", rebind)
    monkeypatch.setattr(memory._country, "_admit", admit)
    return rebind_calls, admit_calls


def make_fixture(monkeypatch: pytest.MonkeyPatch, *,
                 member_ids: tuple[int, ...] = (1, 2, 3), center_id: int = 1,
                 selected_id: int = 2, owners: dict[int, str] | None = None,
                 discovered: dict[int, bool] | None = None,
                 owner_states: dict[str, int] | None = None,
                 processors: dict[int, int] | None = None,
                 cache_value: int = 169,
                 unknown_owner_id: int | None = None,
                 denied_tags: tuple[str, ...] = (),
                 repeated_member: bool = False, node_id: str = NODE_ID):
    reader = FakeMemory()
    owners = owners or {1: "ENG", 2: "POR", 3: "ENG"}
    discovered = discovered or {}
    owner_states = owner_states or {}
    processors = processors or {}
    observer = _binding("FRA", FRA_SLOT, 0xB00000)
    country_bindings = [
        observer,
        _binding("ENG", 8, OWNER_ENG),
        _binding("POR", 9, OWNER_POR),
    ]
    rebind_calls, admit_calls = _install_country_stubs(
        monkeypatch, country_bindings, denied_tags=denied_tags)

    ids_for_vector = ((member_ids[0], member_ids[1], member_ids[1])
                      if repeated_member else member_ids)
    vector = b"".join(_q(RECORDS + pid * STRIDE) for pid in ids_for_vector)
    reader.write(DEFINITION + 0x10, _string32_inline(node_id))
    reader.write(DEFINITION + 0x68, _q(VECTOR) + _q(VECTOR + len(vector)))
    reader.write(DEFINITION + 0xDC, _i(center_id))
    reader.write(VECTOR, vector)
    reader.write(BASE + 0x233FE58, _q(WORLD))
    reader.write(WORLD + 0x1C90, _q(PROVINCE_VECTOR))
    reader.write(WORLD + 0x1C98, _q(PROVINCE_VECTOR + COUNT * 8))
    reader.write(WORLD + 0x1CA8, _q(RECORDS))
    reader.write(WORLD + 0x25D0, _q(MARKET))
    reader.write(MARKET + 8, _q(PRICES))
    reader.write(PRICES + PRICE_INDEX * 0x38 + 4, _i(1500))
    reader.write(BASE + 0x2358060, _q(MANAGER))
    for index, key in DESCRIPTORS.items():
        _install_descriptor(reader, index, key, processors.get(index, 0))

    reader.write(RUNTIME + 0xA8, _q(DEFINITION))
    reader.write(RUNTIME + 0xB0, _i(cache_value))
    province_scan = {
        "status": "observed",
        "world": {"pointer": hex(WORLD)},
        "header": {
            "begin": hex(PROVINCE_VECTOR),
            "end": hex(PROVINCE_VECTOR + COUNT * 8),
            "records_pointer": hex(RECORDS),
            "count": COUNT,
        },
    }
    owner_addresses = {"ENG": OWNER_ENG, "POR": OWNER_POR}
    owner_value_addresses = {"ENG": OWNER_VALUES_ENG, "POR": OWNER_VALUES_POR}
    owner_components = {
        "ENG": {184: 184, 491: 491},
        "POR": {184: 0, 491: 10},
    }
    for tag, pointer in owner_addresses.items():
        reader.write(pointer + 0x28C8, _i(owner_states.get(tag, 0)))
        _install_dense(reader, pointer + quality.COUNTRY_MODIFIER_OBJECT_OFFSET,
                       owner_value_addresses[tag], owner_components[tag])

    province_components = {
        1: {20: 20, 21: 21, 101: 101, 112: 112},
        2: {20: 2, 21: 0, 101: 0, 112: 0},
        3: {20: 1, 21: 0, 101: 0, 112: 0},
    }
    owner_refs = {tag: _fullref(tag, 8 if tag == "ENG" else 9)
                  for tag in ("ENG", "POR")}
    if unknown_owner_id is not None:
        owner_refs["NED"] = _fullref("NED", 11)
        owners[unknown_owner_id] = "NED"

    all_ids = set(member_ids) | {center_id, selected_id}
    for pid in all_ids:
        record = RECORDS + pid * STRIDE
        reader.write(record + 0x20, _i(pid))
        reader.write(record + 0xE8, _q(RUNTIME))
        bitset = BITSETS + pid * 0x100
        reader.write(record + 0x5E0, _q(bitset))
        is_discovered = discovered.get(pid, True)
        reader.write(bitset, struct.pack("<I", (1 << FRA_SLOT) if is_discovered else 0))
        tag = owners.get(pid, "ENG")
        reader.write(record + 0x468, _q(owner_refs[tag]))
        # These controller bytes deliberately name a third country. The cash
        # reconstruction must use the owner reference and never consult them.
        reader.write(record + 0x470, _q(_fullref("DEN", 30)))
        resource_definition = RESOURCE_BASE + pid * 0x1000
        reader.write(record + 0x458, _q(resource_definition))
        reader.write(resource_definition + 0x18, _string32_inline("grain"))
        reader.write(resource_definition + 0x78, _i(PRICE_INDEX))
        values = province_components.get(pid, {20: 0, 21: 0, 101: 0, 112: 0})
        _install_dense(reader, record + 0x998, PROVINCE_VALUES + pid * 0x1000, values)

    country_scan = {"status": "observed", "rows": []}
    allocation = _allocation(member_ids, center_id, selected_id,
                             repeated_member=repeated_member, node_id=node_id)
    return {
        "reader": reader,
        "province_scan": province_scan,
        "observer": observer,
        "country_scan": country_scan,
        "allocation": allocation,
        "rebind_calls": rebind_calls,
        "admit_calls": admit_calls,
    }


def _read(env):
    return memory.read_fields(env["reader"], BASE, env["province_scan"], env["observer"],
                              env["country_scan"], env["allocation"])[memory.FIELD]


def test_multi_member_cash_uses_each_owner_and_ignores_controller_with_shared_reads(monkeypatch):
    env = make_fixture(monkeypatch)

    field = _read(env)

    assert field["status"] == "known"
    assert field["value"]["node_id"] == NODE_ID
    assert field["value"]["member_count"] == 3
    assert field["value"]["valued_member_count"] == 3
    assert field["value"]["unresolved_province_ids"] == []
    # Independent hand check: member inputs yield 1137, 18 and 873;
    # 1137+18+873=2028, then trunc(2028/12)=169.
    assert field["value"]["province_input_sum_raw"] == 2028
    assert field["value"]["calculated_node_cash_raw"] == 169
    assert field["value"]["cached_node_cash_raw"] == 169
    assert field["value"]["matches_cache"] is True
    assert [row["calculation"]["value_raw"] for row in field["raw_inputs"]["members"]] == [
        1137, 18, 873,
    ]
    assert [row["owner"] for row in field["raw_inputs"]["members"]] == ["ENG", "POR", "ENG"]

    # Observer and each distinct owner are rebound/admitted once. The shared
    # ENG rows reuse one owner read, while all members share descriptor and price reads.
    assert len(env["rebind_calls"]) == len(env["admit_calls"]) == 3
    assert [label for _ref, label in env["rebind_calls"]].count("node_cash.observer") == 1
    assert [label for _ref, label in env["rebind_calls"]].count("node_cash.owner") == 2
    assert env["admit_calls"].count("ENG") == 1
    assert env["admit_calls"].count("POR") == 1
    assert env["admit_calls"].count("FRA") == 1
    reads = env["reader"].reads
    for address in (MANAGER + 20 * 0x60, PRICES + PRICE_INDEX * 0x38 + 4,
                    OWNER_ENG + 0x28C8, OWNER_VALUES_ENG + 491 * 8 + 4):
        # One actual value read and its independent stability reread.
        assert sum(read_address == address for read_address, _size, _label in reads) == 2
    assert all(address not in {RECORDS + pid * STRIDE + 0x470 for pid in (1, 2, 3)}
               for address, _size, _label in reads)
    assert any("stability." in label for _address, _size, label in reads)
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= memory.MAX_BYTES
    assert field["raw_inputs"]["budget"]["calls"] <= memory.MAX_CALLS


def test_loaded_node_key_accepts_uppercase_dot_dash_and_colon(monkeypatch):
    node_id = "Node.X-1:Q"
    assert trade_value_memory.NODE_ID_RE.fullmatch(node_id)
    env = make_fixture(monkeypatch, node_id=node_id)

    field = _read(env)

    assert field["status"] == "known"
    assert field["value"]["node_id"] == node_id
    assert field["raw_inputs"]["node_binding"]["node_id"] == node_id


def test_undiscovered_member_does_not_read_owner_resource_or_modifier_values(monkeypatch):
    env = make_fixture(monkeypatch, discovered={3: False})

    field = _read(env)

    assert field["status"] == "known"
    assert field["value"]["all_member_values_known"] is False
    assert field["value"]["unresolved_province_ids"] == [3]
    assert field["value"]["province_input_sum_raw"] is None
    assert field["value"]["calculated_node_cash_raw"] is None
    record = RECORDS + 3 * STRIDE
    forbidden = {
        record + 0x468,
        record + 0x458,
        record + 0x998 + quality.MODIFIER_DENSE_FLAG_OFFSET,
    }
    assert not forbidden.intersection(address for address, _size, _label in env["reader"].reads)
    assert [label for _ref, label in env["rebind_calls"]].count("node_cash.owner") == 2


def test_unknown_owner_is_unresolved_and_never_converted_to_zero(monkeypatch):
    env = make_fixture(monkeypatch, unknown_owner_id=2)

    field = _read(env)

    assert field["status"] == "known"
    assert field["value"]["all_member_values_known"] is False
    assert field["value"]["unresolved_province_ids"] == [2]
    assert field["value"]["province_input_sum_raw"] is None
    assert field["value"]["calculated_node_cash_raw"] is None
    member = next(row for row in field["raw_inputs"]["members"] if row["province_id"] == 2)
    assert member["reason"] == "NODE_CASH_OWNER_UNVERIFIED"
    record = RECORDS + 2 * STRIDE
    assert not any(address in {record + 0x458, record + 0x998 + quality.MODIFIER_DENSE_FLAG_OFFSET}
                   for address, _size, _label in env["reader"].reads)
    assert not any(address == OWNER_POR + 0x28C8 for address, _size, _label in env["reader"].reads)


def test_denied_owner_does_not_read_country_values_or_resource(monkeypatch):
    env = make_fixture(monkeypatch, denied_tags=("POR",))

    field = _read(env)

    assert field["status"] == "known"
    assert field["value"]["unresolved_province_ids"] == [2]
    assert field["value"]["all_member_values_known"] is False
    assert not any(address == OWNER_POR + 0x28C8 for address, _size, _label in env["reader"].reads)
    assert not any(address == OWNER_POR + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
                   + quality.MODIFIER_DENSE_FLAG_OFFSET
                   for address, _size, _label in env["reader"].reads)
    assert not any(address in {RECORDS + 2 * STRIDE + 0x458,
                              RECORDS + 2 * STRIDE + 0x998 + quality.MODIFIER_DENSE_FLAG_OFFSET}
                   for address, _size, _label in env["reader"].reads)
    assert env["admit_calls"].count("POR") == 1


def test_undiscovered_center_blocks_node_cash_read(monkeypatch):
    env = make_fixture(monkeypatch, discovered={1: False})

    field = _read(env)

    assert field["status"] == "unknown"
    assert field["reason"] == "NODE_CASH_CENTER_NOT_DISCOVERED"
    assert "value" not in field
    assert not any(address == RUNTIME + 0xB0 for address, _size, _label in env["reader"].reads)
    assert not any(label.startswith("node_cash.descriptor") for _address, _size, label in env["reader"].reads)
    assert [label for _ref, label in env["rebind_calls"]] == ["node_cash.observer"]


@pytest.mark.parametrize("mutation", ["repeated_member", "changed_vector", "member_id", "member_runtime"])
def test_repeated_or_changed_member_vector_identity_is_unknown(monkeypatch, mutation):
    env = make_fixture(monkeypatch, repeated_member=(mutation == "repeated_member"))
    reader = env["reader"]
    if mutation == "changed_vector":
        reader.write(VECTOR + 2 * 8, _q(RECORDS + 4 * STRIDE))
    elif mutation == "member_id":
        reader.write(RECORDS + 3 * STRIDE + 0x20, _i(4))
    elif mutation == "member_runtime":
        reader.write(RECORDS + 3 * STRIDE + 0xE8, _q(RUNTIME + 0x1000))

    field = _read(env)

    assert field["status"] == "unknown"
    assert "value" not in field
    expected = {
        "repeated_member": "NODE_CASH_MEMBER_IDENTITY_INVALID",
        "changed_vector": "NODE_CASH_MEMBER_VECTOR_CHANGED",
        "member_id": "NODE_CASH_MEMBER_IDENTITY_CHANGED",
        "member_runtime": "NODE_CASH_MEMBER_IDENTITY_CHANGED",
    }
    assert field["reason"] == expected[mutation]


@pytest.mark.parametrize("unsupported", ["processor", "owner_state"])
def test_unsupported_processor_or_owner_state_does_not_create_cash_value(monkeypatch, unsupported):
    if unsupported == "processor":
        env = make_fixture(monkeypatch, processors={20: 0x970000})
    else:
        env = make_fixture(monkeypatch, owner_states={"POR": 1})

    field = _read(env)

    if unsupported == "processor":
        assert field["status"] == "unknown"
        assert field["reason"] == "NODE_CASH_PROCESSOR_PRESENT"
        assert "value" not in field
        assert not any(address == OWNER_ENG + 0x28C8 for address, _size, _label in env["reader"].reads)
    else:
        assert field["status"] == "known"
        assert field["value"]["unresolved_province_ids"] == [2]
        member = next(row for row in field["raw_inputs"]["members"] if row["province_id"] == 2)
        assert member["reason"] == "NODE_CASH_OWNER_CACHE_UNSUPPORTED"
        assert not any(address == RECORDS + 2 * STRIDE + 0x458
                       for address, _size, _label in env["reader"].reads)
    assert not any(address == OWNER_POR + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
                   + quality.MODIFIER_DENSE_FLAG_OFFSET
                   for address, _size, _label in env["reader"].reads)


@pytest.mark.parametrize("failure", ["short_read", "stability_drift"])
def test_actual_read_failure_or_stability_drift_retracts_cash(monkeypatch, failure):
    env = make_fixture(monkeypatch)
    price_address = PRICES + PRICE_INDEX * 0x38 + 4
    if failure == "short_read":
        env["reader"].short_addresses.add(price_address)
    else:
        env["reader"].drift_address = price_address

    field = _read(env)

    assert field["status"] == "unknown"
    assert "value" not in field
    assert field["reason"] == "NODE_CASH_INPUT_STABILITY_UNVERIFIED"
    if failure == "stability_drift":
        assert any("stability." in label for _address, _size, label in env["reader"].reads)


def test_cash_read_budget_is_enforced_and_private_result_stays_unknown(monkeypatch):
    env = make_fixture(monkeypatch)
    monkeypatch.setattr(memory, "MAX_BYTES", 256)

    field = _read(env)

    assert field["status"] == "unknown"
    assert "value" not in field
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= 256
    assert field["raw_inputs"]["budget"]["calls"] <= memory.MAX_CALLS
