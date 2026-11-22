from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import trade_power_sum_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x200000000
TABLE = 0x200001000
COUNTRY = 0x200002000
WORLD = 0x200003000
MEMBERS = 0x200004000
CONTROLLERS = 0x200005000
MEMBER_A = 0x200006000
MEMBER_C = 0x200007000
COUNTRY_SLOT = 7


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def _fullref(tag: str, slot: int) -> bytes:
    value = bytearray(8)
    value[:3] = tag.encode("ascii")
    value[4:6] = slot.to_bytes(2, "little", signed=True)
    return bytes(value)


def _addr(value: int) -> dict[str, str]:
    return {"va": hex(value)}


class Reader:
    def __init__(self, data: dict[tuple[int, int], bytes]):
        self.data = data
        self.reads: list[tuple[int, int, str]] = []
        self.mutate_labels: dict[str, bytes] = {}
        self.short_labels: set[str] = set()

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        raw = self.mutate_labels.get(label, self.data.get((address, size)))
        if raw is None:
            raise AssertionError(f"unexpected read {label} {address:#x} {size}")
        if label in self.short_labels:
            return raw[:-1]
        return raw


@pytest.fixture(autouse=True)
def validate_trade_income_fixture(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        memory._trade,
        "validate_record",
        lambda record: isinstance(record, dict) and record.get("_fixture_valid") is True,
    )


def _environment(
    *,
    members: list[tuple[int, bytes]] | None = None,
    role_human_count: int = 1,
    role_controller_type: int = 0,
    observer: str = "FRA",
) -> tuple[Reader, dict, dict]:
    if members is None:
        members = [
            (MEMBER_A, _fullref("POR", 2)),
            (COUNTRY, _fullref(observer, COUNTRY_SLOT)),
            (MEMBER_C, _fullref("POR", 11)),
        ]
    data: dict[tuple[int, int], bytes] = {}
    data[(MODULE_BASE + memory.DATABASE_GLOBAL_RVA, 8)] = _qword(DATABASE)
    data[(DATABASE + memory.DATABASE_TABLE_OFFSET, 8)] = _qword(TABLE)
    data[(TABLE + COUNTRY_SLOT * 8, 8)] = _qword(COUNTRY)
    country_fullref = _fullref(observer, COUNTRY_SLOT)
    data[(COUNTRY + memory.COUNTRY_FULLREF_OFFSET, 8)] = country_fullref
    data[(MODULE_BASE + memory.WORLD_GLOBAL_RVA, 8)] = _qword(WORLD)
    data[(WORLD + memory.WORLD_MEMBER_LIST_OFFSET, 8)] = _qword(MEMBERS)
    data[(WORLD + memory.WORLD_MEMBER_COUNT_OFFSET, 4)] = _i32(len(members))
    data[(WORLD + memory.WORLD_HUMAN_COUNT_OFFSET, 4)] = _i32(role_human_count)
    data[(WORLD + memory.WORLD_CONTROLLERS_OFFSET, 8)] = _qword(CONTROLLERS)
    data[(CONTROLLERS + COUNTRY_SLOT * memory.CONTROLLER_I32_STRIDE, 4)] = _i32(role_controller_type)
    member_vector = b"".join(_qword(pointer) for pointer, _ref in members)
    data[(MEMBERS, len(member_vector))] = member_vector
    for pointer, fullref in members:
        data[(pointer + memory.COUNTRY_FULLREF_OFFSET, 8)] = fullref

    table_cell = DATABASE + memory.DATABASE_TABLE_OFFSET
    country_handle = {
        "address": _addr(COUNTRY + memory.COUNTRY_FULLREF_OFFSET),
        "raw_hex": country_fullref.hex(),
        "value": hex(int.from_bytes(country_fullref, "little")),
        "tag": observer,
        "slot": COUNTRY_SLOT,
    }
    country_scan = {
        "status": "observed",
        "requested_country": observer,
        "scanned_entries": memory.MAX_SOURCE_SCAN_ENTRIES,
        "table_field": {
            "address": _addr(table_cell),
            "raw_hex": _qword(TABLE).hex(),
            "value": hex(TABLE),
        },
        "country_pointer": _addr(COUNTRY),
        "country_handle": country_handle,
        "matches": [{"table_index": COUNTRY_SLOT, "country_pointer": _addr(COUNTRY)}],
    }
    trade_income = {
        "_fixture_valid": True,
        "status": "observed",
        "country": observer,
        "country_pointer": hex(COUNTRY),
        "country_fullref_address": hex(COUNTRY + memory.COUNTRY_FULLREF_OFFSET),
        "country_fullref_raw_hex": country_fullref.hex(),
        "country_slot": COUNTRY_SLOT,
    }
    return Reader(data), trade_income, country_scan


def _read(reader: Reader, trade_income: dict, country_scan: dict):
    return memory.read_fields(reader, MODULE_BASE, trade_income, country_scan)


@pytest.mark.parametrize("observer", ("FRA", "TUR"))
def test_unique_member_and_npc_role_are_verified(observer):
    reader, trade_income, country_scan = _environment(observer=observer)

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "observed"
    assert result["basis"] == "native_global_country_power_sum_membership"
    assert result["period"] == "current"
    assert result["complete"] is False
    assert result["stable"] is True
    assert result["country_slot"] == COUNTRY_SLOT
    assert result["canonical_observer_verified"] is True
    assert result["observer_nonplayer_verified"] is True
    assert result["membership"]["member_count"] == 3
    assert result["membership"]["observer_occurrences"] == 1
    assert result["membership"]["fullref_occurrences"] == 1
    assert result["membership"]["slot_occurrences"] == 1
    assert result["membership"]["members"][1]["tag"] == observer
    wrong_scan = {**country_scan, "requested_country": "TUR" if observer == "FRA" else "FRA"}
    assert _read(reader, trade_income, wrong_scan)["reason"] == "country_scan_country_mismatch"
    assert result["raw_inputs"]["stable"] is True
    assert result["raw_inputs"]["role"]["human_count"] == 1
    assert result["raw_inputs"]["role"]["controller_type"] == 0
    assert result["raw_inputs"]["anchors_before"]["world_member_list"] == _qword(MEMBERS).hex()
    assert result["raw_inputs"]["anchors_after"]["world_member_list"] == _qword(MEMBERS).hex()
    assert result["raw_inputs"]["anchors_after"]["member_list_bytes"] == result["raw_inputs"]["anchors_before"]["member_list_bytes"]
    assert all(label.startswith("trade_power_sum.") for _address, _size, label in reader.reads)
    assert not any("power_value" in label or "income" in label for _a, _s, label in reader.reads)
    assert not any(size == memory.MAX_SOURCE_SCAN_ENTRIES * 8 for _a, size, _label in reader.reads)


@pytest.mark.parametrize(
    ("members", "reason", "expected_counts"),
    [
        ([(MEMBER_A, _fullref("POR", 2)), (MEMBER_C, _fullref("POR", 11))],
         "observer_membership_not_unique", (0, 0, 0)),
        ([(COUNTRY, _fullref("FRA", COUNTRY_SLOT)),
          (MEMBER_A, _fullref("POR", 2)),
          (MEMBER_C, _fullref("FRA", COUNTRY_SLOT))],
         "observer_membership_not_unique", (1, 2, 2)),
        ([(MEMBER_A, _fullref("POR", 2)),
          (COUNTRY, _fullref("FRA", COUNTRY_SLOT)),
          (MEMBER_C, _fullref("POR", COUNTRY_SLOT))],
         "observer_membership_not_unique", (1, 1, 2)),
        ([(MEMBER_A, _fullref("POR", 2)),
          (COUNTRY, _fullref("FRA", COUNTRY_SLOT)),
          (COUNTRY, _fullref("FRA", COUNTRY_SLOT))],
         "member_pointer_invalid_or_aliased", None),
    ],
)
def test_missing_or_nonunique_membership_is_unknown(members, reason, expected_counts):
    reader, trade_income, country_scan = _environment(members=members)

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert "reads" in result["raw_inputs"]
    if expected_counts is not None:
        assert tuple(result["membership"][key] for key in (
            "observer_occurrences", "fullref_occurrences", "slot_occurrences"
        )) == expected_counts


def test_country_slot_mismatch_is_rejected_before_native_reads():
    reader, trade_income, country_scan = _environment()
    trade_income["country_slot"] = COUNTRY_SLOT + 1

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "trade_income_identity_invalid"
    assert reader.reads == []


@pytest.mark.parametrize("bad_scan", [
    {"status": "unknown"},
    {"status": "observed", "requested_country": "POR"},
    {"status": "observed", "requested_country": "FRA", "scanned_entries": 255},
])
def test_malformed_parent_country_scan_is_rejected_before_native_reads(bad_scan):
    reader, trade_income, country_scan = _environment()
    country_scan.update(bad_scan)

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert not reader.reads


def test_duplicate_parent_match_is_rejected_before_native_reads():
    reader, trade_income, country_scan = _environment()
    country_scan["matches"].append(deepcopy(country_scan["matches"][0]))

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "country_scan_match_not_unique"
    assert reader.reads == []


@pytest.mark.parametrize("human_count,controller_type", [(0, 0), (1, 1), (2, 0)])
def test_stable_non_npc_role_is_unknown_with_private_reads(human_count, controller_type):
    reader, trade_income, country_scan = _environment(
        role_human_count=human_count, role_controller_type=controller_type
    )

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "observer_role_mismatch"
    assert result["raw_inputs"]["stable"] is True
    assert result["raw_inputs"]["role"]["human_count"] == human_count
    assert result["raw_inputs"]["role"]["controller_type"] == controller_type


@pytest.mark.parametrize(
    ("label", "replacement"),
    [
        ("trade_power_sum.world_global.after", _qword(WORLD + 0x1000)),
        ("trade_power_sum.database_table.after", _qword(TABLE + 0x1000)),
    ],
)
def test_changed_selected_header_anchor_retracts_membership(label, replacement):
    reader, trade_income, country_scan = _environment()
    reader.mutate_labels[label] = replacement

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "anchors_changed"
    assert result["raw_inputs"]["stable"] is False


def test_changed_member_vector_retracts_membership():
    reader, trade_income, country_scan = _environment()
    original = reader.data[(MEMBERS, 24)]
    reader.mutate_labels["trade_power_sum.members.after"] = _qword(MEMBER_A) + _qword(MEMBER_C) + original[16:]

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "anchors_changed"
    assert result["raw_inputs"]["stable"] is False


def test_short_member_vector_read_retains_only_observed_private_reads():
    reader, trade_income, country_scan = _environment()
    reader.short_labels.add("trade_power_sum.members.before")

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "short_read"
    assert result["raw_inputs"]["reads"][-1]["label"] == "trade_power_sum.members.before"
    assert result["raw_inputs"]["reads"][-1]["bytes_received"] == 23


def test_count_over_native_bound_is_rejected_before_vector_read():
    reader, trade_income, country_scan = _environment()
    reader.data[(WORLD + memory.WORLD_MEMBER_COUNT_OFFSET, 4)] = _i32(4097)

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "member_count_out_of_range"
    assert not any(label == "trade_power_sum.members.before" for _a, _s, label in reader.reads)


def test_maximum_4096_member_count_fits_leaf_budget():
    selected_index = 2000
    members = [(0x300000000 + index * 0x100, _fullref("POR", 1)) for index in range(4096)]
    members[selected_index] = (COUNTRY, _fullref("FRA", COUNTRY_SLOT))
    reader, trade_income, country_scan = _environment(members=members)

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "observed"
    assert result["membership"]["member_count"] == 4096
    assert result["membership"]["selected_index"] == selected_index
    assert result["raw_inputs"]["budget"]["bytes_requested"] <= memory.MAX_TOTAL_READ
    assert result["raw_inputs"]["budget"]["calls"] <= memory.MAX_READ_CALLS


@pytest.mark.parametrize("budget_name", ["MAX_READ_CALLS", "MAX_TOTAL_READ"])
def test_local_read_budget_is_enforced(budget_name, monkeypatch):
    reader, trade_income, country_scan = _environment()
    monkeypatch.setattr(memory, budget_name, 1 if budget_name == "MAX_READ_CALLS" else 8)

    result = _read(reader, trade_income, country_scan)

    assert result["status"] == "unknown"
    assert result["reason"] == "read_budget_exceeded"
    assert len(reader.reads) == 1

