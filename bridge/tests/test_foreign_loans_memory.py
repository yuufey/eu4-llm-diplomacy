"""Offline leaf tests using the accepted economy-permission memory fixture."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import engine_dates
from bridge.information import foreign_economy_visibility_memory as visibility
from bridge.information import foreign_loans_memory as loans
from bridge.tests import test_foreign_economy_visibility_memory as economy_fixture


BASE = economy_fixture.BASE
TARGET_SLOT = economy_fixture.TARGET_SLOT
OBSERVER_SLOT = economy_fixture.OBSERVER_SLOT
NODE_BASE = 0x7000000000
RECORD_BASE = 0x7100000000
NODE_STRIDE = 0x100
RECORD_STRIDE = 0x100
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1


def _pack_i32(*values: int) -> bytes:
    return b"".join(value.to_bytes(4, "little", signed=True) for value in values)


def _make_permission(*, active_target: bool = True):
    image, observer, target = economy_fixture._environment(target_in_world=active_target)
    permission = visibility.read_permission(
        image, BASE, observer, target, page=visibility.LOANS_PAGE
    )
    assert permission["status"] == "known"
    assert permission["admitted"] is active_target
    assert visibility.validate_permission(permission, page=visibility.LOANS_PAGE)
    image.reads.clear()
    return image, observer, target, permission


def _put_list(image, target: dict, lenders: list[int],
              financials: list[tuple[int, int, int] | None]) -> tuple[list[int], list[int]]:
    assert len(lenders) == len(financials)
    target_pointer = int(target["country_pointer"], 16)
    node_pointers: list[int] = []
    record_pointers: list[int] = []
    for index, (lender, values) in enumerate(zip(lenders, financials)):
        node = NODE_BASE + index * NODE_STRIDE
        record = RECORD_BASE + index * RECORD_STRIDE
        node_pointers.append(node)
        record_pointers.append(record)
        next_node = NODE_BASE + (index + 1) * NODE_STRIDE if index + 1 < len(lenders) else 0
        image.put_u64(node, record)
        image.put_u64(node + 8, 0xA5A5A5A5A5A5A5A5)
        image.put_u64(node + 0x10, next_node)
        image.put_u64(record + 0x20, lender)
        if values is not None:
            image.put(record + 0x28, _pack_i32(*values))
    image.put_u64(target_pointer + 0xDE8, node_pointers[0] if node_pointers else 0)
    return node_pointers, record_pointers


def _read(image, observer: dict, target: dict, permission: dict,
          *, base: int = BASE, fields: tuple[str, ...] = (loans.FIELD,)) -> dict:
    return loans.read_fields(image, base, observer, target, fields, permission=permission)


def _observer_ref(observer: dict) -> int:
    return int(observer["fullref"], 16)


def _labels(image) -> list[str]:
    return [label for _address, _size, label in image.reads]


def _assert_budget(field: dict) -> None:
    budget = field["raw_inputs"]["budget"]
    assert budget["max_calls"] == loans.MAX_READ_CALLS == 256
    assert budget["max_bytes"] == loans.MAX_READ_BYTES == 16 * 1024
    assert budget["max_nodes"] == loans.MAX_NODES == 64
    assert budget["max_single_read_bytes"] == 1024
    assert budget["calls"] <= budget["max_calls"]
    assert budget["bytes_requested"] <= budget["max_bytes"]
    assert max((row["size"] for row in field["raw_inputs"]["reads"]), default=0) <= 1024


def test_matching_observer_lender_reads_financials_and_keeps_derived_sum_unwrapped():
    image, observer, target, permission = _make_permission()
    due1, due2 = 56_564_448, 56_564_424
    _put_list(image, target, [_observer_ref(observer), _observer_ref(observer)],
              [(4000, I32_MAX, due1), (-250, 10, due2)])

    result = _read(image, observer, target, permission)
    field = result[loans.FIELD]
    value = field["value"]
    subset = value["loans_to_observer"]

    assert field["status"] == "known" and field["complete"] is False and field["partial"] is True
    assert field["unit"] == "observed_loan_records" and field["scale"] == 1 and field["period"] == "current"
    assert field["basis"] == "native_ledger_loans_lent_by_observer"
    assert value["total_debt"] == {"status": "unknown", "reason": "TOTAL_FOREIGN_DEBT_NOT_ESTABLISHED"}
    assert subset["status"] == "known" and subset["coverage"] == "observer_lent_loans_only"
    assert subset["complete_country_debt"] is False and subset["record_count"] == 2
    first, second = subset["records"]
    assert first["lender"] == "FRA" and first["borrower"] == "ENG"
    assert first["principal"] == {"status": "known", "raw": I32_MAX, "value": I32_MAX,
                                   "unit": "ducats", "scale": 1}
    assert first["interest"] == {"status": "known", "raw": 4000, "value": 4000,
                                  "unit": "percent", "scale": 1000}
    assert first["due"]["raw"] == due1
    assert first["due"]["raw_hex"] == due1.to_bytes(4, "little", signed=True).hex()
    assert first["due"]["unit"] == "eu4_hour_tick" and first["due"]["scale"] == 1
    assert first["due"]["calendar"] == engine_dates.project_engine_date(due1)
    assert second["principal"]["raw"] == 10 and second["interest"]["raw"] == -250
    assert subset["observed_principal_sum"] == {
        "status": "known", "raw": I32_MAX + 10, "value": I32_MAX + 10,
        "unit": "ducats", "scale": 1,
    }
    assert subset["observed_principal_sum"]["value"] > I32_MAX
    labels = _labels(image)
    assert "foreign_loans.target_list_head" in labels
    assert "foreign_loans.node[0]" in labels
    assert "foreign_loans.lender[0]" in labels
    assert "foreign_loans.financials[0]" in labels
    assert len(field["raw_inputs"]["reads"]) == len(image.reads)
    _assert_budget(field)


def test_third_country_and_same_slot_different_generation_never_read_amounts():
    image, observer, target, permission = _make_permission()
    third_country = economy_fixture._fullref("POR", 210, 0x3456)
    same_slot_new_generation = economy_fixture._fullref("FRA", OBSERVER_SLOT, 0x1235)
    _put_list(image, target, [third_country, same_slot_new_generation], [None, None])

    result = _read(image, observer, target, permission)[loans.FIELD]
    subset = result["value"]["loans_to_observer"]

    assert result["status"] == "known"
    assert subset["record_count"] == 0 and subset["records"] == []
    assert subset["observed_principal_sum"] == {
        "status": "known", "raw": 0, "value": 0, "unit": "ducats", "scale": 1,
    }
    assert result["value"]["total_debt"] == {
        "status": "unknown", "reason": "TOTAL_FOREIGN_DEBT_NOT_ESTABLISHED",
    }
    assert "foreign_loans.financials[0]" not in _labels(image)
    assert "foreign_loans.financials[1]" not in _labels(image)
    _assert_budget(result)


def test_empty_list_means_zero_observer_lent_records_not_zero_country_debt():
    image, observer, target, permission = _make_permission()
    _put_list(image, target, [], [])

    field = _read(image, observer, target, permission)[loans.FIELD]
    subset = field["value"]["loans_to_observer"]
    assert field["status"] == "known"
    assert subset["records"] == [] and subset["record_count"] == 0
    assert subset["observed_principal_sum"]["value"] == 0
    assert field["value"]["total_debt"]["status"] == "unknown"
    assert "foreign_loans.target_list_head" in _labels(image)
    assert not any(label.startswith("foreign_loans.financials") for label in _labels(image))
    _assert_budget(field)


@pytest.mark.parametrize("corruption,expected_reason", [
    ("cycle", "FOREIGN_LOANS_NODE_CYCLE"),
    ("duplicate_record", "FOREIGN_LOANS_DUPLICATE_RECORD"),
    ("oversize", "FOREIGN_LOANS_NODE_LIMIT"),
    ("short_read", "FOREIGN_LOANS_SHORT_READ"),
])
def test_malformed_or_overbound_lists_are_all_withdrawn(corruption: str, expected_reason: str):
    image, observer, target, permission = _make_permission()
    observer_ref = _observer_ref(observer)
    if corruption == "cycle":
        nodes, _records = _put_list(image, target, [observer_ref], [(100, 200, 56_564_448)])
        image.put_u64(nodes[0] + 0x10, nodes[0])
    elif corruption == "duplicate_record":
        nodes, records = _put_list(image, target, [observer_ref, observer_ref],
                                   [(100, 200, 56_564_448), (100, 300, 56_564_450)])
        image.put_u64(nodes[1], records[0])
    elif corruption == "oversize":
        count = loans.MAX_NODES + 1
        lenders = [economy_fixture._fullref("POR", 200 + index, 0x3456) for index in range(count)]
        _put_list(image, target, lenders, [None] * count)
    else:
        _nodes, records = _put_list(image, target, [observer_ref], [(100, 200, 56_564_448)])
        image.short_at.add(records[0] + 0x28)

    field = _read(image, observer, target, permission)[loans.FIELD]
    assert field["status"] == "unknown" and field["partial"] is True and field["complete"] is False
    assert field["reason"] == expected_reason
    assert field["raw_inputs"]["reads"]
    _assert_budget(field)


@pytest.mark.parametrize("tamper", ["permission_page", "base", "target", "observer"])
def test_permission_and_binding_mismatches_reject_before_resource_reads(tamper: str):
    image, observer, target, permission = _make_permission()
    _put_list(image, target, [_observer_ref(observer)], [(10, 20, 56_564_448)])
    if tamper == "permission_page":
        changed_permission = deepcopy(permission)
        changed_permission["page"] = visibility.INCOME_PAGE
        changed_base, changed_observer, changed_target = BASE, observer, target
    elif tamper == "base":
        changed_permission = permission
        changed_base, changed_observer, changed_target = BASE + 0x1000, observer, target
    elif tamper == "target":
        changed_permission = permission
        changed_base, changed_observer = BASE, observer
        changed_target = deepcopy(target)
        changed_target["fullref"] = hex(int(target["fullref"], 16) ^ (1 << 48))
        changed_target["fullref_raw_hex"] = int(changed_target["fullref"], 16).to_bytes(8, "little").hex()
    else:
        changed_permission = permission
        changed_base, changed_target = BASE, target
        changed_observer = deepcopy(observer)
        changed_observer["fullref"] = hex(int(observer["fullref"], 16) ^ (1 << 48))
        changed_observer["fullref_raw_hex"] = int(changed_observer["fullref"], 16).to_bytes(8, "little").hex()

    image.reads.clear()
    field = _read(image, changed_observer, changed_target, changed_permission,
                  base=changed_base)[loans.FIELD]
    assert field["status"] == "unknown"
    assert image.reads == []
    assert field["raw_inputs"]["reads"] == []


@pytest.mark.parametrize("changed_role", ["observer", "target"])
def test_live_fullref_change_after_permission_is_rejected_before_list_walk(changed_role: str):
    image, observer, target, permission = _make_permission()
    target_pointer = int(target["country_pointer"], 16)
    observer_pointer = int(observer["country_pointer"], 16)
    _put_list(image, target, [_observer_ref(observer)], [(10, 20, 56_564_448)])
    if changed_role == "target":
        address = target_pointer + 0x20
        new_ref = economy_fixture._fullref("ENG", TARGET_SLOT, 0x2346)
    else:
        address = observer_pointer + 0x20
        new_ref = economy_fixture._fullref("FRA", OBSERVER_SLOT, 0x1235)
    image.put_u64(address, new_ref)
    image.reads.clear()

    field = _read(image, observer, target, permission)[loans.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "FOREIGN_LOANS_BINDING_CHANGED"
    assert "foreign_loans.target_list_head" not in _labels(image)
    assert not any(label.startswith("foreign_loans.financials") for label in _labels(image))


def test_denied_loans_permission_and_unrequested_fields_do_not_read_resources():
    image, observer, target, denied_permission = _make_permission(active_target=False)
    _put_list(image, target, [_observer_ref(observer)], [(10, 20, 56_564_448)])
    image.reads.clear()
    field = _read(image, observer, target, denied_permission)[loans.FIELD]
    assert field["status"] == "unknown"
    assert field["reason"] == "OBSERVER_LENT_LOANS_PERMISSION_NOT_ADMITTED"
    assert image.reads == [] and field["raw_inputs"]["reads"] == []

    image, observer, target, permission = _make_permission()
    _put_list(image, target, [_observer_ref(observer)], [(10, 20, 56_564_448)])
    image.reads.clear()
    assert _read(image, observer, target, permission, fields=()) == {}
    assert _read(image, observer, target, permission, fields=("F03.income",)) == {}
    assert image.reads == []

