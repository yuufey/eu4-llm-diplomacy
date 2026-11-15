"""Narrow offline tests for the r3 permanent-claim predicate reader."""
from __future__ import annotations

import pytest

from bridge.information import province_permanent_claim_memory as memory
from bridge.tests.test_information_province_interest_memory import (
    BASE,
    CLAIM_NODES,
    COUNTRY_TAG_SLOTS,
    MemoryImage,
    PROVINCE_ID,
    _fullref,
    _province_record,
    _put_claim_chain,
    make_image,
)


HISTORY_FIRST_NODES = 0x6000000000
HISTORY_SECOND_NODES = 0x6100000000
HISTORY_CHILDREN = 0x6200000000
HISTORY_VTABLE = BASE + memory.RDATA_RVA_BEGIN + 0x100
HISTORY_METHOD = BASE + memory.TEXT_RVA_BEGIN + 0x100
K = memory.NATIVE_THRESHOLD


def _field(result: dict) -> dict:
    return result["targets"][0]["fields"]["G01.permanent_claims"]


def _put_child(image: MemoryImage, address: int, fullref: int, scalar: int,
               *, type_id: int = memory.CLAIM_RECORD_TYPE_ID,
               getter: str = "mov", method_index: int = 0) -> None:
    vtable = HISTORY_VTABLE + method_index * 0x100
    method = HISTORY_METHOD + method_index * 0x20
    image.put_u64(address, vtable)
    image.put_u64(vtable + memory.TYPE_METHOD_OFFSET, method)
    if getter == "mov":
        code = b"\xb8" + type_id.to_bytes(4, "little") + b"\xc3"
    elif getter == "xor":
        code = b"\x31\xc0\xc3"
    else:
        code = b"\x90\x90\x90\x90\x90\x90"
    image.put(method, code)
    image.put_i32(address + memory.RECORD_SCALAR_OFFSET, scalar)
    if type_id == memory.CLAIM_RECORD_TYPE_ID:
        image.put_u64(address + memory.ACTIVE_FULLREF_OFFSET, fullref)


def _put_list(image: MemoryImage, specs: list[dict], *, first: bool,
              next_override: int | None = None) -> tuple[int, list[int]]:
    if not specs:
        return 0, []
    base = HISTORY_FIRST_NODES if first else HISTORY_SECOND_NODES
    next_offset = (memory.FIRST_NODE_NEXT_OFFSET if first
                   else memory.SECOND_NODE_NEXT_OFFSET)
    nodes = [base + index * 0x100 for index in range(len(specs))]
    children = []
    for index, spec in enumerate(specs):
        child = HISTORY_CHILDREN + (index + (0 if first else 0x100)) * 0x100
        children.append(child)
        _put_child(image, child, spec["fullref"], spec.get("scalar", 0),
                   type_id=spec.get("type_id", memory.CLAIM_RECORD_TYPE_ID),
                   getter=spec.get("getter", "mov"),
                   method_index=spec.get("method_index", index + (0 if first else 8)))
        image.put_u64(nodes[index], child)
        if index + 1 < len(nodes):
            next_node = nodes[index + 1]
        elif next_override is not None:
            next_node = next_override
        else:
            next_node = 0
        image.put_u64(nodes[index] + next_offset, next_node)
    return nodes[0], children


def _make_image(tags: tuple[str, ...] = ("ENG",), *, first=(), second=(),
                discovered: bool = True, admitted: bool = True,
                role_verified: bool = True, first_next_override=None):
    image = make_image(discovered=discovered, admitted=admitted,
                       role_verified=role_verified)
    active_refs = [_fullref(tag, COUNTRY_TAG_SLOTS[tag]) for tag in tags]
    if active_refs:
        _put_claim_chain(image, active_refs)
    record = _province_record()
    first_specs = [dict(item) for item in first]
    second_specs = [dict(item) for item in second]
    first_head, first_children = _put_list(
        image, first_specs, first=True, next_override=first_next_override)
    second_head, second_children = _put_list(image, second_specs, first=False)
    group = record + memory.HISTORY_GROUP_OFFSET
    image.put_u64(group + memory.FIRST_LIST_OFFSET, first_head)
    image.put_u64(group + memory.SECOND_LIST_OFFSET, second_head)
    return image, active_refs, [*first_children, *second_children]


def _spec(tag: str, scalar: int, **extra) -> dict:
    return {"fullref": _fullref(tag, COUNTRY_TAG_SLOTS[tag]),
            "scalar": scalar, **extra}


def test_first_list_matches_exact_threshold_and_preserves_active_claim_order():
    image, _refs, _children = _make_image(
        tags=("SWE", "ENG"),
        first=[_spec("ENG", K), _spec("SWE", K)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert result["schema"] == memory.SCHEMA
    assert _field(result)["status"] == "known"
    assert _field(result)["value"] == ["SWE", "ENG"]


def test_first_list_does_not_treat_any_lower_scalar_as_a_match():
    image, _refs, _children = _make_image(first=[_spec("ENG", K - 1)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result) == {
        "status": "known",
        "value": [],
        "basis": "native_permanent_claim_predicate_after_positive_discovery",
        "raw_inputs": _field(result)["raw_inputs"],
    }


@pytest.mark.parametrize("scalar,expected", [(-1, True), (K, True), (K + 1, False)])
def test_second_list_applies_signed_final_threshold(scalar: int, expected: bool):
    image, _refs, _children = _make_image(first=[], second=[_spec("ENG", scalar)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    field = _field(result)
    assert field["status"] == "known"
    assert field["value"] == (["ENG"] if expected else [])


def test_empty_active_claims_are_known_empty_without_history_reads():
    image, _refs, _children = _make_image(tags=(), first=[_spec("ENG", K)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "known"
    assert _field(result)["value"] == []
    assert not any("province_permanent.history" in label for _, _, label in image.reads)


def test_unknown_type_getter_fails_closed_without_executing_code():
    image, _refs, _children = _make_image(first=[_spec("ENG", K, getter="unknown")])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "HISTORY_TYPE_GETTER_UNKNOWN"


def test_matching_slot_with_noncanonical_history_fullref_is_unknown():
    image, _refs, _children = _make_image(
        first=[{"fullref": _fullref("ENG", COUNTRY_TAG_SLOTS["ENG"], generation=0x1300),
                "scalar": K}])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "HISTORY_ACTIVE_FULLREF_MISMATCH"


def test_history_list_cycle_and_overlapping_node_fail_closed():
    image, _refs, children = _make_image(first=[_spec("ENG", K - 1)])
    first_node = HISTORY_FIRST_NODES
    image.put_u64(first_node + memory.FIRST_NODE_NEXT_OFFSET, first_node)
    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "HISTORY_LIST_CYCLE"

    image, _refs, children = _make_image(first=[_spec("ENG", K - 1), _spec("ENG", K - 1)])
    image.put_u64(HISTORY_FIRST_NODES + memory.FIRST_NODE_NEXT_OFFSET,
                  HISTORY_FIRST_NODES + 8)
    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "HISTORY_GRAPH_RANGE_OVERLAP"


def test_graph_entry_bound_is_hard_and_not_silently_truncated(monkeypatch):
    image, _refs, _children = _make_image(first=[_spec("ENG", K)])
    monkeypatch.setattr(memory, "MAX_GRAPH_ENTRIES", 1)

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "HISTORY_GRAPH_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"discovered": False}, "PROVINCE_DISCOVERY_NOT_ESTABLISHED"),
        ({"role_verified": False}, "OBSERVER_ROLE_NOT_VERIFIED"),
        ({"admitted": False}, "PROVINCE_SELF_ADMISSION_NOT_ESTABLISHED"),
    ],
)
def test_shared_fra_discovery_and_nonplayer_gates_prevent_history_reads(kwargs, reason):
    image, _refs, _children = _make_image(first=[_spec("ENG", K)], **kwargs)

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == reason
    assert not any("province_permanent.history" in label for _, _, label in image.reads)


def test_second_pass_history_scalar_drift_withdraws_only_permanent_field():
    image, _refs, children = _make_image(second=[_spec("ENG", K)])
    child = children[0]

    class Drift:
        def __init__(self):
            self.seen = 0

        def read(self, address, size, label):
            if label == "province_permanent.history.record.scalar":
                self.seen += 1
                if self.seen == 2:
                    image.put_i32(child + memory.RECORD_SCALAR_OFFSET, K + 1)
            return image.read(address, size, label)

    result = memory.read_two_pass(Drift(), BASE, PROVINCE_ID)

    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "FIELD_RAW_DATA_CHANGED"


def test_invalid_text_method_pointer_is_unknown_and_bounded():
    image, _refs, children = _make_image(first=[_spec("ENG", K)])
    child = children[0]
    vtable = HISTORY_VTABLE
    image.put_u64(vtable + memory.TYPE_METHOD_OFFSET, BASE + memory.TEXT_RVA_END + 8)

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "HISTORY_TYPE_GETTER_OUT_OF_MODULE_RANGE"


def test_two_claims_share_one_lazy_history_snapshot_and_read_each_address_once_per_pass():
    image, _refs, _children = _make_image(
        tags=("ENG", "SWE"),
        first=[_spec("ENG", K, method_index=0),
               _spec("SWE", K, method_index=0)])

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "known"
    assert _field(result)["value"] == ["ENG", "SWE"]
    raw = _field(result)["raw_inputs"]["history"]
    assert raw["read_cache"]["cache_hits"] > 0
    history_reads = [
        (address, size) for address, size, label in image.reads
        if label.startswith("province_permanent.history")
    ]
    counts = {key: history_reads.count(key) for key in set(history_reads)}
    # Each pass owns a fresh cache; the same graph address may therefore be
    # read twice overall, but never once per claim within a pass.
    assert counts
    assert max(counts.values()) <= 2
    assert len(raw["claim_results"]) == 2


def test_adjacent_nonclaim_objects_use_only_the_common_0x30_range():
    image, _refs, children = _make_image(
        first=[_spec("ENG", K, type_id=0, getter="xor", method_index=0),
               _spec("ENG", K, type_id=0, getter="xor", method_index=1)])
    first_child = children[0]
    adjacent = first_child + 0x30
    _put_child(image, adjacent, _fullref("ENG", COUNTRY_TAG_SLOTS["ENG"]), 0,
               type_id=0, getter="xor", method_index=0)
    image.put_u64(HISTORY_FIRST_NODES + 0x100, adjacent)

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "known"
    assert _field(result)["value"] == []


def test_claim_range_extension_rejects_an_adjacent_object_overlap():
    image, _refs, children = _make_image(
        first=[_spec("ENG", K, method_index=1)])
    claim_child = children[0]
    nonclaim_child = HISTORY_CHILDREN + 0x300
    adjacent = claim_child + 0x30
    _put_child(image, nonclaim_child,
               _fullref("ENG", COUNTRY_TAG_SLOTS["ENG"]), 0,
               type_id=0, getter="xor", method_index=0)
    image.put_u64(_province_record() + memory.HISTORY_GROUP_OFFSET
                  + memory.FIRST_LIST_OFFSET, adjacent)
    image.put_u64(adjacent, nonclaim_child)
    image.put_u64(adjacent + memory.FIRST_NODE_NEXT_OFFSET,
                  HISTORY_FIRST_NODES)
    image.put_u64(HISTORY_FIRST_NODES, claim_child)
    image.put_u64(HISTORY_FIRST_NODES + memory.FIRST_NODE_NEXT_OFFSET, 0)

    result = memory.read_two_pass(image, BASE, PROVINCE_ID)

    assert _field(result)["status"] == "unknown"
    assert _field(result)["reason"] == "HISTORY_GRAPH_RANGE_OVERLAP"
