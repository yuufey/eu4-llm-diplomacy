"""Bounded native predicate projection for G01 permanent claims.

This leaf deliberately lives beside, rather than inside, the r2 province
interest reader.  The r2 reader remains the source of the canonical current
claim list; this module only asks the separately profiled history graph
whether each already-canonical claim satisfies the confirmed native
permanence predicate.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import province_interest_memory as _old
from . import province_state_memory as _state


SCHEMA = "information.province_permanent_claim_memory.v1"
FIELDS = ("G01.permanent_claims",)
MAX_MEMBERS = _old.MAX_MEMBERS
_PUBLIC_TO_ALIAS = {
    "G01.permanent_claims": "G02.interest_permanent_claims",
}
_ALIAS_TO_PUBLIC = {value: key for key, value in _PUBLIC_TO_ALIAS.items()}

# The native helper is called with province-record + 0x30.  Its two child
# lists are at +0x20/+0x28 and have different link widths.
HISTORY_GROUP_OFFSET = 0x30
FIRST_LIST_OFFSET = 0x20
SECOND_LIST_OFFSET = 0x28
FIRST_NODE_NEXT_OFFSET = 0x10
SECOND_NODE_NEXT_OFFSET = 0x8
CHILD_PAYLOAD_OFFSET = 0x0
CHILD_VTABLE_OFFSET = 0x0
TYPE_METHOD_OFFSET = 0x80
ACTIVE_FULLREF_OFFSET = 0x58
RECORD_SCALAR_OFFSET = 0x10

CLAIM_RECORD_TYPE_ID = 0x27C5
NATIVE_THRESHOLD = 0x029C77F8

MAX_DEPTH = 32
MAX_GRAPH_ENTRIES = 1024

# These are the fixed B23 section bounds from the r3 layout evidence.  The
# owner/profile may replace them when the production profile is wired; no
# code pointer is accepted outside a bounded section.
TEXT_RVA_BEGIN = 0x1000
TEXT_RVA_END = 0x1B65CE8
RDATA_RVA_BEGIN = 0x1B66000
RDATA_RVA_END = 0x1FAF8AA


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if raw_inputs is not None:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


class _HistoryFailure(Exception):
    """A bounded history/type graph cannot be trusted."""


class _HistoryReader:
    """State for one bounded history walk and its replay-visible summary."""

    def __init__(self, reader: Any, module_base: int) -> None:
        self.reader = reader
        self.module_base = module_base
        self.entries = 0
        self.entry_keys: set[tuple[str, int]] = set()
        self.entry_ranges: dict[tuple[str, int], tuple[int, int]] = {}
        self.active_nodes: set[int] = set()
        self.active_objects: set[int] = set()
        self.active_groups: set[int] = set()
        self.group_memo: dict[tuple[int, int], tuple[dict[str, Any] | None,
                                                       dict[str, Any] | None]] = {}
        self.ranges: list[tuple[int, int, str]] = []
        self.cache: dict[tuple[int, int], bytes] = {}
        self.cache_hits = 0
        self.raw: dict[str, Any] = {
            "group_offset": hex(HISTORY_GROUP_OFFSET),
            "threshold": NATIVE_THRESHOLD,
            "first_list": None,
            "second_list": None,
            "list_nodes": [],
            "objects": [],
            "type_getters": [],
            "claim_results": [],
        }

    def _entry(self, kind: str, address: int, size: int, label: str) -> None:
        begin, end = _state._checked_range(address, size, label)
        key = (kind, address)
        old_range = self.entry_ranges.get(key)
        if old_range is not None:
            old_begin, old_end = old_range
            if end <= old_end:
                return
            # The same object may be extended after its type is known.  The
            # extension is legal only if it remains disjoint from every other
            # object/list range already admitted to this graph snapshot.
            for prior_begin, prior_end, prior_kind in self.ranges:
                if prior_kind == kind and prior_begin == old_begin:
                    continue
                if begin < prior_end and prior_begin < end:
                    raise _HistoryFailure("HISTORY_GRAPH_RANGE_OVERLAP")
            self.entry_ranges[key] = (old_begin, end)
            for index, (prior_begin, prior_end, prior_kind) in enumerate(self.ranges):
                if (prior_kind == kind and prior_begin == old_begin
                        and prior_end == old_end):
                    self.ranges[index] = (old_begin, end, kind)
                    break
            return
        if key not in self.entry_keys:
            self.entries += 1
            self.entry_keys.add(key)
            if self.entries > MAX_GRAPH_ENTRIES:
                raise _HistoryFailure("HISTORY_GRAPH_LIMIT_EXCEEDED")
        for prior_begin, prior_end, prior_kind in self.ranges:
            if begin < prior_end and prior_begin < end:
                raise _HistoryFailure("HISTORY_GRAPH_RANGE_OVERLAP")
        self.entry_ranges[key] = (begin, end)
        self.ranges.append((begin, end, kind))

    def read(self, address: int, size: int, label: str) -> bytes:
        key = (address, size)
        cached = self.cache.get(key)
        if cached is not None:
            self.cache_hits += 1
            return cached
        raw = _state._read_exact(self.reader, address, size, label)
        self.cache[key] = raw
        return raw

    def u64(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little", signed=False), raw

    def i32(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 4, label)
        return int.from_bytes(raw, "little", signed=True), raw

    def user_pointer(self, value: int, label: str) -> int:
        if type(value) is not int or not _state._is_user_address(value) or value & 7:
            raise _HistoryFailure(f"{label}_INVALID")
        return value

    def module_range(self, address: int, size: int, begin: int, end: int,
                     label: str) -> None:
        if type(address) is not int or type(size) is not int or size <= 0:
            raise _HistoryFailure(f"{label}_INVALID")
        if (address < self.module_base + begin
                or address > self.module_base + end - size):
            raise _HistoryFailure(f"{label}_OUT_OF_MODULE_RANGE")

    def finish(self) -> dict[str, Any]:
        result = deepcopy(self.raw)
        result["entries"] = self.entries
        result["limits"] = {
            "max_depth": MAX_DEPTH,
            "max_graph_entries": MAX_GRAPH_ENTRIES,
        }
        result["read_cache"] = {
            "unique_address_size_reads": len(self.cache),
            "cache_hits": self.cache_hits,
        }
        return result


def _parse_hex(value: Any, label: str) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise _HistoryFailure(f"{label}_INVALID") from exc
    else:
        raise _HistoryFailure(f"{label}_INVALID")
    if type(parsed) is not int or parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise _HistoryFailure(f"{label}_INVALID")
    return parsed


def _valid_module_pointer(reader: _HistoryReader, value: int, begin: int,
                          end: int, label: str, *, aligned: bool = False) -> int:
    if type(value) is not int or (aligned and value & 7):
        raise _HistoryFailure(f"{label}_INVALID")
    if value < reader.module_base + begin or value >= reader.module_base + end:
        raise _HistoryFailure(f"{label}_OUT_OF_MODULE_RANGE")
    return value


def _find_raw_record(rows: list[dict[str, Any]], key: str,
                     value: Any) -> dict[str, Any] | None:
    for row in reversed(rows):
        if row.get(key) == value:
            return row
    return None


def _type_id(reader: _HistoryReader, child: int) -> int:
    """Decode only the two exact immutable getter forms; never execute code."""
    reader.user_pointer(child, "HISTORY_CHILD")
    reader._entry("object", child, 0x30, "history.child")
    vtable, vtable_raw = reader.u64(
        child + CHILD_VTABLE_OFFSET, "province_permanent.history.child.vtable")
    vtable = _valid_module_pointer(
        reader, vtable, RDATA_RVA_BEGIN, RDATA_RVA_END,
        "HISTORY_VTABLE", aligned=True)
    reader.module_range(vtable, TYPE_METHOD_OFFSET + 8,
                        RDATA_RVA_BEGIN, RDATA_RVA_END,
                        "HISTORY_VTABLE_RANGE")
    method_address, method_raw = reader.u64(
        vtable + TYPE_METHOD_OFFSET,
        "province_permanent.history.type_getter_pointer")
    method_address = _valid_module_pointer(
        reader, method_address, TEXT_RVA_BEGIN, TEXT_RVA_END,
        "HISTORY_TYPE_GETTER", aligned=False)
    reader.module_range(method_address, 6, TEXT_RVA_BEGIN, TEXT_RVA_END,
                        "HISTORY_TYPE_GETTER_RANGE")
    code = reader.read(method_address, 6,
                       "province_permanent.history.type_getter_code")
    getter_record = {
        "child": hex(child),
        "vtable": hex(vtable),
        "vtable_raw_hex": vtable_raw.hex(),
        "method": hex(method_address),
        "method_raw_hex": method_raw.hex(),
        "code_hex": code.hex(),
        "status": "unknown",
    }
    existing_getter = _find_raw_record(
        reader.raw["type_getters"], "child", hex(child))
    if existing_getter is None:
        reader.raw["type_getters"].append(getter_record)
    else:
        existing_getter.update(getter_record)
        getter_record = existing_getter
    object_record = _find_raw_record(
        reader.raw["objects"], "address", hex(child))
    if object_record is None:
        object_record = {"address": hex(child), "vtable": hex(vtable)}
        reader.raw["objects"].append(object_record)
    else:
        object_record.update({"vtable": hex(vtable)})
    value: int | None = None
    form: str | None = None
    if code[0] == 0xB8 and code[5] == 0xC3:
        value = int.from_bytes(code[1:5], "little", signed=False)
        form = "mov_eax_imm32_ret"
    elif code[:3] in (b"\x31\xc0\xc3", b"\x33\xc0\xc3"):
        value = 0
        form = "xor_eax_eax_ret"
    if value is None or form is None:
        raise _HistoryFailure("HISTORY_TYPE_GETTER_UNKNOWN")
    getter_record.update({"status": "known", "form": form, "value": value})
    object_record["type_id"] = value
    return value


def _claim_ref(reader: _HistoryReader, child: int, target_ref: int,
               target_slot: int, label: str) -> bool:
    """Return whether child is the exact active canonical claim record."""
    fullref, raw = reader.u64(
        child + ACTIVE_FULLREF_OFFSET, f"{label}.active_fullref")
    slot = (fullref >> 32) & 0xFFFF
    object_record = _find_raw_record(
        reader.raw["objects"], "address", hex(child))
    if object_record is not None:
        object_record.update({
            "active_fullref": hex(fullref),
            "active_fullref_raw_hex": raw.hex(),
            "active_slot": slot,
        })
    if slot != target_slot:
        return False
    if fullref != target_ref:
        raise _HistoryFailure("HISTORY_ACTIVE_FULLREF_MISMATCH")
    return True


def _walk_child(reader: _HistoryReader, child: int, target_ref: int,
                target_slot: int, depth: int, *, first: bool) -> dict[str, Any] | None:
    if depth > MAX_DEPTH:
        raise _HistoryFailure("HISTORY_GRAPH_DEPTH_EXCEEDED")
    reader.user_pointer(child, "HISTORY_CHILD")
    if child in reader.active_objects:
        raise _HistoryFailure("HISTORY_OBJECT_CYCLE")
    reader.active_objects.add(child)
    try:
        type_id = _type_id(reader, child)
        matches = False
        if type_id == CLAIM_RECORD_TYPE_ID:
            reader._entry("object", child, ACTIVE_FULLREF_OFFSET + 8,
                          "history.claim_child")
            matches = _claim_ref(
                reader, child, target_ref, target_slot,
                "province_permanent.history.child")
            if matches and first:
                scalar, scalar_raw = reader.i32(
                    child + RECORD_SCALAR_OFFSET,
                    "province_permanent.history.first.scalar")
                object_record = _find_raw_record(
                    reader.raw["objects"], "address", hex(child))
                if object_record is not None:
                    object_record.update({
                    "scalar": scalar,
                    "scalar_raw_hex": scalar_raw.hex(),
                    })
                if scalar == NATIVE_THRESHOLD:
                    return {"address": child, "scalar": scalar}
        if matches and not first:
            # The native second-list branch returns the matching record before
            # the outer getter applies the final <= threshold test.
            return {"address": child, "scalar": None}

        group_first, group_second = _walk_group(
            reader, child, target_ref, target_slot, depth + 1)
        found = group_first if group_first is not None else group_second
        if found is None:
            return None
        if first:
            scalar, scalar_raw = reader.i32(
                found["address"] + RECORD_SCALAR_OFFSET,
                "province_permanent.history.recursive_first.scalar")
            matched_record = _find_raw_record(
                reader.raw["objects"], "address", hex(found["address"]))
            if matched_record is None:
                matched_record = {"address": hex(found["address"])}
                reader.raw["objects"].append(matched_record)
            matched_record.update({
                "recursive_scalar": scalar,
                "recursive_scalar_raw_hex": scalar_raw.hex(),
            })
            return found if scalar == NATIVE_THRESHOLD else None
        return found
    finally:
        reader.active_objects.remove(child)


def _walk_list(reader: _HistoryReader, head: int, target_ref: int,
               target_slot: int, depth: int, *, first: bool) -> dict[str, Any] | None:
    node = head
    seen_chain: set[int] = set()
    next_offset = FIRST_NODE_NEXT_OFFSET if first else SECOND_NODE_NEXT_OFFSET
    node_size = next_offset + 8
    list_name = "first" if first else "second"
    while node:
        current_node = reader.user_pointer(
            node, f"HISTORY_{list_name.upper()}_NODE")
        if current_node in seen_chain or current_node in reader.active_nodes:
            raise _HistoryFailure("HISTORY_LIST_CYCLE")
        seen_chain.add(current_node)
        reader._entry("list_node", current_node, node_size,
                      f"history.{list_name}.node")
        reader.active_nodes.add(current_node)
        try:
            payload, payload_raw = reader.u64(
                current_node + CHILD_PAYLOAD_OFFSET,
                f"province_permanent.history.{list_name}.payload")
            payload = reader.user_pointer(payload, "HISTORY_CHILD")
            next_node, next_raw = reader.u64(
                current_node + next_offset,
                f"province_permanent.history.{list_name}.next")
            if next_node:
                reader.user_pointer(next_node, "HISTORY_NEXT_NODE")
            if _find_raw_record(reader.raw["list_nodes"], "address",
                                hex(current_node)) is None:
                reader.raw["list_nodes"].append({
                    "list": list_name,
                    "address": hex(current_node),
                    "payload": hex(payload),
                    "payload_raw_hex": payload_raw.hex(),
                    "next": hex(next_node) if next_node else None,
                    "next_raw_hex": next_raw.hex(),
                })
            found = _walk_child(
                reader, payload, target_ref, target_slot, depth, first=first)
            if found is not None:
                return found
            node = next_node
        finally:
            reader.active_nodes.remove(current_node)
    return None


def _walk_group(reader: _HistoryReader, group: int, target_ref: int,
                target_slot: int, depth: int) -> tuple[dict[str, Any] | None,
                                                       dict[str, Any] | None]:
    if depth > MAX_DEPTH:
        raise _HistoryFailure("HISTORY_GRAPH_DEPTH_EXCEEDED")
    reader.user_pointer(group, "HISTORY_GROUP")
    if group in reader.active_groups:
        raise _HistoryFailure("HISTORY_GROUP_CYCLE")
    memo_key = (group, target_ref)
    memoized = reader.group_memo.get(memo_key)
    if memoized is not None:
        return deepcopy(memoized)
    reader.active_groups.add(group)
    try:
        first_cell = _state._checked_add(group, FIRST_LIST_OFFSET,
                                         "province_permanent.history.first_cell")
        first, first_raw = reader.u64(
            first_cell, "province_permanent.history.first_head")
        group_key = (hex(group), "first")
        if not any(item.get("group") == group_key[0]
                   and item.get("which") == group_key[1]
                   for item in reader.raw.setdefault("group_reads", [])):
            reader.raw["group_reads"].append({
                "group": hex(group),
                "which": "first",
                "first_cell": hex(first_cell),
                "first_raw_hex": first_raw.hex(),
            })
        reader.raw["first_list"] = hex(first) if first else None
        if first:
            found = _walk_list(reader, first, target_ref, target_slot, depth,
                               first=True)
            if found is not None:
                result = (found, None)
                reader.group_memo[memo_key] = deepcopy(result)
                return result
        second_cell = _state._checked_add(group, SECOND_LIST_OFFSET,
                                          "province_permanent.history.second_cell")
        second, second_raw = reader.u64(
            second_cell, "province_permanent.history.second_head")
        group_key = (hex(group), "second")
        if not any(item.get("group") == group_key[0]
                   and item.get("which") == group_key[1]
                   for item in reader.raw["group_reads"]):
            reader.raw["group_reads"].append({
                "group": hex(group),
                "which": "second",
                "second_cell": hex(second_cell),
                "second_raw_hex": second_raw.hex(),
            })
        reader.raw["second_list"] = hex(second) if second else None
        if second:
            found = _walk_list(reader, second, target_ref, target_slot, depth,
                               first=False)
            if found is not None:
                result = (None, found)
                reader.group_memo[memo_key] = deepcopy(result)
                return result
        result = (None, None)
        reader.group_memo[memo_key] = deepcopy(result)
        return result
    finally:
        reader.active_groups.remove(group)


def _history_for_claim(history: _HistoryReader, record: int,
                       fullref: int) -> dict[str, Any]:
    target_slot = (fullref >> 32) & 0xFFFF
    try:
        group = _state._checked_add(
            record, HISTORY_GROUP_OFFSET, "province_permanent.history.group")
        first, second = _walk_group(
            history, group, fullref, target_slot, 0)
        found = first or second
        if found is None:
            return {"status": "known", "value": False}
        scalar = found.get("scalar")
        if scalar is None:
            scalar, scalar_raw = history.i32(
                found["address"] + RECORD_SCALAR_OFFSET,
                "province_permanent.history.record.scalar")
            history.raw.setdefault("matched_records", []).append({
                "address": hex(found["address"]),
                "scalar": scalar,
                "scalar_raw_hex": scalar_raw.hex(),
            })
        return {"status": "known", "value": scalar <= NATIVE_THRESHOLD,
                "matched_record": {"address": hex(found["address"]),
                                   "scalar": scalar}}
    except _state._ReadFailure as exc:
        return _unknown(str(exc))
    except _HistoryFailure as exc:
        return _unknown(str(exc))
    except Exception as exc:
        return _unknown(f"HISTORY_READ_FAILED:{type(exc).__name__}")


def _canonical_claim_fullref(node: Mapping[str, Any]) -> int:
    raw = node.get("country_reference")
    if not isinstance(raw, Mapping) or raw.get("status") != "known":
        raise _HistoryFailure("ACTIVE_CLAIM_REFERENCE_UNKNOWN")
    inputs = raw.get("raw_inputs")
    if not isinstance(inputs, Mapping):
        raise _HistoryFailure("ACTIVE_CLAIM_REFERENCE_RAW_MISSING")
    canonical = _parse_hex(inputs.get("canonical_fullref"),
                           "ACTIVE_CLAIM_CANONICAL_FULLREF")
    current = _parse_hex(node.get("fullref"), "ACTIVE_CLAIM_FULLREF")
    if canonical != current:
        raise _HistoryFailure("ACTIVE_CLAIM_CANONICAL_FULLREF_MISMATCH")
    return canonical


def _read_permanent_claims(limiter: Any, module_base: int,
                           province_binding: Mapping[str, Any]) -> dict[str, Any]:
    """Read only canonical active claims, then classify each independently."""
    try:
        claims = _old._read_claim_list(limiter, module_base, province_binding)
    except Exception as exc:
        return _unknown(f"ACTIVE_CLAIMS_READ_FAILED:{type(exc).__name__}")
    if not isinstance(claims, Mapping) or claims.get("status") != "known":
        reason = claims.get("reason", "ACTIVE_CLAIMS_UNKNOWN") if isinstance(claims, Mapping) else "ACTIVE_CLAIMS_INVALID"
        raw = claims.get("raw_inputs") if isinstance(claims, Mapping) else None
        return _unknown(str(reason), {"active_claims": deepcopy(raw)} if isinstance(raw, Mapping) else None)
    tags = claims.get("value")
    raw_claims = claims.get("raw_inputs")
    if not isinstance(tags, list) or not isinstance(raw_claims, Mapping):
        return _unknown("ACTIVE_CLAIMS_RESULT_INVALID")
    # Empty canonical claims are a known empty result and must not touch the
    # history graph or any type getter.
    if not tags:
        return {
            "status": "known", "value": [],
            "basis": "native_permanent_claim_predicate_after_positive_discovery",
            "raw_inputs": {"active_claims": deepcopy(dict(raw_claims)),
                           "history": [], "claim_count": 0},
        }
    try:
        record = _old._record_pointer(province_binding)
    except Exception as exc:
        return _unknown(
            f"ACTIVE_CLAIM_RECORD_POINTER_INVALID:{type(exc).__name__}",
            {"active_claims": deepcopy(dict(raw_claims))})
    nodes = raw_claims.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != len(tags):
        return _unknown("ACTIVE_CLAIMS_NODE_SUMMARY_INVALID",
                        {"active_claims": deepcopy(dict(raw_claims))})
    history = _HistoryReader(limiter, module_base)
    history.raw["province_record_pointer"] = hex(record)
    permanent: list[str] = []
    for tag, node in zip(tags, nodes):
        if not isinstance(tag, str) or not isinstance(node, Mapping):
            return _unknown("ACTIVE_CLAIMS_NODE_INVALID",
                            {"active_claims": deepcopy(dict(raw_claims)),
                             "history": history.finish()})
        try:
            fullref = _canonical_claim_fullref(node)
            classified = _history_for_claim(history, record, fullref)
        except _HistoryFailure as exc:
            return _unknown(str(exc), {"active_claims": deepcopy(dict(raw_claims)),
                                       "history": history.finish()})
        claim_result = {
            "tag": tag,
            "fullref": hex(fullref),
            "status": classified.get("status"),
        }
        if "value" in classified:
            claim_result["value"] = classified["value"]
        if "matched_record" in classified:
            claim_result["matched_record"] = deepcopy(classified["matched_record"])
        if "reason" in classified:
            claim_result["reason"] = classified["reason"]
        history.raw["claim_results"].append(claim_result)
        if classified.get("status") != "known":
            return _unknown(classified.get("reason", "HISTORY_UNKNOWN"),
                            {"active_claims": deepcopy(dict(raw_claims)),
                             "history": history.finish()})
        if classified.get("value") is True:
            permanent.append(tag)
    return {
        "status": "known", "value": permanent,
        "basis": "native_permanent_claim_predicate_after_positive_discovery",
        "raw_inputs": {"active_claims": deepcopy(dict(raw_claims)),
                       "history": history.finish(), "claim_count": len(tags)},
    }


def _read_fields(limiter: Any, module_base: int,
                 province_binding: Mapping[str, Any],
                 fields: tuple[str, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for alias in fields:
        if _ALIAS_TO_PUBLIC.get(alias) == "G01.permanent_claims":
            result[alias] = _read_permanent_claims(
                limiter, module_base, province_binding)
        else:
            result[alias] = _unknown("UNSUPPORTED_FIELD_READER")
    return result


def _valid_fields(fields: Any) -> tuple[str, ...] | None:
    if not isinstance(fields, (list, tuple)) or not fields or len(fields) > len(FIELDS):
        return None
    selected: list[str] = []
    for field in fields:
        if type(field) is not str or field not in FIELDS or field in selected:
            return None
        selected.append(field)
    return tuple(selected)


def _remap_fields(raw: Any, selected: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {field: _unknown("FIELD_RESULT_INVALID") for field in selected}
    return {
        field: deepcopy(raw.get(_PUBLIC_TO_ALIAS[field],
                                _unknown("FIELD_RESULT_MISSING")))
        for field in selected
    }


def _invalid_result(province_id: Any, observer: Any) -> dict[str, Any]:
    result = _state._base_result(province_id, observer, fields=())
    result["schema"] = SCHEMA
    result["errors"].append({"code": "field_scope_invalid"})
    target = result["targets"][0]
    target["fields"] = {field: _unknown("FIELD_SCOPE_INVALID") for field in FIELDS}
    target["field_consistency"] = {
        field: {"status": "unknown", "reason": "FIELD_SCOPE_INVALID"}
        for field in FIELDS
    }
    return result


def read_two_pass(reader: Any, base: int, province_id: int, *,
                  observer: str = "FRA",
                  fields: list[str] | tuple[str, ...] = FIELDS,
                  observer_scoped=False) -> dict[str, Any]:
    """Read the permanent-claim predicate after both discovery checks."""
    selected = _valid_fields(fields)
    if selected is None:
        return _invalid_result(province_id, observer)
    aliases = tuple(_PUBLIC_TO_ALIAS[field] for field in selected)
    result = _state.read_two_pass(
        reader, base, province_id, observer=observer,
        fields=aliases, read_fields=_read_fields, observer_scoped=observer_scoped)
    result = deepcopy(result)
    result["schema"] = SCHEMA
    targets = result.get("targets")
    if isinstance(targets, list) and targets and isinstance(targets[0], Mapping):
        target = dict(targets[0])
        target["fields"] = _remap_fields(target.get("fields"), selected)
        target["field_consistency"] = _remap_fields(
            target.get("field_consistency"), selected)
        result["targets"] = [target, *targets[1:]]
    passes = result.get("pass_evidence")
    if isinstance(passes, Mapping):
        mapped_passes: dict[str, Any] = {}
        for phase, item in passes.items():
            if isinstance(item, Mapping):
                copied = dict(item)
                copied["fields_raw"] = _remap_fields(
                    copied.get("fields_raw"), selected)
                mapped_passes[phase] = copied
            else:
                mapped_passes[phase] = item
        result["pass_evidence"] = mapped_passes
    return result


__all__ = [
    "SCHEMA", "FIELDS", "MAX_MEMBERS", "MAX_DEPTH", "MAX_GRAPH_ENTRIES",
    "CLAIM_RECORD_TYPE_ID", "NATIVE_THRESHOLD", "read_two_pass",
]
