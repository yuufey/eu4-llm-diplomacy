"""Read private, bounded province core and claim candidate memberships.

The leaf reuses the province identity, non-player, country-view admission,
and positive-discovery gates from :mod:`province_state_memory`. It reports
only data that those gates and the field-specific readers can validate. A
province's clear discovery bit remains unknown, and the leaf does not classify
full-core status or permanent claims.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import province_state_memory as _state


SCHEMA = "information.province_interest_memory.v1"
FIELDS = ("G01.cores", "G01.claims", "G01.permanent_claims")

# province_state_memory intentionally accepts only its existing G02 field
# namespace. These private aliases let this leaf reuse its two-pass gates
# without adding public G02 fields or changing the pinned G02 source.
_FIELD_ALIASES = {
    "G01.cores": "G02.interest_cores",
    "G01.claims": "G02.interest_claims",
    "G01.permanent_claims": "G02.interest_permanent_claims",
}
_ALIAS_FIELDS = {alias: field for field, alias in _FIELD_ALIASES.items()}

CORE_BEGIN_OFFSET = 0x490
CORE_END_OFFSET = 0x498
CLAIMS_HEAD_OFFSET = 0x4C0
CLAIMS_NEXT_OFFSET = 0x10
MAX_MEMBERS = 256


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if raw_inputs is not None:
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _valid_fields(fields: Any) -> tuple[str, ...] | None:
    if not isinstance(fields, (list, tuple)) or not fields or len(fields) > len(FIELDS):
        return None
    selected: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if type(field) is not str or field not in FIELDS or field in seen:
            return None
        seen.add(field)
        selected.append(field)
    return tuple(selected)


def _record_pointer(binding: Mapping[str, Any]) -> int:
    value = binding.get("record_pointer")
    if type(value) is int:
        record = value
    elif isinstance(value, str):
        record = int(value, 0)
    else:
        raise ValueError("PROVINCE_RECORD_POINTER_INVALID")
    if not _state._is_user_address(record) or record & 7:
        raise ValueError("PROVINCE_RECORD_POINTER_INVALID")
    return record


def _resolve_member(limiter: Any, module_base: int, raw: bytes,
                    label_prefix: str) -> dict[str, Any]:
    resolved = _state._resolve_country_reference(
        limiter, module_base, raw, label_prefix)
    raw_inputs = resolved.get("raw_inputs")
    if resolved.get("status") != "known" or type(resolved.get("value")) is not str:
        return {
            "status": "unknown",
            "reason": resolved.get("reason", "COUNTRY_FULLREF_INVALID"),
            "raw_inputs": deepcopy(dict(raw_inputs)) if isinstance(raw_inputs, Mapping) else {},
        }
    return {
        "status": "known",
        "tag": resolved["value"],
        "raw_inputs": deepcopy(dict(raw_inputs)) if isinstance(raw_inputs, Mapping) else {},
    }


def _read_core_vector(limiter: Any, module_base: int,
                      province_binding: Mapping[str, Any]) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {}
    try:
        record = _record_pointer(province_binding)
        begin_address = _state._checked_add(record, CORE_BEGIN_OFFSET,
                                            "province_interest.cores.begin")
        end_address = _state._checked_add(record, CORE_END_OFFSET,
                                          "province_interest.cores.end")
        header_raw = _state._read_exact(
            limiter, begin_address, 16, "province_interest.cores.vector_header")
        begin = int.from_bytes(header_raw[:8], "little", signed=False)
        end = int.from_bytes(header_raw[8:], "little", signed=False)
        raw_inputs.update({
            "province_record_pointer": hex(record),
            "begin_address": hex(begin_address),
            "end_address": hex(end_address),
            "header_raw_hex": header_raw.hex(),
            "begin_raw_hex": header_raw[:8].hex(),
            "end_raw_hex": header_raw[8:].hex(),
            "begin": hex(begin),
            "end": hex(end),
            "members": [],
        })

        # Equal endpoints denote an empty vector only when they are the null
        # pair or a valid aligned user pointer. Do not accept arbitrary equal
        # integers as evidence of an empty list, and do not read a capacity.
        if begin == end:
            if begin != 0 and (not _state._is_user_address(begin) or begin & 7):
                return _unknown("CORE_VECTOR_POINTERS_INVALID", raw_inputs)
            raw_inputs["count"] = 0
            return {"status": "known", "value": [],
                    "basis": "province_core_fullref_vector_after_positive_discovery",
                    "raw_inputs": raw_inputs}
        if (not _state._is_user_address(begin)
                or not _state._is_user_address(end)
                or begin & 7 or end & 7 or end < begin):
            return _unknown("CORE_VECTOR_POINTERS_INVALID", raw_inputs)
        length = end - begin
        if length % 8:
            return _unknown("CORE_VECTOR_LENGTH_MISALIGNED", raw_inputs)
        count = length // 8
        raw_inputs["count"] = count
        if count > MAX_MEMBERS:
            return _unknown("CORE_VECTOR_COUNT_OUT_OF_RANGE", raw_inputs)
        _state._checked_range(begin, length, "province_interest.cores.vector")

        tags: list[str] = []
        seen_fullrefs: set[int] = set()
        seen_tags: set[str] = set()
        for index in range(count):
            address = _state._checked_add(
                begin, index * 8, f"province_interest.cores.member[{index}]")
            member_raw = _state._read_exact(
                limiter, address, 8, f"province_interest.cores.member[{index}].fullref")
            fullref = int.from_bytes(member_raw, "little", signed=False)
            member: dict[str, Any] = {
                "index": index,
                "address": hex(address),
                "fullref_raw_hex": member_raw.hex(),
                "fullref": hex(fullref),
            }
            raw_inputs["members"].append(member)
            if fullref in seen_fullrefs:
                member["country_reference"] = {"status": "unknown",
                                               "reason": "DUPLICATE_CORE_FULLREF"}
                return _unknown("DUPLICATE_CORE_FULLREF", raw_inputs)
            seen_fullrefs.add(fullref)
            resolved = _resolve_member(
                limiter, module_base, member_raw,
                f"province_interest.cores.member[{index}]")
            member["country_reference"] = resolved
            if resolved.get("status") != "known":
                return _unknown("CORE_MEMBER_FULLREF_INVALID", raw_inputs)
            tag = resolved["tag"]
            if tag in seen_tags:
                return _unknown("DUPLICATE_CORE_TAG", raw_inputs)
            seen_tags.add(tag)
            tags.append(tag)

        return {"status": "known", "value": tags,
                "basis": "province_core_fullref_vector_after_positive_discovery",
                "raw_inputs": raw_inputs}
    except _state._ReadFailure as exc:
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        return _unknown(f"CORE_VECTOR_READ_FAILED:{type(exc).__name__}", raw_inputs)


def _read_claim_list(limiter: Any, module_base: int,
                     province_binding: Mapping[str, Any]) -> dict[str, Any]:
    raw_inputs: dict[str, Any] = {}
    try:
        record = _record_pointer(province_binding)
        head_address = _state._checked_add(
            record, CLAIMS_HEAD_OFFSET, "province_interest.claims.head")
        head_raw = _state._read_exact(
            limiter, head_address, 8, "province_interest.claims.head_pointer")
        node = int.from_bytes(head_raw, "little", signed=False)
        raw_inputs.update({
            "province_record_pointer": hex(record),
            "head_address": hex(head_address),
            "head_raw_hex": head_raw.hex(),
            "head_pointer": hex(node),
            "count": 0,
            "nodes": [],
        })
        if node == 0:
            return {"status": "known", "value": [],
                    "basis": "province_claim_fullref_chain_after_positive_discovery",
                    "raw_inputs": raw_inputs}
        if not _state._is_user_address(node) or node & 7:
            return _unknown("CLAIM_NODE_POINTER_INVALID", raw_inputs)

        tags: list[str] = []
        seen_nodes: set[int] = set()
        seen_node_ranges: list[tuple[int, int]] = []
        seen_fullrefs: set[int] = set()
        seen_tags: set[str] = set()
        while node:
            if len(tags) >= MAX_MEMBERS:
                return _unknown("CLAIM_NODE_COUNT_OUT_OF_RANGE", raw_inputs)
            if not _state._is_user_address(node) or node & 7:
                return _unknown("CLAIM_NODE_POINTER_INVALID", raw_inputs)
            if node in seen_nodes:
                return _unknown("CLAIM_NODE_CYCLE", raw_inputs)
            seen_nodes.add(node)
            node_range = _state._checked_range(
                node, CLAIMS_NEXT_OFFSET + 8,
                "province_interest.claims.node")
            if any(_state._overlaps(node_range, prior)
                   for prior in seen_node_ranges):
                # A next pointer into any already visited node could reinterpret
                # its opaque +8 payload (or another field) as a new fullref.
                return _unknown("CLAIM_NODE_RANGES_OVERLAP", raw_inputs)
            seen_node_ranges.append(node_range)
            fullref_address = node
            next_address = _state._checked_add(
                node, CLAIMS_NEXT_OFFSET, "province_interest.claims.next")
            fullref_raw = _state._read_exact(
                limiter, fullref_address, 8,
                f"province_interest.claims.node[{len(tags)}].fullref")
            next_raw = _state._read_exact(
                limiter, next_address, 8,
                f"province_interest.claims.node[{len(tags)}].next")
            fullref = int.from_bytes(fullref_raw, "little", signed=False)
            next_node = int.from_bytes(next_raw, "little", signed=False)
            item: dict[str, Any] = {
                "index": len(tags),
                "node_pointer": hex(node),
                "fullref_address": hex(fullref_address),
                "fullref_raw_hex": fullref_raw.hex(),
                "fullref": hex(fullref),
                "next_address": hex(next_address),
                "next_raw_hex": next_raw.hex(),
                "next_pointer": hex(next_node),
            }
            raw_inputs["nodes"].append(item)
            raw_inputs["count"] = len(raw_inputs["nodes"])
            if fullref in seen_fullrefs:
                item["country_reference"] = {"status": "unknown",
                                              "reason": "DUPLICATE_CLAIM_FULLREF"}
                return _unknown("DUPLICATE_CLAIM_FULLREF", raw_inputs)
            seen_fullrefs.add(fullref)
            resolved = _resolve_member(
                limiter, module_base, fullref_raw,
                f"province_interest.claims.node[{len(tags)}]")
            item["country_reference"] = resolved
            if resolved.get("status") != "known":
                return _unknown("CLAIM_MEMBER_FULLREF_INVALID", raw_inputs)
            tag = resolved["tag"]
            if tag in seen_tags:
                return _unknown("DUPLICATE_CLAIM_TAG", raw_inputs)
            seen_tags.add(tag)
            tags.append(tag)

            if next_node:
                if not _state._is_user_address(next_node) or next_node & 7:
                    return _unknown("CLAIM_NODE_POINTER_INVALID", raw_inputs)
                if next_node in seen_nodes:
                    return _unknown("CLAIM_NODE_CYCLE", raw_inputs)
                if any(_state._overlaps((next_node, next_node + CLAIMS_NEXT_OFFSET + 8), prior)
                       for prior in seen_node_ranges):
                    return _unknown("CLAIM_NODE_RANGES_OVERLAP", raw_inputs)
                if len(tags) >= MAX_MEMBERS:
                    return _unknown("CLAIM_NODE_COUNT_OUT_OF_RANGE", raw_inputs)
            node = next_node

        return {"status": "known", "value": tags,
                "basis": "province_claim_fullref_chain_after_positive_discovery",
                "raw_inputs": raw_inputs}
    except _state._ReadFailure as exc:
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        return _unknown(f"CLAIM_CHAIN_READ_FAILED:{type(exc).__name__}", raw_inputs)


def _read_fields(limiter: Any, module_base: int,
                 province_binding: Mapping[str, Any],
                 fields: tuple[str, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for alias in fields:
        public_field = _ALIAS_FIELDS.get(alias)
        if public_field == "G01.cores":
            result[alias] = _read_core_vector(limiter, module_base, province_binding)
        elif public_field == "G01.claims":
            result[alias] = _read_claim_list(limiter, module_base, province_binding)
        elif public_field == "G01.permanent_claims":
            # This layout is not established. Do not read the opaque +8 claim
            # node payload or infer permanence from ordinary modifiers.
            result[alias] = _unknown("PERMANENT_CLAIM_LAYOUT_NOT_CLOSED")
        else:
            result[alias] = _unknown("UNSUPPORTED_FIELD_READER")
    return result


def _remap_fields(raw: Any, selected: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {field: _unknown("FIELD_RESULT_INVALID") for field in selected}
    return {
        field: deepcopy(raw.get(_FIELD_ALIASES[field],
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
    """Read selected G01 province-interest fields behind shared admission gates.

    The returned packet follows ``province_state_memory``'s two-pass envelope,
    but exposes only G01 field names.  The core and claim members are private
    reader outputs; a parent must apply its own profile and publication gates.
    """
    selected = _valid_fields(fields)
    if selected is None:
        return _invalid_result(province_id, observer)

    aliases = tuple(_FIELD_ALIASES[field] for field in selected)
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
                copied["fields_raw"] = _remap_fields(copied.get("fields_raw"), selected)
                mapped_passes[phase] = copied
            else:
                mapped_passes[phase] = item
        result["pass_evidence"] = mapped_passes
    return result


__all__ = ["SCHEMA", "FIELDS", "MAX_MEMBERS", "read_two_pass"]
