"""Read current coalition membership through the bound B23 country table.

The caller owns executable, process, observer and two-pass validation. This
leaf follows the native target handle and its reciprocal member list. Removed
list nodes remain traversal links until the game's deferred cleanup.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
import struct


FIELDS = ("R03.coalition_members", "R03.targets")
TARGET_OFFSET = 0x18F8
MEMBERS_OFFSET = 0x1910
MAX_MEMBERS = 4096
_TAG = re.compile(r"[A-Z0-9]{3}\Z")


def _pointer(value):
    if type(value) is not int or not 0x10000 <= value < 0x800000000000 or value & 7:
        raise ValueError("COALITION_POINTER_INVALID")
    return value


def _read(reader, address, size, label):
    _pointer(address & ~7)
    if address + size > 0x800000000000:
        raise ValueError("COALITION_READ_RANGE_INVALID")
    raw = reader(address, size, "coalition." + label)
    if not isinstance(raw, bytes) or len(raw) != size:
        raise ValueError("COALITION_SHORT_READ")
    return raw


def _country(reader, scan, reference):
    rows = scan.get("rows")
    slot = (reference >> 32) & 0xFFFF
    if (not isinstance(rows, list) or type(scan.get("count")) is not int
            or len(rows) != scan["count"] or not 0 <= slot < len(rows)):
        raise ValueError("COALITION_COUNTRY_SLOT_INVALID")
    row = rows[slot]
    if (not isinstance(row, Mapping) or row.get("slot") != slot
            or row.get("fullref_slot") != slot or row.get("fullref") != hex(reference)
            or not isinstance(row.get("tag"), str) or not _TAG.fullmatch(row["tag"])):
        raise ValueError("COALITION_COUNTRY_REFERENCE_MISMATCH")
    pointer = _pointer(int(row["country_pointer"], 0))
    entry = _pointer(int(row["table_entry_address"], 0))
    if (_read(reader, entry, 8, row["tag"] + ".table_entry") != pointer.to_bytes(8, "little")
            or _read(reader, pointer + 0x20, 8, row["tag"] + ".fullref")
            != reference.to_bytes(8, "little")):
        raise ValueError("COALITION_COUNTRY_BINDING_CHANGED")
    return {"tag": row["tag"], "slot": slot, "country_pointer": hex(pointer),
            "fullref": hex(reference), "fullref_raw_hex": row["fullref_raw_hex"],
            "country_fullref_address": row["fullref_address"],
            "table_entry_address": row["table_entry_address"],
            "table_entry_raw_hex": row["table_entry_raw_hex"]}


def _list(reader, binding, cache):
    tag, pointer = binding["tag"], int(binding["country_pointer"], 0)
    if tag in cache:
        return cache[tag]

    def header(phase):
        raw = _read(reader, pointer + MEMBERS_OFFSET, 24, tag + ".members." + phase)
        head, tail, count = struct.unpack_from("<QQi", raw)
        if not 0 <= count <= MAX_MEMBERS or raw[20] not in (0, 1):
            raise ValueError("COALITION_LIST_HEADER_INVALID")
        if bool(head) != bool(count) or bool(tail) != bool(count):
            raise ValueError("COALITION_LIST_ENDPOINT_MISMATCH")
        return head, tail, count, raw[20]

    before = header("before")
    node, tail, count, _ = before
    previous, seen, members = 0, set(), []
    for _ in range(count):
        _pointer(node)
        if node in seen:
            raise ValueError("COALITION_LIST_CYCLE")
        seen.add(node)
        raw = _read(reader, node, 32, tag + ".member_node")
        reference, prior, following = struct.unpack_from("<QQQ", raw)
        removed = raw[24]
        if prior != previous or removed not in (0, 1):
            raise ValueError("COALITION_MEMBER_LINK_INVALID")
        members.append({"reference": reference, "previous": prior,
                        "next": following, "removed": bool(removed)})
        previous, node = node, following
    if node or previous != tail or header("after") != before:
        raise ValueError("COALITION_LIST_CHANGED_OR_COUNT_MISMATCH")
    result = {"header": list(before), "nodes": members}
    cache[tag] = result
    return result


def read_fields(reader, module_base, binding, requested, *, country_scan,
                admit_country=None):
    """Return independently known member and target lists for one country.

    `admit_country` is supplied by the identity-bound parent to verify visible
    country references. A missing callback leaves visibility to the caller.
    Private graph evidence participates in the parent's two-pass comparison.
    """
    read = getattr(reader, "read", reader)
    cache, result = {}, {}
    own_reference = int(binding["fullref"], 0)

    def admit(member):
        if admit_country is not None and admit_country(member) is not True:
            raise ValueError("COALITION_COUNTRY_VISIBILITY_UNVERIFIED")

    for field in requested:
        try:
            if field not in FIELDS:
                raise ValueError("COALITION_FIELD_NOT_SUPPORTED")
            own = _country(read, country_scan, own_reference)
            if own["tag"] != binding["tag"] or own["country_pointer"] != binding["country_pointer"]:
                raise ValueError("COALITION_TARGET_BINDING_MISMATCH")
            tags, evidence = [], {}
            if field == FIELDS[0]:
                graph = _list(read, own, cache)
                for node in graph["nodes"]:
                    if node["removed"]:
                        continue
                    member = _country(read, country_scan, node["reference"])
                    if member["tag"] == own["tag"] or member["tag"] in tags:
                        raise ValueError("COALITION_MEMBER_DUPLICATE_OR_SELF")
                    target = _read(read, int(member["country_pointer"], 0) + TARGET_OFFSET,
                                   8, member["tag"] + ".target")
                    if int.from_bytes(target, "little") != own_reference:
                        raise ValueError("COALITION_MEMBER_TARGET_MISMATCH")
                    admit(member)
                    tags.append(member["tag"])
                evidence["members"] = graph
            else:
                raw = _read(read, int(own["country_pointer"], 0) + TARGET_OFFSET,
                            8, own["tag"] + ".target")
                reference = int.from_bytes(raw, "little")
                evidence["target_reference"] = hex(reference)
                # The native setter and predicates use the handle's top byte.
                if reference >> 56:
                    target = _country(read, country_scan, reference)
                    if target["tag"] == own["tag"]:
                        raise ValueError("COALITION_TARGET_IS_SELF")
                    graph = _list(read, target, cache)
                    matches = [node for node in graph["nodes"]
                               if not node["removed"] and node["reference"] == own_reference]
                    if len(matches) != 1:
                        raise ValueError("COALITION_TARGET_MEMBERSHIP_MISMATCH")
                    admit(target)
                    tags.append(target["tag"])
                    evidence["target_members"] = graph
            result[field] = {"status": "known", "value": sorted(tags),
                             "evidence": evidence}
        except (KeyError, TypeError, ValueError, OSError) as exc:
            result[field] = {"status": "unknown", "reason": str(exc)[:180]}
    return result
