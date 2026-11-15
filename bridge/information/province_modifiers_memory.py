"""Internal bounded reader for province modifier membership predicates.

This leaf copies only the two contract-pinned modifier-definition tables and
the selected province containers.  It does not open a process, invoke a native
getter/virtual method, register a public source, or decide visibility,
admission, profile identity, or two-pass stability.  The copied offsets and
trivial method-byte checks are an internal candidate until a versioned live
profile and an owning capture contract are added.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import province_identity_memory as _identity


SCHEMA = "information.province_modifiers_memory.v1"
BASIS = "native_province_modifier_membership_candidate_unprofiled"
MAX_PROVINCE_ID = 0xFFFF
MAX_KEYS = 64
MAX_KEY_BYTES = 255
MAX_BUCKETS = 65536
MAX_CHAIN_NODES = 128
MAX_ACTIVE_ITEMS = 128
MAX_READ_BYTES = 256 * 1024
MAX_READ_CALLS = 32768

# These constants are copied from the frozen 1.37.4 native contract.  They are
# not a runtime profile and must not be used to register this leaf for live use.
IMAGE_SIZE = 39714816
PRIMARY_MANAGER_GLOBAL_RVA = 0x242BCE8
SECONDARY_MANAGER_GLOBAL_RVA = 0x242BEB8
PRIMARY_UNMATCHED_SENTINEL_GLOBAL_RVA = 0x2458C48
MANAGER_BUCKET_COUNT_OFFSET = 0x4
MANAGER_BUCKETS_POINTER_OFFSET = 0x8
MANAGER_HEADER_WIDTH = 0x10
HASH_NODE_DEFINITION_OFFSET = 0x0
HASH_NODE_NEXT_OFFSET = 0x8
HASH_NODE_WIDTH = 0x10
DEFINITION_KEY_OFFSET = 0x158
DEFINITION_KEY_LENGTH_OFFSET = 0x168
DEFINITION_KEY_CAPACITY_OFFSET = 0x170
DEFINITION_VTABLE_WIDTH = 8
DEFINITION_KEY_STRING32_WIDTH = 0x20
DEFINITION_KEY_LENGTH_RELATIVE_OFFSET = 0x10
DEFINITION_KEY_CAPACITY_RELATIVE_OFFSET = 0x18
DEFINITION_KIND_SLOT_OFFSET = 0x90
SUPPORTED_TRUE_METHOD_RVA = 0x8F440
SUPPORTED_FALSE_METHOD_RVA = 0x8F450
SUPPORTED_TRUE_METHOD_BYTES = bytes.fromhex("b001c3")
SUPPORTED_FALSE_METHOD_BYTES = bytes.fromhex("32c0c3")
PROVINCE_PRIMARY_BEGIN_OFFSET = 0x2F0
PROVINCE_PRIMARY_END_OFFSET = 0x2F8
INSTANCE_DEFINITION_OFFSET = 0x30
PROVINCE_SECONDARY_ARRAY_OFFSET = 0x310
PROVINCE_SECONDARY_COUNT_OFFSET = 0x31C
POINTER_SIZE = 8

_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,255}\Z", re.ASCII)
_GAPS = [
    "PROVINCE_ADMISSION_DISCOVERY_AND_OBSERVER_ROLE_ARE_PARENT_OWNED",
    "PARENT_PROFILE_SESSION_MODULE_AND_FULL_CODE_GUARDS_NOT_PERFORMED",
    "PARENT_TWO_PASS_CONTEXT_AND_FIELD_STABILITY_NOT_PERFORMED",
    "EFFECTIVE_SCRIPTED_ESTUARY_OR_VOCABULARY_NOT_BOUND",
    "NO_LIVE_SOURCE_REGISTRATION_OR_RUNTIME_OBSERVATION",
]


class _ReadFailure(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _BudgetedReader:
    """One-call exact reader with a byte/call budget and same-call cache."""

    def __init__(self, reader: Any) -> None:
        self.reader = reader
        self.bytes_read = 0
        self.calls = 0
        self.cache_hits = 0
        self.cache: dict[tuple[int, int], bytes] = {}
        self.reads: list[dict[str, Any]] = []
        self.failures: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str, *, fresh: bool = False) -> bytes:
        try:
            _identity._checked_user_range(address, size, label)
        except Exception as exc:
            raise _ReadFailure(f"{label}_range_invalid:{type(exc).__name__}") from exc
        cache_key = (address, size)
        if not fresh and cache_key in self.cache:
            self.cache_hits += 1
            return self.cache[cache_key]
        if size > MAX_READ_BYTES - self.bytes_read:
            raise _ReadFailure("read_budget_exceeded")
        if self.calls >= MAX_READ_CALLS:
            raise _ReadFailure("read_call_budget_exceeded")
        self.calls += 1
        try:
            raw = _identity._read_exact(self.reader, address, size, label)
        except Exception as exc:
            reason = str(exc)
            if reason.startswith("short_read:"):
                code = "short_read"
            elif reason == "reader_read_unavailable":
                code = reason
            else:
                code = f"memory_read_failed:{type(exc).__name__}"
            self.failures.append({
                "label": label,
                "address": hex(address),
                "size": size,
                "reason": code,
            })
            raise _ReadFailure(code) from exc
        self.bytes_read += size
        self.cache[cache_key] = raw
        self.reads.append({
            "label": label,
            "address": hex(address),
            "size": size,
            "raw_hex": raw.hex(),
        })
        return raw


class _ReadState:
    def __init__(self, reader: Any, module_base: int, record: int) -> None:
        self.reader = _BudgetedReader(reader)
        self.module_base = module_base
        self.record = record
        self.managers: dict[str, dict[str, Any]] = {}
        self.manager_errors: dict[str, str] = {}
        self.key_cache: dict[int, dict[str, Any]] = {}
        self.node_cache: dict[int, tuple[int, int]] = {}
        self.manager_snapshots: dict[str, dict[str, Any]] = {}
        self.sentinel_snapshot: dict[str, Any] | None = None
        self.dependencies: dict[str, set[str]] = {}

    def image_address(self, rva: int, size: int, label: str) -> int:
        if type(rva) is not int or rva < 0 or size < 1 or rva + size > IMAGE_SIZE:
            raise _ReadFailure(f"{label}_outside_pinned_image_bounds")
        address = self.module_base + rva
        try:
            _identity._checked_user_range(address, size, label)
        except Exception as exc:
            raise _ReadFailure(f"{label}_address_invalid") from exc
        return address

    @staticmethod
    def user_pointer(value: int, label: str, *, aligned: bool = True) -> int:
        if type(value) is not int:
            raise _ReadFailure(f"{label}_pointer_invalid")
        try:
            return _identity._user_pointer(value, label, aligned=aligned)
        except Exception as exc:
            raise _ReadFailure(str(exc) or f"{label}_pointer_invalid") from exc

    def u64(self, address: int, label: str, *, fresh: bool = False) -> int:
        return int.from_bytes(self.reader.read(address, 8, label, fresh=fresh), "little")

    def manager(self, name: str) -> dict[str, Any]:
        if name in self.manager_errors:
            raise _ReadFailure(self.manager_errors[name])
        if name in self.managers:
            return self.managers[name]
        rva = PRIMARY_MANAGER_GLOBAL_RVA if name == "primary" else SECONDARY_MANAGER_GLOBAL_RVA
        try:
            global_address = self.image_address(rva, 8, f"{name}_manager_global")
            global_raw = self.reader.read(global_address, 8, f"{name}.manager_global")
            manager_pointer = int.from_bytes(global_raw, "little")
            self.user_pointer(manager_pointer, f"{name}_manager", aligned=True)
            header = self.reader.read(manager_pointer, MANAGER_HEADER_WIDTH,
                                      f"{name}.manager_header")
            count = int.from_bytes(
                header[MANAGER_BUCKET_COUNT_OFFSET:MANAGER_BUCKET_COUNT_OFFSET + 4],
                "little",
                signed=False,
            )
            buckets = int.from_bytes(
                header[MANAGER_BUCKETS_POINTER_OFFSET:MANAGER_BUCKETS_POINTER_OFFSET + 8],
                "little",
                signed=False,
            )
            if not 1 <= count <= MAX_BUCKETS:
                raise _ReadFailure(f"{name}_bucket_count_out_of_bounds")
            self.user_pointer(buckets, f"{name}_bucket_table", aligned=True)
            try:
                _identity._checked_user_range(buckets, count * POINTER_SIZE,
                                              f"{name}_bucket_table")
            except Exception as exc:
                raise _ReadFailure(f"{name}_bucket_table_range_invalid") from exc
            result = {
                "global_rva": hex(rva),
                "global_address": hex(global_address),
                "global_raw_hex": global_raw.hex(),
                "manager_pointer": manager_pointer,
                "header_raw_hex": header.hex(),
                "bucket_count": count,
                "buckets_pointer": buckets,
            }
            self.managers[name] = result
            self.manager_snapshots[name] = {
                "global_address": global_address,
                "global_raw": global_raw,
                "manager_pointer": manager_pointer,
                "header_raw": header,
            }
            return result
        except _ReadFailure as exc:
            self.manager_errors[name] = exc.reason
            raise

    @staticmethod
    def hash_key(key: str) -> int:
        value = 0
        for byte in key.encode("ascii"):
            # The supported grammar is ASCII, so signed char equals byte.
            value = ((value + byte) * 61) & 0xFFFFFFFF
        return value

    def definition_key(self, definition: int) -> dict[str, Any]:
        cached = self.key_cache.get(definition)
        if cached is not None:
            return cached
        self.user_pointer(definition, "modifier_definition", aligned=True)
        vtable_raw = self.reader.read(definition, DEFINITION_VTABLE_WIDTH,
                                     "modifier.definition_vtable")
        vtable = int.from_bytes(vtable_raw, "little")
        self.user_pointer(vtable, "modifier_definition_vtable", aligned=True)
        if not self.module_base <= vtable < self.module_base + IMAGE_SIZE:
            raise _ReadFailure("modifier_definition_vtable_outside_module_image")
        key_string32 = self.reader.read(
            definition + DEFINITION_KEY_OFFSET,
            DEFINITION_KEY_STRING32_WIDTH,
            "modifier.definition_key_string32",
        )
        length = int.from_bytes(
            key_string32[DEFINITION_KEY_LENGTH_RELATIVE_OFFSET:
                         DEFINITION_KEY_LENGTH_RELATIVE_OFFSET + 8],
            "little",
            signed=False,
        )
        capacity = int.from_bytes(
            key_string32[DEFINITION_KEY_CAPACITY_RELATIVE_OFFSET:
                         DEFINITION_KEY_CAPACITY_RELATIVE_OFFSET + 8],
            "little",
            signed=False,
        )
        if not 1 <= length <= MAX_KEY_BYTES or capacity < length:
            raise _ReadFailure("modifier_definition_key_metadata_invalid")
        field = key_string32[:8]
        pointer = int.from_bytes(field, "little")
        if capacity < 0x10:
            if length > 15:
                raise _ReadFailure("modifier_definition_inline_key_too_long")
            key_raw = key_string32[:length + 1]
            storage = "inline"
            key_address = definition + DEFINITION_KEY_OFFSET
        else:
            self.user_pointer(pointer, "modifier_definition_key_data", aligned=False)
            key_address = pointer
            key_raw = self.reader.read(pointer, length + 1, "modifier.definition_key_heap")
            storage = "heap"
        if len(key_raw) != length + 1 or key_raw[-1] != 0:
            raise _ReadFailure("modifier_definition_key_terminator_invalid")
        try:
            key = key_raw[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise _ReadFailure("modifier_definition_key_not_ascii") from exc
        if not _KEY_RE.fullmatch(key):
            raise _ReadFailure("modifier_definition_key_invalid")
        result = {
            "definition_pointer": definition,
            "vtable_pointer": vtable,
            "vtable_rva": hex(vtable - self.module_base),
            "key": key,
            "key_raw_hex": key_raw.hex(),
            "key_address": key_address,
            "key_storage": storage,
            "key_length": length,
            "key_capacity": capacity,
            "key_field_raw_hex": field.hex(),
            "vtable_raw_hex": vtable_raw.hex(),
            "key_string32_raw_hex": key_string32.hex(),
        }
        self.key_cache[definition] = result
        return result

    def lookup(self, manager_name: str, key: str) -> dict[str, Any]:
        manager = self.manager(manager_name)
        key_hash = self.hash_key(key)
        bucket_index = key_hash % manager["bucket_count"]
        bucket_address = manager["buckets_pointer"] + bucket_index * POINTER_SIZE
        try:
            _identity._checked_user_range(bucket_address, POINTER_SIZE,
                                          f"{manager_name}_bucket_cell")
        except Exception as exc:
            raise _ReadFailure(f"{manager_name}_bucket_cell_range_invalid") from exc
        current = self.u64(bucket_address, f"{manager_name}.bucket_head[{bucket_index}]")
        visited: set[int] = set()
        candidates: list[dict[str, Any]] = []
        matches: list[int] = []
        while current:
            if len(visited) >= MAX_CHAIN_NODES:
                raise _ReadFailure(f"{manager_name}_chain_limit_exceeded")
            if current in visited:
                raise _ReadFailure(f"{manager_name}_chain_cycle_detected")
            self.user_pointer(current, f"{manager_name}_hash_node", aligned=True)
            visited.add(current)
            node = self.node_cache.get(current)
            if node is None:
                raw = self.reader.read(current, HASH_NODE_WIDTH,
                                       f"{manager_name}.hash_node")
                definition = int.from_bytes(
                    raw[HASH_NODE_DEFINITION_OFFSET:HASH_NODE_DEFINITION_OFFSET + 8], "little")
                next_node = int.from_bytes(
                    raw[HASH_NODE_NEXT_OFFSET:HASH_NODE_NEXT_OFFSET + 8], "little")
                node = (definition, next_node)
                self.node_cache[current] = node
            definition, next_node = node
            self.user_pointer(definition, f"{manager_name}_hash_definition", aligned=True)
            if next_node:
                self.user_pointer(next_node, f"{manager_name}_hash_next", aligned=True)
            detail = self.definition_key(definition)
            candidate_hash = self.hash_key(detail["key"])
            if candidate_hash % manager["bucket_count"] != bucket_index:
                raise _ReadFailure(f"{manager_name}_bucket_hash_mismatch")
            candidates.append({
                "node_pointer": current,
                "definition_pointer": definition,
                "key": detail["key"],
                "key_storage": detail["key_storage"],
                "key_length": detail["key_length"],
                "key_capacity": detail["key_capacity"],
                "vtable_raw_hex": detail["vtable_raw_hex"],
                "key_string32_raw_hex": detail["key_string32_raw_hex"],
                "matches_requested_key": detail["key"] == key,
            })
            if detail["key"] == key:
                matches.append(definition)
            current = next_node
        if len(matches) > 1:
            raise _ReadFailure(f"{manager_name}_duplicate_key_definition")
        return {
            "manager": manager_name,
            "key_hash_u32": key_hash,
            "bucket_index": bucket_index,
            "bucket_count": manager["bucket_count"],
            "bucket_address": hex(bucket_address),
            "nodes_examined": len(visited),
            "candidates": candidates,
            "definition_pointer": matches[0] if matches else None,
        }

    def sentinel(self) -> int:
        if self.sentinel_snapshot is not None:
            return self.sentinel_snapshot["pointer"]
        address = self.image_address(PRIMARY_UNMATCHED_SENTINEL_GLOBAL_RVA,
                                     POINTER_SIZE, "primary_unmatched_sentinel_global")
        raw = self.reader.read(address, POINTER_SIZE, "primary.sentinel_global")
        pointer = int.from_bytes(raw, "little")
        self.user_pointer(pointer, "primary_unmatched_sentinel", aligned=True)
        self.sentinel_snapshot = {
            "global_address": address,
            "global_raw": raw,
            "pointer": pointer,
        }
        return pointer

    def kind_method(self, definition: int, *, sentinel: bool = False) -> dict[str, Any]:
        if sentinel:
            self.user_pointer(definition, "primary_unmatched_sentinel", aligned=True)
            vtable = self.u64(definition, "primary.sentinel_vtable")
            self.user_pointer(vtable, "primary_sentinel_vtable", aligned=True)
            if not self.module_base <= vtable < self.module_base + IMAGE_SIZE:
                raise _ReadFailure("primary_sentinel_vtable_outside_module_image")
        else:
            detail = self.definition_key(definition)
            vtable = detail["vtable_pointer"]
        slot_address = vtable + DEFINITION_KIND_SLOT_OFFSET
        if slot_address + POINTER_SIZE > self.module_base + IMAGE_SIZE:
            raise _ReadFailure("modifier_definition_kind_slot_outside_module_image")
        try:
            _identity._checked_user_range(slot_address, POINTER_SIZE, "modifier_definition_kind_slot")
        except Exception as exc:
            raise _ReadFailure("modifier_definition_kind_slot_outside_user_range") from exc
        target = self.u64(slot_address, "modifier.definition_kind_vtable_slot")
        target_true = self.module_base + SUPPORTED_TRUE_METHOD_RVA
        target_false = self.module_base + SUPPORTED_FALSE_METHOD_RVA
        if target == target_true:
            expected = SUPPORTED_TRUE_METHOD_BYTES
            value = True
            method_rva = SUPPORTED_TRUE_METHOD_RVA
        elif target == target_false:
            expected = SUPPORTED_FALSE_METHOD_BYTES
            value = False
            method_rva = SUPPORTED_FALSE_METHOD_RVA
        else:
            raise _ReadFailure("modifier_definition_kind_method_unsupported")
        method_address = self.image_address(method_rva, len(expected),
                                            "modifier_definition_kind_method")
        code = self.reader.read(method_address, len(expected),
                                "modifier.definition_kind_method_code")
        if code != expected:
            raise _ReadFailure("modifier_definition_kind_method_guard_mismatch")
        return {
            "definition_pointer": definition,
            "vtable_pointer": vtable,
            "slot_offset": hex(DEFINITION_KIND_SLOT_OFFSET),
            "slot_address": hex(slot_address),
            "method_pointer": target,
            "method_rva": hex(method_rva),
            "method_bytes_hex": code.hex(),
            "value": value,
        }

    def primary_membership(self, definition: int) -> dict[str, Any]:
        range_address = self.record + PROVINCE_PRIMARY_BEGIN_OFFSET
        header = self.reader.read(range_address, 0x10,
                                  "province.primary_instance_vector_bounds")
        begin = int.from_bytes(header[:8], "little")
        end = int.from_bytes(header[8:16], "little")
        if begin == 0 and end == 0:
            return {
                "container": "primary_instance_vector",
                "begin": 0,
                "end": 0,
                "count": 0,
                "entries": [],
                "matched": False,
            }
        self.user_pointer(begin, "province_primary_vector_begin", aligned=True)
        self.user_pointer(end, "province_primary_vector_end", aligned=True)
        if end < begin or (end - begin) % POINTER_SIZE:
            raise _ReadFailure("province_primary_vector_bounds_invalid")
        count = (end - begin) // POINTER_SIZE
        if count > MAX_ACTIVE_ITEMS:
            raise _ReadFailure("province_primary_vector_count_out_of_bounds")
        if count == 0:
            return {
                "container": "primary_instance_vector",
                "begin": begin,
                "end": end,
                "count": 0,
                "entries": [],
                "matched": False,
            }
        try:
            _identity._checked_user_range(begin, count * POINTER_SIZE,
                                          "province_primary_instance_vector")
        except Exception as exc:
            raise _ReadFailure("province_primary_vector_range_invalid") from exc
        vector = self.reader.read(begin, count * POINTER_SIZE,
                                  "province.primary_instance_vector")
        entries: list[dict[str, Any]] = []
        matched = False
        for index in range(count):
            instance = int.from_bytes(vector[index * 8:(index + 1) * 8], "little")
            self.user_pointer(instance, "province_primary_instance", aligned=True)
            definition_address = instance + INSTANCE_DEFINITION_OFFSET
            item_definition = self.u64(definition_address,
                                       f"province.primary_instance[{index}].definition")
            self.user_pointer(item_definition, "province_primary_instance_definition", aligned=True)
            is_match = item_definition == definition
            matched = matched or is_match
            entries.append({
                "index": index,
                "instance_pointer": instance,
                "definition_pointer": item_definition,
                "matches": is_match,
            })
        return {
            "container": "primary_instance_vector",
            "begin": begin,
            "end": end,
            "count": count,
            "vector_raw_hex": vector.hex(),
            "entries": entries,
            "matched": matched,
        }

    def secondary_membership(self, definition: int) -> dict[str, Any]:
        header_address = self.record + PROVINCE_SECONDARY_ARRAY_OFFSET
        header = self.reader.read(header_address, 0x10,
                                  "province.secondary_definition_array_header")
        array_pointer = int.from_bytes(header[:8], "little")
        count = int.from_bytes(header[12:16], "little", signed=True)
        if count < 0:
            raise _ReadFailure("province_secondary_array_negative_count")
        if count > MAX_ACTIVE_ITEMS:
            raise _ReadFailure("province_secondary_array_count_out_of_bounds")
        if count == 0:
            return {
                "container": "secondary_definition_pointer_array",
                "array_pointer": array_pointer,
                "count": 0,
                "entries": [],
                "matched": False,
                "header_raw_hex": header.hex(),
            }
        self.user_pointer(array_pointer, "province_secondary_array", aligned=True)
        try:
            _identity._checked_user_range(array_pointer, count * POINTER_SIZE,
                                          "province_secondary_definition_array")
        except Exception as exc:
            raise _ReadFailure("province_secondary_array_range_invalid") from exc
        raw = self.reader.read(array_pointer, count * POINTER_SIZE,
                               "province.secondary_definition_pointer_array")
        entries: list[dict[str, Any]] = []
        matched = False
        for index in range(count):
            pointer = int.from_bytes(raw[index * 8:(index + 1) * 8], "little")
            self.user_pointer(pointer, "province_secondary_definition", aligned=True)
            is_match = pointer == definition
            matched = matched or is_match
            entries.append({"index": index, "definition_pointer": pointer, "matches": is_match})
        return {
            "container": "secondary_definition_pointer_array",
            "array_pointer": array_pointer,
            "count": count,
            "array_raw_hex": raw.hex(),
            "entries": entries,
            "matched": matched,
            "header_raw_hex": header.hex(),
        }


def _raw_binding(module_base: Any, province_binding: Any) -> dict[str, Any]:
    return {
        "module_base": _identity._raw_scalar(module_base),
        "province_binding": {
            key: _identity._raw_scalar(province_binding.get(key))
            for key in ("province_id", "record_id", "record_pointer", "id_address", "id_raw_hex")
        } if isinstance(province_binding, Mapping) else _identity._raw_scalar(province_binding),
    }


def _unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
    }


def _known(value: bool, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "known",
        "complete": False,
        "value": value,
        "raw_inputs": raw_inputs,
    }


def _validate_keys(keys: Any) -> tuple[str, ...]:
    if not isinstance(keys, (tuple, list)):
        raise _ReadFailure("keys_must_be_list_or_tuple")
    if not keys:
        raise _ReadFailure("keys_empty")
    if len(keys) > MAX_KEYS:
        raise _ReadFailure("key_count_out_of_bounds")
    if any(type(key) is not str or not _KEY_RE.fullmatch(key) for key in keys):
        raise _ReadFailure("modifier_key_invalid")
    if len(set(keys)) != len(keys):
        raise _ReadFailure("duplicate_modifier_key")
    return tuple(keys)


def _resolve_one(state: _ReadState, key: str) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "key": key,
        "hash_algorithm": "h=0; h=((h+ASCII_byte)*61)&0xffffffff",
        "read_failures": [],
    }
    try:
        state.dependencies.setdefault(key, set()).add("primary")
        primary = state.lookup("primary", key)
        raw["primary_lookup"] = primary
        primary_definition = primary["definition_pointer"]
        if primary_definition is None:
            primary_definition = state.sentinel()
            state.dependencies[key].add("sentinel")
            raw["primary_resolution"] = "unmatched_sentinel"
            raw["primary_sentinel_pointer"] = hex(primary_definition)
        else:
            detail = state.definition_key(primary_definition)
            if detail["key"] != key:
                raise _ReadFailure("primary_definition_key_mismatch")
            raw["primary_resolution"] = "matched_definition"
            raw["primary_definition"] = {
                "pointer": hex(primary_definition),
                "key": detail["key"],
                "key_storage": detail["key_storage"],
                "key_raw_hex": detail["key_raw_hex"],
                "vtable_raw_hex": detail["vtable_raw_hex"],
                "key_string32_raw_hex": detail["key_string32_raw_hex"],
            }
        kind = state.kind_method(
            primary_definition,
            sentinel=raw["primary_resolution"] == "unmatched_sentinel",
        )
        raw["primary_kind"] = kind
        if kind["value"]:
            membership = state.primary_membership(primary_definition)
            raw["selected_container"] = membership
            return _known(membership["matched"], raw)

        state.dependencies[key].add("secondary")
        secondary = state.lookup("secondary", key)
        raw["secondary_lookup"] = secondary
        secondary_definition = secondary["definition_pointer"]
        if secondary_definition is None:
            return _unknown("secondary_definition_missing", raw)
        detail = state.definition_key(secondary_definition)
        if detail["key"] != key:
            raise _ReadFailure("secondary_definition_key_mismatch")
        raw["secondary_definition"] = {
            "pointer": hex(secondary_definition),
            "key": detail["key"],
            "key_storage": detail["key_storage"],
            "key_raw_hex": detail["key_raw_hex"],
            "vtable_raw_hex": detail["vtable_raw_hex"],
            "key_string32_raw_hex": detail["key_string32_raw_hex"],
        }
        membership = state.secondary_membership(secondary_definition)
        raw["selected_container"] = membership
        return _known(membership["matched"], raw)
    except _ReadFailure as exc:
        raw["read_failures"].append({"reason": exc.reason})
        return _unknown(exc.reason, raw)
    except Exception as exc:
        raw["read_failures"].append({"reason": f"unexpected:{type(exc).__name__}"})
        return _unknown(f"unexpected:{type(exc).__name__}", raw)


def _context_recheck(state: _ReadState) -> dict[str, str]:
    changed: dict[str, str] = {}
    for name, snapshot in state.manager_snapshots.items():
        try:
            current_global = state.reader.read(
                snapshot["global_address"], 8, f"{name}.manager_global_recheck", fresh=True)
            if current_global != snapshot["global_raw"]:
                changed[name] = "manager_global_changed_during_leaf_read"
                continue
            current_header = state.reader.read(
                snapshot["manager_pointer"], MANAGER_HEADER_WIDTH,
                f"{name}.manager_header_recheck", fresh=True)
            if current_header != snapshot["header_raw"]:
                changed[name] = "manager_header_changed_during_leaf_read"
        except _ReadFailure as exc:
            changed[name] = f"manager_recheck_failed:{exc.reason}"
    if state.sentinel_snapshot is not None:
        snapshot = state.sentinel_snapshot
        try:
            current = state.reader.read(
                snapshot["global_address"], 8, "primary.sentinel_global_recheck", fresh=True)
            if current != snapshot["global_raw"]:
                changed["sentinel"] = "primary_sentinel_changed_during_leaf_read"
        except _ReadFailure as exc:
            changed["sentinel"] = f"primary_sentinel_recheck_failed:{exc.reason}"
    return changed


def read_predicates(
    reader: Any,
    module_base: Any,
    province_binding: Any,
    keys: tuple[str, ...] | list[str],
) -> dict[str, Any]:
    """Copy bounded current province modifier membership for explicit keys.

    The caller must already hold a canonical province binding.  Each requested
    key resolves independently; malformed inputs cause no memory reads, and a
    failed key stays unknown rather than becoming false.  The result is always
    ``complete=False`` until a separate live profile/capture owner exists.
    """
    try:
        normalized_keys = _validate_keys(keys)
    except _ReadFailure as exc:
        return {
            "schema": SCHEMA,
            "status": "unknown",
            "complete": False,
            "reason": exc.reason,
            "predicates": {},
            "basis": BASIS,
            "gaps": list(_GAPS),
            "raw_inputs": {"binding": _raw_binding(module_base, province_binding),
                           "reads": [], "read_budget": {"bytes_used": 0, "limit_bytes": MAX_READ_BYTES}},
        }

    try:
        base, record, binding = _identity._validate_binding(module_base, province_binding)
        if not 1 <= binding["province_id"] <= MAX_PROVINCE_ID:
            raise ValueError("province_id_out_of_supported_range")
        _identity._checked_user_range(base, IMAGE_SIZE, "pinned_module_image")
    except Exception as exc:
        reason = str(exc) or type(exc).__name__
        predicates = {key: _unknown(reason, _raw_binding(module_base, province_binding))
                      for key in normalized_keys}
        return {
            "schema": SCHEMA,
            "status": "unknown",
            "complete": False,
            "predicates": predicates,
            "basis": BASIS,
            "gaps": list(_GAPS),
            "raw_inputs": {"binding": _raw_binding(module_base, province_binding),
                           "reads": [], "read_budget": {"bytes_used": 0, "limit_bytes": MAX_READ_BYTES}},
        }

    state = _ReadState(reader, base, record)
    predicates = {key: _resolve_one(state, key) for key in normalized_keys}
    changed = _context_recheck(state)
    if changed:
        for key, result in predicates.items():
            dependencies = state.dependencies.get(key, set())
            relevant = {name: reason for name, reason in changed.items() if name in dependencies}
            if relevant:
                reason = ";".join(f"{name}:{value}" for name, value in sorted(relevant.items()))
                predicates[key] = _unknown("leaf_context_changed:" + reason,
                                            {**result.get("raw_inputs", {}),
                                             "stability_recheck": relevant})

    known = sum(value["status"] == "known" for value in predicates.values())
    status = "known" if known == len(predicates) else ("partial" if known else "unknown")
    raw_inputs = {
        "module_base": hex(base),
        "module_image_size": IMAGE_SIZE,
        "province_binding": binding,
        "manager_snapshots": {
            name: {
                "global_rva": value["global_rva"],
                "manager_pointer": hex(value["manager_pointer"]),
                "bucket_count": value["bucket_count"],
                "buckets_pointer": hex(value["buckets_pointer"]),
                "header_raw_hex": value["header_raw_hex"],
            }
            for name, value in state.managers.items()
        },
        "stability_recheck": changed,
        "reads": state.reader.reads,
        "read_failures": state.reader.failures,
        "read_budget": {
            "bytes_used": state.reader.bytes_read,
            "calls_used": state.reader.calls,
            "cache_hits": state.reader.cache_hits,
            "limit_bytes": MAX_READ_BYTES,
            "limit_calls": MAX_READ_CALLS,
        },
    }
    return {
        "schema": SCHEMA,
        "status": status,
        "complete": False,
        "predicates": predicates,
        "basis": BASIS,
        "gaps": list(_GAPS),
        "raw_inputs": raw_inputs,
    }


__all__ = [
    "BASIS",
    "IMAGE_SIZE",
    "MAX_ACTIVE_ITEMS",
    "MAX_KEYS",
    "MAX_KEY_BYTES",
    "MAX_PROVINCE_ID",
    "MAX_READ_BYTES",
    "MAX_CHAIN_NODES",
    "SCHEMA",
    "read_predicates",
]
