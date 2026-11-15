"""Bounded, read-only reader for the fixed 1.37.4 battle message definitions.

This module reads only the two registered definition records named in its
hashed profile. It does not invoke the native lookup routine (which has
logging/allocation side effects), attach definitions to events, or infer UI
visibility from the current settings fields.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import localization_memory as _lm
from . import mission_memory as _mm


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "battle-definition-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "f6457372e7ca0ce47a9590d3bdedff8280a26cbb1b582d681840253d2fb8e587"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
PROCESS_ACCESS = _mm.PROCESS_ACCESS


class ProfileError(RuntimeError):
    """The bounded message-definition profile is absent or inconsistent."""


class ProbeError(RuntimeError):
    """A bounded read or contract check failed without a safe fallback."""


def _load_profile(path: Path = PROFILE_FILE) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{size}")
        raw = path.read_bytes()
    except OSError as exc:
        raise ProfileError(f"profile_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > PROFILE_MAX_BYTES:
        raise ProfileError("profile_read_size_changed")
    if hashlib.sha256(raw).hexdigest() != EXPECTED_PROFILE_SHA256:
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict) or profile.get("profile_id") != "battle-definition-memory-1374":
        raise ProfileError("profile_shape_invalid")
    return profile


PROFILE = _load_profile()


def _profile_int(value: Any, label: str) -> int:
    parsed = _mm._parse_int(value)
    if parsed is None or parsed < 0:
        raise ProfileError(f"profile_integer_invalid:{label}")
    return parsed


EXPECTED_KEYS: dict[str, int] = {
    str(item["key"]): _profile_int(item["kind"], f"keys.{item.get('key')}.kind")
    for item in PROFILE["keys"]
}
SUPPORTED_KEYS = ("LANDBATTLEOVER", "NAVALBATTLEOVER")
MANAGER_CELL_RVA = _profile_int(PROFILE["globals"]["manager_cell_rva"], "globals.manager_cell_rva")
MANAGER_BUCKET_COUNT_OFFSET = _profile_int(PROFILE["manager"]["bucket_count_offset"], "manager.bucket_count_offset")
MANAGER_BUCKET_ARRAY_OFFSET = _profile_int(PROFILE["manager"]["bucket_array_offset"], "manager.bucket_array_offset")
NODE_DEFINITION_OFFSET = _profile_int(PROFILE["node"]["definition_offset"], "node.definition_offset")
NODE_NEXT_OFFSET = _profile_int(PROFILE["node"]["next_offset"], "node.next_offset")
DEFINITION_KEY_OFFSET = _profile_int(PROFILE["definition"]["key_offset"], "definition.key_offset")
DEFINITION_KEY_LENGTH_OFFSET = _profile_int(PROFILE["definition"]["key_length_offset"], "definition.key_length_offset")
DEFINITION_KEY_CAPACITY_OFFSET = _profile_int(PROFILE["definition"]["key_capacity_offset"], "definition.key_capacity_offset")
DEFINITION_VTABLE_OFFSET = 0
DEFINITION_KIND_OFFSET = _profile_int(PROFILE["definition"]["kind_offset"], "definition.kind_offset")
DEFINITION_LAYOUT_OFFSET = _profile_int(PROFILE["definition"]["layout_raw_offset"], "definition.layout_raw_offset")
DEFINITION_BUTTON_OFFSET = _profile_int(PROFILE["definition"]["button_flag_raw_offset"], "definition.button_flag_raw_offset")
HASH_SEED = _profile_int(PROFILE["hash"]["seed"], "hash.seed")
HASH_MULTIPLIER = _profile_int(PROFILE["hash"]["multiplier"], "hash.multiplier")
HASH_BITS = _profile_int(PROFILE["hash"]["arithmetic_bits"], "hash.arithmetic_bits")
MAX_TOTAL_RPM = _profile_int(PROFILE["limits"]["max_total_rpm"], "limits.max_total_rpm")
MAX_SINGLE_RPM = _profile_int(PROFILE["limits"]["max_single_rpm"], "limits.max_single_rpm")
MAX_RPM_CALLS = _profile_int(PROFILE["limits"]["max_rpm_calls"], "limits.max_rpm_calls")
MAX_NODES_PER_BUCKET = _profile_int(PROFILE["limits"]["max_nodes_per_bucket"], "limits.max_nodes_per_bucket")
MAX_BUCKET_COUNT = _profile_int(PROFILE["limits"]["max_bucket_count"], "limits.max_bucket_count")
MAX_KEY_BYTES = _profile_int(PROFILE["limits"]["max_key_bytes"], "limits.max_key_bytes")
MAX_STRING_CAPACITY = _profile_int(PROFILE["limits"]["max_string_capacity"], "limits.max_string_capacity")


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    source = PROFILE if profile is None else profile
    guards = source.get("code_guards")
    if not isinstance(guards, list) or not guards:
        raise ProfileError("profile_code_guards_missing")
    result: list[dict[str, Any]] = []
    labels: set[str] = set()
    for item in guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        label = item.get("label")
        raw_hex = item.get("expected_hex")
        if not isinstance(label, str) or not label or label in labels:
            raise ProfileError("profile_code_guard_label_invalid")
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{label}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{label}") from exc
        rva = _profile_int(item.get("rva"), f"code_guards.{label}.rva")
        byte_count = _profile_int(item.get("bytes"), f"code_guards.{label}.bytes")
        if len(raw) != byte_count:
            raise ProfileError(f"profile_code_guard_length_mismatch:{label}")
        expected_hash = item.get("sha256")
        if not isinstance(expected_hash, str) or hashlib.sha256(raw).hexdigest() != expected_hash.lower():
            raise ProfileError(f"profile_code_guard_sha256_mismatch:{label}")
        if not isinstance(item.get("runtime"), bool):
            raise ProfileError(f"profile_code_guard_runtime_invalid:{label}")
        labels.add(label)
        result.append({"label": label, "rva": rva, "raw": raw, "runtime": item["runtime"]})
    return result


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "profile_path": str(PROFILE_FILE),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        profile_size = PROFILE_FILE.stat().st_size
        if profile_size <= 0 or profile_size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{profile_size}")
        profile_raw = PROFILE_FILE.read_bytes()
        if len(profile_raw) != profile_size or len(profile_raw) > PROFILE_MAX_BYTES:
            raise ProfileError("profile_read_size_changed")
        profile_hash = hashlib.sha256(profile_raw).hexdigest()
        result["checks"] = {
            "profile_sha256": profile_hash == EXPECTED_PROFILE_SHA256,
            "profile_id": PROFILE.get("profile_id") == "battle-definition-memory-1374",
            "game_version": PROFILE.get("game_version") == EXPECTED_VERSION,
            "executable_sha256": str(PROFILE.get("executable", {}).get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "supported_country": PROFILE.get("country", {}).get("supported_country") == EXPECTED_COUNTRY,
            "keys": EXPECTED_KEYS == {"LANDBATTLEOVER": 1, "NAVALBATTLEOVER": 2},
            "hash_contract": HASH_SEED == 0 and HASH_MULTIPLIER == 61 and HASH_BITS == 32,
            "manager_layout": MANAGER_BUCKET_COUNT_OFFSET == 4 and MANAGER_BUCKET_ARRAY_OFFSET == 8,
            "node_layout": NODE_DEFINITION_OFFSET == 0 and NODE_NEXT_OFFSET == 8,
            "definition_layout": (
                DEFINITION_KEY_OFFSET == 0x38
                and DEFINITION_KEY_LENGTH_OFFSET == 0x48
                and DEFINITION_KEY_CAPACITY_OFFSET == 0x50
                and DEFINITION_KIND_OFFSET == 0x58
                and DEFINITION_LAYOUT_OFFSET == 0x5C
                and DEFINITION_BUTTON_OFFSET == 0x60
            ),
            "limits": (
                0 < MAX_TOTAL_RPM <= 131072
                and 0 < MAX_SINGLE_RPM <= 8192
                and 0 < MAX_RPM_CALLS <= 2048
                and 0 < MAX_NODES_PER_BUCKET <= 64
                and 0 < MAX_BUCKET_COUNT <= 65536
                and 0 < MAX_KEY_BYTES <= 64
                and 16 <= MAX_STRING_CAPACITY <= 8192
            ),
        }
        _profile_code_guards()
        result["checks"]["code_guard_profile"] = True
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("static_contract_mismatch:" + ",".join(failed))
            result["status"] = "mismatch"
        else:
            result["status"] = "observed"
    except (OSError, ProfileError, TypeError, ValueError, KeyError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _file_code_guard(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for item in _profile_code_guards():
            actual = _lm._read_pe_rva_bytes(path, item["rva"], len(item["raw"]))
            result["records"][item["label"]] = {
                "rva": _hex(item["rva"]),
                "runtime": item["runtime"],
                "expected_hex": item["raw"].hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][item["label"]] = actual == item["raw"]
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProfileError, ProbeError, ValueError, KeyError, TypeError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _runtime_code_guard(reader: Any, module_base: int) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "checks": {}, "records": {}, "unknown_conditions": []}
    try:
        for item in _profile_code_guards():
            if not item["runtime"]:
                continue
            address = module_base + item["rva"]
            actual = reader.read_code(address, len(item["raw"]), f"code_guard.{item['label']}")
            result["records"][item["label"]] = {
                "rva": _hex(item["rva"]),
                "address": _mm._address(address, module_base, known_rva=item["rva"]),
                "expected_hex": item["raw"].hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][item["label"]] = actual == item["raw"]
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProfileError, ProbeError, ValueError, KeyError, TypeError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


class BoundedRPM(_mm.BoundedRPM):
    """Shared RPM reader with the profile's stricter call/byte/single limits."""

    def _read(self, address: int, size: int, label: str, *, aligned: bool) -> bytes:
        if size > MAX_SINGLE_RPM:
            raise ProbeError(f"single_read_limit_exceeded:{label}")
        if self.calls + 1 > MAX_RPM_CALLS:
            raise ProbeError("rpm_call_limit_exceeded")
        if self.bytes_requested + size > MAX_TOTAL_RPM:
            raise ProbeError("rpm_total_limit_exceeded")
        return super()._read(address, size, label, aligned=aligned)


def _checked_address(base: int, offset: int, size: int, label: str) -> int:
    if not _mm._valid_pointer(base) or not isinstance(offset, int) or offset < 0 or not isinstance(size, int) or size <= 0:
        raise ProbeError(f"invalid_address_components:{label}")
    address = base + offset
    end = address + size
    if address < 0x10000 or end < address or end > MAX_USER_ADDRESS:
        raise ProbeError(f"address_range_out_of_bound:{label}")
    return address


def _hash_ascii(key: str) -> int:
    try:
        raw = key.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ProbeError("non_ascii_profile_key") from exc
    value = HASH_SEED
    mask = (1 << HASH_BITS) - 1
    for byte in raw:
        value = ((value + byte) * HASH_MULTIPLIER) & mask
    return value


def _world_identity(reader: Any, module_base: int, country: str) -> dict[str, Any]:
    game_address = module_base + _lm.GAME_RVA
    database_address = module_base + _lm.DATABASE_RVA
    game, game_raw = reader.qword(game_address, "world.game_pointer")
    database, database_raw = reader.qword(database_address, "world.database_pointer")
    if not _mm._valid_pointer(game) or not _mm._valid_pointer(database):
        raise ProbeError("world_game_or_database_pointer_invalid")
    date_address = _checked_address(game, _lm.GAME_DATE_OFFSET, 4, "world.date")
    date_raw = reader.read(date_address, 4, "world.raw_date")
    country_scan = _lm._country_identity(reader, database, country)
    if country_scan.get("status") != "observed":
        raise ProbeError(str(country_scan.get("unknown_reason", "country_identity_unknown")))
    country_pointer_info = country_scan.get("country_pointer")
    country_handle_info = country_scan.get("country_handle")
    country_pointer = _mm._parse_int(str((country_pointer_info or {}).get("va")))
    country_handle = _mm._parse_int(str((country_handle_info or {}).get("value")))
    if country_pointer is None or not _mm._valid_pointer(country_pointer) or country_handle is None:
        raise ProbeError("country_identity_invalid_after_scan")
    return {
        "game_pointer": {"address": _mm._address(game_address, module_base, known_rva=_lm.GAME_RVA), "raw_hex": game_raw.hex(), "value": _hex(game)},
        "database_pointer": {"address": _mm._address(database_address, module_base, known_rva=_lm.DATABASE_RVA), "raw_hex": database_raw.hex(), "value": _hex(database)},
        "date": {"address": _mm._address(date_address, module_base), "field_offset": _hex(_lm.GAME_DATE_OFFSET), "raw_hex": date_raw.hex(), "value": int.from_bytes(date_raw, "little", signed=True)},
        "country_scan": country_scan,
        "country_pointer": country_pointer_info,
        "country_handle": country_handle_info,
    }


def _read_definition_key(reader: Any, definition: int, label: str) -> dict[str, Any]:
    header_size = DEFINITION_KEY_CAPACITY_OFFSET + 8 - DEFINITION_KEY_OFFSET
    header_address = _checked_address(definition, DEFINITION_KEY_OFFSET, header_size, f"{label}.key_header")
    header = reader.read(header_address, header_size, f"{label}.key_header")
    size_in_header = DEFINITION_KEY_LENGTH_OFFSET - DEFINITION_KEY_OFFSET
    capacity_in_header = DEFINITION_KEY_CAPACITY_OFFSET - DEFINITION_KEY_OFFSET
    length = int.from_bytes(header[size_in_header:size_in_header + 8], "little", signed=False)
    capacity = int.from_bytes(header[capacity_in_header:capacity_in_header + 8], "little", signed=False)
    if length > MAX_KEY_BYTES:
        raise ProbeError(f"definition_key_length_out_of_bound:{label}")
    if capacity < 16:
        if length > 15 or length > capacity:
            raise ProbeError(f"definition_sso_length_invalid:{label}")
        key_bytes = header[:length]
        terminator = header[length:length + 1]
        storage = "sso"
        storage_pointer = None
    else:
        if capacity > MAX_STRING_CAPACITY or length > capacity:
            raise ProbeError(f"definition_string_capacity_or_length_invalid:{label}")
        storage_pointer = int.from_bytes(header[:8], "little", signed=False)
        if not _mm._valid_pointer(storage_pointer):
            raise ProbeError(f"definition_heap_string_pointer_invalid:{label}")
        payload_address = _checked_address(storage_pointer, 0, length + 1, f"{label}.key_bytes")
        payload = reader.read(payload_address, length + 1, f"{label}.key_bytes")
        key_bytes, terminator = payload[:-1], payload[-1:]
        storage = "heap"
    if len(terminator) != 1 or terminator != b"\x00" or b"\x00" in key_bytes:
        raise ProbeError(f"definition_string_terminator_invalid:{label}")
    return {
        "header_address": _mm._address(header_address, reader.module_base),
        "header_raw_hex": header.hex(),
        "length": length,
        "capacity": capacity,
        "storage": storage,
        "storage_pointer": _mm._address(storage_pointer, reader.module_base) if storage_pointer is not None else None,
        "key_bytes_hex": key_bytes.hex(),
        "key_text_ascii": key_bytes.decode("ascii") if all(byte < 0x80 for byte in key_bytes) else None,
    }


def _read_candidate_fields(reader: Any, definition: int, label: str, formatter_kind: int) -> dict[str, Any]:
    vtable_address = _checked_address(definition, DEFINITION_VTABLE_OFFSET, 8, f"{label}.candidate_vtable")
    vtable, vtable_raw = reader.qword(vtable_address, f"{label}.candidate_vtable")
    start = DEFINITION_KIND_OFFSET
    end = DEFINITION_BUTTON_OFFSET + 1
    scalar_address = _checked_address(definition, start, end - start, f"{label}.scalars")
    raw = reader.read(scalar_address, end - start, f"{label}.scalars")
    kind_raw = raw[:4]
    layout_start = DEFINITION_LAYOUT_OFFSET - start
    button_start = DEFINITION_BUTTON_OFFSET - start
    layout_raw = raw[layout_start:layout_start + 4]
    button_raw = raw[button_start:button_start + 1]
    return {
        "candidate_vtable_qword": {
            "address": _mm._address(vtable_address, reader.module_base),
            "raw_hex": vtable_raw.hex(),
            "value": _hex(vtable),
        },
        "address": _mm._address(scalar_address, reader.module_base),
        "raw_hex": raw.hex(),
        "popup_kind_raw": int.from_bytes(kind_raw, "little", signed=True),
        "popup_kind_raw_hex": kind_raw.hex(),
        "formatter_kind": formatter_kind,
        "matches_formatter_kind": int.from_bytes(kind_raw, "little", signed=True) == formatter_kind,
        "layout_raw": int.from_bytes(layout_raw, "little", signed=True),
        "layout_raw_hex": layout_raw.hex(),
        "button_flag_raw": button_raw[0],
        "button_flag_raw_hex": button_raw.hex(),
    }


def _snapshot(reader: Any, module_base: int, country: str = EXPECTED_COUNTRY) -> dict[str, Any]:
    """Read the two fixed definition buckets and their exact-key candidates."""
    result: dict[str, Any] = {"status": "unknown", "unknown_reason": None, "world": None, "manager": None, "buckets": [], "definitions": {}}
    try:
        if country != EXPECTED_COUNTRY:
            raise ProbeError("unsupported_country")
        result["world"] = _world_identity(reader, module_base, country)

        manager_cell_address = module_base + MANAGER_CELL_RVA
        if not _mm._valid_pointer(manager_cell_address):
            raise ProbeError("manager_cell_address_invalid")
        manager, manager_raw = reader.qword(manager_cell_address, "manager.global_cell")
        if not _mm._valid_pointer(manager):
            raise ProbeError("manager_pointer_null_or_invalid")
        manager_header_address = _checked_address(manager, 0, MANAGER_BUCKET_ARRAY_OFFSET + 8, "manager.header")
        manager_header = reader.read(manager_header_address, MANAGER_BUCKET_ARRAY_OFFSET + 8, "manager.header")
        count_at = MANAGER_BUCKET_COUNT_OFFSET
        count = int.from_bytes(manager_header[count_at:count_at + 4], "little", signed=False)
        table_at = MANAGER_BUCKET_ARRAY_OFFSET
        bucket_array = int.from_bytes(manager_header[table_at:table_at + 8], "little", signed=False)
        if count == 0 or count > MAX_BUCKET_COUNT:
            raise ProbeError("bucket_count_zero_or_out_of_bound")
        if not _mm._valid_pointer(bucket_array):
            raise ProbeError("bucket_array_pointer_invalid")
        table_bytes = count * 8
        if table_bytes <= 0 or bucket_array + table_bytes > MAX_USER_ADDRESS:
            raise ProbeError("bucket_array_range_out_of_bound")
        result["manager"] = {
            "cell_address": _mm._address(manager_cell_address, module_base, known_rva=MANAGER_CELL_RVA),
            "cell_raw_hex": manager_raw.hex(),
            "pointer": _mm._address(manager, module_base),
            "header_address": _mm._address(manager_header_address, module_base),
            "header_raw_hex": manager_header.hex(),
            "bucket_count": count,
            "bucket_array": _mm._address(bucket_array, module_base),
            "bucket_array_bytes_bound": table_bytes,
        }

        key_bytes = {key: key.encode("ascii") for key in EXPECTED_KEYS}
        key_hashes = {key: _hash_ascii(key) for key in EXPECTED_KEYS}
        bucket_for_key = {key: key_hashes[key] % count for key in EXPECTED_KEYS}
        chains: dict[int, list[dict[str, Any]]] = {}
        for bucket_index in sorted(set(bucket_for_key.values())):
            bucket_address = _checked_address(bucket_array, bucket_index * 8, 8, f"bucket[{bucket_index}]")
            head, head_raw = reader.qword(bucket_address, f"bucket[{bucket_index}].head")
            if head and not _mm._valid_pointer(head):
                raise ProbeError(f"bucket_head_pointer_invalid:{bucket_index}")
            bucket_record: dict[str, Any] = {
                "index": bucket_index,
                "address": _mm._address(bucket_address, module_base),
                "head_raw_hex": head_raw.hex(),
                "head": _mm._address(head, module_base) if head else None,
                "nodes": [],
            }
            nodes: list[dict[str, Any]] = []
            visited: set[int] = set()
            current = head
            while current:
                if current in visited:
                    raise ProbeError(f"bucket_chain_cycle:{bucket_index}")
                if len(nodes) >= MAX_NODES_PER_BUCKET:
                    raise ProbeError(f"bucket_chain_node_limit_exceeded:{bucket_index}")
                if not _mm._valid_pointer(current):
                    raise ProbeError(f"bucket_node_pointer_invalid:{bucket_index}")
                visited.add(current)
                node_address = _checked_address(current, 0, NODE_NEXT_OFFSET + 8, f"bucket[{bucket_index}].node")
                node_raw = reader.read(node_address, NODE_NEXT_OFFSET + 8, f"bucket[{bucket_index}].node_header")
                definition = int.from_bytes(node_raw[NODE_DEFINITION_OFFSET:NODE_DEFINITION_OFFSET + 8], "little")
                next_node = int.from_bytes(node_raw[NODE_NEXT_OFFSET:NODE_NEXT_OFFSET + 8], "little")
                if not _mm._valid_pointer(definition):
                    raise ProbeError(f"bucket_node_definition_null_or_invalid:{bucket_index}")
                if next_node and not _mm._valid_pointer(next_node):
                    raise ProbeError(f"bucket_next_pointer_invalid:{bucket_index}")
                node_record: dict[str, Any] = {
                    "address": _mm._address(current, module_base),
                    "header_raw_hex": node_raw.hex(),
                    "definition": _mm._address(definition, module_base),
                    "next": _mm._address(next_node, module_base) if next_node else None,
                }
                key_record = _read_definition_key(reader, definition, f"bucket[{bucket_index}].definition")
                node_record["key"] = key_record
                target_key = next((key for key, raw_key in key_bytes.items() if key_record["key_bytes_hex"] == raw_key.hex()), None)
                if target_key is not None:
                    scalars = _read_candidate_fields(reader, definition, target_key, EXPECTED_KEYS[target_key])
                    node_record["candidate_key"] = target_key
                    node_record["candidate_fields"] = scalars
                nodes.append(node_record)
                current = next_node
            bucket_record["nodes"] = nodes
            result["buckets"].append(bucket_record)
            chains[bucket_index] = nodes

        definitions: dict[str, Any] = {}
        for key, expected_kind in EXPECTED_KEYS.items():
            matches: list[dict[str, Any]] = []
            bucket_index = bucket_for_key[key]
            for node in chains[bucket_index]:
                if node["key"]["key_bytes_hex"] == key_bytes[key].hex():
                    matches.append(node)
            if len(matches) == 0:
                raise ProbeError(f"definition_key_not_found:{key}")
            if len(matches) != 1:
                raise ProbeError(f"duplicate_definition_key:{key}")
            match = matches[0]
            fields = match.get("candidate_fields")
            if not isinstance(fields, Mapping):
                raise ProbeError(f"definition_fields_missing:{key}")
            definitions[key] = {
                "status": "observed",
                "key": key,
                "key_bytes_hex": key_bytes[key].hex(),
                "key_header_raw_hex": match["key"]["header_raw_hex"],
                "key_length": match["key"]["length"],
                "key_capacity": match["key"]["capacity"],
                "key_storage": match["key"]["storage"],
                "definition": match["definition"],
                "candidate_vtable_qword": fields["candidate_vtable_qword"],
                "popup_kind_raw": fields["popup_kind_raw"],
                "popup_kind_raw_hex": fields["popup_kind_raw_hex"],
                "formatter_kind": expected_kind,
                "matches_formatter_kind": fields["matches_formatter_kind"],
                "popup_kind_semantics": "registered_raw_value; definition setter may update it during message formation",
                "layout_raw": fields["layout_raw"],
                "layout_raw_hex": fields["layout_raw_hex"],
                "button_flag_raw": fields["button_flag_raw"],
                "button_flag_raw_hex": fields["button_flag_raw_hex"],
                "current_settings_only": True,
                "historical_display_or_visibility_claim": False,
            }
        result["definitions"] = definitions
        result["status"] = "observed"
    except (ProbeError, OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        result["status"] = "unknown"
        result["unknown_reason"] = str(exc)
        result["definitions"] = {
            key: {"status": "unknown", "key": key, "unknown_reason": str(exc)}
            for key in EXPECTED_KEYS
        }
    return result


def _unknown_entries(reason: str) -> dict[str, Any]:
    return {key: {"status": "unknown", "key": key, "unknown_reason": reason} for key in EXPECTED_KEYS}


def _snapshot_mismatches(left: Any, right: Any, path: str = "$") -> list[str]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        keys = sorted(set(left) | set(right))
        differences: list[str] = []
        for key in keys:
            if key not in left or key not in right:
                differences.append(f"{path}.{key}")
            else:
                differences.extend(_snapshot_mismatches(left[key], right[key], f"{path}.{key}"))
        return differences
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return [f"{path}.length"]
        differences = []
        for index, (a, b) in enumerate(zip(left, right)):
            differences.extend(_snapshot_mismatches(a, b, f"{path}[{index}]"))
        return differences
    return [] if left == right else [path]


def _base_report(installation: Path, country: str) -> dict[str, Any]:
    evidence = PROFILE.get("source_evidence")
    if not isinstance(evidence, Mapping):
        evidence = {}
    return {
        "schema": "information.battle_definition_memory_capture.v1",
        "probe": "information-battle-definition-memory",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "profile_id": PROFILE.get("profile_id")},
        "read_only": True,
        "evidence_kind": "bounded_two_pass_runtime_observation_not_static_evidence",
        "request": {"installation": str(installation), "country": country, "keys": list(EXPECTED_KEYS)},
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "manager_cell_rva": _hex(MANAGER_CELL_RVA)},
        "static_contract_reference": {"profile_sha256": EXPECTED_PROFILE_SHA256, "source_evidence": dict(evidence), "no_native_fallback": True},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard_before": None,
        "runtime_code_guard_after": None,
        "identity": {
            "installation_path": str(installation), "installation_pid": None,
            "installation_creation_filetime": None, "installation_session_id": None,
            "process_path": None, "process_path_sha256": None,
            "process_path_sha256_matches_expected": None, "process_creation_filetime": None,
            "process_creation_utc": None, "process_creation_matches_installation": None,
            "module_path": None, "module_path_matches_process": None,
            "binding_verified": False,
        },
        "module_base": None,
        "before": None,
        "after": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "definitions": _unknown_entries("not_read"),
        "access": {
            "open_process_mask": "QUERY_INFORMATION|VM_READ", "open_process_mask_hex": hex(PROCESS_ACCESS),
            "rpm_total_limit": MAX_TOTAL_RPM, "rpm_call_limit": MAX_RPM_CALLS,
            "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0,
            "native_game_calls": False, "native_fallback": False, "target_memory_writes": False,
            "dll_injection": False, "private_heap_scan": False, "ui_control": False,
            "date_advance": False, "save_or_reload": False,
        },
        "cleanup": {"handle_close": {"status": "not_opened", "success": None, "closed": False}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def capture(installation: Path, country: str = EXPECTED_COUNTRY) -> dict[str, Any]:
    """Capture the two fixed message-definition records from the bound process."""
    installation = Path(installation)
    report = _base_report(installation, country)
    handle = None
    kernel = None
    reader: BoundedRPM | None = None
    try:
        report["probe_script_sha256"] = _lm._sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "error": str(exc)})

    if country != EXPECTED_COUNTRY:
        report["status"] = "unsupported_country"
        report["definitions"] = _unknown_entries("unsupported_country")
        report["errors"].append({"stage": "request", "error": "Only FRA is permitted"})
        report["completed"] = True
        return report

    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["definitions"] = _unknown_entries("static_contract_mismatch")
        report["errors"].append({"stage": "static_contract", "error": "Battle definition profile did not match"})
        report["completed"] = True
        return report

    try:
        document = _lm._load_installation(installation)
        pid = _mm._parse_int(document.get("pid"))
        creation = _mm._parse_int(document.get("creation_filetime"))
        if pid is None or creation is None:
            raise ProbeError("installation_pid_or_creation_invalid")
        kernel = _lm._configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        module_base = _lm._capture_identity(report, document, kernel, handle)
        report["file_code_guard"] = _file_code_guard(Path(report["identity"]["process_path"]))
        if report["file_code_guard"].get("status") != "observed":
            raise ProbeError("file_code_guard_mismatch")
        reader = BoundedRPM(kernel, handle, module_base)
        report["runtime_code_guard_before"] = _runtime_code_guard(reader, module_base)
        if report["runtime_code_guard_before"].get("status") != "observed":
            raise ProbeError("runtime_code_guard_before_mismatch")

        before = _snapshot(reader, module_base, country)
        after = _snapshot(reader, module_base, country)
        report["before"] = before
        report["after"] = after
        report["doublepass"]["performed"] = True
        mismatches = _snapshot_mismatches(before, after)
        report["doublepass"]["mismatches"] = mismatches
        report["doublepass"]["consistent"] = not mismatches

        report["runtime_code_guard_after"] = _runtime_code_guard(reader, module_base)
        if report["runtime_code_guard_after"].get("status") != "observed":
            raise ProbeError("runtime_code_guard_after_mismatch")
        guard_differences = _snapshot_mismatches(
            report["runtime_code_guard_before"].get("checks", {}),
            report["runtime_code_guard_after"].get("checks", {}),
            "$.runtime_code_guard",
        )
        if guard_differences:
            report["doublepass"]["mismatches"].extend(guard_differences)
            report["doublepass"]["consistent"] = False

        if not before.get("status") == after.get("status") == "observed":
            reason = before.get("unknown_reason") or after.get("unknown_reason") or "snapshot_unknown"
            report["status"] = "unknown"
            report["definitions"] = _unknown_entries(str(reason))
            report["errors"].append({"stage": "snapshot", "error": str(reason)})
        elif report["doublepass"]["consistent"] is not True:
            report["status"] = "doublepass_mismatch"
            report["definitions"] = _unknown_entries("two_pass_snapshot_mismatch")
            report["errors"].append({"stage": "doublepass", "error": "world identity or definition evidence changed between passes"})
        else:
            report["status"] = "observed"
            report["definitions"] = after["definitions"]
    except Exception as exc:
        report["status"] = "error"
        report["definitions"] = _unknown_entries("capture_error")
        report["errors"].append({"stage": "capture", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        report["cleanup"]["handle_close"] = _lm._close_process_handle(kernel, handle)
        if not report["cleanup"]["handle_close"].get("closed") and handle:
            report["status"] = "cleanup_error"
            report["definitions"] = _unknown_entries("handle_close_failed")
        report["completed"] = True
    return report


__all__ = [
    "PROFILE_FILE", "PROFILE", "EXPECTED_PROFILE_SHA256", "EXPECTED_EXE_SHA256",
    "BoundedRPM", "ProbeError", "ProfileError", "_snapshot", "_static_contract_guard",
    "_file_code_guard", "_runtime_code_guard", "capture",
]
