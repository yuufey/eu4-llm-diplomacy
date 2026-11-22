"""Bounded reader for the native trade-node country-income cache.

The reader follows the runtime graph recorded in the pinned profile.  It reads
the graph and the country entry with ordinary bounded RPM and never calls a
game function.  Placeholder definitions are skipped, while a real definition
whose predicate or runtime linkage cannot be proved makes the complete result
unknown.  Cache values are signed 32-bit integers in ducats at scale 1000;
the public ``income_raw`` value is zero for an ineligible node while the
original cache value is retained as ``cache_income_raw``.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
import struct
from typing import Any, Mapping


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "trade-income-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_INDEX_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_SHA256 = "1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

BASIS = "native_trade_node_country_income_cache"
UNIT = "ducats"
SCALE = 1000
PERIOD = "month"
VALUE_ORIGIN = "derived_from_copied_native_caches"
NODE_VALUE_ORIGIN = "copied_native_cache"

INT32_MODULUS = 1 << 32
INT32_SIGN = 1 << 31
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
MAX_SINGLE_READ = 64 * 1024
MAX_TOTAL_READ = 512 * 1024
QWORD_WIDTH = 8
I32_WIDTH = 4


class ProfileError(RuntimeError):
    """The pinned trade-income profile or source index is unavailable."""


class ReadError(RuntimeError):
    """A bounded graph, string, or cache read failed."""


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if result < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return result


def _bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > limit:
            raise ProfileError(f"{label}_size_out_of_bound:{size}")
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"{label}_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > limit:
        raise ProfileError(f"{label}_read_size_changed")
    return raw


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _source_index_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("source_index_path_invalid")
    path = Path(raw_path)
    resolved = path.resolve() if path.is_absolute() else (_workspace_root() / path).resolve()
    root = _workspace_root()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_index_outside_workspace")
    return resolved


def _validate_source_index(profile: Mapping[str, Any]) -> dict[str, Any]:
    source = profile.get("source_index")
    if not isinstance(source, Mapping):
        raise ProfileError("source_index_missing")
    source_id = source.get("source_index_id")
    expected = source.get("sha256")
    if not isinstance(source_id, str) or not source_id:
        raise ProfileError("source_index_id_invalid")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ProfileError("source_index_sha256_invalid")
    path = _source_index_path(source.get("path"))
    raw = _bounded_bytes(path, SOURCE_INDEX_MAX_BYTES, "source_index")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("source_index_sha256_mismatch")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"source_index_json_invalid:{exc}") from exc
    if not isinstance(document, dict):
        raise ProfileError("source_index_shape_invalid")
    if document.get("source_index_id") != source_id:
        raise ProfileError("source_index_id_mismatch")
    if document.get("profile_id") != profile.get("profile_id"):
        raise ProfileError("source_index_profile_id_mismatch")
    return {
        "path": str(path),
        "source_index_id": source_id,
        "sha256": expected.lower(),
        "bytes": len(raw),
        "document": document,
    }


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    names = (
        "manager_global_rva", "vector_begin_offset", "vector_end_offset",
        "vector_stride", "max_definitions", "definition_predicate_slot",
        "predicate_true_rva", "predicate_false_rva", "definition_key_offset",
        "string_size", "string_length_offset", "string_capacity_offset",
        "string_inline_capacity", "max_key_length", "definition_center_offset",
        "max_center", "game_global_rva", "province_base_offset",
        "province_stride", "province_trade_node_offset", "node_definition_offset",
        "country_fullref_offset", "country_slot_offset", "entry_table_offset",
        "entry_stride", "entry_income_offset", "entry_flags_offset",
        "special_slot_global_rva", "wrap_bits",
    )
    try:
        result = {name: _parse_int(raw[name], f"layout.{name}") for name in names}
        result["signed"] = raw["signed"]
    except (KeyError, TypeError) as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc
    if result["vector_stride"] != QWORD_WIDTH:
        raise ProfileError("profile_vector_stride_mismatch")
    if result["max_definitions"] < 1 or result["max_definitions"] > 1024:
        raise ProfileError("profile_definition_bound_invalid")
    if result["definition_predicate_slot"] != 0x40:
        raise ProfileError("profile_predicate_slot_mismatch")
    if result["predicate_true_rva"] != 0x8F440 or result["predicate_false_rva"] != 0x8F450:
        raise ProfileError("profile_predicate_rva_mismatch")
    if result["string_size"] != 32 or result["string_length_offset"] != 16 or result["string_capacity_offset"] != 24:
        raise ProfileError("profile_string_layout_mismatch")
    if result["string_inline_capacity"] != 16 or result["max_key_length"] != 128:
        raise ProfileError("profile_string_bound_mismatch")
    if result["max_center"] != 32767 or result["province_stride"] != 0x2E10:
        raise ProfileError("profile_center_layout_mismatch")
    if result["entry_stride"] != 0xC0 or result["entry_income_offset"] != 0x34:
        raise ProfileError("profile_entry_layout_mismatch")
    if result["entry_flags_offset"] != 0xAC or result["wrap_bits"] != 32 or result["signed"] is not True:
        raise ProfileError("profile_int32_contract_mismatch")
    if result["country_slot_offset"] != 4:
        raise ProfileError("profile_country_slot_offset_mismatch")
    return result


def _profile_code_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, bytes]]:
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_missing")
    guards: list[tuple[str, int, bytes]] = []
    names: set[str] = set()
    total = 0
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = item.get("name")
        raw_hex = item.get("hex", item.get("bytes"))
        if not isinstance(name, str) or not name or name in names:
            raise ProfileError("profile_code_guard_name_invalid")
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        if not raw or len(raw) > MAX_SINGLE_READ:
            raise ProfileError(f"profile_code_guard_size_invalid:{name}")
        total += len(raw)
        if total > MAX_TOTAL_READ:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        guards.append((name, rva, raw))
    return guards


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "trade-income-memory-1374":
        raise ProfileError("profile_shape_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _profile_layout(profile)
    _profile_code_guards(profile)


def _load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    path = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if not isinstance(expected, str) or len(expected) != 64 or expected == "pending-profile":
        raise ProfileError("profile_sha256_pending_or_invalid")
    raw = _bounded_bytes(path, PROFILE_MAX_BYTES, "profile")
    if hashlib.sha256(raw).hexdigest().lower() != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    _validate_profile_shape(profile)
    source = _validate_source_index(profile)
    profile = dict(profile)
    profile["_validated_source_index"] = source
    return profile


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _active_profile() -> dict[str, Any]:
    return _load_profile()


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _valid_address(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0x10000 <= value <= MAX_USER_ADDRESS


def _wrap_i32(value: int) -> int:
    value &= INT32_MODULUS - 1
    return value - INT32_MODULUS if value & INT32_SIGN else value


def _i32_hex(value: int) -> str:
    return (value & (INT32_MODULUS - 1)).to_bytes(4, "little", signed=False).hex()


def _pointer_raw_hex(value: int) -> str:
    return value.to_bytes(QWORD_WIDTH, "little", signed=False).hex()


def _pointer_from_hex(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = int(value, 0)
    except (TypeError, ValueError):
        return None
    return parsed if _valid_address(parsed) else None


def _deepcopy(value: Any) -> Any:
    return json.loads(json.dumps(value))


class _Budget:
    def __init__(self, reader: Any) -> None:
        self.reader = reader
        self.bytes_requested = 0
        self.calls = 0
        self.read_log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if not _valid_address(address):
            raise ReadError(f"address_invalid:{label}")
        if not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_READ:
            raise ReadError(f"read_size_invalid:{label}")
        if self.bytes_requested + size > MAX_TOTAL_READ:
            raise ReadError("read_budget_exceeded")
        method = getattr(self.reader, "read", None)
        if not callable(method):
            raise ReadError("reader_read_method_missing")
        raw = method(address, size, label)
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
            raise ReadError(f"short_or_invalid_read:{label}")
        data = bytes(raw)
        self.bytes_requested += size
        self.calls += 1
        self.read_log.append({"address": _hex(address), "size": size, "label": label, "raw_hex": data.hex()})
        return data


def _qword(ctx: _Budget, address: int, label: str) -> tuple[int, bytes]:
    raw = ctx.read(address, QWORD_WIDTH, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _i32(ctx: _Budget, address: int, label: str) -> tuple[int, bytes]:
    raw = ctx.read(address, I32_WIDTH, label)
    return int.from_bytes(raw, "little", signed=True), raw


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {"status": "unknown", "checks": {}, "unknown_conditions": [reason or "profile_unavailable"]}
    source = profile.get("_validated_source_index", profile.get("source_index", {}))
    source_ok = isinstance(source, Mapping) and all(
        isinstance(source.get(key), str) and bool(source.get(key)) for key in ("source_index_id", "path", "sha256")
    )
    checks = {
        "profile_id": profile.get("profile_id") == "trade-income-memory-1374",
        "game_version": profile.get("game_version") == EXPECTED_VERSION,
        "executable_sha256": isinstance(profile.get("executable"), Mapping)
        and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
        "source_index": source_ok,
        "layout": True,
        "code_guards": True,
    }
    failed = [key for key, value in checks.items() if value is not True]
    return {
        "status": "observed" if not failed else "unknown",
        "profile_id": profile.get("profile_id"),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": checks,
        "source_index": {
            key: source.get(key)
            for key in ("source_index_id", "path", "sha256", "bytes")
            if isinstance(source, Mapping) and key in source
        },
        "unknown_conditions": ["profile_contract_failed:" + ",".join(failed)] if failed else ([reason] if reason else []),
    }


def _empty_record(reason: str, *, guard: Mapping[str, Any] | None = None, profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    static_guard = _static_contract_guard(profile, reason)
    return {
        "status": "unknown",
        "reason": reason,
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": static_guard,
        "runtime_code_guard": _deepcopy(guard) if isinstance(guard, Mapping) else None,
        "module_base": None,
        "country_pointer": None,
        "country": EXPECTED_COUNTRY,
        "country_fullref_raw_hex": None,
        "country_slot": None,
        "special_slot": None,
        "graph": None,
        "nodes": None,
        "total_raw": None,
        "total_raw_hex": None,
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "read_budget": {"bytes_requested": 0, "calls": 0},
        "observation": {"status": "unknown", "reason": reason},
    }


def _runtime_code_guard(ctx: _Budget, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown", "module_base": _hex(module_base), "checks": {}, "records": {}, "unknown_conditions": []
    }
    try:
        for name, rva, expected in _profile_code_guards(profile):
            address = module_base + rva
            if not _valid_address(address):
                raise ReadError(f"guard_address_invalid:{name}")
            actual = ctx.read(address, len(expected), f"trade_income.code.{name}")
            result["records"][name] = {
                "rva": _hex(rva), "address": _hex(address), "expected_hex": expected.hex(), "actual_hex": actual.hex(),
                "expected_sha256": hashlib.sha256(expected).hexdigest(), "actual_sha256": hashlib.sha256(actual).hexdigest(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _address_add(base: int, offset: int, label: str) -> int:
    if not _valid_address(base) or not isinstance(offset, int) or offset < 0:
        raise ReadError(f"address_base_invalid:{label}")
    address = base + offset
    if not _valid_address(address):
        raise ReadError(f"address_overflow:{label}")
    return address


def _node_key(ctx: _Budget, definition: int, layout: Mapping[str, int], index: int) -> tuple[str, str, int, str]:
    object_address = _address_add(definition, layout["definition_key_offset"], f"node[{index}].key_object")
    raw = ctx.read(object_address, layout["string_size"], f"node[{index}].key_object")
    length = int.from_bytes(raw[layout["string_length_offset"]:layout["string_length_offset"] + 8], "little")
    capacity = int.from_bytes(raw[layout["string_capacity_offset"]:layout["string_capacity_offset"] + 8], "little")
    if length < 1 or length > layout["max_key_length"] or capacity < length:
        raise ReadError(f"node_key_length_invalid:{index}")
    if capacity < layout["string_inline_capacity"]:
        payload = raw[:length + 1]
    else:
        pointer = int.from_bytes(raw[:8], "little")
        if not _valid_address(pointer):
            raise ReadError(f"node_key_pointer_invalid:{index}")
        payload = ctx.read(pointer, length + 1, f"node[{index}].key_bytes")
    if len(payload) != length + 1 or payload[length] != 0 or 0 in payload[:length]:
        raise ReadError(f"node_key_nul_invalid:{index}")
    if any(byte < 1 or byte >= 0x80 for byte in payload[:length]):
        raise ReadError(f"node_key_ascii_invalid:{index}")
    return payload[:length].decode("ascii"), payload.hex(), length, raw.hex()


def read_fields(reader: Any, module_base: int, country_pointer: int,
                country: str = EXPECTED_COUNTRY) -> dict[str, Any]:
    """Read the bounded native graph and return one JSON-shaped record."""
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
    except Exception as exc:
        return _empty_record(f"profile_unavailable:{type(exc).__name__}:{exc}")
    static_guard = _static_contract_guard(profile)
    if static_guard.get("status") != "observed":
        return _empty_record("static_contract_guard_failed", profile=profile)
    if not _valid_address(module_base) or not _valid_address(country_pointer):
        return _empty_record("module_or_country_pointer_invalid", profile=profile)
    ctx = _Budget(reader)
    guard = _runtime_code_guard(ctx, module_base, profile)
    if guard.get("status") != "observed":
        result = _empty_record("runtime_code_guard_failed", guard=guard, profile=profile)
        result["read_budget"] = {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls}
        return result
    try:
        if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
            raise ReadError("country_tag_invalid")
        fullref_address = _address_add(country_pointer, layout["country_fullref_offset"], "country.fullref")
        fullref_raw = ctx.read(fullref_address, QWORD_WIDTH, "country.fullref")
        if fullref_raw[:4] != country.encode("ascii") + b"\0":
            raise ReadError("country_fullref_prefix_mismatch")
        slot_offset = layout["country_slot_offset"]
        if slot_offset + 2 > len(fullref_raw):
            raise ReadError("country_slot_offset_out_of_bounds")
        slot = int.from_bytes(fullref_raw[slot_offset:slot_offset + 2], "little", signed=True)
        if slot < 0 or slot > 32767:
            raise ReadError("country_slot_invalid")
        special_address = _address_add(module_base, layout["special_slot_global_rva"], "globals.special_slot")
        special_raw = ctx.read(special_address, I32_WIDTH, "globals.special_slot")
        special_slot = int.from_bytes(special_raw, "little", signed=True)
        if special_slot < 0 or special_slot > 32767:
            raise ReadError("special_slot_invalid")
        manager_address = _address_add(module_base, layout["manager_global_rva"], "globals.manager")
        manager, manager_raw = _qword(ctx, manager_address, "globals.manager")
        if not _valid_address(manager):
            raise ReadError("manager_pointer_invalid")
        begin, begin_raw = _qword(ctx, _address_add(manager, layout["vector_begin_offset"], "manager.begin"), "manager.begin")
        end, end_raw = _qword(ctx, _address_add(manager, layout["vector_end_offset"], "manager.end"), "manager.end")
        if not _valid_address(begin) or not _valid_address(end) or end < begin:
            raise ReadError("vector_range_invalid")
        stride = layout["vector_stride"]
        distance = end - begin
        if distance == 0 or distance % stride:
            raise ReadError("vector_range_not_stride_aligned")
        count = distance // stride
        if count < 1 or count > layout["max_definitions"]:
            raise ReadError("vector_definition_count_out_of_bound")
        vector_raw = ctx.read(begin, distance, "trade_node.definition_vector")
        game_address = _address_add(module_base, layout["game_global_rva"], "globals.game")
        game, game_raw = _qword(ctx, game_address, "globals.game")
        if not _valid_address(game):
            raise ReadError("game_pointer_invalid")
        province_base, province_base_raw = _qword(
            ctx, _address_add(game, layout["province_base_offset"], "game.province_base"), "game.province_base"
        )
        if not _valid_address(province_base):
            raise ReadError("province_base_invalid")
        nodes: list[dict[str, Any]] = []
        graph_entries: list[dict[str, Any]] = []
        placeholders = 0
        seen: set[str] = set()
        total = 0
        for index in range(count):
            graph_raw = vector_raw[index * stride:(index + 1) * stride]
            definition = int.from_bytes(graph_raw, "little", signed=False)
            if not _valid_address(definition):
                raise ReadError(f"definition_pointer_invalid:{index}")
            vtable, vtable_raw = _qword(ctx, definition, f"node[{index}].vtable")
            if not _valid_address(vtable):
                raise ReadError(f"vtable_pointer_invalid:{index}")
            method, method_raw = _qword(
                ctx, _address_add(vtable, layout["definition_predicate_slot"], f"node[{index}].predicate"), f"node[{index}].predicate"
            )
            method_rva = method - module_base
            if method_rva == layout["predicate_false_rva"]:
                placeholders += 1
                graph_entries.append({
                    "graph_raw_hex": graph_raw.hex(),
                    "definition_pointer": _hex(definition),
                    "predicate_rva": _hex(method_rva),
                    "placeholder": True,
                })
                continue
            if method_rva != layout["predicate_true_rva"]:
                raise ReadError(f"definition_predicate_unknown:{index}")
            node_id, key_bytes_hex, key_length, key_object_hex = _node_key(ctx, definition, layout, index)
            if node_id in seen:
                raise ReadError(f"duplicate_node_id:{node_id}")
            seen.add(node_id)
            center, center_raw = _i32(ctx, _address_add(definition, layout["definition_center_offset"], f"node[{index}].center"), f"node[{index}].center")
            if center < 1 or center > layout["max_center"]:
                raise ReadError(f"center_invalid:{index}")
            province_offset = center * layout["province_stride"]
            if province_offset > MAX_USER_ADDRESS:
                raise ReadError(f"province_offset_overflow:{index}")
            province = _address_add(province_base, province_offset, f"node[{index}].province")
            runtime, runtime_raw = _qword(ctx, _address_add(province, layout["province_trade_node_offset"], f"node[{index}].runtime"), f"node[{index}].runtime")
            if not _valid_address(runtime):
                raise ReadError(f"runtime_pointer_invalid:{index}")
            native_definition, native_definition_raw = _qword(ctx, _address_add(runtime, layout["node_definition_offset"], f"node[{index}].native_definition"), f"node[{index}].native_definition")
            if native_definition != definition:
                raise ReadError(f"native_definition_mismatch:{index}")
            table, table_raw = _qword(ctx, _address_add(runtime, layout["entry_table_offset"], f"node[{index}].table"), f"node[{index}].table")
            if not _valid_address(table):
                raise ReadError(f"entry_table_invalid:{index}")
            entry_offset = slot * layout["entry_stride"]
            if entry_offset > MAX_USER_ADDRESS:
                raise ReadError(f"entry_offset_overflow:{index}")
            entry = _address_add(table, entry_offset, f"node[{index}].entry")
            entry_raw = ctx.read(entry, layout["entry_stride"], f"node[{index}].entry")
            income_offset = layout["entry_income_offset"]
            flags_offset = layout["entry_flags_offset"]
            if income_offset + I32_WIDTH > len(entry_raw) or flags_offset + 3 > len(entry_raw):
                raise ReadError(f"entry_field_out_of_bounds:{index}")
            cache_income = int.from_bytes(entry_raw[income_offset:income_offset + I32_WIDTH], "little", signed=True)
            flag_ac, flag_ad, flag_ae = entry_raw[flags_offset:flags_offset + 3]
            eligible = bool(
                slot == special_slot
                or (flag_ae != 0 and flag_ac == 0)
                or (flag_ad != 0 and not (flag_ae != 0 and flag_ac != 0))
            )
            income = cache_income if eligible else 0
            total = _wrap_i32(total + income)
            graph_entries.append({
                "graph_raw_hex": graph_raw.hex(),
                "definition_pointer": _hex(definition),
                "predicate_rva": _hex(method_rva),
                "placeholder": False,
                "node_id": node_id,
            })
            nodes.append({
                "node_id": node_id,
                "node_id_raw_hex": key_bytes_hex,
                "key_raw_hex": key_bytes_hex,
                "node_id_length": key_length,
                "node_key_object_raw_hex": key_object_hex,
                "key_object_raw_hex": key_object_hex,
                "graph_entry_raw_hex": graph_raw.hex(),
                "graph_raw_hex": graph_raw.hex(),
                "definition_pointer": _hex(definition),
                "definition_raw_hex": graph_raw.hex(),
                "definition_pointer_raw_hex": graph_raw.hex(),
                "vtable_pointer": _hex(vtable),
                "vtable_raw_hex": vtable_raw.hex(),
                "predicate_pointer": _hex(method),
                "predicate_raw_hex": method_raw.hex(),
                "predicate_pointer_raw_hex": method_raw.hex(),
                "predicate_rva": _hex(method_rva),
                "center": center,
                "center_raw_hex": center_raw.hex(),
                "province_pointer": _hex(province),
                "province_pointer_raw_hex": _pointer_raw_hex(province),
                "province_runtime_field_address": _hex(
                    _address_add(province, layout["province_trade_node_offset"], f"node[{index}].runtime")
                ),
                "runtime_pointer": _hex(runtime),
                "runtime_raw_hex": runtime_raw.hex(),
                "runtime_definition_field_address": _hex(
                    _address_add(runtime, layout["node_definition_offset"], f"node[{index}].native_definition")
                ),
                "native_definition_pointer": _hex(native_definition),
                "native_definition_raw_hex": native_definition_raw.hex(),
                "runtime_table_field_address": _hex(
                    _address_add(runtime, layout["entry_table_offset"], f"node[{index}].table")
                ),
                "table_pointer": _hex(table),
                "table_raw_hex": table_raw.hex(),
                "entry_pointer": _hex(entry),
                "entry_pointer_raw_hex": _pointer_raw_hex(entry),
                "entry_raw_hex": entry_raw.hex(),
                "cache_income_raw": cache_income,
                "cache_income_raw_hex": _i32_hex(cache_income),
                "income_raw": income,
                "income_raw_hex": _i32_hex(income),
                "value_origin": NODE_VALUE_ORIGIN,
                "flag_ac": flag_ac,
                "flag_ad": flag_ad,
                "flag_ae": flag_ae,
                "eligible": eligible,
            })
        if not nodes:
            raise ReadError("no_real_trade_nodes")
        graph = {
            "manager_global_address": _hex(manager_address),
            "manager_pointer": _hex(manager), "manager_raw_hex": manager_raw.hex(),
            "begin_pointer": _hex(begin), "begin_raw_hex": begin_raw.hex(),
            "end_pointer": _hex(end), "end_raw_hex": end_raw.hex(),
            "vector_raw_hex": vector_raw.hex(), "node_count": count,
            "real_node_count": len(nodes), "placeholder_count": placeholders,
            "entries": graph_entries,
            "game_global_address": _hex(game_address),
            "game_pointer": _hex(game), "game_raw_hex": game_raw.hex(),
            "province_base_address": _hex(
                _address_add(game, layout["province_base_offset"], "game.province_base")
            ),
            "province_base_pointer": _hex(province_base), "province_base_raw_hex": province_base_raw.hex(),
        }
        return {
            "status": "observed",
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "static_contract_guard": static_guard,
            "runtime_code_guard": guard,
            "module_base": _hex(module_base),
            "country_pointer": _hex(country_pointer),
            "country": country,
            "country_fullref_address": _hex(fullref_address),
            "country_fullref_raw_hex": fullref_raw.hex(),
            "country_slot": slot,
            "special_slot": special_slot,
            "special_slot_address": _hex(special_address),
            "special_slot_raw_hex": special_raw.hex(),
            "graph": graph,
            "nodes": nodes,
            "total_raw": total,
            "total_raw_hex": _i32_hex(total),
            "basis": BASIS,
            "unit": UNIT,
            "scale": SCALE,
            "period": PERIOD,
            "value_origin": VALUE_ORIGIN,
            "read_budget": {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls},
            "observation": {
                "module_base": _hex(module_base), "country_pointer": _hex(country_pointer),
                "country": country, "country_slot": slot, "special_slot": special_slot,
                "node_count": count, "real_node_count": len(nodes), "placeholder_count": placeholders,
            },
        }
    except Exception as exc:
        result = _empty_record(f"read_failed:{type(exc).__name__}:{exc}", guard=guard, profile=profile)
        result["read_budget"] = {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls}
        return result


def _valid_hex(raw: Any, width: int) -> bool:
    if not isinstance(raw, str) or len(raw) != width * 2:
        return False
    try:
        bytes.fromhex(raw)
    except ValueError:
        return False
    return True


def validate_record(record: Any) -> bool:
    """Validate a complete record, including raw bytes and derived totals."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
    except Exception:
        return False
    if record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
        return False
    static = record.get("static_contract_guard")
    runtime = record.get("runtime_code_guard")
    if not isinstance(static, Mapping) or static.get("status") != "observed":
        return False
    if not isinstance(runtime, Mapping) or runtime.get("status") != "observed":
        return False
    if static.get("profile_id") != "trade-income-memory-1374" or static.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
        return False
    module_base = _pointer_from_hex(record.get("module_base"))
    country_pointer = _pointer_from_hex(record.get("country_pointer"))
    if module_base is None or country_pointer is None:
        return False
    static_checks = static.get("checks")
    expected_static_names = {
        "profile_id", "game_version", "executable_sha256", "source_index", "layout", "code_guards"
    }
    if (
        not isinstance(static_checks, Mapping)
        or set(static_checks) != expected_static_names
        or any(value is not True for value in static_checks.values())
        or static.get("unknown_conditions") != []
    ):
        return False
    expected_source = profile.get("_validated_source_index", profile.get("source_index"))
    source_summary = static.get("source_index")
    if not isinstance(expected_source, Mapping) or not isinstance(source_summary, Mapping):
        return False
    for source_key in ("source_index_id", "path", "sha256"):
        if source_summary.get(source_key) != expected_source.get(source_key):
            return False
    runtime_checks = runtime.get("checks")
    try:
        expected_runtime_names = {name for name, _rva, _raw in _profile_code_guards(profile)}
    except Exception:
        return False
    runtime_records = runtime.get("records")
    if (
        not isinstance(runtime_checks, Mapping)
        or set(runtime_checks) != expected_runtime_names
        or any(value is not True for value in runtime_checks.values())
        or not isinstance(runtime_records, Mapping)
        or set(runtime_records) != expected_runtime_names
        or runtime.get("unknown_conditions") != []
    ):
        return False
    for name, rva, expected in _profile_code_guards(profile):
        item = runtime_records.get(name)
        if (
            not isinstance(item, Mapping)
            or item.get("rva") != _hex(rva)
            or item.get("address") != _hex(_address_add(module_base, rva, f"guard.{name}"))
            or item.get("expected_hex") != expected.hex()
            or item.get("actual_hex") != expected.hex()
            or item.get("expected_sha256") != hashlib.sha256(expected).hexdigest()
            or item.get("actual_sha256") != hashlib.sha256(expected).hexdigest()
        ):
            return False
    if runtime.get("module_base") != _hex(module_base):
        return False
    country = record.get("country")
    if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None or record.get("basis") != BASIS:
        return False
    if record.get("unit") != UNIT or record.get("scale") != SCALE or record.get("period") != PERIOD or record.get("value_origin") != VALUE_ORIGIN:
        return False
    fullref_hex = record.get("country_fullref_raw_hex")
    if not _valid_hex(fullref_hex, QWORD_WIDTH):
        return False
    fullref = bytes.fromhex(fullref_hex)
    if fullref[:4] != country.encode("ascii") + b"\0":
        return False
    if record.get("country_fullref_address") != _hex(
        _address_add(country_pointer, layout["country_fullref_offset"], "country.fullref")
    ):
        return False
    slot = int.from_bytes(fullref[layout["country_slot_offset"]:layout["country_slot_offset"] + 2], "little", signed=True)
    if slot != record.get("country_slot") or slot < 0 or slot > 32767:
        return False
    special = record.get("special_slot")
    if not isinstance(special, int) or isinstance(special, bool) or special < 0 or special > 32767:
        return False
    if not _valid_hex(record.get("special_slot_raw_hex"), I32_WIDTH):
        return False
    if int.from_bytes(bytes.fromhex(record["special_slot_raw_hex"]), "little", signed=True) != special:
        return False
    if record.get("special_slot_address") != _hex(
        _address_add(module_base, layout["special_slot_global_rva"], "globals.special_slot")
    ):
        return False
    graph = record.get("graph")
    nodes = record.get("nodes")
    if not isinstance(graph, Mapping) or not isinstance(nodes, list) or not nodes:
        return False
    def pointer_pair(value_key: str, raw_key: str) -> int | None:
        value = _pointer_from_hex(graph.get(value_key) if value_key in graph else record.get(value_key))
        raw = graph.get(raw_key) if raw_key in graph else record.get(raw_key)
        if value is None or not _valid_hex(raw, QWORD_WIDTH):
            return None
        if int.from_bytes(bytes.fromhex(raw), "little", signed=False) != value:
            return None
        return value

    manager = pointer_pair("manager_pointer", "manager_raw_hex")
    begin = pointer_pair("begin_pointer", "begin_raw_hex")
    end = pointer_pair("end_pointer", "end_raw_hex")
    game = pointer_pair("game_pointer", "game_raw_hex")
    province_base = pointer_pair("province_base_pointer", "province_base_raw_hex")
    if None in (manager, begin, end, game, province_base):
        return False
    if graph.get("manager_global_address") != _hex(
        _address_add(module_base, layout["manager_global_rva"], "globals.manager")
    ):
        return False
    if graph.get("game_global_address") != _hex(
        _address_add(module_base, layout["game_global_rva"], "globals.game")
    ):
        return False
    if graph.get("province_base_address") != _hex(
        _address_add(game, layout["province_base_offset"], "game.province_base")
    ):
        return False
    if end < begin or end - begin == 0 or (end - begin) % layout["vector_stride"]:
        return False
    count = graph.get("node_count")
    if not isinstance(count, int) or count != (end - begin) // layout["vector_stride"] or count < len(nodes) or count > layout["max_definitions"]:
        return False
    if graph.get("real_node_count") != len(nodes) or graph.get("placeholder_count") != count - len(nodes):
        return False
    if not _valid_hex(graph.get("vector_raw_hex"), count * layout["vector_stride"]):
        return False
    seen: set[str] = set()
    total = 0
    vector_chunks = [
        bytes.fromhex(graph["vector_raw_hex"])[index:index + layout["vector_stride"]]
        for index in range(0, count * layout["vector_stride"], layout["vector_stride"])
    ]
    graph_entries = graph.get("entries")
    if not isinstance(graph_entries, list) or len(graph_entries) != count:
        return False
    real_entry_indices: list[int] = []
    for index, entry in enumerate(graph_entries):
        if not isinstance(entry, Mapping) or not _valid_hex(entry.get("graph_raw_hex"), layout["vector_stride"]):
            return False
        if bytes.fromhex(entry["graph_raw_hex"]) != vector_chunks[index]:
            return False
        if entry.get("definition_pointer") != _hex(int.from_bytes(vector_chunks[index], "little", signed=False)):
            return False
        if entry.get("placeholder") is True:
            if entry.get("predicate_rva") != _hex(layout["predicate_false_rva"]):
                return False
        elif entry.get("placeholder") is False:
            if entry.get("predicate_rva") != _hex(layout["predicate_true_rva"]):
                return False
            real_entry_indices.append(index)
        else:
            return False
    if len(real_entry_indices) != len(nodes):
        return False
    vector_cursor = 0
    for node, entry_index in zip(nodes, real_entry_indices):
        if not isinstance(node, Mapping):
            return False
        definition = _pointer_from_hex(node.get("definition_pointer"))
        vtable = _pointer_from_hex(node.get("vtable_pointer"))
        predicate = _pointer_from_hex(node.get("predicate_pointer"))
        province = _pointer_from_hex(node.get("province_pointer"))
        runtime = _pointer_from_hex(node.get("runtime_pointer"))
        native_definition = _pointer_from_hex(node.get("native_definition_pointer"))
        table = _pointer_from_hex(node.get("table_pointer"))
        entry = _pointer_from_hex(node.get("entry_pointer"))
        if None in (definition, vtable, predicate, province, runtime, native_definition, table, entry):
            return False
        node_id = node.get("node_id")
        if not isinstance(node_id, str) or node_id in seen or not 1 <= len(node_id) <= layout["max_key_length"]:
            return False
        try:
            encoded = node_id.encode("ascii")
        except UnicodeEncodeError:
            return False
        if not _valid_hex(node.get("node_id_raw_hex"), len(encoded) + 1):
            return False
        key_raw = bytes.fromhex(node["node_id_raw_hex"])
        if key_raw != encoded + b"\0" or node.get("key_raw_hex") != node.get("node_id_raw_hex"):
            return False
        seen.add(node_id)
        if node.get("node_id_length") != len(encoded) or not _valid_hex(node.get("node_key_object_raw_hex"), layout["string_size"]):
            return False
        if node.get("key_object_raw_hex") != node.get("node_key_object_raw_hex"):
            return False
        key_object = bytes.fromhex(node["node_key_object_raw_hex"])
        key_length = int.from_bytes(
            key_object[layout["string_length_offset"]:layout["string_length_offset"] + 8], "little", signed=False
        )
        key_capacity = int.from_bytes(
            key_object[layout["string_capacity_offset"]:layout["string_capacity_offset"] + 8], "little", signed=False
        )
        if key_length != len(encoded) or key_capacity < key_length:
            return False
        if key_capacity < layout["string_inline_capacity"] and key_object[:len(encoded) + 1] != key_raw:
            return False
        if not _valid_hex(node.get("graph_entry_raw_hex"), layout["vector_stride"]):
            return False
        graph_entry = bytes.fromhex(node["graph_entry_raw_hex"])
        if graph_entry != vector_chunks[entry_index] or entry_index < vector_cursor:
            return False
        if node.get("definition_pointer_raw_hex") != node.get("graph_entry_raw_hex"):
            return False
        if int.from_bytes(graph_entry, "little", signed=False) != definition:
            return False
        if graph_entries[entry_index].get("node_id") != node.get("node_id"):
            return False
        try:
            vector_cursor = vector_chunks.index(graph_entry, vector_cursor) + 1
        except ValueError:
            return False
        if node.get("definition_raw_hex") != node.get("graph_entry_raw_hex"):
            return False
        if not _valid_hex(node.get("vtable_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(node["vtable_raw_hex"]), "little", signed=False) != vtable:
            return False
        if not _valid_hex(node.get("predicate_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(node["predicate_raw_hex"]), "little", signed=False) != predicate:
            return False
        if node.get("predicate_pointer_raw_hex") != node.get("predicate_raw_hex"):
            return False
        predicate_rva = node.get("predicate_rva")
        try:
            predicate_rva_value = int(predicate_rva, 0)
        except (TypeError, ValueError):
            return False
        if predicate - module_base != predicate_rva_value or predicate_rva_value != layout["predicate_true_rva"]:
            return False
        if not _valid_hex(node.get("center_raw_hex"), I32_WIDTH):
            return False
        center = int.from_bytes(bytes.fromhex(node["center_raw_hex"]), "little", signed=True)
        if center != node.get("center") or center < 1 or center > layout["max_center"]:
            return False
        if native_definition != definition:
            return False
        if not _valid_hex(node.get("native_definition_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(node["native_definition_raw_hex"]), "little", signed=False) != native_definition:
            return False
        if not _valid_hex(node.get("runtime_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(node["runtime_raw_hex"]), "little", signed=False) != runtime:
            return False
        if not _valid_hex(node.get("table_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(node["table_raw_hex"]), "little", signed=False) != table:
            return False
        if not _valid_hex(node.get("province_pointer_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(node["province_pointer_raw_hex"]), "little", signed=False) != province:
            return False
        expected_province = _address_add(province_base, center * layout["province_stride"], "node.province")
        if province != expected_province:
            return False
        if node.get("province_runtime_field_address") != _hex(
            _address_add(province, layout["province_trade_node_offset"], "node.runtime")
        ):
            return False
        if node.get("runtime_definition_field_address") != _hex(
            _address_add(runtime, layout["node_definition_offset"], "node.native_definition")
        ):
            return False
        if node.get("runtime_table_field_address") != _hex(
            _address_add(runtime, layout["entry_table_offset"], "node.table")
        ):
            return False
        expected_entry = _address_add(table, slot * layout["entry_stride"], "node.entry")
        if entry != expected_entry:
            return False
        if not _valid_hex(node.get("entry_pointer_raw_hex"), QWORD_WIDTH) or int.from_bytes(bytes.fromhex(node["entry_pointer_raw_hex"]), "little", signed=False) != entry:
            return False
        if not _valid_hex(node.get("entry_raw_hex"), layout["entry_stride"]):
            return False
        entry_raw = bytes.fromhex(node["entry_raw_hex"])
        cache = node.get("cache_income_raw")
        income = node.get("income_raw")
        if not isinstance(cache, int) or isinstance(cache, bool) or not -(1 << 31) <= cache < (1 << 31):
            return False
        if not isinstance(income, int) or isinstance(income, bool) or not -(1 << 31) <= income < (1 << 31):
            return False
        if node.get("cache_income_raw_hex") != _i32_hex(cache) or node.get("income_raw_hex") != _i32_hex(income):
            return False
        if node.get("value_origin") != NODE_VALUE_ORIGIN:
            return False
        flags = [node.get("flag_ac"), node.get("flag_ad"), node.get("flag_ae")]
        if any(not isinstance(flag, int) or isinstance(flag, bool) or not 0 <= flag <= 255 for flag in flags):
            return False
        if int.from_bytes(entry_raw[layout["entry_income_offset"]:layout["entry_income_offset"] + I32_WIDTH], "little", signed=True) != cache:
            return False
        if tuple(entry_raw[layout["entry_flags_offset"]:layout["entry_flags_offset"] + 3]) != tuple(flags):
            return False
        eligible = bool(
            slot == special
            or (flags[2] != 0 and flags[0] == 0)
            or (flags[1] != 0 and not (flags[2] != 0 and flags[0] != 0))
        )
        if node.get("eligible") is not eligible or income != (cache if eligible else 0):
            return False
        if not isinstance(node.get("center"), int) or not 1 <= node["center"] <= layout["max_center"]:
            return False
        total = _wrap_i32(total + income)
    if record.get("total_raw") != total or record.get("total_raw_hex") != _i32_hex(total):
        return False
    observation = record.get("observation")
    if not isinstance(observation, Mapping):
        return False
    if (
        observation.get("module_base") != _hex(module_base)
        or observation.get("country_pointer") != _hex(country_pointer)
        or observation.get("country") != country
        or observation.get("country_slot") != slot
        or observation.get("special_slot") != special
        or observation.get("node_count") != count
        or observation.get("real_node_count") != len(nodes)
        or observation.get("placeholder_count") != count - len(nodes)
    ):
        return False
    return True


def retract_record(record: Mapping[str, Any] | None, reason: str) -> dict[str, Any]:
    """Remove consumable node values after a failed parent observation."""
    if isinstance(record, Mapping):
        result = _deepcopy(record)
    else:
        result = _empty_record(reason)
    result["status"] = "unknown"
    result["reason"] = reason
    result["nodes"] = None
    result["total_raw"] = None
    result["total_raw_hex"] = None
    result["observation"] = {"status": "unknown", "reason": reason}
    return result


__all__ = [
    "BASIS", "EXPECTED_COUNTRY", "EXPECTED_EXE_SHA256", "EXPECTED_PROFILE_SHA256", "EXPECTED_VERSION",
    "NODE_VALUE_ORIGIN", "PERIOD", "PROFILE", "PROFILE_FILE", "SCALE", "UNIT", "VALUE_ORIGIN", "ProfileError", "ReadError",
    "read_fields", "retract_record", "validate_record",
]
