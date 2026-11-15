"""Bounded private reader for selected trade-node value caches (T03).

This module only reads a supplied read-only memory interface. It never opens
or controls the game process. Node discovery, G02 admission, two-pass capture,
and public projection remain responsibilities of the parent capture layer.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "trade-value-memory-1374.json"
PROFILE_MAX_BYTES = 128 * 1024
SOURCE_INDEX_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_SHA256 = "cc5ccb8d68494be3fd4c8566738e6654e85efc067306b0c48807642aef9484e1"
PROFILE_SHA256 = EXPECTED_PROFILE_SHA256
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_BASE = 0x140000000

FIELDS = (
    "T03.local_value",
    "T03.incoming_value",
    "T03.total_value",
    "T03.outgoing_value",
    "T03.collected_value",
)
VALUE_FIELDS = FIELDS[:4]
NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", re.ASCII)

UNIT = "ducats"
SCALE = 1000
PERIOD = "current"
BASIS = "native_trade_node_current_value_caches_and_flows"
COLLECTED_UNKNOWN = "NODE_COLLECTED_VALUE_SOURCE_UNPROVEN"

INT32_MODULUS = 1 << 32
INT32_SIGN = 1 << 31
MAX_USER_ADDRESS_EXCLUSIVE = 0x0000800000000000
MAX_SINGLE_READ = 1024
MAX_TOTAL_READ = 256 * 1024
MAX_READ_CALLS = 1024
QWORD_WIDTH = 8
I32_WIDTH = 4


class ProfileError(RuntimeError):
    """The pinned profile or source index is invalid or unavailable."""


class ReadError(RuntimeError):
    """A bounded pointer, graph, or value read failed closed."""


def _valid_address(value: Any, *, alignment: int = 1) -> bool:
    return (type(value) is int and MAX_USER_ADDRESS_EXCLUSIVE > value >= 0x10000
            and alignment > 0 and value % alignment == 0)


def _address_add(base: int, offset: int, label: str) -> int:
    if not _valid_address(base) or type(offset) is not int or offset < 0:
        raise ReadError(f"address_base_invalid:{label}")
    result = base + offset
    if not _valid_address(result):
        raise ReadError(f"address_overflow:{label}")
    return result


def _address_range(address: int, size: int, label: str) -> None:
    if (not _valid_address(address) or type(size) is not int or size <= 0
            or size > MAX_SINGLE_READ or address + size > MAX_USER_ADDRESS_EXCLUSIVE):
        raise ReadError(f"address_range_invalid:{label}")


def _parse_profile_int(value: Any, label: str) -> int:
    if type(value) is int:
        result = value
    elif type(value) is str:
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if result < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return result


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _bounded_read(path: Path, maximum: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > maximum:
            raise ProfileError(f"{label}_size_out_of_bound:{size}")
        raw = path.read_bytes()
    except ProfileError:
        raise
    except OSError as exc:
        raise ProfileError(f"{label}_read_failed:{type(exc).__name__}") from exc
    if len(raw) != size or len(raw) > maximum:
        raise ProfileError(f"{label}_size_changed")
    return raw


def _profile_code_guards(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_guards = profile.get("code_guards")
    if type(raw_guards) is not list or not raw_guards:
        raise ProfileError("profile_code_guards_missing")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    total = 0
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_invalid")
        name = item.get("name")
        rva = _parse_profile_int(item.get("rva"), "code_guard.rva")
        end = _parse_profile_int(item.get("end_rva_exclusive"), "code_guard.end")
        raw_hex = item.get("bytes")
        digest = item.get("sha256")
        if (type(name) is not str or not name or name in names
                or type(raw_hex) is not str or not raw_hex or len(raw_hex) % 2
                or type(digest) is not str or len(digest) != 64):
            raise ProfileError("profile_code_guard_shape_invalid")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError("profile_code_guard_hex_invalid") from exc
        if not raw or len(raw) > MAX_SINGLE_READ or end != rva + len(raw):
            raise ProfileError(f"profile_code_guard_range_invalid:{name}")
        if hashlib.sha256(raw).hexdigest() != digest.lower():
            raise ProfileError(f"profile_code_guard_sha256_mismatch:{name}")
        total += len(raw)
        if total > MAX_TOTAL_READ:
            raise ProfileError("profile_code_guard_budget_exceeded")
        names.add(name)
        result.append({"name": name, "rva": rva, "end_rva_exclusive": end,
                       "bytes": raw, "sha256": digest.lower()})
    return result


def _validate_layout(profile: Mapping[str, Any]) -> dict[str, int]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    int_fields = (
        "manager_global_rva", "vector_begin_offset", "vector_end_offset", "vector_stride",
        "max_definitions", "definition_predicate_slot", "predicate_true_rva",
        "predicate_false_rva", "definition_key_offset", "string_size", "string_length_offset",
        "string_capacity_offset", "string_inline_capacity", "max_key_length",
        "definition_center_offset", "max_center", "game_global_rva", "province_base_offset",
        "province_stride", "province_runtime_offset", "node_definition_offset",
        "province_identity_id_offset", "node_local_value_offset", "node_outgoing_value_offset",
        "node_incoming_begin_offset", "node_incoming_end_offset", "incoming_entry_stride",
        "incoming_entry_value_offset", "max_incoming_entries", "node_ratio_pointer_offset",
        "node_outgoing_base_value_offset", "definition_routes_begin_offset",
        "definition_routes_end_offset", "route_stride", "route_definition_pointer_offset",
        "max_routes", "route_ratio_width", "route_amount_scale", "max_single_read_bytes",
        "max_total_read_bytes", "max_read_calls", "wrap_bits",
    )
    try:
        layout = {name: _parse_profile_int(raw[name], f"layout.{name}") for name in int_fields}
        signed = raw["signed"]
    except (KeyError, TypeError) as exc:
        raise ProfileError(f"profile_layout_invalid:{type(exc).__name__}") from exc
    expected = {
        "manager_global_rva": 0x242BE28, "vector_begin_offset": 0, "vector_end_offset": 8,
        "vector_stride": 8, "max_definitions": 1024, "definition_predicate_slot": 0x40,
        "predicate_true_rva": 0x8F440, "predicate_false_rva": 0x8F450,
        "definition_key_offset": 0x10, "string_size": 32, "string_length_offset": 0x10,
        "string_capacity_offset": 0x18, "string_inline_capacity": 16, "max_key_length": 128,
        "definition_center_offset": 0xDC, "max_center": 32767, "game_global_rva": 0x233FE58,
        "province_base_offset": 0x1CA8, "province_stride": 0x2E10,
        "province_runtime_offset": 0xE8, "node_definition_offset": 0xA8,
        "province_identity_id_offset": 0x20, "node_local_value_offset": 0xB4,
        "node_outgoing_value_offset": 0xBC, "node_incoming_begin_offset": 0xF0,
        "node_incoming_end_offset": 0xF8, "incoming_entry_stride": 32,
        "incoming_entry_value_offset": 0x10, "max_incoming_entries": 64,
        "node_ratio_pointer_offset": 0x88, "node_outgoing_base_value_offset": 0xC0,
        "definition_routes_begin_offset": 0x98, "definition_routes_end_offset": 0xA0,
        "route_stride": 0x78, "route_definition_pointer_offset": 0x30,
        "max_routes": 32, "route_ratio_width": 4, "route_amount_scale": 1000,
        "max_single_read_bytes": MAX_SINGLE_READ, "max_total_read_bytes": MAX_TOTAL_READ,
        "max_read_calls": MAX_READ_CALLS, "wrap_bits": 32,
    }
    if layout != expected or signed is not True:
        raise ProfileError("profile_layout_contract_mismatch")
    return layout


def _validate_source_index(profile: Mapping[str, Any]) -> dict[str, Any]:
    source = profile.get("source_index")
    if not isinstance(source, Mapping):
        raise ProfileError("source_index_missing")
    source_id = source.get("source_index_id")
    expected_hash = source.get("sha256")
    path_value = source.get("path")
    if (type(source_id) is not str or not source_id
            or type(expected_hash) is not str or len(expected_hash) != 64
            or type(path_value) is not str or not path_value):
        raise ProfileError("source_index_binding_invalid")
    source_path = Path(path_value)
    resolved = source_path.resolve() if source_path.is_absolute() else (_workspace_root() / source_path).resolve()
    root = _workspace_root()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("source_index_outside_workspace")
    raw = _bounded_read(resolved, SOURCE_INDEX_MAX_BYTES, "source_index")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != expected_hash.lower():
        raise ProfileError("source_index_sha256_mismatch")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError("source_index_json_invalid") from exc
    target = document.get("target") if isinstance(document, dict) else None
    if (not isinstance(document, dict) or not isinstance(target, Mapping)
            or document.get("schema") != "information.trade_value_memory.source_index.v1"
            or document.get("source_index_id") != source_id
            or document.get("profile_id") != profile.get("profile_id")
            or target.get("exe_sha256") != EXPECTED_EXE_SHA256):
        raise ProfileError("source_index_contract_mismatch")
    inputs = document.get("inputs")
    if type(inputs) is not list or not inputs:
        raise ProfileError("source_index_inputs_missing")
    for item in inputs:
        if (not isinstance(item, Mapping) or type(item.get("path")) is not str
                or type(item.get("bytes")) is not int or item["bytes"] <= 0
                or type(item.get("sha256")) is not str or len(item["sha256"]) != 64):
            raise ProfileError("source_index_input_shape_invalid")
    return {"path": str(resolved), "source_index_id": source_id,
            "sha256": actual_hash, "bytes": len(raw), "document": document}


def _validate_profile(profile: Any) -> dict[str, Any]:
    if not isinstance(profile, dict):
        raise ProfileError("profile_json_shape_invalid")
    if (profile.get("profile_id") != "trade-value-memory-1374"
            or profile.get("profile_version") != 1
            or profile.get("game_version") != EXPECTED_VERSION
            or profile.get("observer") != "FRA"):
        raise ProfileError("profile_identity_mismatch")
    executable = profile.get("executable")
    if (not isinstance(executable, Mapping)
            or executable.get("sha256") != EXPECTED_EXE_SHA256
            or executable.get("image_base_va") != hex(EXPECTED_BASE)):
        raise ProfileError("profile_executable_mismatch")
    semantics = profile.get("semantics")
    if (not isinstance(semantics, Mapping) or semantics.get("basis") != BASIS
            or semantics.get("unit") != UNIT or semantics.get("scale") != SCALE
            or semantics.get("period") != PERIOD
            or semantics.get("collected_value") != "unknown; not derived from country income or retention power"):
        raise ProfileError("profile_semantics_mismatch")
    _validate_layout(profile)
    _profile_code_guards(profile)
    source = _validate_source_index(profile)
    result = dict(profile)
    result["_validated_source_index"] = source
    return result


def load_profile(path: Path | None = None, expected_sha256: str | None = None) -> dict[str, Any]:
    """Load and strictly validate the fixed profile and source-index digest."""
    selected = PROFILE_FILE if path is None else Path(path)
    expected = EXPECTED_PROFILE_SHA256 if expected_sha256 is None else expected_sha256
    if type(expected) is not str or len(expected) != 64 or expected == "pending-profile":
        raise ProfileError("profile_sha256_pending_or_invalid")
    raw = _bounded_read(selected, PROFILE_MAX_BYTES, "profile")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError("profile_json_invalid") from exc
    return _validate_profile(parsed)


def code_guards() -> list[dict[str, str]]:
    """Return verified expected code windows in the composite-loader shape."""
    profile = load_profile()
    result = []
    for item in _profile_code_guards(profile):
        result.append({"name": item["name"], "rva": hex(item["rva"]),
                       "end_rva_exclusive": hex(item["end_rva_exclusive"]),
                       "bytes": item["bytes"].hex(), "sha256": item["sha256"]})
    return result


def _wrap_i32(value: int) -> int:
    value &= INT32_MODULUS - 1
    return value - INT32_MODULUS if value >= INT32_SIGN else value


def _i32(raw: bytes) -> int:
    if len(raw) != I32_WIDTH:
        raise ReadError("i32_width_mismatch")
    return int.from_bytes(raw, "little", signed=True)


def _qword(raw: bytes) -> int:
    if len(raw) != QWORD_WIDTH:
        raise ReadError("qword_width_mismatch")
    return int.from_bytes(raw, "little", signed=False)


class _Budget:
    def __init__(self, reader: Any, layout: Mapping[str, int]):
        self.reader = reader
        self.layout = layout
        self.calls = 0
        self.bytes_requested = 0
        self.read_log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if type(label) is not str or not label or len(label) > 160:
            raise ReadError("read_label_invalid")
        _address_range(address, size, label)
        if size > self.layout["max_single_read_bytes"]:
            raise ReadError(f"single_read_limit_exceeded:{label}")
        if self.calls + 1 > self.layout["max_read_calls"]:
            raise ReadError("read_call_budget_exceeded")
        if self.bytes_requested + size > self.layout["max_total_read_bytes"]:
            raise ReadError("read_byte_budget_exceeded")
        record = {"address": hex(address), "size": size, "label": label,
                  "status": "attempted", "raw_hex": None}
        self.read_log.append(record)
        self.calls += 1
        self.bytes_requested += size
        method = getattr(self.reader, "read", None)
        if not callable(method):
            record["status"] = "reader_missing"
            raise ReadError("reader_read_method_missing")
        try:
            raw = method(address, size, label)
        except Exception as exc:
            record["status"] = "read_failed"
            record["error_type"] = type(exc).__name__
            raise ReadError(f"read_failed:{label}:{type(exc).__name__}") from exc
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
            record["status"] = "short_or_invalid_read"
            record["returned_bytes"] = len(raw) if isinstance(raw, (bytes, bytearray)) else None
            raise ReadError(f"short_or_invalid_read:{label}")
        data = bytes(raw)
        record["status"] = "read"
        record["raw_hex"] = data.hex()
        return data


def _read_qword(ctx: _Budget, address: int, label: str, *, alignment: int = 8) -> tuple[int, bytes]:
    if not _valid_address(address, alignment=alignment):
        raise ReadError(f"pointer_field_address_invalid:{label}")
    raw = ctx.read(address, QWORD_WIDTH, label)
    return _qword(raw), raw


def _read_i32(ctx: _Budget, address: int, label: str) -> tuple[int, bytes]:
    if not _valid_address(address, alignment=4):
        raise ReadError(f"i32_field_address_invalid:{label}")
    raw = ctx.read(address, I32_WIDTH, label)
    return _i32(raw), raw


def _user_pointer(value: int, label: str, *, alignment: int = 8) -> int:
    if not _valid_address(value, alignment=alignment):
        raise ReadError(f"pointer_invalid:{label}")
    return value


def _parse_node_key(ctx: _Budget, definition: int, header: bytes, layout: Mapping[str, int], index: int) -> tuple[str, dict[str, Any]]:
    key_obj = header[layout["definition_key_offset"]:layout["definition_key_offset"] + layout["string_size"]]
    if len(key_obj) != layout["string_size"]:
        raise ReadError(f"node_key_object_truncated:{index}")
    length_start = layout["string_length_offset"]
    capacity_start = layout["string_capacity_offset"]
    length = int.from_bytes(key_obj[length_start:length_start + 8], "little", signed=False)
    capacity = int.from_bytes(key_obj[capacity_start:capacity_start + 8], "little", signed=False)
    if length < 1 or length > layout["max_key_length"] or capacity < length:
        raise ReadError(f"node_key_length_invalid:{index}")
    if capacity < layout["string_inline_capacity"]:
        if length + 1 > layout["string_inline_capacity"]:
            raise ReadError(f"node_key_inline_length_invalid:{index}")
        payload = key_obj[:length + 1]
        storage = "inline"
    else:
        pointer = _user_pointer(_qword(key_obj[:8]), f"node[{index}].key_pointer", alignment=1)
        payload = ctx.read(pointer, length + 1, f"node[{index}].key_payload")
        storage = "heap"
    if (len(payload) != length + 1 or payload[length] != 0 or 0 in payload[:length]
            or any(byte < 0x21 or byte >= 0x7F for byte in payload[:length])):
        raise ReadError(f"node_key_bytes_invalid:{index}")
    key = payload[:length].decode("ascii")
    if NODE_ID_RE.fullmatch(key) is None:
        raise ReadError(f"node_key_syntax_invalid:{index}")
    return key, {"definition_pointer": hex(definition), "key_object_raw_hex": key_obj.hex(),
                 "key_payload_raw_hex": payload.hex(), "key_length": length,
                 "key_capacity": capacity, "storage": storage}


def _code_guard(ctx: _Budget, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "checks": [], "reason": None}
    try:
        for item in _profile_code_guards(profile):
            address = _address_add(module_base, item["rva"], f"code_guard.{item['name']}")
            actual = ctx.read(address, len(item["bytes"]), f"trade_value.code.{item['name']}")
            result["checks"].append({"name": item["name"], "rva": hex(item["rva"]),
                                     "address": hex(address), "expected_sha256": item["sha256"],
                                     "actual_sha256": hashlib.sha256(actual).hexdigest(),
                                     "matched": actual == item["bytes"]})
        result["status"] = "observed" if all(item["matched"] for item in result["checks"]) else "mismatch"
        if result["status"] != "observed":
            result["reason"] = "runtime_code_guard_mismatch"
    except Exception as exc:
        result["status"] = "unknown"
        result["reason"] = f"runtime_code_guard_failed:{type(exc).__name__}:{exc}"
    return result


def _resolve_identity(ctx: _Budget, module_base: int, node_id: str, profile: Mapping[str, Any]) -> dict[str, Any]:
    layout = _validate_layout(profile)
    if not _valid_address(module_base, alignment=8):
        raise ReadError("module_base_invalid")
    identity_read_start = len(ctx.read_log)
    code_guard = _code_guard(ctx, module_base, profile)
    if code_guard.get("status") != "observed":
        raise ReadError("runtime_code_guard_failed")

    manager_global_address = _address_add(module_base, layout["manager_global_rva"], "manager.global")
    manager, manager_raw = _read_qword(ctx, manager_global_address, "trade_value.manager_global")
    manager = _user_pointer(manager, "manager")
    begin, begin_raw = _read_qword(ctx, _address_add(manager, layout["vector_begin_offset"], "manager.begin"), "trade_value.manager.begin")
    end, end_raw = _read_qword(ctx, _address_add(manager, layout["vector_end_offset"], "manager.end"), "trade_value.manager.end")
    if (not _valid_address(begin, alignment=8) or not _valid_address(end, alignment=8)
            or end <= begin or end > MAX_USER_ADDRESS_EXCLUSIVE):
        raise ReadError("manager_definition_vector_bounds_invalid")
    distance = end - begin
    stride = layout["vector_stride"]
    if distance % stride:
        raise ReadError("manager_definition_vector_misaligned")
    count = distance // stride
    if not 1 <= count <= layout["max_definitions"]:
        raise ReadError("manager_definition_count_out_of_bounds")
    graph_chunks: list[bytes] = []
    for first in range(0, count, MAX_SINGLE_READ // stride):
        entries = min(MAX_SINGLE_READ // stride, count - first)
        graph_chunks.append(ctx.read(begin + first * stride, entries * stride,
                                     f"trade_value.manager.definitions[{first}:{first + entries}]"))
    graph_raw = b"".join(graph_chunks)
    if len(graph_raw) != distance:
        raise ReadError("manager_definition_vector_short")

    predicate_by_vtable: dict[int, tuple[int, bytes]] = {}
    nodes_by_key: dict[str, dict[str, Any]] = {}
    nodes_by_definition: dict[int, tuple[str, int]] = {}
    scanned: list[dict[str, Any]] = []
    for index in range(count):
        graph_entry = graph_raw[index * stride:(index + 1) * stride]
        definition = _user_pointer(_qword(graph_entry), f"definition[{index}]")
        header = ctx.read(definition, 0x30, f"trade_value.definition_header[{index}]")
        vtable = _user_pointer(_qword(header[:8]), f"definition[{index}].vtable")
        cached_predicate = predicate_by_vtable.get(vtable)
        if cached_predicate is None:
            method, method_raw = _read_qword(
                ctx,
                _address_add(vtable, layout["definition_predicate_slot"], f"vtable[{index}].predicate"),
                f"trade_value.definition_predicate[{index}]",
            )
            predicate_by_vtable[vtable] = (method, method_raw)
        else:
            method, method_raw = cached_predicate
        method_rva = method - module_base
        if method_rva == layout["predicate_false_rva"]:
            scanned.append({"index": index, "graph_entry_raw_hex": graph_entry.hex(),
                            "definition_pointer": hex(definition), "vtable_pointer": hex(vtable),
                            "predicate_pointer": hex(method), "predicate_raw_hex": method_raw.hex(),
                            "placeholder": True})
            continue
        if method_rva != layout["predicate_true_rva"]:
            raise ReadError(f"definition_predicate_unrecognized:{index}")
        key, key_evidence = _parse_node_key(ctx, definition, header, layout, index)
        center, center_raw = _read_i32(
            ctx, _address_add(definition, layout["definition_center_offset"], f"definition[{index}].center"),
            f"trade_value.definition_center[{index}]",
        )
        if not 1 <= center <= layout["max_center"]:
            raise ReadError(f"definition_center_invalid:{index}")
        if key in nodes_by_key:
            raise ReadError(f"duplicate_definition_key:{key}")
        entry = {"index": index, "node_id": key, "center_province_id": center,
                 "center_raw_hex": center_raw.hex(), "graph_entry_raw_hex": graph_entry.hex(),
                 "definition_pointer": hex(definition), "definition_header_raw_hex": header.hex(),
                 "vtable_pointer": hex(vtable), "predicate_pointer": hex(method),
                 "predicate_raw_hex": method_raw.hex(), "predicate_rva": hex(method_rva),
                 "key": key_evidence, "placeholder": False}
        nodes_by_key[key] = entry
        nodes_by_definition[definition] = (key, center)
        scanned.append(entry)
    selected = nodes_by_key.get(node_id)
    if selected is None:
        raise ReadError("requested_node_id_not_in_manager")

    game_global_address = _address_add(module_base, layout["game_global_rva"], "game.global")
    game, game_raw = _read_qword(ctx, game_global_address, "trade_value.game_global")
    game = _user_pointer(game, "game")
    province_base_address = _address_add(game, layout["province_base_offset"], "game.province_base")
    province_base, province_base_raw = _read_qword(ctx, province_base_address, "trade_value.province_base")
    province_base = _user_pointer(province_base, "province_base")
    center = selected["center_province_id"]
    province_offset = center * layout["province_stride"]
    if province_offset > MAX_USER_ADDRESS_EXCLUSIVE:
        raise ReadError("center_province_offset_overflow")
    runtime_province = _address_add(province_base, province_offset, "selected.runtime_province")
    runtime_field_address = _address_add(runtime_province, layout["province_runtime_offset"], "selected.runtime_field")
    runtime, runtime_raw = _read_qword(ctx, runtime_field_address, "trade_value.selected_runtime_pointer")
    runtime = _user_pointer(runtime, "selected_runtime")
    definition_field_address = _address_add(runtime, layout["node_definition_offset"], "selected.runtime_definition_field")
    runtime_definition, runtime_definition_raw = _read_qword(ctx, definition_field_address, "trade_value.selected_runtime_definition")
    if runtime_definition != int(selected["definition_pointer"], 0):
        raise ReadError("selected_runtime_definition_mismatch")

    identity_reads = deepcopy(ctx.read_log[identity_read_start:])
    trace = {
        "module_base": hex(module_base), "requested_node_id": node_id,
        "runtime_code_guard": code_guard,
        "manager_global_address": hex(manager_global_address), "manager_pointer": hex(manager),
        "manager_pointer_raw_hex": manager_raw.hex(), "definitions_begin": hex(begin),
        "definitions_begin_raw_hex": begin_raw.hex(), "definitions_end": hex(end),
        "definitions_end_raw_hex": end_raw.hex(), "definition_count": count,
        "definition_vector_raw_hex": graph_raw.hex(), "definitions": scanned,
        "selected_definition": deepcopy(selected), "game_global_address": hex(game_global_address),
        "game_pointer": hex(game), "game_raw_hex": game_raw.hex(),
        "province_base_address": hex(province_base_address), "province_base_pointer": hex(province_base),
        "province_base_raw_hex": province_base_raw.hex(), "selected_center_province_id": center,
        "runtime_province_pointer": hex(runtime_province),
        "runtime_pointer_field_address": hex(runtime_field_address),
        "runtime_pointer": hex(runtime), "runtime_pointer_raw_hex": runtime_raw.hex(),
        "runtime_definition_field_address": hex(definition_field_address),
        "runtime_definition_pointer": hex(runtime_definition),
        "runtime_definition_raw_hex": runtime_definition_raw.hex(),
        "ordered_reads": identity_reads,
        "read_budget": {"calls": sum(1 for x in identity_reads if x["status"] in ("read", "short_or_invalid_read", "read_failed")),
                        "bytes_requested": sum(x["size"] for x in identity_reads),
                        "max_single_read_bytes": MAX_SINGLE_READ,
                        "max_total_read_bytes": MAX_TOTAL_READ,
                        "max_read_calls": MAX_READ_CALLS},
    }
    return {"layout": layout, "node_id": node_id, "center_province_id": center,
            "definition_pointer": int(selected["definition_pointer"], 0),
            "runtime_pointer": runtime, "province_base_pointer": province_base,
            "nodes_by_definition": nodes_by_definition, "identity": trace}


def _parse_binding(province_binding: Any, identity: Mapping[str, Any], ctx: _Budget,
                   layout: Mapping[str, int]) -> dict[str, Any]:
    if not isinstance(province_binding, Mapping):
        raise ReadError("province_binding_invalid")
    province_id = province_binding.get("province_id")
    record_id = province_binding.get("record_id")
    record_pointer_value = province_binding.get("record_pointer")
    id_address_value = province_binding.get("id_address")
    id_raw_hex = province_binding.get("id_raw_hex")
    if (type(province_id) is not int or province_id <= 0 or type(record_id) is not int
            or type(record_pointer_value) is not str or type(id_address_value) is not str
            or type(id_raw_hex) is not str or len(id_raw_hex) != 8):
        raise ReadError("province_binding_shape_invalid")
    try:
        record_pointer = int(record_pointer_value, 0)
        id_address = int(id_address_value, 0)
        id_bytes = bytes.fromhex(id_raw_hex)
    except (ValueError, TypeError) as exc:
        raise ReadError("province_binding_encoding_invalid") from exc
    if (not _valid_address(record_pointer, alignment=8)
            or record_pointer != _address_add(
                identity["province_base_pointer"],
                identity["center_province_id"] * layout["province_stride"],
                "binding.province_record_expected",
            )
            or id_address != _address_add(record_pointer, layout["province_identity_id_offset"], "binding.id_address")
            or len(id_bytes) != I32_WIDTH or _i32(id_bytes) != province_id
            or record_id != province_id or province_id != identity["center_province_id"]):
        raise ReadError("province_binding_center_mismatch")
    actual_id = ctx.read(id_address, I32_WIDTH, "trade_value.province_binding.id")
    if actual_id != id_bytes or _i32(actual_id) != province_id:
        raise ReadError("province_binding_id_read_mismatch")
    return {"province_id": province_id, "record_id": record_id,
            "record_pointer": hex(record_pointer), "id_address": hex(id_address),
            "id_raw_hex": id_raw_hex.lower(), "actual_id_raw_hex": actual_id.hex(),
            "center_province_id": identity["center_province_id"],
            "matched": True}


def _vector_header(ctx: _Budget, object_pointer: int, begin_offset: int, end_offset: int,
                   stride: int, max_count: int, label: str) -> tuple[int, int, int, dict[str, Any]]:
    begin_address = _address_add(object_pointer, begin_offset, f"{label}.begin_address")
    end_address = _address_add(object_pointer, end_offset, f"{label}.end_address")
    begin, begin_raw = _read_qword(ctx, begin_address, f"{label}.begin")
    end, end_raw = _read_qword(ctx, end_address, f"{label}.end")
    if begin == 0 and end == 0:
        return 0, 0, 0, {"begin_address": hex(begin_address), "begin_raw_hex": begin_raw.hex(),
                         "begin": hex(begin), "end_address": hex(end_address),
                         "end_raw_hex": end_raw.hex(), "end": hex(end), "count": 0,
                         "stride": stride, "empty": True}
    if (not _valid_address(begin, alignment=8) or not _valid_address(end, alignment=8)
            or end < begin or end > MAX_USER_ADDRESS_EXCLUSIVE):
        raise ReadError(f"{label}_vector_bounds_invalid")
    distance = end - begin
    if distance % stride:
        raise ReadError(f"{label}_vector_stride_mismatch")
    count = distance // stride
    if count > max_count:
        raise ReadError(f"{label}_vector_count_out_of_bounds")
    return begin, end, count, {"begin_address": hex(begin_address), "begin_raw_hex": begin_raw.hex(),
                              "begin": hex(begin), "end_address": hex(end_address),
                              "end_raw_hex": end_raw.hex(), "end": hex(end),
                              "count": count, "stride": stride, "empty": count == 0}


def _read_incoming(ctx: _Budget, runtime: int, layout: Mapping[str, int]) -> tuple[int, dict[str, Any]]:
    begin, end, count, header = _vector_header(
        ctx, runtime, layout["node_incoming_begin_offset"], layout["node_incoming_end_offset"],
        layout["incoming_entry_stride"], layout["max_incoming_entries"], "incoming")
    entries: list[dict[str, Any]] = []
    total = 0
    per_chunk = MAX_SINGLE_READ // layout["incoming_entry_stride"]
    for first in range(0, count, per_chunk):
        chunk_count = min(per_chunk, count - first)
        chunk = ctx.read(begin + first * layout["incoming_entry_stride"],
                         chunk_count * layout["incoming_entry_stride"],
                         f"trade_value.incoming_entries[{first}:{first + chunk_count}]")
        for local_index in range(chunk_count):
            item = chunk[local_index * layout["incoming_entry_stride"]:(local_index + 1) * layout["incoming_entry_stride"]]
            raw_value = item[layout["incoming_entry_value_offset"]:layout["incoming_entry_value_offset"] + I32_WIDTH]
            if len(raw_value) != I32_WIDTH:
                raise ReadError("incoming_value_offset_out_of_bounds")
            value = _i32(raw_value)
            total = _wrap_i32(total + value)
            entries.append({"index": first + local_index, "entry_raw_hex": item.hex(),
                            "value_raw_hex": raw_value.hex(), "value_i32": value,
                            "sum_after_i32": total})
    return total, {"vector": header, "entries": entries, "sum_i32": total,
                   "wrap_bits": 32, "entry_reads": deepcopy(ctx.read_log[-((count + per_chunk - 1) // per_chunk):]) if count else []}


def _read_local(ctx: _Budget, runtime: int, layout: Mapping[str, int]) -> tuple[int, dict[str, Any]]:
    address = _address_add(runtime, layout["node_local_value_offset"], "local_value")
    value, raw = _read_i32(ctx, address, "trade_value.node.local_value_i32")
    return value, {"address": hex(address), "raw_hex": raw.hex(), "value_i32": value}


def _read_outgoing_scalar(ctx: _Budget, runtime: int, layout: Mapping[str, int]) -> tuple[int, dict[str, Any]]:
    address = _address_add(runtime, layout["node_outgoing_value_offset"], "outgoing_value")
    value, raw = _read_i32(ctx, address, "trade_value.node.outgoing_value_i32")
    return value, {"address": hex(address), "raw_hex": raw.hex(), "value_i32": value}


def _trunc_div(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ReadError("route_scale_invalid")
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def _read_outgoing_routes(ctx: _Budget, identity: Mapping[str, Any], profile_layout: Mapping[str, int],
                          outgoing_total: int) -> tuple[dict[str, Any], dict[str, Any]]:
    definition = identity["definition_pointer"]
    runtime = identity["runtime_pointer"]
    begin, end, count, vector = _vector_header(
        ctx, definition, profile_layout["definition_routes_begin_offset"],
        profile_layout["definition_routes_end_offset"], profile_layout["route_stride"],
        profile_layout["max_routes"], "outgoing_routes")
    route_records: list[dict[str, Any]] = []
    per_chunk = MAX_SINGLE_READ // profile_layout["route_stride"]
    for first in range(0, count, per_chunk):
        chunk_count = min(per_chunk, count - first)
        chunk = ctx.read(begin + first * profile_layout["route_stride"],
                         chunk_count * profile_layout["route_stride"],
                         f"trade_value.outgoing_routes[{first}:{first + chunk_count}]")
        for local_index in range(chunk_count):
            raw = chunk[local_index * profile_layout["route_stride"]:(local_index + 1) * profile_layout["route_stride"]]
            pointer_offset = profile_layout["route_definition_pointer_offset"]
            definition_raw = raw[pointer_offset:pointer_offset + QWORD_WIDTH]
            if len(definition_raw) != QWORD_WIDTH:
                raise ReadError("outgoing_route_definition_pointer_truncated")
            route_records.append({"index": first + local_index, "raw_hex": raw.hex(),
                                 "definition_pointer_raw_hex": definition_raw.hex(),
                                 "definition_pointer": _qword(definition_raw)})
    nodes_by_definition = identity["nodes_by_definition"]
    destinations: list[dict[str, Any]] = []
    for route in route_records:
        destination_definition = _user_pointer(route["definition_pointer"],
                                              f"outgoing_route[{route['index']}].definition")
        destination = nodes_by_definition.get(destination_definition)
        if destination is None:
            raise ReadError(f"outgoing_route_definition_not_in_manager:{route['index']}")
        destination_node_id, destination_center = destination
        province_address = _address_add(
            identity["province_base_pointer"], destination_center * profile_layout["province_stride"],
            f"outgoing_route[{route['index']}].province",
        )
        runtime_address = _address_add(province_address, profile_layout["province_runtime_offset"],
                                       f"outgoing_route[{route['index']}].runtime_field")
        target_runtime, target_runtime_raw = _read_qword(ctx, runtime_address,
                                                         f"trade_value.outgoing_route_runtime[{route['index']}]")
        target_runtime = _user_pointer(target_runtime, f"outgoing_route[{route['index']}].runtime")
        target_definition_address = _address_add(target_runtime, profile_layout["node_definition_offset"],
                                                 f"outgoing_route[{route['index']}].definition_field")
        target_definition, target_definition_raw = _read_qword(
            ctx, target_definition_address, f"trade_value.outgoing_route_definition[{route['index']}]")
        if target_definition != destination_definition:
            raise ReadError(f"outgoing_route_runtime_definition_mismatch:{route['index']}")
        destinations.append({"index": route["index"], "node_id": destination_node_id,
                             "destination_center": destination_center,
                             "definition_pointer": hex(destination_definition),
                             "runtime_pointer": hex(target_runtime),
                             "runtime_pointer_raw_hex": target_runtime_raw.hex(),
                             "runtime_definition_raw_hex": target_definition_raw.hex(),
                             "route_raw_hex": route["raw_hex"]})

    results: list[dict[str, Any]] = []
    if count:
        ratios_pointer_address = _address_add(runtime, profile_layout["node_ratio_pointer_offset"], "outgoing.ratios_pointer")
        ratios_pointer, ratios_pointer_raw = _read_qword(ctx, ratios_pointer_address,
                                                         "trade_value.outgoing_ratios_pointer")
        ratios_pointer = _user_pointer(ratios_pointer, "outgoing_ratios", alignment=4)
        ratio_bytes = ctx.read(ratios_pointer, count * profile_layout["route_ratio_width"],
                               "trade_value.outgoing_ratios_i32")
        if len(ratio_bytes) != count * profile_layout["route_ratio_width"]:
            raise ReadError("outgoing_ratio_array_short")
        base_address = _address_add(runtime, profile_layout["node_outgoing_base_value_offset"], "outgoing.base_value")
        base_value, base_raw = _read_i32(ctx, base_address, "trade_value.outgoing_base_value_i32")
        for index, destination in enumerate(destinations):
            ratio_raw = ratio_bytes[index * 4:(index + 1) * 4]
            ratio = _i32(ratio_raw)
            quotient = _trunc_div(ratio * base_value, profile_layout["route_amount_scale"])
            amount = _wrap_i32(quotient)
            results.append({"node_id": destination["node_id"],
                            "destination_center": destination["destination_center"],
                            "raw": amount})
            destination["ratio_index"] = index
            destination["ratio_raw_hex"] = ratio_raw.hex()
            destination["ratio_i32"] = ratio
            destination["amount_i32"] = amount
            destination["amount_unwrapped_quotient"] = quotient
    else:
        ratios_pointer_address = None
        ratios_pointer_raw = b""
        ratio_bytes = b""
        base_address = None
        base_value = None
        base_raw = b""
    value = {"total_raw": outgoing_total, "routes": results}
    evidence = {
        "route_vector": vector, "route_records": route_records,
        "validated_destinations": destinations,
        "ratio_pointer_address": hex(ratios_pointer_address) if ratios_pointer_address is not None else None,
        "ratio_pointer_raw_hex": ratios_pointer_raw.hex(),
        "ratio_array_raw_hex": ratio_bytes.hex(),
        "base_address": hex(base_address) if base_address is not None else None,
        "base_raw_hex": base_raw.hex(), "base_i32": base_value,
        "total_raw_i32": outgoing_total,
        "route_sum_is_required_to_match_total": False,
        "amount_formula": "wrap_i32(trunc_toward_zero(i64(ratio_i32)*i64(base_i32)/1000))",
    }
    return value, evidence


def _unknown(reason: str, raw_inputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "reason": reason}
    if isinstance(raw_inputs, Mapping):
        result["raw_inputs"] = deepcopy(dict(raw_inputs))
    return result


def _field_ids(fields: Any) -> tuple[str, ...] | None:
    if not isinstance(fields, (list, tuple)) or not 1 <= len(fields) <= 16:
        return None
    normalized: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if type(field) is not str or not field.isascii() or len(field) > 64 or field not in FIELDS or field in seen:
            return None
        seen.add(field)
        normalized.append(field)
    return tuple(normalized)


def _copy_reads(ctx: _Budget, start: int) -> tuple[list[dict[str, Any]], int, int]:
    records = deepcopy(ctx.read_log[start:])
    return records, len(records), sum(item["size"] for item in records)


def find_node(reader: Any, base: int, node_id: str) -> dict[str, Any]:
    """Resolve a requested manager node and its province-runtime identity only.

    No T03 numeric cache, vector, or route amount is read by this function.
    """
    if type(node_id) is not str or NODE_ID_RE.fullmatch(node_id) is None:
        return _unknown("REQUESTED_NODE_ID_INVALID")
    ctx: _Budget | None = None
    try:
        profile = load_profile()
        layout = _validate_layout(profile)
        if not _valid_address(base, alignment=8):
            raise ReadError("module_base_invalid")
        ctx = _Budget(reader, layout)
        identity = _resolve_identity(ctx, base, node_id, profile)
        return {
            "status": "known", "node_id": node_id,
            "center_province_id": identity["center_province_id"],
            "runtime_pointer": hex(identity["runtime_pointer"]),
            "definition_pointer": hex(identity["definition_pointer"]),
            "raw_inputs": {"profile_sha256": PROFILE_SHA256,
                           "identity": identity["identity"],
                           "read_budget": {"calls": ctx.calls, "bytes_requested": ctx.bytes_requested,
                                           "max_single_read_bytes": MAX_SINGLE_READ,
                                           "max_total_read_bytes": MAX_TOTAL_READ,
                                           "max_read_calls": MAX_READ_CALLS}},
        }
    except Exception as exc:
        return _unknown(f"NODE_IDENTITY_RESOLUTION_FAILED:{type(exc).__name__}:{exc}",
                        {"profile_sha256": PROFILE_SHA256,
                         "ordered_reads": deepcopy(ctx.read_log) if ctx is not None else [],
                         "read_budget": {"calls": ctx.calls, "bytes_requested": ctx.bytes_requested}
                         if ctx is not None else None})


def read_fields(reader: Any, base: int, province_binding: Mapping[str, Any], fields: Any,
                *, node_id: str) -> dict[str, Any]:
    """Read only requested selected-node values after the outer G02 admission.

    The parent must positively establish non-player FRA and the center
    province's discovery bit before calling this function. Unknown fields are
    fail-closed and never carry a consumable value.
    """
    requested = _field_ids(fields)
    if requested is None:
        if isinstance(fields, (list, tuple)):
            return {field: _unknown("FIELD_REQUEST_INVALID") for field in fields if type(field) is str}
        return {}
    output: dict[str, Any] = {}
    collected_requested = "T03.collected_value" in requested
    supported = tuple(field for field in requested if field in VALUE_FIELDS)
    if not supported:
        for field in requested:
            output[field] = _unknown(COLLECTED_UNKNOWN if field == "T03.collected_value" else "UNSUPPORTED_FIELD")
        return output
    if type(node_id) is not str or NODE_ID_RE.fullmatch(node_id) is None:
        for field in requested:
            output[field] = _unknown("REQUESTED_NODE_ID_INVALID")
        return output

    ctx: _Budget | None = None
    try:
        profile = load_profile()
        layout = _validate_layout(profile)
        if not _valid_address(base, alignment=8):
            raise ReadError("module_base_invalid")
        ctx = _Budget(reader, layout)
        identity = _resolve_identity(ctx, base, node_id, profile)
        identity_log = deepcopy(identity["identity"]["ordered_reads"])
        identity_calls = len(identity_log)
        identity_bytes = sum(item["size"] for item in identity_log)
        binding_start = len(ctx.read_log)
        binding_evidence = _parse_binding(province_binding, identity, ctx, layout)
        binding_reads, binding_calls, binding_bytes = _copy_reads(ctx, binding_start)
    except Exception as exc:
        reason = f"NODE_OR_PROVINCE_BINDING_UNKNOWN:{type(exc).__name__}:{exc}"
        raw = {"profile_sha256": PROFILE_SHA256,
               "ordered_reads": deepcopy(ctx.read_log) if ctx is not None else [],
               "read_budget": {"calls": ctx.calls, "bytes_requested": ctx.bytes_requested}
               if ctx is not None else None}
        for field in requested:
            output[field] = _unknown(COLLECTED_UNKNOWN if field == "T03.collected_value" else reason, raw)
        return output

    operation: dict[str, dict[str, Any]] = {}

    def run_operation(name: str, function: Any) -> None:
        start = len(ctx.read_log)
        try:
            value, evidence = function()
            status, reason = "known", None
        except Exception as exc:
            value, evidence = None, {"failure_type": type(exc).__name__}
            status, reason = "unknown", f"{name.upper()}_READ_FAILED:{type(exc).__name__}:{exc}"
        reads, calls, byte_count = _copy_reads(ctx, start)
        operation[name] = {"status": status, "reason": reason, "value": value,
                           "evidence": evidence, "reads": reads,
                           "budget": {"calls": calls, "bytes_requested": byte_count}}

    runtime = identity["runtime_pointer"]
    if "T03.local_value" in supported or "T03.total_value" in supported:
        run_operation("local", lambda: _read_local(ctx, runtime, layout))
    if "T03.incoming_value" in supported or "T03.total_value" in supported:
        run_operation("incoming", lambda: _read_incoming(ctx, runtime, layout))
    if "T03.outgoing_value" in supported or "T03.total_value" in supported:
        run_operation("outgoing_scalar", lambda: _read_outgoing_scalar(ctx, runtime, layout))
    if "T03.outgoing_value" in supported:
        scalar = operation.get("outgoing_scalar", {})
        if scalar.get("status") == "known":
            run_operation("outgoing_routes", lambda: _read_outgoing_routes(
                ctx, identity, layout, scalar["value"]))
        else:
            operation["outgoing_routes"] = {
                "status": "unknown", "reason": "OUTGOING_TOTAL_UNAVAILABLE",
                "value": None, "evidence": {}, "reads": [],
                "budget": {"calls": 0, "bytes_requested": 0},
            }

    def raw_inputs_for(needed: tuple[str, ...]) -> dict[str, Any]:
        field_operations = {name: operation[name] for name in needed if name in operation}
        field_calls = sum(item["budget"]["calls"] for item in field_operations.values())
        field_bytes = sum(item["budget"]["bytes_requested"] for item in field_operations.values())
        return {
            "profile_sha256": PROFILE_SHA256,
            "request": {"node_id": node_id, "requested_fields": list(requested)},
            "identity": identity["identity"],
            "province_binding": binding_evidence,
            "province_binding_reads": binding_reads,
            "operations": field_operations,
            "read_budget": {
                "identity_calls": identity_calls, "identity_bytes_requested": identity_bytes,
                "binding_calls": binding_calls, "binding_bytes_requested": binding_bytes,
                "field_calls": field_calls, "field_bytes_requested": field_bytes,
                "operation_names": list(needed), "max_single_read_bytes": MAX_SINGLE_READ,
                "max_total_read_bytes": MAX_TOTAL_READ, "max_read_calls": MAX_READ_CALLS,
            },
        }

    if "T03.local_value" in supported:
        op = operation["local"]
        output["T03.local_value"] = (
            {"status": "known", "value": op["value"], "raw_inputs": raw_inputs_for(("local",)),
             "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD}
            if op["status"] == "known" else _unknown(op["reason"], raw_inputs_for(("local",)))
        )
    if "T03.incoming_value" in supported:
        op = operation["incoming"]
        output["T03.incoming_value"] = (
            {"status": "known", "value": op["value"], "raw_inputs": raw_inputs_for(("incoming",)),
             "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD}
            if op["status"] == "known" else _unknown(op["reason"], raw_inputs_for(("incoming",)))
        )
    if "T03.outgoing_value" in supported:
        scalar = operation["outgoing_scalar"]
        routes = operation["outgoing_routes"]
        needed = ("outgoing_scalar", "outgoing_routes")
        if scalar["status"] == "known" and routes["status"] == "known":
            output["T03.outgoing_value"] = {
                "status": "known", "value": routes["value"],
                "raw_inputs": raw_inputs_for(needed),
                "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD,
            }
        else:
            reason = routes.get("reason") if scalar["status"] == "known" else scalar.get("reason")
            output["T03.outgoing_value"] = _unknown(reason or "OUTGOING_ROUTE_EVIDENCE_UNKNOWN",
                                                      raw_inputs_for(needed))
    if "T03.total_value" in supported:
        needed = ("local", "incoming", "outgoing_scalar")
        local_op, incoming_op, outgoing_op = (operation[name] for name in needed)
        if all(item["status"] == "known" for item in (local_op, incoming_op, outgoing_op)):
            total = _wrap_i32(local_op["value"] + incoming_op["value"] - outgoing_op["value"])
            output["T03.total_value"] = {
                "status": "known", "value": total, "raw_inputs": raw_inputs_for(needed),
                "basis": BASIS, "unit": UNIT, "scale": SCALE, "period": PERIOD,
                "formula": "wrap_i32(local_i32+incoming_i32-outgoing_i32)",
            }
        else:
            failed = next((item for item in (local_op, incoming_op, outgoing_op)
                           if item["status"] != "known"), None)
            output["T03.total_value"] = _unknown(
                failed.get("reason", "TOTAL_INPUT_UNKNOWN") if isinstance(failed, Mapping) else "TOTAL_INPUT_UNKNOWN",
                raw_inputs_for(needed),
            )
    if collected_requested:
        output["T03.collected_value"] = _unknown(COLLECTED_UNKNOWN, raw_inputs_for(()))
    return {field: output[field] for field in requested}


__all__ = [
    "BASIS", "COLLECTED_UNKNOWN", "EXPECTED_EXE_SHA256", "EXPECTED_PROFILE_SHA256",
    "FIELDS", "PERIOD", "PROFILE_FILE", "PROFILE_SHA256", "SCALE", "UNIT",
    "ProfileError", "ReadError", "code_guards", "find_node", "load_profile", "read_fields",
]
