"""Derive country and total trade power from the guarded trade-node record.

The trade-income reader owns the complete runtime graph and the country
binding.  This child consumes that validated record, copies the five signed
entry components from each retained 0xC0 entry, and performs the UI's current
power arithmetic.  It reads only ``runtime + 0xc8`` for the total-power cache;
the graph is never walked a second time and no game function is called.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import trade_income_memory as _trade


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "trade-power-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_INDEX_MAX_BYTES = 128 * 1024
EXPECTED_PROFILE_SHA256 = "d695e2da142143b8b4b4097e6a093bba120537018dcbcd24e9ded3ff32ff5868"
EXPECTED_EXE_SHA256 = _trade.EXPECTED_EXE_SHA256
EXPECTED_VERSION = _trade.EXPECTED_VERSION
EXPECTED_COUNTRY = _trade.EXPECTED_COUNTRY
EXPECTED_TRADE_PROFILE_SHA256 = _trade.EXPECTED_PROFILE_SHA256

BASIS = "native_trade_node_power_caches"
UNIT = "trade_power"
SCALE = 1000
PERIOD = "current"
VALUE_ORIGIN = "derived_from_copied_native_caches"
NODE_VALUE_ORIGIN = "derived_from_copied_native_entry_caches"
TOTAL_VALUE_ORIGIN = "copied_native_cache"

RUNTIME_TOTAL_POWER_OFFSET = 0xC8
ENTRY_POWER_OFFSETS = (0x44, 0x48, 0x4C, 0x50, 0x54)
ENTRY_WIDTH = 0xC0
I32_WIDTH = 4
QWORD_WIDTH = 8


class ProfileError(RuntimeError):
    """The pinned trade-power profile or source index is unavailable."""


class ReadError(RuntimeError):
    """A bounded child read or field derivation failed."""


def _deepcopy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _canonical_digest(record: Mapping[str, Any]) -> str:
    raw = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


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
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"{label}_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > limit:
        raise ProfileError(f"{label}_read_size_changed")
    return raw


def _profile_layout(profile: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.get("layout")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_layout_missing")
    runtime_offset = _parse_int(raw.get("runtime_total_power_offset"), "layout.runtime_total_power_offset")
    offsets_raw = raw.get("entry_power_offsets")
    if isinstance(offsets_raw, Mapping):
        offsets = tuple(
            _parse_int(offsets_raw.get(hex(offset)), f"layout.entry_power_offsets.{hex(offset)}")
            for offset in ENTRY_POWER_OFFSETS
        )
    elif isinstance(offsets_raw, (list, tuple)):
        if len(offsets_raw) != len(ENTRY_POWER_OFFSETS):
            raise ProfileError("profile_entry_power_offsets_count_mismatch")
        offsets = tuple(_parse_int(value, f"layout.entry_power_offsets[{index}]") for index, value in enumerate(offsets_raw))
    else:
        raise ProfileError("profile_entry_power_offsets_missing")
    source_trade_profile_sha256 = raw.get("source_trade_profile_sha256")
    if runtime_offset != RUNTIME_TOTAL_POWER_OFFSET:
        raise ProfileError("profile_runtime_total_power_offset_mismatch")
    if offsets != ENTRY_POWER_OFFSETS:
        raise ProfileError("profile_entry_power_offsets_mismatch")
    if source_trade_profile_sha256 != EXPECTED_TRADE_PROFILE_SHA256:
        raise ProfileError("profile_source_trade_profile_sha256_mismatch")
    return {
        "runtime_total_power_offset": runtime_offset,
        "entry_power_offsets": offsets,
        "source_trade_profile_sha256": source_trade_profile_sha256,
    }


def _profile_semantics(profile: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.get("semantics")
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_semantics_missing")
    basis = raw.get("basis")
    unit = raw.get("unit")
    scale = raw.get("scale")
    period = raw.get("period")
    country_origin = raw.get("country_value_origin", raw.get("value_origin"))
    node_origin = raw.get("node_value_origin")
    total_origin = raw.get("total_value_origin", raw.get("total_origin"))
    if basis != BASIS or unit != UNIT or scale != SCALE or period != PERIOD:
        raise ProfileError("profile_semantics_mismatch")
    if country_origin != VALUE_ORIGIN or total_origin != TOTAL_VALUE_ORIGIN:
        raise ProfileError("profile_value_origin_mismatch")
    if node_origin is not None and node_origin != NODE_VALUE_ORIGIN:
        raise ProfileError("profile_node_value_origin_mismatch")
    return {
        "basis": basis,
        "unit": unit,
        "scale": scale,
        "period": period,
        "country_value_origin": country_origin,
        "node_value_origin": node_origin,
        "total_value_origin": total_origin,
    }


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
            raw_bytes = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        if not raw_bytes or len(raw_bytes) > _trade.MAX_SINGLE_READ:
            raise ProfileError(f"profile_code_guard_size_invalid:{name}")
        total += len(raw_bytes)
        if total > _trade.MAX_TOTAL_READ:
            raise ProfileError("profile_code_guards_budget_invalid")
        names.add(name)
        guards.append((name, rva, raw_bytes))
    return guards


def _source_index_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("profile_source_index_path_invalid")
    root = Path(__file__).resolve().parents[2]
    path = Path(raw_path)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if resolved != root and root not in resolved.parents:
        raise ProfileError("profile_source_index_path_escape")
    return resolved


def _validate_source_index(profile: Mapping[str, Any]) -> dict[str, Any]:
    source = profile.get("source_index")
    if not isinstance(source, Mapping):
        raise ProfileError("profile_source_index_missing")
    source_id = source.get("source_index_id")
    expected_sha = source.get("sha256")
    if not isinstance(source_id, str) or not source_id:
        raise ProfileError("profile_source_index_id_invalid")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        raise ProfileError("profile_source_index_sha256_invalid")
    path = _source_index_path(source.get("path"))
    raw = _bounded_bytes(path, SOURCE_INDEX_MAX_BYTES, "source_index")
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha.lower() != expected_sha.lower():
        raise ProfileError("profile_source_index_sha256_mismatch")
    return {"source_index_id": source_id, "path": str(path), "sha256": expected_sha.lower(), "bytes": len(raw)}


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "trade-power-memory-1374":
        raise ProfileError("profile_shape_invalid")
    if profile.get("game_version") != EXPECTED_VERSION:
        raise ProfileError("profile_version_mismatch")
    executable = profile.get("executable")
    if not isinstance(executable, Mapping) or str(executable.get("sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProfileError("profile_executable_mismatch")
    _profile_layout(profile)
    _profile_semantics(profile)
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
    profile = dict(profile)
    profile["_validated_source_index"] = _validate_source_index(profile)
    return profile


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    PROFILE = None


def _active_profile() -> dict[str, Any]:
    return _load_profile()


def _static_contract_guard(profile: Mapping[str, Any] | None = None, reason: str | None = None) -> dict[str, Any]:
    if not isinstance(profile, Mapping):
        return {"status": "unknown", "checks": {}, "unknown_conditions": [reason or "profile_unavailable"]}
    source = profile.get("_validated_source_index", profile.get("source_index", {}))
    source_ok = isinstance(source, Mapping) and all(
        isinstance(source.get(key), str) and bool(source.get(key))
        for key in ("source_index_id", "path", "sha256")
    )
    try:
        _profile_layout(profile)
        layout_ok = True
    except ProfileError:
        layout_ok = False
    try:
        _profile_code_guards(profile)
        guards_ok = True
    except ProfileError:
        guards_ok = False
    checks = {
        "profile_id": profile.get("profile_id") == "trade-power-memory-1374",
        "game_version": profile.get("game_version") == EXPECTED_VERSION,
        "executable_sha256": isinstance(profile.get("executable"), Mapping)
        and str(profile["executable"].get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
        "source_index": source_ok,
        "layout": layout_ok,
        "code_guards": guards_ok,
    }
    failed = [name for name, ok in checks.items() if ok is not True]
    unknown = ["profile_contract_failed:" + ",".join(failed)] if failed else []
    if reason:
        unknown.append(reason)
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
        "unknown_conditions": unknown,
    }


def _empty_record(
    reason: str,
    *,
    profile: Mapping[str, Any] | None = None,
    guard: Mapping[str, Any] | None = None,
    source: Mapping[str, Any] | None = None,
    source_digest: str | None = None,
    module_base: int | None = None,
) -> dict[str, Any]:
    source = source or {}
    return {
        "status": "unknown",
        "reason": reason,
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "static_contract_guard": _static_contract_guard(profile, reason if profile is None else None),
        "runtime_code_guard": _deepcopy(guard) if isinstance(guard, Mapping) else None,
        "module_base": _hex(module_base),
        "country_pointer": source.get("country_pointer"),
        "source_trade_record_canonical_sha256": source_digest,
        "country": source.get("country", EXPECTED_COUNTRY),
        "country_fullref_raw_hex": source.get("country_fullref_raw_hex"),
        "country_slot": source.get("country_slot"),
        "nodes": None,
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "node_value_origin": NODE_VALUE_ORIGIN,
        "total_value_origin": TOTAL_VALUE_ORIGIN,
        "read_budget": {"bytes_requested": 0, "calls": 0},
        "observation": {"status": "unknown", "reason": reason},
    }


def _runtime_code_guard(ctx: Any, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _hex(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        if not _trade._valid_address(module_base):
            raise ReadError("module_base_invalid")
        for name, rva, expected in _profile_code_guards(profile):
            address = _trade._address_add(module_base, rva, f"guard.{name}")
            actual = ctx.read(address, len(expected), f"trade_power.code.{name}")
            result["records"][name] = {
                "rva": _hex(rva),
                "address": _hex(address),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
                "expected_sha256": hashlib.sha256(expected).hexdigest(),
                "actual_sha256": hashlib.sha256(actual).hexdigest(),
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


def _valid_hex(raw: Any, width: int) -> bool:
    if not isinstance(raw, str) or len(raw) != width * 2:
        return False
    try:
        bytes.fromhex(raw)
    except ValueError:
        return False
    return True


def _i32_hex(value: int) -> str:
    return (value & 0xFFFFFFFF).to_bytes(I32_WIDTH, "little", signed=False).hex()


def _source_components(source_node: Mapping[str, Any], offsets: tuple[int, ...]) -> tuple[dict[str, int], str]:
    raw_hex = source_node.get("entry_raw_hex")
    if not _valid_hex(raw_hex, ENTRY_WIDTH):
        raise ReadError("trade_income_entry_raw_invalid")
    entry = bytes.fromhex(raw_hex)
    components: dict[str, int] = {}
    raw_parts: list[str] = []
    for offset in offsets:
        chunk = entry[offset:offset + I32_WIDTH]
        if len(chunk) != I32_WIDTH:
            raise ReadError(f"entry_power_component_out_of_bounds:{hex(offset)}")
        components[hex(offset)] = int.from_bytes(chunk, "little", signed=True)
        raw_parts.append(chunk.hex())
    return components, "".join(raw_parts)


def _trunc0_div(value: int, divisor: int) -> int:
    if value >= 0:
        return value // divisor
    return -((-value) // divisor)


def _country_power(components: Mapping[str, int]) -> int:
    product = components["0x44"] * components["0x4c"]
    quotient = _trunc0_div(product, 1000)
    # The native TEST/CMOVG sequence tests EDX after the quotient has been
    # narrowed to its low 32 bits.  A positive 64-bit quotient whose signed
    # low 32 bits are negative therefore takes the zero branch.
    quotient32 = _trade._wrap_i32(quotient)
    positive32 = quotient32 if quotient32 > 0 else 0
    cap = components["0x48"]
    capped = cap if cap < positive32 else positive32
    delta = _trade._wrap_i32(components["0x54"] - components["0x50"])
    return _trade._wrap_i32(capped + delta)


def _expected_runtime_guard(record: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    guard = record.get("runtime_code_guard")
    module_base = record.get("module_base")
    try:
        module = int(module_base, 0)
        expected_guards = _profile_code_guards(profile)
    except (TypeError, ValueError, ProfileError):
        return False
    if not _trade._valid_address(module) or not isinstance(guard, Mapping) or guard.get("status") != "observed":
        return False
    checks = guard.get("checks")
    records = guard.get("records")
    expected_names = {name for name, _rva, _raw in expected_guards}
    if (
        not isinstance(checks, Mapping)
        or set(checks) != expected_names
        or any(value is not True for value in checks.values())
        or not isinstance(records, Mapping)
        or set(records) != expected_names
    ):
        return False
    for name, rva, expected in expected_guards:
        item = records.get(name)
        if (
            not isinstance(item, Mapping)
            or item.get("rva") != _hex(rva)
            or item.get("address") != _hex(module + rva)
            or item.get("expected_hex") != expected.hex()
            or item.get("actual_hex") != expected.hex()
            or item.get("expected_sha256") != hashlib.sha256(expected).hexdigest()
            or item.get("actual_sha256") != hashlib.sha256(expected).hexdigest()
        ):
            return False
    return guard.get("module_base") == _hex(module) and guard.get("unknown_conditions") == []


def read_fields(reader: Any, module_base: int, trade_income_record: Any) -> dict[str, Any]:
    """Read power caches and derive country power from a validated trade record."""
    if not isinstance(trade_income_record, Mapping) or not _trade.validate_record(trade_income_record):
        return _empty_record("trade_income_record_invalid")
    source_digest = _canonical_digest(trade_income_record)
    source_module = _trade._pointer_from_hex(trade_income_record.get("module_base"))
    if not isinstance(module_base, int) or isinstance(module_base, bool) or source_module != module_base:
        return _empty_record(
            "module_base_source_mismatch",
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base if isinstance(module_base, int) else None,
        )
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
    except Exception as exc:
        return _empty_record(
            f"profile_unavailable:{type(exc).__name__}:{exc}",
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base,
        )
    static_guard = _static_contract_guard(profile)
    if static_guard.get("status") != "observed":
        return _empty_record(
            "static_contract_guard_failed",
            profile=profile,
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base,
        )
    ctx = _trade._Budget(reader)
    guard = _runtime_code_guard(ctx, module_base, profile)
    if guard.get("status") != "observed":
        result = _empty_record(
            "runtime_code_guard_failed",
            profile=profile,
            guard=guard,
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base,
        )
        result["read_budget"] = {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls}
        return result
    try:
        source_nodes = trade_income_record.get("nodes")
        if not isinstance(source_nodes, list) or not source_nodes:
            raise ReadError("trade_income_nodes_missing")
        nodes: list[dict[str, Any]] = []
        for index, source_node in enumerate(source_nodes):
            if not isinstance(source_node, Mapping):
                raise ReadError(f"trade_income_node_invalid:{index}")
            node_id = source_node.get("node_id")
            if not isinstance(node_id, str) or not node_id:
                raise ReadError(f"trade_income_node_id_invalid:{index}")
            runtime = _trade._pointer_from_hex(source_node.get("runtime_pointer"))
            if runtime is None:
                raise ReadError(f"runtime_pointer_invalid:{index}")
            runtime_address = _trade._address_add(
                runtime, layout["runtime_total_power_offset"], f"node[{index}].runtime_total_power"
            )
            runtime_raw = ctx.read(runtime_address, I32_WIDTH, f"trade_power.node[{index}].runtime_total_power")
            total_power = int.from_bytes(runtime_raw, "little", signed=True)
            components, components_hex = _source_components(source_node, layout["entry_power_offsets"])
            country_power = _country_power(components)
            nodes.append({
                "node_id": node_id,
                "runtime_pointer": _hex(runtime),
                "runtime_total_power_address": _hex(runtime_address),
                "total_power_raw": total_power,
                "total_power_raw_hex": runtime_raw.hex(),
                "country_power_raw": country_power,
                "country_power_raw_hex": _i32_hex(country_power),
                "entry_power_components_raw": components,
                "entry_power_components_raw_hex": components_hex,
                "value_origin": VALUE_ORIGIN,
                "node_value_origin": NODE_VALUE_ORIGIN,
                "total_value_origin": TOTAL_VALUE_ORIGIN,
            })
        return {
            "status": "observed",
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "static_contract_guard": static_guard,
            "runtime_code_guard": guard,
            "module_base": _hex(module_base),
            "country_pointer": trade_income_record.get("country_pointer"),
            "source_trade_record_canonical_sha256": source_digest,
            "country": trade_income_record.get("country"),
            "country_fullref_raw_hex": trade_income_record.get("country_fullref_raw_hex"),
            "country_slot": trade_income_record.get("country_slot"),
            "nodes": nodes,
            "basis": BASIS,
            "unit": UNIT,
            "scale": SCALE,
            "period": PERIOD,
            "value_origin": VALUE_ORIGIN,
            "node_value_origin": NODE_VALUE_ORIGIN,
            "total_value_origin": TOTAL_VALUE_ORIGIN,
            "read_budget": {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls},
            "observation": {
                "status": "observed",
                "module_base": _hex(module_base),
                "country_pointer": trade_income_record.get("country_pointer"),
                "country": trade_income_record.get("country"),
                "country_slot": trade_income_record.get("country_slot"),
                "node_count": len(nodes),
                "runtime_total_power_offset": _hex(layout["runtime_total_power_offset"]),
                "entry_power_offsets": [_hex(offset) for offset in layout["entry_power_offsets"]],
            },
        }
    except Exception as exc:
        result = _empty_record(
            f"read_failed:{type(exc).__name__}:{exc}",
            profile=profile,
            guard=guard,
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base,
        )
        result["read_budget"] = {"bytes_requested": ctx.bytes_requested, "calls": ctx.calls}
        return result


def validate_record(record: Any, trade_income_record: Any) -> bool:
    """Validate source binding, copied raw fields, formula and code guards."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return False
    if not isinstance(trade_income_record, Mapping) or not _trade.validate_record(trade_income_record):
        return False
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
    except Exception:
        return False
    if record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
        return False
    static = record.get("static_contract_guard")
    if (
        not isinstance(static, Mapping)
        or static.get("status") != "observed"
        or static.get("profile_id") != "trade-power-memory-1374"
        or static.get("profile_sha256") != EXPECTED_PROFILE_SHA256
        or static.get("checks") != _static_contract_guard(profile).get("checks")
        or static.get("source_index") != _static_contract_guard(profile).get("source_index")
        or static.get("unknown_conditions") != []
    ):
        return False
    if not _expected_runtime_guard(record, profile):
        return False
    module_base = _trade._pointer_from_hex(record.get("module_base"))
    source_module = _trade._pointer_from_hex(trade_income_record.get("module_base"))
    if module_base is None or module_base != source_module:
        return False
    source_digest = _canonical_digest(trade_income_record)
    if record.get("source_trade_record_canonical_sha256") != source_digest:
        return False
    for key in ("country_pointer", "country", "country_fullref_raw_hex", "country_slot"):
        if record.get(key) != trade_income_record.get(key):
            return False
    if record.get("country") != EXPECTED_COUNTRY:
        return False
    if (
        record.get("basis") != BASIS
        or record.get("unit") != UNIT
        or record.get("scale") != SCALE
        or record.get("period") != PERIOD
        or record.get("value_origin") != VALUE_ORIGIN
        or record.get("node_value_origin") != NODE_VALUE_ORIGIN
        or record.get("total_value_origin") != TOTAL_VALUE_ORIGIN
    ):
        return False
    source_nodes = trade_income_record.get("nodes")
    nodes = record.get("nodes")
    if not isinstance(source_nodes, list) or not source_nodes or not isinstance(nodes, list) or len(nodes) != len(source_nodes):
        return False
    for index, (source_node, node) in enumerate(zip(source_nodes, nodes)):
        if not isinstance(source_node, Mapping) or not isinstance(node, Mapping):
            return False
        if node.get("node_id") != source_node.get("node_id"):
            return False
        runtime = _trade._pointer_from_hex(source_node.get("runtime_pointer"))
        node_runtime = _trade._pointer_from_hex(node.get("runtime_pointer"))
        if runtime is None or node_runtime != runtime:
            return False
        try:
            runtime_address = _trade._address_add(runtime, layout["runtime_total_power_offset"], f"node[{index}].runtime_total_power")
        except Exception:
            return False
        if node.get("runtime_total_power_address") != _hex(runtime_address):
            return False
        total_power = node.get("total_power_raw")
        if not isinstance(total_power, int) or isinstance(total_power, bool) or not -(1 << 31) <= total_power < (1 << 31):
            return False
        if node.get("total_power_raw_hex") != _i32_hex(total_power):
            return False
        try:
            expected_components, expected_components_hex = _source_components(source_node, layout["entry_power_offsets"])
        except Exception:
            return False
        components = node.get("entry_power_components_raw")
        if components != expected_components or node.get("entry_power_components_raw_hex") != expected_components_hex:
            return False
        if any(
            not isinstance(value, int) or isinstance(value, bool) or not -(1 << 31) <= value < (1 << 31)
            for value in expected_components.values()
        ):
            return False
        country_power = node.get("country_power_raw")
        if not isinstance(country_power, int) or isinstance(country_power, bool) or not -(1 << 31) <= country_power < (1 << 31):
            return False
        if country_power != _country_power(expected_components) or node.get("country_power_raw_hex") != _i32_hex(country_power):
            return False
        if (
            node.get("value_origin") != VALUE_ORIGIN
            or node.get("node_value_origin") != NODE_VALUE_ORIGIN
            or node.get("total_value_origin") != TOTAL_VALUE_ORIGIN
        ):
            return False
    observation = record.get("observation")
    return (
        isinstance(observation, Mapping)
        and observation.get("status") == "observed"
        and observation.get("module_base") == _hex(module_base)
        and observation.get("country_pointer") == trade_income_record.get("country_pointer")
        and observation.get("country") == EXPECTED_COUNTRY
        and observation.get("country_slot") == trade_income_record.get("country_slot")
        and observation.get("node_count") == len(source_nodes)
        and observation.get("runtime_total_power_offset") == _hex(layout["runtime_total_power_offset"])
        and observation.get("entry_power_offsets") == [_hex(offset) for offset in layout["entry_power_offsets"]]
    )


def retract_record(record: Mapping[str, Any] | None, reason: str) -> dict[str, Any]:
    """Retract copied/derived power values after parent cleanup or failure."""
    result = _deepcopy(record) if isinstance(record, Mapping) else _empty_record(reason)
    result["status"] = "unknown"
    result["reason"] = reason
    result["nodes"] = None
    result["observation"] = {"status": "unknown", "reason": reason}
    return result


__all__ = [
    "BASIS", "EXPECTED_COUNTRY", "EXPECTED_EXE_SHA256", "EXPECTED_PROFILE_SHA256", "EXPECTED_VERSION",
    "PERIOD", "PROFILE", "PROFILE_FILE", "SCALE", "UNIT", "VALUE_ORIGIN", "NODE_VALUE_ORIGIN", "TOTAL_VALUE_ORIGIN",
    "ProfileError", "ReadError", "read_fields", "validate_record", "retract_record",
]
