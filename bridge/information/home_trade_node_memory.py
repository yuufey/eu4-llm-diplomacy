"""Derive the selected country's home trade node from trade-entry flags.

The parent trade reader already owns the complete, guarded node graph and the
country binding.  This reader consumes that validated record and only checks a
small field-specific profile/code guard before deriving ``home_node`` from the
entry ``+0xAD`` byte.  It never walks the native graph a second time and never
calls a game function.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import trade_income_memory as _trade


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "home-trade-node-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "3090fc60dd6c99b03adb1e1e317069cc37de5816422bb5eb814dfede8124e957"
EXPECTED_EXE_SHA256 = _trade.EXPECTED_EXE_SHA256
EXPECTED_VERSION = _trade.EXPECTED_VERSION
EXPECTED_COUNTRY = _trade.EXPECTED_COUNTRY

BASIS = "native_trade_node_home_flag"
UNIT = "trade_node"
SCALE = 1
PERIOD = "current"
VALUE_ORIGIN = "derived_from_copied_native_flags"
ENTRY_FLAG_AD_OFFSET = 0xAD
REQUIRED_HOME_COUNT = 1
EXPECTED_TRADE_PROFILE_SHA256 = _trade.EXPECTED_PROFILE_SHA256
MAX_SOURCE_BYTES = 128 * 1024

_ROOT = Path(__file__).resolve().parents[2]


class ProfileError(RuntimeError):
    """The field-specific profile is missing, pending, or tampered."""


class ReadError(RuntimeError):
    """The bounded field-specific guard/read contract failed."""


def _deepcopy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _valid_address(value: Any) -> bool:
    return _trade._valid_address(value)


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if parsed < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return parsed


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
    offset = _parse_int(raw.get("entry_home_flag_offset"), "layout.entry_home_flag_offset")
    required_count = _parse_int(raw.get("required_home_count"), "layout.required_home_count")
    source_trade_profile_sha256 = raw.get("source_trade_profile_sha256")
    if offset != ENTRY_FLAG_AD_OFFSET:
        raise ProfileError("profile_entry_home_flag_offset_mismatch")
    if required_count != REQUIRED_HOME_COUNT:
        raise ProfileError("profile_required_home_count_mismatch")
    if source_trade_profile_sha256 != EXPECTED_TRADE_PROFILE_SHA256:
        raise ProfileError("profile_source_trade_profile_sha256_mismatch")
    return {
        "entry_home_flag_offset": offset,
        "required_home_count": required_count,
        "source_trade_profile_sha256": source_trade_profile_sha256,
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


def _validate_source_index(profile: Mapping[str, Any]) -> dict[str, Any]:
    source = profile.get("source_index")
    if not isinstance(source, Mapping):
        raise ProfileError("profile_source_index_missing")
    source_id = source.get("source_index_id")
    source_path = source.get("path")
    expected_sha = source.get("sha256")
    if (
        not isinstance(source_id, str) or not source_id
        or not isinstance(source_path, str) or not source_path
        or not isinstance(expected_sha, str) or len(expected_sha) != 64
    ):
        raise ProfileError("profile_source_index_shape_invalid")
    path = ( _ROOT / source_path ).resolve()
    try:
        path.relative_to(_ROOT)
    except ValueError as exc:
        raise ProfileError("profile_source_index_path_escape") from exc
    raw = _bounded_bytes(path, MAX_SOURCE_BYTES, "source_index")
    actual = hashlib.sha256(raw).hexdigest()
    if actual.lower() != expected_sha.lower():
        raise ProfileError("profile_source_index_sha256_mismatch")
    return {
        "source_index_id": source_id,
        "path": source_path,
        "sha256": expected_sha,
        "bytes": len(raw),
    }


def _validate_profile_shape(profile: Mapping[str, Any]) -> None:
    if profile.get("profile_id") != "home-trade-node-memory-1374":
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
    result = dict(profile)
    result["_validated_source_index"] = source
    return result


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
        "profile_id": profile.get("profile_id") == "home-trade-node-memory-1374",
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
        "source_trade_record_canonical_sha256": source_digest,
        "country": source.get("country", EXPECTED_COUNTRY),
        "country_fullref_raw_hex": source.get("country_fullref_raw_hex"),
        "country_slot": source.get("country_slot"),
        "nodes": None,
        "derived_nodes": None,
        "home_node": None,
        "known_reason": reason,
        "basis": BASIS,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "value_origin": VALUE_ORIGIN,
        "observation": {"status": "unknown", "reason": reason},
    }


def _runtime_code_guard(reader: Any, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _hex(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        if not _valid_address(module_base):
            raise ReadError("module_base_invalid")
        method = getattr(reader, "read", None)
        if not callable(method):
            raise ReadError("reader_read_method_missing")
        for name, rva, expected in _profile_code_guards(profile):
            address = module_base + rva
            if not _valid_address(address):
                raise ReadError(f"guard_address_invalid:{name}")
            actual = method(address, len(expected), f"home_trade_node.code.{name}")
            if not isinstance(actual, (bytes, bytearray)) or len(actual) != len(expected):
                raise ReadError(f"short_or_invalid_guard_read:{name}")
            actual = bytes(actual)
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


def _canonical_digest(record: Mapping[str, Any]) -> str:
    raw = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _flag_ad_raw(node: Mapping[str, Any], offset: int) -> tuple[int, str]:
    raw_hex = node.get("entry_raw_hex")
    if not isinstance(raw_hex, str) or len(raw_hex) < (offset + 1) * 2:
        raise ReadError("trade_node_entry_raw_missing")
    try:
        entry = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReadError("trade_node_entry_raw_invalid") from exc
    value = entry[offset]
    return value, f"{value:02x}"


def _compact_nodes(trade_income_record: Mapping[str, Any], layout: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    source_nodes = trade_income_record.get("nodes")
    if not isinstance(source_nodes, list) or not source_nodes:
        raise ReadError("trade_income_nodes_missing")
    nodes: list[dict[str, Any]] = []
    candidates: list[str] = []
    seen: set[str] = set()
    for source_node in source_nodes:
        if not isinstance(source_node, Mapping):
            raise ReadError("trade_income_node_invalid")
        node_id = source_node.get("node_id")
        if not isinstance(node_id, str) or not node_id or node_id in seen:
            raise ReadError("trade_income_node_id_invalid")
        seen.add(node_id)
        flag_ad, raw_hex = _flag_ad_raw(source_node, layout["entry_home_flag_offset"])
        if source_node.get("flag_ad") != flag_ad:
            raise ReadError(f"trade_income_flag_ad_mismatch:{node_id}")
        compact = {"node_id": node_id, "flag_ad": flag_ad, "flag_ad_raw_hex": raw_hex}
        nodes.append(compact)
        if flag_ad != 0:
            candidates.append(node_id)
    return nodes, candidates


def read_fields(reader: Any, module_base: int, trade_income_record: Any) -> dict[str, Any]:
    """Derive home node from a previously validated trade-income record."""
    # This ordering is intentional: an invalid/absent old record must not
    # trigger a new profile load or any RPM/code-guard read.
    if not isinstance(trade_income_record, Mapping) or not _trade.validate_record(trade_income_record):
        return _empty_record("trade_income_record_invalid")
    source_digest = _canonical_digest(trade_income_record)
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
    except Exception as exc:
        return _empty_record(
            f"profile_unavailable:{type(exc).__name__}:{exc}",
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base if isinstance(module_base, int) else None,
        )
    static_guard = _static_contract_guard(profile)
    if static_guard.get("status") != "observed":
        return _empty_record(
            "static_contract_guard_failed",
            profile=profile,
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base if isinstance(module_base, int) else None,
        )
    guard = _runtime_code_guard(reader, module_base, profile)
    if guard.get("status") != "observed":
        return _empty_record(
            "runtime_code_guard_failed",
            profile=profile,
            guard=guard,
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base if isinstance(module_base, int) else None,
        )
    try:
        nodes, candidates = _compact_nodes(trade_income_record, layout)
        if len(candidates) == REQUIRED_HOME_COUNT:
            status = "observed"
            home_node = candidates[0]
            known_reason = "unique_flag_ad"
            reason = None
        elif not candidates:
            status = "unknown"
            home_node = None
            known_reason = "no_flag_ad"
            reason = "no_node_with_flag_ad"
        else:
            status = "unknown"
            home_node = None
            known_reason = "multiple_flag_ad"
            reason = "multiple_nodes_with_flag_ad"
        result = {
            "status": status,
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "static_contract_guard": static_guard,
            "runtime_code_guard": guard,
            "module_base": _hex(module_base),
            "source_trade_record_canonical_sha256": source_digest,
            "country": trade_income_record.get("country"),
            "country_fullref_raw_hex": trade_income_record.get("country_fullref_raw_hex"),
            "country_slot": trade_income_record.get("country_slot"),
            "nodes": nodes,
            "derived_nodes": candidates,
            "home_node": home_node,
            "known_reason": known_reason,
            "basis": BASIS,
            "unit": UNIT,
            "scale": SCALE,
            "period": PERIOD,
            "value_origin": VALUE_ORIGIN,
            "observation": {
                "status": status,
                "module_base": _hex(module_base),
                "source_trade_record_canonical_sha256": source_digest,
                "country": trade_income_record.get("country"),
                "country_slot": trade_income_record.get("country_slot"),
                "candidate_count": len(candidates),
            },
        }
        if reason:
            result["reason"] = reason
        return result
    except Exception as exc:
        return _empty_record(
            f"derive_failed:{type(exc).__name__}:{exc}",
            profile=profile,
            guard=guard,
            source=trade_income_record,
            source_digest=source_digest,
            module_base=module_base if isinstance(module_base, int) else None,
        )


def _expected_runtime_guard(record: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    guard = record.get("runtime_code_guard")
    module_base = record.get("module_base")
    try:
        module = int(module_base, 0)
        expected_guards = _profile_code_guards(profile)
    except (TypeError, ValueError, ProfileError):
        return False
    if not _valid_address(module) or not isinstance(guard, Mapping) or guard.get("status") != "observed":
        return False
    checks = guard.get("checks")
    records = guard.get("records")
    if not isinstance(checks, Mapping) or not isinstance(records, Mapping):
        return False
    if set(checks) != {name for name, _rva, _raw in expected_guards} or any(value is not True for value in checks.values()):
        return False
    if set(records) != set(checks):
        return False
    for name, rva, expected in expected_guards:
        item = records.get(name)
        if not isinstance(item, Mapping):
            return False
        if (
            item.get("rva") != _hex(rva)
            or item.get("address") != _hex(module + rva)
            or item.get("expected_hex") != expected.hex()
            or item.get("actual_hex") != expected.hex()
            or item.get("expected_sha256") != hashlib.sha256(expected).hexdigest()
            or item.get("actual_sha256") != hashlib.sha256(expected).hexdigest()
        ):
            return False
    return guard.get("module_base") == _hex(module) and guard.get("unknown_conditions") == []


def validate_record(record: Any, trade_income_record: Any) -> bool:
    """Validate source digest, compact raw AD bytes, guards and uniqueness."""
    if not isinstance(record, Mapping) or not isinstance(trade_income_record, Mapping):
        return False
    if not _trade.validate_record(trade_income_record):
        return False
    try:
        profile = _active_profile()
        layout = _profile_layout(profile)
    except Exception:
        return False
    if record.get("profile_sha256") != EXPECTED_PROFILE_SHA256:
        return False
    static = record.get("static_contract_guard")
    expected_static = _static_contract_guard(profile)
    if (
        not isinstance(static, Mapping)
        or static.get("status") != "observed"
        or static.get("profile_id") != expected_static.get("profile_id")
        or static.get("profile_sha256") != EXPECTED_PROFILE_SHA256
        or static.get("checks") != expected_static.get("checks")
        or static.get("source_index") != expected_static.get("source_index")
        or static.get("unknown_conditions") != []
    ):
        return False
    if not _expected_runtime_guard(record, profile):
        return False
    module_base = record.get("module_base")
    if not isinstance(module_base, str):
        return False
    try:
        module_value = int(module_base, 0)
    except ValueError:
        return False
    if not _valid_address(module_value):
        return False
    # The child record must remain attached to the exact native source
    # observation.  A valid-looking code guard at another module base is not
    # sufficient to rebind this derived value.
    if module_base != trade_income_record.get("module_base"):
        return False
    source_digest = _canonical_digest(trade_income_record)
    if record.get("source_trade_record_canonical_sha256") != source_digest:
        return False
    if record.get("country") != trade_income_record.get("country"):
        return False
    if record.get("country_fullref_raw_hex") != trade_income_record.get("country_fullref_raw_hex"):
        return False
    if record.get("country_slot") != trade_income_record.get("country_slot"):
        return False
    if record.get("basis") != BASIS or record.get("unit") != UNIT or record.get("scale") != SCALE:
        return False
    if record.get("period") != PERIOD or record.get("value_origin") != VALUE_ORIGIN:
        return False
    try:
        expected_nodes, candidates = _compact_nodes(trade_income_record, layout)
    except Exception:
        return False
    if record.get("nodes") != expected_nodes or record.get("derived_nodes") != candidates:
        return False
    if record.get("known_reason") != (
        "unique_flag_ad" if len(candidates) == 1 else "no_flag_ad" if not candidates else "multiple_flag_ad"
    ):
        return False
    if len(candidates) == REQUIRED_HOME_COUNT:
        if record.get("status") != "observed" or record.get("home_node") != candidates[0] or record.get("reason") is not None:
            return False
    elif not candidates:
        if record.get("status") != "unknown" or record.get("home_node") is not None or record.get("reason") != "no_node_with_flag_ad":
            return False
    else:
        if record.get("status") != "unknown" or record.get("home_node") is not None or record.get("reason") != "multiple_nodes_with_flag_ad":
            return False
    observation = record.get("observation")
    if not isinstance(observation, Mapping):
        return False
    return (
        observation.get("status") == record.get("status")
        and observation.get("module_base") == module_base
        and observation.get("source_trade_record_canonical_sha256") == source_digest
        and observation.get("country") == trade_income_record.get("country")
        and observation.get("country_slot") == trade_income_record.get("country_slot")
        and observation.get("candidate_count") == len(candidates)
    )


def retract_record(record: Mapping[str, Any] | None, reason: str) -> dict[str, Any]:
    """Retract candidate/home values after parent cleanup or context failure."""
    result = _deepcopy(record) if isinstance(record, Mapping) else _empty_record(reason)
    result["status"] = "unknown"
    result["reason"] = reason
    result["known_reason"] = reason
    result["nodes"] = None
    result["derived_nodes"] = None
    result["home_node"] = None
    result["observation"] = {"status": "unknown", "reason": reason}
    return result


__all__ = [
    "BASIS", "EXPECTED_COUNTRY", "EXPECTED_EXE_SHA256", "EXPECTED_PROFILE_SHA256", "EXPECTED_VERSION",
    "PERIOD", "PROFILE", "PROFILE_FILE", "SCALE", "UNIT", "VALUE_ORIGIN", "ProfileError", "ReadError",
    "read_fields", "retract_record", "validate_record",
]
