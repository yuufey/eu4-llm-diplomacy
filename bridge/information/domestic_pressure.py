"""Read-only N04 domestic-pressure adapter.

The native reader is intentionally loaded only when a live N04 query is
read.  This module validates its bounded report as untrusted input and never
uses a recorded source, a user-supplied installation path, or a public action
inspection as a substitute for the native capture.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re
from typing import Any

from .model import InformationError, canonical
from .observation_time import context_identity, dates_match
from .sources import _copy, _result, _source_info


_VERSION = "1.37.4"
_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
_COUNTRY = "FRA"
_FIELDS = ("stability", "war_exhaustion", "corruption", "religious_unity", "overextension", "unrest")
_UNITS = {
    "stability": "stability",
    "war_exhaustion": "war_exhaustion",
    "corruption": "corruption",
    "religious_unity": "fraction",
    "overextension": "fraction",
    "unrest": "unrest",
}
_CONTEXT_KEYS = (
    "session_id", "game_sha256", "observer", "game_version", "game_date", "world_id",
)
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1


def _known(raw: int, raw_hex: str, field: str) -> dict[str, Any]:
    return {
        "status": "known",
        # ``value`` is required by the information service wire contract;
        # ``raw``/``raw_hex`` retain the native scalar without applying a
        # floating-point conversion.
        "value": raw,
        "raw": raw,
        "raw_hex": raw_hex,
        "unit": _UNITS[field],
        "scale": 1000,
    }


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _identity_snapshot(context: dict[str, Any]) -> tuple[Any, ...]:
    return context_identity(context, _CONTEXT_KEYS)


def _context_reason(context: Any) -> str | None:
    if not isinstance(context, dict):
        return "DOMESTIC_PRESSURE_CONTEXT_UNAVAILABLE"
    if context.get("status") != "ready" or context.get("complete") is not True:
        return "DOMESTIC_PRESSURE_LIVE_CONTEXT_UNAVAILABLE"
    if context.get("mode") != "live":
        return "DOMESTIC_PRESSURE_LIVE_CONTEXT_REQUIRED"
    if context.get("observer") != _COUNTRY:
        return "DOMESTIC_PRESSURE_OBSERVER_SCOPE_MISMATCH"
    if context.get("game_version") != _VERSION:
        return "DOMESTIC_PRESSURE_GAME_VERSION_MISMATCH"
    if context.get("game_sha256") != _GAME_SHA256:
        return "DOMESTIC_PRESSURE_GAME_IDENTITY_MISMATCH"
    if not isinstance(context.get("session_id"), str) or not context["session_id"]:
        return "DOMESTIC_PRESSURE_SESSION_ID_UNAVAILABLE"
    if type(context.get("game_date")) is not int:
        return "DOMESTIC_PRESSURE_GAME_DATE_UNAVAILABLE"
    if "game_date_raw" in context:
        if type(context.get("game_date_raw")) is not int or context["game_date_raw"] != context["game_date"]:
            return "DOMESTIC_PRESSURE_GAME_DATE_IDENTITY_MISMATCH"
    return None


def _session_binding(base_source: Any, context: dict[str, Any]) -> tuple[Path | None, int | None, str | None]:
    session = getattr(base_source, "session", None)
    if session is None:
        return None, None, "DOMESTIC_PRESSURE_SESSION_UNAVAILABLE"
    directory = getattr(session, "directory", None)
    if directory is None:
        return None, None, "DOMESTIC_PRESSURE_SESSION_DIRECTORY_UNAVAILABLE"
    record = getattr(session, "record", None)
    if not isinstance(record, dict):
        return None, None, "DOMESTIC_PRESSURE_SESSION_RECORD_UNAVAILABLE"
    creation = record.get("creation_filetime")
    if type(creation) is not int:
        return None, None, "DOMESTIC_PRESSURE_CREATION_FILETIME_UNAVAILABLE"
    record_session_id = record.get("session_id")
    if record_session_id is not None and record_session_id != context.get("session_id"):
        return None, None, "DOMESTIC_PRESSURE_SESSION_ID_MISMATCH"
    session_creation = getattr(session, "creation_filetime", None)
    if session_creation is not None and session_creation != creation:
        return None, None, "DOMESTIC_PRESSURE_CREATION_FILETIME_MISMATCH"
    try:
        installation = Path(directory) / "installation.json"
    except (TypeError, ValueError):
        return None, None, "DOMESTIC_PRESSURE_SESSION_DIRECTORY_INVALID"
    return installation, creation, None


def _hex_digest(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return hashlib.sha256(bytes.fromhex(value)).hexdigest()
    except ValueError:
        return None


def _compact_check_value(value: Any) -> Any:
    """Remove code bytes and raw-read logs from nested guard checks."""

    forbidden = {
        "expected_hex", "actual_hex", "code_hex", "bytes_hex",
        "expected_bytes", "actual_bytes", "raw_bytes", "read_log",
    }
    if isinstance(value, dict):
        return {
            key: _compact_check_value(child)
            for key, child in value.items()
            if key not in forbidden
        }
    if isinstance(value, list):
        return [_compact_check_value(child) for child in value]
    return deepcopy(value)


def _compact_code_guard(guard: Any) -> dict[str, Any]:
    """Keep guard identity and hashes, never code hex or raw read logs."""

    if not isinstance(guard, dict):
        return {"status": None, "checks": {}, "records": {}}
    records: dict[str, Any] = {}
    raw_records = guard.get("records")
    if isinstance(raw_records, dict):
        for name, raw_record in raw_records.items():
            if not isinstance(name, str) or not isinstance(raw_record, dict):
                continue
            compact: dict[str, Any] = {}
            if "rva" in raw_record:
                compact["rva"] = deepcopy(raw_record["rva"])
            if "address" in raw_record:
                compact["address"] = deepcopy(raw_record["address"])
                if isinstance(raw_record["address"], dict):
                    compact.setdefault("rva", deepcopy(raw_record["address"].get("rva")))
            expected = raw_record.get("expected_sha256") or _hex_digest(raw_record.get("expected_hex"))
            actual = raw_record.get("actual_sha256") or _hex_digest(raw_record.get("actual_hex"))
            compact["expected_sha256"] = expected
            compact["actual_sha256"] = actual
            records[name] = compact
    result: dict[str, Any] = {
        "status": guard.get("status"),
        "checks": _compact_check_value(guard.get("checks", {}))
        if isinstance(guard.get("checks", {}), dict) else {},
        "records": records,
    }
    for key in ("profile", "profile_sha256", "module_base"):
        if key in guard:
            result[key] = deepcopy(guard[key])
    if isinstance(guard.get("source_dependencies"), list):
        result["source_dependencies"] = [
            {"path": item.get("path"), "sha256": item.get("sha256")}
            for item in guard["source_dependencies"]
            if isinstance(item, dict)
        ]
    if isinstance(guard.get("dependency_hash_checks"), dict):
        result["dependency_hash_checks"] = deepcopy(guard["dependency_hash_checks"])
    if isinstance(guard.get("unknown_conditions"), list):
        result["unknown_conditions"] = deepcopy(guard["unknown_conditions"][:256])
    return result


def _compact_static_guard(guard: Any) -> dict[str, Any]:
    if not isinstance(guard, dict):
        return {"status": None, "checks": {}, "dependencies": []}
    result: dict[str, Any] = {
        "status": guard.get("status"),
        "profile": guard.get("profile"),
        "profile_sha256": guard.get("profile_sha256"),
        "checks": _compact_check_value(guard.get("checks", {}))
        if isinstance(guard.get("checks", {}), dict) else {},
        "dependency_hash_checks": deepcopy(guard.get("dependency_hash_checks", {}))
        if isinstance(guard.get("dependency_hash_checks", {}), dict) else {},
        "dependencies": [
            {"path": item.get("path"), "sha256": item.get("sha256")}
            for item in guard.get("source_dependencies", [])
            if isinstance(item, dict)
        ] if isinstance(guard.get("source_dependencies"), list) else [],
    }
    if isinstance(guard.get("unknown_conditions"), list):
        result["unknown_conditions"] = deepcopy(guard["unknown_conditions"][:256])
    return result


def _compact_snapshot(snapshot: Any) -> dict[str, Any] | None:
    if not isinstance(snapshot, dict):
        return None
    result: dict[str, Any] = {
        "status": snapshot.get("status"),
        "game_date": deepcopy(snapshot.get("game_date")),
        "field_results": {},
    }
    fields = snapshot.get("field_results")
    if isinstance(fields, dict):
        for field, item in fields.items():
            if not isinstance(field, str) or not isinstance(item, dict):
                continue
            result["field_results"][field] = {
                key: deepcopy(item[key])
                for key in ("status", "raw", "raw_hex", "unit", "scale", "reason")
                if key in item
            }
    token_guard = snapshot.get("save_token_guard")
    if isinstance(token_guard, dict):
        compact_guard: dict[str, Any] = {
            key: deepcopy(token_guard[key])
            for key in ("status", "vector", "vector_raw_hex", "checks", "unknown_conditions")
            if key in token_guard
        }
        records = token_guard.get("records")
        if isinstance(records, dict):
            compact_guard["records"] = {}
            for field, record in records.items():
                if not isinstance(field, str) or not isinstance(record, dict):
                    continue
                compact_guard["records"][field] = {
                    key: deepcopy(record[key])
                    for key in (
                        "key_id", "expected_name", "actual_name", "status", "header_hex",
                        "length", "capacity", "payload_hex", "nul_terminator_observed", "reason",
                    )
                    if key in record
                }
        result["save_token_guard"] = compact_guard
    return result


def _capture_audit(report: dict[str, Any]) -> dict[str, Any]:
    identity = report.get("identity")
    compact_identity = {}
    if isinstance(identity, dict):
        for key in (
            "binding_verified", "installation_session_id", "installation_creation_filetime",
            "process_creation_filetime", "process_path_sha256",
            "process_path_sha256_matches_expected", "process_creation_matches_installation",
        ):
            if key in identity:
                compact_identity[key] = deepcopy(identity[key])
    access = report.get("access")
    compact_access = {}
    if isinstance(access, dict):
        for key in (
            "rpm_bytes_requested", "rpm_calls", "rpm_total_limit", "rpm_single_read_limit",
            "native_game_calls", "target_memory_writes", "dll_injection", "private_heap_scan", "ui_control",
            "date_advance", "save_or_reload",
        ):
            if key in access:
                compact_access[key] = deepcopy(access[key])
    profile = report.get("profile")
    compact_profile = None
    if isinstance(profile, dict):
        compact_profile = {
            key: deepcopy(profile.get(key))
            for key in ("path", "sha256", "max_bytes")
            if key in profile
        }
    compact: dict[str, Any] = {
        "status": report.get("status"),
        "read_only": report.get("read_only"),
        "native_function_invoked": report.get("native_function_invoked"),
        "completed": report.get("completed"),
        "country": report.get("country"),
        "target_build": deepcopy(report.get("target_build")),
        "probe_script_sha256": report.get("probe_script_sha256"),
        "profile": compact_profile,
        "identity": compact_identity,
        "static_contract_guard": _compact_static_guard(report.get("static_contract_guard")),
        "file_code_guard": _compact_code_guard(report.get("file_code_guard")),
        "runtime_code_guard": _compact_code_guard(report.get("runtime_code_guard")),
        "doublepass": deepcopy(report.get("doublepass")),
        "cleanup": deepcopy(report.get("cleanup")),
        "access": compact_access,
        "before": _compact_snapshot(report.get("before")),
        "after": _compact_snapshot(report.get("after")),
    }
    return compact


def _capture_sha256(report: Any) -> str | None:
    try:
        return hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
    except Exception:
        return None


def _provenance(report: dict[str, Any] | None = None, *, reason: str | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "adapter": "NativeDomesticPressureSource",
        "capture": "bridge.information.domestic_pressure_memory.capture",
        "read_only": True,
        "native_function_invoked": False,
        "scope": "country_scope",
        "supported_country": _COUNTRY,
        "target_build": {"version": _VERSION, "game_sha256": _GAME_SHA256},
        "context_identity_keys": list(_CONTEXT_KEYS),
        "capture_report_hash_algorithm": "sha256(canonical_json_utf8;information.model.canonical)",
    }
    if reason is not None:
        value["reason"] = reason
    if isinstance(report, dict):
        value["capture"] = _capture_audit(report)
        value["capture_report_sha256"] = _capture_sha256(report)
    return value


def _snapshot_date(snapshot: Any) -> int | None:
    if not isinstance(snapshot, dict) or snapshot.get("status") != "observed":
        return None
    date = snapshot.get("game_date")
    if not isinstance(date, dict) or type(date.get("value")) is not int:
        return None
    raw_hex = date.get("raw_hex")
    if not isinstance(raw_hex, str) or re.fullmatch(r"[0-9a-fA-F]{8}", raw_hex) is None:
        return None
    try:
        if int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) != date["value"]:
            return None
    except ValueError:
        return None
    return date["value"]


def _date_valid(snapshot: Any, expected: int) -> bool:
    observed = _snapshot_date(snapshot)
    return observed is not None and dates_match(expected, observed)


def _reader_profile_pin() -> str | None:
    """Return the enabled reader pin, if the native reader has one.

    Keep the adapter tied to the reader's checked-in pin without embedding a
    second copy of the profile digest here.  A zero digest remains accepted as
    an explicitly disabled reader seam for isolated fake-reader tests.
    """

    try:
        from . import domestic_pressure_memory as reader

        pin = getattr(reader, "EXPECTED_PROFILE_SHA256", None)
    except Exception:
        return None
    if not isinstance(pin, str) or re.fullmatch(r"[0-9a-fA-F]{64}", pin) is None:
        return None
    if pin.lower() == "0" * 64:
        return None
    return pin.lower()


def _profile_reason(report: dict[str, Any]) -> str | None:
    profile = report.get("profile")
    if not isinstance(profile, dict) or "sha256" not in profile:
        return None
    supplied = profile.get("sha256")
    if not isinstance(supplied, str) or re.fullmatch(r"[0-9a-fA-F]{64}", supplied) is None:
        return "DOMESTIC_PRESSURE_PROFILE_SHA_INVALID"
    pin = _reader_profile_pin()
    if pin is not None and supplied.lower() != pin:
        return "DOMESTIC_PRESSURE_PROFILE_SHA_MISMATCH"
    return None


def _access_reason(report: dict[str, Any]) -> str | None:
    access = report.get("access")
    if access is None:
        return None
    if not isinstance(access, dict):
        return "DOMESTIC_PRESSURE_ACCESS_INVALID"
    for key in (
        "target_memory_writes", "memory_writes", "writes",
        "native_game_calls", "native_calls", "native_function_calls",
        "dll_injection", "dll_injection_used",
    ):
        if access.get(key) is True:
            return "DOMESTIC_PRESSURE_READ_ONLY_ACCESS_INVALID"
    return None


def _identity_valid(identity: Any, context: dict[str, Any], creation_filetime: int) -> bool:
    if not isinstance(identity, dict) or identity.get("binding_verified") is not True:
        return False
    exe_sha = identity.get("process_path_sha256", identity.get("exe_sha256"))
    session_id = identity.get("installation_session_id", identity.get("session_id"))
    installation_creation = identity.get("installation_creation_filetime", identity.get("creation_filetime"))
    process_creation = identity.get("process_creation_filetime", identity.get("process_creation"))
    if exe_sha != _GAME_SHA256 or session_id != context.get("session_id"):
        return False
    if type(installation_creation) is not int or installation_creation != creation_filetime:
        return False
    if type(process_creation) is not int or process_creation != creation_filetime:
        return False
    for key in ("process_path_sha256_matches_expected", "process_creation_matches_installation"):
        if key in identity and identity[key] is not True:
            return False
    return True


def _global_report_reason(report: Any, context: dict[str, Any], creation_filetime: int) -> str | None:
    if not isinstance(report, dict):
        return "DOMESTIC_PRESSURE_CAPTURE_INVALID"
    if (
        report.get("status") != "observed"
        or report.get("read_only") is not True
        or report.get("native_function_invoked") is not False
        or report.get("country") != _COUNTRY
        or report.get("completed") is not True
    ):
        return "DOMESTIC_PRESSURE_CAPTURE_CONTRACT_INVALID"
    target_build = report.get("target_build")
    if not isinstance(target_build, dict) or target_build.get("version") != _VERSION:
        return "DOMESTIC_PRESSURE_TARGET_BUILD_INVALID"
    target_sha = target_build.get("expected_exe_sha256", target_build.get("exe_sha256"))
    if target_sha != _GAME_SHA256:
        return "DOMESTIC_PRESSURE_TARGET_BUILD_INVALID"
    if not _identity_valid(report.get("identity"), context, creation_filetime):
        return "DOMESTIC_PRESSURE_IDENTITY_INVALID"
    for key in ("static_contract_guard", "file_code_guard", "runtime_code_guard"):
        guard = report.get(key)
        if not isinstance(guard, dict) or guard.get("status") != "observed":
            return "DOMESTIC_PRESSURE_GUARD_INVALID"
    doublepass = report.get("doublepass")
    if not isinstance(doublepass, dict) or doublepass.get("performed") is not True or doublepass.get("consistent") is not True:
        return "DOMESTIC_PRESSURE_DOUBLEPASS_INVALID"
    mismatches = doublepass.get("mismatches")
    if mismatches is not None and (not isinstance(mismatches, list) or bool(mismatches)):
        return "DOMESTIC_PRESSURE_DOUBLEPASS_INVALID"
    cleanup = report.get("cleanup")
    handle_close = cleanup.get("handle_close") if isinstance(cleanup, dict) else None
    if (
        not isinstance(handle_close, dict)
        or handle_close.get("status") != "closed"
        or handle_close.get("closed") is not True
    ):
        return "DOMESTIC_PRESSURE_CLEANUP_INVALID"
    before_date = _snapshot_date(report.get("before"))
    after_date = _snapshot_date(report.get("after"))
    if before_date is None or not _date_valid(report.get("before"), context["game_date"]):
        return "DOMESTIC_PRESSURE_BEFORE_DATE_INVALID"
    if after_date is None or not _date_valid(report.get("after"), context["game_date"]):
        return "DOMESTIC_PRESSURE_AFTER_DATE_INVALID"
    if not dates_match(context["game_date"], before_date, after_date):
        return "DOMESTIC_PRESSURE_SNAPSHOT_DATE_ORDER_INVALID"
    profile_reason = _profile_reason(report)
    if profile_reason is not None:
        return profile_reason
    access_reason = _access_reason(report)
    if access_reason is not None:
        return access_reason
    return None


def _validated_field_record(item: Any, field: str, label: str) -> tuple[tuple[int, str, str, int] | None, str | None]:
    if not isinstance(item, dict):
        return None, f"DOMESTIC_PRESSURE_{label}_INVALID"
    status = item.get("status")
    if status == "unknown":
        reason = item.get("reason")
        return None, reason if isinstance(reason, str) and reason else f"DOMESTIC_PRESSURE_{label}_UNKNOWN"
    if status != "known":
        return None, f"DOMESTIC_PRESSURE_{label}_STATUS_INVALID"
    raw = item.get("raw")
    raw_hex = item.get("raw_hex")
    if type(raw) is not int or not _INT32_MIN <= raw <= _INT32_MAX:
        return None, f"DOMESTIC_PRESSURE_{label}_RAW_INVALID"
    if not isinstance(raw_hex, str) or re.fullmatch(r"[0-9a-fA-F]{8}", raw_hex) is None:
        return None, f"DOMESTIC_PRESSURE_{label}_RAW_HEX_INVALID"
    try:
        decoded = int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True)
    except ValueError:
        return None, f"DOMESTIC_PRESSURE_{label}_RAW_HEX_INVALID"
    if decoded != raw:
        return None, f"DOMESTIC_PRESSURE_{label}_RAW_MISMATCH"
    # The native reader must state these semantics explicitly.  A missing
    # unit/scale is as unsafe as an incorrect one.
    if "unit" not in item or item.get("unit") != _UNITS[field]:
        return None, f"DOMESTIC_PRESSURE_{label}_UNIT_INVALID"
    if "scale" not in item or type(item.get("scale")) is not int or item.get("scale") != 1000:
        return None, f"DOMESTIC_PRESSURE_{label}_SCALE_INVALID"
    if field == "religious_unity":
        from .religious_unity_memory import validate_record
        if not validate_record(item):
            return None, f"DOMESTIC_PRESSURE_{label}_UNITY_CALCULATION_INVALID"
    if field == "overextension":
        from .overextension_memory import validate_record
        if not validate_record(item):
            return None, f"DOMESTIC_PRESSURE_{label}_OVEREXTENSION_CACHE_INVALID"
    if field == "unrest":
        from .average_unrest_memory import validate_record
        if not validate_record(item):
            return None, f"DOMESTIC_PRESSURE_{label}_AVERAGE_UNREST_CACHE_INVALID"
    return (raw, raw_hex.lower(), item["unit"], item["scale"]), None


def _field_value(report: dict[str, Any], field: str) -> dict[str, Any]:
    field_results = report.get("field_results")
    if not isinstance(field_results, dict) or field not in field_results:
        return _unknown("DOMESTIC_PRESSURE_FIELD_MISSING")
    top_record, reason = _validated_field_record(field_results[field], field, "FIELD")
    if reason is not None or top_record is None:
        return _unknown(reason or "DOMESTIC_PRESSURE_FIELD_INVALID")
    values = report.get("values")
    if not isinstance(values, dict) or field not in values or type(values[field]) is not int or values[field] != top_record[0]:
        return _unknown("DOMESTIC_PRESSURE_VALUES_MISMATCH")
    for snapshot_name in ("before", "after"):
        snapshot = report.get(snapshot_name)
        if not isinstance(snapshot, dict):
            return _unknown(f"DOMESTIC_PRESSURE_{snapshot_name.upper()}_FIELD_MISSING")
        snapshot_fields = snapshot.get("field_results")
        if not isinstance(snapshot_fields, dict) or field not in snapshot_fields:
            return _unknown(f"DOMESTIC_PRESSURE_{snapshot_name.upper()}_FIELD_MISSING")
        snapshot_record, snapshot_reason = _validated_field_record(
            snapshot_fields[field], field, f"{snapshot_name.upper()}_FIELD"
        )
        if snapshot_reason is not None or snapshot_record is None:
            return _unknown(snapshot_reason or f"DOMESTIC_PRESSURE_{snapshot_name.upper()}_FIELD_INVALID")
        if snapshot_record != top_record:
            return _unknown("DOMESTIC_PRESSURE_FIELD_SNAPSHOT_MISMATCH")
    raw, raw_hex, _unit, _scale = top_record
    result = _known(raw, raw_hex, field)
    if field == "religious_unity":
        calculation = field_results[field]["calculation"]
        inputs = calculation["inputs"]
        result.update(basis=calculation["basis"], upper_clamp=False,
                      value_origin="derived_from_copied_native_inputs",
                      components={"province_component_raw": inputs.get("province_component_raw"),
                                  "modifier_raw": inputs.get("unity_modifier", {}).get("base_raw"),
                                  "special_rule_forced": inputs["special_rule"]["base_raw"] != 0
                                  and bool(inputs["special_rule"]["type_flags"] & 0x40)})
    if field == "overextension":
        result.update(basis="native_ui_current_cache", value_origin="copied_native_ui_cache")
    if field == "unrest":
        result.update(basis="native_country_average_unrest_cache",
                      value_origin="copied_native_country_average_cache")
    return result


_CATALOG_ITEM = {
    "topic_id": "N04",
    "catalog_ids": ["N04"],
    "title": "本国国内压力（原生只读字段）",
    "status": "available",
    "fields": {
        field: {
            # Fixed-build FRA query and paused periodic reads have separate
            # native-reference and real MCP acceptance evidence.
            "coverage": "available",
            "runtime_validation": "validated",
            "source": "bridge.information.domestic_pressure_memory.capture",
            "unit": _UNITS[field],
            "scale": 1000,
            "raw": True,
            "raw_semantics": f"field_results.{field}.raw / 1000",
            "paths": [f"field_results.{field}.raw"],
            "supported_countries": [_COUNTRY],
        }
        for field in _FIELDS
    },
    "object_types": ["country"],
    "observer_roles": ["country"],
    "observer_scope": [_COUNTRY],
    "parameters": {
        "type": "object", "properties": {}, "required": [], "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic", "change"],
    "runtime_validation": "validated",
    "change_detection": "sampled_state_comparison_not_lossless_events",
    "source": "NativeDomesticPressureSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "只读取显式请求的FRA观察国家；不由存档、用户路径或公开外交检查推导国内资源。"
        " 固定1.37.4的主动查询和暂停时周期读取已实机核验；"
        "变化采样仍不等同于无损事件，双遍读取不保证主线程原子快照或世界代际。"
    ),
}

_CATALOG_ITEM["fields"]["religious_unity"].update(
    coverage="partial", runtime_validation="normal_cache_without_processors_observed",
    value_origin="derived_from_copied_native_inputs", upper_clamp=False,
    supported_path="non_calculating_cache_without_modifier_processors",
    gaps=["MODIFIER_PROCESSOR_PATHS_NOT_IMPLEMENTED", "CALCULATING_CACHE_PATH_NOT_IMPLEMENTED"],
)
_CATALOG_ITEM["scope_note"] += (
    " 宗教统一按界面不截上限的getter计算，当前仅覆盖非计算中缓存且相关处理器为空的路径；"
    "处理器与计算中缓存路径保留partial及具体缺项。"
)
_CATALOG_ITEM["fields"]["overextension"].update(value_origin="copied_native_ui_cache")
_CATALOG_ITEM["scope_note"] += " 过度扩张读取国家界面采用的当前缓存，不重新计算或采用选定和约预览。"
_CATALOG_ITEM["fields"]["unrest"].update(
    value_origin="copied_native_country_average_cache",
    value_semantics="national_average_unrest",
)
_CATALOG_ITEM["scope_note"] += " 叛乱度读取average_unrest国家平均缓存，保留负值，不以全国叛乱修正替代。"


class NativeDomesticPressureSource:
    """Expose stored N04 scalars and the supported effective-unity path."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None):
        self.base_source = base_source
        self.capture = capture

    def context(self) -> dict[str, Any]:
        try:
            context = self.base_source.context()
        except Exception as exc:
            raise InformationError("source_context", f"base source context failed: {type(exc).__name__}") from exc
        if not isinstance(context, dict):
            raise InformationError("source_context", "base source context must be an object")
        canonical(context)
        return _copy(context)

    def catalog(self) -> list[dict[str, Any]]:
        return [deepcopy(_CATALOG_ITEM)]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError(
                "invalid_parameters",
                f"N04 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != "N04":
            raise InformationError("unknown_topic", "NativeDomesticPressureSource supports N04 only")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"}:
            raise InformationError("invalid_object", "N04 queries require type and country only")
        if obj.get("type") != "country" or obj.get("country") != _COUNTRY:
            raise InformationError("observer_scope_mismatch", "N04 supports the verified FRA observer only")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError("invalid_fields", "N04 fields must be a non-empty list of unique strings")
        unknown = set(fields) - set(_FIELDS)
        if unknown:
            raise InformationError("unknown_field", f"N04 fields are outside the native adapter: {sorted(unknown)}")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "N04 parameters must be an empty object")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            if context.get("observer") is not None and context.get("observer") != _COUNTRY:
                raise InformationError("observer_scope_mismatch", "N04 is outside the verified FRA observer scope")
        normalized = {
            "topic": "N04", "object": deepcopy(obj), "fields": list(fields), "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _failure_fields(fields: list[str], reason: str, *, unavailable: bool) -> dict[str, dict[str, Any]]:
        factory = _unavailable if unavailable else _unknown
        return {field: factory(reason) for field in fields}

    @staticmethod
    def _result(
        normalized: dict[str, Any], context: dict[str, Any], fields: dict[str, dict[str, Any]],
        complete: bool, provenance: dict[str, Any], *, source_complete: bool | None = None,
    ) -> dict[str, Any]:
        return _result(
            normalized,
            context,
            fields,
            complete,
            _source_info(
                "NativeDomesticPressureSource",
                context,
                complete=complete if source_complete is None else source_complete,
                provenance=provenance,
            ),
        )

    def _capture_reader(self):
        if self.capture is not None:
            return self.capture
        try:
            from .domestic_pressure_memory import capture
        except Exception:
            return None
        return capture

    def read(self, query: dict, context: dict | None = None) -> dict:
        supplied = _copy(context) if isinstance(context, dict) else None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        try:
            before = self.context()
        except InformationError:
            before = current
        reason = _context_reason(before)
        if reason is not None:
            return self._result(
                normalized, before,
                self._failure_fields(normalized["fields"], reason, unavailable=True),
                False, _provenance(reason=reason), source_complete=False,
            )
        if supplied is not None:
            supplied_reason = _context_reason(supplied)
            if supplied_reason is not None:
                return self._result(
                    normalized, before,
                    self._failure_fields(normalized["fields"], supplied_reason, unavailable=True),
                    False, _provenance(reason=supplied_reason), source_complete=False,
                )
            if (
                _identity_snapshot(supplied) != _identity_snapshot(before)
                or not dates_match(supplied["game_date"], before["game_date"])
            ):
                reason = "DOMESTIC_PRESSURE_CONTEXT_CHANGED_BEFORE_CAPTURE"
                return self._result(
                    normalized, before,
                    self._failure_fields(normalized["fields"], reason, unavailable=True),
                    False, _provenance(reason=reason), source_complete=False,
                )
        installation, creation_filetime, binding_reason = _session_binding(self.base_source, before)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = binding_reason or "DOMESTIC_PRESSURE_INSTALLATION_UNAVAILABLE"
            return self._result(
                normalized, before,
                self._failure_fields(normalized["fields"], reason, unavailable=True),
                False, _provenance(reason=reason), source_complete=False,
            )
        capture = self._capture_reader()
        if not callable(capture):
            reason = "DOMESTIC_PRESSURE_CAPTURE_UNAVAILABLE"
            return self._result(
                normalized, before,
                self._failure_fields(normalized["fields"], reason, unavailable=True),
                False, _provenance(reason=reason), source_complete=False,
            )
        try:
            report = capture(installation, _COUNTRY, list(normalized["fields"]))
        except Exception as exc:
            reason = "DOMESTIC_PRESSURE_CAPTURE_FAILED:" + type(exc).__name__
            return self._result(
                normalized, before,
                self._failure_fields(normalized["fields"], reason, unavailable=True),
                False, _provenance(reason=reason), source_complete=False,
            )
        audit = _provenance(report if isinstance(report, dict) else None)
        global_reason = _global_report_reason(report, before, creation_filetime)
        if global_reason is not None:
            return self._result(
                normalized, before,
                self._failure_fields(normalized["fields"], global_reason, unavailable=False),
                False, dict(audit, reason=global_reason), source_complete=False,
            )
        try:
            after = self.context()
        except InformationError:
            after = {}
        after_reason = _context_reason(after)
        supplied_date = supplied["game_date"] if supplied is not None else before["game_date"]
        dates_stable = (
            type(after.get("game_date")) is int
            and dates_match(supplied_date, before["game_date"], after["game_date"])
        )
        if after_reason is not None or _identity_snapshot(before) != _identity_snapshot(after) or not dates_stable:
            reason = after_reason or "DOMESTIC_PRESSURE_CONTEXT_CHANGED_DURING_CAPTURE"
            return self._result(
                normalized, before,
                self._failure_fields(normalized["fields"], reason, unavailable=False),
                False, dict(audit, reason=reason), source_complete=False,
            )
        fields = {field: _field_value(report, field) for field in normalized["fields"]}
        complete = all(item.get("status") == "known" for item in fields.values())
        provenance = dict(audit, context_guard={
            "status": "passed",
            "identity_keys": list(_CONTEXT_KEYS),
            "installation": "base_source.session.directory/installation.json",
        })
        return self._result(normalized, before, fields, complete, provenance)

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeDomesticPressureSource"]
