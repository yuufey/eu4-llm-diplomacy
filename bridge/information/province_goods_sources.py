"""Project one validated cached province modifier component for N09.

This is an internal delegate owned by NativeFinalAttributesSource. It does not
register a second N09 adapter or claim complete source attribution.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from importlib import import_module
import hashlib
import re
from typing import Any

from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _observer_context_reason as _base_reason,
    _identity,
    _session_binding,
)


FIELD = "source_breakdown"
FIELD_GOODS_SOURCE = "G02.province_goods_modifier_source"
BASIS = "native_cached_province_modifier_component_candidate"
BASIS_V2 = "native_cached_and_reconstructed_province_modifier_sources"
MODIFIER_INDEX = 21
MODIFIER_KEY = "trade_goods_size_modifier"
SCHEMA = "information.province_goods_sources_capture.v1"
INNER_SCHEMA = "information.province_goods_sources_observer_snapshot.v1"
SCHEMA_V2 = "information.province_modifier_sources_capture.v2"
INNER_SCHEMA_V2 = "information.province_modifier_sources_observer_snapshot.v2"
MAX_PROVINCE_ID = 0xFFFF
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_REASON = re.compile(r"[A-Za-z][A-Za-z0-9_:-]{0,255}\Z")
_SOURCE_KEY = re.compile(r"[\x20-\x7e]{1,255}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PASSPHASES = ("pass1", "pass2")
_GAPS = [
    "OTHER_PROVINCE_MODIFIER_CALLBACKS_NOT_CAPTURED",
    "PROVINCE_MODIFIER_CACHE_PHASE_UNRESOLVED",
    "PROVINCE_ACQUISITION_DELTA_NOT_CAPTURED",
    "SOURCE_KEY_NAMES_A_CACHED_DEFINITION_NOT_A_UNIQUE_RUNTIME_CAUSE",
]
_PUBLIC_COMPONENT_KEYS = {
    "province_id", "modifier_index", "modifier_key", "source_key",
    "aggregate_raw", "cached_component_raw", "residual_raw",
    "province_scale_input_raw", "scale", "current_only",
    "full_source_coverage", "descriptor_qualified",
}
_PUBLIC_FIELD_KEYS = {
    "status", "value", "unit", "scale", "period", "complete",
    "partial", "basis", "gaps",
}
_PUBLIC_FIELD_KEYS_V2 = _PUBLIC_FIELD_KEYS | {"projection_version"}
_V2_VALUE_KEYS = {
    "province_id", "modifier_index", "modifier_key", "aggregate_raw",
    "cached_components", "cached_sum_raw", "direct_sources", "direct_sum_raw",
    "residual_raw", "scale", "current_only", "full_source_coverage",
    "last_refresh_execution_observed", "descriptor_qualified",
}
_V2_CACHED_KNOWN_KEYS = {"status", "source_key", "raw", "scale"}
_V2_CACHED_UNKNOWN_KEYS = {"status", "source_key", "reason"}
_V2_DIRECT_BASE_KEYS = {
    "status", "source_key", "definition_raw", "enabled", "applied_raw",
    "scale", "basis", "last_refresh_execution_observed",
}
_V2_DIRECT_UNKNOWN_KEYS = _V2_DIRECT_BASE_KEYS | {"reason"}
_V2_DIRECT_KEYS = ("under_siege", "blockaded", "in_state", "prosperity")
_V2_DIRECT_BASIS = "current_native_condition_reconstruction"
_V2_GAPS = [
    "OTHER_PROVINCE_MODIFIER_CALLBACKS_NOT_CAPTURED",
    "PROVINCE_MODIFIER_CACHE_PHASE_UNRESOLVED",
    "PROVINCE_ACQUISITION_DELTA_NOT_CAPTURED",
]


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & (1 << 31) else value


def _field(status: str, reason: str | None = None, *, value: Any = None,
           projection_version: int = 1) -> dict[str, Any]:
    basis = BASIS_V2 if projection_version == 2 else BASIS
    result: dict[str, Any] = {
        "status": status,
        "unit": "attribute_breakdown_map",
        "scale": 1,
        "period": "current",
        "complete": False,
        "partial": True,
        "basis": basis,
        "gaps": list(_V2_GAPS if projection_version == 2 else _GAPS),
    }
    if projection_version == 2:
        result["projection_version"] = 2
    if reason is not None:
        result["reason"] = reason
    if status == "known":
        result["value"] = deepcopy(value)
    return result


def _public_reason(value: Any, fallback: str) -> str:
    if _valid_reason(value):
        return value
    return fallback


def _valid_reason(value: Any) -> bool:
    return (isinstance(value, str) and _REASON.fullmatch(value) is not None
            and "0x" not in value.lower())


def _valid_source_key(value: Any) -> bool:
    return (value is None or (isinstance(value, str) and len(value) <= 255
            and all(" " <= char <= "~" for char in value)
            and "0x" not in value.lower()))


def _valid_i32(value: Any) -> bool:
    return type(value) is int and _INT32_MIN <= value <= _INT32_MAX


def _positive_admission(value: Any, observer: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    role = value.get("observer_nonplayer_role")
    return (
        value.get("status") == "known"
        and type(value.get("admitted")) is bool
        and value["admitted"] is True
        and isinstance(role, Mapping)
        and role.get("observer") == observer
        and role.get("verified") is True
    )


def _positive_discovery(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("status") == "known"
        and type(value.get("value")) is bool
        and value["value"] is True
    )


def _backend_target(report: Any, province_id: int, observer: str,
                    projection_version: int = 1) -> tuple[dict[str, Any] | None, str | None]:
    outer_schema = SCHEMA_V2 if projection_version == 2 else SCHEMA
    inner_schema = INNER_SCHEMA_V2 if projection_version == 2 else INNER_SCHEMA
    if not isinstance(report, Mapping) or set(report) != {"schema", "observer", "object", "capture"}:
        return None, "PROVINCE_GOODS_SOURCES_CAPTURE_INVALID"
    if report.get("schema") != outer_schema:
        return None, "PROVINCE_GOODS_SOURCES_CAPTURE_INVALID"
    if report.get("observer") != observer:
        return None, "PROVINCE_GOODS_SOURCES_CAPTURE_OBSERVER_MISMATCH"
    outer = report.get("object")
    if (not isinstance(outer, Mapping) or set(outer) != {"type", "province_id"}
            or outer.get("type") != "province"
            or type(outer.get("province_id")) is not int
            or outer["province_id"] != province_id):
        return None, "PROVINCE_GOODS_SOURCES_CAPTURE_OBJECT_MISMATCH"
    inner = report.get("capture")
    observation = inner.get("observation") if isinstance(inner, Mapping) else None
    if (not isinstance(inner, Mapping) or inner.get("schema") != inner_schema
            or inner.get("status") != "observed" or inner.get("completed") is not True
            or not isinstance(observation, Mapping) or observation.get("stable") is not True):
        return None, "PROVINCE_GOODS_SOURCES_CAPTURE_OBSERVATION_UNSTABLE"
    backend = observation.get("backend")
    consistency = backend.get("consistency") if isinstance(backend, Mapping) else None
    if (not isinstance(backend, Mapping) or backend.get("status") != "observed"
            or not isinstance(consistency, Mapping) or consistency.get("status") != "stable"):
        return None, "PROVINCE_GOODS_SOURCES_BACKEND_UNSTABLE"
    backend_observer = backend.get("observer")
    if not isinstance(backend_observer, Mapping) or backend_observer.get("tag") != observer:
        return None, "PROVINCE_GOODS_SOURCES_BACKEND_OBSERVER_MISMATCH"
    targets = backend.get("targets")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], Mapping):
        return None, "PROVINCE_GOODS_SOURCES_BACKEND_TARGET_INVALID"
    target = targets[0]
    if type(target.get("province_id")) is not int or target["province_id"] != province_id:
        return None, "PROVINCE_GOODS_SOURCES_BACKEND_PROVINCE_MISMATCH"
    admissions = target.get("admission_by_pass")
    discoveries = target.get("discovery_by_pass")
    if (not isinstance(admissions, Mapping) or not isinstance(discoveries, Mapping)
            or any(not _positive_admission(admissions.get(phase), observer) for phase in _PASSPHASES)
            or any(not _positive_discovery(discoveries.get(phase)) for phase in _PASSPHASES)):
        return None, "PROVINCE_GOODS_SOURCES_ADMISSION_OR_DISCOVERY_UNVERIFIED"
    field_consistency = target.get("field_consistency")
    if (not isinstance(field_consistency, Mapping)
            or not isinstance(field_consistency.get(FIELD_GOODS_SOURCE), Mapping)):
        return None, "PROVINCE_GOODS_SOURCES_FIELD_CONSISTENCY_MISSING"
    consistency_status = field_consistency[FIELD_GOODS_SOURCE].get("status")
    if consistency_status == "changed":
        return None, "PROVINCE_GOODS_SOURCES_FIELD_CHANGED_BETWEEN_PASSES"
    if consistency_status not in ("stable", "unknown"):
        return None, "PROVINCE_GOODS_SOURCES_FIELD_CONSISTENCY_INVALID"
    fields = target.get("fields")
    if not isinstance(fields, Mapping) or set(fields) != {FIELD_GOODS_SOURCE}:
        return None, "PROVINCE_GOODS_SOURCES_FIELD_MISSING"
    return dict(target), None


def _project_component(target: Mapping[str, Any], province_id: int,
                       projection_version: int = 1) -> dict[str, Any]:
    if projection_version == 2:
        return _project_v2_component(target, province_id)
    return _project_v1_component(target, province_id)


def _project_v1_component(target: Mapping[str, Any], province_id: int) -> dict[str, Any]:
    fields = target.get("fields")
    raw = fields.get(FIELD_GOODS_SOURCE) if isinstance(fields, Mapping) else None
    if not isinstance(raw, Mapping):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_MISSING")
    status = raw.get("status")
    if status != "known":
        reason = _public_reason(raw.get("reason"), "PROVINCE_GOODS_SOURCES_OBSERVATION_UNKNOWN")
        return _field("unknown", reason)
    consistency = target.get("field_consistency")
    item_consistency = consistency.get(FIELD_GOODS_SOURCE) if isinstance(consistency, Mapping) else None
    if not isinstance(item_consistency, Mapping):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_NOT_STABLE")
    if item_consistency.get("status") == "unknown":
        return _field("unknown", _public_reason(
            item_consistency.get("reason"), "PROVINCE_GOODS_SOURCES_FIELD_CONSISTENCY_UNKNOWN"))
    if item_consistency.get("status") != "stable":
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_NOT_STABLE")
    value = raw.get("value")
    if (not isinstance(value, Mapping) or set(value) != _PUBLIC_COMPONENT_KEYS
            or raw.get("complete") is not False or raw.get("basis") != BASIS
            or raw.get("period") != "current"):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_INVALID")
    if (type(value.get("province_id")) is not int or value["province_id"] != province_id
            or type(value.get("modifier_index")) is not int or value["modifier_index"] != MODIFIER_INDEX
            or value.get("modifier_key") != MODIFIER_KEY
            or not isinstance(value.get("source_key"), str)
            or _SOURCE_KEY.fullmatch(value["source_key"]) is None
            or "0x" in value["source_key"].lower()
            or type(value.get("scale")) is not int or value["scale"] != 1000
            or type(value.get("current_only")) is not bool or value["current_only"] is not True
            or type(value.get("full_source_coverage")) is not bool
            or value["full_source_coverage"] is not False
            or type(value.get("descriptor_qualified")) is not bool
            or value["descriptor_qualified"] is not True):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_COMPONENT_INVALID")
    signed_values = (value.get("aggregate_raw"), value.get("cached_component_raw"),
                     value.get("residual_raw"), value.get("province_scale_input_raw"))
    if any(type(item) is not int or not _INT32_MIN <= item <= _INT32_MAX for item in signed_values):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_ARITHMETIC_INVALID")
    if value["province_scale_input_raw"] <= 0:
        return _field("unknown", "PROVINCE_GOODS_SOURCES_SCALE_INPUT_INVALID")
    if _i32(value["aggregate_raw"] - value["cached_component_raw"]) != value["residual_raw"]:
        return _field("unknown", "PROVINCE_GOODS_SOURCES_RESIDUAL_MISMATCH")
    component = {
        "province_id": province_id,
        "modifier_index": MODIFIER_INDEX,
        "modifier_key": MODIFIER_KEY,
        "source_key": value["source_key"],
        "aggregate_raw": value["aggregate_raw"],
        "cached_component_raw": value["cached_component_raw"],
        "residual_raw": value["residual_raw"],
        "province_scale_input_raw": value["province_scale_input_raw"],
        "scale": 1000,
        "current_only": True,
        "full_source_coverage": False,
        "descriptor_qualified": True,
    }
    return _field("known", value={MODIFIER_KEY: component})


def _project_v2_component(target: Mapping[str, Any], province_id: int) -> dict[str, Any]:
    fields = target.get("fields")
    raw = fields.get(FIELD_GOODS_SOURCE) if isinstance(fields, Mapping) else None
    if not isinstance(raw, Mapping):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_MISSING", projection_version=2)
    if raw.get("status") != "known":
        reason = _public_reason(raw.get("reason"), "PROVINCE_GOODS_SOURCES_OBSERVATION_UNKNOWN")
        return _field("unknown", reason, projection_version=2)
    consistency = target.get("field_consistency")
    item_consistency = consistency.get(FIELD_GOODS_SOURCE) if isinstance(consistency, Mapping) else None
    if not isinstance(item_consistency, Mapping):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_NOT_STABLE", projection_version=2)
    if item_consistency.get("status") == "unknown":
        return _field("unknown", _public_reason(
            item_consistency.get("reason"), "PROVINCE_GOODS_SOURCES_FIELD_CONSISTENCY_UNKNOWN"),
            projection_version=2)
    if item_consistency.get("status") != "stable":
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_NOT_STABLE", projection_version=2)

    value = raw.get("value")
    if (not isinstance(value, Mapping) or set(value) != _V2_VALUE_KEYS
            or raw.get("complete") is not False or raw.get("basis") != BASIS_V2
            or raw.get("period") != "current"):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_FIELD_INVALID", projection_version=2)
    if (type(province_id) is not int or not 1 <= province_id <= MAX_PROVINCE_ID
            or type(value.get("province_id")) is not int or value["province_id"] != province_id
            or type(value.get("modifier_index")) is not int or value["modifier_index"] != MODIFIER_INDEX
            or value.get("modifier_key") != MODIFIER_KEY
            or type(value.get("scale")) is not int or value["scale"] != 1000
            or value.get("current_only") is not True or type(value.get("current_only")) is not bool
            or value.get("full_source_coverage") is not False
            or type(value.get("full_source_coverage")) is not bool
            or value.get("last_refresh_execution_observed") is not False
            or type(value.get("last_refresh_execution_observed")) is not bool
            or value.get("descriptor_qualified") is not True
            or type(value.get("descriptor_qualified")) is not bool
            or not _valid_i32(value.get("aggregate_raw"))):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_COMPONENT_INVALID", projection_version=2)

    cached = value.get("cached_components")
    if not isinstance(cached, list) or len(cached) != 23:
        return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_COMPONENTS_INVALID", projection_version=2)
    cached_values: list[int] = []
    cached_complete = True
    for row in cached:
        if not isinstance(row, Mapping):
            return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_COMPONENT_INVALID", projection_version=2)
        source_key = row.get("source_key")
        if not _valid_source_key(source_key):
            return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_SOURCE_KEY_INVALID", projection_version=2)
        if row.get("status") == "known":
            if (set(row) != _V2_CACHED_KNOWN_KEYS or not _valid_i32(row.get("raw"))
                    or type(row.get("scale")) is not int or row["scale"] != 1000):
                return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_COMPONENT_INVALID", projection_version=2)
            cached_values.append(row["raw"])
        elif row.get("status") == "unknown":
            if (set(row) != _V2_CACHED_UNKNOWN_KEYS
                    or not _valid_reason(row.get("reason"))):
                return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_COMPONENT_INVALID", projection_version=2)
            cached_complete = False
        else:
            return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_COMPONENT_INVALID", projection_version=2)
    expected_cached_sum = _i32(sum(cached_values)) if cached_complete else None
    if value.get("cached_sum_raw") != expected_cached_sum:
        return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_SUM_MISMATCH", projection_version=2)
    if expected_cached_sum is not None and not _valid_i32(value.get("cached_sum_raw")):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_CACHED_SUM_INVALID", projection_version=2)

    direct = value.get("direct_sources")
    if not isinstance(direct, list) or len(direct) != len(_V2_DIRECT_KEYS):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_SOURCES_INVALID", projection_version=2)
    direct_values: list[int] = []
    direct_complete = True
    for key, row in zip(_V2_DIRECT_KEYS, direct):
        if not isinstance(row, Mapping) or row.get("source_key") != key:
            return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_SOURCE_KEY_INVALID", projection_version=2)
        if row.get("status") == "known":
            if (set(row) != _V2_DIRECT_BASE_KEYS
                    or row.get("definition_raw") is not None and not _valid_i32(row.get("definition_raw"))
                    or type(row.get("enabled")) is not bool
                    or not _valid_i32(row.get("applied_raw"))
                    or type(row.get("scale")) is not int or row["scale"] != 1000
                    or row.get("basis") != _V2_DIRECT_BASIS
                    or row.get("last_refresh_execution_observed") is not False
                    or type(row.get("last_refresh_execution_observed")) is not bool):
                return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_SOURCE_INVALID", projection_version=2)
            definition_raw = row.get("definition_raw")
            if ((row["enabled"] is True and
                    (not _valid_i32(definition_raw) or row["applied_raw"] != definition_raw))
                    or (row["enabled"] is False and row["applied_raw"] != 0)):
                return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_CONDITION_INVALID", projection_version=2)
            direct_values.append(row["applied_raw"])
        elif row.get("status") == "unknown":
            if (set(row) != _V2_DIRECT_UNKNOWN_KEYS
                    or row.get("definition_raw") is not None and not _valid_i32(row.get("definition_raw"))
                    or row.get("enabled") is not None or row.get("applied_raw") is not None
                    or type(row.get("scale")) is not int or row["scale"] != 1000
                    or row.get("basis") != _V2_DIRECT_BASIS
                    or row.get("last_refresh_execution_observed") is not False
                    or type(row.get("last_refresh_execution_observed")) is not bool
                    or not _valid_reason(row.get("reason"))):
                return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_SOURCE_INVALID", projection_version=2)
            direct_complete = False
        else:
            return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_SOURCE_INVALID", projection_version=2)
    expected_direct_sum = _i32(sum(direct_values)) if direct_complete else None
    if value.get("direct_sum_raw") != expected_direct_sum:
        return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_SUM_MISMATCH", projection_version=2)
    if expected_direct_sum is not None and not _valid_i32(value.get("direct_sum_raw")):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_DIRECT_SUM_INVALID", projection_version=2)

    expected_residual = (
        _i32(value["aggregate_raw"] - expected_cached_sum - expected_direct_sum)
        if expected_cached_sum is not None and expected_direct_sum is not None else None
    )
    if value.get("residual_raw") != expected_residual:
        return _field("unknown", "PROVINCE_GOODS_SOURCES_RESIDUAL_MISMATCH", projection_version=2)
    if expected_residual is not None and not _valid_i32(value.get("residual_raw")):
        return _field("unknown", "PROVINCE_GOODS_SOURCES_RESIDUAL_INVALID", projection_version=2)

    component = {key: deepcopy(value[key]) for key in _V2_VALUE_KEYS}
    return _field("known", value={MODIFIER_KEY: component}, projection_version=2)


def validate_public_breakdown(field: Any, province_id: int) -> dict[str, Any]:
    """Revalidate the N09 projection crossing the internal delegate boundary."""
    if not isinstance(field, Mapping):
        raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_FIELD_INVALID")
    status = field.get("status")
    if status != "known":
        if status not in {"unknown", "unavailable"}:
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_STATE_INVALID")
        reason = field.get("reason")
        if not isinstance(reason, str) or len(reason) > 256:
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_REASON_INVALID")
        version = field.get("projection_version")
        if version is None:
            return {"status": status, "reason": reason}
        if type(version) is not int or version != 2:
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_STATE_INVALID")
        if set(field) == {"status", "reason", "projection_version"}:
            return {"status": status, "reason": reason, "projection_version": 2}
        expected_unknown = _field(status, reason, projection_version=2)
        if dict(field) != expected_unknown:
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_STATE_INVALID")
        return deepcopy(expected_unknown)
    projection_version = field.get("projection_version", 1)
    if type(projection_version) is not int or projection_version not in (1, 2):
        raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_VERSION_INVALID")
    if projection_version == 2:
        if (set(field) != _PUBLIC_FIELD_KEYS_V2 or field.get("projection_version") != 2
                or field.get("unit") != "attribute_breakdown_map"
                or type(field.get("scale")) is not int or field["scale"] != 1
                or field.get("period") != "current" or field.get("complete") is not False
                or field.get("partial") is not True or field.get("basis") != BASIS_V2
                or field.get("gaps") != _V2_GAPS):
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_CONTRACT_INVALID")
        values = field.get("value")
        if not isinstance(values, Mapping) or set(values) != {MODIFIER_KEY}:
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_VALUE_INVALID")
        component = values[MODIFIER_KEY]
        if not isinstance(component, Mapping) or set(component) != _V2_VALUE_KEYS:
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_COMPONENT_INVALID")
        candidate = {
            "fields": {FIELD_GOODS_SOURCE: {
                "status": "known", "value": dict(component), "complete": False,
                "period": "current", "basis": BASIS_V2,
            }},
            "field_consistency": {FIELD_GOODS_SOURCE: {"status": "stable"}},
        }
        projected = _project_component(candidate, province_id, projection_version=2)
        if projected.get("status") != "known" or projected != dict(field):
            raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_COMPONENT_INVALID")
        return deepcopy(dict(field))
    if (set(field) != _PUBLIC_FIELD_KEYS or field.get("unit") != "attribute_breakdown_map"
            or type(field.get("scale")) is not int or field["scale"] != 1
            or field.get("period") != "current" or field.get("complete") is not False
            or field.get("partial") is not True or field.get("basis") != BASIS
            or field.get("gaps") != _GAPS):
        raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_CONTRACT_INVALID")
    values = field.get("value")
    if not isinstance(values, Mapping) or set(values) != {MODIFIER_KEY}:
        raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_VALUE_INVALID")
    component = values[MODIFIER_KEY]
    if not isinstance(component, Mapping) or set(component) != _PUBLIC_COMPONENT_KEYS:
        raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_COMPONENT_INVALID")
    # Reuse the leaf-level validator by constructing the smallest target shape.
    candidate = {
        "fields": {FIELD_GOODS_SOURCE: {
            "status": "known", "value": dict(component), "complete": False,
            "period": "current", "basis": BASIS,
        }},
        "field_consistency": {FIELD_GOODS_SOURCE: {"status": "stable"}},
    }
    projected = _project_component(candidate, province_id, projection_version=1)
    if projected.get("status") != "known" or projected != dict(field):
        raise ValueError("FINAL_ATTRIBUTES_PROVINCE_BREAKDOWN_COMPONENT_INVALID")
    return deepcopy(dict(field))


class NativeProvinceGoodsSourceBreakdownSource(NativeTradeIncomeSource):
    """Capture and project one candidate cached province goods modifier."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None, projection_version: int = 1):
        if type(projection_version) is not int or projection_version not in (1, 2):
            raise ValueError("PROVINCE_GOODS_SOURCES_PROJECTION_VERSION_INVALID")
        super().__init__(base_source, capture=capture)
        self.projection_version = projection_version

    def catalog(self) -> list[dict[str, Any]]:
        # This is an internal delegate. N09 has one public field owner.
        return []

    def validate_query(self, query: Any, context: dict[str, Any] | None = None) -> dict[str, Any]:
        if (not isinstance(query, dict)
                or not {"topic", "object", "fields"} <= set(query)
                or set(query) - {"topic", "object", "fields", "parameters"}):
            raise InformationError("invalid_parameters", "N09 province breakdown query has missing or unknown keys")
        if query["topic"] != "N09":
            raise InformationError("unknown_topic", "Province goods source supports N09 only")
        obj = query["object"]
        if (not isinstance(obj, dict) or set(obj) != {"type", "province_id"}
                or obj.get("type") != "province" or type(obj.get("province_id")) is not int
                or not 1 <= obj["province_id"] <= MAX_PROVINCE_ID):
            raise InformationError("invalid_object", "N09 province breakdown requires a bounded province_id")
        if query["fields"] != [FIELD]:
            raise InformationError("invalid_fields", "Province goods source supports source_breakdown only")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "N09 province breakdown has no extra parameters")
        if context is not None and not isinstance(context, dict):
            raise InformationError("invalid_context", "N09 province breakdown context must be an object")
        normalized = {
            "topic": "N09", "object": deepcopy(obj), "fields": [FIELD], "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        reason = _base_reason(context)
        return reason.replace("TRADE_INCOME_", "PROVINCE_GOODS_SOURCES_", 1) if reason else None

    def _result_for(self, query: dict[str, Any], context: dict[str, Any], field: dict[str, Any],
                    provenance: dict[str, Any]) -> dict[str, Any]:
        source = _source_info(
            "NativeProvinceGoodsSourceBreakdownSource",
            context,
            complete=False,
            provenance=deepcopy(provenance),
        )
        if field.get("status") == "unavailable":
            source["status"] = "unavailable"
        source.update(context_scope="visible_scope", projection_version=self.projection_version)
        return _result(query, context, {FIELD: field}, False, source)

    def _failure(self, query: dict[str, Any], context: dict[str, Any], reason: str,
                 provenance: dict[str, Any], *, unavailable: bool = False) -> dict[str, Any]:
        field = _field("unavailable" if unavailable else "unknown", reason,
                       projection_version=self.projection_version)
        return self._result_for(query, context, field, provenance)

    def read(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        province_id = normalized["object"]["province_id"]
        observer = current.get("observer")
        provenance: dict[str, Any] = {
            "observer": observer, "province_id": province_id,
            "read_only": True, "native_function_invoked": False,
            "basis": BASIS_V2 if self.projection_version == 2 else BASIS,
            "full_source_coverage": False,
        }

        reason = self._context_reason(current)
        if reason:
            return self._failure(normalized, current, reason, provenance, unavailable=True)
        try:
            before = self.context()
        except Exception:
            return self._failure(normalized, current, "PROVINCE_GOODS_SOURCES_CONTEXT_UNAVAILABLE",
                                 provenance, unavailable=True)
        reason = self._context_reason(before)
        if reason:
            return self._failure(normalized, before, reason, provenance, unavailable=True)
        if _identity(current) != _identity(before):
            return self._failure(normalized, before, "PROVINCE_GOODS_SOURCES_CONTEXT_STALE",
                                 provenance, unavailable=True)

        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return self._failure(
                normalized, before,
                binding_reason or "PROVINCE_GOODS_SOURCES_INSTALLATION_UNAVAILABLE",
                provenance, unavailable=True,
            )
        try:
            module_name = (".province_modifier_sources_capture" if self.projection_version == 2
                           else ".province_goods_sources_capture")
            module = import_module(module_name, __package__)
        except Exception:
            return self._failure(normalized, before, "PROVINCE_GOODS_SOURCES_CAPTURE_UNAVAILABLE",
                                 provenance, unavailable=True)
        capture = self.capture if self.capture is not None else getattr(module, "capture", None)
        validator = getattr(module, "validate_capture", None)
        if not callable(capture) or not callable(validator):
            return self._failure(normalized, before, "PROVINCE_GOODS_SOURCES_CAPTURE_UNAVAILABLE",
                                 provenance, unavailable=True)

        report = None
        capture_error = None
        try:
            report = capture(installation, province_id=province_id, observer=observer)
        except Exception as exc:
            capture_error = f"PROVINCE_GOODS_SOURCES_CAPTURE_FAILED:{type(exc).__name__}"
        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _identity(before) != _identity(after):
            return self._failure(normalized, before,
                                 "PROVINCE_GOODS_SOURCES_CONTEXT_CHANGED_DURING_CAPTURE",
                                 provenance, unavailable=True)
        final_installation, final_creation, final_reason = _session_binding(self.base_source)
        if (final_reason or final_installation != installation or final_creation != creation):
            return self._failure(normalized, before,
                                 "PROVINCE_GOODS_SOURCES_SESSION_CHANGED_DURING_CAPTURE",
                                 provenance, unavailable=True)
        if capture_error:
            return self._failure(normalized, before, capture_error, provenance)

        try:
            valid = validator(report, before, creation, province_id)
        except Exception:
            valid = False
        if valid is not True:
            return self._failure(normalized, before, "PROVINCE_GOODS_SOURCES_CAPTURE_INVALID", provenance)

        target, envelope_error = _backend_target(report, province_id, observer, self.projection_version)
        if target is None:
            return self._failure(normalized, before,
                                 envelope_error or "PROVINCE_GOODS_SOURCES_CAPTURE_INVALID", provenance)
        observation = report["capture"]["observation"]
        if (observation.get("context_before", {}).get("game_date") != before.get("game_date")
                or observation.get("context_after", {}).get("game_date") != before.get("game_date")):
            return self._failure(normalized, before, "PROVINCE_GOODS_SOURCES_CAPTURE_DATE_MISMATCH", provenance)
        try:
            provenance["capture_report_sha256"] = hashlib.sha256(
                canonical(report).encode("utf-8")
            ).hexdigest()
        except Exception:
            return self._failure(normalized, before, "PROVINCE_GOODS_SOURCES_CAPTURE_INVALID", provenance)
        profile_hash = getattr(module, "PROFILE_SHA256", None)
        if isinstance(profile_hash, str) and _SHA.fullmatch(profile_hash):
            provenance["profile_sha256"] = profile_hash

        field = _project_component(target, province_id, self.projection_version)
        return self._result_for(normalized, before, field, provenance)


__all__ = [
    "BASIS", "BASIS_V2", "FIELD", "FIELD_GOODS_SOURCE", "MODIFIER_INDEX", "MODIFIER_KEY",
    "SCHEMA", "INNER_SCHEMA", "SCHEMA_V2", "INNER_SCHEMA_V2",
    "NativeProvinceGoodsSourceBreakdownSource", "validate_public_breakdown",
]
