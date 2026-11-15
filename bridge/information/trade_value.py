"""Read-only T03 trade-node cache adapter for the verified FRA observer.

This source exposes the four projected node-value caches.  Collection value
remains unknown because the current native evidence does not establish it.
The adapter never invokes game functions and does not claim that a UI rendered
the projected values.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import os
import re
from typing import Any, Mapping

from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import _context_reason as _base_context_reason
from .trade_income import _identity as _base_identity
from .trade_income import _session_binding


_TOPIC = "T03"
_COUNTRY = "FRA"
_VERSION = "1.37.4"
_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_SOURCE = "bridge.information.trade_value_capture_v2.capture"
_UNIT = "ducats"
_SCALE = 1000
_PERIOD = "current"
_VALUE_FIELDS = (
    "local_value", "incoming_value", "total_value", "outgoing_value",
)
_FIELDS = frozenset((*_VALUE_FIELDS, "collected_value"))
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SAFE_TEXT = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_HEX32 = re.compile(r"[0-9a-fA-F]{8}\Z")
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_I32_MASK = (1 << 32) - 1
_MAX_OUTGOING_ROUTES = 1024
def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _int32(value: Any) -> bool:
    return type(value) is int and _I32_MIN <= value <= _I32_MAX


def _reason(value: Any, fallback: str) -> str:
    if isinstance(value, str) and _SAFE_TEXT.fullmatch(value):
        return value
    return fallback


def _hash_report(report: Any) -> str | None:
    try:
        return hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
    except Exception:
        return None


def _binding_path(path: Any) -> str | None:
    if path is None:
        return None
    try:
        return os.path.normcase(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError):
        return None


def _public_projected_field(name: str, item: Any) -> dict[str, Any]:
    """Validate and copy only the projector's public, typed field wrapper."""
    if not isinstance(item, Mapping):
        return _unknown("TRADE_VALUE_PROJECTED_FIELD_INVALID")
    status = item.get("status")
    if isinstance(status, str) and status in {"unknown", "invisible", "unavailable", "stale", "unsupported"}:
        return {"status": status, "reason": _reason(item.get("reason"), "TRADE_VALUE_FIELD_UNKNOWN")}
    if status != "known":
        return _unknown("TRADE_VALUE_PROJECTED_FIELD_INVALID")
    if item.get("unit") != _UNIT or type(item.get("scale")) is not int or item.get("scale") != _SCALE:
        return _unknown("TRADE_VALUE_PROJECTED_FIELD_INVALID")
    if item.get("complete") is not False:
        return _unknown("TRADE_VALUE_COMPLETENESS_NOT_PROVEN")

    value = item.get("value")
    result: dict[str, Any] = {"status": "known"}
    if name == "outgoing_value":
        if not isinstance(value, Mapping) or set(value) != {"total_raw", "routes"}:
            return _unknown("TRADE_VALUE_OUTGOING_SHAPE_INVALID")
        total_raw = value.get("total_raw")
        routes = value.get("routes")
        if not _int32(total_raw) or not isinstance(routes, list) or len(routes) > _MAX_OUTGOING_ROUTES:
            return _unknown("TRADE_VALUE_OUTGOING_SHAPE_INVALID")
        safe_routes = []
        for route in routes:
            if (not isinstance(route, Mapping) or not {"node_id", "raw"}.issubset(route)
                    or not isinstance(route.get("node_id"), str)
                    or _NODE_ID.fullmatch(route["node_id"]) is None
                    or route["node_id"] == "Null" or not _int32(route.get("raw"))):
                return _unknown("TRADE_VALUE_OUTGOING_ROUTE_INVALID")
            safe_routes.append({"node_id": route["node_id"], "raw": route["raw"]})
        result["value"] = {"total_raw": total_raw, "routes": safe_routes}
        if "raw" in item:
            raw = item.get("raw")
            if not _int32(raw) or raw != total_raw:
                return _unknown("TRADE_VALUE_OUTGOING_RAW_MISMATCH")
            result["raw"] = raw
    else:
        raw = item.get("raw")
        if not _int32(value) or not _int32(raw) or value != raw:
            return _unknown("TRADE_VALUE_SIGNED_RAW_INVALID")
        result["value"] = value
        result["raw"] = raw

    raw_hex = item.get("raw_hex")
    if raw_hex is not None:
        if not isinstance(raw_hex, str) or _HEX32.fullmatch(raw_hex) is None:
            return _unknown("TRADE_VALUE_RAW_HEX_INVALID")
        raw_value = value.get("total_raw") if name == "outgoing_value" else value
        if int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) != raw_value:
            return _unknown("TRADE_VALUE_RAW_HEX_MISMATCH")
        result["raw_hex"] = raw_hex.lower()

    result["unit"] = _UNIT
    result["scale"] = _SCALE
    for key in ("period", "basis", "value_origin"):
        val = item.get(key)
        if val is not None:
            if not isinstance(val, str) or _SAFE_TEXT.fullmatch(val) is None:
                return _unknown("TRADE_VALUE_PROJECTED_METADATA_INVALID")
            result[key] = val
    result["complete"] = False
    return result


class NativeTradeValueSource:
    """Expose bounded T03 trade-node caches for a logical FRA observer."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture: Any = None):
        self.base_source = base_source
        self.capture = capture

    def context(self) -> dict[str, Any]:
        try:
            context = self.base_source.context()
        except Exception as exc:
            raise InformationError("source_context", f"base source context failed: {type(exc).__name__}") from exc
        if not isinstance(context, Mapping):
            raise InformationError("source_context", "base source context must be an object")
        context = dict(context)
        canonical(context)
        return deepcopy(context)

    def catalog(self) -> list[dict[str, Any]]:
        common = {
            "coverage": "partial",
            "complete": False,
            "runtime_validation": "trade_value_capture_v2.validate_capture",
            "source": _SOURCE,
            "supported_observers": [_COUNTRY],
            "supported_object_types": ["trade_node"],
            "supported_versions": [_VERSION],
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "raw": True,
            "basis": "native_trade_node_value_cache",
            "gaps": ["ACTUAL_UI_RENDER_NOT_OBSERVED", "NATIVE_CACHE_FRESHNESS_NOT_PROVEN"],
        }
        descriptions = {
            "local_value": "节点本地产生价值的原生缓存，保留有符号32位杜卡特原始值。",
            "incoming_value": "对原生流入记录逐项累加，保留有符号32位的原生算术口径。",
            "total_value": "按原生界面算式计算本地值＋流入值－流出值，保留有符号32位回绕。",
            "outgoing_value": "原生流出总缓存及按目标节点列出的原始杜卡特分项。",
        }
        field_origins = {
            "local_value": ("native_trade_node_local_value_cache", "copied_native_trade_node_cache"),
            "incoming_value": ("native_trade_node_incoming_vector_signed32_sum", "derived_from_native_trade_node_cache_inputs"),
            "total_value": ("native_trade_node_ui_signed32_local_plus_incoming_minus_outgoing", "derived_from_native_trade_node_cache_inputs_and_native_ui_formula"),
            "outgoing_value": ("native_trade_node_outgoing_cache_and_route_vectors", "derived_from_native_trade_node_cache_inputs"),
        }
        fields = {
            name: {**deepcopy(common), "description": descriptions[name],
                   "basis": field_origins[name][0], "value_origin": field_origins[name][1],
                   "paths": [f"capture.observation.backend.targets[0].fields['T03.{name}'].value"],
                    "projection": "bridge.information.trade_value_capture_v2.project_fields"}
            for name in _VALUE_FIELDS
        }
        fields["collected_value"] = {
            **deepcopy(common), "coverage": "partial",
            "runtime_validation": "trade_value_capture_v2.validate_capture",
            "description": (
                "贸易节点留存金额，即各国贸易效率修正前的signed32杜卡特原始值；"
                "不是贸易力量百分比，也不是各国贸易收入之和。"
            ),
            "paths": ["capture.observation.backend.targets[0].fields['T03.collected_value'].value"],
            "basis": "native_trade_node_retention_tooltip_amount",
            "value_origin": "derived_from_native_ui_cache_inputs",
            "raw": True,
            "projection": "bridge.information.trade_value_capture_v2.project_fields",
            "gaps": ["ACTUAL_UI_RENDER_NOT_OBSERVED", "NATIVE_CACHE_FRESHNESS_NOT_PROVEN"],
        }
        return [{
            "topic_id": _TOPIC,
            "catalog_ids": [_TOPIC],
            "title": "节点贸易价值",
            "status": "available",
            "fields": fields,
            "object_types": ["trade_node"],
            "observer_roles": [],
            "observer_scope": [_COUNTRY],
            "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
            "supported_versions": [_VERSION],
            "triggers": ["query", "periodic"],
            "runtime_validation": "validated_capture_v2_and_public_projection",
            "source": type(self).__name__,
            "visibility": "visible_scope",
            "context_scope": "visible_scope",
            "scope_note": (
                "仅投影G02正向中心发现和非玩家观察门控后允许的当前贸易节点缓存；"
                "collected_value表示节点留存金额，不是贸易力量百分比或各国收入之和；"
                "不表示完整GUI可见性或实际UI渲染，缓存新鲜度未证明。"
            ),
        }]

    def validate_query(self, query: Any, context: Any = None) -> dict[str, Any]:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "T03 query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        if not {"topic", "object", "fields"} <= set(query) or set(query) - allowed:
            raise InformationError("invalid_parameters", "T03 query has missing or unknown keys")
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeTradeValueSource supports T03 only")
        obj = query.get("object")
        if (not isinstance(obj, dict) or set(obj) != {"type", "node_id"}
                or obj.get("type") != "trade_node"
                or not isinstance(obj.get("node_id"), str)
                or _NODE_ID.fullmatch(obj["node_id"]) is None
                or obj["node_id"] == "Null"):
            raise InformationError("invalid_object", "T03 requires one bounded trade_node node_id")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(field, str) or field not in _FIELDS for field in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError("invalid_fields", "T03 fields must be unique supported field names")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "T03 parameters must be an empty object")
        if context is not None:
            if not isinstance(context, Mapping):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if observer is not None and observer != _COUNTRY:
                raise InformationError("observer_scope_mismatch", "T03 is restricted to logical FRA observer")
        normalized = {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _failure_fields(fields: list[str], reason: str) -> dict[str, dict[str, Any]]:
        return {field: _unknown(reason) for field in fields}

    @staticmethod
    def _result(normalized: dict[str, Any], context: dict[str, Any],
                fields: dict[str, dict[str, Any]], provenance: dict[str, Any]) -> dict[str, Any]:
        source = _source_info(
            "NativeTradeValueSource", context, complete=False,
            provenance=deepcopy(provenance),
        )
        source["context_scope"] = "visible_scope"
        return _result(normalized, context, fields, False, source)

    def _capture_api(self):
        injected = self.capture
        if injected is not None and all(callable(getattr(injected, name, None))
                                        for name in ("validate_capture", "project_fields")):
            capture_fn = getattr(injected, "capture", None)
            return injected, capture_fn if callable(capture_fn) else None
        try:
            module = importlib.import_module(".trade_value_capture_v2", __package__)
        except Exception:
            return None, None
        capture_fn = injected if callable(injected) else getattr(module, "capture", None)
        return module, capture_fn if callable(capture_fn) else None

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        reason = _base_context_reason(context, _COUNTRY)
        return reason.replace("TRADE_INCOME_", "TRADE_VALUE_", 1) if reason else None

    def read(self, query: dict, context: dict | None = None) -> dict[str, Any]:
        if context is not None and not isinstance(context, Mapping):
            raise InformationError("invalid_context", "context must be an object")
        supplied = deepcopy(dict(context)) if isinstance(context, Mapping) else None
        normalized = self.validate_query(query, supplied)
        requested = normalized["fields"]
        node_id = normalized["object"]["node_id"]
        provenance: dict[str, Any] = {
            "adapter": _SOURCE,
            "observer": _COUNTRY,
            "node_id": node_id,
            "read_only": True,
            "native_function_invoked": False,
            "actual_UI_observed": False,
            "current_center_discovery_positive": None,
            "completeness": "partial",
            "context_guard": {
                "mode": "live", "game_version": _VERSION,
                "game_sha256": _GAME_SHA256,
                "identity_keys": ["session_id", "game_sha256", "observer", "game_date", "game_version"],
            },
        }

        def result(ctx: dict[str, Any], field_values: dict[str, dict[str, Any]]) -> dict[str, Any]:
            return self._result(normalized, ctx, field_values, provenance)

        context_failed = False
        try:
            current = supplied if supplied is not None else self.context()
        except Exception:
            current = {}
            context_failed = True

        if context_failed:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, "TRADE_VALUE_CONTEXT_UNAVAILABLE"))
        reason = self._context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, reason))

        try:
            before = self.context()
        except Exception:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, "TRADE_VALUE_CONTEXT_UNAVAILABLE"))
        before_reason = self._context_reason(before)
        if before_reason is not None or _base_identity(current) != _base_identity(before):
            provenance["context_guard"]["status"] = "stale"
            return result(current, self._failure_fields(requested, before_reason or "TRADE_VALUE_CONTEXT_STALE"))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or type(creation_filetime) is not int:
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, binding_reason or "TRADE_VALUE_INSTALLATION_UNAVAILABLE"))

        module, capture_fn = self._capture_api()
        validate_fn = getattr(module, "validate_capture", None) if module is not None else None
        project_fn = getattr(module, "project_fields", None) if module is not None else None
        if not callable(capture_fn) or not callable(validate_fn) or not callable(project_fn):
            provenance["context_guard"]["status"] = "capture_unavailable"
            return result(before, self._failure_fields(requested, "TRADE_VALUE_CAPTURE_UNAVAILABLE"))

        report: Any = None
        capture_error: str | None = None
        try:
            report = capture_fn(installation, node_id, observer=_COUNTRY)
        except Exception as exc:
            capture_error = "TRADE_VALUE_CAPTURE_FAILED:" + type(exc).__name__
        provenance["capture_performed"] = True

        # Always rebind after a capture attempt, including a thrown exception.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._context_reason(after)
        final_installation, final_creation, final_binding_reason = _session_binding(self.base_source)
        if (after_reason is not None or _base_identity(before) != _base_identity(after)
                or final_binding_reason is not None
                or _binding_path(installation) != _binding_path(final_installation)
                or creation_filetime != final_creation):
            provenance["context_guard"]["status"] = "changed"
            return result(before, self._failure_fields(requested, "TRADE_VALUE_CONTEXT_OR_INSTALLATION_CHANGED"))
        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            return result(before, self._failure_fields(requested, capture_error))

        try:
            valid = validate_fn(report, before, creation_filetime, node_id)
        except Exception:
            valid = False
        if valid is not True:
            provenance["context_guard"]["status"] = "capture_invalid"
            return result(before, self._failure_fields(requested, "TRADE_VALUE_CAPTURE_INVALID"))
        if (not isinstance(report, Mapping)
                or report.get("schema") not in {
                    "information.trade_value_capture.v1",
                    "information.trade_value_capture.v2",
                }
                or report.get("observer") != _COUNTRY
                or not isinstance(report.get("object"), Mapping)
                or set(report["object"]) != {"type", "node_id"}
                or report["object"].get("type") != "trade_node"
                or report["object"].get("node_id") != node_id):
            provenance["context_guard"]["status"] = "capture_shape_invalid"
            return result(before, self._failure_fields(requested, "TRADE_VALUE_CAPTURE_SHAPE_INVALID"))
        report_hash = _hash_report(report)
        if report_hash is None:
            provenance["context_guard"]["status"] = "capture_shape_invalid"
            return result(before, self._failure_fields(requested, "TRADE_VALUE_CAPTURE_NOT_CANONICAL"))

        # Only the capture module's public projector may produce field values.
        try:
            projected = project_fn(report)
        except Exception:
            projected = None
        if not isinstance(projected, Mapping):
            provenance["context_guard"]["status"] = "projection_invalid"
            return result(before, self._failure_fields(requested, "TRADE_VALUE_PROJECTOR_INVALID"))

        provenance["context_guard"]["status"] = "passed"
        provenance["capture_report_sha256"] = report_hash
        public_fields: dict[str, dict[str, Any]] = {}
        projected_statuses = []
        for field in requested:
            field_value = _public_projected_field(field, projected.get(field))
            public_fields[field] = field_value
            projected_statuses.append(field_value.get("status"))
        if any(status == "known" for status in projected_statuses):
            provenance["current_center_discovery_positive"] = True
        return result(before, public_fields)

    def poll_events(self, context: dict | None, cursor: Any) -> dict[str, Any]:
        if cursor is not None and not isinstance(cursor, dict):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeTradeValueSource"]
