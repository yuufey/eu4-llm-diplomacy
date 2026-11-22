"""Read-only T04 trade-power adapter.

The parent country capture owns the guarded trade-income graph.  This adapter
requests the field-specific power child once, validates the parent and all
three snapshots, and projects only the requested node's two bounded values.
It does not infer shares or sources and never turns a missing node into zero.
"""
from __future__ import annotations

from copy import deepcopy
import importlib
import re
from typing import Any, Mapping

from .model import InformationError, canonical
from .sources import _copy, _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _CONTEXT_KEYS,
    _GAME_SHA256,
    _VERSION,
    _capture_record_reason,
    _observer_context_reason,
    _identity,
    _parent_report_reason,
    _record_canonical_sha256,
    _session_binding,
)


_TOPIC = "T04"
_FIELDS = ("country_power", "total_power")
_COUNTRY_POWER = "country_power"
_TOTAL_POWER = "total_power"
_BASIS = "native_trade_node_power_caches"
_UNIT = "trade_power"
_SCALE = 1000
_PERIOD = "current"
_COUNTRY_ORIGIN = "derived_from_copied_native_caches"
_TOTAL_ORIGIN = "copied_native_cache"
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_INT32_MASK = (1 << 32) - 1
_HEX = re.compile(r"[0-9a-fA-F]+\Z")


_CATALOG_ITEM = {
    "topic_id": _TOPIC,
    "catalog_ids": [_TOPIC],
    "title": "贸易竞争力与总贸易力",
    "status": "available",
    "fields": {
        _COUNTRY_POWER: {
            "coverage": "partial",
            "runtime_validation": "validated_native_cache",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _UNIT,
            "scale": _SCALE,
            "raw": True,
            "raw_semantics": "selected trade-node entry country-power cache / 1000",
            "paths": ["trade_power.nodes[].country_power_raw"],
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _COUNTRY_ORIGIN,
            "complete": False,
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "LIVE_GUI_SELECTOR_ALIGNMENT_NOT_PROVEN",
            ],
        },
        _TOTAL_POWER: {
            "coverage": "partial",
            "runtime_validation": "validated_native_cache",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _UNIT,
            "scale": _SCALE,
            "raw": True,
            "raw_semantics": "selected trade-node total-power cache / 1000",
            "paths": ["trade_power.nodes[].total_power_raw"],
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _TOTAL_ORIGIN,
            "complete": False,
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "LIVE_GUI_SELECTOR_ALIGNMENT_NOT_PROVEN",
            ],
        },
    },
    "object_types": ["trade_node"],
    "observer_roles": ["country"],
    "observer_scope": [],
    "parameters": {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic"],
    "runtime_validation": "validated",
    "source": "NativeTradePowerSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "读取观察国在指定节点的贸易竞争力及节点总贸易力缓存。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _raw_hex(value: int) -> str:
    return (value & _INT32_MASK).to_bytes(4, "little", signed=False).hex()


def _valid_raw(value: Any, raw_hex: Any) -> bool:
    return (
        type(value) is int
        and _INT32_MIN <= value <= _INT32_MAX
        and isinstance(raw_hex, str)
        and len(raw_hex) == 8
        and _HEX.fullmatch(raw_hex) is not None
        and raw_hex.lower() == _raw_hex(value)
    )


def _power_context_reason(context: Any) -> str | None:
    reason = _observer_context_reason(context)
    return reason.replace("TRADE_INCOME_", "TRADE_POWER_", 1) if reason else None


def _power_module():
    try:
        return importlib.import_module(".trade_power_memory", __package__)
    except Exception:
        return None


def _power_validate_reason(power: Any, trade_income: Any) -> str | None:
    module = _power_module()
    if module is None:
        return "TRADE_POWER_VALIDATOR_UNAVAILABLE"
    validator = getattr(module, "validate_record", None)
    if not callable(validator):
        return "TRADE_POWER_VALIDATOR_UNAVAILABLE"
    try:
        valid = validator(power, trade_income)
    except Exception as exc:
        return "TRADE_POWER_RECORD_VALIDATION_FAILED:" + type(exc).__name__
    if valid is not True:
        return "TRADE_POWER_RECORD_INVALID"
    expected = getattr(module, "EXPECTED_PROFILE_SHA256", None)
    if (
        isinstance(expected, str)
        and len(expected) == 64
        and expected != "pending-profile"
        and power.get("profile_sha256") != expected
    ):
        return "TRADE_POWER_PROFILE_PIN_INVALID"
    return _power_shape_reason(power, trade_income.get('country'))


def _power_shape_reason(power: Any, country: str) -> str | None:
    if not isinstance(power, Mapping) or power.get("status") != "observed":
        return "TRADE_POWER_RECORD_INVALID"
    if (
        power.get("country") != country
        or power.get("basis") != _BASIS
        or power.get("unit") != _UNIT
        or power.get("scale") != _SCALE
        or power.get("period") != _PERIOD
        or power.get("value_origin") != _COUNTRY_ORIGIN
        or power.get("total_value_origin") != _TOTAL_ORIGIN
    ):
        return "TRADE_POWER_RECORD_SHAPE_INVALID"
    nodes = power.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return "TRADE_POWER_NODES_INVALID"
    seen: set[str] = set()
    for node in nodes:
        if not isinstance(node, Mapping):
            return "TRADE_POWER_NODE_INVALID"
        node_id = node.get("node_id")
        if not isinstance(node_id, str) or _NODE_ID.fullmatch(node_id) is None or node_id in seen:
            return "TRADE_POWER_NODE_ID_INVALID"
        seen.add(node_id)
        for name in _FIELDS:
            raw = node.get(name + "_raw")
            raw_hex = node.get(name + "_raw_hex")
            if not _valid_raw(raw, raw_hex):
                return f"TRADE_POWER_{name.upper()}_INVALID"
    return None


def _node_for(power: Mapping[str, Any], node_id: str) -> Mapping[str, Any] | None:
    nodes = power.get("nodes")
    if not isinstance(nodes, list):
        return None
    for node in nodes:
        if isinstance(node, Mapping) and node.get("node_id") == node_id:
            return node
    return None


def _compact_guard(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"status": None, "checks": {}, "records": {}}
    result: dict[str, Any] = {
        "status": value.get("status"),
        "checks": deepcopy(value.get("checks", {}))
        if isinstance(value.get("checks", {}), Mapping) else {},
        "records": {},
    }
    for key in ("profile_id", "profile_sha256", "module_base"):
        if key in value:
            result[key] = deepcopy(value[key])
    records = value.get("records")
    if isinstance(records, Mapping):
        for name, record in records.items():
            if not isinstance(name, str) or not isinstance(record, Mapping):
                continue
            result["records"][name] = {
                key: deepcopy(record[key])
                for key in ("rva", "address", "expected_sha256", "actual_sha256")
                if key in record
            }
    return result


def _compact_power_provenance(
    power: Mapping[str, Any],
    trade_income: Mapping[str, Any],
    node_id: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": power.get("status"),
        "profile_sha256": power.get("profile_sha256"),
        "static_contract_guard": _compact_guard(power.get("static_contract_guard")),
        "runtime_code_guard": _compact_guard(power.get("runtime_code_guard")),
        "record_canonical_sha256": _record_canonical_sha256(power),
        "trade_income_record_canonical_sha256": _record_canonical_sha256(trade_income),
        "country": power.get("country"),
        "country_fullref_raw_hex": power.get("country_fullref_raw_hex"),
        "country_slot": power.get("country_slot"),
        "basis": power.get("basis"),
        "unit": power.get("unit"),
        "scale": power.get("scale"),
        "period": power.get("period"),
        "value_origin": power.get("value_origin"),
        "total_value_origin": power.get("total_value_origin"),
        "requested_node_id": node_id,
    }
    node = _node_for(power, node_id)
    if node is not None:
        result["node"] = {
            "node_id": node_id,
            "runtime_pointer": node.get("runtime_pointer"),
            "runtime_total_power_address": node.get("runtime_total_power_address"),
            "entry_power_components_raw": deepcopy(node.get("entry_power_components_raw", {})),
            "entry_power_components_raw_hex": node.get("entry_power_components_raw_hex"),
            "country_power_raw": node.get("country_power_raw"),
            "country_power_raw_hex": node.get("country_power_raw_hex"),
            "total_power_raw": node.get("total_power_raw"),
            "total_power_raw_hex": node.get("total_power_raw_hex"),
        }
    if power.get("reason") is not None:
        result["reason"] = power.get("reason")
    return result


def _power_record_reason(report: Any) -> str | None:
    if not isinstance(report, Mapping):
        return "TRADE_POWER_PARENT_CAPTURE_INVALID"
    top = report.get("trade_power")
    before_snapshot = report.get("before")
    after_snapshot = report.get("after")
    before = before_snapshot.get("trade_power") if isinstance(before_snapshot, Mapping) else None
    after = after_snapshot.get("trade_power") if isinstance(after_snapshot, Mapping) else None
    trade_top = report.get("trade_income")
    trade_before = before_snapshot.get("trade_income") if isinstance(before_snapshot, Mapping) else None
    trade_after = after_snapshot.get("trade_income") if isinstance(after_snapshot, Mapping) else None
    for label, power, trade in (
        ("TOP", top, trade_top),
        ("BEFORE", before, trade_before),
        ("AFTER", after, trade_after),
    ):
        if not isinstance(power, Mapping) or not isinstance(trade, Mapping):
            return "TRADE_POWER_RECORD_MISSING"
        reason = _power_validate_reason(power, trade)
        if reason is not None:
            return f"TRADE_POWER_{label}_{reason.removeprefix('TRADE_POWER_')}"
    try:
        if canonical(top) != canonical(before) or canonical(top) != canonical(after):
            return "TRADE_POWER_SNAPSHOT_MISMATCH"
    except Exception:
        return "TRADE_POWER_RECORD_CANONICAL_INVALID"
    return None


def _power_parent_reason(report: Any, context: Mapping[str, Any], creation: int) -> str | None:
    reason = _parent_report_reason(report, context, context.get('observer'), creation)
    if reason is not None:
        return reason.replace("TRADE_INCOME_", "TRADE_POWER_", 1)
    request = report.get("request") if isinstance(report, Mapping) else None
    if not isinstance(request, Mapping) or request.get("include_trade_power") is not True:
        return "TRADE_POWER_PARENT_REQUEST_INVALID"
    return None


class NativeTradePowerSource(NativeTradeIncomeSource):
    """Expose T04 country and total trade-power caches for an observer's node."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None):
        super().__init__(base_source, capture=capture)

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
                f"T04 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeTradePowerSource supports T04 only")
        obj = query.get("object")
        if (
            not isinstance(obj, dict)
            or set(obj) != {"type", "node_id"}
            or obj.get("type") != "trade_node"
            or not isinstance(obj.get("node_id"), str)
            or _NODE_ID.fullmatch(obj["node_id"]) is None
            or obj["node_id"] == "Null"
        ):
            raise InformationError("invalid_object", "T04 requires a bounded trade_node selector")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError("invalid_fields", "T04 fields must be a non-empty list of unique strings")
        unknown = set(fields) - set(_FIELDS)
        if unknown:
            raise InformationError("unknown_field", f"T04 fields are outside the native adapter: {sorted(unknown)}")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "T04 parameters must be an empty object")
        if context is not None and not isinstance(context, dict):
            raise InformationError("invalid_context", "context must be an object")
        normalized = {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _failure_fields(fields: list[str], reason: str, *, unavailable: bool) -> dict[str, dict[str, Any]]:
        factory = _unavailable if unavailable else _unknown
        return {field: factory(reason) for field in fields}

    @staticmethod
    def _result(
        normalized: dict[str, Any],
        context: dict[str, Any],
        fields: dict[str, dict[str, Any]],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        source = _source_info("NativeTradePowerSource", context, complete=False, provenance=provenance)
        source["context_scope"] = "country_scope"
        if fields and all(
            isinstance(item, dict) and item.get("status") == "unavailable"
            for item in fields.values()
        ):
            source["status"] = "unavailable"
        return _result(normalized, context, fields, False, source)

    def _capture_reader(self):
        if self.capture is not None:
            return self.capture
        try:
            from .country_resources_memory import capture
        except Exception:
            return None
        return capture

    @staticmethod
    def _field_from_node(node: Mapping[str, Any], field: str) -> dict[str, Any]:
        raw = node.get(field + "_raw")
        raw_hex = node.get(field + "_raw_hex")
        if not _valid_raw(raw, raw_hex):
            raise ValueError(f"TRADE_POWER_{field.upper()}_INVALID")
        origin = _COUNTRY_ORIGIN if field == _COUNTRY_POWER else _TOTAL_ORIGIN
        return {
            "status": "known",
            "value": raw,
            "raw": raw,
            "raw_hex": raw_hex,
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": origin,
            "complete": False,
        }

    def read(self, query: dict, context: dict | None = None) -> dict:
        supplied = _copy(context) if isinstance(context, dict) else None
        context_supplied = supplied is not None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]
        node_id = normalized["object"]["node_id"]
        observer = current.get('observer')
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": observer,
            "read_only": True,
            "native_function_invoked": False,
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "basis": _BASIS,
            "requested_node_id": node_id,
            "context_guard": {
                "mode": "live",
                "game_version": _VERSION,
                "game_sha256": _GAME_SHA256,
                "identity_keys": list(_CONTEXT_KEYS),
            },
        }

        def result(ctx: dict[str, Any], fields: dict[str, dict[str, Any]]) -> dict[str, Any]:
            return self._result(normalized, ctx, fields, provenance)

        reason = _power_context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, reason, unavailable=True))

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            before_reason = _power_context_reason(before)
            if before_reason is not None:
                provenance["context_guard"]["status"] = "unavailable"
                return result(before, self._failure_fields(requested, before_reason, unavailable=True))
            if _identity(current) != _identity(before):
                provenance["context_guard"]["status"] = "stale"
                return result(current, self._failure_fields(requested, "TRADE_POWER_CONTEXT_STALE", unavailable=True))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = binding_reason or "TRADE_POWER_INSTALLATION_UNAVAILABLE"
            reason = reason.replace("TRADE_INCOME_", "TRADE_POWER_", 1)
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        capture = self._capture_reader()
        if not callable(capture):
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, "TRADE_POWER_CAPTURE_UNAVAILABLE", unavailable=True))

        report: Any = None
        capture_error: str | None = None
        try:
            report = capture(
                installation,
                observer,
                include_trade_income=True,
                include_trade_power=True,
            )
        except Exception as exc:
            capture_error = "TRADE_POWER_CAPTURE_FAILED:" + type(exc).__name__

        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = _power_context_reason(after)
        if after_reason is not None or _identity(before) != _identity(after):
            provenance["context_guard"]["status"] = "changed"
            reason = after_reason or "TRADE_POWER_CONTEXT_CHANGED_DURING_CAPTURE"
            if isinstance(report, Mapping):
                power = report.get("trade_power")
                trade = report.get("trade_income")
                if isinstance(power, Mapping) and isinstance(trade, Mapping):
                    provenance["trade_power"] = _compact_power_provenance(power, trade, node_id)
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            return result(before, self._failure_fields(requested, capture_error, unavailable=False))

        if isinstance(report, Mapping):
            power = report.get("trade_power")
            trade = report.get("trade_income")
            if isinstance(power, Mapping) and isinstance(trade, Mapping):
                provenance["trade_power"] = _compact_power_provenance(power, trade, node_id)
        provenance["context_guard"]["status"] = "capture_invalid"

        reason = _power_parent_reason(report, before, creation_filetime)
        if reason is not None:
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        reason = _capture_record_reason(report, observer)
        if reason is not None:
            reason = reason.replace("TRADE_INCOME_", "TRADE_POWER_TRADE_INCOME_", 1)
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        reason = _power_record_reason(report)
        if reason is not None:
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        power = report["trade_power"]
        trade = report["trade_income"]
        provenance["context_guard"]["status"] = "passed"
        provenance["trade_power"] = _compact_power_provenance(power, trade, node_id)
        node = _node_for(power, node_id)
        if node is None:
            provenance["capture_reason"] = "NODE_NOT_FOUND"
            return result(before, {field: _unknown("NODE_NOT_FOUND") for field in requested})
        fields: dict[str, dict[str, Any]] = {}
        for field in requested:
            try:
                fields[field] = self._field_from_node(node, field)
            except Exception as exc:
                provenance["capture_reason"] = str(exc) or type(exc).__name__
                fields[field] = _unknown(provenance["capture_reason"])
        return result(before, fields)

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeTradePowerSource"]
