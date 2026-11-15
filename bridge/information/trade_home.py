"""Read-only T02 home-trade-node adapter.

The parent capture owns the guarded country/trade-node graph.  This adapter
requests that graph once with the opt-in home child, validates the parent and
all three child snapshots, and exposes a home node only when the child proves
exactly one ``entry+0xAD`` candidate.  It does not call a game function or a
localisation reader and does not use a node id as a raw flag value.
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
    _COUNTRY,
    _GAME_SHA256,
    _PERIOD,
    _SCALE,
    _UNIT,
    _VERSION,
    _capture_record_reason,
    _context_reason,
    _identity,
    _parent_report_reason,
    _record_canonical_sha256,
    _session_binding,
)


_TOPIC = "T02"
_FIELD = "home_node"
_BASIS = "native_trade_node_home_flag"
_VALUE_ORIGIN = "derived_from_copied_native_flags"
_HOME_UNIT = "trade_node"
_HOME_SCALE = 1
_HOME_PERIOD = "current"
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-fA-F]+\Z")


_CATALOG_ITEM = {
    "topic_id": _TOPIC,
    "catalog_ids": [_TOPIC],
    "title": "本埠与贸易收集路线",
    "status": "available",
    "fields": {
        _FIELD: {
            "coverage": "partial",
            "runtime_validation": "validated_native_entry_flag",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _HOME_UNIT,
            "scale": _HOME_SCALE,
            "raw": False,
            "raw_semantics": "唯一 entry+0xAD 非零节点的 node_id；flag raw 单独保留",
            "paths": ["home_trade_node.home_node"],
            "supported_countries": [_COUNTRY],
            "period": _HOME_PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "complete": False,
            "gaps": [
                "NATIVE_HOME_NODE_UNIQUENESS_IS_RUNTIME_GUARDED",
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
            ],
        },
    },
    "object_types": ["country"],
    "observer_roles": ["country"],
    "observer_scope": [_COUNTRY],
    "parameters": {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic"],
    "runtime_validation": "validated",
    "source": "NativeTradeHomeSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "仅读取固定1.37.4、FRA观察者的原生贸易 entry+0xAD；"
        "零或多候选均保持unknown，缓存新鲜度及完整路线仍未闭合。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _home_context_reason(context: Any) -> str | None:
    reason = _context_reason(context)
    return reason.replace("TRADE_INCOME_", "TRADE_HOME_", 1) if reason else None


def _home_parent_reason(report: Any, context: Mapping[str, Any], creation: int) -> str | None:
    reason = _parent_report_reason(report, context, _COUNTRY, creation)
    if reason is not None:
        return reason.replace("TRADE_INCOME_", "TRADE_HOME_", 1)
    request = report.get("request") if isinstance(report, Mapping) else None
    if not isinstance(request, Mapping) or request.get("include_home_trade_node") is not True:
        return "TRADE_HOME_PARENT_REQUEST_INVALID"
    return None


def _home_module():
    try:
        return importlib.import_module(".home_trade_node_memory", __package__)
    except Exception:
        return None


def _home_validate_reason(home: Any, trade_income: Any) -> str | None:
    module = _home_module()
    if module is None:
        return "TRADE_HOME_VALIDATOR_UNAVAILABLE"
    validator = getattr(module, "validate_record", None)
    if not callable(validator):
        return "TRADE_HOME_VALIDATOR_UNAVAILABLE"
    try:
        valid = validator(home, trade_income)
    except Exception as exc:
        return "TRADE_HOME_RECORD_VALIDATION_FAILED:" + type(exc).__name__
    return None if valid is True else "TRADE_HOME_RECORD_INVALID"


def _compact_guard(value: Any) -> dict[str, Any]:
    """Keep guard identity/hashes without copying code bytes or read logs."""

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
                for key in (
                    "rva", "address", "expected_sha256", "actual_sha256",
                )
                if key in record
            }
    if isinstance(value.get("unknown_conditions"), list):
        result["unknown_conditions"] = deepcopy(value["unknown_conditions"][:64])
    return result


def _compact_home_provenance(home: Mapping[str, Any], trade_income: Mapping[str, Any]) -> dict[str, Any]:
    """Expose the bounded home audit, never the old 192-byte entry graph."""

    result: dict[str, Any] = {
        "status": home.get("status"),
        "profile_sha256": home.get("profile_sha256"),
        "static_contract_guard": _compact_guard(home.get("static_contract_guard")),
        "runtime_code_guard": _compact_guard(home.get("runtime_code_guard")),
        "module_base": home.get("module_base"),
        "country": home.get("country"),
        "country_fullref_raw_hex": home.get("country_fullref_raw_hex"),
        "country_slot": home.get("country_slot"),
        "source_trade_record_canonical_sha256": home.get(
            "source_trade_record_canonical_sha256"
        ),
        "trade_income_record_canonical_sha256": _record_canonical_sha256(trade_income),
        "basis": home.get("basis"),
        "unit": home.get("unit"),
        "scale": home.get("scale"),
        "period": home.get("period"),
        "value_origin": home.get("value_origin"),
        "known_reason": home.get("known_reason"),
    }
    if home.get("reason") is not None:
        result["reason"] = home.get("reason")
    candidates = home.get("derived_nodes")
    if isinstance(candidates, list):
        result["candidate_node_ids"] = [
            node for node in candidates
            if isinstance(node, str) and _NODE_ID.fullmatch(node)
        ]
    nodes = home.get("nodes")
    if isinstance(nodes, list):
        compact_nodes = []
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            node_id = node.get("node_id")
            flag = node.get("flag_ad")
            raw_hex = node.get("flag_ad_raw_hex")
            if (
                isinstance(node_id, str) and _NODE_ID.fullmatch(node_id)
                and type(flag) is int and 0 <= flag <= 0xFF
                and isinstance(raw_hex, str) and len(raw_hex) == 2
                and _HEX.fullmatch(raw_hex)
            ):
                compact_nodes.append({
                    "node_id": node_id,
                    "flag_ad": flag,
                    "flag_ad_raw_hex": raw_hex,
                })
        result["nodes"] = compact_nodes
    return result


def _home_record_reason(report: Any) -> str | None:
    """Validate top/before/after home children and their canonical identity."""

    if not isinstance(report, Mapping):
        return "TRADE_HOME_PARENT_CAPTURE_INVALID"
    top = report.get("home_trade_node")
    before_snapshot = report.get("before")
    after_snapshot = report.get("after")
    before = before_snapshot.get("home_trade_node") if isinstance(before_snapshot, Mapping) else None
    after = after_snapshot.get("home_trade_node") if isinstance(after_snapshot, Mapping) else None
    trade_top = report.get("trade_income")
    trade_before = before_snapshot.get("trade_income") if isinstance(before_snapshot, Mapping) else None
    trade_after = after_snapshot.get("trade_income") if isinstance(after_snapshot, Mapping) else None
    children = (top, before, after)
    trade_children = (trade_top, trade_before, trade_after)
    for child, trade in zip(children, trade_children):
        if not isinstance(child, Mapping) or not isinstance(trade, Mapping):
            return "TRADE_HOME_RECORD_MISSING"
        if (
            child.get("country") != _COUNTRY
            or child.get("basis") != _BASIS
            or child.get("unit") != _HOME_UNIT
            or child.get("scale") != _HOME_SCALE
            or child.get("period") != _HOME_PERIOD
            or child.get("value_origin") != _VALUE_ORIGIN
        ):
            return "TRADE_HOME_RECORD_SHAPE_INVALID"
        reason = _home_validate_reason(child, trade)
        if reason is not None:
            return reason
    try:
        if canonical(top) != canonical(before) or canonical(top) != canonical(after):
            return "TRADE_HOME_SNAPSHOT_MISMATCH"
    except Exception:
        return "TRADE_HOME_RECORD_CANONICAL_INVALID"
    return None


def _field_from_home(home: Mapping[str, Any]) -> dict[str, Any]:
    node_id = home.get("home_node")
    if not isinstance(node_id, str) or _NODE_ID.fullmatch(node_id) is None:
        raise ValueError("TRADE_HOME_NODE_ID_INVALID")
    nodes = home.get("nodes")
    matching = [
        node for node in nodes
        if isinstance(node, Mapping) and node.get("node_id") == node_id
    ] if isinstance(nodes, list) else []
    if len(matching) != 1:
        raise ValueError("TRADE_HOME_NODE_PROVENANCE_MISMATCH")
    node = matching[0]
    flag = node.get("flag_ad")
    raw_hex = node.get("flag_ad_raw_hex")
    if (
        type(flag) is not int or flag == 0
        or not isinstance(raw_hex, str)
        or raw_hex.lower() != f"{flag:02x}"
    ):
        raise ValueError("TRADE_HOME_FLAG_INVALID")
    return {
        "status": "known",
        "value": node_id,
        "unit": _HOME_UNIT,
        "scale": _HOME_SCALE,
        "period": _HOME_PERIOD,
        "basis": _BASIS,
        "value_origin": _VALUE_ORIGIN,
        "complete": False,
        "native_home_flag_raw": flag,
        "native_home_flag_raw_hex": raw_hex,
    }


class NativeTradeHomeSource(NativeTradeIncomeSource):
    """Expose T02.home_node for the verified FRA observer."""

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
                f"T02 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeTradeHomeSource supports T02 only")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"}:
            raise InformationError("invalid_object", "T02.home_node requires a country object")
        if obj.get("type") != "country":
            raise InformationError("invalid_object", "T02.home_node does not support trade_node objects")
        if obj.get("country") != _COUNTRY:
            raise InformationError("observer_scope_mismatch", "T02.home_node supports verified FRA only")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError("invalid_fields", "T02 fields must be a non-empty list of unique strings")
        unknown = set(fields) - {_FIELD}
        if unknown:
            raise InformationError("unknown_field", f"T02 fields are outside the home adapter: {sorted(unknown)}")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "T02.home_node parameters must be empty")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if observer is not None and observer != _COUNTRY:
                raise InformationError("observer_scope_mismatch", "T02.home_node is outside FRA observer scope")
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
        source = _source_info(
            "NativeTradeHomeSource", context, complete=False, provenance=provenance,
        )
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

    def read(self, query: dict, context: dict | None = None) -> dict:
        supplied = _copy(context) if isinstance(context, dict) else None
        context_supplied = supplied is not None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": _COUNTRY,
            "read_only": True,
            "native_function_invoked": False,
            "unit": _HOME_UNIT,
            "scale": _HOME_SCALE,
            "period": _HOME_PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "context_guard": {
                "mode": "live", "game_version": _VERSION,
                "game_sha256": _GAME_SHA256,
                "identity_keys": list(_CONTEXT_KEYS),
            },
        }

        def result(ctx: dict[str, Any], fields: dict[str, dict[str, Any]]) -> dict[str, Any]:
            return self._result(normalized, ctx, fields, provenance)

        reason = _home_context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, reason, unavailable=True))

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            before_reason = _home_context_reason(before)
            if before_reason is not None:
                provenance["context_guard"]["status"] = "unavailable"
                return result(before, self._failure_fields(requested, before_reason, unavailable=True))
            if _identity(current) != _identity(before):
                reason = "TRADE_HOME_CONTEXT_STALE"
                provenance["context_guard"]["status"] = "stale"
                return result(current, self._failure_fields(requested, reason, unavailable=True))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = (binding_reason or "TRADE_INCOME_INSTALLATION_UNAVAILABLE").replace(
                "TRADE_INCOME_", "TRADE_HOME_", 1
            )
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        capture = self._capture_reader()
        if not callable(capture):
            reason = "TRADE_HOME_CAPTURE_UNAVAILABLE"
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        report: Any = None
        capture_error: str | None = None
        try:
            report = capture(
                installation,
                _COUNTRY,
                include_trade_income=True,
                include_home_trade_node=True,
            )
        except Exception as exc:
            capture_error = "TRADE_HOME_CAPTURE_FAILED:" + type(exc).__name__

        # Always perform the after-context check, including reader exceptions.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = _home_context_reason(after)
        if after_reason is not None or _identity(before) != _identity(after):
            provenance["context_guard"]["status"] = "changed"
            reason = after_reason or "TRADE_HOME_CONTEXT_CHANGED_DURING_CAPTURE"
            if isinstance(report, Mapping):
                home = report.get("home_trade_node")
                trade = report.get("trade_income")
                if isinstance(home, Mapping) and isinstance(trade, Mapping):
                    provenance["home_trade_node"] = _compact_home_provenance(home, trade)
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            return result(before, self._failure_fields(requested, capture_error, unavailable=False))

        if isinstance(report, Mapping):
            home = report.get("home_trade_node")
            trade = report.get("trade_income")
            if isinstance(home, Mapping) and isinstance(trade, Mapping):
                provenance["home_trade_node"] = _compact_home_provenance(home, trade)
                provenance["trade_income"] = {
                    "record_canonical_sha256": _record_canonical_sha256(trade),
                }
        provenance["context_guard"]["status"] = "capture_invalid"

        reason = _home_parent_reason(report, before, creation_filetime)
        if reason is not None:
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        reason = _capture_record_reason(report)
        if reason is not None:
            reason = reason.replace("TRADE_INCOME_", "TRADE_HOME_TRADE_INCOME_", 1)
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        reason = _home_record_reason(report)
        if reason is not None:
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        trade = report["trade_income"]
        home = report["home_trade_node"]
        provenance["context_guard"]["status"] = "passed"
        # Validate the exact source child once more before projecting compact
        # provenance; this keeps a future mutation from becoming a known value.
        provenance["home_trade_node"] = _compact_home_provenance(home, trade)
        if home.get("status") != "observed":
            reason = home.get("reason") or home.get("known_reason") or "TRADE_HOME_NODE_UNAVAILABLE"
            factory = _unavailable if home.get("status") == "unavailable" else _unknown
            provenance["capture_reason"] = reason
            return result(before, {field: factory(reason) for field in requested})
        try:
            field = _field_from_home(home)
        except Exception as exc:
            reason = str(exc) or type(exc).__name__
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        return result(before, {_FIELD: field})

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeTradeHomeSource"]
