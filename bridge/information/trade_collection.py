"""Expose the T02 collect-node list through one shared T05 income reader.

The native country trade graph is owned by :class:`NativeTradeIncomeSource`.
This adapter deliberately does not capture it again, select a home node, or
derive routes or income.  It only changes the public topic/field and keeps
the upstream bounded provenance intact.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from .model import InformationError, canonical
from .sources import _copy, _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _COLLECTION_BASIS,
    _COLLECTION_ORIGIN,
    _CONTEXT_KEYS,
    _GAME_SHA256,
    _VERSION,
    _observer_context_reason,
    _identity,
)


_TOPIC = "T02"
_FIELD = "collect_node"
_UPSTREAM_TOPIC = "T05"
_UPSTREAM_FIELD = "collection"
_UPSTREAM_UNIT = "state"
_UNIT = "trade_node_list"
_SCALE = 1
_PERIOD = "current"
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
# This is the max_definitions bound in the pinned trade-income profile.  The
# upstream source validates the complete graph; this adapter also bounds the
# public list before promoting it.
_MAX_NODE_COUNT = 1024


_CATALOG_ITEM = {
    "topic_id": _TOPIC,
    "catalog_ids": [_TOPIC],
    "title": "本埠与贸易收集路线",
    "status": "available",
    "fields": {
        _FIELD: {
            "coverage": "partial",
            "runtime_validation": "delegated_native_trade_income_collection",
            "source": "NativeTradeCollectionSource",
            "unit": _UNIT,
            "scale": _SCALE,
            "raw": False,
            "raw_semantics": (
                "ordered node_id list whose upstream native collection predicate "
                "is true; no home-node, route, or income inference"
            ),
            "paths": ["trade_income.nodes[].eligible", "trade_income.nodes[].node_id"],
            "period": _PERIOD,
            "basis": _COLLECTION_BASIS,
            "value_origin": _COLLECTION_ORIGIN,
            "complete": False,
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "MERCHANT_TASK_LIFECYCLE_NOT_PROVEN",
            ],
        },
    },
    "object_types": ["country"],
    "observer_roles": ["country"],
    "observer_scope": [],
    "parameters": {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic"],
    "runtime_validation": "validated_upstream_native_trade_income",
    "source": "NativeTradeCollectionSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "列出当前观察国满足原生贸易收集条件的节点。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _valid_node_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value != "Null"
        and _NODE_ID.fullmatch(value) is not None
    )


class NativeTradeCollectionSource:
    """Expose T02.collect_node from a shared T05 income-source instance."""

    event_types: tuple[str, ...] = ()

    def __init__(self, trade_income_source: NativeTradeIncomeSource):
        if not callable(getattr(trade_income_source, "read", None)):
            raise TypeError("trade_income_source must expose read")
        if not callable(getattr(trade_income_source, "context", None)):
            raise TypeError("trade_income_source must expose context")
        self.trade_income_source = trade_income_source

    def context(self) -> dict[str, Any]:
        return _copy(self.trade_income_source.context())

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
            raise InformationError(
                "unknown_topic", "NativeTradeCollectionSource supports T02 only"
            )
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"}:
            raise InformationError(
                "invalid_object", "T02.collect_node requires a country object"
            )
        if obj.get("type") != "country":
            raise InformationError(
                "invalid_object", "T02.collect_node does not support trade_node objects"
            )
        country = obj.get('country')
        if not isinstance(country, str) or not re.fullmatch(r"[A-Z0-9]{3}", country):
            raise InformationError("invalid_object", "T02.collect_node requires a country tag")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError(
                "invalid_fields", "T02.collect_node fields must be unique strings"
            )
        if set(fields) != {_FIELD}:
            raise InformationError(
                "unknown_field", "T02.collect_node supports collect_node only"
            )
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError(
                "invalid_parameters", "T02.collect_node parameters must be empty"
            )
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if observer is not None and observer != country:
                raise InformationError("observer_scope_mismatch", "T02.collect_node is limited to the configured observer country")
        normalized = {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _result(
        normalized: dict[str, Any],
        context: dict[str, Any],
        fields: dict[str, dict[str, Any]],
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        source = _source_info(
            "NativeTradeCollectionSource", context, complete=False,
            provenance=provenance,
        )
        source["context_scope"] = "country_scope"
        source["game_date"] = context.get("game_date")
        if fields and all(
            isinstance(item, dict) and item.get("status") == "unavailable"
            for item in fields.values()
        ):
            source["status"] = "unavailable"
        return _result(normalized, context, fields, False, source)

    @staticmethod
    def _upstream_query(country: str) -> dict[str, Any]:
        return {
            "topic": _UPSTREAM_TOPIC,
            "object": {"type": "country", "country": country},
            "fields": [_UPSTREAM_FIELD],
            "parameters": {},
        }

    @staticmethod
    def _attach_upstream(provenance: dict[str, Any], upstream: Any) -> None:
        if not isinstance(upstream, Mapping):
            return
        source = upstream.get("source")
        if isinstance(source, Mapping):
            # Keep the upstream bounded trade_income.nodes/flags and its
            # record_canonical_sha256 exactly as supplied.  Do not synthesize
            # a capture_report_sha256 that the parent source does not expose.
            upstream_source = deepcopy(dict(source))
            provenance["upstream_source"] = upstream_source
            upstream_provenance = source.get("provenance")
            if isinstance(upstream_provenance, Mapping):
                trade_record = upstream_provenance.get("trade_income")
                if isinstance(trade_record, Mapping):
                    provenance["trade_income"] = deepcopy(dict(trade_record))

    @staticmethod
    def _upstream_identity_reason(
        upstream: Any, context: Mapping[str, Any]
    ) -> str | None:
        if not isinstance(upstream, Mapping):
            return "TRADE_COLLECTION_UPSTREAM_RESULT_INVALID"
        if upstream.get("topic") != _UPSTREAM_TOPIC:
            return "TRADE_COLLECTION_UPSTREAM_TOPIC_INVALID"
        source = upstream.get("source")
        if not isinstance(source, Mapping):
            return "TRADE_COLLECTION_UPSTREAM_SOURCE_MISSING"
        if source.get("name") != "NativeTradeIncomeSource":
            return "TRADE_COLLECTION_UPSTREAM_SOURCE_NAME_INVALID"
        if source.get("status") != "observed":
            fields = upstream.get("fields")
            field = fields.get(_UPSTREAM_FIELD) if isinstance(fields, Mapping) else None
            if not (source.get("status") == "unavailable" and isinstance(field, Mapping)
                    and field.get("status") == "unavailable"):
                return "TRADE_COLLECTION_UPSTREAM_SOURCE_STATUS_INVALID"
        if source.get("mode") != context.get("mode", "live"):
            return "TRADE_COLLECTION_UPSTREAM_SOURCE_MODE_MISMATCH"
        observer = context.get('observer')
        if source.get("observer") != observer:
            return "TRADE_COLLECTION_UPSTREAM_SOURCE_OBSERVER_MISMATCH"
        if source.get("session_id") != context.get("session_id"):
            return "TRADE_COLLECTION_UPSTREAM_SOURCE_SESSION_MISMATCH"
        if upstream.get("game_date") != context.get("game_date"):
            return "TRADE_COLLECTION_UPSTREAM_GAME_DATE_MISMATCH"
        objects = upstream.get("objects")
        if objects != [{"type": "country", "country": observer}]:
            return "TRADE_COLLECTION_UPSTREAM_OBJECT_MISMATCH"
        return None

    @staticmethod
    def _project_upstream_field(upstream: Any) -> dict[str, Any]:
        if not isinstance(upstream, Mapping):
            return _unknown("TRADE_COLLECTION_UPSTREAM_RESULT_INVALID")
        fields = upstream.get("fields")
        field = fields.get(_UPSTREAM_FIELD) if isinstance(fields, Mapping) else None
        if not isinstance(field, Mapping):
            return _unknown("TRADE_COLLECTION_UPSTREAM_FIELD_MISSING")
        status = field.get("status")
        if status in {"unknown", "unavailable"}:
            return deepcopy(dict(field))
        if status != "known":
            return _unknown("TRADE_COLLECTION_UPSTREAM_FIELD_STATUS_INVALID")
        if (
            field.get("unit") != _UPSTREAM_UNIT
            or type(field.get("scale")) is not int
            or field.get("scale") != _SCALE
            or field.get("period") != _PERIOD
            or field.get("basis") != _COLLECTION_BASIS
            or field.get("value_origin") != _COLLECTION_ORIGIN
            or field.get("complete") is not False
        ):
            return _unknown("TRADE_COLLECTION_UPSTREAM_FIELD_CONTRACT_INVALID")
        values = field.get("value")
        if not isinstance(values, list) or len(values) > _MAX_NODE_COUNT:
            return _unknown("TRADE_COLLECTION_NODE_LIST_INVALID")
        seen: set[str] = set()
        for node_id in values:
            if not _valid_node_id(node_id) or node_id in seen:
                return _unknown("TRADE_COLLECTION_NODE_ID_INVALID")
            seen.add(node_id)
        return {
            "status": "known",
            "value": deepcopy(values),
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "basis": _COLLECTION_BASIS,
            "value_origin": _COLLECTION_ORIGIN,
            "complete": False,
            "partial": True,
        }

    def read(self, query: dict, context: dict | None = None) -> dict:
        normalized = self.validate_query(query, context)
        country = normalized['object']['country']
        supplied = _copy(context) if context is not None else None
        initial_context_error: str | None = None
        if supplied is not None:
            current = supplied
        else:
            try:
                current = self.context()
            except Exception as exc:
                current = {}
                initial_context_error = (
                    "TRADE_COLLECTION_CONTEXT_READ_FAILED:" + type(exc).__name__
                )
        provenance: dict[str, Any] = {
            "adapter": "NativeTradeCollectionSource",
            "upstream_adapter": "NativeTradeIncomeSource",
            "country": country,
            "read_only": True,
            "native_function_invoked": False,
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "basis": _COLLECTION_BASIS,
            "value_origin": _COLLECTION_ORIGIN,
            "context_guard": {
                "mode": "live",
                "game_version": _VERSION,
                "game_sha256": _GAME_SHA256,
                "identity_keys": list(_CONTEXT_KEYS),
            },
        }

        def result(ctx: dict[str, Any], field: dict[str, Any]) -> dict[str, Any]:
            return self._result(normalized, ctx, {_FIELD: field}, provenance)

        if initial_context_error is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, _unavailable(initial_context_error))

        reason = _observer_context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, _unavailable(reason))

        if current.get('observer') != country:
            raise InformationError('observer_scope_mismatch', 'T02.collect_node is limited to the configured observer country')

        before = current
        if supplied is not None:
            try:
                before = self.context()
            except Exception as exc:
                provenance["context_guard"]["status"] = "unavailable"
                return result(current, _unavailable(
                    "TRADE_COLLECTION_CONTEXT_READ_FAILED:" + type(exc).__name__
                ))
            before_reason = _observer_context_reason(before)
            if before_reason is not None:
                provenance["context_guard"]["status"] = "unavailable"
                return result(before, _unavailable(before_reason))
            if _identity(current) != _identity(before):
                provenance["context_guard"]["status"] = "stale"
                return result(current, _unavailable("TRADE_COLLECTION_CONTEXT_STALE"))

        upstream: Any = None
        upstream_error: str | None = None
        try:
            upstream = self.trade_income_source.read(
                self._upstream_query(country), _copy(before)
            )
        except Exception as exc:
            upstream_error = "TRADE_COLLECTION_UPSTREAM_READ_FAILED:" + type(exc).__name__

        try:
            after = self.context()
        except Exception as exc:
            after = None
            after_error = "TRADE_COLLECTION_CONTEXT_READ_FAILED:" + type(exc).__name__
        else:
            after_error = None
        if after_error is not None:
            provenance["context_guard"]["status"] = "unavailable"
            self._attach_upstream(provenance, upstream)
            return result(before, _unavailable(after_error))
        after_reason = _observer_context_reason(after)
        if after_reason is not None or _identity(before) != _identity(after):
            provenance["context_guard"]["status"] = "changed"
            self._attach_upstream(provenance, upstream)
            return result(
                before,
                _unknown(after_reason or "TRADE_COLLECTION_CONTEXT_CHANGED_DURING_READ"),
            )

        self._attach_upstream(provenance, upstream)
        if upstream_error is not None:
            provenance["context_guard"]["status"] = "upstream_failed"
            return result(before, _unknown(upstream_error))
        provenance["context_guard"]["status"] = "passed"
        identity_reason = self._upstream_identity_reason(upstream, before)
        if identity_reason is not None:
            provenance["capture_reason"] = identity_reason
            return result(before, _unknown(identity_reason))
        return result(before, self._project_upstream_field(upstream))

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeTradeCollectionSource"]
