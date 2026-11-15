"""Read-only T05 trade-power transfer relation adapter.

The bounded transfer containers are captured by the existing trade-details
child.  This adapter only projects those containers; it does not calculate
income, shares, merchant tasks, or node value flow.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from .model import InformationError, canonical
from .sources import _copy, _result, _source_info
from .trade_details import (
    NativeTradeDetailsSource,
    _CONTEXT_KEYS,
    _COUNTRY,
    _GAME_SHA256,
    _NODE_ID,
    _PERIOD,
    _SOURCE_ROW_UNIT,
    _SOURCE_SCALE,
    _VERSION,
    _VALUE_ORIGIN,
    _details_context_reason,
    _identity,
    _session_binding,
)


_TOPIC = "T05"
_FIELD = "transfer"
_BASIS = "native_trade_power_transfer_relations"
_COMPLETE = False
_HEX = re.compile(r"[0-9a-fA-F]+\Z")


_CATALOG_ITEM = {
    "topic_id": _TOPIC,
    "catalog_ids": [_TOPIC],
    "title": "贸易收集、转移与收入",
    "status": "available",
    "fields": {
        _FIELD: {
            "coverage": "partial",
            "runtime_validation": "validated_native_cache",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _SOURCE_ROW_UNIT,
            "scale": _SOURCE_SCALE,
            "raw": False,
            "raw_semantics": (
                "TO/FROM transfer containers copied from each verified trade-node "
                "entry; direction comes from the container and signed raw values "
                "are retained"
            ),
            "paths": [
                "trade_details.nodes[].transfer_sources.to",
                "trade_details.nodes[].transfer_sources.from",
            ],
            "supported_countries": [_COUNTRY],
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "complete": _COMPLETE,
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "TRANSFER_COUNTRY_VISIBILITY_NOT_GENERALIZED",
                "LIVE_GUI_SELECTOR_ALIGNMENT_NOT_PROVEN",
                "MULTIPLIER_AND_NATIVE_TAIL_NOT_CLOSED",
                "OTHER_COUNTRIES_NOT_SUPPORTED",
            ],
        },
    },
    "object_types": ["country", "trade_node"],
    "observer_roles": ["country"],
    "observer_scope": [_COUNTRY],
    "parameters": {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic"],
    "runtime_validation": "validated",
    "source": "NativeTradeTransferSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "仅读取固定1.37.4、FRA观察者的原生贸易权转移容器；" 
        "该字段表示转出/转入关系，不表示商人任务、节点价值流量或收入。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _public_reason(reason: str) -> str:
    if reason.startswith("TRADE_DETAILS_"):
        return "TRADE_TRANSFER_" + reason.removeprefix("TRADE_DETAILS_")
    if reason.startswith("TRADE_INCOME_"):
        return "TRADE_TRANSFER_" + reason.removeprefix("TRADE_INCOME_")
    return reason


class NativeTradeTransferSource(NativeTradeDetailsSource):
    """Expose the verified T05 transfer containers with one shared capture."""

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
                f"T05 transfer query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeTradeTransferSource supports T05 only")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) not in ({"type", "country"}, {"type", "node_id"}):
            raise InformationError(
                "invalid_object", "T05 transfer requires a country or trade_node object",
            )
        if obj.get("type") == "country":
            if set(obj) != {"type", "country"} or obj.get("country") != _COUNTRY:
                raise InformationError("observer_scope_mismatch", "Only the verified FRA country is supported")
        elif obj.get("type") == "trade_node":
            if (
                set(obj) != {"type", "node_id"}
                or not isinstance(obj.get("node_id"), str)
                or _NODE_ID.fullmatch(obj["node_id"]) is None
                or obj["node_id"] == "Null"
            ):
                raise InformationError("invalid_object", "trade_node node_id must be bounded")
        else:
            raise InformationError("invalid_object", "T05 transfer object type is unsupported")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError("invalid_fields", "T05 transfer fields must be unique strings")
        if set(fields) != {_FIELD}:
            raise InformationError("unknown_field", "T05 transfer supports the transfer field only")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "T05 transfer parameters must be empty")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if observer is not None and observer != _COUNTRY:
                raise InformationError("observer_scope_mismatch", "T05 transfer is outside the FRA scope")
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
            "NativeTradeTransferSource", context, complete=False, provenance=provenance,
        )
        source["context_scope"] = "country_scope"
        if fields and all(
            isinstance(item, dict) and item.get("status") == "unavailable"
            for item in fields.values()
        ):
            source["status"] = "unavailable"
        return _result(normalized, context, fields, False, source)

    @staticmethod
    def _node_transfer(node: Mapping[str, Any]) -> dict[str, Any]:
        transfers = NativeTradeDetailsSource._transfer_sources(node)
        return {
            "node_id": node["node_id"],
            "to": transfers["to"],
            "from": transfers["from"],
        }

    def read(self, query: dict, context: dict | None = None) -> dict[str, Any]:
        supplied = _copy(context) if isinstance(context, dict) else None
        context_supplied = supplied is not None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]
        obj = normalized["object"]
        node_id = obj.get("node_id") if obj.get("type") == "trade_node" else None
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": _COUNTRY,
            "read_only": True,
            "native_function_invoked": False,
            "period": _PERIOD,
            "basis": _BASIS,
            "requested_object": deepcopy(obj),
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

        reason = _details_context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, _public_reason(reason), unavailable=True))

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            before_reason = _details_context_reason(before)
            if before_reason is not None:
                provenance["context_guard"]["status"] = "unavailable"
                return result(before, self._failure_fields(requested, _public_reason(before_reason), unavailable=True))
            if _identity(current) != _identity(before):
                provenance["context_guard"]["status"] = "stale"
                return result(before, self._failure_fields(requested, "TRADE_TRANSFER_CONTEXT_STALE", unavailable=True))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = _public_reason(binding_reason or "TRADE_INCOME_INSTALLATION_UNAVAILABLE")
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        captured = self._capture_trade_details_record(
            before,
            creation_filetime,
            installation,
            provenance,
            requested_node_id=node_id,
        )
        if not captured["ok"]:
            reason = _public_reason(captured.get("reason") or "TRADE_TRANSFER_CAPTURE_INVALID")
            provenance["capture_reason"] = reason
            return result(
                before,
                self._failure_fields(
                    requested, reason, unavailable=bool(captured.get("unavailable")),
                ),
            )

        details = captured["details"]
        nodes = details.get("nodes")
        if not isinstance(nodes, list):
            provenance["capture_reason"] = "TRADE_TRANSFER_NODES_MISSING"
            return result(before, self._failure_fields(requested, "TRADE_TRANSFER_NODES_MISSING", unavailable=False))
        provenance["node_count"] = len(nodes)

        if node_id is not None:
            selected = next(
                (node for node in nodes if isinstance(node, Mapping) and node.get("node_id") == node_id),
                None,
            )
            if selected is None:
                provenance["capture_reason"] = "NODE_NOT_FOUND"
                return result(before, {field: _unknown("NODE_NOT_FOUND") for field in requested})
            try:
                value: Any = self._node_transfer(selected)
            except Exception as exc:
                reason = "TRADE_TRANSFER_PROJECTION_FAILED:" + type(exc).__name__
                provenance["capture_reason"] = reason
                return result(before, self._failure_fields(requested, reason, unavailable=False))
        else:
            try:
                value = [
                    self._node_transfer(node)
                    for node in nodes
                    if isinstance(node, Mapping)
                ]
            except Exception as exc:
                reason = "TRADE_TRANSFER_PROJECTION_FAILED:" + type(exc).__name__
                provenance["capture_reason"] = reason
                return result(before, self._failure_fields(requested, reason, unavailable=False))

        fields = {
            _FIELD: {
                "status": "known",
                "value": value,
                "unit": _SOURCE_ROW_UNIT,
                "scale": _SOURCE_SCALE,
                "period": _PERIOD,
                "basis": _BASIS,
                "value_origin": _VALUE_ORIGIN,
                "complete": _COMPLETE,
            },
        }
        return result(before, fields)


__all__ = ["NativeTradeTransferSource"]
