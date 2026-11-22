"""Read-only T04 trade-share/source adapter.

The country-resources parent owns the country identity and the guarded trade
income graph.  This adapter requests the independent share/source child in the
same capture, validates all three child snapshots, and projects only the
selected node.  It never derives shares from trade power or aggregates source
rows into country power.
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
    _identity,
    _observer_context_reason,
    _parent_report_reason,
    _record_canonical_sha256,
    _session_binding,
)


_TOPIC = "T04"
_FIELDS = ("shares", "sources")
_SHARES = "shares"
_SOURCES = "sources"
_BASIS = "native_trade_node_share_and_source_caches"
_DETAILS_BASIS_ALIASES = frozenset({
    _BASIS,
    "native_trade_node_share_source_capital_dynamic_and_transfer_tail",
})
_PERIOD = "current"
_SHARE_UNIT = "ratio"
_SHARE_SCALE = 1000
_SOURCE_UNIT = "mixed"
_SOURCE_ROW_UNIT = "trade_power"
_SOURCE_SCALE = 1000
_DYNAMIC_UNIT = "unknown"
_DYNAMIC_NAME_REASON = "DYNAMIC_SOURCE_NAME_LOOKUP_NOT_RESOLVED"
_DYNAMIC_NAME_KEY_INVALID = "DYNAMIC_SOURCE_NAME_KEY_INVALID"
_LOCALISATION_NOT_READ = "LOCALISATION_NOT_READ"
_CLOSED_SOURCE_ROWS = frozenset({
    "TP_PROVINCE_POWER", "TP_SHIP_POWER", "TRADE_POWER_CAPITAL",
    "MERCHANT_DOWNSTREAM_BONUS",
})
_VALUE_ORIGIN = "copied_native_cache"
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_I32_MASK = (1 << 32) - 1


_CATALOG_ITEM = {
    "topic_id": _TOPIC,
    "catalog_ids": [_TOPIC],
    "title": "贸易节点份额与来源",
    "status": "available",
    "fields": {
        _SHARES: {
            "coverage": "partial",
            "runtime_validation": "validated_native_cache",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _SHARE_UNIT,
            "scale": _SHARE_SCALE,
            "raw": False,
            "raw_semantics": "selected entry+0x2c signed share cache for the configured observer",
            "paths": ["trade_details.nodes[].share_raw"],
            "supported_countries": [],
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "complete": False,
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "LIVE_GUI_SELECTOR_ALIGNMENT_NOT_PROVEN",
                "OTHER_COUNTRIES_NOT_SUPPORTED",
            ],
        },
        _SOURCES: {
            "coverage": "partial",
            "runtime_validation": "validated_native_cache",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _SOURCE_UNIT,
            "scale": _SOURCE_SCALE,
            "raw": False,
            "raw_semantics": (
                "selected node source rows; four closed trade-power row kinds are retained "
                "separately, while dynamic and transfer containers remain explicit and are "
                "never summed into country power; dynamic names conditionally use literal "
                "native localization, in a separate identity/date-guarded capture"
            ),
            "paths": [
                "trade_details.nodes[].source_rows",
                "trade_details.nodes[].capital",
                "trade_details.nodes[].dynamic_sources",
                "trade_details.nodes[].transfer_sources",
            ],
            "supported_countries": [],
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "complete": False,
            "gaps": [
                "LITERAL_DYNAMIC_SOURCE_NAMES_ONLY",
                "DYNAMIC_LOCALIZATION_SUBSTITUTION_NOT_EVALUATED",
                "DYNAMIC_SOURCE_VALUE_UNIT_NOT_CLOSED",
                "NAMES_AND_SOURCE_VALUES_NOT_ATOMIC",
                "LIVE_NONEMPTY_DYNAMIC_SOURCE_NOT_OBSERVED",
                "TRANSFER_COUNTRY_VISIBILITY_NOT_GENERALIZED",
                "MULTIPLIER_AND_NATIVE_TAIL_NOT_CLOSED",
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "LIVE_GUI_SELECTOR_ALIGNMENT_NOT_PROVEN",
                "OTHER_COUNTRIES_NOT_SUPPORTED",
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
    "source": "NativeTradeDetailsSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "仅读取固定1.37.4、FRA观察者指定贸易节点的原生份额和来源缓存；"
        "竞争国、缓存新鲜度、GUI选择器对应关系及来源字段完整语义仍未闭合。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _i32(value: Any) -> bool:
    return type(value) is int and _I32_MIN <= value <= _I32_MAX


def _i32_hex(value: int) -> str:
    return (value & _I32_MASK).to_bytes(4, "little", signed=False).hex()


def _valid_hex(value: Any, *, width: int | None = None) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if width is not None and len(value) != width:
        return False
    if width is None and len(value) != 8:
        return False
    return _HEX.fullmatch(value) is not None


def _valid_bytes_hex(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) % 2 or _HEX.fullmatch(value) is None:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _details_context_reason(context: Any) -> str | None:
    reason = _observer_context_reason(context)
    return reason.replace("TRADE_INCOME_", "TRADE_DETAILS_", 1) if reason else None


def _details_module():
    try:
        return importlib.import_module(".trade_details_memory", __package__)
    except Exception:
        return None


def _source_included(item: Mapping[str, Any]) -> bool | None:
    """Read either spelling used by the bounded child source contract."""

    for key in ("included", "included_by_static_condition"):
        value = item.get(key)
        if type(value) is bool:
            return value
    return None


def _capital_shape_reason(node: Mapping[str, Any]) -> str | None:
    capital = node.get("capital_status", node.get("capital"))
    if not isinstance(capital, Mapping):
        return "TRADE_DETAILS_CAPITAL_STATUS_INVALID"
    status = capital.get("status")
    if status in ("observed", "known"):
        if type(capital.get("included")) is not bool:
            return "TRADE_DETAILS_CAPITAL_STATUS_INVALID"
        if capital.get("included") or capital.get("raw") is not None:
            raw = capital.get("raw")
            raw_hex = capital.get("raw_hex")
            if not _i32(raw) or not _valid_hex(raw_hex) or raw_hex.lower() != _i32_hex(raw):
                return "TRADE_DETAILS_CAPITAL_VALUE_INVALID"
        return None
    if status in ("unknown", "unavailable"):
        if not isinstance(capital.get("reason"), str) or not capital.get("reason"):
            return "TRADE_DETAILS_CAPITAL_STATUS_INVALID"
        return None
    return "TRADE_DETAILS_CAPITAL_STATUS_INVALID"


def _dynamic_shape_reason(dynamic: Any) -> str | None:
    if not isinstance(dynamic, Mapping):
        return "TRADE_DETAILS_DYNAMIC_SOURCES_INVALID"
    status = dynamic.get("status")
    if status not in ("observed", "empty", "known", "unknown", "unavailable"):
        return "TRADE_DETAILS_DYNAMIC_SOURCES_INVALID"
    items = dynamic.get("items")
    if not isinstance(items, list):
        return "TRADE_DETAILS_DYNAMIC_SOURCES_INVALID"
    if status in ("unknown", "unavailable") and (
        not isinstance(dynamic.get("reason"), str) or not dynamic.get("reason")
    ):
        return "TRADE_DETAILS_DYNAMIC_SOURCES_INVALID"
    for item in items:
        if not isinstance(item, Mapping):
            return "TRADE_DETAILS_DYNAMIC_ITEM_INVALID"
        raw = item.get("raw", item.get("value_raw"))
        raw_hex = item.get("raw_hex", item.get("value_raw_hex"))
        if not _i32(raw) or not _valid_hex(raw_hex) or raw_hex.lower() != _i32_hex(raw):
            return "TRADE_DETAILS_DYNAMIC_ITEM_INVALID"
        name = item.get("name")
        name_raw_hex = item.get("name_raw_hex")
        if isinstance(name, Mapping):
            name_raw_hex = name.get("raw_hex", name.get("raw_template_hex", name_raw_hex))
        if name_raw_hex is not None and not _valid_bytes_hex(name_raw_hex):
            return "TRADE_DETAILS_DYNAMIC_NAME_INVALID"
        if "unit" in item and item.get("unit") != _DYNAMIC_UNIT:
            return "TRADE_DETAILS_DYNAMIC_UNIT_INVALID"
        if "scale" in item and item.get("scale") != _SOURCE_SCALE:
            return "TRADE_DETAILS_DYNAMIC_SCALE_INVALID"
    return None


def _transfer_item_shape_reason(item: Any, direction: str) -> str | None:
    if not isinstance(item, Mapping):
        return "TRADE_DETAILS_TRANSFER_ITEM_INVALID"
    raw = item.get("raw", item.get("value_raw"))
    raw_hex = item.get("raw_hex", item.get("value_raw_hex"))
    if not _i32(raw) or not _valid_hex(raw_hex) or raw_hex.lower() != _i32_hex(raw):
        return "TRADE_DETAILS_TRANSFER_ITEM_INVALID"
    fullref = item.get("fullref", item.get("fullref_raw_hex"))
    if isinstance(fullref, str):
        if not _valid_hex(fullref, width=16):
            return "TRADE_DETAILS_TRANSFER_FULLREF_INVALID"
    elif type(fullref) is not int or fullref < 0:
        return "TRADE_DETAILS_TRANSFER_FULLREF_INVALID"
    slot = item.get("slot", item.get("country_slot"))
    if type(slot) is not int or not 0 <= slot <= 0xFFFF:
        return "TRADE_DETAILS_TRANSFER_SLOT_INVALID"
    if "unit" in item and item.get("unit") != _SOURCE_ROW_UNIT:
        return "TRADE_DETAILS_TRANSFER_UNIT_INVALID"
    if "scale" in item and item.get("scale") != _SOURCE_SCALE:
        return "TRADE_DETAILS_TRANSFER_SCALE_INVALID"
    item_direction = item.get("direction")
    if item_direction is not None and item_direction != direction:
        return "TRADE_DETAILS_TRANSFER_DIRECTION_INVALID"
    country = item.get("country", item.get("country_tag"))
    if country is not None:
        if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
            return "TRADE_DETAILS_TRANSFER_COUNTRY_INVALID"
        for key in ("country_table_validated", "country_validated", "fullref_validated"):
            if item.get(key) is False:
                return "TRADE_DETAILS_TRANSFER_COUNTRY_UNVALIDATED"
        if item.get("country_fullref_matched") is False:
            return "TRADE_DETAILS_TRANSFER_COUNTRY_UNVALIDATED"
    return None


def _transfer_shape_reason(container: Any, direction: str) -> str | None:
    if not isinstance(container, Mapping):
        return "TRADE_DETAILS_TRANSFER_SOURCES_INVALID"
    status = container.get("status")
    if status not in ("observed", "empty", "known", "unknown", "unavailable"):
        return "TRADE_DETAILS_TRANSFER_SOURCES_INVALID"
    items = container.get("items")
    if not isinstance(items, list):
        return "TRADE_DETAILS_TRANSFER_SOURCES_INVALID"
    if status in ("unknown", "unavailable") and (
        not isinstance(container.get("reason"), str) or not container.get("reason")
    ):
        return "TRADE_DETAILS_TRANSFER_SOURCES_INVALID"
    for item in items:
        reason = _transfer_item_shape_reason(item, direction)
        if reason is not None:
            return reason
    return None


def _details_shape_reason(details: Any, country: str) -> str | None:
    if not isinstance(details, Mapping) or details.get("status") != "observed":
        return "TRADE_DETAILS_RECORD_INVALID"
    if (
        details.get("country") != country
        or details.get("basis") not in _DETAILS_BASIS_ALIASES
        or details.get("period") != _PERIOD
        or details.get("value_origin") != _VALUE_ORIGIN
        or details.get("unit", _SOURCE_UNIT) != _SOURCE_UNIT
        or not isinstance(details.get("country_fullref_raw_hex"), str)
        or not _valid_hex(details.get("country_fullref_raw_hex"), width=16)
        or type(details.get("country_slot")) is not int
        or not 0 <= details["country_slot"] <= 0xFFFF
    ):
        return "TRADE_DETAILS_RECORD_SHAPE_INVALID"
    for guard_name in ("static_contract_guard", "runtime_code_guard"):
        guard = details.get(guard_name)
        if not isinstance(guard, Mapping) or guard.get("status") != "observed":
            return f"TRADE_DETAILS_{guard_name.upper()}_INVALID"
    nodes = details.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return "TRADE_DETAILS_NODES_INVALID"
    seen: set[str] = set()
    for node in nodes:
        if not isinstance(node, Mapping):
            return "TRADE_DETAILS_NODE_INVALID"
        node_id = node.get("node_id")
        if (
            not isinstance(node_id, str)
            or _NODE_ID.fullmatch(node_id) is None
            or node_id == "Null"
            or node_id in seen
        ):
            return "TRADE_DETAILS_NODE_ID_INVALID"
        seen.add(node_id)
        share = node.get("share_raw")
        share_hex = node.get("share_raw_hex")
        if not _i32(share) or not _valid_hex(share_hex) or share_hex.lower() != _i32_hex(share):
            return "TRADE_DETAILS_SHARE_INVALID"
        inputs = node.get("source_inputs")
        rows = node.get("source_rows")
        if not isinstance(inputs, Mapping) or not isinstance(rows, list):
            return "TRADE_DETAILS_SOURCE_SHAPE_INVALID"
        included_keys: set[str] = set()
        for native_key, item in inputs.items():
            if not isinstance(native_key, str) or not native_key or not isinstance(item, Mapping):
                return "TRADE_DETAILS_SOURCE_INPUT_INVALID"
            raw = item.get("raw")
            raw_hex = item.get("raw_hex")
            if (
                not _i32(raw)
                or not _valid_hex(raw_hex)
                or raw_hex.lower() != _i32_hex(raw)
                or _source_included(item) is None
            ):
                return "TRADE_DETAILS_SOURCE_INPUT_INVALID"
            if _source_included(item):
                included_keys.add(native_key)
        seen_rows: set[str] = set()
        for row in rows:
            if not isinstance(row, Mapping):
                return "TRADE_DETAILS_SOURCE_ROW_INVALID"
            native_key = row.get("native_key")
            raw = row.get("raw")
            raw_hex = row.get("raw_hex")
            if (
                not isinstance(native_key, str)
                or not native_key
                or native_key in seen_rows
                or not _i32(raw)
                or not _valid_hex(raw_hex)
                or raw_hex.lower() != _i32_hex(raw)
                or ("unit" in row and row.get("unit") != _SOURCE_ROW_UNIT)
                or ("scale" in row and row.get("scale") != _SOURCE_SCALE)
            ):
                return "TRADE_DETAILS_SOURCE_ROW_INVALID"
            if native_key not in _CLOSED_SOURCE_ROWS:
                # Keep the child record auditable but never publish an
                # unclosed multiplier/native-tail value as a source row.
                seen_rows.add(native_key)
                continue
            if native_key == "TRADE_POWER_CAPITAL" and native_key not in inputs:
                source_input = node.get("capital_status", node.get("capital"))
                if not isinstance(source_input, Mapping):
                    return "TRADE_DETAILS_SOURCE_ROW_INPUT_MISMATCH"
            else:
                if native_key not in inputs:
                    return "TRADE_DETAILS_SOURCE_ROW_INVALID"
                source_input = inputs[native_key]
            if raw != source_input.get("raw") or raw_hex.lower() != str(source_input.get("raw_hex", "")).lower():
                return "TRADE_DETAILS_SOURCE_ROW_INPUT_MISMATCH"
            row_included = _source_included(row)
            capital_included = source_input.get("included") is True if native_key == "TRADE_POWER_CAPITAL" else False
            if row_included is True and native_key not in included_keys and not capital_included:
                return "TRADE_DETAILS_SOURCE_INCLUSION_MISMATCH"
            if row_included is False and native_key in included_keys and native_key != "TRADE_POWER_CAPITAL":
                return "TRADE_DETAILS_SOURCE_INCLUSION_MISMATCH"
            seen_rows.add(native_key)
        capital_reason = _capital_shape_reason(node)
        if capital_reason is not None:
            return capital_reason
        dynamic_reason = _dynamic_shape_reason(node.get("dynamic_sources"))
        if dynamic_reason is not None:
            return dynamic_reason
        for direction in ("to", "from"):
            container = node.get(f"transfer_sources_{direction}")
            if container is None and isinstance(node.get("transfer_sources"), Mapping):
                container = node["transfer_sources"].get(direction)
            if container is not None:
                transfer_reason = _transfer_shape_reason(container, direction)
                if transfer_reason is not None:
                    return transfer_reason
    return None


def _details_validate_reason(details: Any, trade_income: Any) -> str | None:
    module = _details_module()
    if module is None:
        return "TRADE_DETAILS_VALIDATOR_UNAVAILABLE"
    validator = getattr(module, "validate_record", None)
    if not callable(validator):
        return "TRADE_DETAILS_VALIDATOR_UNAVAILABLE"
    try:
        valid = validator(details, trade_income)
    except Exception as exc:
        return "TRADE_DETAILS_RECORD_VALIDATION_FAILED:" + type(exc).__name__
    if valid is not True:
        return "TRADE_DETAILS_RECORD_INVALID"
    expected = getattr(module, "EXPECTED_PROFILE_SHA256", None)
    if (
        isinstance(expected, str)
        and len(expected) == 64
        and expected != "pending-profile"
        and details.get("profile_sha256") != expected
    ):
        return "TRADE_DETAILS_PROFILE_PIN_INVALID"
    return _details_shape_reason(details, trade_income.get("country"))


def _details_parent_reason(report: Any, context: Mapping[str, Any], creation: int) -> str | None:
    reason = _parent_report_reason(report, context, context["observer"], creation)
    if reason is not None:
        return reason.replace("TRADE_INCOME_", "TRADE_DETAILS_", 1)
    request = report.get("request") if isinstance(report, Mapping) else None
    if not isinstance(request, Mapping) or request.get("include_trade_details") is not True:
        return "TRADE_DETAILS_PARENT_REQUEST_INVALID"
    return None


def _details_record_reason(report: Any) -> str | None:
    if not isinstance(report, Mapping):
        return "TRADE_DETAILS_PARENT_CAPTURE_INVALID"
    top = report.get("trade_details")
    before_snapshot = report.get("before")
    after_snapshot = report.get("after")
    before = before_snapshot.get("trade_details") if isinstance(before_snapshot, Mapping) else None
    after = after_snapshot.get("trade_details") if isinstance(after_snapshot, Mapping) else None
    trade_top = report.get("trade_income")
    trade_before = before_snapshot.get("trade_income") if isinstance(before_snapshot, Mapping) else None
    trade_after = after_snapshot.get("trade_income") if isinstance(after_snapshot, Mapping) else None
    for label, details, trade in (
        ("TOP", top, trade_top), ("BEFORE", before, trade_before), ("AFTER", after, trade_after),
    ):
        if not isinstance(details, Mapping) or not isinstance(trade, Mapping):
            return "TRADE_DETAILS_RECORD_MISSING"
        reason = _details_validate_reason(details, trade)
        if reason is not None:
            return f"TRADE_DETAILS_{label}_{reason.removeprefix('TRADE_DETAILS_')}"
    try:
        if canonical(top) != canonical(before) or canonical(top) != canonical(after):
            return "TRADE_DETAILS_SNAPSHOT_MISMATCH"
    except Exception:
        return "TRADE_DETAILS_RECORD_CANONICAL_INVALID"
    return None


def _node_for(details: Mapping[str, Any], node_id: str) -> Mapping[str, Any] | None:
    nodes = details.get("nodes")
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
        "checks": deepcopy(value.get("checks", {})) if isinstance(value.get("checks", {}), Mapping) else {},
        "records": {},
    }
    for key in ("profile_id", "profile_sha256", "module_base"):
        if key in value:
            result[key] = deepcopy(value[key])
    records = value.get("records")
    if isinstance(records, Mapping):
        for name, record in records.items():
            if isinstance(name, str) and isinstance(record, Mapping):
                result["records"][name] = {
                    key: deepcopy(record[key])
                    for key in ("rva", "address", "expected_sha256", "actual_sha256")
                    if key in record
                }
    return result


def _compact_details_provenance(
    details: Mapping[str, Any], trade_income: Mapping[str, Any], node_id: str | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": details.get("status"),
        "profile_sha256": details.get("profile_sha256"),
        "static_contract_guard": _compact_guard(details.get("static_contract_guard")),
        "runtime_code_guard": _compact_guard(details.get("runtime_code_guard")),
        "record_canonical_sha256": _record_canonical_sha256(details),
        "trade_income_record_canonical_sha256": _record_canonical_sha256(trade_income),
        "country": details.get("country"),
        "country_fullref_raw_hex": details.get("country_fullref_raw_hex"),
        "country_slot": details.get("country_slot"),
        "basis": details.get("basis"),
        "period": details.get("period"),
        "value_origin": details.get("value_origin"),
        "requested_node_id": node_id,
    }
    node = _node_for(details, node_id) if isinstance(node_id, str) else None
    if node is not None:
        capital = node.get("capital_status", node.get("capital"))
        result["node"] = {
            "node_id": node_id,
            "share_raw": node.get("share_raw"),
            "share_raw_hex": node.get("share_raw_hex"),
            "source_inputs": deepcopy(node.get("source_inputs")),
            "source_rows": deepcopy(node.get("source_rows")),
            "capital_status": deepcopy(capital),
            "dynamic_sources": deepcopy(node.get("dynamic_sources")),
        }
        transfer = node.get("transfer_sources")
        if transfer is not None:
            result["node"]["transfer_sources"] = deepcopy(transfer)
        for direction in ("to", "from"):
            key = f"transfer_sources_{direction}"
            if node.get(key) is not None:
                result["node"][key] = deepcopy(node[key])
    if details.get("reason") is not None:
        result["reason"] = details.get("reason")
    return result


class NativeTradeDetailsSource(NativeTradeIncomeSource):
    """Expose T04 shares and source rows for the configured observer country."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None, localization_reader=None):
        super().__init__(base_source, capture=capture)
        # Keep construction side-effect free.  The neutral native reader is
        # created only after a selected node has a validated, non-empty
        # dynamic list and the caller actually requested ``sources``.
        self.localization_reader = localization_reader

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
            raise InformationError("unknown_topic", "NativeTradeDetailsSource supports T04 only")
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
            raise InformationError("unknown_field", f"T04 fields are outside the details adapter: {sorted(unknown)}")
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
        source = _source_info("NativeTradeDetailsSource", context, complete=False, provenance=provenance)
        source["context_scope"] = "country_scope"
        if isinstance(provenance, Mapping) and provenance.get("name_localization") is not None:
            source["name_localization"] = deepcopy(provenance["name_localization"])
        if fields and all(
            isinstance(item, dict) and item.get("status") == "unavailable"
            for item in fields.values()
        ):
            source["status"] = "unavailable"
        return _result(normalized, context, fields, False, source)

    def _localization_reader(self):
        """Return an injected reader or lazily construct the neutral reader."""

        if self.localization_reader is None:
            from .native_localization import NativeLocalizationReader
            self.localization_reader = NativeLocalizationReader(self.base_source)
        return self.localization_reader

    def _capture_reader(self):
        if self.capture is not None:
            return self.capture
        try:
            from .country_resources_memory import capture
        except Exception:
            return None
        return capture

    def _capture_trade_details_record(
        self,
        before: Mapping[str, Any],
        creation_filetime: int,
        installation: Any,
        provenance: dict[str, Any],
        *,
        requested_node_id: str | None = None,
    ) -> dict[str, Any]:
        """Capture and validate the shared trade-income/details child once.

        T04 and T05 transfer must consume the same parent report.  Keeping the
        context recheck, parent contract, and all three child validations here
        prevents a second capture when a query selects the country collection.
        The returned mapping is intentionally private and carries the complete
        validated report only to sibling adapters.
        """

        capture = self._capture_reader()
        if not callable(capture):
            provenance["context_guard"]["status"] = "unavailable"
            return {
                "ok": False,
                "reason": "TRADE_DETAILS_CAPTURE_UNAVAILABLE",
                "unavailable": True,
                "context": dict(before),
                "report": None,
            }

        report: Any = None
        capture_error: str | None = None
        try:
            report = capture(
                installation,
                before["observer"],
                include_trade_income=True,
                include_trade_details=True,
            )
        except Exception as exc:
            capture_error = "TRADE_DETAILS_CAPTURE_FAILED:" + type(exc).__name__

        # Always re-read context, including when the capture callable raised.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = _details_context_reason(after)
        if after_reason is not None or _identity(before) != _identity(after):
            provenance["context_guard"]["status"] = "changed"
            reason = after_reason or "TRADE_DETAILS_CONTEXT_CHANGED_DURING_CAPTURE"
            if isinstance(report, Mapping):
                details = report.get("trade_details")
                trade = report.get("trade_income")
                if isinstance(details, Mapping) and isinstance(trade, Mapping):
                    provenance["trade_details"] = _compact_details_provenance(
                        details, trade, requested_node_id,
                    )
            return {
                "ok": False,
                "reason": reason,
                "unavailable": False,
                "context": dict(before),
                "report": report,
                "after": after,
            }

        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            return {
                "ok": False,
                "reason": capture_error,
                "unavailable": False,
                "context": dict(before),
                "report": report,
                "after": after,
            }

        if isinstance(report, Mapping):
            details = report.get("trade_details")
            trade = report.get("trade_income")
            if isinstance(details, Mapping) and isinstance(trade, Mapping):
                provenance["trade_details"] = _compact_details_provenance(
                    details, trade, requested_node_id,
                )
                provenance["trade_income"] = {
                    "record_canonical_sha256": _record_canonical_sha256(trade),
                }
        provenance["context_guard"]["status"] = "capture_invalid"

        reason = _details_parent_reason(report, before, creation_filetime)
        if reason is not None:
            provenance["capture_reason"] = reason
            return {
                "ok": False,
                "reason": reason,
                "unavailable": False,
                "context": dict(before),
                "report": report,
                "after": after,
            }
        reason = _capture_record_reason(report, before["observer"])
        if reason is not None:
            reason = reason.replace("TRADE_INCOME_", "TRADE_DETAILS_TRADE_INCOME_", 1)
            provenance["capture_reason"] = reason
            return {
                "ok": False,
                "reason": reason,
                "unavailable": False,
                "context": dict(before),
                "report": report,
                "after": after,
            }
        reason = _details_record_reason(report)
        if reason is not None:
            provenance["capture_reason"] = reason
            return {
                "ok": False,
                "reason": reason,
                "unavailable": False,
                "context": dict(before),
                "report": report,
                "after": after,
            }

        trade = report["trade_income"]
        details = report["trade_details"]
        provenance["context_guard"]["status"] = "passed"
        provenance["trade_details"] = _compact_details_provenance(
            details, trade, requested_node_id,
        )
        return {
            "ok": True,
            "reason": None,
            "unavailable": False,
            "context": dict(before),
            "after": after,
            "report": report,
            "trade": trade,
            "details": details,
        }

    @staticmethod
    def _capital_status(node: Mapping[str, Any]) -> dict[str, Any]:
        capital = node.get("capital_status", node.get("capital"))
        if not isinstance(capital, Mapping):
            return {"status": "unknown", "reason": "CAPITAL_STATUS_NOT_CAPTURED"}
        status = capital.get("status")
        if status in ("observed", "known") and type(capital.get("included")) is bool:
            result: dict[str, Any] = {
                "status": "known", "included": capital["included"],
            }
            if capital.get("raw") is not None:
                result["raw"] = capital.get("raw")
                result["raw_hex"] = capital.get("raw_hex")
                result["unit"] = _SOURCE_ROW_UNIT
                result["scale"] = _SOURCE_SCALE
            if capital.get("reason"):
                result["reason"] = capital.get("reason")
            return result
        reason = capital.get("reason")
        return {"status": "unknown", "reason": reason or "CAPITAL_STATUS_NOT_CAPTURED"}

    @staticmethod
    def _dynamic_sources(
        node: Mapping[str, Any], *, localized_names: list[dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        dynamic = node.get("dynamic_sources")
        if not isinstance(dynamic, Mapping):
            return {"status": "unknown", "items": [], "reason": "DYNAMIC_SOURCES_NOT_CAPTURED"}
        status = dynamic.get("status")
        if status in ("unknown", "unavailable"):
            return {
                "status": "unknown",
                "items": [],
                "reason": dynamic.get("reason") or "DYNAMIC_SOURCES_UNKNOWN",
            }
        if status not in ("observed", "empty", "known"):
            return {"status": "unknown", "items": [], "reason": "DYNAMIC_SOURCES_INVALID"}
        items: list[dict[str, Any]] = []
        for index, source in enumerate(dynamic.get("items", [])):
            if not isinstance(source, Mapping):
                raise ValueError("TRADE_DETAILS_DYNAMIC_ITEM_INVALID")
            raw = source.get("raw", source.get("value_raw"))
            raw_hex = source.get("raw_hex", source.get("value_raw_hex"))
            if not _i32(raw) or not _valid_hex(raw_hex) or raw_hex.lower() != _i32_hex(raw):
                raise ValueError("TRADE_DETAILS_DYNAMIC_ITEM_INVALID")
            name = source.get("name")
            name_raw_hex = source.get("name_raw_hex")
            if isinstance(name, Mapping):
                name_raw_hex = name.get("raw_hex", name.get("raw_template_hex", name_raw_hex))
            if name_raw_hex is not None and not _valid_bytes_hex(name_raw_hex):
                raise ValueError("TRADE_DETAILS_DYNAMIC_NAME_INVALID")
            if localized_names is not None and index < len(localized_names) and localized_names[index] is not None:
                localized_name = deepcopy(localized_names[index])
            else:
                localized_name = {
                    "status": "unknown",
                    "reason": _DYNAMIC_NAME_REASON,
                    "raw_hex": name_raw_hex,
                }
            items.append({
                "raw": raw,
                "raw_hex": raw_hex,
                "unit": _DYNAMIC_UNIT,
                "scale": _SOURCE_SCALE,
                "name": localized_name,
            })
        return {"status": "known", "items": items}

    @staticmethod
    def _transfer_sources(node: Mapping[str, Any]) -> dict[str, Any]:
        raw_container = node.get("transfer_sources")
        result: dict[str, Any] = {}
        for direction in ("to", "from"):
            container = node.get(f"transfer_sources_{direction}")
            if container is None and isinstance(raw_container, Mapping):
                container = raw_container.get(direction)
            if not isinstance(container, Mapping):
                result[direction] = {
                    "status": "unknown", "items": [],
                    "reason": "TRANSFER_SOURCES_NOT_CAPTURED",
                }
                continue
            status = container.get("status")
            if status in ("unknown", "unavailable"):
                result[direction] = {
                    "status": "unknown", "items": [],
                    "reason": container.get("reason") or "TRANSFER_SOURCES_UNKNOWN",
                }
                continue
            if status not in ("observed", "empty", "known") or not isinstance(container.get("items"), list):
                raise ValueError("TRADE_DETAILS_TRANSFER_SOURCES_INVALID")
            items: list[dict[str, Any]] = []
            for source in container["items"]:
                reason = _transfer_item_shape_reason(source, direction)
                if reason is not None:
                    raise ValueError(reason)
                fullref = source.get("fullref", source.get("fullref_raw_hex"))
                country = source.get("country", source.get("country_tag"))
                # A child validator owns the country-table equality guard.  A
                # negative explicit marker still suppresses the tag here.
                if any(source.get(key) is False for key in ("country_table_validated", "country_validated", "fullref_validated")) or source.get("country_fullref_matched") is False:
                    country = None
                items.append({
                    "country": country,
                    "fullref_raw_hex": fullref,
                    "slot": source.get("slot", source.get("country_slot")),
                    "raw": source.get("raw", source.get("value_raw")),
                    "raw_hex": source.get("raw_hex", source.get("value_raw_hex")),
                    "unit": _SOURCE_ROW_UNIT,
                    "scale": _SOURCE_SCALE,
                    "native_key": source.get("native_key") or (
                        "TRANSFER_TRADE_POWER_TO" if direction == "to" else "TRANSFER_TRADE_POWER_FROM"
                    ),
                    "direction": direction,
                })
            result[direction] = {"status": "known", "items": items}
        return result

    @staticmethod
    def _source_rows(node: Mapping[str, Any]) -> list[dict[str, Any]]:
        rows = node.get("source_rows")
        if not isinstance(rows, list):
            raise ValueError("TRADE_DETAILS_SOURCE_ROWS_INVALID")
        result: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError("TRADE_DETAILS_SOURCE_ROW_INVALID")
            item = deepcopy(dict(row))
            if item.get("native_key") not in _CLOSED_SOURCE_ROWS:
                continue
            item.setdefault("unit", _SOURCE_ROW_UNIT)
            item.setdefault("scale", _SOURCE_SCALE)
            if item.get("unit") != _SOURCE_ROW_UNIT or item.get("scale") != _SOURCE_SCALE:
                raise ValueError("TRADE_DETAILS_SOURCE_ROW_INVALID")
            result.append(item)
        return result

    @staticmethod
    def _field_from_node(
        node: Mapping[str, Any], field: str, *, country: str,
        localized_names: list[dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        share = node.get("share_raw")
        share_hex = node.get("share_raw_hex")
        if not _i32(share) or not _valid_hex(share_hex) or share_hex.lower() != _i32_hex(share):
            raise ValueError("TRADE_DETAILS_SHARE_INVALID")
        common = {
            "status": "known",
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "complete": False,
        }
        if field == _SHARES:
            return dict(common, value={country: {
                "raw": share,
                "raw_hex": share_hex,
                "unit": _SHARE_UNIT,
                "scale": _SHARE_SCALE,
            }}, unit=_SHARE_UNIT, scale=_SHARE_SCALE)
        rows = NativeTradeDetailsSource._source_rows(node)
        value = {
            "rows": rows,
            "capital_status": NativeTradeDetailsSource._capital_status(node),
            "dynamic_sources": NativeTradeDetailsSource._dynamic_sources(
                node, localized_names=localized_names,
            ),
            "transfer_sources": NativeTradeDetailsSource._transfer_sources(node),
            "multiplier": deepcopy(node.get("multiplier")) if isinstance(node.get("multiplier"), Mapping) else {
                "status": "unknown", "reason": "TRADE_MULTIPLIER_NOT_CLOSED",
            },
        }
        return dict(common, value={country: value}, unit=_SOURCE_UNIT, scale=_SOURCE_SCALE)

    @staticmethod
    def _dynamic_key(raw_hex: Any) -> tuple[str | None, str | None]:
        """Decode one bounded dynamic name only when it is a locale key.

        The child record has already proved the C-string terminator and byte
        bounds.  This second filter is deliberately stricter: localization
        keys are non-empty printable ASCII, with one terminal NUL and no
        embedded NUL.  Invalid bytes remain auditable in the public name.
        """

        if not _valid_bytes_hex(raw_hex):
            return None, _DYNAMIC_NAME_KEY_INVALID
        raw = bytes.fromhex(raw_hex)
        if (
            len(raw) < 2
            or raw[-1:] != b"\0"
            or b"\0" in raw[:-1]
            or len(raw) - 1 > 160
            or any(byte < 0x21 or byte > 0x7E for byte in raw[:-1])
        ):
            return None, _DYNAMIC_NAME_KEY_INVALID
        try:
            key = raw[:-1].decode("ascii")
        except UnicodeDecodeError:
            return None, _DYNAMIC_NAME_KEY_INVALID
        return (key, None) if key else (None, _DYNAMIC_NAME_KEY_INVALID)

    @staticmethod
    def _name_metadata(
        raw_hex: Any, key: str | None = None, localized: Mapping[str, Any] | None = None,
        entry: Mapping[str, Any] | None = None, *, status: str = "unknown",
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Build bounded name audit data without exposing cache bytes as text."""

        localized = localized if isinstance(localized, Mapping) else {}
        entry = entry if isinstance(entry, Mapping) else {}
        reader_provenance = localized.get("provenance", {})
        if not isinstance(reader_provenance, Mapping):
            reader_provenance = {}
        codec = entry.get("codec")
        if codec is None:
            codec = localized.get("codec")
        if codec is None:
            codec = reader_provenance.get("codec")
        raw_template_hex = entry.get("raw_template_hex")
        if raw_template_hex is None:
            raw_template_hex = entry.get("value_hex")
        metadata: dict[str, Any] = {
            "status": status,
            "raw_hex": deepcopy(raw_hex),
        }
        if key is not None:
            metadata.update({
                "key": key,
                "language": localized.get("language", entry.get("language")),
                "codec": codec,
                "raw_template_hex": deepcopy(raw_template_hex),
                "reader_provenance": deepcopy(dict(reader_provenance)),
            })
        if reason is not None:
            metadata["reason"] = reason
        return metadata

    @staticmethod
    def _entry_name(
        raw_hex: Any, key: str, localized: Any, entry: Any,
    ) -> dict[str, Any]:
        """Map one neutral-reader entry to a dynamic item name."""

        localized_map = localized if isinstance(localized, Mapping) else {}
        entry_map = entry if isinstance(entry, Mapping) else None
        if entry_map is None:
            return NativeTradeDetailsSource._name_metadata(
                raw_hex, key, localized_map, None,
                reason="LOCALIZATION_KEY_UNRESOLVED",
            )
        entry_status = entry_map.get("status")
        if entry_status != "known":
            reason = entry_map.get("reason") or entry_map.get("unknown_reason")
            if not isinstance(reason, str) or not reason:
                reason = (
                    "DYNAMIC_LOCALIZATION_UNRESOLVED"
                    if entry_status in {"template", "dynamic"}
                    else "LOCALIZATION_KEY_UNRESOLVED"
                )
            result = NativeTradeDetailsSource._name_metadata(
                raw_hex, key, localized_map, entry_map, reason=reason,
            )
            # Keep unresolved template/bytes for audit, while never treating
            # either as the displayed name.
            for field in ("template", "unresolved_tokens", "unresolved_markers"):
                if field in entry_map:
                    result[field] = deepcopy(entry_map[field])
            return result

        text = entry_map.get("text")
        raw_template_hex = entry_map.get("raw_template_hex", entry_map.get("value_hex"))
        valid_raw = (
            raw_template_hex is None
            or (
                isinstance(raw_template_hex, str)
                and len(raw_template_hex) % 2 == 0
                and _HEX.fullmatch(raw_template_hex) is not None
            )
        )
        dynamic = (
            not isinstance(text, str)
            or any(marker in text for marker in "[]$")
            or bool(entry_map.get("dynamic_tokens"))
            or bool(entry_map.get("unresolved_tokens"))
            or bool(entry_map.get("unresolved_markers"))
            or (
                isinstance(entry_map.get("template"), str)
                and (
                    entry_map.get("template") != text
                    or any(marker in entry_map["template"] for marker in "[]$")
                )
            )
            or entry_map.get("decoded_status") not in {None, "decoded"}
        )
        if not valid_raw:
            reason = entry_map.get("reason") if isinstance(entry_map.get("reason"), str) else "LOCALIZATION_BYTES_INVALID"
            return NativeTradeDetailsSource._name_metadata(
                raw_hex, key, localized_map, entry_map, reason=reason,
            )
        if dynamic:
            reason = entry_map.get("reason") if isinstance(entry_map.get("reason"), str) else "DYNAMIC_LOCALIZATION_UNRESOLVED"
            result = NativeTradeDetailsSource._name_metadata(
                raw_hex, key, localized_map, entry_map, reason=reason,
            )
            for field in ("template", "unresolved_tokens", "unresolved_markers"):
                if field in entry_map:
                    result[field] = deepcopy(entry_map[field])
            return result
        result = NativeTradeDetailsSource._name_metadata(
            raw_hex, key, localized_map, entry_map, status="known",
        )
        result["value"] = text
        return result

    def _localized_dynamic_names(
        self, node: Mapping[str, Any], context: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any] | None] | None, dict[str, Any] | None, bool]:
        """Resolve validated dynamic keys, returning names, audit and attempt flag."""

        dynamic = node.get("dynamic_sources")
        if (
            not isinstance(dynamic, Mapping)
            or dynamic.get("status") != "observed"
            or not isinstance(dynamic.get("items"), list)
            or not dynamic.get("items")
        ):
            return None, None, False
        names: list[dict[str, Any] | None] = [None] * len(dynamic["items"])
        key_by_index: dict[int, str] = {}
        raw_by_index: dict[int, Any] = {}
        keys: list[str] = []
        seen: set[str] = set()
        for index, source in enumerate(dynamic["items"]):
            if not isinstance(source, Mapping):
                continue
            name = source.get("name")
            raw_hex = source.get("name_raw_hex")
            if isinstance(name, Mapping):
                raw_hex = name.get("raw_hex", name.get("raw_template_hex", raw_hex))
            raw_by_index[index] = raw_hex
            key, invalid_reason = self._dynamic_key(raw_hex)
            if key is None:
                names[index] = self._name_metadata(raw_hex, reason=invalid_reason or _DYNAMIC_NAME_KEY_INVALID)
                continue
            key_by_index[index] = key
            if key not in seen:
                seen.add(key)
                keys.append(key)
        if not keys:
            return names, None, False

        # A legacy/base source without an operator-selected native text codec
        # has no usable localization reader contract.  Leave the historical
        # unresolved name untouched and, crucially, do not perform a cache
        # read merely because a dynamic list exists.  An explicitly injected
        # reader is still allowed to define its own offline seam.
        if self.localization_reader is None:
            session = getattr(self.base_source, "session", None)
            record = getattr(session, "record", {})
            if not isinstance(record, Mapping) or not record.get("native_text_codec"):
                return names, None, False

        try:
            reader = self._localization_reader()
        except Exception:
            for index, key in key_by_index.items():
                names[index] = self._name_metadata(
                    raw_by_index[index], key, reason="LOCALIZATION_READ_FAILED",
                )
            return names, {
                "status": "unknown", "keys": keys, "reason": "LOCALIZATION_READ_FAILED",
            }, False
        method = getattr(reader, "localized_text", None)
        if not callable(method):
            for index, key in key_by_index.items():
                names[index] = self._name_metadata(raw_by_index[index], key, reason=_LOCALISATION_NOT_READ)
            return names, {
                "status": "unknown", "keys": keys, "reason": _LOCALISATION_NOT_READ,
            }, False

        localized: Any = None
        lookup_reason: str | None = None
        try:
            localized = method(context["observer"], deepcopy(dict(context)), keys)
        except InformationError as exc:
            lookup_reason = str(getattr(exc, "code", "LOCALIZATION_READ_FAILED"))
        except Exception as exc:
            lookup_reason = getattr(exc, "code", None)
            if not isinstance(lookup_reason, str) or not lookup_reason:
                lookup_reason = "LOCALIZATION_READ_FAILED"
        if lookup_reason is not None:
            for index, key in key_by_index.items():
                names[index] = self._name_metadata(
                    raw_by_index[index], key, reason=lookup_reason,
                )
            return names, {
                "status": "unknown", "keys": keys, "reason": lookup_reason,
            }, True

        localized_map = localized if isinstance(localized, Mapping) else {}
        entries = localized_map.get("entries")
        top_status = localized_map.get("status")
        if top_status != "known":
            reason = localized_map.get("reason")
            if not isinstance(reason, str) or not reason:
                reason = "LOCALIZATION_READER_INCOMPLETE"
            for index, key in key_by_index.items():
                names[index] = self._name_metadata(raw_by_index[index], key, localized_map, None, reason=reason)
        else:
            for index, key in key_by_index.items():
                entry = entries.get(key) if isinstance(entries, Mapping) else None
                names[index] = self._entry_name(raw_by_index[index], key, localized_map, entry)
        reader_provenance = localized_map.get("provenance", {})
        if not isinstance(reader_provenance, Mapping):
            reader_provenance = {}
        resolved_names = [
            names[index] for index in key_by_index
            if isinstance(names[index], Mapping)
        ]
        all_literals = bool(resolved_names) and all(
            item.get("status") == "known" for item in resolved_names
        )
        audit: dict[str, Any] = {
            "status": "known" if top_status == "known" and all_literals else "unknown",
            "keys": keys,
            "language": localized_map.get("language"),
            "codec": localized_map.get("codec", reader_provenance.get("codec")),
            "reader_provenance": deepcopy(dict(reader_provenance)),
        }
        if top_status != "known":
            audit["reason"] = localized_map.get("reason") or "LOCALIZATION_READER_INCOMPLETE"
        elif not all_literals:
            audit["reason"] = next(
                (item.get("reason") for item in resolved_names if isinstance(item.get("reason"), str)),
                "LOCALIZATION_KEY_UNRESOLVED",
            )
        return names, audit, True

    def read(self, query: dict, context: dict | None = None) -> dict:
        supplied = _copy(context) if isinstance(context, dict) else None
        context_supplied = supplied is not None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]
        node_id = normalized["object"]["node_id"]
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": current.get("observer"),
            "read_only": True,
            "native_function_invoked": False,
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

        reason = _details_context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, reason, unavailable=True))

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            before_reason = _details_context_reason(before)
            if before_reason is not None:
                provenance["context_guard"]["status"] = "unavailable"
                return result(before, self._failure_fields(requested, before_reason, unavailable=True))
            if _identity(current) != _identity(before):
                provenance["context_guard"]["status"] = "stale"
                return result(current, self._failure_fields(requested, "TRADE_DETAILS_CONTEXT_STALE", unavailable=True))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = (binding_reason or "TRADE_INCOME_INSTALLATION_UNAVAILABLE").replace(
                "TRADE_INCOME_", "TRADE_DETAILS_", 1
            )
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        capture_result = self._capture_trade_details_record(
            before,
            creation_filetime,
            installation,
            provenance,
            requested_node_id=node_id,
        )
        if not capture_result["ok"]:
            reason = capture_result["reason"]
            if reason is None:
                reason = "TRADE_DETAILS_CAPTURE_INVALID"
            return result(
                before,
                self._failure_fields(
                    requested,
                    reason,
                    unavailable=bool(capture_result.get("unavailable")),
                ),
            )

        trade = capture_result["trade"]
        details = capture_result["details"]
        provenance["context_guard"]["status"] = "passed"
        provenance["trade_details"] = _compact_details_provenance(details, trade, node_id)
        node = _node_for(details, node_id)
        if node is None:
            provenance["capture_reason"] = "NODE_NOT_FOUND"
            return result(before, {field: _unknown("NODE_NOT_FOUND") for field in requested})

        # Dynamic labels are an optional second read.  It is deliberately
        # after the static parent/child validators and only runs for a
        # ``sources`` request with a non-empty, observed dynamic list.  A
        # reader error keeps the native rows and containers; a context change
        # during this second read retracts the whole query below.
        localized_names: list[dict[str, Any] | None] | None = None
        if _SOURCES in requested:
            localized_names, localization_audit, localization_attempted = self._localized_dynamic_names(node, before)
            if localization_audit is not None:
                provenance["name_localization"] = localization_audit
            if localization_attempted:
                try:
                    localized_after = self.context()
                except Exception:
                    localized_after = {}
                localized_reason = _details_context_reason(localized_after)
                if localized_reason is not None or _identity(before) != _identity(localized_after):
                    provenance["context_guard"]["status"] = "changed"
                    reason = localized_reason or "TRADE_DETAILS_CONTEXT_CHANGED_DURING_LOCALIZATION"
                    if isinstance(localization_audit, dict):
                        localization_audit.update({"status": "unknown", "reason": reason})
                    return result(before, self._failure_fields(requested, reason, unavailable=False))

        fields: dict[str, dict[str, Any]] = {}
        for field in requested:
            try:
                fields[field] = self._field_from_node(
                    node, field, country=before["observer"], localized_names=localized_names,
                )
            except Exception as exc:
                reason = str(exc) or type(exc).__name__
                provenance["capture_reason"] = reason
                fields[field] = _unknown(reason)
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


__all__ = ["NativeTradeDetailsSource"]
