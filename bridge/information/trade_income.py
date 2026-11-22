"""Read-only T05 trade-income and aggregate-collection adapter.

The low-level reader is intentionally imported only for a live read.  This
adapter consumes the country-resources parent report and exposes the bounded
trade-node cache for the configured observer country. It never invokes a game
function, uses a mission/localization resolver, or turns a missing node into
zero.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import re
from pathlib import Path
from typing import Any, Mapping

from .country_state import NativeCountryStateSource
from .model import InformationError, canonical
from .sources import _copy, _result, _source_info


_TOPIC = "T05"
_FIELD = "income"
_COLLECTION_FIELD = "collection"
_MERCHANT_TASK_FIELD = "merchant_task"
_COUNTRY = "FRA"
_VERSION = "1.37.4"
_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
_BASIS = "native_trade_node_country_income_cache"
_COLLECTION_BASIS = "native_trade_node_collection_predicate"
_UNIT = "ducats"
_SCALE = 1000
_PERIOD = "month"
_COLLECTION_UNIT = "state"
_COLLECTION_SCALE = 1
_COLLECTION_PERIOD = "current"
_MERCHANT_TASK_BASIS = "native_trade_node_merchant_presence_and_collection_predicate"
_MERCHANT_TASK_UNIT = "state"
_MERCHANT_TASK_SCALE = 1
_MERCHANT_TASK_PERIOD = "current"
_MERCHANT_TASK_ORIGIN = "derived_from_copied_native_flags"
_COUNTRY_ORIGIN = "derived_from_copied_native_caches"
_COLLECTION_ORIGIN = "derived_from_copied_native_flags"
_NODE_ORIGIN = "copied_native_cache"
_INELIGIBLE_ORIGIN = "derived_from_copied_native_caches"
_CONTEXT_KEYS = (
    "session_id", "game_sha256", "observer", "game_date", "game_version",
)
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_INT32_MASK = (1 << 32) - 1
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
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
            "unit": _UNIT,
            "scale": _SCALE,
            "raw": True,
            "raw_semantics": (
                "country: trade_income.total_raw / 1000; "
                "trade_node: matching trade_income.nodes[].income_raw / 1000"
            ),
            "paths": ["trade_income.total_raw", "trade_income.nodes[].income_raw"],
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _COUNTRY_ORIGIN,
            "complete": False,
            "gaps": ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN"],
        },
        _COLLECTION_FIELD: {
            "coverage": "partial",
            "runtime_validation": "validated_native_aggregate_predicate",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _COLLECTION_UNIT,
            "scale": _COLLECTION_SCALE,
            "raw": False,
            "raw_semantics": (
                "country: ordered node_id list whose copied native eligible predicate is true; "
                "trade_node: the copied native eligible predicate as a bool"
            ),
            "paths": ["trade_income.nodes[].eligible"],
            "period": _COLLECTION_PERIOD,
            "basis": _COLLECTION_BASIS,
            "value_origin": _COLLECTION_ORIGIN,
            "complete": False,
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "MERCHANT_TASK_LIFECYCLE_NOT_PROVEN",
            ],
        },
        _MERCHANT_TASK_FIELD: {
            "coverage": "partial",
            "runtime_validation": "validated_native_flags_and_aggregate_predicate",
            "source": "bridge.information.country_resources_memory.capture",
            "unit": _MERCHANT_TASK_UNIT,
            "scale": _MERCHANT_TASK_SCALE,
            "raw": False,
            "raw_semantics": (
                "trade_node: none when copied native flag_ae is zero; "
                "collect when flag_ae is nonzero and the copied native eligible "
                "predicate is true; transfer when flag_ae is nonzero and it is false; "
                "country: ordered active rows only"
            ),
            "paths": ["trade_income.nodes[].flag_ae", "trade_income.nodes[].eligible"],
            "period": _MERCHANT_TASK_PERIOD,
            "basis": _MERCHANT_TASK_BASIS,
            "value_origin": _MERCHANT_TASK_ORIGIN,
            "complete": False,
            "gaps": [
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "TRANSIT_IDLE_TASK_LIFECYCLE_NOT_PROVEN",
            ],
        },
    },
    "object_types": ["country", "trade_node"],
    "observer_roles": ["country"],
    "observer_scope": [],
    "parameters": {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic"],
    "runtime_validation": "validated",
    "source": "NativeTradeIncomeSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "读取 1.37.4 观察国的原生贸易节点收入缓存。"
        "缓存新鲜度及完整GUI预算重算仍未闭合。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _int32(value: Any) -> bool:
    return type(value) is int and _INT32_MIN <= value <= _INT32_MAX


def _raw_hex(value: int) -> str:
    return (value & _INT32_MASK).to_bytes(4, "little", signed=False).hex()


def _valid_hex(value: Any, *, width: int | None = None) -> bool:
    if not isinstance(value, str) or not value or len(value) % 2:
        return False
    if width is not None and len(value) != width:
        return False
    return _HEX.fullmatch(value) is not None


def _decode_i32_hex(value: Any) -> int | None:
    if not _valid_hex(value, width=8):
        return None
    try:
        return int.from_bytes(bytes.fromhex(value), "little", signed=True)
    except ValueError:
        return None


def _wrap_i32(value: int) -> int:
    value &= _INT32_MASK
    return value - (1 << 32) if value & (1 << 31) else value


def _identity(context: Mapping[str, Any]) -> tuple[Any, ...]:
    """Use the same live identity tuple as the native country-state reader."""

    return NativeCountryStateSource._monarch_points_context_identity(dict(context))


def _context_reason(context: Any, country: str = _COUNTRY) -> str | None:
    reason = NativeCountryStateSource._monarch_points_context_reason(context, country)
    return reason.replace("MONARCH_POINTS_", "TRADE_INCOME_", 1) if reason else None


def _observer_context_reason(context: Any) -> str | None:
    observer = context.get("observer") if isinstance(context, dict) else None
    reason = NativeCountryStateSource._monarch_points_context_reason(
        context, observer, observer_scoped=True)
    return reason.replace("MONARCH_POINTS_", "TRADE_INCOME_", 1) if reason else None


def _session_binding(base_source: Any) -> tuple[Path | None, int | None, str | None]:
    session = getattr(base_source, "session", None)
    if session is None:
        return None, None, "TRADE_INCOME_SESSION_UNAVAILABLE"
    try:
        directory = getattr(session, "directory", None)
        if directory is None:
            raise ValueError("session directory is missing")
        installation = Path(directory) / "installation.json"
        record = getattr(session, "record", None)
        if not isinstance(record, dict):
            raise ValueError("session record is missing")
        creation_filetime = record.get("creation_filetime")
        if type(creation_filetime) is not int:
            raise ValueError("session creation_filetime is missing")
        session_creation = getattr(session, "creation_filetime", None)
        if session_creation is not None and (
                type(session_creation) is not int
                or session_creation != creation_filetime):
            raise ValueError("session creation_filetime differs from record")
        return installation, creation_filetime, None
    except Exception:
        return None, None, "TRADE_INCOME_INSTALLATION_UNAVAILABLE"


def _guard_observed(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("status") == "observed"


def _snapshot_date_valid(snapshot: Any, game_date: int) -> bool:
    if not isinstance(snapshot, Mapping) or snapshot.get("status") != "observed":
        return False
    date = snapshot.get("game_date")
    if not isinstance(date, Mapping) or type(date.get("value")) is not int:
        return False
    if date.get("value") != game_date or not _valid_hex(date.get("raw_hex"), width=8):
        return False
    raw_hex = date["raw_hex"]
    try:
        raw = bytes.fromhex(raw_hex)
        return int.from_bytes(raw, "little", signed=True) == game_date
    except (TypeError, ValueError):
        return False


def _parent_report_reason(
    report: Any,
    context: Mapping[str, Any],
    country: str,
    creation_filetime: int,
) -> str | None:
    """Validate the country-resources parent contract around the child."""

    if not isinstance(report, Mapping):
        return "TRADE_INCOME_PARENT_CAPTURE_INVALID"
    target = report.get("target_build")
    if (
        report.get("status") != "observed"
        or report.get("read_only") is not True
        or report.get("native_function_invoked") is not False
        or report.get("country") != country
        or report.get("completed") is not True
        or not isinstance(target, Mapping)
        or target.get("version") != _VERSION
        or str(target.get("expected_exe_sha256", "")).lower() != _GAME_SHA256
        or not _guard_observed(report.get("static_contract_guard"))
        or not _guard_observed(report.get("file_code_guard"))
        or not _guard_observed(report.get("runtime_code_guard"))
    ):
        return "TRADE_INCOME_PARENT_CAPTURE_INVALID"

    request = report.get("request")
    if not isinstance(request, Mapping) or request.get("include_trade_income") is not True:
        return "TRADE_INCOME_PARENT_REQUEST_INVALID"

    identity = report.get("identity")
    if not isinstance(identity, Mapping):
        return "TRADE_INCOME_PARENT_IDENTITY_INVALID"
    if (
        identity.get("binding_verified") is not True
        or str(identity.get("process_path_sha256", "")).lower() != _GAME_SHA256
        or identity.get("installation_session_id") != context.get("session_id")
        or type(identity.get("installation_creation_filetime")) is not int
        or identity.get("installation_creation_filetime") != creation_filetime
        or type(identity.get("process_creation_filetime")) is not int
        or identity.get("process_creation_filetime") != creation_filetime
    ):
        return "TRADE_INCOME_PARENT_IDENTITY_INVALID"

    doublepass = report.get("doublepass")
    if (
        not isinstance(doublepass, Mapping)
        or doublepass.get("performed") is not True
        or doublepass.get("consistent") is not True
    ):
        return "TRADE_INCOME_PARENT_DOUBLEPASS_INVALID"
    cleanup = report.get("cleanup")
    handle_close = cleanup.get("handle_close") if isinstance(cleanup, Mapping) else None
    if (
        not isinstance(handle_close, Mapping)
        or handle_close.get("status") != "closed"
        or ("closed" in handle_close and handle_close.get("closed") is not True)
    ):
        return "TRADE_INCOME_PARENT_CLEANUP_INVALID"

    game_date = context.get("game_date")
    if type(game_date) is not int:
        return "TRADE_INCOME_PARENT_DATE_INVALID"
    if not _snapshot_date_valid(report.get("before"), game_date):
        return "TRADE_INCOME_PARENT_DATE_INVALID"
    if not _snapshot_date_valid(report.get("after"), game_date):
        return "TRADE_INCOME_PARENT_DATE_INVALID"
    return None


def _low_level_module():
    try:
        # import_module consults the package cache and also keeps the
        # dependency lazy, while allowing isolated tests to inject the
        # bounded child reader before a neighboring test imports it.
        trade_income_memory = importlib.import_module(
            ".trade_income_memory", __package__
        )
    except Exception:
        return None
    return trade_income_memory


def _record_shape_reason(record: Any, country: str = _COUNTRY) -> str | None:
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return "TRADE_INCOME_RECORD_INVALID"
    if (
        record.get("country") != country
        or record.get("basis") != _BASIS
        or record.get("unit") != _UNIT
        or record.get("scale") != _SCALE
        or record.get("period") != _PERIOD
        or record.get("value_origin") != _COUNTRY_ORIGIN
        or not _guard_observed(record.get("static_contract_guard"))
        or not _guard_observed(record.get("runtime_code_guard"))
        or not isinstance(record.get("country_fullref_raw_hex"), str)
        or not _valid_hex(record.get("country_fullref_raw_hex"), width=16)
        or type(record.get("country_slot")) is not int
        or not 0 <= record["country_slot"] <= 0xFFFF
    ):
        return "TRADE_INCOME_RECORD_SHAPE_INVALID"
    total = record.get("total_raw")
    if not _int32(total) or record.get("total_raw_hex") != _raw_hex(total):
        return "TRADE_INCOME_TOTAL_INVALID"
    nodes = record.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return "TRADE_INCOME_NODES_INVALID"
    seen: set[str] = set()
    total_check = 0
    for node in nodes:
        if not isinstance(node, Mapping):
            return "TRADE_INCOME_NODE_INVALID"
        node_id = node.get("node_id")
        if not isinstance(node_id, str) or _NODE_ID.fullmatch(node_id) is None:
            return "TRADE_INCOME_NODE_ID_INVALID"
        if node_id == "Null" or node_id in seen:
            return "TRADE_INCOME_NODE_ID_INVALID"
        seen.add(node_id)
        cache = node.get("cache_income_raw")
        income = node.get("income_raw")
        if not _int32(cache) or not _int32(income):
            return "TRADE_INCOME_NODE_VALUE_INVALID"
        if node.get("income_raw_hex") != _raw_hex(income):
            return "TRADE_INCOME_NODE_RAW_INVALID"
        if "cache_income_raw_hex" in node:
            if node.get("cache_income_raw_hex") != _raw_hex(cache):
                return "TRADE_INCOME_NODE_RAW_INVALID"
        eligible = node.get("eligible")
        if type(eligible) is not bool:
            return "TRADE_INCOME_NODE_ELIGIBILITY_INVALID"
        if income != (cache if eligible else 0):
            return "TRADE_INCOME_NODE_PROJECTION_INVALID"
        if "value_origin" in node and node.get("value_origin") not in {
                _NODE_ORIGIN, _INELIGIBLE_ORIGIN}:
            return "TRADE_INCOME_NODE_ORIGIN_INVALID"
        raw_graph = node.get("raw_graph", node.get("graph"))
        if raw_graph is not None and not isinstance(raw_graph, Mapping):
            return "TRADE_INCOME_NODE_GRAPH_INVALID"
        total_check = _wrap_i32(total_check + income)
    if total_check != total:
        return "TRADE_INCOME_TOTAL_MISMATCH"
    return None


def _record_reason(record: Any, country: str = _COUNTRY) -> str | None:
    module = _low_level_module()
    if module is None:
        return "TRADE_INCOME_VALIDATOR_UNAVAILABLE"
    validator = getattr(module, "validate_record", None)
    if not callable(validator):
        return "TRADE_INCOME_VALIDATOR_UNAVAILABLE"
    try:
        valid = validator(record)
    except Exception as exc:
        return "TRADE_INCOME_RECORD_VALIDATION_FAILED:" + type(exc).__name__
    if valid is not True:
        return "TRADE_INCOME_RECORD_INVALID"
    expected = getattr(module, "EXPECTED_PROFILE_SHA256", None)
    if (
        isinstance(expected, str)
        and len(expected) == 64
        and expected != "pending-profile"
        and record.get("profile_sha256") != expected
    ):
        return "TRADE_INCOME_PROFILE_PIN_INVALID"
    return _record_shape_reason(record, country)


def _capture_record_reason(report: Any, country: str = _COUNTRY) -> str | None:
    if not isinstance(report, Mapping):
        return "TRADE_INCOME_PARENT_CAPTURE_INVALID"
    top = report.get("trade_income")
    reason = _record_reason(top, country)
    if reason is not None:
        return reason
    for snapshot_name in ("before", "after"):
        snapshot = report.get(snapshot_name)
        child = snapshot.get("trade_income") if isinstance(snapshot, Mapping) else None
        reason = _record_reason(child, country)
        if reason is not None:
            return f"TRADE_INCOME_{snapshot_name.upper()}_{reason.removeprefix('TRADE_INCOME_')}"
        try:
            if canonical(child) != canonical(top):
                return "TRADE_INCOME_SNAPSHOT_MISMATCH"
        except Exception:
            return "TRADE_INCOME_RECORD_CANONICAL_INVALID"
    return None


_RECORD_HASH_ALGORITHM = "sha256(canonical_json_utf8;information.model.canonical)"


def _record_canonical_sha256(record: Any) -> str | None:
    try:
        material = canonical(record).encode("utf-8")
    except Exception:
        return None
    return hashlib.sha256(material).hexdigest()


def _compact_node_provenance(node: Mapping[str, Any]) -> dict[str, Any]:
    """Project one node without copying its 192-byte entry or pointer graph."""

    result: dict[str, Any] = {
        "node_id": node.get("node_id"),
        "cache_income_raw_hex": node.get("cache_income_raw_hex"),
        "income_raw": node.get("income_raw"),
        "income_raw_hex": node.get("income_raw_hex"),
        "eligible": node.get("eligible"),
    }
    if "node_id_raw_hex" in node:
        result["node_id_raw_hex"] = node["node_id_raw_hex"]
    if all(key in node for key in ("flag_ac", "flag_ad", "flag_ae")):
        result["flags"] = {
            "flag_ac": node["flag_ac"],
            "flag_ad": node["flag_ad"],
            "flag_ae": node["flag_ae"],
        }
    elif isinstance(node.get("flags"), Mapping):
        # Preserve only scalar flag metadata supplied by an injected reader;
        # never copy a nested graph or raw entry under the flags key.
        result["flags"] = {
            key: deepcopy(value)
            for key, value in node["flags"].items()
            if isinstance(key, str)
            and key in {"flag_ac", "flag_ad", "flag_ae", "predicate_rva"}
            and type(value) in (int, str, bool)
        }
    return result


def _record_provenance(
    record: Mapping[str, Any],
    *,
    selector: Mapping[str, Any] | None = None,
    reason: str | None = None,
    include_nodes: bool = False,
) -> dict[str, Any]:
    """Return a bounded audit projection of a validated or failed child.

    The complete low-level record remains in the parent capture report and is
    validated before a successful projection is made.  Public provenance only
    carries a canonical digest of that record plus enough compact raw data to
    audit the requested total or node contribution.
    """

    result: dict[str, Any] = {
        "status": record.get("status"),
        "profile_sha256": record.get("profile_sha256"),
        "static_contract_guard": deepcopy(record.get("static_contract_guard")),
        "runtime_code_guard": deepcopy(record.get("runtime_code_guard")),
        "record_canonical_sha256": _record_canonical_sha256(record),
        "record_hash_algorithm": _RECORD_HASH_ALGORITHM,
    }
    if reason is not None:
        result["reason"] = reason
    elif record.get("reason") is not None:
        result["reason"] = record.get("reason")
    if not include_nodes:
        return result

    for key in (
        "country", "country_fullref_raw_hex", "country_slot", "basis",
        "total_raw", "total_raw_hex",
    ):
        if key in record:
            result[key] = deepcopy(record[key])
    graph = record.get("graph")
    if isinstance(graph, Mapping):
        result["graph_counts"] = {
            key: graph.get(key)
            for key in ("node_count", "real_node_count", "placeholder_count")
            if key in graph
        }
    nodes = record.get("nodes")
    if isinstance(nodes, list):
        requested_node_id = (
            selector.get("node_id")
            if isinstance(selector, Mapping)
            and selector.get("type") == "trade_node"
            else None
        )
        if requested_node_id is not None:
            nodes = [
                node for node in nodes
                if isinstance(node, Mapping)
                and node.get("node_id") == requested_node_id
            ]
        result["nodes"] = [
            _compact_node_provenance(node)
            for node in nodes
            if isinstance(node, Mapping)
        ]
    return result


class NativeTradeIncomeSource:
    """Expose the configured observer's native trade-node income cache."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None):
        self.base_source = base_source
        self.capture = capture

    def context(self) -> dict[str, Any]:
        try:
            context = self.base_source.context()
        except Exception as exc:
            raise InformationError(
                "source_context", f"base source context failed: {type(exc).__name__}"
            ) from exc
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
                f"T05 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeTradeIncomeSource supports T05 only")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) not in ({"type", "country"}, {"type", "node_id"}):
            raise InformationError(
                "invalid_object", "T05 queries require country or node_id object selectors only"
            )
        if obj.get("type") == "country":
            if set(obj) != {"type", "country"} or not isinstance(obj.get("country"), str) or not re.fullmatch(r"[A-Z0-9]{3}", obj["country"]):
                raise InformationError("invalid_object", "T05 requires a country tag")
        elif obj.get("type") == "trade_node":
            if set(obj) != {"type", "node_id"} or (
                    not isinstance(obj.get("node_id"), str)
                    or _NODE_ID.fullmatch(obj["node_id"]) is None
                    or obj["node_id"] == "Null"):
                raise InformationError("invalid_object", "trade_node node_id must be a bounded ASCII identifier")
        else:
            raise InformationError("invalid_object", "T05 object type is unsupported")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError("invalid_fields", "T05 fields must be a non-empty list of unique strings")
        unknown = set(fields) - {_FIELD, _COLLECTION_FIELD, _MERCHANT_TASK_FIELD}
        if unknown:
            raise InformationError("unknown_field", f"T05 fields are outside the native adapter: {sorted(unknown)}")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "T05 parameters must be an empty object")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if observer is not None and obj['type'] == 'country' and observer != obj['country']:
                raise InformationError("observer_scope_mismatch", "T05 is limited to the configured observer country")
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
            "NativeTradeIncomeSource", context, complete=False, provenance=provenance,
        )
        if fields and all(
                isinstance(item, dict) and item.get("status") == "unavailable"
                for item in fields.values()):
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

    def _field_from_country(self, record: Mapping[str, Any]) -> dict[str, Any]:
        raw = record["total_raw"]
        return {
            "status": "known", "value": raw, "raw": raw,
            "raw_hex": record["total_raw_hex"], "unit": _UNIT,
            "scale": _SCALE, "period": _PERIOD, "basis": _BASIS,
            "value_origin": _COUNTRY_ORIGIN, "complete": False,
        }

    def _field_from_node(self, node: Mapping[str, Any]) -> dict[str, Any]:
        # The low-level record retains the copied cache's origin for audit
        # purposes.  A public zero produced by the B58C70 eligibility filter
        # is a derived contribution and must say so explicitly.
        origin = _NODE_ORIGIN if node.get("eligible") is True else _INELIGIBLE_ORIGIN
        result = {
            "status": "known", "value": node["income_raw"],
            "raw": node["income_raw"], "raw_hex": node["income_raw_hex"],
            "unit": _UNIT, "scale": _SCALE, "period": _PERIOD,
            "basis": _BASIS, "value_origin": origin, "complete": False,
            "eligible": node["eligible"],
            "cache_income_raw": node["cache_income_raw"],
        }
        if "cache_income_raw_hex" in node:
            result["cache_income_raw_hex"] = node["cache_income_raw_hex"]
        if "flags" in node:
            result["flags"] = deepcopy(node["flags"])
        elif "flags_ac_ad_ae_hex" in node:
            result["flags_ac_ad_ae_hex"] = node["flags_ac_ad_ae_hex"]
        elif all(key in node for key in ("flag_ac", "flag_ad", "flag_ae")):
            result["flags"] = {
                "flag_ac": node["flag_ac"],
                "flag_ad": node["flag_ad"],
                "flag_ae": node["flag_ae"],
            }
        return result

    @staticmethod
    def _field_from_collection_country(record: Mapping[str, Any]) -> dict[str, Any]:
        """Project the native aggregate predicate in graph order.

        ``trade_income_memory`` has already validated that ``nodes`` contains
        unique real definitions and that ``eligible`` is a bool derived from
        the bounded B58C70-equivalent predicate.  This projection therefore
        keeps the public country value compact while preserving the full
        eligible/flag evidence in provenance.
        """
        nodes = record["nodes"]
        return {
            "status": "known",
            "value": [
                node["node_id"]
                for node in nodes
                if node.get("eligible") is True
            ],
            "unit": _COLLECTION_UNIT,
            "scale": _COLLECTION_SCALE,
            "period": _COLLECTION_PERIOD,
            "basis": _COLLECTION_BASIS,
            "value_origin": _COLLECTION_ORIGIN,
            "complete": False,
        }

    @staticmethod
    def _field_from_collection_node(node: Mapping[str, Any]) -> dict[str, Any]:
        eligible = node.get("eligible")
        if type(eligible) is not bool:
            raise ValueError("TRADE_INCOME_NODE_ELIGIBILITY_INVALID")
        return {
            "status": "known",
            "value": eligible,
            "unit": _COLLECTION_UNIT,
            "scale": _COLLECTION_SCALE,
            "period": _COLLECTION_PERIOD,
            "basis": _COLLECTION_BASIS,
            "value_origin": _COLLECTION_ORIGIN,
            "complete": False,
        }

    @staticmethod
    def _node_flag(node: Mapping[str, Any], name: str) -> int | None:
        value = node.get(name)
        if type(value) is int and 0 <= value <= 0xFF:
            return value
        flags = node.get("flags")
        if isinstance(flags, Mapping):
            value = flags.get(name)
            if type(value) is int and 0 <= value <= 0xFF:
                return value
        return None

    @classmethod
    def _merchant_task_for_node(cls, node: Mapping[str, Any]) -> str:
        flag_ae = cls._node_flag(node, "flag_ae")
        eligible = node.get("eligible")
        if flag_ae is None or type(eligible) is not bool:
            raise ValueError("TRADE_INCOME_MERCHANT_TASK_PROVENANCE_INVALID")
        if flag_ae == 0:
            return "none"
        return "collect" if eligible else "transfer"

    @classmethod
    def _field_from_merchant_task_country(cls, record: Mapping[str, Any]) -> dict[str, Any]:
        rows = []
        for node in record["nodes"]:
            flag_ae = cls._node_flag(node, "flag_ae")
            if flag_ae is None:
                raise ValueError("TRADE_INCOME_MERCHANT_TASK_PROVENANCE_INVALID")
            if flag_ae != 0:
                rows.append({
                    "node_id": node["node_id"],
                    "task": cls._merchant_task_for_node(node),
                })
        return {
            "status": "known",
            "value": rows,
            "unit": _MERCHANT_TASK_UNIT,
            "scale": _MERCHANT_TASK_SCALE,
            "period": _MERCHANT_TASK_PERIOD,
            "basis": _MERCHANT_TASK_BASIS,
            "value_origin": _MERCHANT_TASK_ORIGIN,
            "complete": False,
        }

    @classmethod
    def _field_from_merchant_task_node(cls, node: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "status": "known",
            "value": cls._merchant_task_for_node(node),
            "unit": _MERCHANT_TASK_UNIT,
            "scale": _MERCHANT_TASK_SCALE,
            "period": _MERCHANT_TASK_PERIOD,
            "basis": _MERCHANT_TASK_BASIS,
            "value_origin": _MERCHANT_TASK_ORIGIN,
            "complete": False,
        }

    def read(self, query: dict, context: dict | None = None) -> dict:
        supplied = _copy(context) if isinstance(context, dict) else None
        context_supplied = supplied is not None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]
        country = current.get('observer')
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": country,
            "read_only": True,
            "native_function_invoked": False,
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _COUNTRY_ORIGIN,
            "context_guard": {
                "mode": "live", "game_version": _VERSION,
                "game_sha256": _GAME_SHA256, "identity_keys": list(_CONTEXT_KEYS),
            },
        }

        def result(ctx: dict[str, Any], fields: dict[str, dict[str, Any]]) -> dict[str, Any]:
            return self._result(normalized, ctx, fields, provenance)

        reason = _observer_context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, reason, unavailable=True))

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            before_reason = _observer_context_reason(before)
            if before_reason is not None:
                provenance["context_guard"]["status"] = "unavailable"
                return result(before, self._failure_fields(requested, before_reason, unavailable=True))
            if _identity(current) != _identity(before):
                reason = "TRADE_INCOME_CONTEXT_STALE"
                provenance["context_guard"]["status"] = "stale"
                return result(current, self._failure_fields(requested, reason, unavailable=True))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = binding_reason or "TRADE_INCOME_INSTALLATION_UNAVAILABLE"
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        capture = self._capture_reader()
        if not callable(capture):
            reason = "TRADE_INCOME_CAPTURE_UNAVAILABLE"
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        report: Any = None
        capture_error: str | None = None
        try:
            report = capture(installation, country, include_trade_income=True)
        except Exception as exc:
            capture_error = "TRADE_INCOME_CAPTURE_FAILED:" + type(exc).__name__

        # Re-read after every attempted capture, including an exception, so a
        # failed reader cannot hide a changed process/session identity.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = _observer_context_reason(after)
        if (
            after_reason is not None
            or _identity(before) != _identity(after)
        ):
            provenance["context_guard"]["status"] = "changed"
            reason = after_reason or "TRADE_INCOME_CONTEXT_CHANGED_DURING_CAPTURE"
            if isinstance(report, Mapping) and isinstance(report.get("trade_income"), Mapping):
                provenance["trade_income"] = _record_provenance(
                    report["trade_income"], reason=reason, include_nodes=False,
                )
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            return result(before, self._failure_fields(requested, capture_error, unavailable=False))

        if isinstance(report, Mapping) and isinstance(report.get("trade_income"), Mapping):
            provenance["trade_income"] = _record_provenance(
                report["trade_income"], selector=normalized["object"],
                include_nodes=False,
            )
        provenance["context_guard"]["status"] = "capture_invalid"
        reason = _parent_report_reason(report, before, country, creation_filetime)
        if reason is not None:
            provenance["capture_reason"] = reason
            if isinstance(report, Mapping) and isinstance(report.get("trade_income"), Mapping):
                provenance["trade_income"]["reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        reason = _capture_record_reason(report, country)
        if reason is not None:
            provenance["capture_reason"] = reason
            if isinstance(report, Mapping) and isinstance(report.get("trade_income"), Mapping):
                provenance["trade_income"]["reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        record = report["trade_income"]
        provenance["context_guard"]["status"] = "passed"
        provenance["trade_income"] = _record_provenance(
            record, selector=normalized["object"], include_nodes=True,
        )
        if normalized["object"]["type"] == "country":
            fields = {}
            if _FIELD in requested:
                fields[_FIELD] = self._field_from_country(record)
            if _COLLECTION_FIELD in requested:
                fields[_COLLECTION_FIELD] = self._field_from_collection_country(record)
            if _MERCHANT_TASK_FIELD in requested:
                fields[_MERCHANT_TASK_FIELD] = self._field_from_merchant_task_country(record)
        else:
            node_id = normalized["object"]["node_id"]
            node = next((item for item in record["nodes"] if item["node_id"] == node_id), None)
            if node is None:
                provenance["capture_reason"] = "NODE_NOT_FOUND"
                fields = {
                    field: _unknown("NODE_NOT_FOUND")
                    for field in requested
                }
            else:
                fields = {}
                if _FIELD in requested:
                    fields[_FIELD] = self._field_from_node(node)
                if _COLLECTION_FIELD in requested:
                    fields[_COLLECTION_FIELD] = self._field_from_collection_node(node)
                if _MERCHANT_TASK_FIELD in requested:
                    try:
                        fields[_MERCHANT_TASK_FIELD] = self._field_from_merchant_task_node(node)
                    except ValueError as exc:
                        provenance["capture_reason"] = str(exc)
                        fields[_MERCHANT_TASK_FIELD] = _unknown(str(exc))
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


__all__ = ["NativeTradeIncomeSource"]
