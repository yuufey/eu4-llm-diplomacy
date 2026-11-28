"""List the observer-visible provinces owned by a selected country.

The live province and discovery readers already enforce the native session,
observer role and discovery-bit gates.  This adapter composes those readers
into a bounded country view.  It deliberately reports only provinces that
were positively discovered and whose G02 owner field identifies the selected
country.  A missing owner or resource remains unknown and is never treated as
an empty value.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from . import country_province_ids_capture
from .model import InformationError
from .sources import _result, _source_info
from .trade_income import _session_binding


TOPIC = "G06"
FIELD = "provinces"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_NODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_LIMIT = 24
_MAX_SCAN = 24
_ESTUARY_SCAN_LIMIT = 8
_MAX_OFFSET = 4096


def _known(field: Any) -> Any:
    return field.get("value") if isinstance(field, dict) and field.get("status") == "known" else None


def _resource_matches(value: Any, wanted: str) -> bool:
    if not isinstance(value, dict):
        return False
    key = value.get("localization_key")
    if isinstance(key, str) and key.casefold() == wanted.casefold():
        return True
    name = value.get("name")
    if isinstance(name, dict) and isinstance(name.get("text"), str):
        return name["text"].casefold() == wanted.casefold()
    return False


class NativeCountryProvincesSource:
    """Expose a bounded, filtered list of visible provinces for one country.

    The country ownership vector bounds the candidates. G02 checks discovery
    and current ownership for each result. G04 supplies static node membership.
    """

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, province_state: Any, static_trade: Any = None,
                 estuary_reader: Any = None,
                 owned_ids_capture: Any = country_province_ids_capture,
                 max_scan: int = _MAX_SCAN):
        self.base_source = base_source
        self.province_state = province_state
        self.static_trade = static_trade
        self.estuary_reader = estuary_reader
        self.owned_ids_capture = owned_ids_capture
        if type(max_scan) is not int or not 0 < max_scan <= _MAX_SCAN:
            raise ValueError("max_scan must be a positive bounded integer")
        self.max_scan = max_scan

    def context(self) -> dict:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict]:
        return [{
            "topic_id": TOPIC,
            "catalog_ids": [TOPIC],
            "title": "国家可见省份候选",
            "status": "available",
            "object_types": ["country"],
            "observer_roles": [],
            "observer_scope": [],
            "parameters": {
                "type": "object",
                "properties": {
                    "resource": {"type": "string", "minLength": 1, "maxLength": 128},
                    "trade_node": {"type": "string", "pattern": _NODE.pattern},
                    "center_of_trade": {"type": "boolean"},
                    "river_estuary": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": _MAX_LIMIT},
                    "offset": {"type": "integer", "minimum": 0, "maximum": _MAX_OFFSET},
                },
                "required": [], "additionalProperties": False,
            },
            "supported_versions": ["1.37.4"],
            "triggers": ["query"],
            "source": type(self).__name__,
            "context_scope": "visible_scope",
            "visibility": "observer_discovered_province_scope",
            "scope_note": "只列观察国已发现且能确认所有者的省份。候选域和省份状态采集均为非原子读取。",
            "fields": {
                FIELD: {
                    "coverage": "partial",
                    "complete": False,
                    "source": type(self).__name__,
                    "unit": "province_records",
                    "scale": 1,
                    "period": "current",
                    "basis": "positive_discovery_bit_and_G02_owner_match",
                    "value_origin": "native_owned_province_vector_and_G02_province_state",
                    "description": "按国家筛选观察国已发现的省份，可附资源、贸易节点、贸易中心和河口条件。",
                    "supported_object_types": ["country"],
                    "gaps": ["NONATOMIC_MULTI_PROVINCE_READ",
                             "UNKNOWN_PROVINCE_STATE_ROWS_OMITTED"],
                }
            },
        }]

    @staticmethod
    def _tag(value: Any) -> bool:
        return isinstance(value, str) and _TAG.fullmatch(value) is not None

    def validate_query(self, query: Any, context: dict | None = None) -> dict:
        if (not isinstance(query, dict)
                or set(query) - {"topic", "object", "fields", "parameters"}
                or not {"topic", "object", "fields"} <= set(query)):
            raise InformationError("invalid_parameters", "G06 query has missing or unknown keys")
        if query["topic"] != TOPIC:
            raise InformationError("unsupported_topic", "NativeCountryProvincesSource supports G06 only")
        obj = query["object"]
        if (not isinstance(obj, dict) or set(obj) != {"type", "country"}
                or obj.get("type") != "country" or not self._tag(obj.get("country"))):
            raise InformationError("invalid_object", "G06 requires a country object")
        fields = query["fields"]
        if fields != [FIELD]:
            raise InformationError("invalid_fields", "G06 supports provinces only")
        params = query.get("parameters", {})
        if not isinstance(params, dict):
            raise InformationError("invalid_parameters", "G06 parameters must be an object")
        allowed = {"resource", "trade_node", "center_of_trade", "river_estuary", "limit", "offset"}
        if set(params) - allowed:
            raise InformationError("invalid_parameters", "G06 contains an unknown filter")
        if "resource" in params and (not isinstance(params["resource"], str)
                                      or not params["resource"].strip()
                                      or len(params["resource"]) > 128):
            raise InformationError("invalid_parameters", "resource must be a non-empty string")
        if "trade_node" in params and (not isinstance(params["trade_node"], str)
                                        or _NODE.fullmatch(params["trade_node"]) is None
                                        or params["trade_node"] == "Null"):
            raise InformationError("invalid_parameters", "trade_node is invalid")
        for name in ("center_of_trade", "river_estuary"):
            if name in params and type(params[name]) is not bool:
                raise InformationError("invalid_parameters", f"{name} must be boolean")
        if "limit" in params and (type(params["limit"]) is not int
                                   or not 1 <= params["limit"] <= _MAX_LIMIT):
            raise InformationError("invalid_parameters", "limit is out of range")
        if "offset" in params and (type(params["offset"]) is not int
                                   or not 0 <= params["offset"] <= _MAX_OFFSET):
            raise InformationError("invalid_parameters", "offset is out of range")
        return {"topic": TOPIC, "object": deepcopy(obj), "fields": [FIELD],
                "parameters": deepcopy(params)}

    def _result(self, query: dict, context: dict, field: dict) -> dict:
        complete = field.get("status") == "known" and field.get("complete") is True
        source = _source_info(type(self).__name__, context, complete=complete,
                              provenance={"read_only": True, "native_function_invoked": False,
                                          "basis": "positive_discovery_bit_and_G02_owner_match"})
        source.update(context_scope="visible_scope", projection_version=1)
        return _result(query, context, {FIELD: field}, complete, source)

    def _failure(self, query: dict, context: dict, reason: str, *, unavailable: bool = False) -> dict:
        return self._result(query, context, {"status": "unavailable" if unavailable else "unknown",
                                             "reason": reason, "period": "current",
                                             "complete": False})

    def _owned_ids(self, country: str, context: dict) -> list[int] | None:
        installation, creation, reason = _session_binding(self.base_source)
        if reason or installation is None or creation is None:
            return None
        module = self.owned_ids_capture
        try:
            report = module.capture(installation, country, observer=context.get("observer"))
            if module.validate_capture(report, context, creation, country) is not True:
                return None
            projected = module.project_fields(report)
            return projected[country_province_ids_capture.FIELD]["value"]
        except Exception:
            return None

    def _state(self, province_id: int, context: dict) -> dict | None:
        reader = getattr(self.province_state, "read", None)
        if not callable(reader):
            return None
        request = {"topic": "G02", "object": {"type": "province", "province_id": province_id},
                   "fields": ["owner", "controller", "resource", "center_of_trade"],
                   "parameters": {}}
        result = reader(request, context)
        fields = result.get("fields") if isinstance(result, dict) else None
        return fields if isinstance(fields, dict) else None

    def _trade_node(self, province_id: int, context: dict) -> str | None:
        request = {"topic": "G04", "object": {"type": "province", "province_id": province_id},
                   "fields": ["trade_node"], "parameters": {}}
        try:
            result = self.static_trade.read(request, context)
        except Exception:
            return None
        return _known(result.get("fields", {}).get("trade_node")) if isinstance(result, dict) else None

    def _trade_node_members(self, node: str, context: dict) -> set[int] | None:
        query = {"topic": "T01", "object": {"type": "trade_node", "node_id": node},
                 "fields": ["provinces"], "parameters": {}}
        try:
            result = self.static_trade.read(query, context)
        except Exception:
            return None
        members = _known(result.get("fields", {}).get("provinces")) if isinstance(result, dict) else None
        if not isinstance(members, list) or any(type(member) is not int for member in members):
            return None
        return set(members)

    def read(self, query: Any, context: dict | None = None) -> dict:
        query = self.validate_query(query, context)
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        if not isinstance(current, dict) or current.get("status") != "ready":
            return self._failure(query, current, "COUNTRY_PROVINCES_CONTEXT_UNAVAILABLE", unavailable=True)
        params = query["parameters"]
        country = query["object"]["country"]
        wanted_node = params.get("trade_node")
        if wanted_node is not None and self.static_trade is None:
            return self._failure(query, current, "STATIC_TRADE_SOURCE_UNAVAILABLE", unavailable=True)
        node_members = self._trade_node_members(wanted_node, current) if wanted_node is not None else None
        if wanted_node is not None and node_members is None:
            return self._failure(query, current, "TRADE_NODE_MEMBERSHIP_UNAVAILABLE", unavailable=True)
        wanted_estuary = params.get("river_estuary")
        if wanted_estuary is not None and self.estuary_reader is None:
            return self._failure(query, current, "ESTUARY_SOURCE_UNAVAILABLE", unavailable=True)
        ids = self._owned_ids(country, current)
        if ids is None:
            return self._failure(query, current, "COUNTRY_PROVINCES_OWNED_LIST_UNAVAILABLE", unavailable=True)
        offset = params.get("offset", 0)
        limit = params.get("limit", 12)
        wanted_resource = params.get("resource")
        wanted_cot = params.get("center_of_trade")
        rows: list[dict] = []
        scanned = 0
        unknown = 0
        scan_limit = min(self.max_scan, _ESTUARY_SCAN_LIMIT) if wanted_estuary is not None else self.max_scan
        for province_id in ids[offset:offset + scan_limit]:
            scanned += 1
            if node_members is not None and province_id not in node_members:
                continue
            fields = self._state(province_id, current)
            owner = _known(fields.get("owner")) if fields else None
            if owner != country:
                unknown += 1
                continue
            resource = _known(fields.get("resource"))
            cot = _known(fields.get("center_of_trade"))
            if ((wanted_resource is not None and resource is None)
                    or (wanted_cot is not None and cot is None)):
                unknown += 1
                continue
            if wanted_resource is not None and not _resource_matches(resource, wanted_resource):
                continue
            if wanted_cot is not None and (not isinstance(cot, dict) or cot.get("present") is not wanted_cot):
                continue
            node = self._trade_node(province_id, current) if self.static_trade is not None else None
            if wanted_node is not None and node != wanted_node:
                unknown += 1
                continue
            if wanted_estuary is not None:
                estuary = _known(self.estuary_reader.read(province_id, current))
                if type(estuary) is not bool:
                    unknown += 1
                if estuary is not wanted_estuary:
                    continue
            row = {"province_id": province_id, "owner": owner,
                   "controller": _known(fields.get("controller")) if fields else None,
                   "resource": resource, "center_of_trade": cot}
            if node is not None:
                row["trade_node"] = node
            if wanted_estuary is not None:
                row["river_estuary"] = wanted_estuary
            rows.append(row)
            if len(rows) >= limit:
                break
        next_offset = offset + scanned if offset + scanned < len(ids) else None
        field = {"status": "known", "value": {"rows": rows,
                    "next_offset": next_offset,
                    "scanned": scanned, "unknown_candidates": unknown},
                 "unit": "province_records", "scale": 1, "period": "current",
                 "basis": "positive_discovery_bit_and_G02_owner_match",
                 "complete": next_offset is None and unknown == 0,
                 "partial": True}
        return self._result(query, current, field)


__all__ = ["NativeCountryProvincesSource", "TOPIC", "FIELD"]
