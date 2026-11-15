"""Explicit sea-crossing definitions, with runtime passage kept separate."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from .catalog import get_topic
from .model import InformationError, canonical
from .sources import _result, _source_info

_FIELDS = frozenset(get_topic("G03")["fields"])
_IDENTITY_KEYS = ("session_id", "observer", "game_date", "game_day", "world_id", "paused")
_STATIC_KEYS = ("definitions_sha256", "config_sha256", "configuration_sha256", "game_version")


class StaticStraitsSource:
    event_types = ()

    def __init__(self, game_root=None, user_data=None, enabled_mods=None,
                 context_provider=None, *, index=None):
        if index is None:
            from .strait_definitions import StraitDefinitionIndex
            index = StraitDefinitionIndex(game_root=game_root, user_data=user_data,
                                           enabled_mods=enabled_mods)
        self.index = index
        self.context_provider = context_provider

    def _index_context(self):
        try:
            value = self.index.context()
            if not isinstance(value, Mapping):
                raise ValueError("INDEX_CONTEXT_NOT_OBJECT")
            canonical(value)
            return deepcopy(dict(value))
        except Exception:
            return {"status": "unready", "mode": "static", "context_scope": "static_rules",
                    "game_version": None, "complete": False,
                    "reasons": [{"code": "STATIC_STRAITS_CONTEXT_UNAVAILABLE"}]}

    def _effective_context(self, supplied=None):
        own = self._index_context()
        own.update(mode="static", context_scope="static_rules")
        provider = supplied
        if provider is None and self.context_provider is not None:
            try:
                provider = (self.context_provider() if callable(self.context_provider)
                            else self.context_provider.context())
            except Exception:
                provider = None
        if isinstance(provider, Mapping):
            for key in _IDENTITY_KEYS:
                if key in provider:
                    own[key] = deepcopy(provider[key])
            if provider.get("game_version") and provider["game_version"] != own.get("game_version"):
                own.update(status="unready", complete=False)
                own.setdefault("reasons", []).append({"code": "CONTEXT_GAME_VERSION_MISMATCH"})
        return own

    def context(self):
        return self._effective_context()

    def catalog(self):
        topic = get_topic("G03")
        topic.update(status="available", source=type(self).__name__, context_scope="static_rules",
                     visibility="static_rules", supported_versions=["1.37.4"],
                     triggers=["query", "periodic"], observer_roles=[],
                     parameters={"type": "object", "properties": {}, "required": [], "additionalProperties": False})
        # Keep both planned G03 object kinds visible. Resolving country-owned
        # province sets remains an explicit gap rather than silently shrinking it.
        topic["fields"] = {"straits": {
            "coverage": "partial", "source": type(self).__name__, "complete": False,
            "unit": "sea_connection", "scale": 1, "period": "static_rules",
            "basis": "effective_map_explicit_sea_adjacencies",
            "value_origin": "parsed_effective_static_files",
            "supported_object_types": ["province"],
            "description": "有效地图文件中与指定省份端点或途经省份相关的显式sea记录。",
            "paths": ["StraitDefinitionIndex.lookup(province_id).value"],
            "gaps": ["COUNTRY_PAIR_STRAITS_NOT_IMPLEMENTED", "CURRENT_PASSAGE_CONDITIONS_NOT_CAPTURED"],
        }}
        topic["scope_note"] = "静态连接定义；国家对的省份集合与当前通行条件保持未知。"
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or set(query) - {"topic", "object", "fields", "parameters"}:
            raise InformationError("invalid_parameters", "G03 query must be an object with declared keys")
        if not {"topic", "object", "fields"} <= set(query) or query["topic"] != "G03":
            raise InformationError("unsupported_topic", "StaticStraitsSource supports G03 only")
        obj = query["object"]
        if not isinstance(obj, dict):
            raise InformationError("invalid_object", "G03 requires an explicit province or country pair")
        if obj.get("type") == "province":
            if (set(obj) != {"type", "province_id"} or type(obj.get("province_id")) is not int
                    or not 1 <= obj["province_id"] <= 65535):
                raise InformationError("invalid_object", "province_id must be a positive bounded integer")
        elif obj.get("type") == "country_pair":
            import re
            if (set(obj) != {"type", "actor", "recipient"}
                    or any(not isinstance(obj[key], str) or re.fullmatch(r"[A-Z0-9]{3}", obj[key]) is None
                           for key in ("actor", "recipient"))):
                raise InformationError("invalid_object", "country_pair requires actor and recipient tags")
        else:
            raise InformationError("invalid_object", "G03 requires a province or country_pair")
        fields = query["fields"]
        if (not isinstance(fields, list) or not fields
                or any(type(name) is not str or name not in _FIELDS for name in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError("invalid_fields", "G03 requires unique declared fields")
        if query.get("parameters", {}) != {}:
            raise InformationError("invalid_parameters", "G03 parameters must be empty")
        normalized = {"topic": "G03", "object": deepcopy(obj), "fields": list(fields), "parameters": {}}
        canonical(normalized)
        return normalized

    @staticmethod
    def _safe_lookup(value):
        if not isinstance(value, Mapping) or value.get("status") not in {"known", "unknown", "unavailable"}:
            return {"status": "unknown", "reason": "STATIC_STRAITS_RESULT_INVALID"}
        if value["status"] != "known":
            reason = value.get("reason")
            return {"status": value["status"], "reason": reason if isinstance(reason, str) else "STATIC_STRAITS_UNKNOWN"}
        rows = value.get("value")
        if not isinstance(rows, list) or len(rows) > 20000:
            return {"status": "unknown", "reason": "STATIC_STRAITS_RESULT_INVALID"}
        safe = []
        for row in rows:
            if not isinstance(row, Mapping):
                return {"status": "unknown", "reason": "STATIC_STRAITS_RESULT_INVALID"}
            a, b, through, lines = (row.get(key) for key in
                                    ("from_province", "to_province", "through_province", "source_lines"))
            if (type(a) is not int or type(b) is not int or not 1 <= a <= 65535 or not 1 <= b <= 65535
                    or through is not None and (type(through) is not int or not 1 <= through <= 65535)
                    or not isinstance(lines, list) or not lines or len(lines) > 20000
                    or any(type(line) is not int or line < 1 for line in lines)):
                return {"status": "unknown", "reason": "STATIC_STRAITS_RESULT_INVALID"}
            safe.append({"from_province": a, "to_province": b,
                         "through_province": through, "source_lines": list(lines)})
        return {"status": "known", "value": safe, "unit": "sea_connection", "scale": 1,
                "period": "static_rules", "basis": "effective_map_explicit_sea_adjacencies", "complete": False}

    def read(self, query, context=None):
        normalized = self.validate_query(query, context)
        current = self._effective_context(context)
        fields = {name: {"status": "unsupported", "reason": "STATIC_GEOGRAPHY_FIELD_NOT_IMPLEMENTED"}
                  for name in normalized["fields"]}
        if current.get("status") != "ready":
            fields = {name: {"status": "unavailable", "reason": "STATIC_STRAITS_SOURCE_UNREADY"} for name in fields}
        elif "straits" in fields:
            if normalized["object"]["type"] != "province":
                fields["straits"] = {"status": "unknown", "reason": "COUNTRY_PAIR_STRAITS_NOT_IMPLEMENTED"}
            else:
                try:
                    fields["straits"] = self._safe_lookup(self.index.lookup(normalized["object"]["province_id"]))
                except Exception:
                    fields["straits"] = {"status": "unavailable", "reason": "STATIC_STRAITS_LOOKUP_FAILED"}
        after = self._index_context()
        if current.get("status") == "ready" and (
                after.get("status") != "ready" or any(current.get(key) != after.get(key) for key in _STATIC_KEYS)):
            fields = {name: {"status": "unavailable", "reason": "STATIC_STRAITS_INPUT_CHANGED"} for name in fields}
        source = _source_info(type(self).__name__, current, mode="static", complete=False,
                              provenance={"static_map_inputs": deepcopy(current), "runtime_passage_evaluated": False})
        source["context_scope"] = "static_rules"
        return _result(normalized, current, fields, False, source)

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {}, "complete": True, "gaps": []}


__all__ = ["StaticStraitsSource"]
