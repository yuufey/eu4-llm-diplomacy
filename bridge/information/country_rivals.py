"""R03 read-only list of the observer country's outgoing active rivals."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re
from typing import Mapping

from .model import InformationError, canonical
from .observation_time import dates_match
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _VERSION, _observer_context_reason, _identity, _session_binding


_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_PARAMETERS = {"type": "object", "properties": {}, "additionalProperties": False}
_BASIS = "native_outgoing_rival_membership"


def _public_field(field, country):
    if not isinstance(field, Mapping) or field.get("status") != "known":
        return {"status": "unknown", "reason": "RIVALS_MEMBERSHIP_UNAVAILABLE"}
    tags = field.get("value")
    if (not isinstance(tags, list) or len(tags) > 64
            or any(not isinstance(tag, str) or not _TAG.fullmatch(tag) or tag == country for tag in tags)
            or len(set(tags)) != len(tags) or tags != sorted(tags)):
        raise ValueError("invalid_rivals_membership")
    return {"status": "known", "value": list(tags), "unit": "country_tags", "scale": 1,
            "period": "current", "direction": "outgoing_declared_by_country", "basis": _BASIS,
            "value_origin": "copied_native_cache", "complete": True, "partial": False}


class NativeCountryRivalsSource(NativeTradeIncomeSource):
    event_types = ()

    def catalog(self):
        return [{"topic_id": "R03", "catalog_ids": ["R03"], "title": "本国当前主动指定的宿敌",
                 "status": "available", "fields": {"rivals": {
                     "coverage": "available", "complete": True,
                     "source": "bridge.information.country_rivals_memory.capture",
                     "description": "观察国当前主动指定的宿敌完整列表",
                     "unit": "country_tags", "scale": 1, "period": "current", "basis": _BASIS,
                     "direction": "outgoing_declared_by_country",
                     "supported_object_types": ["country"], "order": "country_tag_ascending"}},
                 "parameters": deepcopy(_PARAMETERS), "object_types": ["country"],
                 "observer_roles": ["country"], "observer_scope": [],
                 "supported_versions": [_VERSION], "triggers": ["query", "periodic"],
                 "context_scope": "country_scope", "visibility": "country_scope",
                 "source": type(self).__name__}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or set(query) - {"topic", "object", "fields", "parameters"}
                or query.get("topic") != "R03"):
            raise InformationError("invalid_parameters", "Expected an R03 rivals query")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"} or obj.get("type") != "country":
            raise InformationError("invalid_object", "rivals requires a country object")
        country = obj.get("country")
        if not isinstance(country, str) or not _TAG.fullmatch(country):
            raise InformationError("invalid_object", "Expected a country tag")
        if query.get("fields") != ["rivals"]:
            raise InformationError("invalid_fields", "Expected the rivals field")
        if not isinstance(query.get("parameters", {}), dict) or query.get("parameters", {}):
            raise InformationError("invalid_parameters", "rivals does not take parameters")
        if context is not None and (not isinstance(context, dict) or context.get("observer", country) != country):
            raise InformationError("observer_scope_mismatch", "Rivals are limited to the configured observer country")
        return {"topic": "R03", "object": deepcopy(obj), "fields": ["rivals"], "parameters": {}}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        country = normalized["object"]["country"]
        provenance = {"read_only": True, "native_function_invoked": False,
                      "adapter": "bridge.information.country_rivals_memory.capture", "country": country}

        def result(field):
            complete = field.get("status") == "known" and field.get("complete") is True
            source = _source_info(type(self).__name__, current, complete=complete, provenance=provenance)
            source["context_scope"] = "country_scope"
            return _result(normalized, current, {"rivals": field}, complete, source)

        def failure(reason, unavailable=False):
            return result({"status": "unavailable" if unavailable else "unknown", "reason": reason})

        reason = _observer_context_reason(current)
        if reason:
            return failure(reason.replace("TRADE_INCOME", "RIVALS"), True)
        try:
            before = self.context()
        except Exception:
            before = {}
        if _observer_context_reason(before) or _identity(before) != _identity(current):
            return failure("RIVALS_CONTEXT_STALE", True)
        installation, creation, reason = _session_binding(self.base_source)
        if reason or installation is None or creation is None:
            return failure("RIVALS_INSTALLATION_UNAVAILABLE", True)
        try:
            module = import_module(".country_rivals_memory", __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, country=country)
        except Exception as exc:
            return failure("RIVALS_CAPTURE_FAILED:" + type(exc).__name__)
        try:
            after = self.context()
        except Exception:
            after = {}
        if (_observer_context_reason(after) or _identity(after) != _identity(before) or
                not dates_match(current.get("game_date"), before.get("game_date"),
                                after.get("game_date"))):
            return failure("RIVALS_CONTEXT_CHANGED_DURING_CAPTURE")
        try:
            valid = module.validate_capture(report, before, creation, country)
        except Exception:
            valid = False
        if valid is not True:
            return failure("RIVALS_CAPTURE_INVALID")
        provenance["capture_report_sha256"] = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        try:
            return result(_public_field(report["before"]["record"]["fields"]["rivals"], country))
        except (ValueError, TypeError, KeyError):
            return failure("RIVALS_FIELD_INVALID")


__all__ = ["NativeCountryRivalsSource"]
