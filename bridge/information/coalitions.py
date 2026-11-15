"""Expose visible current coalition members and targets through R03."""
from copy import deepcopy
import hashlib
import re

from .catalog import get_topic, validate_query
from .model import InformationError, canonical
from .observation_time import dates_match
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _context_reason, _identity, _session_binding


FIELDS = ("coalition_members", "targets")
_TAG = re.compile(r"[A-Z0-9]{3}\Z")


class NativeCoalitionsSource(NativeTradeIncomeSource):
    event_types = ()

    def catalog(self):
        topic = get_topic("R03")
        topic.update(source=type(self).__name__, status="available", object_types=["country"],
                     observer_roles=[], observer_scope=["FRA"], supported_versions=["1.37.4"],
                     context_scope="visible_scope", visibility="visible_scope",
                     triggers=["query", "periodic", "change"],
                     parameters={"type": "object", "properties": {}, "additionalProperties": False})
        topic["fields"] = {
            field: {"coverage": "available", "complete": True, "source": type(self).__name__,
                    "unit": "country_tags", "scale": 1, "period": "current",
                    "description": ("针对所查国家的当前包围网成员" if field == FIELDS[0]
                                    else "所查国家当前加入的包围网所针对的国家"),
                    "object_types": ["country"], "order": "country_tag_ascending"}
            for field in FIELDS}
        return [topic]

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized["topic"] != "R03" or normalized["object"]["type"] != "country":
            raise InformationError("invalid_object", "Coalitions require an R03 country query")
        if set(normalized["fields"]) - set(FIELDS):
            raise InformationError("invalid_fields", "Unsupported coalition field")
        if normalized["parameters"]:
            raise InformationError("invalid_parameters", "Coalitions take no parameters")
        return normalized

    def read(self, query, context=None):
        from . import coalition_capture

        normalized = self.validate_query(query, context)
        before = self.context()
        current = before if context is None else context
        country = normalized["object"]["country"]
        provenance = {"read_only": True, "native_function_invoked": False}

        def result(fields):
            complete = all(item.get("status") == "known" for item in fields.values())
            info = _source_info(type(self).__name__, current, complete=complete,
                                provenance=deepcopy(provenance))
            info["context_scope"] = "visible_scope"
            return _result(normalized, current, fields, complete, info)

        def failure(reason, status="unknown"):
            return result({field: {"status": status, "reason": reason}
                           for field in normalized["fields"]})

        if (_context_reason(current) or _context_reason(before)
                or _identity(current) != _identity(before)):
            return failure("COALITION_CONTEXT_UNAVAILABLE", "unavailable")
        installation, creation, reason = _session_binding(self.base_source)
        if reason or installation is None or creation is None:
            return failure("COALITION_INSTALLATION_UNAVAILABLE", "unavailable")
        try:
            capture = self.capture if self.capture is not None else coalition_capture.capture
            report = capture(installation, country, observer="FRA")
            after = self.context()
            if (_context_reason(after) or _identity(after) != _identity(before)
                    or not dates_match(current.get("game_date"), before.get("game_date"),
                                       after.get("game_date"))):
                return failure("COALITION_CONTEXT_CHANGED_DURING_CAPTURE")
            if not coalition_capture.validate_capture(report, before, creation, country):
                return failure("COALITION_CAPTURE_INVALID")
            provenance["capture_report_sha256"] = hashlib.sha256(canonical(report).encode()).hexdigest()
            target = report["observation"]["backend"]["targets"][0]
            fields = {}
            for name in normalized["fields"]:
                raw = target["fields"]["R03." + name]
                if raw["status"] != "known":
                    fields[name] = {"status": raw["status"], "reason": raw.get("reason", "COALITION_UNKNOWN")}
                    continue
                tags = raw["value"]
                if (not isinstance(tags, list) or len(tags) > 4096
                        or any(not isinstance(tag, str) or not _TAG.fullmatch(tag) or tag == country for tag in tags)
                        or tags != sorted(set(tags)) or (name == "targets" and len(tags) > 1)):
                    raise ValueError("COALITION_PUBLIC_FIELD_INVALID")
                fields[name] = {"status": "known", "value": tags, "unit": "country_tags",
                                "scale": 1, "period": "current", "complete": True}
            return result(fields)
        except Exception as exc:
            return failure("COALITION_CAPTURE_FAILED:" + type(exc).__name__)
