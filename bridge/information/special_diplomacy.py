"""Project S05 trade-league state from the shared R01 relation source."""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from .catalog import get_topic, validate_query as _validate_catalog_query
from .model import InformationError, digest
from .sources import _result, _source_info
from .subject_relations import _identity_snapshot


FIELD = "trade_league"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_FIELD_NOT_IMPLEMENTED = "S05_FIELD_NOT_IMPLEMENTED"


def _is_tag(value: Any) -> bool:
    return isinstance(value, str) and _TAG.fullmatch(value) is not None


class NativeSpecialDiplomacySource:
    """Expose the observer’s validated trade-league record already read for R01."""

    event_types: tuple[str, ...] = ()

    def __init__(self, relation_source):
        self.relation_source = relation_source

    def context(self):
        return deepcopy(self.relation_source.context())

    def catalog(self):
        topic = get_topic("S05")
        topic.update(
            source=type(self).__name__, status="available",
            object_types=["country"],
            supported_versions=["1.37.4"], context_scope="country_scope",
            visibility="country_scope", observer_roles=["country"], observer_scope=[],
            triggers=["query", "periodic", "change"],
            change_detection="sampled_state_comparison_not_lossless_events",
            object_semantics="current_country_trade_league_membership",
        )
        topic["fields"] = {FIELD: {
            "coverage": "partial", "source": type(self).__name__, "complete": False,
            "unit": "trade_league_state", "scale": 1, "period": "current",
            "supported_object_types": ["country"],
            "basis": "native_country_trade_league_membership",
            "value_origin": "copied_native_country_trade_league_object_vector",
            "description": "读取当前观察国的贸易联盟状态、领导国和原生成员顺序。",
            "paths": ["NativeRelationSource._extension_report('trade_league', observer, None).before.actor_record"],
            "gaps": ["S05_SESSION_OBJECT_NOT_IMPLEMENTED", "OTHER_S05_FIELDS_NOT_IMPLEMENTED",
                     "SAMPLED_STATE_COMPARISON_NOT_LOSSLESS_EVENTS"],
        }}
        return [topic]

    def validate_query(self, query, context=None):
        if context is not None and not isinstance(context, dict):
            raise InformationError("invalid_context", "S05 context must be an object")
        normalized = _validate_catalog_query(query, context)
        if normalized["topic"] != "S05":
            raise InformationError("unsupported_topic", "Special diplomacy source supports S05 only")
        if normalized["parameters"] != {}:
            raise InformationError("invalid_parameters", "S05 special diplomacy takes no parameters")
        obj = normalized["object"]
        observer = context.get("observer") if context else None
        if observer is not None and obj["type"] == "country" and obj["country"] != observer:
            raise InformationError("observer_scope_mismatch", "S05 country view requires the configured observer")
        return normalized

    @staticmethod
    def _unknown(reason):
        return {"status": "unknown", "reason": reason}

    @classmethod
    def _project_actor_record(cls, report, observer):
        if not isinstance(report, Mapping):
            return cls._unknown("TRADE_LEAGUE_REPORT_INVALID")
        before = report.get("before")
        actor_record = before.get("actor_record") if isinstance(before, Mapping) else None
        if (not isinstance(actor_record, Mapping) or actor_record.get("status") != "observed"
                or actor_record.get("country") != observer):
            return cls._unknown("TRADE_LEAGUE_ACTOR_RECORD_INVALID")

        predicate = actor_record.get("predicate")
        members = actor_record.get("members")
        leader = actor_record.get("league_leader")
        if (type(predicate) is not bool or not isinstance(members, list)
                or len(members) > 512 or (leader is not None and not _is_tag(leader))):
            return cls._unknown("TRADE_LEAGUE_ACTOR_RECORD_INVALID")
        tags = []
        for member in members:
            if not isinstance(member, Mapping) or not _is_tag(member.get("country")):
                return cls._unknown("TRADE_LEAGUE_ACTOR_RECORD_INVALID")
            tags.append(member["country"])

        # The predicate is the native active bit.  In particular, do not infer
        # it from whether the copied member list happens to be empty.
        return {
            "status": "known",
            "value": {"country": observer, "active": predicate,
                      "leader": leader, "members": tags},
            "unit": "trade_league_state", "scale": 1, "period": "current",
            "complete": False, "partial": True,
            "basis": "native_country_trade_league_membership",
            "value_origin": "copied_native_country_trade_league_object_vector",
        }

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        try:
            before, before_reason = self.relation_source._base_context()
        except Exception:
            before, before_reason = None, "BASE_CONTEXT_UNAVAILABLE"
        current = before or deepcopy(context) or {
            "status": "unready", "mode": "live", "complete": False,
        }
        fields = {name: {"status": "unsupported", "reason": _FIELD_NOT_IMPLEMENTED}
                  for name in query["fields"]}
        provenance = {
            "shared_reader": "NativeRelationSource._extension_report",
            "capture_validator": "trade_league_memory.validate_capture",
            "read_only": True, "native_function_invoked": False,
            "change_detection": "sampled_state_comparison_not_lossless_events",
        }
        used_extension = False

        if FIELD in fields:
            obj = query["object"]
            if obj["type"] == "session":
                fields[FIELD] = {"status": "unsupported", "reason": "S05_SESSION_OBJECT_NOT_IMPLEMENTED"}
            elif before is None or before_reason:
                fields[FIELD] = {"status": "unavailable",
                                 "reason": before_reason or "BASE_CONTEXT_UNAVAILABLE"}
            elif context is not None and _identity_snapshot(context) != _identity_snapshot(before):
                fields[FIELD] = {"status": "unavailable", "reason": "BASE_CONTEXT_CHANGED_BEFORE_QUERY"}
            else:
                self.validate_query(query, before)
                observer = before["observer"]
                used_extension = True
                try:
                    report, reason = self.relation_source._extension_report(
                        "trade_league", observer, None, before
                    )
                except Exception:
                    report, reason = None, "TRADE_LEAGUE_READ_FAILED"
                if report is None:
                    fields[FIELD] = self._unknown(
                        reason if isinstance(reason, str) and reason else "TRADE_LEAGUE_CAPTURE_UNKNOWN"
                    )
                else:
                    fields[FIELD] = self._project_actor_record(report, observer)
                    if fields[FIELD].get('status') == 'known':
                        try:
                            provenance['capture_report_sha256'] = digest(report)
                        except (ValueError, TypeError):
                            fields[FIELD] = self._unknown('TRADE_LEAGUE_CAPTURE_EVIDENCE_INVALID')

        after_context = before
        if used_extension:
            try:
                after_context, after_reason = self.relation_source._base_context()
            except Exception:
                after_context, after_reason = None, "BASE_CONTEXT_UNAVAILABLE"
            if (after_context is None or after_reason
                    or _identity_snapshot(before) != _identity_snapshot(after_context)):
                fields[FIELD] = {"status": "unavailable", "reason": "CONTEXT_CHANGED_DURING_QUERY"}
                provenance["reason"] = "CONTEXT_CHANGED_DURING_QUERY"

        complete = all(item.get("status") == "known" and item.get("complete") is True
                       for item in fields.values())
        source = _source_info(type(self).__name__, after_context or current,
                              complete=complete, provenance=provenance)
        source["context_scope"] = "country_scope"
        return _result(query, after_context or current, fields, complete, source)

    def poll_events(self, context, cursor):
        return {
            "events": [], "cursor": deepcopy(cursor or {}), "complete": False,
            "gaps": ["SAMPLED_STATE_COMPARISON_NOT_LOSSLESS_EVENTS"],
        }


__all__ = ["NativeSpecialDiplomacySource"]
