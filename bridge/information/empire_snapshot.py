"""Query the recorded HRE snapshot without treating it as live game state."""
from __future__ import annotations

from copy import deepcopy
import re

from .catalog import get_topic, list_topics, validate_query
from .model import InformationError
from .saved_empire import SavedEmpireSnapshot
from .sources import _field_result, _result, _source_info


_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_S01_FIELDS = frozenset({"emperor", "electors", "reforms"})


class SavedEmpireSource:
    """Read-only S01/C01 adapter for an explicitly supplied saved snapshot."""

    event_types = ()

    def __init__(self, snapshot: SavedEmpireSnapshot):
        self.snapshot = snapshot

    def context(self):
        return self.snapshot.context()

    def catalog(self):
        topics = list_topics()
        for topic in topics:
            topic["triggers"] = ["query"]
            topic["status"] = "planned"
            for field in topic["fields"].values():
                field["coverage"] = "planned"
        c01 = next(topic for topic in topics if topic["topic_id"] == "C01")
        c01.update(source=type(self).__name__, status="available", context_scope="saved_snapshot",
                   supported_versions=["1.37.4"])
        for name in ("observer", "game_date", "game_version", "status"):
            c01["fields"][name].update(source=type(self).__name__, coverage="available")

        s01 = next(topic for topic in topics if topic["topic_id"] == "S01")
        s01.update(
            source=type(self).__name__,
            status="available",
            visibility="saved_snapshot_global",
            context_scope="saved_snapshot",
            supported_versions=["1.37.4"],
            observer_roles=[],
            parameters={"type": "object", "properties": {}, "additionalProperties": False},
        )
        for name, unit, description in (
            ("emperor", "country_tag", "保存时神圣罗马帝国皇帝国家标签；不推断空缺或当前可见性。"),
            ("electors", "country_tag", "保存时选帝侯标签列表；仅显式列表可知，完整性仍为false。"),
            ("reforms", "reform_id", "保存时已通过改革标识；不推断当前生效状态或UI可见性。"),
        ):
            s01["fields"][name].update({
                "source": type(self).__name__,
                "coverage": "partial",
                "complete": False,
                "period": "saved_snapshot",
                "scale": 1,
                "value_origin": "jomini_eu4save_empire_snapshot",
                "basis": "saved_global_empire_record",
                "unit": unit,
                "supported_object_types": ["country", "session"],
                "description": description,
                "gaps": ["HISTORICAL_SNAPSHOT_NOT_LIVE", "CURRENT_UI_VISIBILITY_NOT_VERIFIED",
                         "EMPIRE_INTERVENTION_AND_RELIGIOUS_LEAGUES_NOT_CAPTURED"],
            })
        return topics

    def validate_query(self, query, context=None):
        normalized = validate_query(query, context)
        if normalized["topic"] != "S01":
            return normalized
        obj = normalized["object"]
        if obj.get("type") == "session":
            valid = set(obj) == {"type"} and obj.get("type") == "session"
        elif obj.get("type") == "country":
            valid = (set(obj) == {"type", "country"}
                     and isinstance(obj.get("country"), str)
                     and _TAG.fullmatch(obj["country"]) is not None)
        else:
            valid = False
        if not valid:
            raise InformationError(
                "invalid_object", "S01 requires {type:session} or a complete country tag object"
            )
        if normalized.get("parameters", {}) != {}:
            raise InformationError("invalid_parameters", "S01 snapshot parameters must be empty")
        return normalized

    def read(self, query, context=None):
        query = self.validate_query(query, context)
        current = self.context()
        supplied_context_matches = context is None or context == current

        if query["topic"] == "C01":
            supported_fields = set(query["fields"])
            if not supplied_context_matches:
                fields = {name: {"status": "unavailable", "reason": "SAVED_EMPIRE_CONTEXT_MISMATCH"}
                          for name in query["fields"]}
                complete = False
            elif current["status"] != "ready":
                fields = {name: {"status": "unavailable", "reason": "SAVED_EMPIRE_SOURCE_UNREADY"}
                          for name in query["fields"]}
                complete = False
            else:
                fields, complete = _field_result(query["fields"], current, get_topic("C01"))
        elif query["topic"] == "S01":
            fields = {}
            supported_fields = set(query["fields"]) & _S01_FIELDS
            for name in query["fields"]:
                if name not in _S01_FIELDS:
                    fields[name] = {"status": "unsupported", "reason": "SAVED_EMPIRE_FIELD_NOT_IMPLEMENTED"}
                elif not supplied_context_matches:
                    fields[name] = {"status": "unavailable", "reason": "SAVED_EMPIRE_CONTEXT_MISMATCH"}
                elif current["status"] != "ready":
                    fields[name] = {"status": "unavailable", "reason": "SAVED_EMPIRE_SOURCE_UNREADY"}
                else:
                    try:
                        fields[name] = self.snapshot.lookup(query["object"], name)
                    except (OSError, ValueError):
                        fields[name] = {"status": "unavailable", "reason": "SAVED_EMPIRE_INPUT_CHANGED"}
            complete = False
        else:
            fields = {name: {"status": "unsupported", "reason": "TOPIC_NOT_ADAPTED"}
                      for name in query["fields"]}
            supported_fields = set()
            complete = False

        after = self.context()
        if after != current:
            for name in supported_fields:
                fields[name] = {"status": "unavailable", "reason": "SAVED_EMPIRE_INPUT_OR_PARSER_CHANGED"}
            complete = False
        if not supplied_context_matches:
            for name in supported_fields:
                fields[name] = {"status": "unavailable", "reason": "SAVED_EMPIRE_CONTEXT_MISMATCH"}
            complete = False

        source = _source_info(
            type(self).__name__, current, mode="recorded", complete=complete,
            provenance={"archive": deepcopy(current["archive"]),
                        "parser": deepcopy(current["parser"]),
                        "live_state_observed": False,
                        "global_empire_record": True},
        )
        source["context_scope"] = "saved_snapshot"
        return _result(query, current, fields, complete, source)

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["SavedEmpireSource"]
