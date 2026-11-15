"""Expose declared timing for one explicitly selected mission task.

This source wraps the existing M04 duration projection.  It does not evaluate
mission conditions or apply effects, and it does not convert declared terms
into a candidate start or expiry date.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from .catalog import get_topic
from .model import InformationError


FIELD = "reward_timing"
TOPIC = "M05"
SOURCE_FIELD = "duration"
SOURCE_TOPIC = "M04"
BASIS = "selected_mission_task_declared_reward_timing"
VALUE_ORIGIN = "declared_effect_timing_parameters"
GAPS = [
    "MISSION_REWARD_CONDITIONS_NOT_EVALUATED",
    "MISSION_CANDIDATE_FEASIBILITY_UNKNOWN",
    "MISSION_REWARD_APPLICATION_NOT_PROVEN",
    "MISSION_REWARD_START_AND_EXPIRY_UNKNOWN",
]
_SELECTOR_KEYS = {"root_id", "task_id"}
_QUERY_KEYS = {"topic", "object", "fields", "parameters"}
_DURATION_SCHEMA = "information.mission_reward_duration.v1"


class MissionChainTimingSource:
    """Project a selected M04 duration value into the partial M05 field."""

    event_types = ()

    def __init__(self, missions: Any):
        self.missions = missions

    def context(self) -> dict:
        return deepcopy(self.missions.context())

    def catalog(self) -> list[dict]:
        m04 = next((item for item in self.missions.catalog()
                    if isinstance(item, dict) and item.get("topic_id") == SOURCE_TOPIC), None)
        if m04 is None:
            raise InformationError("mission_source_unavailable", "M04 capability catalog is missing")
        topic = get_topic(TOPIC)
        m05_field = deepcopy(topic.get("fields", {}).get(FIELD, {}))
        m05_field.update({
            "coverage": "partial",
            "complete": False,
            "period": "static_rules",
            "basis": BASIS,
            "value_origin": VALUE_ORIGIN,
            "source": type(self).__name__,
            "runtime_validation": "MissionInformationSource.M04.duration",
            "description": (
                "所选且已验证加载任务的奖励声明期限及命令专属单位；"
                "不判断任务条件、候选方案可行性、奖励是否生效或实际起止时间"
            ),
            "gaps": list(GAPS),
        })
        topic.update({
            "status": "available",
            "source": type(self).__name__,
            "context_scope": m04.get("context_scope", "country_scope"),
            "visibility": m04.get("visibility", "country_scope"),
            "observer_roles": deepcopy(m04.get("observer_roles", ["country"])),
            "object_types": deepcopy(m04.get("object_types", ["country"])),
            "triggers": deepcopy(m04.get("triggers", ["query"])),
            "supported_versions": deepcopy(m04.get("supported_versions", [])),
            "fields": {FIELD: m05_field},
            "parameters": {
                "type": "object",
                "properties": deepcopy(m04.get("parameters", {}).get("properties", {})),
                "required": ["root_id", "task_id"],
                "additionalProperties": False,
            },
        })
        for key in ("supported_observers", "supported_countries"):
            if key in m04:
                topic[key] = deepcopy(m04[key])
        return [topic]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "M05 query must be an object")
        missing = _QUERY_KEYS - set(query)
        extra = set(query) - _QUERY_KEYS
        if missing or extra:
            raise InformationError(
                "invalid_parameters", f"M05 query: missing={sorted(missing)}, unknown={sorted(extra)}"
            )
        if query.get("topic") != TOPIC:
            raise InformationError("unknown_topic", "MissionChainTimingSource supports M05 only")
        if query.get("fields") != [FIELD]:
            raise InformationError("invalid_fields", "M05 supports reward_timing only")
        params = query.get("parameters")
        if not isinstance(params, dict) or set(params) != _SELECTOR_KEYS:
            raise InformationError(
                "invalid_parameters", "M05.reward_timing requires root_id and task_id"
            )
        projected = {
            "topic": SOURCE_TOPIC,
            "object": deepcopy(query.get("object")),
            "fields": [SOURCE_FIELD],
            "parameters": deepcopy(params),
        }
        normalized = self.missions.validate_query(projected, context)
        return {
            "topic": TOPIC,
            "object": deepcopy(normalized["object"]),
            "fields": [FIELD],
            "parameters": deepcopy(normalized["parameters"]),
        }

    @staticmethod
    def _source_with_projection(source_value: Any, metadata: dict) -> dict:
        source = deepcopy(source_value) if isinstance(source_value, dict) else {}
        provenance = source.get("provenance")
        provenance = deepcopy(provenance) if isinstance(provenance, dict) else {}
        provenance["reward_timing_projection"] = deepcopy(metadata)
        source.update(name="MissionChainTimingSource", provenance=provenance, complete=False)
        return source

    @staticmethod
    def _field(status: str, reason: str | None = None, **extras: Any) -> dict:
        field = {
            "status": status,
            "period": "static_rules",
            "basis": BASIS,
            "value_origin": VALUE_ORIGIN,
            "partial": True,
            "complete": False,
        }
        if reason is not None:
            field["reason"] = reason
        field.update(deepcopy(extras))
        return field

    @staticmethod
    def _duration_metadata(duration: dict, selector: dict) -> dict:
        return {
            "source_topic": SOURCE_TOPIC,
            "source_field": SOURCE_FIELD,
            "duration_schema": duration.get("schema"),
            "duration_provenance": deepcopy(duration.get("provenance")),
            "duration_evidence": deepcopy(duration.get("evidence")),
            "selector": deepcopy(selector),
        }

    @staticmethod
    def _selected_duration_matches(value: Any, root_id: str, task_id: str) -> bool:
        if not isinstance(value, dict) or value.get("field") != SOURCE_FIELD:
            return False
        if value.get("complete") is not False:
            return False
        rules = value.get("rules")
        if not isinstance(rules, list) or len(rules) != 1:
            return False
        row = rules[0]
        if (not isinstance(row, dict) or row.get("root_id") != root_id
                or row.get("task_id") != task_id
                or row.get("status") not in {"known", "unknown"}):
            return False
        if (type(value.get("task_count")) is not int or value["task_count"] != 1
                or type(value.get("materialized_task_count")) is not int
                or value["materialized_task_count"] != 1):
            return False
        return True

    def read(self, query: dict, context: dict | None = None) -> dict:
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        country = normalized["object"]["country"]
        selector = normalized["parameters"]
        m04_query = {
            "topic": SOURCE_TOPIC,
            "object": deepcopy(normalized["object"]),
            "fields": [SOURCE_FIELD],
            "parameters": deepcopy(selector),
        }
        # Invoke the real source exactly once; all native membership, context,
        # definition freshness, and duration projection rules stay upstream.
        original = self.missions.read(m04_query, current)
        raw_fields = original.get("fields") if isinstance(original, dict) else None
        duration = raw_fields.get(SOURCE_FIELD) if isinstance(raw_fields, dict) else None
        source_value = original.get("source") if isinstance(original, dict) else None
        provenance = (source_value.get("provenance")
                      if isinstance(source_value, dict) else None)
        metadata = self._duration_metadata(
            duration if isinstance(duration, dict) else {}, selector,
        )
        metadata["country"] = country
        source = self._source_with_projection(source_value, metadata)

        output = {
            "topic": TOPIC,
            "fields": {},
            "complete": False,
            "game_date": original.get("game_date") if isinstance(original, dict) else current.get("game_date"),
            "objects": deepcopy(original.get("objects", [normalized["object"]]))
            if isinstance(original, dict) else [deepcopy(normalized["object"])],
            "source": source,
        }

        if not isinstance(duration, dict):
            output["fields"][FIELD] = self._field("unknown", "MISSION_DURATION_RESULT_INVALID")
            return output
        status = duration.get("status")
        if status != "known":
            reason = duration.get("reason")
            extras = {}
            for key in ("schema", "field", "evidence", "provenance"):
                if key in duration:
                    extras[key] = deepcopy(duration[key])
            output["fields"][FIELD] = self._field(
                status if isinstance(status, str) else "unknown",
                reason if isinstance(reason, str) else "MISSION_DURATION_NOT_KNOWN",
                **extras,
            )
            return output

        if (current.get("mode") == "live"
                and (not isinstance(provenance, dict)
                     or provenance.get("task_membership_source") != "captured_loaded_task_objects"
                     or provenance.get("task_membership_status") != "known")):
            metadata["loaded_task_membership_verified"] = False
            output["source"] = self._source_with_projection(source_value, metadata)
            output["fields"][FIELD] = self._field(
                "unknown", "LOADED_TASK_MEMBERSHIP_REQUIRED_FOR_REWARD_TIMING",
            )
            return output

        duration_value = duration.get("value")
        if not self._selected_duration_matches(
                duration_value, selector["root_id"], selector["task_id"]):
            metadata["selected_duration_binding"] = "mismatch_or_ambiguous"
            output["source"] = self._source_with_projection(source_value, metadata)
            output["fields"][FIELD] = self._field(
                "unknown", "MISSION_DURATION_TASK_BINDING_UNVERIFIED",
            )
            return output

        metadata["loaded_task_membership_verified"] = (
            provenance.get("task_membership_source") == "captured_loaded_task_objects"
            and provenance.get("task_membership_status") == "known"
        ) if isinstance(provenance, dict) else False
        metadata["selected_duration_binding"] = "exact"
        output["source"] = self._source_with_projection(source_value, metadata)
        output["fields"][FIELD] = self._field(
            "known",
            value={
                "candidate": {
                    "root_id": selector["root_id"],
                    "task_id": selector["task_id"],
                    "country": country,
                },
                "declared_timing": deepcopy(duration_value),
                "conditions_evaluated": False,
                "effects_executed": False,
                "candidate_feasibility": "unknown",
                "applied": "unknown",
                "start_time": "unknown",
                "expiry_time": "unknown",
                "complete": False,
            },
        )
        return output

    def poll_events(self, context: dict, cursor: dict | None):
        poll = getattr(self.missions, "poll_events", None)
        if callable(poll):
            return poll(context, cursor)
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["FIELD", "MissionChainTimingSource"]
