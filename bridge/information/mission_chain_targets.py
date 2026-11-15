"""Join loaded mission dependencies and target rules from one captured state.

CWTools continues to own script parsing.  MissionInformationSource continues
to own native membership and rule projection; this adapter only relates its
existing M02 and M03 results to the explicitly selected mission.
"""
from __future__ import annotations

from copy import deepcopy

from .mission_chain_timing import MissionChainTimingSource
from .missions import FIELDS, MissionInformationSource
from .model import InformationError, canonical


CHAIN_FIELDS = ("linked_targets", "basis")


class MissionChainTargetsSource:
    event_types = ()

    def __init__(self, missions):
        self.missions = missions
        self._selector = MissionChainTimingSource(missions)

    def context(self):
        return deepcopy(self.missions.context())

    def catalog(self):
        topic = deepcopy(self._selector.catalog()[0])
        from .catalog import get_topic
        original = get_topic("M05")
        topic["source"] = type(self).__name__
        topic["triggers"] = ["query", "periodic"] if self.missions.scheduling else ["query"]
        topic["fields"] = {}
        descriptions = {
            "linked_targets": "所选已加载任务的前置与后续任务及其目标条件引用；不判断扩张可行性或连带完成",
            "basis": "任务链依赖、目标条件的输入摘要与未决条件；贸易、外交冲突和实际代价仍待分析",
        }
        for field in CHAIN_FIELDS:
            topic["fields"][field] = dict(deepcopy(original["fields"][field]),
                coverage="partial", complete=False, source=type(self).__name__,
                period="captured_state_and_static_rules", description=descriptions[field],
                runtime_validation="MissionInformationSource.M02.prerequisites/M03; one frozen state",
                gaps=["MISSION_CANDIDATE_FEASIBILITY_UNKNOWN", "MISSION_JOINT_COMPLETION_NOT_EVALUATED",
                      "MISSION_TRADE_DIPLOMACY_CONFLICTS_UNKNOWN", "MISSION_CANDIDATE_COSTS_UNKNOWN"])
        return [topic]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "M05 query must be an object")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(field, str) or field not in CHAIN_FIELDS for field in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError("invalid_fields", "M05 chain supports linked_targets and basis")
        normalized = self._selector.validate_query(dict(deepcopy(query), fields=["reward_timing"]), context)
        normalized["fields"] = deepcopy(fields)
        return normalized

    @staticmethod
    def _failed(fields, reason, *, status="unknown"):
        return {field: {"status": status, "reason": reason, "partial": True, "complete": False}
                for field in fields}

    @staticmethod
    def _same_inputs(prerequisites, targets):
        sources = [item.get("source", {}) for item in (prerequisites, targets)]
        if not all(isinstance(item, dict) for item in sources):
            return False
        provenance = [item.get("provenance", {}) for item in sources]
        if not all(isinstance(item, dict) for item in provenance):
            return False
        for source, proof in zip(sources, provenance):
            if (source.get("status") != "observed"
                    or proof.get("task_membership_source") != "captured_loaded_task_objects"
                    or proof.get("task_membership_status") != "known"):
                return False
            definitions = proof.get("definitions")
            if (not isinstance(definitions, dict) or definitions.get("status") != "ready"
                    or definitions != proof.get("definitions_after")):
                return False
        return all(canonical(provenance[0].get(key)) == canonical(provenance[1].get(key))
                   for key in ("state", "definitions", "definitions_after", "observer_scope"))

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        result = {"topic": "M05", "fields": {}, "complete": False,
                  "game_date": current.get("game_date"), "objects": [deepcopy(normalized["object"])],
                  "source": {"name": type(self).__name__, "complete": False,
                             "mode": current.get("mode"), "session_id": current.get("session_id"),
                             "observer": current.get("observer")}}
        if current.get("status") != "ready":
            result["fields"] = self._failed(normalized["fields"], "source_unavailable", status="unavailable")
            return result
        try:
            state = self.missions._state(normalized["object"]["country"], current)
        except Exception as exc:
            result["fields"] = self._failed(normalized["fields"], getattr(exc, "code", "mission_read_failed"),
                                            status="unavailable")
            return result

        # Both public projectors see precisely this state.  The original
        # native reader is invoked once, with no additional capture or layout.
        frozen = MissionInformationSource(self.missions.base_source, self.missions.definitions,
            lambda country: deepcopy(state), scheduling=False, scope_index=self.missions.scope_index)
        base = {"object": deepcopy(normalized["object"]), "parameters": {}}
        prerequisites = frozen.read(dict(base, topic="M02", fields=["prerequisites"]), current)
        targets = frozen.read(dict(base, topic="M03", fields=list(FIELDS["M03"])), current)
        result["source"]["provenance"] = {
            "single_captured_state": True,
            "prerequisites": deepcopy(prerequisites.get("source")),
            "targets": deepcopy(targets.get("source")),
            "selector": deepcopy(normalized["parameters"]),
        }
        if not self._same_inputs(prerequisites, targets):
            result["fields"] = self._failed(normalized["fields"], "MISSION_CHAIN_INPUTS_UNVERIFIED_OR_CHANGED")
            return result
        from .mission_chain_graph import project_chain
        projected = project_chain(prerequisites.get("fields", {}).get("prerequisites"),
                                  targets.get("fields", {}), normalized["parameters"])
        result["fields"] = {field: deepcopy(projected[field]) for field in normalized["fields"]}
        return result

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}
