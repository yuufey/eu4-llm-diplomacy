"""Project mission rules into rule-associated static province memberships.

This G01 owner deliberately consumes only M05.linked_targets.  M05 retains the
loaded-task, definition, and context guards; this adapter relates each M03 rule
to its task-chain role and exposes province IDs only when the M03 static-scope
evidence contains validated province membership.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import re
from typing import Any

from .catalog import get_topic
from .model import InformationError, canonical
from .province_interest_parameters import parameters_schema, validate_parameters
from .province_interests_live import NativeProvinceInterestsSource
from .sources import _result, _source_info


_TOPIC = "G01"
_FIELD = "task_targets"
_COUNTRY = "FRA"
_M05_FIELD = "linked_targets"
_ROLE_FIELDS = ("selected", "prerequisite", "follow_up", "supporting_prerequisite")
_TARGET_FIELDS = ("provinces", "regions", "countries", "ownership", "control", "cores", "subjects")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REFERENCE_SCOPES = {
    "province_id": frozenset({"province"}),
    "area": frozenset({"area"}),
    "region": frozenset({"region"}),
    "superregion": frozenset({"superregion"}),
    "continent": frozenset({"continent"}),
    "province_group": frozenset({"province_group"}),
}
_MAX_CHAIN_NODES = 4096
_MAX_RULE_ASSOCIATIONS = 4096
_MAX_TASK_FIELD_ROWS = _MAX_CHAIN_NODES * len(_TARGET_FIELDS)
_MAX_STATIC_MEMBERS_PER_RULE = 65535
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _unknown(reason: str, *, status: str = "unknown", **extra: Any) -> dict[str, Any]:
    field = {"status": status, "reason": reason, "partial": True, "complete": False}
    field.update(deepcopy(extra))
    return field


def _scope_members(rule: Mapping[str, Any]) -> tuple[list[int] | None, dict[str, Any] | None, str | None]:
    """Return only scope members with an internally consistent source pin."""

    scope = rule.get("static_scope")
    if not isinstance(scope, Mapping):
        resolution = rule.get("target_resolution")
        reason = (resolution.get("reason") if isinstance(resolution, Mapping)
                  and isinstance(resolution.get("reason"), str)
                  else "STATIC_SCOPE_MEMBERSHIP_UNAVAILABLE")
        return None, None, reason

    reference_kind = rule.get("reference_kind")
    if not isinstance(reference_kind, str):
        return None, deepcopy(dict(scope)), "STATIC_SCOPE_REFERENCE_KIND_INVALID"
    expected_kind = _REFERENCE_SCOPES.get(reference_kind)
    kind = scope.get("kind")
    if expected_kind is None or not isinstance(kind, str) or kind not in expected_kind:
        return None, deepcopy(dict(scope)), "STATIC_SCOPE_KIND_NOT_PROVINCE_COMPATIBLE"

    reference = rule.get("symbolic_value", rule.get("literal_value"))
    scope_name = scope.get("name")
    if (not isinstance(scope_name, str) or not isinstance(reference, (str, int))
            or type(reference) is bool or str(reference) != scope_name):
        return None, deepcopy(dict(scope)), "STATIC_SCOPE_REFERENCE_MISMATCH"

    members = scope.get("members")
    if (not isinstance(members, list) or not members
            or len(members) > _MAX_STATIC_MEMBERS_PER_RULE
            or any(type(member) is not int or not 1 <= member <= 65535 for member in members)
            or len(members) != len(set(members))):
        return None, deepcopy(dict(scope)), "STATIC_SCOPE_MEMBERS_INVALID_OR_EMPTY"

    source = scope.get("source")
    files = source.get("files") if isinstance(source, Mapping) else None
    config_hash = source.get("configuration_sha256") if isinstance(source, Mapping) else None
    if (not isinstance(config_hash, str) or _SHA256.fullmatch(config_hash) is None
            or not isinstance(files, list) or not files or len(files) > 64
            or any(not isinstance(item, Mapping)
                   or not isinstance(item.get("relative"), str)
                   or not isinstance(item.get("sha256"), str)
                   or _SHA256.fullmatch(item["sha256"]) is None
                   for item in files)):
        return None, deepcopy(dict(scope)), "STATIC_SCOPE_SOURCE_EVIDENCE_INVALID"

    return sorted(set(members)), deepcopy(dict(scope)), None


def _role_map(value: Mapping[str, Any], selector: Mapping[str, str]):
    """Validate the M05 closure roles before attaching a rule to a task."""

    roles: dict[str, list[dict[str, str]]] = {}
    role_for: dict[tuple[str, str], str] = {}
    total = 0
    for role in _ROLE_FIELDS:
        rows = value.get(role)
        if not isinstance(rows, list):
            return None, None, "M05_CHAIN_ROLE_LIST_INVALID"
        total += len(rows)
        if total > _MAX_CHAIN_NODES:
            return None, None, "M05_CHAIN_NODE_LIMIT_EXCEEDED"
        clean = []
        for row in rows:
            if (not isinstance(row, Mapping) or not _identifier(row.get("root_id"))
                    or not _identifier(row.get("task_id"))):
                return None, None, "M05_CHAIN_ROLE_NODE_INVALID"
            pair = (row["root_id"], row["task_id"])
            if pair in role_for:
                return None, None, "M05_CHAIN_ROLE_NODE_DUPLICATE"
            role_for[pair] = role
            clean.append({"root_id": pair[0], "task_id": pair[1]})
        roles[role] = clean

    selected = roles["selected"]
    if selected != [dict(root_id=selector["root_id"], task_id=selector["task_id"])]:
        return None, None, "M05_SELECTED_TASK_MISMATCH"
    return roles, role_for, None


class ProvinceTaskTargetsSource:
    """Own the live, partial G01 mission-rule/static-province association."""

    event_types: tuple[str, ...] = ()

    def __init__(self, mission_analysis: Any):
        self.mission_analysis = mission_analysis
        missions = getattr(mission_analysis, "missions", None)
        base_source = getattr(missions, "base_source", None)
        # validate_query does not read this source; the placeholder keeps the
        # shared G01 object/field validator usable with offline fake M05 owners.
        self._query_validator = NativeProvinceInterestsSource(
            base_source if base_source is not None else object())

    def context(self) -> dict[str, Any]:
        context = self.mission_analysis.context()
        return deepcopy(context) if isinstance(context, dict) else {}

    def catalog(self) -> list[dict[str, Any]]:
        topic = get_topic(_TOPIC)
        m05 = {}
        try:
            rows = self.mission_analysis.catalog()
            m05 = next((row for row in rows if isinstance(row, dict)
                        and row.get("topic_id") == "M05"), {})
        except Exception:
            pass
        topic.update(
            status="available",
            source=type(self).__name__,
            visibility="country_scope",
            context_scope="country_scope",
            observer_roles=["country"],
            object_types=["country"],
            supported_versions=deepcopy(m05.get("supported_versions", ["1.37.4"])),
            supported_observers=deepcopy(m05.get("supported_observers", [_COUNTRY])),
            supported_countries=deepcopy(m05.get("supported_countries", [_COUNTRY])),
            triggers=deepcopy(m05.get("triggers", ["query"])),
            parameters=parameters_schema(),
            fields={_FIELD: {
                "coverage": "partial",
                "complete": False,
                "source": type(self).__name__,
                "period": "captured_state_and_static_rules",
                "unit": "rule_associated_province_id",
                "scale": 1,
                "basis": "M05_loaded_task_chain_and_M03_static_scope_membership",
                "value_origin": "validated_static_map_definition_membership",
                "supported_object_types": ["country"],
                "runtime_validation": "single MissionAnalysisSource.read of M05.linked_targets",
                "description": (
                    "所选已加载任务链中，具备静态地图成员证据的规则—任务—省份关联；"
                    "保留任务角色、规则引用和来源文件，动态条件不展开"
                ),
                "gaps": [
                    "MISSION_RUNTIME_CONDITIONS_NOT_EVALUATED",
                    "STATIC_SCOPE_MEMBERSHIP_NOT_PROVEN_ENGINE_LOADED",
                    "DYNAMIC_COUNTRY_SCOPE_NOT_EXPANDED",
                    "FULL_TARGET_SET_UNRESOLVED",
                ],
            }},
        )
        return [topic]

    def validate_query(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        normalized = self._query_validator.validate_query(query, context)
        if normalized["topic"] != _TOPIC:
            raise InformationError("unsupported_topic", "ProvinceTaskTargetsSource supports G01 only")
        if normalized["fields"] != [_FIELD]:
            raise InformationError("unknown_field", "ProvinceTaskTargetsSource owns task_targets only")
        parameters = validate_parameters(normalized["parameters"])
        if not {"root_id", "task_id"} <= set(parameters):
            raise InformationError(
                "invalid_parameters", "G01.task_targets requires root_id and task_id together")
        obj = normalized["object"]
        if (obj.get("type") == "country" and isinstance(context, dict)
                and context.get("status") == "ready"
                and context.get("observer") != obj.get("country")):
            raise InformationError("observer_scope_mismatch", "task_targets requires the active logical observer")
        return dict(normalized, parameters=parameters)

    @staticmethod
    def _failed(reason: str, *, status: str = "unknown", **extra: Any) -> dict[str, Any]:
        return _unknown(reason, status=status, **extra)

    def _project_linked_targets(self, linked: Any, selector: Mapping[str, str]) -> dict[str, Any]:
        if not isinstance(linked, Mapping):
            return self._failed("M05_LINKED_TARGETS_FIELD_INVALID")
        status = linked.get("status")
        if status in ("unknown", "unavailable"):
            passed = deepcopy(dict(linked))
            passed["partial"] = True
            passed["complete"] = False
            return passed
        if status != "known" or linked.get("complete") is not False:
            return self._failed("M05_LINKED_TARGETS_STATUS_INVALID")
        value = linked.get("value")
        if (not isinstance(value, Mapping) or value.get("evaluated") is not False
                or value.get("complete") is not False
                or not isinstance(value.get("target_rules"), Mapping)):
            return self._failed("M05_LINKED_TARGETS_VALUE_INVALID")

        roles, role_for, role_error = _role_map(value, selector)
        if role_error:
            return self._failed(role_error)

        unresolved: list[dict[str, Any]] = []
        unknowns = deepcopy(value.get("unknowns", [])) if isinstance(value.get("unknowns"), list) else []
        associations: list[dict[str, Any]] = []
        tasks_by_pair: dict[tuple[str, str], dict[str, Any]] = {}
        task_field_rows = 0
        contexts_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
        association_count = 0
        target_rules = value["target_rules"]

        # M05 repeats M03 task/context rows for each target field. Keep one
        # exact copy keyed by its loaded task and trigger context, and reject
        # conflicting copies instead of silently selecting one AST.
        for target_field in _TARGET_FIELDS:
            envelope = target_rules.get(target_field)
            target_value = envelope.get("value") if isinstance(envelope, Mapping) else None
            if not isinstance(envelope, Mapping) or envelope.get("status") != "known" or not isinstance(target_value, Mapping):
                continue
            task_rows = target_value.get("tasks")
            if task_rows is not None:
                if not isinstance(task_rows, list) or len(task_rows) > _MAX_CHAIN_NODES:
                    return self._failed("M03_TASK_METADATA_INVALID")
                for task_row in task_rows:
                    task_field_rows += 1
                    if task_field_rows > _MAX_TASK_FIELD_ROWS:
                        return self._failed("M03_TASK_METADATA_LIMIT_EXCEEDED")
                    if (not isinstance(task_row, Mapping) or not _identifier(task_row.get("root_id"))
                            or not _identifier(task_row.get("task_id"))):
                        unknowns.append({"code": "M03_TASK_METADATA_INVALID", "target_field": target_field})
                        continue
                    pair = (task_row["root_id"], task_row["task_id"])
                    identity_keys = ("task_index", "root_id", "task_id", "source", "status",
                                     "trigger_root_count", "context_ids")
                    identity = {key: deepcopy(task_row[key]) for key in identity_keys if key in task_row}
                    existing = tasks_by_pair.get(pair)
                    if existing is not None and canonical(existing["identity"]) != canonical(identity):
                        return self._failed("M03_TASK_METADATA_CONFLICT")
                    if existing is None:
                        existing = {"identity": identity, "target_field_metadata": {}}
                        tasks_by_pair[pair] = existing
                    field_metadata = {key: deepcopy(item) for key, item in task_row.items()
                                      if key not in identity_keys}
                    old_field_metadata = existing["target_field_metadata"].get(target_field)
                    if (old_field_metadata is not None
                            and canonical(old_field_metadata) != canonical(field_metadata)):
                        return self._failed("M03_TASK_FIELD_METADATA_CONFLICT")
                    existing["target_field_metadata"][target_field] = field_metadata
            context_rows = target_value.get("trigger_contexts")
            if context_rows is None:
                unknowns.append({"code": "M03_TRIGGER_CONTEXTS_NOT_AVAILABLE",
                                 "target_field": target_field})
                continue
            if not isinstance(context_rows, list) or len(context_rows) > _MAX_CHAIN_NODES:
                return self._failed("M03_TRIGGER_CONTEXTS_INVALID")
            for context_row in context_rows:
                if (not isinstance(context_row, Mapping)
                        or not _identifier(context_row.get("root_id"))
                        or not _identifier(context_row.get("task_id"))
                        or not _identifier(context_row.get("context_id"))
                        or not isinstance(context_row.get("trigger_ast"), Mapping)):
                    unknowns.append({"code": "M03_TRIGGER_CONTEXT_INVALID",
                                     "target_field": target_field})
                    continue
                key = (context_row["root_id"], context_row["task_id"], context_row["context_id"])
                existing = contexts_by_key.get(key)
                if existing is not None and canonical(existing) != canonical(context_row):
                    return self._failed("M03_TRIGGER_CONTEXT_CONFLICT")
                contexts_by_key.setdefault(key, deepcopy(dict(context_row)))
                if len(contexts_by_key) > _MAX_CHAIN_NODES:
                    return self._failed("M03_TRIGGER_CONTEXT_LIMIT_EXCEEDED")

        for target_field in _TARGET_FIELDS:
            envelope = target_rules.get(target_field)
            if not isinstance(envelope, Mapping):
                unknowns.append({"code": "M03_TARGET_FIELD_MISSING", "target_field": target_field})
                continue
            if envelope.get("status") != "known":
                unknown = {"code": "M03_TARGET_FIELD_NOT_KNOWN", "target_field": target_field,
                           "status": envelope.get("status"), "reason": envelope.get("reason")}
                for key in ("gaps", "upstream_provenance"):
                    if key in envelope:
                        unknown[key] = deepcopy(envelope[key])
                unknowns.append(unknown)
                continue
            target_value = envelope.get("value")
            rules = target_value.get("rules") if isinstance(target_value, Mapping) else None
            if not isinstance(rules, list):
                unknowns.append({"code": "M03_TARGET_RULES_INVALID", "target_field": target_field})
                continue
            for rule in rules:
                association_count += 1
                if association_count > _MAX_RULE_ASSOCIATIONS:
                    return self._failed("TASK_TARGETS_RULE_ASSOCIATION_LIMIT_EXCEEDED")
                if not isinstance(rule, Mapping):
                    unknowns.append({"code": "M03_TARGET_RULE_INVALID", "target_field": target_field})
                    continue
                root_id, task_id = rule.get("root_id"), rule.get("task_id")
                if not _identifier(root_id) or not _identifier(task_id):
                    unknowns.append({"code": "M03_TARGET_RULE_ID_INVALID", "target_field": target_field})
                    continue
                pair = (root_id, task_id)
                role = role_for.get(pair)
                rule_copy = deepcopy(dict(rule))
                if role is None:
                    unresolved.append({"root_id": root_id, "task_id": task_id,
                                       "target_field": target_field,
                                       "reason": "RULE_TASK_ROLE_NOT_IN_M05_CLOSURE",
                                       "rule": rule_copy})
                    continue
                context_id = rule.get("trigger_context_id")
                context_key = (root_id, task_id, context_id) if _identifier(context_id) else None
                if context_key is None or context_key not in contexts_by_key:
                    unresolved.append({"root_id": root_id, "task_id": task_id,
                                       "mission_role": role, "target_field": target_field,
                                       "reason": "RULE_TRIGGER_CONTEXT_NOT_RETAINED",
                                       "rule": rule_copy})
                    continue
                resolution = rule.get("target_resolution")
                if isinstance(resolution, Mapping) and resolution.get("status") != "known":
                    unresolved.append({"root_id": root_id, "task_id": task_id,
                                       "mission_role": role, "target_field": target_field,
                                       "reason": resolution.get("reason", "TARGET_RESOLUTION_UNKNOWN"),
                                       "rule": rule_copy})
                    continue
                province_ids, static_scope, scope_error = _scope_members(rule)
                if scope_error is not None or not province_ids:
                    unresolved.append({"root_id": root_id, "task_id": task_id,
                                       "mission_role": role, "target_field": target_field,
                                       "reason": scope_error or "STATIC_SCOPE_HAS_NO_PROVINCE_MEMBERS",
                                       "rule": rule_copy,
                                       **({"static_scope": static_scope} if static_scope is not None else {})})
                    continue
                associations.append({
                    "root_id": root_id,
                    "task_id": task_id,
                    "mission_role": role,
                    "target_field": target_field,
                    "reference_kind": rule.get("reference_kind"),
                    "reference_name": rule.get("symbolic_value", rule.get("literal_value")),
                    "province_ids": province_ids,
                    "static_scope": static_scope,
                    "rule": rule_copy,
                })

        if not associations:
            unresolved_field = self._failed(
                "NO_VALIDATED_STATIC_PROVINCE_ASSOCIATIONS",
                unresolved_rules=unresolved,
                unknowns=unknowns,
            )
            try:
                if len(canonical(unresolved_field).encode("utf-8")) > _MAX_OUTPUT_BYTES:
                    return self._failed("TASK_TARGETS_OUTPUT_LIMIT_EXCEEDED")
            except (TypeError, ValueError, OverflowError):
                return self._failed("TASK_TARGETS_OUTPUT_NOT_CANONICAL_JSON")
            return unresolved_field

        projected_value = {
            "schema": "information.g01_task_targets.v1",
            "selector": deepcopy(dict(selector)),
            **deepcopy(roles),
            "tasks": [
                {"root_id": key[0], "task_id": key[1], **deepcopy(tasks_by_pair[key]["identity"]),
                 "target_field_metadata": deepcopy(tasks_by_pair[key]["target_field_metadata"])}
                for key in sorted(tasks_by_pair)
            ],
            "trigger_contexts": [deepcopy(contexts_by_key[key]) for key in sorted(contexts_by_key)],
            "rules": associations,
            "unresolved_rules": unresolved,
            "unknowns": unknowns,
            "semantics": "rule_associated_static_map_definition_membership_only",
            "runtime_conditions_evaluated": False,
            "full_target_set_resolved": False,
            "actual_target_set": "unknown",
            "complete": False,
        }
        try:
            if len(canonical(projected_value).encode("utf-8")) > _MAX_OUTPUT_BYTES:
                return self._failed("TASK_TARGETS_OUTPUT_LIMIT_EXCEEDED")
        except (TypeError, ValueError, OverflowError):
            return self._failed("TASK_TARGETS_OUTPUT_NOT_CANONICAL_JSON")
        return {
            "status": "known",
            "partial": True,
            "complete": False,
            "basis": "M05_loaded_task_chain_and_M03_static_scope_membership",
            "runtime_conditions_evaluated": False,
            "full_target_set_resolved": False,
            "actual_target_set": "unknown",
            "value": projected_value,
        }

    def read(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            current = deepcopy(context) if isinstance(context, dict) else self.context()
        except Exception:
            current = {}
        normalized = self.validate_query(query, current)
        field: dict[str, Any]
        provenance: dict[str, Any] = {
            "observer": current.get("observer"),
            "read_only": True,
            "mission_analysis_read": False,
            "requested_m05_fields": [_M05_FIELD],
            "runtime_conditions_evaluated": False,
            "full_target_set_resolved": False,
            "actual_target_set": "unknown",
        }

        def result() -> dict[str, Any]:
            nonlocal field
            source = _source_info(type(self).__name__, current, complete=False, provenance=provenance)
            source.update(context_scope="country_scope", projection_version=1)
            payload = _result(normalized, current, {_FIELD: deepcopy(field)}, False, source)
            try:
                if len(canonical(payload).encode("utf-8")) > _MAX_OUTPUT_BYTES:
                    upstream_proof = provenance.pop("mission_analysis", None)
                    if upstream_proof is not None:
                        try:
                            proof_bytes = canonical(upstream_proof).encode("utf-8")
                            provenance["mission_analysis_provenance_sha256"] = hashlib.sha256(proof_bytes).hexdigest()
                        except (TypeError, ValueError, OverflowError):
                            provenance["mission_analysis_provenance_sha256"] = None
                        provenance["mission_analysis_provenance_omitted_for_output_limit"] = True
                    field = self._failed("TASK_TARGETS_OUTPUT_LIMIT_EXCEEDED")
                    source = _source_info(type(self).__name__, current, complete=False, provenance=provenance)
                    source.update(context_scope="country_scope", projection_version=1)
                    payload = _result(normalized, current, {_FIELD: deepcopy(field)}, False, source)
            except (TypeError, ValueError, OverflowError):
                field = self._failed("TASK_TARGETS_OUTPUT_NOT_CANONICAL_JSON")
                source = _source_info(type(self).__name__, current, complete=False, provenance={
                    "read_only": True, "mission_analysis_read": provenance.get("mission_analysis_read") is True,
                    "output_validation": "failed",
                })
                source.update(context_scope="country_scope", projection_version=1)
                payload = _result(normalized, current, {_FIELD: deepcopy(field)}, False, source)
            return payload

        if normalized["object"]["type"] == "province":
            field = {"status": "not_applicable", "reason": "TASK_TARGETS_REQUIRES_COUNTRY_OBJECT",
                     "partial": True, "complete": False}
            provenance["not_applicable"] = True
            return result()

        m05_query = {
            "topic": "M05",
            "object": deepcopy(normalized["object"]),
            "fields": [_M05_FIELD],
            "parameters": {name: normalized["parameters"][name] for name in ("root_id", "task_id")},
        }
        try:
            mission_result = self.mission_analysis.read(m05_query, current)
        except Exception as exc:
            field = self._failed(getattr(exc, "code", "MISSION_ANALYSIS_READ_FAILED"), status="unavailable")
            provenance["mission_analysis_error"] = getattr(exc, "code", "mission_analysis_read_failed")
            return result()
        provenance["mission_analysis_read"] = True
        if isinstance(mission_result, Mapping):
            upstream_source = mission_result.get("source")
            if isinstance(upstream_source, Mapping):
                provenance["mission_analysis"] = deepcopy(dict(upstream_source))
            upstream_fields = mission_result.get("fields")
            linked = upstream_fields.get(_M05_FIELD) if isinstance(upstream_fields, Mapping) else None
        else:
            linked = None
        field = self._project_linked_targets(linked, m05_query["parameters"])
        return result()

    def poll_events(self, context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["ProvinceTaskTargetsSource"]
