"""Expose explicitly declared strategic targets without treating them as game facts."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import re
from typing import Any

from .catalog import get_topic
from .model import InformationError, canonical
from .province_interest_parameters import parameters_schema
from .province_interests_live import NativeProvinceInterestsSource
from .sources import _result, _source_info


_TOPIC = "G01"
_FIELD = "strategic_targets"
_VALUE_SCHEMA = "information.strategic_targets.v1"
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION_KEYS = ("activegameversion", "active_game_version", "game_version")
_SCOPE_COMPONENT = {
    "province": "province_ids",
    "area": "areas",
    "region": "regions",
    "country": "country_tags",
}
_SCOPE_KIND = {
    "province": "province_id",
    "area": "areas",
    "region": "regions",
    "country": "country_tag",
}


def _failed(reason: str, *, status: str = "unknown", **extra: Any) -> dict[str, Any]:
    value = {"status": status, "reason": reason, "partial": True, "complete": False}
    value.update(deepcopy(extra))
    return value


def _signature(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    try:
        return canonical(dict(value))
    except (TypeError, ValueError, UnicodeError):
        return None


def _version(context: Mapping[str, Any]) -> str | None:
    for key in _VERSION_KEYS:
        value = context.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _declaration(item: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(item))
    result["source_kind"] = "caller_input"
    result["game_fact"] = False
    return result


def _file_evidence(source: Any, index_context: Mapping[str, Any]) -> bool:
    """Require source files to be pinned by the index's current context."""
    if not isinstance(source, Mapping):
        return False
    config_hash = source.get("configuration_sha256")
    if not isinstance(config_hash, str) or _SHA256.fullmatch(config_hash) is None:
        return False
    if config_hash != index_context.get("configuration_sha256"):
        return False
    files = source.get("files")
    context_files = index_context.get("definition_files")
    if (not isinstance(files, list) or not files or len(files) > 512
            or not isinstance(context_files, list)):
        return False
    by_relative = {
        item.get("relative"): item for item in context_files
        if isinstance(item, Mapping) and isinstance(item.get("relative"), str)
    }
    for item in files:
        if (not isinstance(item, Mapping)
                or not isinstance(item.get("relative"), str)
                or not isinstance(item.get("sha256"), str)
                or _SHA256.fullmatch(item["sha256"]) is None):
            return False
        pinned = by_relative.get(item["relative"])
        if not isinstance(pinned, Mapping):
            return False
        if (pinned.get("sha256") != item.get("sha256")
                or pinned.get("bytes") != item.get("bytes")
                or pinned.get("source_kind") != item.get("source_kind")
                or pinned.get("source") != item.get("source")):
            return False
    return True


def _scope_name(target: Mapping[str, Any]) -> str:
    kind = target.get("type")
    if kind == "province":
        return str(target.get("province_id"))
    if kind == "country":
        return str(target.get("country"))
    return str(target.get("name"))


class StrategicTargetsSource:
    """Own G01 caller-declared targets; static lookup never establishes runtime strategy."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, scope_index: Any = None):
        self.base_source = base_source
        self.scope_index = scope_index
        self._query_validator = NativeProvinceInterestsSource(base_source)

    def context(self) -> dict[str, Any]:
        value = self.base_source.context()
        return deepcopy(value) if isinstance(value, dict) else {}

    def catalog(self) -> list[dict[str, Any]]:
        topic = get_topic(_TOPIC)
        topic.update(
            status="available",
            source=type(self).__name__,
            context_scope="country_scope",
            object_types=["country", "province"],
            observer_roles=["country"],
            supported_versions=["1.37.4"],
            triggers=["query", "periodic"],
            parameters=parameters_schema(),
            fields={_FIELD: {
                "coverage": "partial",
                "complete": False,
                "source": type(self).__name__,
                "source_kind": "caller_input",
                "visibility": "input_or_unknown",
                "game_fact": False,
                "period": "explicit_caller_declaration",
                "unit": "caller_declared_target",
                "scale": 1,
                "basis": "explicit_structured_caller_input",
                "value_origin": "caller_input",
                "supported_object_types": ["country", "province"],
                "description": "调用者显式声明的结构化战略目标；静态地图成员仅用于匹配省份对象",
                "gaps": [
                    "NATIVE_AI_STRATEGY_NOT_READ",
                    "DECLARATIONS_DO_NOT_PROVE_GAME_GOALS",
                    "STATIC_MAP_MEMBERSHIP_NOT_PROVEN_ENGINE_LOADED",
                    "COUNTRY_PROVINCE_MEMBERSHIP_NOT_RESOLVED",
                ],
            }},
        )
        return [topic]

    def validate_query(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        normalized = self._query_validator.validate_query(query, context)
        if normalized["topic"] != _TOPIC:
            raise InformationError("unsupported_topic", "StrategicTargetsSource supports G01 only")
        if normalized["fields"] != [_FIELD]:
            raise InformationError("unknown_field", "StrategicTargetsSource owns strategic_targets only")
        obj = normalized["object"]
        if (obj.get("type") == "country" and isinstance(context, dict)
                and context.get("status") == "ready"
                and context.get("observer") != obj.get("country")):
            raise InformationError(
                "observer_scope_mismatch", "strategic_targets country object requires the logical observer")
        return normalized

    @staticmethod
    def _unknown_resolution(reason: str, *, basis: str = "static_map_definition_membership") -> dict[str, Any]:
        return {"status": "unknown", "basis": basis, "reason": reason}

    def _static_context(self, current: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
        if self.scope_index is None:
            return None, "STATIC_SCOPE_INDEX_UNAVAILABLE"
        try:
            context = self.scope_index.context()
        except Exception:
            return None, "STATIC_SCOPE_CONTEXT_UNAVAILABLE"
        if not isinstance(context, Mapping) or context.get("status") != "ready":
            return None, "STATIC_SCOPE_CONTEXT_UNREADY"
        active_version = _version(current)
        if active_version is None:
            return None, "ACTIVE_GAME_VERSION_UNAVAILABLE"
        if context.get("game_version") != active_version:
            return None, "STATIC_SCOPE_GAME_VERSION_MISMATCH"
        config_hash = context.get("configuration_sha256")
        if not isinstance(config_hash, str) or _SHA256.fullmatch(config_hash) is None:
            return None, "STATIC_SCOPE_CONFIGURATION_EVIDENCE_INVALID"
        return deepcopy(dict(context)), None

    @staticmethod
    def _component_ready(context: Mapping[str, Any], target_type: str) -> bool:
        states = context.get("component_statuses")
        component = _SCOPE_COMPONENT.get(target_type)
        row = states.get(component) if isinstance(states, Mapping) and component else None
        return isinstance(row, Mapping) and row.get("status") == "ready" and row.get("complete") is True

    def _resolve_targets(self, declarations: list[dict[str, Any]],
                         current: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
        if not declarations:
            return [], None
        before, reason = self._static_context(current)
        if before is None:
            return [self._unknown_resolution(reason or "STATIC_SCOPE_CONTEXT_UNAVAILABLE")
                    for _ in declarations], None
        raw_targets = [item["target"] for item in declarations]
        names = list(dict.fromkeys(_scope_name(target) for target in raw_targets))
        required_types = {item["target"]["type"] for item in declarations}
        if any(not self._component_ready(before, target_type) for target_type in required_types):
            try:
                after = self.scope_index.context()
            except Exception:
                after = None
            if self._static_signature(after) != self._static_signature(before):
                reason = "STATIC_SCOPE_CONTEXT_CHANGED_DURING_LOOKUP"
            else:
                reason = "STATIC_SCOPE_COMPONENT_UNAVAILABLE"
            return [self._unknown_resolution(reason) for _ in declarations], self._static_signature(after)
        lookup_failed = False
        try:
            looked_up = self.scope_index.lookup_scopes(names)
        except Exception:
            looked_up = None
            lookup_failed = True
        try:
            after = self.scope_index.context()
        except Exception:
            after = None
        if self._static_signature(after) != self._static_signature(before):
            return [self._unknown_resolution("STATIC_SCOPE_CONTEXT_CHANGED_DURING_LOOKUP")
                    for _ in declarations], self._static_signature(after)
        if lookup_failed:
            return [self._unknown_resolution("STATIC_SCOPE_LOOKUP_FAILED")
                    for _ in declarations], self._static_signature(after)
        if not isinstance(looked_up, Mapping):
            return [self._unknown_resolution("STATIC_SCOPE_LOOKUP_RESULT_INVALID")
                    for _ in declarations], self._static_signature(after)

        results: list[dict[str, Any]] = []
        for declaration in declarations:
            target = declaration["target"]
            name = _scope_name(target)
            row = looked_up.get(name)
            expected_kind = _SCOPE_KIND[target["type"]]
            if (not isinstance(row, Mapping) or row.get("status") != "known"
                    or row.get("kind") != expected_kind or row.get("name") != name):
                results.append(self._unknown_resolution(
                    row.get("reason", "STATIC_SCOPE_TARGET_NOT_FOUND")
                    if isinstance(row, Mapping) and isinstance(row.get("reason"), str)
                    else "STATIC_SCOPE_TARGET_NOT_FOUND"))
                continue
            if not _file_evidence(row.get("source"), before):
                results.append(self._unknown_resolution("STATIC_SCOPE_SOURCE_EVIDENCE_INVALID"))
                continue
            source = {
                "configuration_sha256": row["source"]["configuration_sha256"],
                "files": deepcopy(row["source"]["files"]),
            }
            if target["type"] == "country":
                if row.get("value") != target["country"]:
                    results.append(self._unknown_resolution("STATIC_SCOPE_TARGET_VALUE_MISMATCH"))
                    continue
                # A country-tag definition is existence evidence only.  Its
                # current or future province membership is deliberately absent.
                results.append({"status": "known", "basis": "static_country_tag_declaration",
                                "name": name, "source": source,
                                "province_membership": {"status": "unknown",
                                                         "reason": "COUNTRY_DYNAMIC_PROVINCES_NOT_RESOLVED"}})
                continue
            if target["type"] == "province":
                province_ids = [target["province_id"]]
                if row.get("value") != target["province_id"]:
                    results.append(self._unknown_resolution("STATIC_SCOPE_TARGET_VALUE_MISMATCH"))
                    continue
            else:
                province_ids = row.get("members")
                if (row.get("value") != target["name"]
                        or not isinstance(province_ids, list) or not province_ids
                        or len(province_ids) > 65535
                        or any(type(value) is not int or not 1 <= value <= 65535
                               for value in province_ids)
                        or len(province_ids) != len(set(province_ids))):
                    results.append(self._unknown_resolution("STATIC_SCOPE_MEMBERSHIP_INVALID"))
                    continue
                province_ids = sorted(province_ids)
            results.append({
                "status": "known",
                "basis": ("static_map_province_definition_membership" if target["type"] == "province"
                          else f"static_map_{target['type']}_province_membership"),
                "name": name,
                "province_ids": province_ids,
                "source": source,
            })
        return results, self._static_signature(after)

    @staticmethod
    def _static_signature(context: Any) -> str | None:
        if not isinstance(context, Mapping):
            return None
        try:
            return canonical(context)
        except (TypeError, ValueError, UnicodeError):
            return None

    @staticmethod
    def _value(declarations: list[dict[str, Any]], resolutions: list[dict[str, Any]],
               object_value: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        view_is_province = object_value.get("type") == "province"
        matching: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []
        province_id = object_value.get("province_id") if view_is_province else None
        for item, resolution in zip(declarations, resolutions):
            row = dict(_declaration(item), resolution=deepcopy(resolution))
            if not view_is_province:
                matching.append(row)
                if resolution.get("status") != "known":
                    unresolved.append(dict(deepcopy(row), reason=resolution.get("reason", "STATIC_TARGET_UNRESOLVED")))
                continue
            province_ids = resolution.get("province_ids") if resolution.get("status") == "known" else None
            if not isinstance(province_ids, list):
                reason = (resolution.get("province_membership", {}).get("reason")
                          if isinstance(resolution.get("province_membership"), Mapping)
                          else resolution.get("reason"))
                unresolved.append(dict(deepcopy(row), reason=reason or "PROVINCE_MEMBERSHIP_UNRESOLVED"))
                continue
            if province_id in province_ids:
                matching.append(row)
        value = {
            "schema": _VALUE_SCHEMA,
            "source_kind": "caller_input",
            "basis": "explicitly_declared_caller_input",
            "declarations": matching,
            "unresolved": unresolved,
            "game_fact": False,
            "partial": True,
            "complete": False,
            "empty_semantics": "NO_MATCHING_DECLARED_TARGET; DOES NOT PROVE_NO_GAME_STRATEGY",
        }
        # Unknown membership without a positive match cannot be reported as a
        # known empty set. Positive matches remain known partial evidence.
        is_unknown = view_is_province and bool(unresolved) and not matching
        return value, is_unknown

    @staticmethod
    def _not_declared() -> dict[str, Any]:
        return {
            "status": "unknown",
            "reason": "NOT_DECLARED",
            "partial": True,
            "complete": False,
            "source_kind": "caller_input",
            "game_fact": False,
            "value": {
                "schema": _VALUE_SCHEMA,
                "source_kind": "caller_input",
                "basis": "explicitly_declared_caller_input",
                "declarations": [], "unresolved": [],
                "game_fact": False, "partial": True, "complete": False,
                "empty_semantics": "NO_MATCHING_DECLARED_TARGET; DOES NOT PROVE_NO_GAME_STRATEGY",
            },
        }

    @staticmethod
    def _output_limited(normalized: Mapping[str, Any], object_value: Mapping[str, Any]) -> dict[str, Any]:
        declarations = normalized["parameters"].get("strategic_targets", [])
        rows = []
        unresolved = []
        for item in declarations:
            row = dict(_declaration(item), resolution={
                "status": "unknown", "basis": "static_map_definition_membership",
                "reason": "STRATEGIC_TARGETS_OUTPUT_LIMIT_EXCEEDED"})
            rows.append(row)
            unresolved.append(dict(deepcopy(row), reason="STRATEGIC_TARGETS_OUTPUT_LIMIT_EXCEEDED"))
        value = {
            "schema": _VALUE_SCHEMA, "source_kind": "caller_input",
            "basis": "explicitly_declared_caller_input", "declarations": rows,
            "unresolved": unresolved, "game_fact": False, "partial": True,
            "complete": False,
            "empty_semantics": "NO_MATCHING_DECLARED_TARGET; DOES NOT PROVE_NO_GAME_STRATEGY",
        }
        return {"status": "known" if object_value.get("type") == "country" and declarations else "unknown",
                "reason": "STRATEGIC_TARGETS_OUTPUT_LIMIT_EXCEEDED",
                "partial": True, "complete": False, "source_kind": "caller_input",
                "game_fact": False, "value": value}

    def read(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        supplied = deepcopy(context) if isinstance(context, dict) else None
        try:
            current = supplied if supplied is not None else self.context()
        except Exception:
            current = {}
        normalized = self.validate_query(query, current)
        requested = normalized["parameters"].get("strategic_targets")
        selectors = {key: deepcopy(normalized["parameters"][key])
                     for key in ("root_id", "task_id") if key in normalized["parameters"]}
        provenance: dict[str, Any] = {
            "read_only": True,
            "source_kind": "caller_input",
            "game_fact": False,
            "native_ai_strategy_read": False,
            "selectors": selectors,
            "static_scope_index_used": False,
        }

        def result(ctx: Mapping[str, Any], field: dict[str, Any]) -> dict[str, Any]:
            source = _source_info(type(self).__name__, dict(ctx), complete=False, provenance=provenance)
            source.update(context_scope="country_scope", projection_version=1)
            payload = _result(normalized, dict(ctx), {_FIELD: deepcopy(field)}, False, source)
            if len(canonical(payload).encode("utf-8")) > _MAX_OUTPUT_BYTES:
                field = self._output_limited(normalized, normalized["object"])
                source = _source_info(type(self).__name__, dict(ctx), complete=False,
                                      provenance={"read_only": True, "source_kind": "caller_input",
                                                   "game_fact": False, "selectors": selectors,
                                                   "output_limit_exceeded": True})
                source.update(context_scope="country_scope", projection_version=1)
                payload = _result(normalized, dict(ctx), {_FIELD: field}, False, source)
            return payload

        def unavailable(reason: str, ctx: Mapping[str, Any] | None = None) -> dict[str, Any]:
            field = _failed(reason, status="unavailable")
            return result(ctx if isinstance(ctx, Mapping) else current, field)

        if current.get("status") != "ready":
            return unavailable("STRATEGIC_TARGETS_CONTEXT_UNAVAILABLE")
        observer = current.get("observer")
        if not isinstance(observer, str) or re.fullmatch(r"[A-Z0-9]{3}", observer) is None:
            return unavailable("STRATEGIC_TARGETS_LOGICAL_OBSERVER_UNAVAILABLE")
        if supplied is not None:
            try:
                live_before = self.context()
            except Exception:
                live_before = {}
            if (_signature(supplied) is None or _signature(supplied) != _signature(live_before)
                    or live_before.get("status") != "ready"):
                return unavailable("STRATEGIC_TARGETS_CONTEXT_STALE", live_before)
            current = deepcopy(live_before)

        if requested is None:
            field = self._not_declared()
            try:
                after = self.context()
            except Exception:
                after = {}
            if _signature(current) is None or _signature(current) != _signature(after):
                return unavailable("STRATEGIC_TARGETS_CONTEXT_CHANGED_DURING_READ", after)
            provenance["context_guard"] = "stable_before_after"
            return result(current, field)

        declarations = deepcopy(requested)
        provenance.update(
            declaration_count=len(declarations),
            declaration_ids=[item["id"] for item in declarations],
            static_scope_index_used=self.scope_index is not None and bool(declarations),
        )
        resolutions, static_after_signature = self._resolve_targets(declarations, current)
        value, unknown = self._value(declarations, resolutions, normalized["object"])
        if normalized["object"]["type"] == "province" and unknown:
            field = {"status": "unknown", "reason": "PROVINCE_TARGET_MEMBERSHIP_UNRESOLVED",
                     "partial": True, "complete": False, "basis": "explicitly_declared_caller_input",
                     "source_kind": "caller_input", "game_fact": False,
                     "value": value}
        else:
            field = {"status": "known", "partial": True, "complete": False,
                     "basis": "explicitly_declared_caller_input",
                     "source_kind": "caller_input", "game_fact": False, "value": value}

        try:
            after = self.context()
        except Exception:
            after = {}
        if _signature(current) is None or _signature(current) != _signature(after):
            return unavailable("STRATEGIC_TARGETS_CONTEXT_CHANGED_DURING_READ", after)
        provenance["context_guard"] = "stable_before_after"
        if static_after_signature is not None:
            provenance["static_scope_context_sha256"] = hashlib.sha256(
                static_after_signature.encode("utf-8")).hexdigest()
        return result(current, field)

    def poll_events(self, context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["StrategicTargetsSource"]
