"""Project the admitted native bilateral-opinion cache."""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from .catalog import list_topics
from .model import InformationError, canonical
from .observation_time import dates_match
from .opinion_memory import FIELDS as _MEMORY_FIELDS
from .opinion_memory import UNKNOWN_REASONS as _MEMORY_UNKNOWN_REASONS
from .sources import _result, _source_info
from .subject_relations import _identity_reason, _identity_snapshot, _is_country


_TOPIC = "R04"
_FIELD = "opinion"
_OBSERVER = "FRA"
_VERSION = "1.37.4"
_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_HEX16 = re.compile(r"[0-9a-f]{4}\Z")
_UNIT = "opinion_points"
_PERIOD = "current_cached"
_BASIS = "native_bilateral_country_opinion_signed_i16_cache"
_UNKNOWN_BACKEND = "OPINION_BACKEND_FIELD_UNKNOWN"
_INVALID_BACKEND = "OPINION_BACKEND_FIELD_INVALID"
_CAPTURE_FAILED = "OPINION_CAPTURE_FAILED"
_CAPTURE_INVALID = "OPINION_CAPTURE_INVALID"
_FIELDS = tuple(_MEMORY_FIELDS)
def _parameters() -> dict[str, Any]:
    return {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    }


def _field_metadata() -> dict[str, Any]:
    return {
        "source": "NativeOpinionSource", "coverage": "partial", "complete": False,
        "unit": _UNIT, "scale": 1, "period": _PERIOD, "raw": True,
        "basis": _BASIS,
        "value_origin": "copied_native_bilateral_opinion_cache",
        "supported_object_types": ["country_pair"],
        "description": "原生双向好感界面使用的当前缓存值；缓存新鲜度与实际绘制未证。",
        "gaps": [
            "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
            "ACTUAL_UI_DISPLAY_NOT_VERIFIED",
            "COMPLETE_BILATERAL_VISIBILITY_NOT_PROVEN",
        ],
    }


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


class NativeOpinionSource:
    """Expose validated cached opinion cells for the observer’s country pair.

    The low-level capture owns its read-only handle and trace.  This adapter
    validates that report, rechecks the live session identity, and exports a
    strict two-direction projection without copying capture provenance.
    """

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None, validator=None):
        self.base_source = base_source
        self._capture = capture
        self._validator = validator

    def context(self) -> dict[str, Any]:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict[str, Any]]:
        topic = next(row for row in list_topics() if row.get("topic_id") == _TOPIC)
        topic.update(
            status="available", source=type(self).__name__,
            supported_versions=[_VERSION], triggers=["query", "periodic", "change"],
            change_detection="sampled_state_comparison_not_lossless_events",
            object_types=["country_pair"], observer_roles=["actor", "recipient"],
            visibility="visible_scope", context_scope="adapter_managed",
            parameters=_parameters(),
            scope_note=(
                "读取观察国参与的国家对，由采集端验证观察国角色和查询准入。"
                "缓存新鲜度与实际绘制未证。"
            ),
            change_scope={
                "fields": [_FIELD], "readiness": "both_directions_known",
                "comparison": "sampled_native_signed_i16_values",
            },
            fields={_FIELD: _field_metadata()},
        )
        return [topic]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict) or set(query) != {"topic", "object", "fields", "parameters"}:
            raise InformationError("invalid_parameters", "R04 requires topic, object, fields and parameters")
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeOpinionSource supports R04 only")
        obj = query.get("object")
        if (not isinstance(obj, dict) or set(obj) != {"type", "actor", "recipient"}
                or obj.get("type") != "country_pair"
                or not _is_country(obj.get("actor")) or not _is_country(obj.get("recipient"))
                or obj["actor"] == obj["recipient"]):
            raise InformationError("invalid_object", "R04 requires two distinct country_pair endpoints")
        observer = context.get("observer") if isinstance(context, dict) else None
        if observer is not None and observer not in (obj["actor"], obj["recipient"]):
            raise InformationError("observer_scope_mismatch", "R04 pair must include the observer")
        fields = query.get("fields")
        if (not isinstance(fields, list) or fields != [_FIELD]):
            raise InformationError("invalid_fields", "NativeOpinionSource supports only the opinion field")
        parameters = query.get("parameters")
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "R04 opinion parameters must be empty")
        if context is not None and not isinstance(context, dict):
            raise InformationError("invalid_context", "R04 context must be an object")
        normalized = {
            "topic": _TOPIC, "object": deepcopy(obj), "fields": [_FIELD], "parameters": {},
        }
        canonical(normalized)
        return normalized

    def _capture_functions(self):
        capture = self._capture
        validator = self._validator
        if capture is None or validator is None:
            from . import opinion_capture
            capture = capture or opinion_capture.capture
            validator = validator or opinion_capture.validate_capture
        return capture, validator

    @staticmethod
    def _project_direction(item: Any, holder: str, target: str) -> dict[str, Any]:
        row = {"holder": holder, "target": target}
        if not isinstance(item, Mapping):
            return {**row, "status": "unknown", "reason": _INVALID_BACKEND}

        status = item.get("status")
        if status == "invisible":
            if set(item) == {"status", "reason"} and item.get("reason") == "admission_denied":
                return {**row, "status": "invisible", "reason": "OPINION_ADMISSION_DENIED"}
            return {**row, "status": "unknown", "reason": _INVALID_BACKEND}
        if status == "unknown":
            reason = item.get("reason")
            if set(item) == {"status", "reason"}:
                if reason in _MEMORY_UNKNOWN_REASONS:
                    return {**row, "status": "unknown", "reason": reason}
                if reason in {
                    "admission_unknown", "field_raw_data_changed", "shared_evidence_changed",
                    "field_missing_or_invalid", "not_read",
                }:
                    return {**row, "status": "unknown", "reason": _UNKNOWN_BACKEND}
            return {**row, "status": "unknown", "reason": _INVALID_BACKEND}
        if (status != "known" or set(item) != {"status", "value", "unit", "scale", "complete"}
                or item.get("unit") != _UNIT or type(item.get("scale")) is not int
                or item["scale"] != 1 or item.get("complete") is not False):
            return {**row, "status": "unknown", "reason": _INVALID_BACKEND}

        value = item.get("value")
        if (not isinstance(value, Mapping) or set(value) != {"holder", "target", "opinion", "raw_hex"}
                or value.get("holder") != holder or value.get("target") != target
                or not _is_country(value.get("holder")) or not _is_country(value.get("target"))
                or value["holder"] == value["target"] or type(value.get("opinion")) is not int
                or not -(1 << 15) <= value["opinion"] < (1 << 15)
                or not isinstance(value.get("raw_hex"), str)
                or _HEX16.fullmatch(value["raw_hex"]) is None):
            return {**row, "status": "unknown", "reason": _INVALID_BACKEND}
        try:
            raw_value = int.from_bytes(bytes.fromhex(value["raw_hex"]), "little", signed=True)
        except ValueError:
            return {**row, "status": "unknown", "reason": _INVALID_BACKEND}
        if raw_value != value["opinion"]:
            return {**row, "status": "unknown", "reason": _INVALID_BACKEND}
        return {
            **row, "status": "known", "opinion": value["opinion"],
            "raw_hex": value["raw_hex"],
        }

    @classmethod
    def _project_backend(cls, report: Any, other: str, actor: str, recipient: str, observer=_OBSERVER) -> dict[str, Any]:
        try:
            observation = report["observation"]
            backend = observation["backend"]
            targets = backend["targets"]
            if (not isinstance(observation, Mapping) or not isinstance(backend, Mapping)
                    or backend.get("status") != "observed"
                    or backend.get("consistency", {}).get("status") != "stable"
                    or not isinstance(targets, list) or len(targets) != 1
                    or not isinstance(targets[0], Mapping) or targets[0].get("tag") != other
                    or not isinstance(targets[0].get("fields"), Mapping)):
                raise ValueError
            internal = targets[0]["fields"]
            if set(internal) != set(_FIELDS):
                raise ValueError

            expected = ((actor, recipient), (recipient, actor))
            rows = []
            for holder, target in expected:
                if holder == observer:
                    field = _FIELDS[0]
                else:
                    field = _FIELDS[1]
                rows.append(cls._project_direction(internal[field], holder, target))

            known = any(row["status"] == "known" for row in rows)
            invisible_count = sum(row["status"] == "invisible" for row in rows)
            result = {
                "unit": _UNIT, "scale": 1, "period": _PERIOD, "complete": False,
                "partial": True, "basis": _BASIS,
                "value_origin": "copied_native_bilateral_opinion_cache",
                "gaps": ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "ACTUAL_UI_DISPLAY_NOT_VERIFIED"],
            }
            if known:
                result.update(status="known", value=rows)
            elif invisible_count == 2:
                result.update(status="invisible", reason="OPINION_DIRECTIONS_NOT_ADMITTED",
                              directions=rows)
            else:
                reasons = [row.get("reason") for row in rows if row["status"] == "unknown"]
                reason = (reasons[0] if len(set(reasons)) == 1 else _UNKNOWN_BACKEND)
                result.update(status="unknown", reason=reason, directions=rows)
            return result
        except (KeyError, TypeError, ValueError, AttributeError):
            return _unknown(_CAPTURE_INVALID)

    @staticmethod
    def _result(normalized: dict, context: dict, fields: dict, *, reason: str | None = None,
                unavailable: bool = False, target: str | None = None,
                capture_status: str = "not_attempted") -> dict:
        provenance = {
            "adapter": "NativeOpinionSource", "read_only": True,
            "native_function_invoked": False, "scope": "selected_country_pair",
            "observer": context.get("observer"), "target": target,
            "capture_status": capture_status,
            "cache_freshness_proven": False, "actual_UI_display_verified": False,
        }
        if reason is not None:
            provenance["reason"] = reason
        source = _source_info("NativeOpinionSource", context,
                              complete=False, provenance=provenance)
        source["context_scope"] = "selected_country_pair"
        if unavailable:
            source["status"] = "unavailable"
        return _result(normalized, context, fields, False, source)

    def read(self, query: dict, context: dict | None = None) -> dict:
        normalized = self.validate_query(query)
        try:
            before = self.context()
        except Exception:
            before = deepcopy(context) if isinstance(context, dict) else {
                "mode": "live", "status": "unready", "complete": False,
            }
            reason = "BASE_CONTEXT_UNAVAILABLE"
            return self._result(normalized, before, {_FIELD: _unavailable(reason)},
                                reason=reason, unavailable=True)

        identity_error = _identity_reason(before)
        if identity_error is not None:
            return self._result(normalized, before, {_FIELD: _unavailable(identity_error)},
                                reason=identity_error, unavailable=True)
        if context is not None:
            supplied_error = _identity_reason(context)
            if supplied_error is not None:
                return self._result(normalized, before, {_FIELD: _unavailable(supplied_error)},
                                    reason=supplied_error, unavailable=True)
            if (_identity_snapshot(context) != _identity_snapshot(before)
                    or not dates_match(context["game_date"], before["game_date"])):
                reason = "BASE_CONTEXT_CHANGED_BEFORE_QUERY"
                return self._result(normalized, before, {_FIELD: _unavailable(reason)},
                                    reason=reason, unavailable=True)

        actor, recipient = normalized["object"]["actor"], normalized["object"]["recipient"]
        observer = before["observer"]
        if observer not in (actor, recipient):
            raise InformationError("observer_scope_mismatch", "R04 pair must include the observer")
        other = recipient if actor == observer else actor
        installation, creation, binding_error = _session_binding(self.base_source)
        if binding_error is not None or installation is None or creation is None:
            reason = binding_error or "OPINION_INSTALLATION_UNAVAILABLE"
            return self._result(normalized, before, {_FIELD: _unavailable(reason)},
                                reason=reason, unavailable=True, target=other)

        capture_status = "capture_failed"
        report = None
        capture_fn = validator = None
        try:
            capture_fn, validator = self._capture_functions()
            if not callable(capture_fn) or not callable(validator):
                raise TypeError
            report = (capture_fn(installation, other) if self._capture is not None
                      else capture_fn(installation, other, observer=observer))
            capture_status = "captured"
        except Exception:
            report = None

        try:
            after = self.context()
        except Exception:
            after = {}
        after_error = _identity_reason(after)
        if (after_error is not None or _identity_snapshot(before) != _identity_snapshot(after)
                or not dates_match(before["game_date"], after["game_date"])):
            reason = "CONTEXT_CHANGED_DURING_CAPTURE"
            return self._result(normalized, after if isinstance(after, dict) else before,
                                {_FIELD: _unknown(reason)}, reason=reason, target=other,
                                capture_status="context_changed")
        if report is None:
            return self._result(normalized, after, {_FIELD: _unknown(_CAPTURE_FAILED)},
                                reason=_CAPTURE_FAILED, target=other,
                                capture_status="capture_failed")

        try:
            valid = validator(report, before, creation, other) is True
        except Exception:
            valid = False
        if not valid:
            return self._result(normalized, after, {_FIELD: _unknown(_CAPTURE_INVALID)},
                                reason=_CAPTURE_INVALID, target=other,
                                capture_status="validation_failed")

        field = self._project_backend(report, other, actor, recipient, observer=observer)
        return self._result(normalized, after, {_FIELD: field}, target=other,
                            capture_status="validated")

    def change_comparison(self, query: dict, sample: dict, context: dict) -> dict | None:
        """Scope change polling to two validated, known signed opinion cells."""
        try:
            normalized = self.validate_query(query, context)
            if _identity_reason(context) is not None:
                return None
            actor, recipient = normalized["object"]["actor"], normalized["object"]["recipient"]
            if not isinstance(sample, dict) or sample.get("topic") != _TOPIC:
                return None
            if sample.get("query") is not None and sample["query"] != normalized:
                return None
            if (sample.get("objects") != [normalized["object"]]
                    or not dates_match(sample.get("game_date"), context.get("game_date"))):
                return None
            if sample.get("complete") is not False or set(sample.get("fields", {})) != {_FIELD}:
                return None

            observer = context["observer"]
            source = sample.get("source")
            if (not isinstance(source, Mapping) or source.get("name") != "NativeOpinionSource"
                    or source.get("status") != "observed" or source.get("mode") != "live"
                    or source.get("observer") != observer
                    or source.get("session_id") != context.get("session_id")
                    or source.get("complete") is not False):
                return None
            provenance = source.get("provenance")
            other = recipient if actor == observer else actor
            if (not isinstance(provenance, Mapping)
                    or provenance.get("adapter") != "NativeOpinionSource"
                    or provenance.get("capture_status") != "validated"
                    or provenance.get("observer") != observer
                    or provenance.get("target") != other):
                return None

            field = sample["fields"][_FIELD]
            expected_field_keys = {
                "status", "value", "unit", "scale", "period", "complete", "partial",
                "basis", "value_origin", "gaps",
            }
            if (not isinstance(field, Mapping) or set(field) != expected_field_keys
                    or field.get("status") != "known" or field.get("unit") != _UNIT
                    or type(field.get("scale")) is not int or field.get("scale") != 1
                    or field.get("period") != _PERIOD or field.get("complete") is not False
                    or field.get("partial") is not True or field.get("basis") != _BASIS
                    or field.get("value_origin") != "copied_native_bilateral_opinion_cache"
                    or field.get("gaps") != ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "ACTUAL_UI_DISPLAY_NOT_VERIFIED"]):
                return None
            rows = field.get("value")
            if not isinstance(rows, list) or len(rows) != 2:
                return None
            for row, (holder, target) in zip(rows, ((actor, recipient), (recipient, actor))):
                if (not isinstance(row, Mapping)
                        or set(row) != {"holder", "target", "status", "opinion", "raw_hex"}
                        or row.get("holder") != holder or row.get("target") != target
                        or row.get("status") != "known" or type(row.get("opinion")) is not int
                        or not -(1 << 15) <= row["opinion"] < (1 << 15)
                        or not isinstance(row.get("raw_hex"), str)
                        or _HEX16.fullmatch(row["raw_hex"]) is None
                        or int.from_bytes(bytes.fromhex(row["raw_hex"]), "little", signed=True) != row["opinion"]):
                    return None

            return {
                "schema": "information.change_comparison.v1",
                "scope": f"R04.opinion.{actor}.{recipient}.native_i16_v1",
                "fields": deepcopy(sample["fields"]),
            }
        except (InformationError, KeyError, TypeError, ValueError, AttributeError):
            return None

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


def _session_binding(base_source: Any):
    from .trade_income import _session_binding as binding
    return binding(base_source)


__all__ = ["NativeOpinionSource"]
