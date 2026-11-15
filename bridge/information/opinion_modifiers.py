"""Project validated native bilateral opinion-modifier records for an FRA pair."""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from .catalog import list_topics
from .model import InformationError, canonical
from .observation_time import dates_match
from .opinion import _session_binding
from .sources import _result, _source_info
from .subject_relations import _identity_reason, _identity_snapshot, _is_country


_TOPIC = "R04"
_FIELD = "opinion_modifiers"
_OBSERVER = "FRA"
_VERSION = "1.37.4"
_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_UNIT = "opinion_points"
_SCALE = 1000
_PERIOD = "current"
_BASIS = "native_current_bilateral_opinion_modifier_records"
_VALUE_ORIGIN = "copied_native_opinion_modifier_records"
_FIELDS = (
    "R04.opinion_modifiers.outgoing",
    "R04.opinion_modifiers.incoming",
)
_DECLARATION_FIELDS = ("opinion", "min", "max", "yearly_decay", "years", "months")
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEX32 = re.compile(r"[0-9a-f]{8}\Z")
_CAPTURE_FAILED = "OPINION_MODIFIERS_CAPTURE_FAILED"
_CAPTURE_INVALID = "OPINION_MODIFIERS_CAPTURE_INVALID"
_INVALID_BACKEND = "OPINION_MODIFIERS_BACKEND_FIELD_INVALID"
_UNKNOWN_BACKEND = "OPINION_MODIFIERS_BACKEND_FIELD_UNKNOWN"
_RECORD_INVALID = "OPINION_MODIFIER_RECORD_INVALID"
_DEFINITION_UNKNOWN = "OPINION_DEFINITION_UNAVAILABLE"
_MAX_RECORDS = 256

_GAPS = [
    "ONLY_CURRENT_STORED_MODIFIER_RECORDS",
    "OTHER_COMPUTED_OPINION_SOURCES_NOT_COVERED",
    "MODIFIER_DURATION_AND_EXPIRY_NOT_PROVEN",
    "MODIFIER_DATE_MULTIPLIER_AND_FLAGS_UNINTERPRETED",
    "DEFINITION_LOADED_MEMBERSHIP_NOT_VERIFIED",
]


def _parameters() -> dict[str, Any]:
    return {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    }


def _field_metadata() -> dict[str, Any]:
    return {
        "source": "NativeOpinionModifiersSource", "coverage": "partial",
        "complete": False, "unit": _UNIT, "scale": _SCALE, "period": _PERIOD,
        "raw": True, "basis": _BASIS, "value_origin": _VALUE_ORIGIN,
        "supported_object_types": ["country_pair"],
        "description": (
            "选定国家对双向原生缓存中的具名修正记录及其当前原始好感值；"
            "不重建综合好感，也不解释记录期限或修正状态。"
        ),
        "gaps": list(_GAPS),
    }


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _decimal_i32(raw: int) -> str:
    sign = "-" if raw < 0 else ""
    integer, fraction = divmod(abs(raw), _SCALE)
    return f"{sign}{integer}.{fraction:03d}"


class NativeOpinionModifiersSource:
    """Expose validated current modifier entries, without deriving total opinion."""

    event_types: tuple[str, ...] = ()
    field = _FIELD

    def __init__(self, base_source: Any, *, capture=None, validator=None, definitions=None):
        self.base_source = base_source
        self._capture = capture
        self._validator = validator
        self._definitions = definitions

    def context(self) -> dict[str, Any]:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict[str, Any]]:
        topic = next(row for row in list_topics() if row.get("topic_id") == _TOPIC)
        topic.update(
            status="available", source=type(self).__name__,
            supported_versions=[_VERSION], triggers=["query", "periodic"],
            object_types=["country_pair"], observer_roles=["actor", "recipient"],
            visibility="visible_scope", context_scope="adapter_managed",
            parameters=_parameters(),
            scope_note=(
                "仅投射逻辑FRA参与的选定国家对；非玩家角色与国家选择准入由采集端验证。"
                "记录中的日期、多倍率及标志仍未解释。"
            ),
            fields={self.field: _field_metadata()},
        )
        return [topic]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict) or set(query) != {"topic", "object", "fields", "parameters"}:
            raise InformationError(
                "invalid_parameters", f"R04 {self.field} requires topic, object, fields and parameters",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeOpinionModifiersSource supports R04 only")
        obj = query.get("object")
        if (not isinstance(obj, dict) or set(obj) != {"type", "actor", "recipient"}
                or obj.get("type") != "country_pair"
                or not _is_country(obj.get("actor")) or not _is_country(obj.get("recipient"))
                or obj["actor"] == obj["recipient"]):
            raise InformationError("invalid_object", "R04 requires two distinct country_pair endpoints")
        if _OBSERVER not in (obj["actor"], obj["recipient"]):
            raise InformationError("observer_scope_mismatch", "R04 pair must include logical FRA")
        if query.get("fields") != [self.field]:
            raise InformationError("invalid_fields", f"{type(self).__name__} supports only {self.field}")
        parameters = query.get("parameters")
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", f"R04 {self.field} parameters must be empty")
        if context is not None and (
                not isinstance(context, dict) or context.get("observer") != _OBSERVER):
            raise InformationError("observer_scope_mismatch", "R04 requires logical observer FRA")
        normalized = {
            "topic": _TOPIC, "object": deepcopy(obj), "fields": [self.field], "parameters": {},
        }
        canonical(normalized)
        return normalized

    def _capture_functions(self):
        capture = self._capture
        validator = self._validator
        if capture is None or validator is None:
            from . import opinion_modifiers_capture
            capture = capture or opinion_modifiers_capture.capture
            validator = validator or opinion_modifiers_capture.validate_capture
        return capture, validator

    @staticmethod
    def _definition_context(definitions: Any) -> tuple[bool, Any]:
        context_fn = getattr(definitions, "context", None)
        if not callable(context_fn):
            return True, None
        try:
            context = context_fn()
        except Exception:
            return False, None
        if (not isinstance(context, Mapping) or context.get("status") != "ready"
                or context.get("source_basis") != "disk_configuration"
                or context.get("loaded_membership_verified") is not False
                or context.get("conditions_evaluated") is not False):
            return False, None
        return True, deepcopy(context.get("source_pins"))

    @staticmethod
    def _definition_declarations(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, Mapping) or set(value) != set(_DECLARATION_FIELDS):
            return None
        output: dict[str, Any] = {}
        for field in _DECLARATION_FIELDS:
            declaration = value[field]
            if not isinstance(declaration, Mapping):
                return None
            status = declaration.get("status")
            if status == "not_declared" and set(declaration) == {"status"}:
                output[field] = {"status": "not_declared"}
            elif (status == "declared" and set(declaration) == {"status", "value"}
                  and isinstance(declaration.get("value"), str)
                  and len(declaration["value"]) <= 64):
                output[field] = {"status": "declared", "value": declaration["value"]}
            elif status == "unknown" and set(declaration) == {"status", "reason"}:
                output[field] = {"status": "unknown", "reason": "OPINION_DEFINITION_VALUE_UNSUPPORTED"}
            else:
                return None
        return output

    def _definition_for(self, key: str, cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
        if key in cache:
            return deepcopy(cache[key])
        definitions = self._definitions
        lookup = getattr(definitions, "lookup", None)
        public = {
            "status": "unknown", "reason": _DEFINITION_UNKNOWN,
            "source_basis": "disk_configuration", "loaded_membership_verified": False,
            "conditions_evaluated": False,
        }
        if callable(lookup):
            try:
                value = lookup(key)
                declarations = self._definition_declarations(value.get("declarations"))
                if (isinstance(value, Mapping) and value.get("status") == "known"
                        and value.get("key") == key
                        and value.get("source_basis") == "disk_configuration"
                        and value.get("loaded_membership_verified") is False
                        and value.get("conditions_evaluated") is False
                        and declarations is not None):
                    public = {
                        "status": "known", "declarations": declarations,
                        "source_basis": "disk_configuration",
                        "loaded_membership_verified": False, "conditions_evaluated": False,
                        "effects_executed": False, "current_decay_evaluated": False,
                        "end_date_evaluated": False,
                    }
            except Exception:
                pass
        cache[key] = public
        return deepcopy(public)

    def _attach_definitions(self, directions: list[dict[str, Any]]) -> None:
        if self._definitions is None:
            return
        before_ok, before_pins = self._definition_context(self._definitions)
        lookup_cache: dict[str, dict[str, Any]] = {}
        for direction in directions:
            if direction.get("status") != "known" or not isinstance(direction.get("records"), list):
                continue
            for record in direction["records"]:
                if record.get("status") == "known" and isinstance(record.get("modifier_id"), str):
                    record["definition"] = self._definition_for(record["modifier_id"], lookup_cache)

        after_ok, after_pins = self._definition_context(self._definitions)
        changed = (not before_ok or not after_ok
                   or (before_pins is not None and after_pins != before_pins))
        if changed:
            for direction in directions:
                if direction.get("status") != "known" or not isinstance(direction.get("records"), list):
                    continue
                for record in direction["records"]:
                    if record.get("status") == "known" and "definition" in record:
                        record["definition"] = {
                            "status": "unknown", "reason": _DEFINITION_UNKNOWN,
                            "source_basis": "disk_configuration",
                            "loaded_membership_verified": False,
                            "conditions_evaluated": False,
                        }

    @staticmethod
    def _project_record(record: Any) -> dict[str, Any]:
        if (isinstance(record, Mapping) and set(record) == {"status", "reason"}
                and record.get("status") == "unknown"
                and record.get("reason") == "OPINION_MODIFIER_CLASS_UNSUPPORTED"):
            return {"status": "unknown", "reason": "OPINION_MODIFIER_CLASS_UNSUPPORTED"}
        expected = {
            "status", "modifier_id", "current_opinion_raw", "raw_hex",
            "record_date_raw", "multiplier_raw", "flags_raw",
        }
        if not isinstance(record, Mapping) or set(record) != expected or record.get("status") != "known":
            return {"status": "unknown", "reason": _RECORD_INVALID}
        key = record.get("modifier_id")
        raw = record.get("current_opinion_raw")
        raw_hex = record.get("raw_hex")
        date_raw = record.get("record_date_raw")
        multiplier_raw = record.get("multiplier_raw")
        flags = record.get("flags_raw")
        if (not isinstance(key, str) or _KEY.fullmatch(key) is None
                or type(raw) is not int or not -(1 << 31) <= raw < (1 << 31)
                or not isinstance(raw_hex, str) or _HEX32.fullmatch(raw_hex) is None
                or type(date_raw) is not int or not -(1 << 31) <= date_raw < (1 << 31)
                or type(multiplier_raw) is not int or not -(1 << 31) <= multiplier_raw < (1 << 31)
                or not isinstance(flags, Mapping) or set(flags) != {"24", "26"}
                or any(type(flags[name]) is not int or not 0 <= flags[name] <= 0xff
                       for name in ("24", "26"))):
            return {"status": "unknown", "reason": _RECORD_INVALID}
        try:
            encoded = bytes.fromhex(raw_hex)
        except ValueError:
            return {"status": "unknown", "reason": _RECORD_INVALID}
        if int.from_bytes(encoded, "little", signed=True) != raw:
            return {"status": "unknown", "reason": _RECORD_INVALID}
        return {
            "status": "known", "modifier_id": key,
            "current_opinion_raw": raw, "current_opinion_decimal": _decimal_i32(raw),
            "raw_hex": raw_hex, "unit": _UNIT, "scale": _SCALE,
        }

    def _project_direction(self, item: Any, holder: str, target: str) -> dict[str, Any]:
        base = {"holder": holder, "target": target}
        if not isinstance(item, Mapping):
            return {**base, "status": "unknown", "reason": _INVALID_BACKEND}
        status = item.get("status")
        if status == "invisible":
            if set(item) == {"status", "reason"} and item.get("reason") == "admission_denied":
                return {**base, "status": "invisible", "reason": "OPINION_ADMISSION_DENIED"}
            return {**base, "status": "unknown", "reason": _INVALID_BACKEND}
        if status == "unknown":
            if set(item) == {"status", "reason"}:
                return {**base, "status": "unknown", "reason": _UNKNOWN_BACKEND}
            return {**base, "status": "unknown", "reason": _INVALID_BACKEND}
        if (status != "known" or set(item) != {"status", "value", "unit", "scale", "complete"}
                or item.get("unit") != _UNIT or type(item.get("scale")) is not int
                or item["scale"] != _SCALE or item.get("complete") is not False):
            return {**base, "status": "unknown", "reason": _INVALID_BACKEND}
        value = item.get("value")
        if (not isinstance(value, Mapping) or set(value) != {"holder", "target", "records"}
                or value.get("holder") != holder or value.get("target") != target
                or not _is_country(value.get("holder")) or not _is_country(value.get("target"))
                or holder == target or not isinstance(value.get("records"), list)
                or len(value["records"]) > _MAX_RECORDS):
            return {**base, "status": "unknown", "reason": _INVALID_BACKEND}
        return {
            **base, "status": "known",
            "records": [self._project_record(row) for row in value["records"]],
        }

    def _project_backend(self, report: Any, other: str, actor: str, recipient: str) -> dict[str, Any]:
        try:
            observation = report["observation"]
            backend = observation["backend"]
            targets = backend["targets"]
            if (not isinstance(observation, Mapping) or not isinstance(backend, Mapping)
                    or backend.get("status") != "observed"
                    or not isinstance(backend.get("consistency"), Mapping)
                    or backend["consistency"].get("status") != "stable"
                    or not isinstance(targets, list) or len(targets) != 1
                    or not isinstance(targets[0], Mapping) or targets[0].get("tag") != other
                    or not isinstance(targets[0].get("fields"), Mapping)):
                raise ValueError
            internal = targets[0]["fields"]
            if set(internal) != set(_FIELDS):
                raise ValueError
            rows = []
            for holder, target in ((actor, recipient), (recipient, actor)):
                field = _FIELDS[0] if holder == _OBSERVER else _FIELDS[1]
                rows.append(self._project_direction(internal[field], holder, target))
            self._attach_definitions(rows)

            result = {
                "unit": _UNIT, "scale": _SCALE, "period": _PERIOD, "complete": False,
                "partial": True, "basis": _BASIS, "value_origin": _VALUE_ORIGIN,
                "gaps": list(_GAPS),
            }
            if any(row["status"] == "known" for row in rows):
                result.update(status="known", value=rows)
            elif all(row["status"] == "invisible" for row in rows):
                result.update(status="invisible", reason="OPINION_DIRECTIONS_NOT_ADMITTED",
                              directions=rows)
            else:
                result.update(status="unknown", reason=_UNKNOWN_BACKEND, directions=rows)
            return result
        except (KeyError, TypeError, ValueError, AttributeError):
            return _unknown(_CAPTURE_INVALID)

    @staticmethod
    def _result(normalized: dict, context: dict, fields: dict, *, reason: str | None = None,
                unavailable: bool = False, target: str | None = None,
                capture_status: str = "not_attempted") -> dict:
        provenance = {
            "adapter": "NativeOpinionModifiersSource", "read_only": True,
            "native_function_invoked": False, "scope": "selected_country_pair",
            "observer": _OBSERVER, "target": target,
            "capture_status": capture_status,
            "modifier_records_only": True, "total_opinion_reconstructed": False,
            "record_date_interpreted": False, "multiplier_interpreted": False,
            "flags_interpreted": False,
        }
        if reason is not None:
            provenance["reason"] = reason
        source = _source_info("NativeOpinionModifiersSource", context,
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
            return self._result(normalized, before, {self.field: _unavailable(reason)},
                                reason=reason, unavailable=True)

        identity_error = _identity_reason(before)
        if identity_error is not None:
            return self._result(normalized, before, {self.field: _unavailable(identity_error)},
                                reason=identity_error, unavailable=True)
        if context is not None:
            supplied_error = _identity_reason(context)
            if supplied_error is not None:
                return self._result(normalized, before, {self.field: _unavailable(supplied_error)},
                                    reason=supplied_error, unavailable=True)
            if (_identity_snapshot(context) != _identity_snapshot(before)
                    or not dates_match(context["game_date"], before["game_date"])):
                reason = "BASE_CONTEXT_CHANGED_BEFORE_QUERY"
                return self._result(normalized, before, {self.field: _unavailable(reason)},
                                    reason=reason, unavailable=True)

        actor, recipient = normalized["object"]["actor"], normalized["object"]["recipient"]
        other = recipient if actor == _OBSERVER else actor
        installation, creation, binding_error = _session_binding(self.base_source)
        if binding_error is not None or installation is None or creation is None:
            reason = binding_error or "OPINION_MODIFIERS_INSTALLATION_UNAVAILABLE"
            return self._result(normalized, before, {self.field: _unavailable(reason)},
                                reason=reason, unavailable=True, target=other)

        capture_status = "capture_failed"
        report = None
        capture_fn = validator = None
        try:
            capture_fn, validator = self._capture_functions()
            if not callable(capture_fn) or not callable(validator):
                raise TypeError
            report = capture_fn(installation, other)
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
                                {self.field: _unknown(reason)}, reason=reason, target=other,
                                capture_status="context_changed")
        if report is None:
            return self._result(normalized, after, {self.field: _unknown(_CAPTURE_FAILED)},
                                reason=_CAPTURE_FAILED, target=other,
                                capture_status="capture_failed")

        try:
            valid = validator(report, before, creation, other) is True
        except Exception:
            valid = False
        if not valid:
            return self._result(normalized, after, {self.field: _unknown(_CAPTURE_INVALID)},
                                reason=_CAPTURE_INVALID, target=other,
                                capture_status="validation_failed")

        field = self._project_backend(report, other, actor, recipient)
        return self._result(normalized, after, {self.field: field}, target=other,
                            capture_status="validated")

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["NativeOpinionModifiersSource"]
