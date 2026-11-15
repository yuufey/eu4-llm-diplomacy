"""Expose the verified logical-FRA province fort-level input through G03."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from importlib import import_module
import hashlib
import re
from typing import Any

from .catalog import get_topic
from .model import InformationError, canonical
from .province_fort_memory import FIELD_FORT_LEVEL
from .sources import _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _context_reason as _base_reason,
    _identity,
    _session_binding,
)


FIELD = "fort"
BASIS = "native_fort_level_scope_trigger_input"
_SCHEMA = "information.province_fort_capture.v1"
_INNER_SCHEMA = "information.province_fort_observer_snapshot.v1"
_FIELDS_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_REASON = re.compile(r"[A-Z0-9_:-]{1,128}\Z")
_MAX_PROVINCE_ID = 0xFFFF
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_PASSPHASES = ("pass1", "pass2")


def _field(status: str, reason: str | None = None, *, value: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "period": "current",
        "basis": BASIS,
        "partial": True,
        "complete": False,
    }
    if reason is not None:
        result["reason"] = reason
    if status == "known":
        result["value"] = deepcopy(value)
    return result


def _public_reason(value: Any, fallback: str) -> str:
    if (isinstance(value, str) and _REASON.fullmatch(value)
            and "0x" not in value.lower()):
        return value
    return fallback


def _positive_admission(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    role = value.get("observer_nonplayer_role")
    return (
        value.get("status") == "known"
        and type(value.get("admitted")) is bool
        and value["admitted"] is True
        and isinstance(role, Mapping)
        and role.get("observer") == "FRA"
        and role.get("verified") is True
    )


def _positive_discovery(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("status") == "known"
        and type(value.get("value")) is bool
        and value["value"] is True
    )


def _backend_target(report: Any, province_id: int) -> tuple[dict[str, Any] | None, str | None]:
    """Return one independently bound target from the strictly replayed capture."""
    if not isinstance(report, Mapping) or report.get("schema") != _SCHEMA:
        return None, "PROVINCE_FORT_CAPTURE_INVALID"
    if report.get("observer") != "FRA":
        return None, "PROVINCE_FORT_CAPTURE_OBSERVER_MISMATCH"
    outer = report.get("object")
    if (not isinstance(outer, Mapping) or set(outer) != {"type", "province_id"}
            or outer.get("type") != "province"
            or type(outer.get("province_id")) is not int
            or outer["province_id"] != province_id):
        return None, "PROVINCE_FORT_CAPTURE_OBJECT_MISMATCH"
    inner = report.get("capture")
    observation = inner.get("observation") if isinstance(inner, Mapping) else None
    if (not isinstance(inner, Mapping) or inner.get("schema") != _INNER_SCHEMA
            or inner.get("status") != "observed" or inner.get("completed") is not True
            or not isinstance(observation, Mapping) or observation.get("stable") is not True):
        return None, "PROVINCE_FORT_CAPTURE_OBSERVATION_UNSTABLE"
    backend = observation.get("backend")
    consistency = backend.get("consistency") if isinstance(backend, Mapping) else None
    if (not isinstance(backend, Mapping) or backend.get("status") != "observed"
            or not isinstance(consistency, Mapping) or consistency.get("status") != "stable"):
        return None, "PROVINCE_FORT_BACKEND_UNSTABLE"
    observer = backend.get("observer")
    if not isinstance(observer, Mapping) or observer.get("tag") != "FRA":
        return None, "PROVINCE_FORT_BACKEND_OBSERVER_MISMATCH"
    targets = backend.get("targets")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], Mapping):
        return None, "PROVINCE_FORT_BACKEND_TARGET_INVALID"
    target = targets[0]
    if type(target.get("province_id")) is not int or target["province_id"] != province_id:
        return None, "PROVINCE_FORT_BACKEND_PROVINCE_MISMATCH"
    admissions = target.get("admission_by_pass")
    discoveries = target.get("discovery_by_pass")
    if (not isinstance(admissions, Mapping) or not isinstance(discoveries, Mapping)
            or any(not _positive_admission(admissions.get(phase)) for phase in _PASSPHASES)
            or any(not _positive_discovery(discoveries.get(phase)) for phase in _PASSPHASES)):
        return None, "PROVINCE_FORT_ADMISSION_OR_DISCOVERY_UNVERIFIED"
    consistency = target.get("field_consistency")
    if not isinstance(consistency, Mapping) or FIELD_FORT_LEVEL not in consistency:
        return None, "PROVINCE_FORT_FIELD_CONSISTENCY_MISSING"
    field_consistency = consistency[FIELD_FORT_LEVEL]
    if not isinstance(field_consistency, Mapping):
        return None, "PROVINCE_FORT_FIELD_CONSISTENCY_INVALID"
    if field_consistency.get("status") == "changed":
        return None, "PROVINCE_FORT_FIELD_CHANGED_BETWEEN_PASSES"
    if field_consistency.get("status") not in ("stable", "unknown"):
        return None, "PROVINCE_FORT_FIELD_CONSISTENCY_INVALID"
    fields = target.get("fields")
    if not isinstance(fields, Mapping) or set(fields) != {FIELD_FORT_LEVEL}:
        return None, "PROVINCE_FORT_FIELD_MISSING"
    return dict(target), None


def _project_fort(target: Mapping[str, Any], province_id: int) -> dict[str, Any]:
    fields = target.get("fields")
    raw = fields.get(FIELD_FORT_LEVEL) if isinstance(fields, Mapping) else None
    if not isinstance(raw, Mapping):
        return _field("unknown", "PROVINCE_FORT_FIELD_MISSING")
    if raw.get("status") != "known":
        reason = _public_reason(raw.get("reason"), "PROVINCE_FORT_OBSERVATION_UNKNOWN")
        return _field("unknown", reason)
    consistency = target.get("field_consistency")
    item_consistency = consistency.get(FIELD_FORT_LEVEL) if isinstance(consistency, Mapping) else None
    if not isinstance(item_consistency, Mapping) or item_consistency.get("status") != "stable":
        return _field("unknown", "PROVINCE_FORT_FIELD_NOT_STABLE")
    value = raw.get("value")
    if (type(value) is not int or not _INT32_MIN <= value <= _INT32_MAX
            or raw.get("complete") is not False
            or raw.get("basis") != BASIS
            or any(key in raw for key in ("unit", "scale", "amount"))):
        return _field("unknown", "PROVINCE_FORT_FIELD_INVALID")
    return _field("known", value={"province_id": province_id, "fort_level": value})


class NativeProvinceFortSource(NativeTradeIncomeSource):
    """Project only the current province fort-level scope input for G03."""

    event_types = ()

    def catalog(self) -> list[dict[str, Any]]:
        topic = get_topic("G03")
        topic.update(
            status="available",
            source=type(self).__name__,
            object_types=["province", "country_pair"],
            observer_roles=[],
            observer_scope=["FRA"],
            supported_versions=["1.37.4"],
            triggers=["query", "periodic"],
            parameters=deepcopy(_FIELDS_SCHEMA),
            context_scope="visible_scope",
            visibility="visible_scope",
            scope_note=("只读取逻辑FRA视角下已通过准入和发现校验的省份当前fort_level输入；"
                        "不宣称这是完整要塞状态。"),
            fields={FIELD: {
                "coverage": "partial",
                "complete": False,
                "source": type(self).__name__,
                "period": "current",
                "basis": BASIS,
                "unit": "fort_level",
                "scale": 1,
                "value_origin": "copied_native_province_fort_level_scope_trigger_input",
                "supported_object_types": ["province"],
                "supported_observers": ["FRA"],
                "supported_province_id_range": [1, _MAX_PROVINCE_ID],
                "runtime_validation": "province_fort_capture.validate_capture",
                "paths": ["value.fort_level"],
                "gaps": [
                    "FULL_FORT_STATE_NOT_CAPTURED",
                    "COUNTRY_PAIR_FORT_SUMMARY_NOT_IMPLEMENTED",
                    "GARRISON_MAINTENANCE_AND_REFRESH_PRODUCER_NOT_CAPTURED",
                ],
            }},
        )
        return [topic]

    def validate_query(self, query: Any, context: dict[str, Any] | None = None) -> dict[str, Any]:
        if (not isinstance(query, dict)
                or not {"topic", "object", "fields"} <= set(query)
                or set(query) - {"topic", "object", "fields", "parameters"}):
            raise InformationError("invalid_parameters", "G03 fort query has missing or unknown keys")
        if query["topic"] != "G03":
            raise InformationError("unknown_topic", "NativeProvinceFortSource supports G03 only")
        obj = query["object"]
        if not isinstance(obj, dict):
            raise InformationError("invalid_object", "G03 requires an explicit province or country pair")
        if obj.get("type") == "province":
            if (set(obj) != {"type", "province_id"} or type(obj.get("province_id")) is not int
                    or not 1 <= obj["province_id"] <= _MAX_PROVINCE_ID):
                raise InformationError("invalid_object", "province_id must be a positive bounded integer")
        elif obj.get("type") == "country_pair":
            if (set(obj) != {"type", "actor", "recipient"}
                    or any(not isinstance(obj[key], str) or _TAG.fullmatch(obj[key]) is None
                           for key in ("actor", "recipient"))):
                raise InformationError("invalid_object", "country_pair requires actor and recipient tags")
        else:
            raise InformationError("invalid_object", "G03 requires a province or country_pair")
        fields = query["fields"]
        if not isinstance(fields, list) or fields != [FIELD]:
            raise InformationError("invalid_fields", "G03 fort source supports fort only")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "G03 fort has no extra parameters")
        if context is not None and (not isinstance(context, dict)
                                    or context.get("observer") not in (None, "FRA")):
            raise InformationError("observer_scope_mismatch", "G03 fort is verified for logical FRA")
        normalized = {
            "topic": "G03",
            "object": deepcopy(obj),
            "fields": [FIELD],
            "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        reason = _base_reason(context, "FRA")
        return reason.replace("TRADE_INCOME_", "PROVINCE_FORT_", 1) if reason else None

    @staticmethod
    def _result_for(query: dict[str, Any], context: dict[str, Any], field: dict[str, Any],
                    provenance: dict[str, Any]) -> dict[str, Any]:
        source = _source_info(
            "NativeProvinceFortSource",
            context,
            complete=False,
            provenance=deepcopy(provenance),
        )
        if field.get("status") == "unavailable":
            source["status"] = "unavailable"
        source.update(context_scope="visible_scope", projection_version=1)
        return _result(query, context, {FIELD: field}, False, source)

    @staticmethod
    def _failure(query: dict[str, Any], context: dict[str, Any], reason: str,
                 provenance: dict[str, Any], *, unavailable: bool = False) -> dict[str, Any]:
        field = _field("unavailable" if unavailable else "unknown", reason)
        return NativeProvinceFortSource._result_for(query, context, field, provenance)

    def read(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        obj = normalized["object"]
        if obj["type"] == "country_pair":
            return self._failure(
                normalized,
                current,
                "FORT_COUNTRY_PAIR_NOT_IMPLEMENTED",
                {"observer": "FRA", "read_only": True, "native_function_invoked": False,
                 "actual_UI_observed": False, "basis": BASIS},
            )

        province_id = obj["province_id"]
        provenance: dict[str, Any] = {
            "observer": "FRA",
            "province_id": province_id,
            "read_only": True,
            "native_function_invoked": False,
            "actual_UI_observed": False,
            "basis": BASIS,
            "full_fort_state_captured": False,
        }

        reason = self._context_reason(current)
        if reason:
            return self._failure(normalized, current, reason, provenance, unavailable=True)
        try:
            before = self.context()
        except Exception:
            return self._failure(normalized, current, "PROVINCE_FORT_CONTEXT_UNAVAILABLE",
                                 provenance, unavailable=True)
        reason = self._context_reason(before)
        if reason:
            return self._failure(normalized, before, reason, provenance, unavailable=True)
        if _identity(current) != _identity(before):
            return self._failure(normalized, before, "PROVINCE_FORT_CONTEXT_STALE",
                                 provenance, unavailable=True)

        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return self._failure(
                normalized,
                before,
                binding_reason or "PROVINCE_FORT_INSTALLATION_UNAVAILABLE",
                provenance,
                unavailable=True,
            )
        try:
            module = import_module(".province_fort_capture", __package__)
        except Exception:
            return self._failure(normalized, before, "PROVINCE_FORT_CAPTURE_UNAVAILABLE",
                                 provenance, unavailable=True)
        capture = self.capture if self.capture is not None else getattr(module, "capture", None)
        if not callable(capture):
            return self._failure(normalized, before, "PROVINCE_FORT_CAPTURE_UNAVAILABLE",
                                 provenance, unavailable=True)

        report = None
        capture_error = None
        try:
            report = capture(installation, province_id=province_id, observer="FRA")
        except Exception as exc:
            capture_error = f"PROVINCE_FORT_CAPTURE_FAILED:{type(exc).__name__}"
        try:
            after = self.context()
        except Exception:
            after = {}
        if self._context_reason(after) or _identity(before) != _identity(after):
            return self._failure(normalized, before, "PROVINCE_FORT_CONTEXT_CHANGED_DURING_CAPTURE",
                                 provenance, unavailable=True)
        final_installation, final_creation, final_reason = _session_binding(self.base_source)
        if (final_reason or final_installation != installation
                or final_creation != creation):
            return self._failure(normalized, before, "PROVINCE_FORT_SESSION_CHANGED_DURING_CAPTURE",
                                 provenance, unavailable=True)
        if capture_error:
            return self._failure(normalized, before, capture_error, provenance)

        try:
            valid = module.validate_capture(report, before, creation, province_id)
        except Exception:
            valid = False
        if valid is not True:
            return self._failure(normalized, before, "PROVINCE_FORT_CAPTURE_INVALID", provenance)

        target, envelope_error = _backend_target(report, province_id)
        if target is None:
            return self._failure(normalized, before, envelope_error or "PROVINCE_FORT_CAPTURE_INVALID",
                                 provenance)
        inner = report["capture"]
        observation = inner["observation"]
        if (observation.get("context_before", {}).get("game_date") != before.get("game_date")
                or observation.get("context_after", {}).get("game_date") != before.get("game_date")):
            return self._failure(normalized, before, "PROVINCE_FORT_CAPTURE_DATE_MISMATCH", provenance)
        try:
            provenance["capture_report_sha256"] = hashlib.sha256(
                canonical(report).encode("utf-8")
            ).hexdigest()
        except Exception:
            return self._failure(normalized, before, "PROVINCE_FORT_CAPTURE_INVALID", provenance)

        field = _project_fort(target, province_id)
        return self._result_for(normalized, before, field, provenance)


__all__ = ["BASIS", "FIELD", "NativeProvinceFortSource"]
