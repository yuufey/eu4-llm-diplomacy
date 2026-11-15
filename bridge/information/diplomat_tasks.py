"""Read-only N05 projection of the verified native diplomat task vector.

The low-level reader owns the process inspection, profile guards and two-pass
record validation.  This module only binds that observation to the live
observer context and projects the bounded task records for the public
information contract.  It deliberately does not infer diplomat capacity,
relation counts, dates, or task meanings beyond the one selector proven by
the native source.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
from typing import Any, Mapping

from .model import InformationError, canonical
from .observation_time import dates_match
from .sources import _copy, _result, _source_info
from .country_state import _is_country, _parameter_schema
from .trade_income import (
    NativeTradeIncomeSource,
    _context_reason,
    _identity,
    _session_binding,
)


_TOPIC = "N05"
_FIELD = "diplomat_tasks"
_COUNTRY = "FRA"
_VERSION = "1.37.4"
_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_UNIT = "diplomat_task_records"
_SCALE = 1
_PERIOD = "current"
_BASIS = "native_country_diplomat_task_records"
_VALUE_ORIGIN = "copied_native_country_diplomat_task_records"
_COMPLETE = False
_KNOWN_TASK_TOKENS = {13176: "build_spy_network"}
_STATE_NAMES = {0: "idle", 1: "returning", 2: "active"}


_CATALOG_ITEM = {
    "topic_id": _TOPIC,
    "catalog_ids": [_TOPIC],
    "title": "本国外交官与关系容量",
    "status": "available",
    "fields": {
        _FIELD: {
            "coverage": "partial",
            "runtime_validation": "validated_native_diplomat_tasks",
            "source": "bridge.information.diplomat_tasks_memory.capture",
            "unit": _UNIT,
            "scale": _SCALE,
            "raw": True,
            "raw_semantics": (
                "bounded native diplomat task records; state 0/1/2 is exposed "
                "as idle/returning/active and other state values remain unknown"
            ),
            "paths": [
                "diplomat_tasks.instance_count_observed",
                "diplomat_tasks.available_count_observed",
                "diplomat_tasks.instances[]",
            ],
            "supported_countries": [_COUNTRY],
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "complete": _COMPLETE,
            "gaps": [
                "DIPLOMATS_TOTAL_NOT_VERIFIED",
                "RETURN_DATES_NOT_VERIFIED",
                "UNKNOWN_TASK_TOKENS_NOT_CLASSIFIED",
                "TASK_LIFECYCLE_NOT_COMPLETE",
            ],
        },
    },
    "object_types": ["country"],
    "observer_roles": ["country"],
    "observer_scope": [_COUNTRY],
    "parameters": _parameter_schema(_TOPIC),
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic"],
    "runtime_validation": "validated",
    "source": "NativeDiplomatTasksSource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "仅读取固定1.37.4、FRA观察者的外交官任务实例；外交官总量、"
        "容量、关系数量和任务日期不在本字段范围内。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _public_reason(reason: str) -> str:
    if reason.startswith("TRADE_INCOME_"):
        return "DIPLOMAT_TASKS_" + reason.removeprefix("TRADE_INCOME_")
    return reason


def _context_failure(context: Any, *, prefix: str = "DIPLOMAT_TASKS") -> str | None:
    reason = _context_reason(context)
    if reason is None:
        return None
    return _public_reason(reason) if reason.startswith("TRADE_INCOME_") else prefix + "_" + reason


def _low_level_module():
    try:
        return importlib.import_module(".diplomat_tasks_memory", __package__)
    except Exception:
        return None


def _report_cleanup_ok(report: Any) -> bool:
    if not isinstance(report, Mapping):
        return False
    cleanup = report.get("cleanup")
    handle = cleanup.get("handle_close") if isinstance(cleanup, Mapping) else None
    return (
        isinstance(handle, Mapping)
        and handle.get("status") == "closed"
        and handle.get("closed") is True
    )


def _report_record(report: Any) -> Mapping[str, Any] | None:
    # ``diplomat_tasks_memory.capture`` has one stable child shape.  Its
    # validator checks both snapshots and their canonical equality before we
    # reach this projection, so the before record is the only source consumed
    # here; no alternate guessed field/record shape is accepted.
    if not isinstance(report, Mapping):
        return None
    before = report.get("before")
    if not isinstance(before, Mapping):
        return None
    record = before.get("record")
    return record if isinstance(record, Mapping) else None


def _state_raw(instance: Mapping[str, Any]) -> int | None:
    value = instance.get("state_raw_18")
    if type(value) is int:
        return value
    value = instance.get("state_raw_18_hex")
    if isinstance(value, str):
        try:
            return int.from_bytes(bytes.fromhex(value), "little", signed=True)
        except (ValueError, TypeError):
            return None
    return None


def _token_raw(instance: Mapping[str, Any]) -> int | None:
    value = instance.get("raw_action_type_a8")
    if type(value) is int:
        return value
    value = instance.get("raw_action_type_a8_hex")
    if isinstance(value, str):
        try:
            return int.from_bytes(bytes.fromhex(value), "little", signed=True)
        except (ValueError, TypeError):
            return None
    return None


def _public_instance(instance: Any) -> dict[str, Any]:
    if not isinstance(instance, Mapping):
        raise ValueError("DIPLOMAT_TASKS_INSTANCE_INVALID")
    result = deepcopy(dict(instance))
    state = _state_raw(instance)
    if state is not None:
        result["state_raw"] = state
        result["state"] = _STATE_NAMES.get(state, "unknown")
    elif "state" not in result:
        raise ValueError("DIPLOMAT_TASKS_STATE_INVALID")
    token = _token_raw(instance)
    if token is not None:
        result["action_token_raw"] = token
        result["task"] = _KNOWN_TASK_TOKENS.get(token, "unknown")
    return result


def _record_value(record: Mapping[str, Any]) -> dict[str, Any]:
    values = record.get("values")
    instances = values.get(_FIELD) if isinstance(values, Mapping) else None
    if not isinstance(instances, list):
        raise ValueError("DIPLOMAT_TASKS_INSTANCES_INVALID")
    count = record.get("instance_count_observed")
    available = record.get("available_count_observed")
    if type(count) is not int or count < 0 or count != len(instances):
        raise ValueError("DIPLOMAT_TASKS_INSTANCE_COUNT_INVALID")
    if available is None:
        available = sum(1 for instance in instances if _state_raw(instance) == 0)
    if type(available) is not int or available < 0 or available > count:
        raise ValueError("DIPLOMAT_TASKS_AVAILABLE_COUNT_INVALID")
    rows = [_public_instance(instance) for instance in instances]
    state_zero = sum(1 for instance in rows if instance.get("state_raw") == 0)
    if state_zero != available:
        raise ValueError("DIPLOMAT_TASKS_AVAILABLE_COUNT_MISMATCH")
    return {
        "instance_count_observed": count,
        "available_count_observed": available,
        "instances": rows,
    }


def concise_diplomat_tasks(value: Any) -> dict[str, Any] | None:
    """Copy the task states and countries needed in a concise report."""
    if not isinstance(value, Mapping):
        return None
    return {
        "instance_count_observed": value.get("instance_count_observed"),
        "available_count_observed": value.get("available_count_observed"),
        "instances": [
            {key: instance[key] for key in ("state", "task", "actor", "recipient")
             if instance.get(key) is not None}
            for instance in value.get("instances", [])
        ],
    }


def _record_sha256(record: Mapping[str, Any]) -> str | None:
    try:
        return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()
    except Exception:
        return None


class NativeDiplomatTasksSource(NativeTradeIncomeSource):
    """Expose only the verified FRA N05 diplomat task records."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None):
        super().__init__(base_source, capture=capture)

    def catalog(self) -> list[dict[str, Any]]:
        return [deepcopy(_CATALOG_ITEM)]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError(
                "invalid_parameters",
                f"N05 diplomat_tasks query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeDiplomatTasksSource supports N05 only")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"} or obj.get("type") != "country":
            raise InformationError("invalid_object", "N05 diplomat_tasks requires a country object")
        if obj.get("country") != _COUNTRY:
            raise InformationError("observer_scope_mismatch", "Only the verified FRA country is supported")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError("invalid_fields", "N05 fields must be unique strings")
        if set(fields) != {_FIELD}:
            raise InformationError("unknown_field", "N05 supports diplomat_tasks only")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict):
            raise InformationError("invalid_parameters", "N05 diplomat_tasks parameters must be an object")
        if set(parameters) not in (set(), {"reference_recipient"}):
            raise InformationError(
                "invalid_parameters",
                "N05 diplomat_tasks parameters may be empty or contain reference_recipient only",
            )
        if "reference_recipient" in parameters:
            recipient = parameters["reference_recipient"]
            if not _is_country(recipient):
                raise InformationError("invalid_parameters", "reference_recipient must be a country tag")
            if recipient == obj["country"]:
                raise InformationError(
                    "invalid_parameters",
                    "reference_recipient must differ from the observed country",
                )
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if observer is not None and observer != _COUNTRY:
                raise InformationError("observer_scope_mismatch", "N05 is outside the FRA scope")
        normalized = {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": deepcopy(parameters),
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _failure_fields(fields: list[str], reason: str, *, unavailable: bool) -> dict[str, dict[str, Any]]:
        factory = _unavailable if unavailable else _unknown
        return {field: factory(reason) for field in fields}

    @staticmethod
    def _result(normalized, context, fields, provenance):
        source = _source_info(
            "NativeDiplomatTasksSource", context, complete=False, provenance=provenance,
        )
        source["context_scope"] = "country_scope"
        if fields and all(
            isinstance(item, dict) and item.get("status") == "unavailable"
            for item in fields.values()
        ):
            source["status"] = "unavailable"
        return _result(normalized, context, fields, False, source)

    def _capture_reader(self):
        if self.capture is not None:
            return self.capture
        module = _low_level_module()
        return getattr(module, "capture", None) if module is not None else None

    def read(self, query: dict, context: dict | None = None) -> dict[str, Any]:
        supplied = _copy(context) if isinstance(context, dict) else None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.diplomat_tasks_memory.capture",
            "country": _COUNTRY,
            "read_only": True,
            "native_function_invoked": False,
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "context_guard": {
                "mode": "live", "game_version": _VERSION,
                "game_sha256": _GAME_SHA256,
            },
        }

        def result(ctx, fields):
            return self._result(normalized, ctx, fields, provenance)

        reason = _context_failure(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, reason, unavailable=True))

        try:
            before = self.context()
        except Exception:
            before = {}
        before_reason = _context_failure(before)
        if before_reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, before_reason, unavailable=True))
        if (_identity(current) != _identity(before)
                or not dates_match(current.get('game_date'), before.get('game_date'))):
            provenance["context_guard"]["status"] = "stale"
            return result(current, self._failure_fields(requested, "DIPLOMAT_TASKS_CONTEXT_STALE", unavailable=True))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = _public_reason(binding_reason or "TRADE_INCOME_INSTALLATION_UNAVAILABLE")
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        capture = self._capture_reader()
        if not callable(capture):
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, "DIPLOMAT_TASKS_CAPTURE_UNAVAILABLE", unavailable=True))

        report = None
        capture_error = None
        try:
            report = capture(installation, country=_COUNTRY)
        except Exception as exc:
            capture_error = "DIPLOMAT_TASKS_CAPTURE_FAILED:" + type(exc).__name__

        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = _context_failure(after)
        if (after_reason is not None or _identity(before) != _identity(after)
                or not dates_match(before.get('game_date'), after.get('game_date'))):
            provenance["context_guard"]["status"] = "changed"
            reason = after_reason or "DIPLOMAT_TASKS_CONTEXT_CHANGED_DURING_CAPTURE"
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            provenance["capture_reason"] = capture_error
            return result(before, self._failure_fields(requested, capture_error, unavailable=False))

        provenance["capture_report_sha256"] = _record_sha256(report) if isinstance(report, Mapping) else None
        module = _low_level_module()
        validator = getattr(module, "validate_capture", None) if module is not None else None
        if not callable(validator):
            reason = "DIPLOMAT_TASKS_VALIDATOR_UNAVAILABLE"
        else:
            try:
                valid = validator(report, before, creation_filetime, _COUNTRY)
            except Exception as exc:
                valid = False
                provenance["validator_error"] = type(exc).__name__
            reason = None if valid is True else "DIPLOMAT_TASKS_CAPTURE_INVALID"
        if reason is None and not _report_cleanup_ok(report):
            reason = "DIPLOMAT_TASKS_CLEANUP_INVALID"
        if reason is None:
            record = _report_record(report)
            if record is None:
                reason = "DIPLOMAT_TASKS_RECORD_MISSING"
        if reason is not None:
            provenance["context_guard"]["status"] = "capture_invalid"
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))

        try:
            value = _record_value(record)
        except (TypeError, ValueError, KeyError) as exc:
            reason = str(exc) or "DIPLOMAT_TASKS_RECORD_INVALID"
            provenance["context_guard"]["status"] = "capture_invalid"
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        provenance["context_guard"]["status"] = "passed"
        provenance["instance_count_observed"] = value["instance_count_observed"]
        provenance["available_count_observed"] = value["available_count_observed"]
        field = {
            "status": "known",
            "value": value,
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "partial": True,
            "complete": _COMPLETE,
        }
        return result(before, {_FIELD: field})

    def poll_events(self, context: dict | None, cursor: Any) -> dict[str, Any]:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeDiplomatTasksSource", "concise_diplomat_tasks"]
