"""Read the observer country's bounded native diplomatic relation count and limit."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
from importlib import import_module
import re
from typing import Any

from .catalog import get_topic
from .country_state import _is_country, _parameter_schema
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import (
    _GAME_SHA256,
    _VERSION,
    _observer_context_reason,
    _identity,
    _session_binding,
)


_TOPIC = "N05"
_FIELDS = ("relations_count", "relations_limit")
_UNIT = "diplomatic_relation"
_SCALE = 1
_PERIOD = "current"
_BASIS = "native_diplomatic_relation_trigger_arithmetic"
_VALUE_ORIGIN = "derived_from_copied_native_modifier_and_relation_caches"
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_SAFE_REASON = re.compile(r"[A-Za-z0-9_:-]{1,160}\Z")
_PROFILE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CONTEXT_IDENTITY_KEYS = [
    "session_id", "game_sha256", "observer", "game_date", "game_version",
]


class NativeRelationsCapacitySource:
    """Expose the observer country's N05.relations_count and N05.relations_limit."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None):
        self.base_source = base_source
        self.capture = capture

    def context(self) -> dict[str, Any]:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict[str, Any]]:
        topic = get_topic(_TOPIC)
        topic.update(
            status="available",
            source=type(self).__name__,
            observer_roles=["country"],
            observer_scope=[],
            visibility="country_scope",
            context_scope="country_scope",
            supported_versions=[_VERSION],
            triggers=["query", "periodic"],
        )
        topic["parameters"] = _parameter_schema(_TOPIC)
        topic["fields"] = {
            field: {
                "coverage": "partial",
                "source": "bridge.information.relations_capacity_capture.capture",
                "runtime_validation": "validated_native_relation_trigger_arithmetic",
                "complete": False,
                "unit": _UNIT,
                "scale": _SCALE,
                "period": _PERIOD,
                "basis": _BASIS,
                "value_origin": _VALUE_ORIGIN,
                "supported_object_types": ["country"],
                "description": (
                    "读取固定范围内本国外交关系计数与容量。关系数量来自原生条件算术，"
                    "容量只在其基础值及修正路径完整已知时返回；不从关系行数推断。"
                ),
                "gaps": [
                    "ONLY_FIXED_NATIVE_RELATION_TRIGGER_SUPPORTED",
                    "UNSUPPORTED_PROCESSOR_PATHS_REMAIN_UNKNOWN",
                    "COMPLETE_RELATION_SEMANTICS_NOT_PROVEN",
                    "CACHE_FRESHNESS_NOT_PROVEN",
                    "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
                ],
            }
            for field in _FIELDS
        }
        return [topic]

    def validate_query(self, query: dict[str, Any],
                       context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError(
                "invalid_parameters",
                f"N05 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError(
                "unknown_topic", "NativeRelationsCapacitySource supports N05 only",
            )
        obj = query.get("object")
        if (not isinstance(obj, dict) or set(obj) != {"type", "country"}
                or obj.get("type") != "country"):
            raise InformationError("invalid_object", "N05 requires a country object")
        country = obj.get("country")
        if not _is_country(country):
            raise InformationError("invalid_object", "N05 requires a country tag")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields or len(fields) > len(_FIELDS)
                or any(type(field) is not str or field not in _FIELDS for field in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError(
                "unknown_field", "N05 fields must select relations_count and/or relations_limit",
            )
        parameters = query.get("parameters", {})
        if (not isinstance(parameters, dict)
                or set(parameters) not in (set(), {"reference_recipient"})):
            raise InformationError("invalid_parameters", "N05 accepts reference_recipient only")
        if "reference_recipient" in parameters:
            recipient = parameters["reference_recipient"]
            if not _is_country(recipient) or recipient == country:
                raise InformationError("invalid_parameters", "reference_recipient must name another country")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            if context.get("observer") is not None and context.get("observer") != country:
                raise InformationError("observer_scope_mismatch", "N05 is limited to the configured observer country")
        normalized = {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": deepcopy(parameters),
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        try:
            reason = _observer_context_reason(context)
        except Exception:
            return "RELATIONS_CAPACITY_CONTEXT_INVALID"
        return reason.replace("TRADE_INCOME_", "RELATIONS_CAPACITY_", 1) if reason else None

    @staticmethod
    def _public_field(status: str, *, reason: str | None = None,
                      value: int | None = None, raw_hex: str | None = None) -> dict[str, Any]:
        output: dict[str, Any] = {
            "status": status,
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "complete": False,
            "partial": True,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
        }
        if status == "known":
            output["value"] = value
            output["raw"] = value
            output["raw_hex"] = raw_hex
        elif reason is not None:
            output["reason"] = reason
        return output

    @staticmethod
    def _safe_reason(value: Any) -> str | None:
        if (type(value) is not str or _SAFE_REASON.fullmatch(value) is None
                or "0x" in value.lower()):
            return None
        return value

    @classmethod
    def _sanitize_field(cls, item: Any) -> dict[str, Any] | None:
        if not isinstance(item, Mapping):
            return None
        status = item.get("status")
        if status in {"unknown", "invisible"}:
            reason = cls._safe_reason(item.get("reason"))
            if reason is None:
                return None
            # Unknown and invisible projections need only their status/reason;
            # their known-value metadata is intentionally not required.
            return cls._public_field(status, reason=reason)
        if status != "known":
            return None
        if set(item) != {
            "status", "value", "raw", "raw_hex", "unit", "scale", "period",
            "partial", "complete", "basis", "value_origin",
        }:
            return None
        value = item.get("value")
        raw = item.get("raw")
        raw_hex = item.get("raw_hex")
        if (type(value) is not int or not _I32_MIN <= value <= _I32_MAX
                or type(raw) is not int or not _I32_MIN <= raw <= _I32_MAX
                or raw != value
                or type(raw_hex) is not str or re.fullmatch(r"[0-9a-f]{8}", raw_hex) is None
                or item.get("unit") != _UNIT
                or type(item.get("scale")) is not int or item.get("scale") != _SCALE
                or item.get("period") != _PERIOD
                or item.get("partial") is not True or item.get("complete") is not False
                or item.get("basis") != _BASIS
                or item.get("value_origin") != _VALUE_ORIGIN):
            return None
        try:
            decoded = int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True)
        except (TypeError, ValueError):
            return None
        if decoded != raw or decoded != value:
            return None
        return cls._public_field("known", value=value, raw_hex=raw_hex)

    def read(self, query: dict[str, Any],
             context: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            current = deepcopy(context) if isinstance(context, dict) else self.context()
        except Exception:
            current = {}
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]
        country = normalized["object"]["country"]
        fields = {
            name: self._public_field("unknown", reason="RELATIONS_CAPACITY_NOT_READ")
            for name in requested
        }
        provenance: dict[str, Any] = {
            "observer": country,
            "country": country,
            "read_only": True,
            "native_function_invoked": False,
            "context_guard": {
                "mode": "live",
                "game_version": _VERSION,
                "game_sha256": _GAME_SHA256,
                "identity_keys": list(_CONTEXT_IDENTITY_KEYS),
            },
        }

        def result(ctx: Any) -> dict[str, Any]:
            safe_context = ctx if isinstance(ctx, dict) else {}
            source = _source_info(
                type(self).__name__, safe_context, complete=False,
                provenance=provenance,
            )
            source.update(context_scope="country_scope", projection_version=1)
            return _result(normalized, safe_context, deepcopy(fields), False, source)

        def failure(reason: str, ctx: Any = None, *, unavailable: bool = False) -> dict[str, Any]:
            nonlocal fields
            state = "unavailable" if unavailable else "unknown"
            fields = {
                name: self._public_field(state, reason=reason)
                for name in requested
            }
            return result(current if ctx is None else ctx)

        reason = self._context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return failure(reason, unavailable=True)
        try:
            before = self.context()
        except Exception:
            provenance["context_guard"]["status"] = "unavailable"
            return failure("RELATIONS_CAPACITY_CONTEXT_UNAVAILABLE", unavailable=True)
        before_reason = self._context_reason(before)
        try:
            identity_matches = _identity(current) == _identity(before)
        except Exception:
            identity_matches = False
        if before_reason is not None or not identity_matches:
            provenance["context_guard"]["status"] = "stale"
            return failure(
                before_reason or "RELATIONS_CAPACITY_CONTEXT_STALE",
                current,
                unavailable=True,
            )

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = binding_reason or "TRADE_INCOME_INSTALLATION_UNAVAILABLE"
            reason = reason.replace("TRADE_INCOME_", "RELATIONS_CAPACITY_", 1)
            provenance["context_guard"]["status"] = "unavailable"
            return failure(reason, before, unavailable=True)

        module = None
        report: Any = None
        capture_failed = False
        try:
            module = import_module(".relations_capacity_capture", __package__)
            capture_reader = self.capture if self.capture is not None else module.capture
            report = capture_reader(installation, observer=country)
        except Exception:
            capture_failed = True

        # Always recheck context and session after attempting capture, even when
        # import or capture itself failed.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._context_reason(after)
        try:
            context_matches = _identity(before) == _identity(after)
        except Exception:
            context_matches = False
        if after_reason is not None or not context_matches:
            provenance["context_guard"]["status"] = "changed"
            return failure(
                after_reason or "RELATIONS_CAPACITY_CONTEXT_CHANGED_DURING_CAPTURE",
                before,
                unavailable=True,
            )
        final_installation, final_creation, final_binding_reason = _session_binding(self.base_source)
        if (final_binding_reason is not None or final_installation != installation
                or final_creation != creation_filetime):
            provenance["context_guard"]["status"] = "session_changed"
            return failure(
                "RELATIONS_CAPACITY_SESSION_CHANGED_DURING_CAPTURE",
                before,
                unavailable=True,
            )
        if capture_failed or module is None:
            provenance["context_guard"]["status"] = "capture_failed"
            return failure("RELATIONS_CAPACITY_CAPTURE_FAILED", before)

        try:
            validator = getattr(module, "validate_capture")
            if validator(report, before, creation_filetime) is not True:
                provenance["context_guard"]["status"] = "capture_invalid"
                return failure("RELATIONS_CAPACITY_CAPTURE_NOT_VALIDATED", before)
            projected = module.project_fields(report)
            profile_sha256 = getattr(module, "PROFILE_SHA256", None)
            if (not isinstance(projected, Mapping) or set(projected) != set(_FIELDS)
                    or type(profile_sha256) is not str
                    or _PROFILE_SHA256.fullmatch(profile_sha256) is None):
                provenance["context_guard"]["status"] = "capture_shape_invalid"
                return failure("RELATIONS_CAPACITY_CAPTURE_SHAPE_INVALID", before)
            sanitized: dict[str, dict[str, Any]] = {}
            for name in requested:
                item = self._sanitize_field(projected.get(name))
                if item is None:
                    provenance["context_guard"]["status"] = "capture_shape_invalid"
                    return failure("RELATIONS_CAPACITY_CAPTURE_SHAPE_INVALID", before)
                sanitized[name] = item
            report_sha256 = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        except Exception:
            provenance["context_guard"]["status"] = "capture_shape_invalid"
            return failure("RELATIONS_CAPACITY_CAPTURE_SHAPE_INVALID", before)

        fields = sanitized
        provenance["context_guard"]["status"] = "passed"
        provenance["capture_report_sha256"] = report_sha256
        provenance["capture_report_hash_algorithm"] = (
            "sha256(canonical_json_utf8;information.model.canonical)"
        )
        provenance["profile_sha256"] = profile_sha256
        return result(before)

    def poll_events(self, context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["NativeRelationsCapacitySource"]
