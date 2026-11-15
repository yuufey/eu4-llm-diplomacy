"""Read the bounded selected military-modifier aggregates for FRA.

The capture module owns native reads and their replay validation.  This source
binds that report to the current live session and publishes only the three
closed aggregate keys.  It does not represent the complete modifier set or
attribute values to named modifier instances.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
from importlib import import_module
import math
import re
from typing import Any

from .catalog import get_topic
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import (
    _GAME_SHA256,
    _VERSION,
    _context_reason as _base_context_reason,
    _identity,
    _session_binding,
)


_TOPIC = "N03"
_FIELD = "military_modifiers"
_COUNTRY = "FRA"
_UNIT = "military_modifier_map"
_SCALE = 1
_PERIOD = "current"
_BASIS = "native_selected_military_modifier_cache"
_VALUE_ORIGIN = "derived_from_copied_native_aggregate_modifiers"
_ITEM_UNIT = "ratio_modifier"
_ITEM_SCALE = 1000
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_SAFE_REASON = re.compile(r"[A-Za-z0-9_:-]{1,160}\Z")
_PROFILE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MODIFIER_KEYS = {
    "army": ("siege_ability", "defensiveness"),
    "navy": ("ship_durability",),
}
_CONTEXT_IDENTITY_KEYS = [
    "session_id", "game_sha256", "observer", "game_date", "game_version",
]


class NativeOwnMilitaryModifiersSource:
    """Own only N03.military_modifiers for the verified FRA live context."""

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
            observer_scope=[_COUNTRY],
            visibility="country_scope",
            context_scope="country_scope",
            supported_versions=[_VERSION],
            triggers=["query", "periodic"],
        )
        topic["parameters"] = {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        }
        topic["fields"] = {
            _FIELD: {
                "coverage": "partial",
                "source": "bridge.information.own_military_modifiers_capture.capture",
                "runtime_validation": "validated_selected_native_aggregate_modifiers",
                "complete": False,
                "unit": _UNIT,
                "scale": _SCALE,
                "period": _PERIOD,
                "basis": _BASIS,
                "value_origin": _VALUE_ORIGIN,
                "supported_countries": [_COUNTRY],
                "supported_object_types": ["country"],
                "description": (
                    "固定观察范围中已验证的陆军围城能力、陆军防御和船只耐久聚合修正。"
                    "这不是完整修正集合，也不表示具名修正实例的贡献。"
                ),
                "gaps": [
                    "ONLY_THREE_SELECTED_AGGREGATES_SUPPORTED",
                    "NAMED_MODIFIER_INSTANCE_CONTRIBUTION_NOT_PROVEN",
                    "COMPLETE_MODIFIER_SET_NOT_PROVEN",
                    "CACHE_FRESHNESS_NOT_PROVEN",
                    "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
                ],
            },
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
                f"N03 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError(
                "unknown_topic", "NativeOwnMilitaryModifiersSource supports N03 only",
            )
        obj = query.get("object")
        if (not isinstance(obj, dict) or set(obj) != {"type", "country"}
                or obj.get("type") != "country"):
            raise InformationError("invalid_object", "N03 requires a country object")
        if obj.get("country") != _COUNTRY:
            raise InformationError(
                "observer_scope_mismatch", "N03 modifiers support the verified FRA observer only",
            )
        fields = query.get("fields")
        if (not isinstance(fields, list) or fields != [_FIELD]):
            raise InformationError(
                "unknown_field", "NativeOwnMilitaryModifiersSource owns military_modifiers only",
            )
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "N03 parameters must be an empty object")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            if context.get("observer") is not None and context.get("observer") != _COUNTRY:
                raise InformationError(
                    "observer_scope_mismatch", "N03 is outside the verified FRA observer scope",
                )
        normalized = {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": [_FIELD],
            "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        try:
            reason = _base_context_reason(context, _COUNTRY)
        except Exception:
            return "OWN_MILITARY_MODIFIERS_CONTEXT_INVALID"
        return reason.replace("TRADE_INCOME_", "OWN_MILITARY_MODIFIERS_", 1) if reason else None

    @staticmethod
    def _public_field(status: str, *, reason: str | None = None,
                      value: dict[str, Any] | None = None) -> dict[str, Any]:
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
            output["value"] = deepcopy(value or {})
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
    def _sanitize_item(cls, item: Any) -> dict[str, Any] | None:
        if not isinstance(item, Mapping):
            return None
        status = item.get("status")
        if status == "known":
            if set(item) != {"status", "value", "raw", "unit", "scale"}:
                return None
            value = item.get("value")
            raw = item.get("raw")
            scale = item.get("scale")
            if (type(raw) is not int or not _I32_MIN <= raw <= _I32_MAX
                    or type(value) not in (int, float) or not math.isfinite(value)
                    or type(scale) is not int or scale != _ITEM_SCALE
                    or item.get("unit") != _ITEM_UNIT or value != raw / _ITEM_SCALE):
                return None
            return {
                "status": "known",
                "value": value,
                "raw": raw,
                "unit": _ITEM_UNIT,
                "scale": _ITEM_SCALE,
            }
        if status in {"unknown", "invisible"}:
            if set(item) != {"status", "reason"}:
                return None
            reason = cls._safe_reason(item.get("reason"))
            if reason is None:
                return None
            return {"status": status, "reason": reason}
        return None

    @classmethod
    def _safe_projected_field(cls, projected: Any) -> dict[str, Any] | None:
        if not isinstance(projected, Mapping):
            return None
        status = projected.get("status")
        if status in {"unknown", "invisible"}:
            if set(projected) != {"status", "reason"}:
                return None
            reason = cls._safe_reason(projected.get("reason"))
            if reason is None:
                return None
            return cls._public_field(status, reason=reason)
        common = {
            "unit": _UNIT,
            "scale": _SCALE,
            "period": _PERIOD,
            "complete": False,
            "partial": True,
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
        }
        for key, expected in common.items():
            if projected.get(key) != expected or type(projected.get(key)) is not type(expected):
                return None
        if (status != "known"
                or set(projected) != {"status", "value", "key_subset", *common}
                or projected.get("key_subset") != [
                    "army.siege_ability", "army.defensiveness", "navy.ship_durability",
                ]):
            return None
        nested = projected.get("value")
        if not isinstance(nested, Mapping) or set(nested) != set(_MODIFIER_KEYS):
            return None
        sanitized: dict[str, Any] = {}
        known_count = 0
        for group, names in _MODIFIER_KEYS.items():
            entries = nested.get(group)
            if not isinstance(entries, Mapping) or set(entries) != set(names):
                return None
            sanitized_entries: dict[str, Any] = {}
            for name in names:
                item = cls._sanitize_item(entries.get(name))
                if item is None:
                    return None
                if item["status"] == "known":
                    known_count += 1
                sanitized_entries[name] = item
            sanitized[group] = sanitized_entries
        if known_count == 0:
            return None
        return cls._public_field("known", value=sanitized)

    def read(self, query: dict[str, Any],
             context: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            current = deepcopy(context) if isinstance(context, dict) else self.context()
        except Exception:
            current = {}
        normalized = self.validate_query(query, current)
        field = self._public_field(
            "unknown", reason="OWN_MILITARY_MODIFIERS_NOT_READ",
        )
        provenance: dict[str, Any] = {
            "observer": _COUNTRY,
            "country": _COUNTRY,
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
            return _result(
                normalized, safe_context, {_FIELD: deepcopy(field)}, False, source,
            )

        def failure(reason: str, ctx: Any = None, *, unavailable: bool = False) -> dict[str, Any]:
            nonlocal field
            field = self._public_field(
                "unavailable" if unavailable else "unknown", reason=reason,
            )
            return result(current if ctx is None else ctx)

        reason = self._context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return failure(reason, unavailable=True)

        try:
            before = self.context()
        except Exception:
            provenance["context_guard"]["status"] = "unavailable"
            return failure("OWN_MILITARY_MODIFIERS_CONTEXT_UNAVAILABLE", unavailable=True)
        before_reason = self._context_reason(before)
        try:
            identities_match = _identity(current) == _identity(before)
        except Exception:
            identities_match = False
        if before_reason is not None or not identities_match:
            provenance["context_guard"]["status"] = "stale"
            return failure(
                before_reason or "OWN_MILITARY_MODIFIERS_CONTEXT_STALE",
                current,
                unavailable=True,
            )

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = binding_reason or "TRADE_INCOME_INSTALLATION_UNAVAILABLE"
            reason = reason.replace("TRADE_INCOME_", "OWN_MILITARY_MODIFIERS_", 1)
            provenance["context_guard"]["status"] = "unavailable"
            return failure(reason, before, unavailable=True)

        module = None
        report: Any = None
        capture_failed = False
        try:
            module = import_module(".own_military_modifiers_capture", __package__)
            capture_reader = self.capture if self.capture is not None else module.capture
            report = capture_reader(installation, observer=_COUNTRY)
        except Exception:
            capture_failed = True

        # Recheck both identities even when the capture/import raised.
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
                after_reason or "OWN_MILITARY_MODIFIERS_CONTEXT_CHANGED_DURING_CAPTURE",
                before,
                unavailable=True,
            )

        final_installation, final_creation, final_binding_reason = _session_binding(self.base_source)
        if (final_binding_reason is not None or final_installation != installation
                or final_creation != creation_filetime):
            provenance["context_guard"]["status"] = "session_changed"
            return failure(
                "OWN_MILITARY_MODIFIERS_SESSION_CHANGED_DURING_CAPTURE",
                before,
                unavailable=True,
            )
        if capture_failed or module is None:
            provenance["context_guard"]["status"] = "capture_failed"
            return failure("OWN_MILITARY_MODIFIERS_CAPTURE_FAILED", before)

        try:
            validator = getattr(module, "validate_capture")
            if validator(report, before, creation_filetime) is not True:
                provenance["context_guard"]["status"] = "capture_invalid"
                return failure("OWN_MILITARY_MODIFIERS_CAPTURE_NOT_VALIDATED", before)
            projected = module.project_field(report)
            public_field = self._safe_projected_field(projected)
            profile_sha256 = getattr(module, "PROFILE_SHA256", None)
            if (public_field is None or type(profile_sha256) is not str
                    or _PROFILE_SHA256.fullmatch(profile_sha256) is None):
                provenance["context_guard"]["status"] = "capture_shape_invalid"
                return failure("OWN_MILITARY_MODIFIERS_CAPTURE_SHAPE_INVALID", before)
            report_sha256 = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        except Exception:
            provenance["context_guard"]["status"] = "capture_shape_invalid"
            return failure("OWN_MILITARY_MODIFIERS_CAPTURE_SHAPE_INVALID", before)

        field = public_field
        provenance["context_guard"]["status"] = "passed"
        provenance["capture_report_sha256"] = report_sha256
        provenance["capture_report_hash_algorithm"] = (
            "sha256(canonical_json_utf8;information.model.canonical)"
        )
        provenance["profile_sha256"] = profile_sha256
        return result(before)

    def poll_events(self, context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["NativeOwnMilitaryModifiersSource"]
