"""Read the verified live G01 permanent-claim predicate for FRA provinces.

This adapter owns only ``G01.permanent_claims``.  The capture module supplies
the bounded two-pass native observation; this layer binds it to the active
session/context, validates the capture contract, and publishes only country
tags or a sanitized status.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
from importlib import import_module
import re
from typing import Any

from .catalog import get_topic
from .model import InformationError, canonical
from .province_interests_live import NativeProvinceInterestsSource
from .province_interest_parameters import parameters_schema
from .sources import _result, _source_info
from .trade_income import _context_reason as _base_context_reason
from .trade_income import _identity, _session_binding


_TOPIC = "G01"
_FIELD = "permanent_claims"
_COUNTRY = "FRA"
_VERSION = "1.37.4"
_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_UNIT = "country_tag"
_SCALE = 1
_PERIOD = "current"
_BASIS = "native_permanent_claim_predicate_after_positive_actor_discovery"
_VALUE_ORIGIN = "derived_from_copied_native_claim_and_history_records"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_REASON = re.compile(r"[A-Za-z0-9_:-]{1,160}\Z")
_PROFILE_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class NativeProvincePermanentClaimsSource:
    """Own the permanent-claim member list for positively discovered FRA provinces."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None):
        self.base_source = base_source
        self.capture = capture
        self._query_validator = NativeProvinceInterestsSource(base_source)

    def context(self) -> dict[str, Any]:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict[str, Any]]:
        topic = get_topic(_TOPIC)
        topic.update(
            status="available",
            source=type(self).__name__,
            visibility="visible_scope",
            context_scope="visible_scope",
            supported_versions=[_VERSION],
            triggers=["query", "periodic"],
        )
        topic["parameters"] = parameters_schema()
        topic["fields"] = {
            _FIELD: {
                "coverage": "partial",
                "source": type(self).__name__,
                "runtime_validation": "validated_native_permanent_claim_predicate",
                "complete": False,
                "unit": _UNIT,
                "scale": _SCALE,
                "period": _PERIOD,
                "basis": _BASIS,
                "value_origin": _VALUE_ORIGIN,
                "supported_countries": [_COUNTRY],
                "supported_object_types": ["province"],
                "visibility": "positive_live_observer_discovery",
                "description": "逻辑法国已发现省份中、由固定版本原生永久宣称谓词判定的国家标签列表。",
                "gaps": [
                    "COMPLETE_PROVINCE_UI_VISIBILITY_NOT_PROVEN",
                    "COUNTRY_REVERSE_ENUMERATION_NOT_IMPLEMENTED",
                ],
            },
        }
        return [topic]

    def validate_query(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        normalized = self._query_validator.validate_query(query, context)
        if normalized["topic"] != _TOPIC:
            raise InformationError("unsupported_topic", "Native permanent claims support G01 only")
        if normalized["fields"] != [_FIELD]:
            raise InformationError(
                "unknown_field",
                "NativeProvincePermanentClaimsSource owns permanent_claims only",
            )
        return normalized

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        try:
            reason = _base_context_reason(context, _COUNTRY)
        except Exception:
            return "PROVINCE_PERMANENT_CLAIMS_CONTEXT_INVALID"
        return reason.replace("TRADE_INCOME_", "PROVINCE_PERMANENT_CLAIMS_", 1) if reason else None

    @staticmethod
    def _public_field(status: str, *, reason: str | None = None,
                      value: list[str] | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
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
            result["value"] = list(value or [])
        elif reason is not None:
            result["reason"] = reason
        return result

    @staticmethod
    def _safe_projected_field(projected: Any) -> dict[str, Any] | None:
        if not isinstance(projected, Mapping):
            return None
        field = projected.get(_FIELD)
        if not isinstance(field, Mapping):
            return None
        status = field.get("status")
        if status == "known":
            value = field.get("value")
            if (not isinstance(value, list) or len(value) > 256
                    or any(type(tag) is not str or _TAG.fullmatch(tag) is None for tag in value)
                    or len(value) != len(set(value))):
                return None
            return NativeProvincePermanentClaimsSource._public_field(
                "known", value=sorted(value),
            )
        if status in {"unknown", "unavailable"}:
            reason = field.get("reason")
            if (type(reason) is not str or _REASON.fullmatch(reason) is None
                    or "0x" in reason.lower() or "0X" in reason):
                return None
            return NativeProvincePermanentClaimsSource._public_field(status, reason=reason)
        return None

    def read(self, query: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        normalized = self.validate_query(query, context)
        try:
            current = deepcopy(context) if isinstance(context, dict) else self.context()
        except Exception:
            current = {}

        field = self._public_field("unknown", reason="PROVINCE_PERMANENT_CLAIMS_NOT_READ")
        provenance: dict[str, Any] = {
            "observer": _COUNTRY,
            "read_only": True,
            "native_function_invoked": False,
            "actual_UI_observed": False,
            "full_province_visibility_complete": False,
        }

        def result(ctx: Any) -> dict[str, Any]:
            safe_context = ctx if isinstance(ctx, dict) else {}
            source = _source_info(
                type(self).__name__, safe_context, complete=False, provenance=provenance,
            )
            source.update(context_scope="visible_scope", projection_version=1)
            return _result(
                normalized,
                safe_context,
                {_FIELD: deepcopy(field)},
                False,
                source,
            )

        def failure(reason: str, ctx: Any = None, *, unavailable: bool = False) -> dict[str, Any]:
            nonlocal field
            field = self._public_field("unavailable" if unavailable else "unknown", reason=reason)
            return result(current if ctx is None else ctx)

        reason = self._context_reason(current)
        if reason:
            return failure(reason, unavailable=True)
        if normalized["object"]["type"] != "province":
            return failure("COUNTRY_REVERSE_ENUMERATION_NOT_IMPLEMENTED", current)

        province_id = normalized["object"]["province_id"]
        provenance["province_id"] = province_id
        try:
            before = self.context()
        except Exception:
            return failure("PROVINCE_PERMANENT_CLAIMS_CONTEXT_UNAVAILABLE", current,
                           unavailable=True)
        reason = self._context_reason(before)
        try:
            identity_matches = _identity(current) == _identity(before)
        except Exception:
            identity_matches = False
        if reason or not identity_matches:
            return failure(reason or "PROVINCE_PERMANENT_CLAIMS_CONTEXT_STALE", before,
                           unavailable=True)

        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            safe_reason = (
                binding_reason.replace("TRADE_INCOME_", "PROVINCE_PERMANENT_CLAIMS_", 1)
                if isinstance(binding_reason, str) else "PROVINCE_PERMANENT_CLAIMS_SESSION_UNAVAILABLE"
            )
            return failure(safe_reason, before, unavailable=True)

        module = None
        report = None
        capture_failed = False
        try:
            module = import_module(".province_permanent_claim_capture", __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, province_id=province_id, observer=_COUNTRY)
        except Exception:
            capture_failed = True

        # Always recheck context and session after the capture attempt, including
        # when importing/calling the low-level capture raised an exception.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._context_reason(after)
        try:
            context_matches = _identity(before) == _identity(after)
        except Exception:
            context_matches = False
        if after_reason or not context_matches:
            return failure(after_reason or "PROVINCE_PERMANENT_CLAIMS_CONTEXT_CHANGED_DURING_CAPTURE",
                           before, unavailable=True)

        final_installation, final_creation, final_reason = _session_binding(self.base_source)
        if (final_reason or final_installation != installation or final_creation != creation):
            return failure("PROVINCE_PERMANENT_CLAIMS_SESSION_CHANGED_DURING_CAPTURE",
                           before, unavailable=True)
        if capture_failed or module is None:
            return failure("PROVINCE_PERMANENT_CLAIMS_CAPTURE_FAILED", before)

        try:
            validator = getattr(module, "validate_capture")
            if validator(report, before, creation, province_id) is not True:
                return failure("PROVINCE_PERMANENT_CLAIMS_CAPTURE_NOT_VALIDATED", before)
            projected = module.project_fields(report)
            public_value = self._safe_projected_field(projected)
            profile_sha256 = getattr(module, "PROFILE_SHA256", None)
            if (public_value is None or type(profile_sha256) is not str
                    or _PROFILE_SHA256.fullmatch(profile_sha256) is None):
                return failure("PROVINCE_PERMANENT_CLAIMS_CAPTURE_SHAPE_INVALID", before)
            report_sha256 = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        except Exception:
            return failure("PROVINCE_PERMANENT_CLAIMS_CAPTURE_SHAPE_INVALID", before)

        field = public_value
        provenance["capture_report_sha256"] = report_sha256
        provenance["profile_sha256"] = profile_sha256
        return result(before)

    def poll_events(self, context: dict[str, Any], cursor: Any) -> dict[str, Any]:
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


__all__ = ["NativeProvincePermanentClaimsSource"]
