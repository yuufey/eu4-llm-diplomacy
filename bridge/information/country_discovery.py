"""Read-only adapter for FRA's bounded native country-discovery candidates.

The source exports only tags which both pass the captured native existence
predicate and are known by FRA. The native candidate domain remains partial.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re
from typing import Any

from .catalog import get_topic
from .empire_live import _context_identity
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import _context_reason as _base_reason, _session_binding


FIELD = "discovered_countries"
TOPIC = "C02"
FIELDS = (FIELD,)
ALL_FIELDS = frozenset(get_topic(TOPIC)["fields"])
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_PROFILE_SHA = re.compile(r"[0-9a-f]{64}\Z")
_BASIS = "native_exists_and_knows_country_for_resolved_ordinary_refs"
_MAX_CANDIDATES = 4096


class NativeCountryDiscoverySource:
    """Expose FRA-known tags among the bounded native ordinary-country scan."""

    event_types: tuple[str, ...] = ()
    field_names = FIELDS
    capture_module = ".country_discovery_capture"
    projection_version = 1

    def __init__(self, base_source: Any, *, capture: Any = None):
        self.base_source = base_source
        # Tests may inject a module-like backend or a capture callable paired
        # with the real module's validation/projection functions.
        self.capture = capture

    def context(self) -> dict:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict]:
        topic = get_topic(TOPIC)
        topic.update(
            status="available",
            source=type(self).__name__,
            visibility="observer_country_discovery_view",
            context_scope="visible_scope",
            supported_versions=["1.37.4"],
            triggers=["query", "periodic"],
            observer_roles=[],
            object_semantics="session_or_FRA_country_discovery_view",
            parameters={"type": "object", "properties": {},
                        "required": [], "additionalProperties": False},
        )
        topic["fields"] = {
            FIELD: {
                "coverage": "partial",
                "source": type(self).__name__,
                "complete": False,
                "unit": "country_tag",
                "scale": 1,
                "period": "current",
                "triggers": ["query", "periodic"],
                "value_origin": "native_country_exists_and_observer_knows_country",
                "basis": _BASIS,
                "supported_object_types": ["session", "country"],
                "description": "FRA知晓且通过原生存在判断的国家标签；候选国家域仍不完整。",
                "gaps": [
                    "ORDINARY_COUNTRY_CANDIDATE_DOMAIN_IS_BOUNDED",
                    "NON_ATOMIC_TWO_PASS_OBSERVATION",
                    "ACTUAL_UI_RENDER_NOT_OBSERVED",
                ],
            }
        }
        return [topic]

    def validate_query(self, query: Any, context: dict | None = None) -> dict:
        if (not isinstance(query, dict)
                or not {"topic", "object", "fields"} <= set(query)
                or set(query) - {"topic", "object", "fields", "parameters"}):
            raise InformationError("invalid_parameters", "C02 query has missing or unknown keys")
        if query["topic"] != TOPIC:
            raise InformationError("unsupported_topic", "Native country discovery supports C02 only")
        obj = query["object"]
        valid = isinstance(obj, dict) and obj == {"type": "session"}
        if isinstance(obj, dict) and obj.get("type") == "session":
            valid = (set(obj) <= {"type", "session_id"}
                     and ("session_id" not in obj
                          or (isinstance(obj.get("session_id"), str)
                              and _SESSION_ID.fullmatch(obj["session_id"]) is not None)))
        elif isinstance(obj, dict) and obj.get("type") == "country":
            valid = (set(obj) == {"type", "country"}
                     and isinstance(obj.get("country"), str)
                     and _TAG.fullmatch(obj["country"]) is not None)
        if not valid:
            raise InformationError("invalid_object", "C02 requires a session or country selector")
        fields = query["fields"]
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(name, str) or name not in ALL_FIELDS for name in fields)
                or len(fields) != len(set(fields))):
            raise InformationError("invalid_fields", "C02 requires unique declared fields")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "C02 native parameters must be empty")
        return {"topic": TOPIC, "object": deepcopy(obj),
                "fields": list(fields), "parameters": {}}

    @staticmethod
    def _context_reason(context: Any) -> str | None:
        reason = _base_reason(context, "FRA")
        return reason.replace("TRADE_INCOME_", "C02_", 1) if reason else None

    def _binding(self, context: dict) -> tuple[Any, int | None, str | None]:
        installation, creation, reason = _session_binding(self.base_source)
        if reason:
            return None, None, reason.replace("TRADE_INCOME_", "C02_", 1)
        session = getattr(self.base_source, "session", None)
        record = getattr(session, "record", None)
        if (not isinstance(record, dict)
                or record.get("session_id") != context.get("session_id")
                or type(creation) is not int or creation <= 0):
            return None, None, "C02_SESSION_RECORD_MISMATCH"
        return installation, creation, None

    @staticmethod
    def _projected_field(projected: Any) -> dict:
        if not isinstance(projected, dict) or set(projected) != {FIELD}:
            raise ValueError("C02_COUNTRY_DISCOVERY_PROJECTION_FIELDS")
        item = projected[FIELD]
        expected = {
            "status", "value", "candidate_count", "existing_candidate_count",
            "domain_complete", "country_existence_filter_applied",
        }
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError("C02_COUNTRY_DISCOVERY_PROJECTION_SHAPE")
        count = item.get("candidate_count")
        existing = item.get("existing_candidate_count")
        tags = item.get("value")
        if (item.get("status") != "known"
                or type(count) is not int or not 1 <= count <= _MAX_CANDIDATES
                or type(existing) is not int or not 0 <= existing <= count
                or type(item.get("domain_complete")) is not bool
                or item["domain_complete"] is not False
                or type(item.get("country_existence_filter_applied")) is not bool
                or item["country_existence_filter_applied"] is not True
                or not isinstance(tags, list) or len(tags) > existing
                or any(not isinstance(tag, str) or _TAG.fullmatch(tag) is None for tag in tags)
                or len(tags) != len(set(tags)) or tags != sorted(tags)):
            raise ValueError("C02_COUNTRY_DISCOVERY_PROJECTION_VALUES")
        return {
            "status": "known",
            "value": list(tags),
            "unit": "country_tag",
            "scale": 1,
            "period": "current",
            "complete": False,
            "basis": _BASIS,
            "candidate_count": count,
            "existing_candidate_count": existing,
            "country_existence_filter_applied": True,
            "domain_complete": False,
        }

    def _backend(self):
        injected = self.capture
        if (injected is not None
                and callable(getattr(injected, "capture", None))
                and callable(getattr(injected, "validate_capture", None))
                and callable(getattr(injected, "project_fields", None))):
            return injected, injected.capture
        module = import_module(self.capture_module, __package__)
        capture = injected if callable(injected) else module.capture
        return module, capture

    def read(self, query: Any, context: dict | None = None) -> dict:
        query = self.validate_query(query, context)
        try:
            current = deepcopy(context) if isinstance(context, dict) else self.context()
        except Exception:
            current = {}
        selected = [name for name in query["fields"] if name in self.field_names]
        fields = {name: {"status": "unsupported", "reason": "C02_COUNTRY_DISCOVERY_FIELD_NOT_IMPLEMENTED"}
                  for name in query["fields"]}
        provenance = {
            "observer": "FRA",
            "read_only": True,
            "native_function_invoked": False,
            "actual_UI_observed": False,
            "atomic_snapshot": False,
            "scope": "native_exists_and_knows_country_for_resolved_ordinary_refs_only",
            "domain_complete": False,
        }

        def result(ctx: dict) -> dict:
            source = _source_info(type(self).__name__, ctx, complete=False,
                                 provenance=provenance)
            source.update(context_scope="visible_scope",
                          projection_version=self.projection_version)
            return _result(query, ctx, fields, False, source)

        def failure(reason: str, ctx: dict = current, *, unavailable: bool = False) -> dict:
            for name in selected:
                fields[name] = {
                    "status": "unavailable" if unavailable else "unknown",
                    "reason": reason,
                    "period": "current",
                    "complete": False,
                }
            return result(ctx)

        if not selected:
            return result(current)

        obj = query["object"]
        if obj.get("type") == "country" and obj.get("country") != "FRA":
            fields[FIELD] = {"status": "not_applicable",
                             "reason": "C02_OBSERVER_DISCOVERY_VIEW_ONLY",
                             "period": "current", "complete": False}
            return result(current)
        reason = self._context_reason(current)
        if reason:
            return failure(reason, unavailable=True)
        selector_session = obj.get("session_id", current.get("session_id"))
        if selector_session != current.get("session_id"):
            return failure("C02_SELECTOR_SESSION_MISMATCH", unavailable=True)

        try:
            before = self.context()
        except Exception:
            return failure("C02_CONTEXT_UNAVAILABLE", unavailable=True)
        reason = self._context_reason(before)
        if reason or _context_identity(current) != _context_identity(before):
            return failure(reason or "C02_CONTEXT_STALE", before, unavailable=True)
        installation, creation, reason = self._binding(before)
        if reason:
            return failure(reason, before, unavailable=True)

        try:
            module, capture = self._backend()
            report = capture(installation, observer="FRA")
        except Exception:
            return failure("C02_CAPTURE_FAILED", before)

        try:
            after_capture = self.context()
        except Exception:
            after_capture = {}
        if (self._context_reason(after_capture)
                or _context_identity(before) != _context_identity(after_capture)):
            return failure("C02_CONTEXT_CHANGED_DURING_CAPTURE", before, unavailable=True)
        final_installation, final_creation, reason = self._binding(after_capture)
        if (reason or final_installation != installation
                or final_creation != creation):
            return failure("C02_SESSION_CHANGED_DURING_CAPTURE", before, unavailable=True)

        try:
            if module.validate_capture(report, before, creation) is not True:
                return failure("C02_CAPTURE_NOT_VALIDATED", before)
            public_field = self._projected_field(module.project_fields(report))
            final = self.context()
            final_binding = self._binding(final)
            if (self._context_reason(final)
                    or _context_identity(final) != _context_identity(before)
                    or final_binding != (installation, creation, None)):
                return failure("C02_CONTEXT_CHANGED_DURING_VALIDATION", before,
                               unavailable=True)
            report_sha256 = hashlib.sha256(
                canonical(report).encode("utf-8")).hexdigest()
            profile_sha256 = module.PROFILE_SHA256
            if not isinstance(profile_sha256, str) or _PROFILE_SHA.fullmatch(profile_sha256) is None:
                raise ValueError("C02_COUNTRY_DISCOVERY_PROFILE_PIN_INVALID")
            provenance["capture_report_sha256"] = report_sha256
            provenance["profile_sha256"] = profile_sha256
            fields[FIELD] = public_field
        except Exception:
            return failure("C02_CAPTURE_SHAPE_INVALID", before)
        return result(before)

    def poll_events(self, context: dict, cursor: dict | None) -> dict:
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


__all__ = ["NativeCountryDiscoverySource"]
