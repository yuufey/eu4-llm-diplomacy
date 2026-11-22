"""Read-only adapter for the configured observer's bounded discovery bitmap.

The bitmap reports positive province-ID candidates only.  Its finite native
range is not proof that every province ID in the game has been enumerated.
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
from .trade_income import _observer_context_reason as _base_reason, _session_binding


FIELD = "discovered_provinces"
TOPIC = "C02"
FIELDS = (FIELD,)
ALL_FIELDS = frozenset(get_topic(TOPIC)["fields"])
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_BASIS = "native_bounded_province_discovery_bitmap_candidates"
_MAX_CANDIDATE_ID = 65535


class NativeProvinceDiscoverySource:
    """Expose only the observer's positive province discovery candidates."""

    event_types: tuple[str, ...] = ()
    field_names = FIELDS
    capture_module = ".province_discovery_capture"
    projection_version = 1

    def __init__(self, base_source: Any, *, capture: Any = None):
        self.base_source = base_source
        # A module-like object can inject all three backend operations in
        # tests. A callable remains compatible with the established live
        # adapters and supplies only the capture operation.
        self.capture = capture

    def context(self) -> dict:
        return deepcopy(self.base_source.context())

    def catalog(self) -> list[dict]:
        topic = get_topic(TOPIC)
        topic.update(
            status="available",
            source=type(self).__name__,
            visibility="observer_discovery_view",
            context_scope="visible_scope",
            supported_versions=["1.37.4"],
            triggers=["query", "periodic"],
            observer_roles=[],
            object_semantics="session_or_observer_country_discovery_view",
            parameters={"type": "object", "properties": {},
                        "required": [], "additionalProperties": False},
        )
        topic["fields"] = {
            FIELD: {
                "coverage": "partial",
                "source": type(self).__name__,
                "complete": False,
                "unit": "province_id",
                "scale": 1,
                "period": "current",
                "triggers": ["query", "periodic"],
                "value_origin": "bounded_native_discovery_bitmap_candidates",
                "basis": _BASIS,
                "supported_object_types": ["session", "country"],
                "description": "观察方发现位图中为正的省份编号候选；不代表完整省份域。",
                "gaps": [
                    "CANDIDATE_ID_RANGE_IS_NOT_COMPLETE_WORLD_DOMAIN",
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
            raise InformationError("unsupported_topic", "Native province discovery supports C02 only")
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
        reason = _base_reason(context)
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
            raise ValueError("C02_DISCOVERY_PROJECTION_FIELDS")
        item = projected[FIELD]
        expected = {
            "status", "value", "candidate_count", "candidate_id_range",
            "domain_complete", "bitmap_words_native_length_bounded",
        }
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError("C02_DISCOVERY_PROJECTION_SHAPE")
        if item.get("status") != "known":
            raise ValueError("C02_DISCOVERY_PROJECTION_STATUS")
        count = item.get("candidate_count")
        bounds = item.get("candidate_id_range")
        ids = item.get("value")
        if (type(count) is not int or not 1 <= count <= _MAX_CANDIDATE_ID
                or type(bounds) is not list or len(bounds) != 2
                or any(type(bound) is not int for bound in bounds)
                or bounds != [1, count]
                or type(item.get("domain_complete")) is not bool
                or item["domain_complete"] is not False
                or type(item.get("bitmap_words_native_length_bounded")) is not bool
                or item["bitmap_words_native_length_bounded"] is not True
                or not isinstance(ids, list) or len(ids) > count
                or any(type(pid) is not int or not 1 <= pid <= count for pid in ids)
                or len(ids) != len(set(ids)) or ids != sorted(ids)):
            raise ValueError("C02_DISCOVERY_PROJECTION_IDS_OR_BOUNDS")
        return {
            "status": "known",
            "value": list(ids),
            "unit": "province_id",
            "scale": 1,
            "period": "current",
            "complete": False,
            "basis": _BASIS,
            "candidate_count": count,
            "candidate_id_range": list(bounds),
            "domain_complete": False,
            "bitmap_words_native_length_bounded": True,
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
        fields = {name: {"status": "unsupported", "reason": "C02_DISCOVERY_FIELD_NOT_IMPLEMENTED"}
                  for name in query["fields"]}
        provenance = {
            "observer": current.get("observer"),
            "read_only": True,
            "native_function_invoked": False,
            "actual_UI_observed": False,
            "atomic_snapshot": False,
            "scope": "positive_bounded_discovery_candidates_only",
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
        if obj.get("type") == "country" and obj.get("country") != current.get("observer"):
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
            report = capture(installation, observer=before["observer"])
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
            provenance["capture_report_sha256"] = report_sha256
            provenance["profile_sha256"] = profile_sha256
            fields[FIELD] = public_field
        except Exception:
            return failure("C02_CAPTURE_SHAPE_INVALID", before)
        return result(before)

    def poll_events(self, context: dict, cursor: dict | None) -> dict:
        return {"events": [], "cursor": deepcopy(cursor or {}),
                "complete": True, "gaps": []}


__all__ = ["NativeProvinceDiscoverySource"]
