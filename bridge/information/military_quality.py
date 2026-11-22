"""Read the verified native country military-technology cache.

The country-resources capture owns process identity, RPM lifetime and the
two-pass parent observation.  This adapter requests only the military-quality
child, validates each requested child against its real pinned validator, and
exposes the closed N03 scalars.  The remaining N03 fields stay with the planned
Composite routes.
"""
from __future__ import annotations

from copy import deepcopy
import importlib
from typing import Any, Mapping

from .country_state import NativeCountryStateSource, _is_country
from .model import InformationError, canonical
from .sources import _copy, _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _CONTEXT_KEYS,
    _GAME_SHA256,
    _VERSION,
    _identity,
    _observer_context_reason,
    _session_binding,
)


_TOPIC = "N03"
_FIELD = "military_technology"
_TRADITION_FIELD = "army_tradition"
_BASIS = "native_country_technology_level_cache"
_VALUE_ORIGIN = "copied_native_country_technology_cache"
_TRADITION_BASIS = "native_country_army_tradition_cache"
_TRADITION_ORIGIN = "copied_native_country_army_tradition_cache"
_UNIT = "technology_level"
_TRADITION_UNIT = "army_tradition"
_SCALE = 1
_TRADITION_SCALE = 1000
_PERIOD = "current"

_FIELD_SPECS = {
    "professionalism": {
        "record_key": "military_professionalism",
        "module": "military_professionalism_memory",
        "basis": "native_country_army_professionalism_cache",
        "value_origin": "copied_native_country_army_professionalism_cache",
        "unit": "ratio",
        "scale": 32768,
    },
    "morale": {
        "record_key": "military_morale",
        "module": "military_morale_memory",
        "basis": "native_country_morale_caches",
        "value_origin": "copied_native_country_morale_cache",
        "unit": "morale",
        "scale": 1000,
    },
    "discipline": {
        "record_key": "military_effective",
        "module": "military_effective_memory",
        "basis": "native_country_discipline_calculation",
        "value_origin": "derived_from_copied_native_inputs",
        "unit": "ratio",
        "scale": 1000,
        "complete": False,
    },
    _FIELD: {
        "record_key": "military_quality",
        "module": "military_quality_memory",
        "basis": _BASIS,
        "value_origin": _VALUE_ORIGIN,
        "unit": _UNIT,
        "scale": _SCALE,
    },
    _TRADITION_FIELD: {
        "record_key": "military_tradition",
        "module": "military_tradition_memory",
        "basis": _TRADITION_BASIS,
        "value_origin": _TRADITION_ORIGIN,
        "unit": _TRADITION_UNIT,
        "scale": _TRADITION_SCALE,
    },
}
_FIELDS = tuple(_FIELD_SPECS)


def _catalog_field(field: str, spec: Mapping[str, Any], *, raw_semantics: str,
                   gaps: list[str]) -> dict[str, Any]:
    return {
        "coverage": "available" if spec.get("complete", True) else "partial",
        "runtime_validation": "validated_native_cache",
        "source": "bridge.information.country_resources_memory.capture",
        "unit": spec["unit"],
        "scale": spec["scale"],
        "raw": True,
        "raw_semantics": raw_semantics,
        "paths": [f"{spec['record_key']}.fields.{field}.value"],
        "period": _PERIOD,
        "basis": spec["basis"],
        "value_origin": spec["value_origin"],
        "complete": spec.get("complete", True),
        "gaps": gaps,
    }


_CATALOG_ITEM = {
    "topic_id": _TOPIC,
    "catalog_ids": [_TOPIC],
    "title": "本国军事质量",
    "status": "available",
    "fields": {
        "professionalism": _catalog_field(
            "professionalism", _FIELD_SPECS["professionalism"],
            raw_semantics=(
                "signed int64 current country army-professionalism cache; raw_hex preserves "
                "the eight copied bytes and raw/32768 is the ratio before percentage display"
            ),
            gaps=["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
                  "FOREIGN_COUNTRY_VISIBILITY_NOT_SUPPORTED"],
        ),
        "morale": _catalog_field(
            "morale", _FIELD_SPECS["morale"],
            raw_semantics=(
                "army and navy signed int32 current country morale caches; value/raw "
                "map army and navy to copied integers and raw_hex preserves both byte sequences"
            ),
            gaps=["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
                  "FOREIGN_COUNTRY_VISIBILITY_NOT_SUPPORTED"],
        ),
        "discipline": _catalog_field(
            "discipline", _FIELD_SPECS["discipline"],
            raw_semantics=(
                "signed int32 result computed with the native discipline base, keyed modifiers, "
                "recognized processor, wrapping arithmetic and minimum; raw_hex encodes the "
                "computed result and copied inputs remain in provenance"
            ),
            gaps=["PROCESSOR_THREAD_CONTEXT_NOT_CAPTURED", "CACHE_CALCULATING_UNSUPPORTED",
                  "MAIN_THREAD_ATOMICITY_NOT_PROVEN", "FOREIGN_COUNTRY_VISIBILITY_NOT_SUPPORTED"],
        ),
        _FIELD: _catalog_field(
            _FIELD, _FIELD_SPECS[_FIELD],
            raw_semantics=(
                "mil_tech definition index selects one signed native country "
                "technology-vector int32; raw_hex preserves the copied bytes"
            ),
            gaps=[
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
                "FOREIGN_COUNTRY_VISIBILITY_NOT_SUPPORTED",
                "MILITARY_COSTS_AND_MODIFIERS_NOT_CLOSED",
            ],
        ),
        _TRADITION_FIELD: _catalog_field(
            _TRADITION_FIELD, _FIELD_SPECS[_TRADITION_FIELD],
            raw_semantics=(
                "native country army-tradition cache int32; raw_hex preserves "
                "the copied bytes and scale is 1000"
            ),
            gaps=[
                "NATIVE_CACHE_FRESHNESS_NOT_PROVEN",
                "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
                "FOREIGN_COUNTRY_VISIBILITY_NOT_SUPPORTED",
                "TRADITION_GAIN_AND_COSTS_NOT_CLOSED",
            ],
        ),
    },
    "object_types": ["country"],
    "observer_roles": ["country"],
    "observer_scope": [],
    "parameters": {
        "type": "object", "properties": {}, "required": [],
        "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "triggers": ["query", "periodic"],
    "runtime_validation": "validated",
    "source": "NativeMilitaryQualitySource",
    "visibility": "country_scope",
    "context_scope": "country_scope",
    "scope_note": (
        "读取 1.37.4 观察国的军事科技等级、陆军传统、陆海军士气、陆军职业度和纪律。"
        "纪律在修正缓存正常且已识别处理器的结果不依赖未知线程标志时可读；"
        "其余线程路径、主线程原子性、外国国家可见性及其他军事修正继续开发。"
    ),
}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _context_reason(context: Any) -> str | None:
    reason = _observer_context_reason(context)
    return reason.replace("TRADE_INCOME_", "MILITARY_QUALITY_", 1) if reason else None


def _pointer_value(value: Any) -> int | None:
    """Decode a parent VA object without treating an RVA as a runtime VA."""

    if isinstance(value, Mapping):
        value = value.get("va")
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _pointer_hex(value: Any) -> str | None:
    address = _pointer_value(value)
    return hex(address) if address is not None else None


def _field_spec(field: str) -> Mapping[str, Any]:
    return _FIELD_SPECS[field]


def _military_module(field: str):
    try:
        return importlib.import_module("." + str(_field_spec(field)["module"]), __package__)
    except Exception:
        return None


def _compact_child(record: Any, field: str) -> dict[str, Any]:
    """Keep raw value and lookup provenance without duplicating RPM logs."""

    if not isinstance(record, Mapping):
        return {"status": None}
    result: dict[str, Any] = {
        "status": record.get("status"),
        "reason": record.get("reason"),
        "profile_sha256": record.get("profile_sha256"),
        "module_base": record.get("module_base"),
        "country_pointer": record.get("country_pointer"),
        "basis": record.get("basis"),
        "unit": record.get("unit"),
        "scale": record.get("scale"),
        "period": record.get("period"),
        "value_origin": record.get("value_origin"),
        "values": deepcopy(record.get("values")),
        "raw_hex": deepcopy(record.get("raw_hex")),
        "observation": deepcopy(record.get("observation")),
    }
    item = record.get("fields", {}).get(field) if isinstance(record.get("fields"), Mapping) else None
    if isinstance(item, Mapping):
        result["field"] = deepcopy(item)
    return result


def _snapshot_country_pointer(snapshot: Any) -> str | None:
    if not isinstance(snapshot, Mapping):
        return None
    scan = snapshot.get("country_scan")
    if not isinstance(scan, Mapping) or scan.get("status") != "observed":
        return None
    return _pointer_hex(scan.get("country_pointer"))


def _parent_reason(report: Any, context: Mapping[str, Any], creation: int) -> str | None:
    """Validate the existing monarch-points parent without trade flags."""

    country = context.get('observer')
    reason = NativeCountryStateSource._capture_report_reason(
        report, dict(context), country, creation
    )
    if reason is not None:
        return reason.replace("MONARCH_POINTS_", "MILITARY_QUALITY_PARENT_", 1)
    if not isinstance(report, Mapping):
        return "MILITARY_QUALITY_PARENT_CAPTURE_INVALID"
    target = report.get("target_build")
    if (
        not isinstance(target, Mapping)
        or target.get("version") != _VERSION
        or str(target.get("expected_exe_sha256", "")).lower() != _GAME_SHA256
    ):
        return "MILITARY_QUALITY_TARGET_BUILD_INVALID"
    request = report.get("request")
    if (
        not isinstance(request, Mapping)
        or request.get("country") != country
        or request.get("include_military_quality") is not True
    ):
        return "MILITARY_QUALITY_PARENT_REQUEST_INVALID"
    return None


def _child_reason(report: Any, field: str) -> str | None:
    """Validate one requested child across all three parent snapshots."""

    if not isinstance(report, Mapping):
        return "MILITARY_QUALITY_PARENT_CAPTURE_INVALID"
    module = _military_module(field)
    validator = getattr(module, "validate_record", None) if module else None
    if not callable(validator):
        return f"MILITARY_QUALITY_{field.upper()}_VALIDATOR_UNAVAILABLE"
    expected_module = _pointer_hex(report.get("module_base"))
    before_snapshot = report.get("before")
    after_snapshot = report.get("after")
    expected_pointers = (
        _snapshot_country_pointer(before_snapshot),
        _snapshot_country_pointer(after_snapshot),
    )
    if expected_module is None or any(pointer is None for pointer in expected_pointers):
        return "MILITARY_QUALITY_PARENT_COUNTRY_BINDING_INVALID"
    record_key = _field_spec(field)["record_key"]
    top = report.get(record_key)
    before = before_snapshot.get(record_key) if isinstance(before_snapshot, Mapping) else None
    after = after_snapshot.get(record_key) if isinstance(after_snapshot, Mapping) else None
    children = (top, before, after)
    child_pointers = (expected_pointers[0], expected_pointers[0], expected_pointers[1])
    for label, child, expected_pointer in zip(("TOP", "BEFORE", "AFTER"), children, child_pointers):
        if not isinstance(child, Mapping):
            return f"MILITARY_QUALITY_{field.upper()}_{label}_RECORD_MISSING"
        try:
            valid = validator(child)
        except Exception as exc:
            return f"MILITARY_QUALITY_{field.upper()}_{label}_VALIDATION_FAILED:{type(exc).__name__}"
        if valid is not True:
            item = child.get("fields", {}).get(field) if isinstance(child.get("fields"), Mapping) else None
            if (isinstance(item, Mapping) and item.get("status") == "unknown"
                    and isinstance(item.get("reason"), str) and item["reason"]):
                return item["reason"]
            return f"MILITARY_QUALITY_{field.upper()}_{label}_RECORD_INVALID"
        if child.get("module_base") != expected_module:
            return f"MILITARY_QUALITY_{field.upper()}_{label}_MODULE_BINDING_INVALID"
        if child.get("country_pointer") != expected_pointer:
            return f"MILITARY_QUALITY_{field.upper()}_{label}_COUNTRY_BINDING_INVALID"
        item = child.get("fields", {}).get(field) if isinstance(child.get("fields"), Mapping) else None
        if (not isinstance(item, Mapping) or item.get("status") != "known"
                or item.get("complete") is not _field_spec(field).get("complete", True)):
            return f"MILITARY_QUALITY_{field.upper()}_{label}_FIELD_INCOMPLETE"
    try:
        if canonical(top) != canonical(before) or canonical(top) != canonical(after):
            return f"MILITARY_QUALITY_{field.upper()}_SNAPSHOT_MISMATCH"
    except Exception:
        return f"MILITARY_QUALITY_{field.upper()}_RECORD_CANONICAL_INVALID"
    return None


class NativeMilitaryQualitySource(NativeTradeIncomeSource):
    """Expose verified native military-quality scalars for the observer country."""

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
                f"N03 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeMilitaryQualitySource supports N03 only")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"} or obj.get("type") != "country":
            raise InformationError("invalid_object", "N03 queries require a country object")
        country = obj.get("country")
        if not _is_country(country):
            raise InformationError("invalid_object", "N03 requires a country tag")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError("invalid_fields", "N03 fields must be a non-empty list of unique strings")
        unknown = set(fields) - set(_FIELDS)
        if unknown:
            raise InformationError("unknown_field", f"N03 fields are outside the native adapter: {sorted(unknown)}")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "N03 parameters must be an empty object")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            if context.get("observer") is not None and context.get("observer") != country:
                raise InformationError("observer_scope_mismatch", "N03 is limited to the configured observer country")
        normalized = {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": {},
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _failure_fields(fields: list[str], reason: str, *, unavailable: bool) -> dict[str, dict[str, Any]]:
        factory = _unavailable if unavailable else _unknown
        return {field: factory(reason) for field in fields}

    @staticmethod
    def _result(
        normalized: dict[str, Any],
        context: dict[str, Any],
        fields: dict[str, dict[str, Any]],
        complete: bool,
        provenance: dict[str, Any],
    ) -> dict[str, Any]:
        source = _source_info(
            "NativeMilitaryQualitySource", context,
            complete=complete, provenance=provenance,
        )
        source["context_scope"] = "country_scope"
        if fields and all(
            isinstance(item, dict) and item.get("status") == "unavailable"
            for item in fields.values()
        ):
            source["status"] = "unavailable"
        return _result(normalized, context, fields, complete, source)

    def _capture_reader(self):
        if self.capture is not None:
            return self.capture
        try:
            from .country_resources_memory import capture
        except Exception:
            return None
        return capture

    def read(self, query: dict, context: dict | None = None) -> dict:
        supplied = _copy(context) if isinstance(context, dict) else None
        context_supplied = supplied is not None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        requested = normalized["fields"]

        def shared_spec(name: str):
            values = {_field_spec(field)[name] for field in requested}
            return next(iter(values)) if len(values) == 1 else "mixed"

        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": normalized['object']['country'],
            "read_only": True,
            "native_function_invoked": False,
            "unit": shared_spec("unit"),
            "scale": shared_spec("scale"),
            "period": _PERIOD,
            "basis": shared_spec("basis"),
            "value_origin": shared_spec("value_origin"),
            "context_guard": {
                "mode": "live",
                "game_version": _VERSION,
                "game_sha256": _GAME_SHA256,
                "identity_keys": list(_CONTEXT_KEYS),
            },
        }

        def result(ctx: dict[str, Any], fields: dict[str, dict[str, Any]], complete: bool = False) -> dict[str, Any]:
            return self._result(normalized, ctx, fields, complete, provenance)

        reason = _context_reason(current)
        if reason is not None:
            provenance["context_guard"]["status"] = "unavailable"
            return result(current, self._failure_fields(requested, reason, unavailable=True))

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            before_reason = _context_reason(before)
            if before_reason is not None:
                provenance["context_guard"]["status"] = "unavailable"
                return result(before, self._failure_fields(requested, before_reason, unavailable=True))
            if _identity(current) != _identity(before):
                provenance["context_guard"]["status"] = "stale"
                return result(current, self._failure_fields(requested, "MILITARY_QUALITY_CONTEXT_STALE", unavailable=True))

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            reason = (binding_reason or "MILITARY_QUALITY_INSTALLATION_UNAVAILABLE").replace(
                "TRADE_INCOME_", "MILITARY_QUALITY_", 1
            )
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, reason, unavailable=True))

        capture = self._capture_reader()
        if not callable(capture):
            provenance["context_guard"]["status"] = "unavailable"
            return result(before, self._failure_fields(requested, "MILITARY_QUALITY_CAPTURE_UNAVAILABLE", unavailable=True))

        report: Any = None
        capture_error: str | None = None
        try:
            # This source owns only the military child.  In particular, it does
            # not add include_trade_income to the request as a parent shortcut.
            report = capture(
                installation,
                normalized['object']['country'],
                include_military_quality=True,
            )
        except Exception as exc:
            capture_error = "MILITARY_QUALITY_CAPTURE_FAILED:" + type(exc).__name__

        # Context is checked after every attempted capture, including reader
        # exceptions, before any parent or child value can become known.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = _context_reason(after)
        if after_reason is not None or _identity(before) != _identity(after):
            provenance["context_guard"]["status"] = "changed"
            provenance["capture_reason"] = after_reason or "MILITARY_QUALITY_CONTEXT_CHANGED_DURING_CAPTURE"
            if isinstance(report, Mapping):
                provenance["capture_report_sha256"] = NativeCountryStateSource._capture_report_sha256(report)
                for field in requested:
                    provenance[_field_spec(field)["record_key"]] = _compact_child(
                        report.get(_field_spec(field)["record_key"]), field
                    )
            return result(before, self._failure_fields(requested, provenance["capture_reason"], unavailable=False))

        if isinstance(report, Mapping):
            provenance["capture_report_sha256"] = NativeCountryStateSource._capture_report_sha256(report)
            provenance["capture_report_hash_algorithm"] = "sha256(canonical_json_utf8;information.model.canonical)"
            for field in requested:
                provenance[_field_spec(field)["record_key"]] = _compact_child(
                    report.get(_field_spec(field)["record_key"]), field
                )

        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            provenance["capture_reason"] = capture_error
            return result(before, self._failure_fields(requested, capture_error, unavailable=False))

        reason = _parent_reason(report, before, creation_filetime)
        if reason is not None:
            provenance["context_guard"]["status"] = "capture_invalid"
            provenance["capture_reason"] = reason
            return result(before, self._failure_fields(requested, reason, unavailable=False))
        provenance["context_guard"]["status"] = "passed"
        fields: dict[str, dict[str, Any]] = {}
        reasons: dict[str, str] = {}
        for field in requested:
            reason = _child_reason(report, field)
            if reason is not None:
                reasons[field] = reason
                fields[field] = _unknown(reason)
                continue
            child = report[_field_spec(field)["record_key"]]
            fields[field] = deepcopy(child["fields"][field])
        if reasons:
            provenance["capture_reason"] = reasons
        complete = all(item.get("status") == "known" and item.get("complete") is True for item in fields.values())
        return result(before, fields, complete=complete)

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeMilitaryQualitySource"]
