"""Expose partial ruler, heir, dynasty, and personal-union panel projections.

The public adapter accepts only whitelisted DTO fields from a validated
country-person capture. It intentionally drops RPM traces, raw pointers, and
other private collector data. Values describe bounded native presentation
inputs and do not claim a complete UI label or a full succession model.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re
from collections.abc import Mapping
from typing import Any

from ..native_text import decode_native_text_hex
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _context_reason as _base_context_reason,
    _identity,
    _session_binding,
)


_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_NAME_HEX = re.compile(r"[0-9A-Fa-f]{0,1026}\Z")
_REASON = re.compile(r"[A-Z0-9_:-]{1,128}\Z")
_POINTER_LIKE = re.compile(r"0x[0-9a-fA-F]{6,}")
_TOPIC = "S04"
_FIELD_KEYS = ("ruler", "heir", "dynasty", "personal_union")
_BACKEND_FIELDS = {name: f"S04.{name}" for name in _FIELD_KEYS}
_OBSERVER = "FRA"
_VERSION = "1.37.4"
_BASIS = "native_monarch_heir_dynasty_and_personal_union_panel_projection"
_VALUE_ORIGIN = "copied_native_country_person_panel_inputs"
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_NAME_MAX_BYTES = 513
_HIDDEN_HEIR_REASON = "NATIVE_HEIR_CHARACTER_PANEL_HIDDEN"


class NativeCountryPersonSource(NativeTradeIncomeSource):
    """Expose four partial S04 country-person fields."""

    event_types: tuple[str, ...] = ()

    def catalog(self) -> list[dict]:
        fields: dict[str, dict[str, Any]] = {}
        for name in _FIELD_KEYS:
            backend_name = _BACKEND_FIELDS[name]
            fields[name] = {
                "coverage": "partial",
                "complete": False,
                "source": "bridge.information.country_person_capture.capture",
                "unit": "native_panel_inputs",
                "scale": 1,
                "period": "current",
                "basis": _BASIS,
                "value_origin": _VALUE_ORIGIN,
                "paths": [f"observation.backend.targets[0].fields['{backend_name}']"],
                "supported_observers": [_OBSERVER],
                "runtime_validation": "country_person_capture.validate_capture",
                "gaps": [
                    "FULL_UI_LABEL_NOT_COMPLETE",
                    "COUNTRY_PERSON_PANEL_INPUTS_ARE_NOT_COMPLETE_UI_OBSERVATIONS",
                ],
            }
        return [{
            "topic_id": _TOPIC,
            "catalog_ids": [_TOPIC],
            "title": "统治者与继承",
            "status": "available",
            "fields": fields,
            "object_types": ["country"],
            "observer_roles": [],
            "observer_scope": [_OBSERVER],
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            "supported_versions": [_VERSION],
            "triggers": ["query", "periodic"],
            "source": type(self).__name__,
            "context_scope": "visible_scope",
            "visibility": "visible_scope",
            "scope_note": (
                "FRA是逻辑观察方，查询对象为单个国家且可包括FRA；"
                "四字段均为partial。ruler只投影已读人物组件与PERSONAL_UNION_WITH显示分支，"
                "不代表完整标题/摄政/技能提示；heir隐藏分支不代表没有继承人；"
                "personal_union只表示该人物面板显示用的上级统治者支路，"
                "不提供完整联统名单或继承预测。"
            ),
        }]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError(
                "invalid_parameters",
                f"S04 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError(
                "unknown_topic", "NativeCountryPersonSource supports S04 only")
        obj = query.get("object")
        if (
            not isinstance(obj, dict)
            or set(obj) != {"type", "country"}
            or obj.get("type") != "country"
            or not isinstance(obj.get("country"), str)
            or _TAG.fullmatch(obj["country"]) is None
        ):
            raise InformationError(
                "invalid_object", "S04 person fields require one country tag")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or len(fields) > len(_FIELD_KEYS)
            or any(not isinstance(field, str) or field not in _FIELD_KEYS for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError(
                "invalid_fields",
                "S04 supports a nonempty unique subset of ruler, heir, dynasty, personal_union",
            )
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "S04 has no extra parameters")
        if context is not None and (
            not isinstance(context, dict) or context.get("observer") != _OBSERVER
        ):
            raise InformationError(
                "observer_scope_mismatch", "The verified logical observer is FRA")
        return {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": {},
        }

    @staticmethod
    def _context_reason(context: dict) -> str | None:
        reason = _base_context_reason(context, _OBSERVER)
        return reason.replace("TRADE_INCOME_", "COUNTRY_PERSON_", 1) if reason else None

    @staticmethod
    def _safe_reason(value: object, fallback: str) -> str:
        if (isinstance(value, str) and _POINTER_LIKE.search(value) is None):
            bounded = value[:128]
            if _REASON.fullmatch(bounded) is not None:
                return bounded
        return fallback

    @staticmethod
    def _field(status: str, reason: str | None = None, value: dict | None = None) -> dict:
        item = {
            "status": status,
            "period": "current",
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "partial": True,
            "complete": False,
        }
        if reason is not None:
            item["reason"] = reason
        if status == "known" and value is not None:
            item["value"] = value
        return item

    @classmethod
    def _component_result(cls, raw: Any, kind: str, fallback: str) -> dict:
        if not isinstance(raw, Mapping):
            return {"status": "unknown", "reason": fallback}
        status = raw.get("status")
        if status in {"unknown", "invisible", "not_applicable"}:
            return {
                "status": status,
                "reason": cls._safe_reason(raw.get("reason"), fallback),
            }
        if status != "known" or "value" not in raw:
            return {"status": "unknown", "reason": fallback}
        try:
            value = cls._component_value(raw, kind)
        except (KeyError, TypeError, ValueError, OverflowError):
            return {"status": "unknown", "reason": fallback}
        result = {"status": "known", "value": value}
        if kind == "age":
            result["unit"] = "years"
        return result

    @staticmethod
    def _text_object(raw: Any) -> dict:
        if not isinstance(raw, Mapping):
            raise ValueError("name shape")
        text = raw.get("text")
        raw_hex = raw.get("raw_hex")
        encoding = raw.get("encoding")
        if (
            not isinstance(text, str)
            or not isinstance(raw_hex, str)
            or _NAME_HEX.fullmatch(raw_hex) is None
            or len(raw_hex) // 2 > _NAME_MAX_BYTES
            or encoding != "eu4_escape"
        ):
            raise ValueError("name value")
        decoded = decode_native_text_hex(
            raw_hex, codec="eu4_escape", max_bytes=_NAME_MAX_BYTES)
        if decoded != text:
            raise ValueError("name decode mismatch")
        name_bytes = bytes.fromhex(raw_hex)
        if b"\x00" in name_bytes:
            raise ValueError("name embedded nul")
        return {
            "text": decoded,
            "raw_hex": raw_hex.lower(),
            "encoding": "eu4_escape",
        }

    @staticmethod
    def _int32(value: Any) -> bool:
        return type(value) is int and _INT32_MIN <= value <= _INT32_MAX

    @classmethod
    def _component_value(cls, raw: Mapping[str, Any], kind: str) -> Any:
        value = raw["value"]
        if kind == "name":
            return cls._text_object(value)
        if kind == "skills":
            if not isinstance(value, Mapping):
                raise ValueError("skills shape")
            keys = ("administrative", "diplomatic", "military")
            if any(not cls._int32(value.get(key)) for key in keys):
                raise ValueError("skills values")
            return {key: value[key] for key in keys}
        if kind == "age":
            if type(value) is not int or value < 0 or raw.get("unit") != "years":
                raise ValueError("age value")
            return value
        if kind == "claim":
            if not isinstance(value, Mapping):
                raise ValueError("claim shape")
            raw_claim = value.get("raw")
            weak = value.get("weak_threshold_raw")
            strong = value.get("strong_threshold_raw")
            category = value.get("category")
            if (
                not cls._int32(raw_claim)
                or not cls._int32(weak)
                or not cls._int32(strong)
                or type(value.get("scale")) is not int
                or value.get("scale") != 1000
                or category not in {"weak", "average", "strong"}
            ):
                raise ValueError("claim value")
            expected = (
                "weak" if raw_claim < weak
                else "average" if raw_claim < strong
                else "strong"
            )
            if category != expected:
                raise ValueError("claim category mismatch")
            return {
                "raw": raw_claim,
                "scale": 1000,
                "category": category,
                "weak_threshold_raw": weak,
                "strong_threshold_raw": strong,
            }
        if kind == "dynasty_name":
            if not isinstance(value, Mapping) or type(value.get("included_in_name")) is not bool:
                raise ValueError("dynasty name shape")
            included = value["included_in_name"]
            name = value.get("name")
            if included:
                safe_name = cls._text_object(name)
            elif name is None:
                safe_name = None
            else:
                raise ValueError("unexpected dynasty name")
            return {"included_in_name": included, "name": safe_name}
        raise ValueError("unknown component kind")

    @classmethod
    def _component(cls, raw: Any, kind: str, fallback: str) -> dict:
        return cls._component_result(raw, kind, fallback)

    @classmethod
    def _project_ruler(cls, raw_value: Any) -> dict:
        if not isinstance(raw_value, Mapping):
            raise ValueError("ruler value shape")
        mode = raw_value.get("display_mode")
        if mode not in {"person", "personal_union", "unknown"}:
            raise ValueError("ruler display mode")
        if raw_value.get("full_ui_label_complete") is not False:
            raise ValueError("ruler completeness marker")
        return {
            "display_mode": mode,
            "name": cls._component(raw_value.get("name"), "name",
                                   "COUNTRY_PERSON_RULER_NAME_UNKNOWN"),
            "skills": cls._component(raw_value.get("skills"), "skills",
                                     "COUNTRY_PERSON_RULER_SKILLS_UNKNOWN"),
            "age": cls._component(raw_value.get("age"), "age",
                                  "COUNTRY_PERSON_RULER_AGE_UNKNOWN"),
            "full_ui_label_complete": False,
        }

    @classmethod
    def _project_heir(cls, raw_value: Any) -> tuple[str, str | None, dict | None]:
        if not isinstance(raw_value, Mapping):
            raise ValueError("heir value shape")
        mode = raw_value.get("mode")
        present = raw_value.get("present")
        if raw_value.get("full_ui_label_complete") is not False:
            raise ValueError("heir completeness marker")
        if mode == "hidden":
            if present is not None:
                raise ValueError("hidden heir present marker")
            return "not_applicable", _HIDDEN_HEIR_REASON, None
        if mode == "no_heir":
            if present is not False:
                raise ValueError("no-heir present marker")
            components = {
                name: raw_value.get(name)
                for name in ("name", "age", "claim")
            }
            if any(
                not isinstance(component, Mapping)
                or component.get("status") != "not_applicable"
                or "value" in component
                for component in components.values()
            ):
                raise ValueError("no-heir component states")
            value = {
                "mode": "no_heir",
                "present": False,
                "name": cls._component(components["name"], "name",
                                       "COUNTRY_PERSON_HEIR_NAME_NOT_APPLICABLE"),
                "age": cls._component(components["age"], "age",
                                      "COUNTRY_PERSON_HEIR_AGE_NOT_APPLICABLE"),
                "claim": cls._component(components["claim"], "claim",
                                        "COUNTRY_PERSON_HEIR_CLAIM_NOT_APPLICABLE"),
                "full_ui_label_complete": False,
            }
            return "known", None, value
        if mode == "character":
            if present is not True:
                raise ValueError("character heir present marker")
        elif mode == "unknown":
            if present is not None:
                raise ValueError("unknown heir present marker")
        else:
            raise ValueError("heir mode")
        value = {
            "mode": mode,
            "present": present,
            "name": cls._component(raw_value.get("name"), "name",
                                   "COUNTRY_PERSON_HEIR_NAME_UNKNOWN"),
            "age": cls._component(raw_value.get("age"), "age",
                                  "COUNTRY_PERSON_HEIR_AGE_UNKNOWN"),
            "claim": cls._component(raw_value.get("claim"), "claim",
                                    "COUNTRY_PERSON_HEIR_CLAIM_UNKNOWN"),
            "full_ui_label_complete": False,
        }
        return "known", None, value

    @classmethod
    def _project_dynasty(cls, raw_value: Any) -> dict:
        if not isinstance(raw_value, Mapping):
            raise ValueError("dynasty value shape")
        return {
            "ruler": cls._component(raw_value.get("ruler"), "dynasty_name",
                                    "COUNTRY_PERSON_RULER_DYNASTY_UNKNOWN"),
            "heir": cls._component(raw_value.get("heir"), "dynasty_name",
                                   "COUNTRY_PERSON_HEIR_DYNASTY_UNKNOWN"),
        }

    @classmethod
    def _project_personal_union(cls, raw_value: Any) -> dict:
        if not isinstance(raw_value, Mapping):
            raise ValueError("personal union value shape")
        uses_senior = raw_value.get("uses_senior_ruler")
        senior_country = raw_value.get("senior_country")
        if type(uses_senior) is not bool:
            raise ValueError("personal union bool")
        if uses_senior:
            if not isinstance(senior_country, str) or _TAG.fullmatch(senior_country) is None:
                raise ValueError("personal union senior country")
        elif senior_country is not None:
            raise ValueError("unexpected senior country")
        return {
            "uses_senior_ruler": uses_senior,
            "senior_country": senior_country,
        }

    @classmethod
    def _project_known_field(cls, field_name: str, private_field: Mapping[str, Any]) -> dict:
        raw_value = private_field.get("value")
        if field_name == "ruler":
            value = cls._project_ruler(raw_value)
            return cls._field("known", value=value)
        if field_name == "heir":
            status, reason, value = cls._project_heir(raw_value)
            if status == "not_applicable":
                return cls._field("not_applicable", reason)
            return cls._field("known", value=value)
        if field_name == "dynasty":
            value = cls._project_dynasty(raw_value)
            return cls._field("known", value=value)
        if field_name == "personal_union":
            value = cls._project_personal_union(raw_value)
            return cls._field("known", value=value)
        return cls._field("unknown", "COUNTRY_PERSON_FIELD_UNSUPPORTED")

    @classmethod
    def _project_private_field(cls, field_name: str, private_field: Any) -> dict:
        fallback = f"COUNTRY_PERSON_{field_name.upper()}_UNKNOWN"
        if not isinstance(private_field, Mapping):
            return cls._field("unknown", fallback)
        status = private_field.get("status")
        if status == "unknown":
            return cls._field(
                "unknown", cls._safe_reason(private_field.get("reason"), fallback))
        if status == "invisible":
            return cls._field(
                "invisible",
                cls._safe_reason(
                    private_field.get("reason"),
                    "COUNTRY_PERSON_NOT_ADMITTED_FOR_OBSERVER",
                ),
            )
        if status != "known":
            return cls._field("unknown", fallback)
        try:
            return cls._project_known_field(field_name, private_field)
        except (KeyError, TypeError, ValueError, OverflowError):
            return cls._field("unknown", "COUNTRY_PERSON_FIELD_INVALID")

    def read(self, query: dict, context: dict | None = None) -> dict:
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        target = normalized["object"]["country"]
        requested = normalized["fields"]
        provenance = {
            "read_only": True,
            "native_function_invoked": False,
            "observer": _OBSERVER,
            "target": target,
            "basis": _BASIS,
            "actual_UI_observed": False,
            "full_ui_label_complete": False,
        }

        def result(fields: dict, result_context: dict = current) -> dict:
            source = _source_info(
                type(self).__name__, result_context, complete=False,
                provenance=deepcopy(provenance),
            )
            source["context_scope"] = "visible_scope"
            source["projection_version"] = 1
            return _result(normalized, result_context, fields, False, source)

        def failure(reason: str, *, unavailable: bool = False,
                    result_context: dict = current) -> dict:
            status = "unavailable" if unavailable else "unknown"
            fields = {
                name: self._field(status, reason)
                for name in requested
            }
            return result(fields, result_context)

        reason = self._context_reason(current)
        if reason is not None:
            return failure(reason, unavailable=True)
        try:
            before = self.context()
        except Exception:
            return failure("COUNTRY_PERSON_CONTEXT_UNAVAILABLE", unavailable=True)
        before_reason = self._context_reason(before)
        if before_reason is not None:
            return failure(before_reason, unavailable=True, result_context=before)
        if _identity(current) != _identity(before):
            return failure(
                "COUNTRY_PERSON_CONTEXT_STALE", unavailable=True, result_context=before)

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            return failure(
                binding_reason or "COUNTRY_PERSON_INSTALLATION_UNAVAILABLE",
                unavailable=True,
                result_context=before,
            )
        try:
            module = import_module(".country_person_capture", __package__)
        except Exception:
            return failure(
                "COUNTRY_PERSON_CAPTURE_UNAVAILABLE", unavailable=True,
                result_context=before,
            )
        capture = self.capture if self.capture is not None else getattr(module, "capture", None)
        if not callable(capture):
            return failure(
                "COUNTRY_PERSON_CAPTURE_UNAVAILABLE", unavailable=True,
                result_context=before,
            )

        report = None
        capture_error: str | None = None
        try:
            report = capture(installation, country=target, observer=_OBSERVER)
        except Exception as exc:
            capture_error = "COUNTRY_PERSON_CAPTURE_FAILED:" + type(exc).__name__

        # Revalidate the complete session binding after every capture attempt,
        # including failures, before inspecting a private DTO.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._context_reason(after)
        if after_reason is not None or _identity(before) != _identity(after):
            return failure(
                "COUNTRY_PERSON_CONTEXT_CHANGED_DURING_CAPTURE",
                unavailable=True,
                result_context=before,
            )
        installation_after, creation_after, after_binding_reason = _session_binding(
            self.base_source)
        if (
            after_binding_reason is not None
            or installation_after != installation
            or creation_after != creation_filetime
        ):
            return failure(
                "COUNTRY_PERSON_SESSION_CHANGED_DURING_CAPTURE",
                unavailable=True,
                result_context=before,
            )
        if capture_error is not None:
            return failure(capture_error, result_context=before)

        try:
            valid = module.validate_capture(report, before, creation_filetime, target)
        except Exception:
            valid = False
        if valid is not True:
            return failure("COUNTRY_PERSON_CAPTURE_INVALID", result_context=before)

        try:
            provenance["capture_report_sha256"] = hashlib.sha256(
                canonical(report).encode("utf-8")
            ).hexdigest()
            observation = report["observation"]
            backend = observation["backend"]
            observer = backend["observer"]
            if not isinstance(observer, Mapping) or observer.get("tag") != _OBSERVER:
                raise ValueError("observer identity")
            targets = backend["targets"]
            if (
                not isinstance(targets, list)
                or len(targets) != 1
                or not isinstance(targets[0], Mapping)
                or targets[0].get("tag") != target
            ):
                raise ValueError("target identity")
            item = targets[0]
            admission = item["admission_by_pass"]["pass2"]
            if (
                not isinstance(admission, Mapping)
                or admission.get("status") != "known"
                or type(admission.get("admitted")) is not bool
            ):
                gate_reason = self._safe_reason(
                    admission.get("reason") if isinstance(admission, Mapping) else None,
                    "COUNTRY_PERSON_VIEW_ADMISSION_UNKNOWN",
                )
                return result({
                    name: self._field("unknown", gate_reason)
                    for name in requested
                }, before)
            if admission["admitted"] is False:
                return result({
                    name: self._field(
                        "invisible", "COUNTRY_PERSON_NOT_ADMITTED_FOR_OBSERVER")
                    for name in requested
                }, before)

            private_fields = item["fields"]
            if not isinstance(private_fields, Mapping):
                raise ValueError("target fields")
            public_fields: dict[str, dict] = {}
            for name in requested:
                public_fields[name] = self._project_private_field(
                    name, private_fields.get(_BACKEND_FIELDS[name]))
            return result(public_fields, before)
        except (KeyError, TypeError, ValueError, IndexError):
            return failure("COUNTRY_PERSON_CAPTURE_SHAPE_INVALID", result_context=before)


__all__ = ["NativeCountryPersonSource"]
