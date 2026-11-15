"""Expose the current primary-faith display name and icon request for S02.

This adapter projects a validated capture into a deliberately small public
DTO.  It keeps the logical FRA observer separate from the physical player,
and it does not treat an icon frame request as proof of a rendered widget.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re

from ..native_text import decode_native_text_hex
from .model import InformationError, canonical
from .religion_binding import binding_digests
from .sources import _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _context_reason as _base_context_reason,
    _identity,
    _session_binding,
)


_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_NAME_HEX = re.compile(r"[0-9A-Fa-f]{2,256}\Z")
_REASON = re.compile(r"[A-Z0-9_:-]{1,128}\Z")
_POINTER_LIKE = re.compile(r"0x[0-9a-fA-F]{6,}")
_TOPIC = "S02"
_FIELD = "faith"
_BACKEND_FIELD = "S02.faith"
_OBSERVER = "FRA"
_VERSION = "1.37.4"
_BASIS = "native_primary_faith_and_country_view_projection"
_VALUE_ORIGIN = "copied_native_primary_faith_name_and_icon_request"
_U32_MAX = (1 << 32) - 1


class NativeCountryFaithSource(NativeTradeIncomeSource):
    """Expose one bounded S02 faith field for a bound country object."""

    event_types: tuple[str, ...] = ()

    def catalog(self) -> list[dict]:
        field = {
            "coverage": "partial",
            "complete": False,
            "source": "bridge.information.country_faith_capture.capture",
            "unit": "native_display_name_and_icon_frame_request",
            "scale": 1,
            "period": "current",
            "basis": _BASIS,
            "value_origin": _VALUE_ORIGIN,
            "raw_semantics": (
                "the target's current primary-faith display-name cache decoded from its "
                "EU4 escape bytes plus the native icon-frame request; this does not identify "
                "a native religion key, and the request is not a rendered-frame observation"
            ),
            "paths": [
                "observation.backend.targets[0].fields['S02.faith'].value.primary_religion_name.text",
                "observation.backend.targets[0].fields['S02.faith'].value.primary_religion_name.raw_hex",
                "observation.backend.targets[0].fields['S02.faith'].value.primary_religion_name.encoding",
                "observation.backend.targets[0].fields['S02.faith'].value.icon_frame_request",
            ],
            "supported_observers": [_OBSERVER],
            "runtime_validation": "country_faith_capture.validate_capture",
            "gaps": [
                "COUNTRY_VIEW_PROJECTION_NOT_ACTUAL_UI_OBSERVATION",
                "NATIVE_RELIGION_IDENTITY_NOT_RESOLVED",
                "FULL_PRIMARY_FAITH_TOOLTIP_NOT_IMPLEMENTED",
                "MAIN_THREAD_ATOMICITY_NOT_PROVEN",
            ],
        }
        return [{
            "topic_id": _TOPIC,
            "catalog_ids": [_TOPIC],
            "title": "宗教与教廷机制",
            "status": "available",
            "fields": {_FIELD: field},
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
                "FRA是逻辑观察方，country对象可为FRA或其他国家；"
                "只公开当前primary faith显示名称缓存、原始EU4 escape字节和图标帧请求，"
                "不把显示名称当作原生宗教键或ID。物理玩家身份不作替换，"
                "国家视角准入是投影而非实际UI观察；图标帧请求不代表实际显示，"
                "完整primary-faith tooltip仍未实现。"
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
                f"S02 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeCountryFaithSource supports S02 only")
        obj = query.get("object")
        if (
            not isinstance(obj, dict)
            or set(obj) != {"type", "country"}
            or obj.get("type") != "country"
            or not isinstance(obj.get("country"), str)
            or _TAG.fullmatch(obj["country"]) is None
        ):
            raise InformationError(
                "invalid_object", "S02.faith requires one three-character country tag"
            )
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or fields != [_FIELD]
        ):
            raise InformationError("invalid_fields", "S02.faith is the only supported faith field")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "S02.faith has no extra parameters")
        if context is not None and (
            not isinstance(context, dict) or context.get("observer") != _OBSERVER
        ):
            raise InformationError("observer_scope_mismatch", "The verified logical observer is FRA")
        return {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": [_FIELD],
            "parameters": {},
        }

    @staticmethod
    def _context_reason(context: dict) -> str | None:
        reason = _base_context_reason(context, _OBSERVER)
        return reason.replace("TRADE_INCOME_", "COUNTRY_FAITH_", 1) if reason else None

    @staticmethod
    def _safe_reason(value: object, fallback: str) -> str:
        if isinstance(value, str) and _POINTER_LIKE.search(value) is None:
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

    def read(self, query: dict, context: dict | None = None) -> dict:
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        target = normalized["object"]["country"]
        provenance = {
            "read_only": True,
            "native_function_invoked": False,
            "observer": _OBSERVER,
            "target": target,
            "basis": _BASIS,
            "actual_UI_observed": False,
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
            item = self._field(status, reason)
            return result({_FIELD: item}, result_context)

        reason = self._context_reason(current)
        if reason is not None:
            return failure(reason, unavailable=True)

        try:
            before = self.context()
        except Exception:
            return failure("COUNTRY_FAITH_CONTEXT_UNAVAILABLE", unavailable=True)
        before_reason = self._context_reason(before)
        if before_reason is not None:
            return failure(before_reason, unavailable=True, result_context=before)
        if _identity(current) != _identity(before):
            return failure("COUNTRY_FAITH_CONTEXT_STALE", unavailable=True, result_context=before)

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            return failure(
                binding_reason or "COUNTRY_FAITH_INSTALLATION_UNAVAILABLE",
                unavailable=True, result_context=before,
            )

        try:
            module = import_module(".country_faith_capture", __package__)
        except Exception:
            return failure("COUNTRY_FAITH_CAPTURE_UNAVAILABLE", unavailable=True,
                           result_context=before)
        capture = self.capture if self.capture is not None else getattr(module, "capture", None)
        if not callable(capture):
            return failure("COUNTRY_FAITH_CAPTURE_UNAVAILABLE", unavailable=True,
                           result_context=before)

        report = None
        capture_error: str | None = None
        try:
            report = capture(installation, country=target, observer=_OBSERVER)
        except Exception as exc:
            capture_error = "COUNTRY_FAITH_CAPTURE_FAILED:" + type(exc).__name__

        # Revalidate both the game/session context and the bound installation
        # after every attempted capture, including a thrown capture error.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._context_reason(after)
        if after_reason is not None or _identity(before) != _identity(after):
            return failure(
                "COUNTRY_FAITH_CONTEXT_CHANGED_DURING_CAPTURE",
                unavailable=True, result_context=before,
            )
        installation_after, creation_after, binding_after_reason = _session_binding(self.base_source)
        if (
            binding_after_reason is not None
            or installation_after != installation
            or creation_after != creation_filetime
        ):
            return failure(
                "COUNTRY_FAITH_SESSION_CHANGED_DURING_CAPTURE",
                unavailable=True, result_context=before,
            )
        if capture_error is not None:
            return failure(capture_error, result_context=before)

        try:
            valid = module.validate_capture(report, before, creation_filetime, target)
        except Exception:
            valid = False
        if valid is not True:
            return failure("COUNTRY_FAITH_CAPTURE_INVALID", result_context=before)

        try:
            provenance["capture_report_sha256"] = hashlib.sha256(
                canonical(report).encode("utf-8")
            ).hexdigest()
            backend = report["observation"]["backend"]
            targets = backend["targets"]
            if not isinstance(targets, list) or not targets:
                raise ValueError("target list")
            item = targets[0]
            if not isinstance(item, dict) or item.get("tag") != target:
                raise ValueError("target mismatch")

            admission = item["admission_by_pass"]["pass2"]
            if (
                not isinstance(admission, dict)
                or admission.get("status") != "known"
                or type(admission.get("admitted")) is not bool
            ):
                gate_reason = self._safe_reason(
                    admission.get("reason") if isinstance(admission, dict) else None,
                    "COUNTRY_FAITH_VIEW_ADMISSION_UNKNOWN",
                )
                return result({
                    _FIELD: self._field("unknown", gate_reason),
                }, before)
            if admission["admitted"] is False:
                return result({
                    _FIELD: self._field(
                        "invisible", "COUNTRY_FAITH_NOT_ADMITTED_FOR_OBSERVER"
                    ),
                }, before)

            fields = item["fields"]
            field = fields[_BACKEND_FIELD]
            if not isinstance(field, dict):
                raise ValueError("faith field")
            status = field.get("status")
            if status == "invisible":
                reason = self._safe_reason(
                    field.get("reason"), "COUNTRY_FAITH_NOT_ADMITTED_FOR_OBSERVER"
                )
                return result({_FIELD: self._field("invisible", reason)}, before)
            if status == "unknown":
                reason = self._safe_reason(field.get("reason"), "COUNTRY_FAITH_BACKEND_UNKNOWN")
                return result({_FIELD: self._field("unknown", reason)}, before)
            if status != "known":
                raise ValueError("faith status")

            value = field["value"]
            name = value["primary_religion_name"]
            icon_frame_request = value["icon_frame_request"]
            if not isinstance(name, dict):
                raise ValueError("faith display name")
            text = name["text"]
            raw_hex = name["raw_hex"]
            encoding = name["encoding"]
            if (
                not isinstance(text, str)
                or not text
                or not isinstance(raw_hex, str)
                or _NAME_HEX.fullmatch(raw_hex) is None
                or encoding != "eu4_escape"
                or type(icon_frame_request) is not int
                or not 0 <= icon_frame_request <= _U32_MAX
            ):
                raise ValueError("faith DTO")
            raw = bytes.fromhex(raw_hex)
            if not raw or b"\x00" in raw:
                raise ValueError("faith display-name bytes")
            decoded = decode_native_text_hex(raw_hex, codec="eu4_escape", max_bytes=128)
            if not decoded or text != decoded:
                raise ValueError("faith display-name decode mismatch")
            public_value = {
                "primary_religion_name": {
                    "text": decoded,
                    "raw_hex": raw_hex.lower(),
                    "encoding": "eu4_escape",
                },
                "icon_frame_request": icon_frame_request,
            }
            # Optional provenance for consumers joining a separately captured
            # configuration identity. A missing digest does not invalidate this
            # independent name projection, but it cannot authorize that join.
            try:
                provenance.update(binding_digests(field, target))
            except Exception:
                pass
            return result({_FIELD: self._field("known", value=public_value)}, before)
        except (KeyError, TypeError, ValueError, IndexError):
            return failure("COUNTRY_FAITH_FIELD_INVALID", result_context=before)


__all__ = ["NativeCountryFaithSource"]
