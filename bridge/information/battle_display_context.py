"""Project same-event copied battle definition and localization values.

The v7 wire captures settings/templates used by the native formatter. This
projection applies the explicit EU4 escape codec while keeping each source
field separate and never claiming that a popup was rendered or visible.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from bridge.native_text import decode_native_text_hex
from work import information_battle_display_context_wire as _wire


FIELD_ORDER = _wire.FIELD_ORDER
FIELD_LIMITS = _wire.FIELD_LIMITS
FIELD_SOURCES = _wire.FIELD_SOURCES
TEXT_CODEC = "eu4_escape"


def _unknown_fields(reason: str, raw_fields: Any = None) -> dict[str, Any]:
    raw_fields = raw_fields if isinstance(raw_fields, Mapping) else {}
    result: dict[str, Any] = {}
    for name in FIELD_ORDER:
        item = raw_fields.get(name)
        raw_hex = item.get("raw_hex") if isinstance(item, Mapping) else None
        state = item.get("state", "unknown") if isinstance(item, Mapping) else "unknown"
        result[name] = {
            "status": "unknown",
            "state": state,
            "source": FIELD_SOURCES[name],
            "codec": TEXT_CODEC,
            "raw_hex": raw_hex,
            "decoded": {"status": "unknown", "reason": reason},
        }
    return result


def _unknown(reason: str, *, context: Any = None, fields: Any = None,
             identity: dict[str, Any] | None = None) -> dict[str, Any]:
    result = {
        "status": "unknown",
        "state": "unknown",
        "reason": reason,
        "text_fields": _unknown_fields(reason, fields),
        "raw_context": dict(context) if isinstance(context, Mapping) else None,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }
    if identity is not None:
        result["captured_identity"] = identity
    return result


def _project_field(name: str, item: Any) -> dict[str, Any]:
    source = FIELD_SOURCES[name]
    if not isinstance(item, Mapping):
        return {
            "status": "unknown", "state": "unknown", "source": source,
            "codec": TEXT_CODEC, "raw_hex": None,
            "decoded": {"status": "unknown", "reason": "DISPLAY_CONTEXT_FIELD_INVALID"},
        }
    state = item.get("state")
    raw_hex = item.get("raw_hex")
    if state == "unknown":
        return {
            "status": "unknown", "state": state, "source": source,
            "codec": TEXT_CODEC, "raw_hex": None,
            "decoded": {"status": "unknown", "reason": "DISPLAY_CONTEXT_FIELD_UNKNOWN"},
        }
    if state == "absent":
        return {
            "status": "absent", "state": state, "source": source,
            "codec": TEXT_CODEC, "raw_hex": None,
            "decoded": {"status": "absent", "reason": "CACHE_KEY_ABSENT_NOT_UI_HIDDEN"},
            "cache_absence_is_not_visibility_evidence": True,
        }
    if state != "observed" or not isinstance(raw_hex, str):
        return {
            "status": "unknown", "state": state, "source": source,
            "codec": TEXT_CODEC, "raw_hex": raw_hex if isinstance(raw_hex, str) else None,
            "decoded": {"status": "unknown", "reason": "DISPLAY_CONTEXT_FIELD_INVALID"},
        }
    try:
        value = decode_native_text_hex(
            raw_hex,
            codec=TEXT_CODEC,
            max_bytes=FIELD_LIMITS[name],
            max_bytes_limit=FIELD_LIMITS[name],
        )
    except (ValueError, UnicodeError):
        return {
            "status": "unknown", "state": "observed", "source": source,
            "codec": TEXT_CODEC, "raw_hex": raw_hex,
            "decoded": {"status": "unknown", "reason": "DISPLAY_CONTEXT_TEXT_DECODE_FAILED"},
        }
    return {
        "status": "known", "state": "observed", "source": source,
        "codec": TEXT_CODEC, "raw_hex": raw_hex,
        "decoded": {"status": "known", "value": value},
    }


def project_display_context(decoded: Mapping[str, Any]) -> dict[str, Any]:
    """Project v7 values only when sequence/date/kind match the embedded v6 event.

    Event mismatches retract this projection only; the base battle observation
    in *decoded* is never modified. Malformed EU4 escape text keeps its raw hex
    and becomes unknown. Cache absence does not imply a hidden UI control.
    """
    if not isinstance(decoded, Mapping):
        return _unknown("DISPLAY_CONTEXT_DECODED_VALUE_INVALID")
    wire7 = decoded.get("wire7")
    if not isinstance(wire7, Mapping) or wire7.get("version") != _wire.VERSION:
        return _unknown("DISPLAY_CONTEXT_WIRE7_NOT_DECODED")
    context = decoded.get("display_context")
    if not isinstance(context, Mapping):
        return _unknown("DISPLAY_CONTEXT_NOT_CAPTURED")
    fields = context.get("fields")
    if context.get("state") == "unknown":
        reason = f"DISPLAY_CONTEXT_CAPTURE_FAILED_{str(context.get('failure_name', 'unknown')).upper()}"
        return _unknown(reason, context=context, fields=fields)
    if context.get("state") != "observed":
        return _unknown("DISPLAY_CONTEXT_STATE_INVALID", context=context, fields=fields)

    observation = decoded.get("observation")
    result = observation.get("result") if isinstance(observation, Mapping) else None
    base_context = decoded.get("context")
    captured_identity = {
        "sequence": context.get("sequence"),
        "raw_date": context.get("raw_date"),
        "battle_kind": context.get("battle_kind"),
    }
    embedded_identity = {
        "sequence": observation.get("sequence") if isinstance(observation, Mapping) else None,
        "raw_date": result.get("raw_date") if isinstance(result, Mapping) else None,
        "battle_kind": base_context.get("kind") if isinstance(base_context, Mapping) else None,
    }
    if (not all(type(value) is int for value in (*captured_identity.values(), *embedded_identity.values()))
            or captured_identity != embedded_identity):
        return _unknown(
            "DISPLAY_CONTEXT_EVENT_IDENTITY_MISMATCH",
            context=context,
            fields=fields,
            identity={"captured": captured_identity, "embedded": embedded_identity},
        )

    if not isinstance(fields, Mapping):
        return _unknown("DISPLAY_CONTEXT_FIELDS_INVALID", context=context)
    if not all(type(context.get(name)) is int for name in (
        "capture_stage", "failure", "battle_kind", "popup_kind_raw", "layout_raw", "button_flag_raw",
    )):
        return _unknown("DISPLAY_CONTEXT_METADATA_INVALID", context=context, fields=fields)
    projected = {name: _project_field(name, fields.get(name)) for name in FIELD_ORDER}
    kind = context["battle_kind"]
    popup_kind = context["popup_kind_raw"]
    definition = {
        "key": projected["definition_key"],
        "source": "native_message_definition",
        "formatter_kind": kind,
        "popup_kind_raw": popup_kind,
        "matches_formatter_kind": popup_kind == kind,
        "layout_raw": context["layout_raw"],
        "button_flag_raw": context["button_flag_raw"],
    }
    return {
        "status": "known", "state": "observed", "reason": None,
        "capture_stage": context["capture_stage"],
        "failure": context["failure"], "failure_name": context.get("failure_name"),
        "sequence": context["sequence"], "raw_date": context["raw_date"],
        "battle_kind": kind,
        "popup_kind_raw": popup_kind,
        "formatter_kind": kind,
        "matches_formatter_kind": popup_kind == kind,
        "layout_raw": context["layout_raw"],
        "button_flag_raw": context["button_flag_raw"],
        "definition": definition,
        "language": projected["language"],
        "text_fields": projected,
        "cache_absence_is_not_visibility_evidence": True,
        "full_display_complete": False,
        "runtime_popup_verified": False,
        "visibility_verified": False,
    }


__all__ = ["project_display_context"]
