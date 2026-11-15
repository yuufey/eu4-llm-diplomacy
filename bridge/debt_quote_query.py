"""Validation and public projection for the read-only Take on Debt quote.

The native query is not a diplomatic action in ``ACTIONS`` and never grants
submission authority.  This module checks the saved native proof against the
independent B23 quote arithmetic, then drops per-loan rows and raw text before
returning the semantic result.
"""
from __future__ import annotations

import re
from typing import Any

from .information.loan_interest_quote_math import quote_total
from .native_text import DEFAULT_NATIVE_TEXT_CODEC, decode_native_text_hex

ACTION_ID = "take_on_debt"
QUERY_CAPABILITY = "native_debt_quote_query"
FAMILY = "debt_quote"
SCHEMA = "native.debt_quote.v1"
BASIS = "native_take_on_debt_description_fold"
SCALE = 1000
MAX_LOANS = 64
MAX_DESCRIPTION_BYTES = 512
I32_MIN = -(1 << 31)
I32_MAX = (1 << 31) - 1
_U32_MAX = (1 << 32) - 1
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_HEX = re.compile(r"[0-9A-Fa-f]*\Z")
_LOAN_FIELDS = frozenset({
    "principal_i32", "stored_rate_i32", "expiry_raw_i32", "interest_raw_i32",
})
_MXCSR_SNAPSHOT_FIELDS = (
    "mxcsr_before", "mxcsr_after_helpers", "mxcsr_before_description", "mxcsr_after",
)
_MXCSR_DERIVED_FIELDS = (
    "mxcsr_model_compatible", "mxcsr_controls_stable",
    "mxcsr_daz_enabled", "mxcsr_ftz_enabled",
)


def _is_i32(value: object) -> bool:
    return type(value) is int and I32_MIN <= value <= I32_MAX


def _is_tag(value: object) -> bool:
    return isinstance(value, str) and _TAG.fullmatch(value) is not None


def normalize_request(actor: object, recipient: object, phase: object,
                      parameters: object) -> dict[str, Any]:
    """Validate the single supported observer request and return empty params."""
    if actor != "FRA" or type(actor) is not str:
        raise ValueError("TAKE_ON_DEBT_ACTOR_MUST_BE_FRA")
    if not _is_tag(recipient):
        raise ValueError("TAKE_ON_DEBT_RECIPIENT_MUST_BE_COUNTRY_TAG")
    if recipient in {"FRA", "POR"}:
        raise ValueError("TAKE_ON_DEBT_RECIPIENT_EXCLUDED")
    if phase != "initiate" or type(phase) is not str:
        raise ValueError("TAKE_ON_DEBT_INITIATE_ONLY")
    if type(parameters) is not dict or parameters:
        raise ValueError("TAKE_ON_DEBT_PARAMETERS_UNSUPPORTED")
    return {}


def _event_identity(event: object, actor: object, recipient: object, phase: object,
                    date_raw: object, query_id: object, session_id: object) -> bool:
    if type(event) is not dict:
        return False
    try:
        normalize_request(actor, recipient, phase, {})
    except (TypeError, ValueError):
        return False
    if not _is_i32(date_raw):
        return False
    if (event.get("event") != "native_alliance_inspection"
            or event.get("action_id") != ACTION_ID
            or event.get("family") != FAMILY
            or event.get("actor") != actor
            or event.get("recipient") != recipient
            or event.get("phase") != phase
            or not _is_i32(event.get("date_raw"))
            or event["date_raw"] != date_raw):
        return False
    event_query_id = event.get("query_id")
    event_session_id = event.get("session_id")
    if (type(event_query_id) is not str or not event_query_id or len(event_query_id) > 256
            or "\x00" in event_query_id):
        return False
    if (type(event_session_id) is not str or not event_session_id
            or len(event_session_id) > 256 or "\x00" in event_session_id):
        return False
    if query_id is not None and (type(query_id) is not str or query_id != event_query_id):
        return False
    if session_id is not None and (
            type(session_id) is not str or session_id != event_session_id):
        return False
    if (event.get("ui_selection_checked") is not True
            or event.get("validity_called") is not False
            or event.get("full_rules_complete") is not False
            or event.get("submitted") is not False
            or type(event.get("native_visibility")) is not bool):
        return False
    return True


def _derive_mxcsr(quote: dict[str, Any]) -> dict[str, bool | None] | None:
    """Check FP fields against the snapshots, strictly for complete quotes."""
    values: list[int | None] = []
    for key in _MXCSR_SNAPSHOT_FIELDS:
        value = quote.get(key)
        if value is not None and (type(value) is not int or not 0 <= value <= _U32_MAX):
            return None
        values.append(value)

    before, after_helpers, before_description, after = values
    flags: dict[str, bool | None] = {}
    for key in _MXCSR_DERIVED_FIELDS:
        supplied = quote.get(key)
        if supplied is not None and type(supplied) is not bool:
            return None
        flags[key] = supplied

    if before is None:
        # The native producer initializes its four derived booleans to false
        # before taking any MXCSR sample.  With no sample, expose no FP claim.
        if any(value is not None for value in values[1:]):
            return None
        if any(flags[key] is not False for key in _MXCSR_DERIVED_FIELDS):
            return None
        return {
            "mxcsr_model_compatible": None,
            "mxcsr_controls_stable": None,
            "mxcsr_daz_enabled": None,
            "mxcsr_ftz_enabled": None,
        }

    supported = (before & 0x6000) == 0 and (before & 0x1F80) == 0x1F80
    daz_enabled = (before & 0x0040) != 0
    ftz_enabled = (before & 0x8000) != 0
    if (flags["mxcsr_model_compatible"] is not supported
            or flags["mxcsr_daz_enabled"] is not daz_enabled
            or flags["mxcsr_ftz_enabled"] is not ftz_enabled
            or type(flags["mxcsr_controls_stable"]) is not bool
            or after is None):
        return None

    if quote["complete"]:
        if (after_helpers is None or before_description is None
                or flags["mxcsr_controls_stable"] is not True):
            return None
        controls = [value & 0xFFC0 for value in values if value is not None]
        if len(controls) != 4 or len(set(controls)) != 1 or not supported:
            return None
    return {
        "mxcsr_model_compatible": supported,
        "mxcsr_controls_stable": flags["mxcsr_controls_stable"],
        "mxcsr_daz_enabled": daz_enabled,
        "mxcsr_ftz_enabled": ftz_enabled,
    }


def _validate_quote(event: dict[str, Any]) -> dict[str, Any] | None:
    quote = event.get("native_debt_quote")
    if type(quote) is not dict:
        return None
    required = {
        "schema", "read_only", "complete", "context_stable", "guards_verified",
        "financial_inputs_read", *_MXCSR_SNAPSHOT_FIELDS, *_MXCSR_DERIVED_FIELDS,
        "total_raw_i32", "scale", "basis", "loans", "description_readable",
        "description_truncated", "description_encoding_known", "description_hex",
        "description_cleanup_performed", "description_cleanup_skipped",
        "action_cleanup_performed",
    }
    if not required.issubset(quote):
        return None
    if (quote.get("schema") != SCHEMA
            or quote.get("read_only") is not True
            or type(quote.get("complete")) is not bool
            or type(quote.get("context_stable")) is not bool
            or type(quote.get("guards_verified")) is not bool
            or type(quote.get("financial_inputs_read")) is not bool
            or type(quote.get("description_readable")) is not bool
            or type(quote.get("description_truncated")) is not bool
            or quote.get("description_encoding_known") is not False
            or type(quote.get("description_cleanup_performed")) is not bool
            or type(quote.get("description_cleanup_skipped")) is not bool
            or type(quote.get("action_cleanup_performed")) is not bool
            or type(quote.get("scale")) is not int or quote["scale"] != SCALE
            or quote.get("basis") != BASIS):
        return None
    if (type(event.get("complete")) is not bool
            or event["complete"] is not quote["complete"]):
        return None
    total = quote.get("total_raw_i32")
    if total is not None and not _is_i32(total):
        return None
    loans = quote.get("loans")
    if type(loans) is not list or len(loans) > MAX_LOANS:
        return None
    for row in loans:
        if (type(row) is not dict or set(row) != _LOAN_FIELDS
                or any(not _is_i32(row[key]) for key in _LOAN_FIELDS)):
            return None
    description_hex = quote.get("description_hex")
    if (type(description_hex) is not str
            or len(description_hex) > MAX_DESCRIPTION_BYTES * 2
            or len(description_hex) % 2
            or _HEX.fullmatch(description_hex) is None):
        return None
    if not quote["description_readable"]:
        if description_hex or quote["description_truncated"]:
            return None
    if (quote["description_cleanup_performed"]
            and quote["description_cleanup_skipped"]):
        return None
    if ((quote["description_cleanup_performed"]
         or quote["description_cleanup_skipped"])
            and not quote["action_cleanup_performed"]):
        return None
    if quote["financial_inputs_read"] and not quote["action_cleanup_performed"]:
        return None

    mxcsr = _derive_mxcsr(quote)
    if mxcsr is None:
        return None

    visible = event["native_visibility"]
    complete = quote["complete"]
    financial_read = quote["financial_inputs_read"]
    # A selector result is meaningful only after the guarded native family
    # and the actor/recipient/date context have both passed their checks.
    # The producer can otherwise emit a bool result with context_stable=false
    # when the context changes immediately after the selector call.
    if not quote["guards_verified"] or not quote["context_stable"]:
        return None
    if not visible:
        if event.get("reason_code") != "NATIVE_VISIBILITY_FALSE":
            return None
        if (complete or financial_read or total is not None or loans
                or quote["description_readable"] or description_hex):
            return None
        if (any(quote[key] is not False for key in _MXCSR_DERIVED_FIELDS)
                or quote["description_cleanup_performed"]
                or quote["description_cleanup_skipped"]
                or quote["action_cleanup_performed"]):
            return None
    if not complete:
        # The native producer clears all partial financial values and text on
        # every incomplete exit; accepting them would blur incomplete and full
        # quote evidence even if the public projector later hid the payload.
        if total is not None or loans or quote["description_readable"]:
            return None
        if quote["description_truncated"] or description_hex:
            return None
    if not financial_read:
        if total is not None or loans:
            return None
        if quote["description_readable"] or quote["description_truncated"] or description_hex:
            return None

    arithmetic: dict[str, Any] | None = None
    if complete:
        if (not visible or not financial_read or not quote["context_stable"]
                or not quote["guards_verified"] or total is None
                or not quote["description_readable"]):
            return None
        if any(value is None for value in (quote[key] for key in _MXCSR_SNAPSHOT_FIELDS)):
            return None
        if (mxcsr["mxcsr_model_compatible"] is not True
                or mxcsr["mxcsr_controls_stable"] is not True):
            return None
        try:
            math_loans = [{
                "principal_i32": row["principal_i32"],
                "stored_rate_i32": row["stored_rate_i32"],
                "expiry_raw_i32": row["expiry_raw_i32"],
            } for row in loans]
            arithmetic = quote_total(loans=math_loans,
                                     as_of_raw_i32=event["date_raw"])
        except (TypeError, ValueError, OverflowError):
            return None
        if (arithmetic["invalid_conversion_count"] != 0
                or arithmetic["quote_i32"] != total
                or len(arithmetic["loans"]) != len(loans)):
            return None
        for input_row, modeled_row in zip(loans, arithmetic["loans"]):
            modeled_interest = modeled_row["interest"]["amount_i32"]
            if (modeled_row["interest"]["conversion_invalid"]
                    or modeled_interest != input_row["interest_raw_i32"]):
                return None
        if (quote["description_cleanup_performed"] is not True
                or quote["description_cleanup_skipped"] is not False):
            return None
        if quote["action_cleanup_performed"] is not True:
            return None

    return {
        "quote": quote,
        "mxcsr": mxcsr,
        "arithmetic": arithmetic,
        "visible": visible,
        "complete": complete,
    }


def _validated_event(event: object, actor: object, recipient: object, phase: object,
                     date_raw: object, query_id: object,
                     session_id: object) -> dict[str, Any] | None:
    if not _event_identity(event, actor, recipient, phase, date_raw,
                           query_id, session_id):
        return None
    assert isinstance(event, dict)
    details = _validate_quote(event)
    if details is None:
        return None
    return {**details, "actor": actor, "recipient": recipient, "phase": phase,
            "date_raw": date_raw}


def validate_event(event: object, actor: object, recipient: object, phase: object,
                   date_raw: object, query_id: str | None = None,
                   session_id: str | None = None) -> bool:
    """Strictly validate identity, native-query scope, FP controls, and quote math."""
    try:
        return _validated_event(event, actor, recipient, phase, date_raw,
                                query_id, session_id) is not None
    except Exception:
        return False


def _public_fp(metadata: dict[str, bool | None]) -> dict[str, Any]:
    compatible = metadata["mxcsr_model_compatible"]
    return {
        "model_compatible": compatible,
        "controls_stable": metadata["mxcsr_controls_stable"],
        "daz_enabled": metadata["mxcsr_daz_enabled"],
        "ftz_enabled": metadata["mxcsr_ftz_enabled"],
        "rounding": "round_to_nearest_ties_to_even" if compatible is True else None,
        "exceptions": "masked" if compatible is True else None,
    }


def _quote_summary(status: str, date_raw: int | None,
                   metadata: dict[str, bool | None] | None = None,
                   total_raw_i32: int | None = None) -> dict[str, Any]:
    complete = status == "known"
    result: dict[str, Any] = {
        "status": status,
        "complete": complete,
        "total_raw_i32": total_raw_i32 if complete else None,
        "value": total_raw_i32 / SCALE if complete and total_raw_i32 is not None else None,
        "scale": SCALE,
        "unit": "ducats",
        "basis": BASIS,
        "as_of_raw": date_raw,
    }
    if metadata is not None:
        result["floating_point"] = _public_fp(metadata)
    return result


def _unknown_projection(event: object) -> dict[str, Any]:
    result: dict[str, Any] = {
        "event": "native_alliance_inspection",
        "action_id": ACTION_ID,
        "family": FAMILY,
        "actor": None,
        "recipient": None,
        "phase": None,
        "date_raw": None,
        "ui_selection_checked": None,
        # Even a well-typed visibility bit is withheld unless the full event
        # proof passed.  Otherwise a tampered quote could retain a false
        # visible/invisible claim while its financial fields fail validation.
        "native_visibility": None,
        "validity_called": None,
        "full_rules_complete": None,
        "submitted": None,
        "debt_quote": _quote_summary("unknown", None),
    }
    return result


def project_event(event: object, codec: str = DEFAULT_NATIVE_TEXT_CODEC) -> dict[str, Any]:
    """Project only a checked total and optional decoded description text.

    Invalid or incomplete records fail closed to a semantic unknown.  Native
    row data, raw text bytes, MXCSR register values, and memory identifiers are
    never returned.
    """
    if type(event) is not dict:
        return _unknown_projection(event)
    parsed = _validated_event(
        event, event.get("actor"), event.get("recipient"), event.get("phase"),
        event.get("date_raw"), event.get("query_id"), event.get("session_id"))
    if parsed is None:
        return _unknown_projection(event)

    quote = parsed["quote"]
    date_raw = parsed["date_raw"]
    metadata = parsed["mxcsr"]
    if not parsed["visible"]:
        summary = _quote_summary("invisible", date_raw)
    elif not parsed["complete"]:
        summary = _quote_summary("unknown", date_raw)
    else:
        arithmetic = parsed["arithmetic"]
        assert isinstance(arithmetic, dict)
        summary = _quote_summary(
            "known", date_raw, metadata, arithmetic["quote_i32"])

    result: dict[str, Any] = {
        "event": "native_alliance_inspection",
        "action_id": ACTION_ID,
        "family": FAMILY,
        "actor": parsed["actor"],
        "recipient": parsed["recipient"],
        "phase": parsed["phase"],
        "date_raw": date_raw,
        "ui_selection_checked": True,
        "native_visibility": parsed["visible"],
        "validity_called": False,
        "full_rules_complete": False,
        "submitted": False,
        "debt_quote": summary,
    }
    if (parsed["visible"] and parsed["complete"]
            and quote["description_readable"]
            and not quote["description_truncated"]):
        try:
            text = decode_native_text_hex(
                quote["description_hex"], codec,
                max_bytes=MAX_DESCRIPTION_BYTES,
                max_bytes_limit=MAX_DESCRIPTION_BYTES)
        except Exception:
            text = None
        if text is not None:
            result["native_description"] = {
                "text": text, "readable": True, "truncated": False,
            }
    return result


def query_only_descriptor(query_available: bool) -> dict[str, Any]:
    """Return an independent catalog row without registering an executable action."""
    if type(query_available) is not bool:
        raise ValueError("QUERY_AVAILABLE_MUST_BE_BOOL")
    return {
        "action_id": ACTION_ID,
        "name_zh": "接手债务报价",
        "name_en": "Take on Debt Quote",
        "category": "diplomatic_action",
        "native_identifier": "0x3469",
        "identification_source": "B23 factory selector 0x3469",
        "parameter_definitions": {},
        "phases": {
            "initiate": {
                "query": QUERY_CAPABILITY if query_available else "unimplemented",
                "execute": "unimplemented",
                "reason_code": None if query_available else "DEBT_QUOTE_QUERY_UNAVAILABLE",
            },
        },
        "runtime_verified": False,
        "query_only": True,
        "submission_supported": False,
    }


__all__ = [
    "ACTION_ID", "QUERY_CAPABILITY", "FAMILY", "SCHEMA", "BASIS",
    "normalize_request", "validate_event", "project_event", "query_only_descriptor",
]
