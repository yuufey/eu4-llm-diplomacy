"""Private native UI-selector evidence for foreign-debt disclosure.

This helper only records whether the native action-list selector is visible for
an observer-to-target trade-favors-for-gold query, under the host's controlled-country
policy.  It does not prove that the AI-accept tooltip's amount is visible, read
or derive any debt amount, or observe a rendered game UI.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any


SCHEMA = "information.foreign_debt_disclosure.v1"
SCOPE = "native_ai_accept_principal_amount"

_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_GAME_VERSION = "1.37.4"
_ACTION_ID = "trade_favors_for_gold"
_PHASE = "initiate"
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")


def _result(
    status: str,
    admitted: bool | None,
    reason: str,
    *,
    native_inspection_calls: int = 0,
    target: Any = None,
    raw_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the private JSON-safe envelope used by capture owners."""
    raw = dict(raw_inputs or {})
    identity = raw.get("identity_before")
    session = identity.get("session") if isinstance(identity, Mapping) else None
    context = identity.get("context") if isinstance(identity, Mapping) else None
    game_date_field = context.get("game_date") if isinstance(context, Mapping) else None
    game_date = (game_date_field.get("value")
                 if isinstance(game_date_field, Mapping)
                 and game_date_field.get("present") is True
                 and _signed_i32(game_date_field.get("value")) else None)
    session_id = session.get("session_id") if isinstance(session, Mapping) else None
    if not isinstance(session_id, str) or not session_id:
        session_id = None
    creation_field = session.get("creation_filetime") if isinstance(session, Mapping) else None
    creation_filetime = (creation_field.get("value")
                         if isinstance(creation_field, Mapping)
                         and creation_field.get("present") is True
                         and type(creation_field.get("value")) is int
                         and creation_field.get("value") >= 0 else None)
    return {
        "schema": SCHEMA,
        "scope": SCOPE,
        "observer": _proof_value(identity, "context", "observer")[1],
        "target": target,
        "game_date": game_date,
        "session_id": session_id,
        "creation_filetime": creation_filetime,
        "status": status,
        "admitted": admitted,
        "reason": reason,
        "native_inspection_calls": native_inspection_calls,
        "actual_UI_render_observed": False,
        "raw_inputs": raw,
    }


def _signed_i32(value: Any) -> bool:
    return type(value) is int and _INT32_MIN <= value <= _INT32_MAX


def _safe_json_copy(value: Any) -> Any:
    """Return a detached JSON-safe copy or raise for non-JSON values."""
    return json.loads(json.dumps(value, allow_nan=False, separators=(",", ":")))


def _json_value(value: Any) -> Any:
    """Keep malformed source values representable without leaking objects."""
    try:
        return _safe_json_copy(value)
    except Exception:
        return {"unsupported_type": type(value).__name__}


def _field_proof(mapping: Any, key: str) -> dict[str, Any]:
    present = isinstance(mapping, Mapping) and key in mapping
    return {
        "present": present,
        "value": _json_value(mapping.get(key)) if present else None,
    }


def _top_identity_from_proof(identity: Any) -> dict[str, Any]:
    session = identity.get("session") if isinstance(identity, Mapping) else None
    context = identity.get("context") if isinstance(identity, Mapping) else None
    game_date_field = context.get("game_date") if isinstance(context, Mapping) else None
    game_date = (game_date_field.get("value")
                 if isinstance(game_date_field, Mapping)
                 and game_date_field.get("present") is True
                 and _signed_i32(game_date_field.get("value")) else None)
    session_id = session.get("session_id") if isinstance(session, Mapping) else None
    if not isinstance(session_id, str) or not session_id:
        session_id = None
    creation_field = session.get("creation_filetime") if isinstance(session, Mapping) else None
    creation_filetime = (creation_field.get("value")
                         if isinstance(creation_field, Mapping)
                         and creation_field.get("present") is True
                         and type(creation_field.get("value")) is int
                         and creation_field.get("value") >= 0 else None)
    return {
        "observer": _proof_value(identity, "context", "observer")[1],
        "game_date": game_date,
        "session_id": session_id,
        "creation_filetime": creation_filetime,
    }


def _capture_identity_proof(base_source: Any, context: Any) -> dict[str, Any]:
    """Copy just the identity/config fields needed for private replay checks."""
    try:
        session = getattr(base_source, "session", None)
        record = getattr(session, "record", None) if session is not None else None
        is_record = isinstance(record, Mapping)
        session_info = {
            "available": session is not None,
            "record_available": is_record,
            "session_id": _json_value(getattr(session, "session_id", None)) if session is not None else None,
            "session_creation_filetime": _json_value(getattr(session, "creation_filetime", None)) if session is not None else None,
            "record_session_id": _field_proof(record, "session_id") if is_record else {"present": False, "value": None},
            "creation_filetime": _field_proof(record, "creation_filetime") if is_record else {"present": False, "value": None},
            "game_sha256": _field_proof(record, "game_sha256") if is_record else {"present": False, "value": None},
            "game_version": {key: _field_proof(record, key) for key in ("game_version", "version")} if is_record else {
                "game_version": {"present": False, "value": None},
                "version": {"present": False, "value": None},
            },
            "game_dates": {key: _field_proof(record, key) for key in ("game_date", "date_raw")} if is_record else {
                "game_date": {"present": False, "value": None},
                "date_raw": {"present": False, "value": None},
            },
        }
        context_keys = (
            "session_id", "observer", "game_sha256", "game_version", "game_date",
            "status", "complete", "mode", "creation_filetime",
        )
        context_proof = {
            key: _field_proof(context, key) for key in context_keys
        } if isinstance(context, Mapping) else {"available": False}
        if isinstance(context, Mapping):
            context_proof["available"] = True
        controls_present = is_record and "controlled_countries" in record
        fallback_country = getattr(session, "controlled_country", None) if session is not None else None
        controls_raw = record.get("controlled_countries") if controls_present else [fallback_country]
        if controls_present and type(controls_raw) is not list:
            controls_value = {"non_list_type": type(controls_raw).__name__,
                              "value": _json_value(controls_raw)}
        else:
            controls_value = _json_value(controls_raw)
        return {
            "session": session_info,
            "context": context_proof,
            "controlled_countries": {
                "source": "session.record",
                "present": controls_present,
                "fallback_country": _json_value(fallback_country),
                "value": _json_value(controls_value),
            },
        }
    except Exception as exc:
        return {"capture_error": type(exc).__name__}


def _proof_value(proof: Any, section: str, key: str) -> tuple[bool, Any]:
    if not isinstance(proof, Mapping):
        return False, None
    block = proof.get(section)
    if not isinstance(block, Mapping):
        return False, None
    field = block.get(key)
    if not isinstance(field, Mapping) or type(field.get("present")) is not bool:
        return False, None
    return field["present"], field.get("value")


def _proof_preflight_error(proof: Any) -> str | None:
    """Pure counterpart to the live session/context validation."""
    if not isinstance(proof, Mapping):
        return "SOURCE_BINDING_PROOF_MISSING"
    if "capture_error" in proof:
        return "SESSION_CONTEXT_READ_FAILED"
    session = proof.get("session")
    context = proof.get("context")
    controls = proof.get("controlled_countries")
    if not isinstance(session, Mapping) or type(session.get("available")) is not bool:
        return "SOURCE_BINDING_PROOF_INVALID"
    if session.get("available") is not True:
        return "SESSION_UNAVAILABLE"
    if session.get("record_available") is not True:
        return "SESSION_RECORD_UNAVAILABLE"

    session_id = session.get("session_id")
    present, record_session_id = _proof_value({"session": session}, "session", "record_session_id")
    if (not isinstance(session_id, str) or not session_id
            or not present or record_session_id != session_id):
        return "SESSION_ID_BINDING_MISMATCH"

    creation_present, creation = _proof_value({"session": session}, "session", "creation_filetime")
    session_creation = session.get("session_creation_filetime")
    if not creation_present or type(creation) is not int or creation < 0:
        return "CREATION_FILETIME_UNAVAILABLE"
    if session_creation is not None and (
            type(session_creation) is not int or session_creation != creation):
        return "CREATION_FILETIME_BINDING_MISMATCH"

    sha_present, sha256 = _proof_value({"session": session}, "session", "game_sha256")
    if not sha_present or sha256 != _GAME_SHA256:
        return "SESSION_GAME_SHA256_MISMATCH"
    versions = session.get("game_version")
    if not isinstance(versions, Mapping):
        return "SESSION_GAME_VERSION_MISMATCH"
    for key in ("game_version", "version"):
        field = versions.get(key)
        if not isinstance(field, Mapping) or type(field.get("present")) is not bool:
            return "SESSION_GAME_VERSION_MISMATCH"
        if field["present"] and field.get("value") != _GAME_VERSION:
            return "SESSION_GAME_VERSION_MISMATCH"

    if not isinstance(context, Mapping) or context.get("available") is not True:
        return "CONTEXT_UNAVAILABLE"
    context_values: dict[str, Any] = {}
    for key in ("session_id", "observer", "game_sha256", "game_version", "game_date",
                "status", "complete", "mode", "creation_filetime"):
        field = context.get(key)
        if not isinstance(field, Mapping) or type(field.get("present")) is not bool:
            return "CONTEXT_BINDING_INVALID"
        context_values[key] = field.get("value") if field["present"] else None
    game_date = context_values["game_date"]
    if (not context["session_id"].get("present")
            or context_values["session_id"] != session_id
            or not context["observer"].get("present")
            or not isinstance(context_values["observer"], str)
            or _TAG_RE.fullmatch(context_values["observer"]) is None
            or not context["game_sha256"].get("present")
            or context_values["game_sha256"] != _GAME_SHA256
            or not context["game_version"].get("present")
            or context_values["game_version"] != _GAME_VERSION
            or not _signed_i32(game_date)):
        return "CONTEXT_BINDING_INVALID"
    if (not context["status"].get("present") or context_values["status"] != "ready"
            or not context["complete"].get("present") or context_values["complete"] is not True):
        return "CONTEXT_NOT_READY"
    if (context["mode"].get("present")
            and context_values["mode"] not in (None, "live")):
        return "CONTEXT_MODE_INVALID"
    if (context["creation_filetime"].get("present")
            and context_values["creation_filetime"] != creation):
        return "CONTEXT_CREATION_FILETIME_MISMATCH"

    game_dates = session.get("game_dates")
    if not isinstance(game_dates, Mapping):
        return "RECORD_DATE_MISMATCH"
    for key in ("game_date", "date_raw"):
        field = game_dates.get(key)
        if not isinstance(field, Mapping) or type(field.get("present")) is not bool:
            return "RECORD_DATE_MISMATCH"
        if field["present"] and (
                not _signed_i32(field.get("value")) or field.get("value") != game_date):
            return "RECORD_DATE_MISMATCH"

    if (not isinstance(controls, Mapping) or controls.get("source") != "session.record"
            or type(controls.get("present")) is not bool):
        return "CONTROLLED_COUNTRY_POLICY_INVALID"
    raw_tags = controls.get("value")
    if (not controls["present"] and
            (not isinstance(controls.get("fallback_country"), str)
             or _TAG_RE.fullmatch(controls["fallback_country"]) is None)):
        return "CONTROLLED_COUNTRY_AUTHORITY_UNAVAILABLE"
    if not controls["present"] and raw_tags != [controls.get("fallback_country")]:
        return "CONTROLLED_COUNTRY_POLICY_INVALID"
    if not isinstance(raw_tags, list):
        return "CONTROLLED_COUNTRIES_NOT_LIST"
    if any(not isinstance(tag, str) or _TAG_RE.fullmatch(tag) is None for tag in raw_tags):
        return "CONTROLLED_COUNTRY_TAG_INVALID"
    if len(raw_tags) != len(set(raw_tags)):
        return "CONTROLLED_COUNTRIES_NOT_UNIQUE"
    if context_values["observer"] not in raw_tags:
        return "OBSERVER_NOT_IN_CONTROLLED_COUNTRIES"
    return None


def _controlled_tags(record: Mapping[str, Any], observer: str, fallback_country: Any) -> tuple[bool, tuple[str, ...] | None, str | None]:
    """Read only the host session record's controlled-country policy."""
    present = "controlled_countries" in record
    if (not present and (not isinstance(fallback_country, str)
                         or _TAG_RE.fullmatch(fallback_country) is None)):
        return False, None, "CONTROLLED_COUNTRY_AUTHORITY_UNAVAILABLE"
    raw = record.get("controlled_countries") if present else [fallback_country]
    if not isinstance(raw, list):
        return True, None, "CONTROLLED_COUNTRIES_NOT_LIST"
    if any(not isinstance(tag, str) or _TAG_RE.fullmatch(tag) is None for tag in raw):
        return True, None, "CONTROLLED_COUNTRY_TAG_INVALID"
    if len(raw) != len(set(raw)):
        return True, None, "CONTROLLED_COUNTRIES_NOT_UNIQUE"
    if observer not in raw:
        return present, None, "OBSERVER_NOT_IN_CONTROLLED_COUNTRIES"
    return present, tuple(raw), None


def _read_identity(base_source: Any, context: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Validate the current session, installation record, and source context."""
    try:
        session = getattr(base_source, "session", None)
        if session is None:
            return None, "SESSION_UNAVAILABLE"
        record = getattr(session, "record", None)
        if not isinstance(record, Mapping):
            return None, "SESSION_RECORD_UNAVAILABLE"

        session_id = getattr(session, "session_id", None)
        record_session_id = record.get("session_id")
        creation_filetime = record.get("creation_filetime")
        session_creation_filetime = getattr(session, "creation_filetime", None)
        if (not isinstance(session_id, str) or not session_id
                or record_session_id != session_id):
            return None, "SESSION_ID_BINDING_MISMATCH"
        if type(creation_filetime) is not int or creation_filetime < 0:
            return None, "CREATION_FILETIME_UNAVAILABLE"
        if (session_creation_filetime is not None
                and (type(session_creation_filetime) is not int
                     or session_creation_filetime != creation_filetime)):
            return None, "CREATION_FILETIME_BINDING_MISMATCH"
        if record.get("game_sha256") != _GAME_SHA256:
            return None, "SESSION_GAME_SHA256_MISMATCH"
        for version_key in ("game_version", "version"):
            if version_key in record and record.get(version_key) != _GAME_VERSION:
                return None, "SESSION_GAME_VERSION_MISMATCH"

        if not isinstance(context, Mapping):
            return None, "CONTEXT_UNAVAILABLE"
        game_date = context.get("game_date")
        if (context.get("session_id") != session_id
                or not isinstance(context.get("observer"), str)
                or _TAG_RE.fullmatch(context["observer"]) is None
                or context.get("game_sha256") != _GAME_SHA256
                or context.get("game_version") != _GAME_VERSION
                or not _signed_i32(game_date)):
            return None, "CONTEXT_BINDING_INVALID"
        if context.get("status") != "ready" or context.get("complete") is not True:
            return None, "CONTEXT_NOT_READY"
        if context.get("mode") not in (None, "live"):
            return None, "CONTEXT_MODE_INVALID"
        if ("creation_filetime" in context
                and context.get("creation_filetime") != creation_filetime):
            return None, "CONTEXT_CREATION_FILETIME_MISMATCH"

        for date_key in ("game_date", "date_raw"):
            if date_key in record:
                record_date = record.get(date_key)
                if not _signed_i32(record_date) or record_date != game_date:
                    return None, "RECORD_DATE_MISMATCH"

        controlled_present, controlled, policy_error = _controlled_tags(
            record, context["observer"], getattr(session, "controlled_country", None))
        if policy_error is not None or controlled is None:
            return None, policy_error or "CONTROLLED_COUNTRY_POLICY_INVALID"

        # Preserve precisely the fields whose stability authorizes the query.
        context_snapshot = {
            "session_id": context.get("session_id"),
            "observer": context.get("observer"),
            "game_sha256": context.get("game_sha256"),
            "game_version": context.get("game_version"),
            "game_date": game_date,
            "status": context.get("status"),
            "complete": context.get("complete"),
            "mode": context.get("mode"),
            "creation_filetime": context.get("creation_filetime"),
        }
        snapshot = {
            "session": session,
            "record": record,
            "session_id": session_id,
            "creation_filetime": creation_filetime,
            "session_creation_filetime": session_creation_filetime,
            "game_sha256": record.get("game_sha256"),
            "game_version": record.get("game_version", record.get("version")),
            "record_dates": {
                key: (key in record, record.get(key)) for key in ("game_date", "date_raw")
            },
            "controlled_present": controlled_present,
            "controlled": controlled,
            "context": context,
            "context_snapshot": context_snapshot,
            "game_date": game_date,
            "raw_proof": {
                "context": context_snapshot,
                "session_binding": {
                    "session_id": session_id,
                    "record_session_id": record_session_id,
                    "creation_filetime": creation_filetime,
                    "session_creation_filetime": session_creation_filetime,
                    "game_sha256": record.get("game_sha256"),
                    "game_version": record.get("game_version", record.get("version")),
                },
                "controlled_countries": {
                    "source": "session.record",
                    "present": controlled_present,
                    "value": list(controlled),
                },
            },
        }
        return snapshot, None
    except Exception:
        return None, "SESSION_CONTEXT_READ_FAILED"


def _identity_still_stable(base_source: Any, snapshot: Mapping[str, Any]) -> bool:
    """Ensure the host binding and controlled policy did not drift mid-call."""
    try:
        session = snapshot["session"]
        record = snapshot["record"]
        if getattr(base_source, "session", None) is not session:
            return False
        if getattr(base_source, "diplomacy_tools", None) is not snapshot.get("tools"):
            return False
        if getattr(session, "record", None) is not record:
            return False
        if getattr(session, "session_id", None) != snapshot.get("session_id"):
            return False
        creation = record.get("creation_filetime")
        if creation != snapshot.get("creation_filetime"):
            return False
        current_session_creation = getattr(session, "creation_filetime", None)
        if current_session_creation != snapshot.get("session_creation_filetime"):
            return False
        if record.get("session_id") != snapshot.get("session_id"):
            return False
        if record.get("game_sha256") != snapshot.get("game_sha256"):
            return False
        if record.get("game_version", record.get("version")) != snapshot.get("game_version"):
            return False
        for key, value in snapshot.get("record_dates", {}).items():
            if (key in record) != value[0] or (value[0] and record.get(key) != value[1]):
                return False
        present, controlled, error = _controlled_tags(
            record, snapshot["context_snapshot"]["observer"],
            getattr(session, "controlled_country", None))
        if (error is not None or present != snapshot.get("controlled_present")
                or controlled != snapshot.get("controlled")):
            return False
        context = snapshot["context"]
        context_snapshot = snapshot["context_snapshot"]
        if not isinstance(context, Mapping):
            return False
        if any(context.get(key) != value for key, value in context_snapshot.items()):
            return False
        if getattr(snapshot["tools"], "session", None) is not session:
            return False
        return True
    except Exception:
        return False


def _inspection_reason(inspection: Any, snapshot: Mapping[str, Any]) -> tuple[str | None, bool | None]:
    """Validate the actual public inspection shape and return native visibility."""
    if not isinstance(inspection, Mapping):
        return "INSPECTION_NOT_OBJECT", None
    if (type(inspection.get("contract_version")) is not int
            or inspection.get("contract_version") != 1):
        return "INSPECTION_CONTRACT_VERSION_INVALID", None
    if (inspection.get("action_id") != _ACTION_ID
            or inspection.get("actor") != snapshot.get("observer")
            or inspection.get("recipient") != snapshot.get("target")
            or inspection.get("phase") != _PHASE):
        return "INSPECTION_ACTION_BINDING_MISMATCH", None

    interface_support = inspection.get("interface_support")
    if (not isinstance(interface_support, Mapping)
            or interface_support.get("query") != "partial_native_rules"):
        return "INSPECTION_QUERY_CAPABILITY_UNAVAILABLE", None

    session = inspection.get("session")
    if (not isinstance(session, Mapping)
            or session.get("status") != "ready"
            or not _signed_i32(session.get("date_raw"))
            or session.get("date_raw") != snapshot.get("game_date")):
        return "INSPECTION_SESSION_DATE_MISMATCH", None

    components = inspection.get("native_rule_components")
    if not isinstance(components, Mapping) or components.get("ui_selection_checked") is not True:
        return "NATIVE_UI_SELECTION_UNCHECKED", None
    native_visibility = components.get("native_visibility")
    if type(native_visibility) is not bool:
        return "NATIVE_VISIBILITY_UNAVAILABLE", None

    visibility = inspection.get("visibility")
    expected_status = "visible" if native_visibility else "hidden"
    if (not isinstance(visibility, Mapping)
            or visibility.get("complete") is not True
            or visibility.get("status") != expected_status):
        return "VISIBILITY_PROJECTION_MISMATCH", None
    return None, native_visibility


def _raw_envelope(
    target: Any,
    identity_before: Mapping[str, Any],
    identity_after: Mapping[str, Any],
    *,
    tool_binding: Mapping[str, Any] | None = None,
    runtime_identity_stable: bool | None = None,
    inspection: Any = None,
    inspection_json_safe: bool | None = None,
    inspection_error: str | None = None,
) -> dict[str, Any]:
    return {
        "evidence_schema": "information.foreign_debt_disclosure.raw.v1",
        "operation": {
            "tool": "DiplomacyTools.inspect_diplomatic_action",
            "read_only": True,
        },
        "debt_amount_source": "not_evaluated_by_helper",
        "request": {
            "action_id": _ACTION_ID,
            "observer": _proof_value(identity_before, "context", "observer")[1],
            "target": _json_value(target),
            "phase": _PHASE,
            "parameters": {},
        },
        "identity_before": _json_value(identity_before),
        "identity_after": _json_value(identity_after),
        "tool_binding": _json_value(tool_binding) if tool_binding is not None else None,
        "runtime_identity_stable": runtime_identity_stable,
        "inspection": _json_value(inspection) if inspection_json_safe is True else None,
        "inspection_json_safe": inspection_json_safe,
        "inspection_error": inspection_error,
    }


def _record_target(record: Mapping[str, Any]) -> Any:
    raw_inputs = record.get("raw_inputs")
    request = raw_inputs.get("request") if isinstance(raw_inputs, Mapping) else None
    return request.get("target") if isinstance(request, Mapping) else None


def _typed_equal(left: Any, right: Any) -> bool:
    """Compare JSON trees without Python's bool/int equivalence."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_typed_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_typed_equal(a, b) for a, b in zip(left, right))
    return left == right


def _expected_from_raw(record: Mapping[str, Any]) -> tuple[str, bool | None, str] | None:
    raw = record.get("raw_inputs")
    if not isinstance(raw, Mapping) or raw.get("evidence_schema") != "information.foreign_debt_disclosure.raw.v1":
        return None
    required_raw = {
        "evidence_schema", "operation", "debt_amount_source", "request", "identity_before",
        "identity_after", "tool_binding", "runtime_identity_stable", "inspection",
        "inspection_json_safe", "inspection_error",
    }
    if set(raw) != required_raw:
        return None
    if (not isinstance(raw.get("operation"), Mapping)
            or set(raw["operation"]) != {"tool", "read_only"}
            or raw["operation"].get("tool") != "DiplomacyTools.inspect_diplomatic_action"
            or raw["operation"].get("read_only") is not True
            or raw.get("debt_amount_source") != "not_evaluated_by_helper"):
        return None
    request = raw.get("request")
    if (not isinstance(request, Mapping)
            or set(request) != {"action_id", "observer", "target", "phase", "parameters"}
            or request.get("action_id") != _ACTION_ID
            or not _typed_equal(request.get("observer"),
                                _proof_value(raw.get("identity_before"), "context", "observer")[1])
            or request.get("phase") != _PHASE
            or type(request.get("parameters")) is not dict
            or request.get("parameters") != {}):
        return None
    target = request.get("target")
    before = raw.get("identity_before")
    after = raw.get("identity_after")
    preflight_error = _proof_preflight_error(before)
    call_count = record.get("native_inspection_calls")
    if type(call_count) is not int or call_count not in (0, 1):
        return None

    if preflight_error is not None:
        return ("unknown", None, preflight_error) if call_count == 0 else None
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return None

    # Before native inspection, malformed targets and protected scopes fail closed.
    if not isinstance(target, str) or _TAG_RE.fullmatch(target) is None:
        expected = ("unknown", None, "TARGET_TAG_INVALID")
        return expected if call_count == 0 and _typed_equal(before, after) else (
            ("unknown", None, "SOURCE_BINDING_DRIFTED") if call_count == 0 else None
        )
    controls = before.get("controlled_countries")
    if not isinstance(controls, Mapping) or not isinstance(controls.get("value"), list):
        return None
    if target in controls["value"]:
        expected = ("known", False, "TARGET_CONTROLLED_BY_HOST")
        if call_count != 0:
            return None
        return expected if _typed_equal(before, after) else ("unknown", None, "SOURCE_BINDING_DRIFTED")

    if not _typed_equal(before, after):
        return ("unknown", None, "SOURCE_BINDING_DRIFTED")

    tool_binding = raw.get("tool_binding")
    if not isinstance(tool_binding, Mapping) or set(tool_binding) != {
            "tools_present", "session_matches", "inspection_callable", "read_error"}:
        return None
    if tool_binding.get("read_error") is not None:
        if not isinstance(tool_binding.get("read_error"), str):
            return None
        return (("unknown", None, "DIPLOMACY_TOOLS_READ_FAILED")
                if call_count == 0 else None)
    if type(tool_binding.get("tools_present")) is not bool or type(tool_binding.get("session_matches")) is not bool or type(tool_binding.get("inspection_callable")) is not bool:
        return None
    if tool_binding["tools_present"] is not True or tool_binding["session_matches"] is not True:
        return (("unknown", None, "DIPLOMACY_TOOLS_SESSION_MISMATCH")
                if call_count == 0 else None)
    if tool_binding["inspection_callable"] is not True:
        return (("unknown", None, "INSPECTION_TOOL_UNAVAILABLE")
                if call_count == 0 else None)
    if call_count == 0:
        return None

    if raw.get("runtime_identity_stable") is not True:
        return ("unknown", None, "SOURCE_BINDING_DRIFTED")
    if raw.get("inspection_error") is not None:
        if not isinstance(raw.get("inspection_error"), str) or raw.get("inspection") is not None:
            return None
        return ("unknown", None, "INSPECTION_CALL_FAILED")
    if raw.get("inspection_json_safe") is False:
        if raw.get("inspection") is not None:
            return None
        return ("unknown", None, "INSPECTION_NOT_JSON_SAFE")
    if raw.get("inspection_json_safe") is not True:
        return None
    inspection = raw.get("inspection")
    try:
        inspection_copy = _safe_json_copy(inspection)
    except Exception:
        return None
    context = before.get("context")
    if not isinstance(context, Mapping):
        return None
    date_field = context.get("game_date")
    if not isinstance(date_field, Mapping) or date_field.get("present") is not True:
        return None
    inspect_error, admitted = _inspection_reason(
        inspection_copy, {"observer": request.get("observer"), "target": target,
                          "game_date": date_field.get("value")}
    )
    if inspect_error is not None:
        return ("unknown", None, inspect_error)
    return ("known", admitted,
            "NATIVE_SELECTOR_VISIBLE" if admitted else "NATIVE_SELECTOR_HIDDEN")


def read_scope(base_source: Any, context: Any, target: Any) -> dict[str, Any]:
    """Read the current native AI-acceptance selector state for observer -> target.

    The single inspection is read-only.  It does not issue a diplomatic action,
    and the returned admitted bit describes only the selector visibility used
    by the native acceptance-tooltip path.  It is not an observed UI render or
    a debt amount.
    """
    identity_before = _capture_identity_proof(base_source, context)
    preflight_error = _proof_preflight_error(identity_before)
    snapshot = None
    if preflight_error is None:
        snapshot, internal_error = _read_identity(base_source, context)
        preflight_error = internal_error
    target_copy = _json_value(target)

    def no_call(status: str, admitted: bool | None, reason: str,
                 *, tool_binding: Mapping[str, Any] | None = None) -> dict[str, Any]:
        identity_after = _capture_identity_proof(base_source, context)
        if preflight_error is None and not _typed_equal(identity_before, identity_after):
            status, admitted, reason = "unknown", None, "SOURCE_BINDING_DRIFTED"
        raw = _raw_envelope(target, identity_before, identity_after, tool_binding=tool_binding)
        return _result(status, admitted, reason, target=target_copy, raw_inputs=raw)

    if preflight_error is not None or snapshot is None:
        return no_call("unknown", None, preflight_error or "SOURCE_BINDING_INVALID")
    if not isinstance(target, str) or _TAG_RE.fullmatch(target) is None:
        return no_call("unknown", None, "TARGET_TAG_INVALID")
    snapshot["target"] = target
    if target in snapshot["controlled"]:
        return no_call("known", False, "TARGET_CONTROLLED_BY_HOST")

    try:
        tools = getattr(base_source, "diplomacy_tools", None)
        tools_present = tools is not None
        same_session = tools_present and getattr(tools, "session", None) is snapshot["session"]
        inspector = getattr(tools, "inspect_diplomatic_action", None) if tools_present else None
        inspector_callable = callable(inspector)
        tool_binding = {
            "tools_present": bool(tools_present),
            "session_matches": bool(same_session),
            "inspection_callable": bool(inspector_callable),
            "read_error": None,
        }
    except Exception as exc:
        tool_binding = {
            "tools_present": False, "session_matches": False,
            "inspection_callable": False, "read_error": type(exc).__name__,
        }
        return no_call("unknown", None, "DIPLOMACY_TOOLS_READ_FAILED",
                       tool_binding=tool_binding)
    if not tools_present or not same_session:
        return no_call("unknown", None, "DIPLOMACY_TOOLS_SESSION_MISMATCH",
                       tool_binding=tool_binding)
    if not inspector_callable:
        return no_call("unknown", None, "INSPECTION_TOOL_UNAVAILABLE",
                       tool_binding=tool_binding)
    snapshot["tools"] = tools

    call_error = None
    inspection = None
    try:
        inspection = inspector(_ACTION_ID, context["observer"], target, _PHASE, {})
    except Exception as exc:
        call_error = type(exc).__name__

    identity_after = _capture_identity_proof(base_source, context)
    stable = (_identity_still_stable(base_source, snapshot)
              and _typed_equal(identity_before, identity_after))
    if not stable:
        raw = _raw_envelope(
            target, identity_before, identity_after, tool_binding=tool_binding,
            runtime_identity_stable=False, inspection_error=call_error,
        )
        if call_error is None:
            try:
                safe = _safe_json_copy(inspection)
            except Exception:
                safe = None
                raw["inspection_json_safe"] = False
            else:
                raw["inspection"] = safe
                raw["inspection_json_safe"] = True
        return _result("unknown", None, "SOURCE_BINDING_DRIFTED",
                       native_inspection_calls=1, target=target_copy, raw_inputs=raw)
    if call_error is not None:
        raw = _raw_envelope(
            target, identity_before, identity_after, tool_binding=tool_binding,
            runtime_identity_stable=True, inspection_error=call_error,
        )
        return _result("unknown", None, "INSPECTION_CALL_FAILED",
                       native_inspection_calls=1, target=target_copy, raw_inputs=raw)

    try:
        inspection_copy = _safe_json_copy(inspection)
    except Exception:
        raw = _raw_envelope(
            target, identity_before, identity_after, tool_binding=tool_binding,
            runtime_identity_stable=True, inspection_json_safe=False,
        )
        return _result("unknown", None, "INSPECTION_NOT_JSON_SAFE",
                       native_inspection_calls=1, target=target_copy, raw_inputs=raw)

    raw = _raw_envelope(
        target, identity_before, identity_after, tool_binding=tool_binding,
        runtime_identity_stable=True, inspection=inspection_copy,
        inspection_json_safe=True,
    )
    validation_error, native_visibility = _inspection_reason(
        inspection_copy, {"observer": context["observer"], "target": target,
                          "game_date": snapshot["game_date"]}
    )
    if validation_error is not None:
        return _result("unknown", None, validation_error,
                       native_inspection_calls=1, target=target_copy, raw_inputs=raw)
    return _result("known", native_visibility,
                   "NATIVE_SELECTOR_VISIBLE" if native_visibility else "NATIVE_SELECTOR_HIDDEN",
                   native_inspection_calls=1, target=target_copy, raw_inputs=raw)


def validate_scope(record: Any) -> bool:
    """Purely validate a saved disclosure helper record; never query native code."""
    try:
        if not isinstance(record, Mapping) or set(record) != {
                "schema", "scope", "observer", "target", "game_date", "session_id",
                "creation_filetime", "status", "admitted", "reason",
                "native_inspection_calls", "actual_UI_render_observed", "raw_inputs"}:
            return False
        if (record.get("schema") != SCHEMA or record.get("scope") != SCOPE
                or record.get("actual_UI_render_observed") is not False
                ):
            return False
        expected = _expected_from_raw(record)
        if expected is None:
            return False
        status, admitted, reason = expected
        if record.get("status") != status or record.get("reason") != reason:
            return False
        if admitted is None:
            if record.get("admitted") is not None:
                return False
        elif type(record.get("admitted")) is not bool or record.get("admitted") is not admitted:
            return False
        count = record.get("native_inspection_calls")
        raw = record.get("raw_inputs")
        if type(count) is not int or count not in (0, 1) or not isinstance(raw, Mapping):
            return False
        if not _typed_equal(record.get("target"), _record_target(record)):
            return False
        top_identity = _top_identity_from_proof(raw.get("identity_before"))
        if (not _typed_equal(record.get("observer"), top_identity["observer"])
                or not _typed_equal(record.get("game_date"), top_identity["game_date"])
                or not _typed_equal(record.get("session_id"), top_identity["session_id"])
                or not _typed_equal(record.get("creation_filetime"), top_identity["creation_filetime"])):
            return False
        if status == "known":
            if (not _signed_i32(record.get("game_date"))
                    or not isinstance(record.get("session_id"), str)
                    or not record.get("session_id")
                    or type(record.get("creation_filetime")) is not int
                    or record.get("creation_filetime") < 0):
                return False
        if count == 1:
            tool_binding = raw.get("tool_binding")
            if (not isinstance(tool_binding, Mapping)
                    or tool_binding.get("tools_present") is not True
                    or tool_binding.get("session_matches") is not True
                    or tool_binding.get("inspection_callable") is not True):
                return False
        if count == 0 and raw.get("inspection") is not None:
            return False
        return True
    except Exception:
        return False
