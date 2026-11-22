"""Public projection for v34 target-principal and independent foreign-debt scopes.

This module keeps the historic observer-lent-loan subset and adds a separately
validated native principal amount. It never exposes private permission records,
memory traces, pointers, or full country references.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from . import foreign_debt_disclosure as _disclosure
from . import foreign_debt_principal_memory as _leaf
from . import target_debt_principal_memory_v34 as _principal_adapter


FIELD = "debt"
PUBLIC_BASIS = "native_debt_independent_scopes"
TOTAL_SCOPE = _disclosure.SCOPE
_OBSERVER = "FRA"
_TAG = re.compile(r"[A-Z0-9]{3}\Z", re.ASCII)
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1


def _base_module():
    # The main economy projection will import this module on its debt branch.
    # Resolve it only when called so that importing the main module stays acyclic.
    from . import foreign_economy_projection_v7
    return foreign_economy_projection_v7


def _safe_reason(base: Any, value: Any, fallback: str) -> str:
    return base._reason(value, fallback)


def _component_status(base: Any, value: Mapping[str, Any]) -> dict[str, Any]:
    status = value.get("status")
    if status not in ("known", "unknown", "invisible"):
        status = "unknown"
    result = {"status": status}
    if status != "known":
        result["reason"] = _safe_reason(base, value.get("reason"),
                                        "DEBT_COMPONENT_UNKNOWN")
    return result


def _permission_status(base: Any, value: Any, fallback: str) -> dict[str, Any]:
    if (isinstance(value, Mapping) and value.get("status") == "known"
            and type(value.get("admitted")) is bool):
        return {"status": "known", "admitted": value["admitted"]}
    reason = value.get("reason") if isinstance(value, Mapping) else None
    return {"status": "unknown", "reason": _safe_reason(base, reason, fallback)}


def _unknown_component(base: Any, reason: Any, fallback: str) -> dict[str, Any]:
    return base._unknown(_safe_reason(base, reason, fallback))


def _visibility(base: Any, country_view: Mapping[str, Any],
                scope_permission: Mapping[str, Any],
                page_permission: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "country_view": dict(country_view),
        "components": {
            "total_debt": {
                "scope": TOTAL_SCOPE,
                "permission": dict(scope_permission),
            },
            "loans_to_observer": {
                "page": base.PAGE_DEBT,
                "permission": dict(page_permission),
            },
        },
        "basis": PUBLIC_BASIS,
    }


def _assemble(base: Any, total: Mapping[str, Any], subset: Mapping[str, Any],
              country_view: Mapping[str, Any], scope_permission: Mapping[str, Any],
              page_permission: Mapping[str, Any]) -> dict[str, Any]:
    value = {
        "total_debt": dict(total),
        "loans_to_observer": dict(subset),
    }
    statuses = {
        "total_debt": _component_status(base, total),
        "loans_to_observer": _component_status(base, subset),
    }
    if any(component["status"] == "known" for component in statuses.values()):
        result = base._known(value, unit="debt_information", scale=1,
                             period="current", basis=PUBLIC_BASIS)
    else:
        reasons = [component.get("reason") for component in statuses.values()
                   if component.get("reason")]
        result = base._unknown(
            reasons[0] if reasons else "NO_DEBT_COMPONENT_AVAILABLE")
        result.update({"unit": "debt_information", "scale": 1,
                       "period": "current", "basis": PUBLIC_BASIS})
    result["component_statuses"] = statuses
    result["visibility"] = _visibility(
        base, country_view, scope_permission, page_permission)
    return result


def failure_field(reason: Any, country_view: Any = None) -> dict[str, Any]:
    """Return a public unknown debt field without a value or private evidence."""
    base = _base_module()
    safe_reason = _safe_reason(base, reason, "FOREIGN_DEBT_PROJECTION_FAILED")
    view = base._country_view_public(country_view)
    component = base._unknown(safe_reason)
    unknown_permission = {"status": "unknown", "reason": safe_reason}
    result = _assemble(base, component, component, view,
                       unknown_permission, unknown_permission)
    result.pop("value", None)
    result["status"] = "unknown"
    result["reason"] = safe_reason
    return result


def _scope_gate(base: Any, scope_record: Any, target: str,
                expected_date: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    fallback = "DEBT_DISCLOSURE_SCOPE_UNKNOWN"
    if not isinstance(scope_record, Mapping):
        reason = "DEBT_DISCLOSURE_SCOPE_MISSING"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    try:
        valid = _disclosure.validate_scope(scope_record)
    except Exception:
        valid = False
    if not valid:
        reason = "DEBT_DISCLOSURE_SCOPE_INVALID"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    status = scope_record.get("status")
    admitted = scope_record.get("admitted")
    if (scope_record.get("schema") != _disclosure.SCHEMA
            or scope_record.get("scope") != _disclosure.SCOPE
            or scope_record.get("observer") != _OBSERVER
            or scope_record.get("target") != target
            or type(scope_record.get("game_date")) is not int
            or type(expected_date) is not int
            or not _I32_MIN <= expected_date <= _I32_MAX
            or scope_record.get("game_date") != expected_date):
        reason = "DEBT_DISCLOSURE_SCOPE_BINDING_OR_DATE_MISMATCH"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    permission = {"status": status, "admitted": admitted}
    if status == "known" and admitted is True:
        return {"status": "known", "admitted": True}, permission
    if status == "known" and admitted is False:
        reason = _safe_reason(base, scope_record.get("reason"),
                              "DEBT_DISCLOSURE_SCOPE_NOT_ADMITTED")
        return base._invisible(reason), permission
    reason = _safe_reason(base, scope_record.get("reason"), fallback)
    return base._unknown(reason), {"status": "unknown", "reason": reason}


def _binding_matches(permission: Mapping[str, Any], state: Mapping[str, Any],
                     base_address: int) -> bool:
    permission_raw = permission.get("raw_inputs")
    request = permission_raw.get("request") if isinstance(permission_raw, Mapping) else None
    state_raw = state.get("raw_inputs")
    if not isinstance(request, Mapping) or not isinstance(state_raw, Mapping):
        return False
    if (type(request.get("module_base")) is not int
            or request["module_base"] != base_address
            or state_raw.get("module_base") != hex(base_address)):
        return False
    for role in ("observer", "target"):
        observed = state_raw.get("bindings")
        observed_binding = observed.get(role) if isinstance(observed, Mapping) else None
        permitted = permission.get(role)
        if not isinstance(observed_binding, Mapping) or not isinstance(permitted, Mapping):
            return False
        expected = {key: permitted.get(key) for key in (
            "tag", "slot", "country_pointer", "fullref", "fullref_raw_hex")}
        if not _principal_adapter._strict_equal(dict(observed_binding), expected):
            return False
        request_binding = request.get(f"{role}_binding")
        if not isinstance(request_binding, Mapping):
            return False
        if (request_binding.get("tag") != permitted.get("tag")
                or type(request_binding.get("slot")) is not int
                or request_binding.get("slot") != permitted.get("slot")
                or request_binding.get("country_pointer") != permitted.get("country_pointer")
                or request_binding.get("fullref") != permitted.get("fullref")
                or request_binding.get("fullref_raw_hex") != permitted.get("fullref_raw_hex")):
            return False
    return True


def _replay_total_state(permission: Mapping[str, Any], state: Any,
                        target: str, base: Any) -> tuple[dict[str, Any] | None, str | None]:
    if (not _principal_adapter.validate_permission(permission)
            or permission.get("status") != "known"
            or permission.get("admitted") is not True
            or permission.get("basis") != _principal_adapter.BASIS
            or permission.get("scope") != _principal_adapter.SCOPE
            or not isinstance(permission.get("observer"), Mapping)
            or permission["observer"].get("tag") != _OBSERVER
            or not isinstance(permission.get("target"), Mapping)
            or permission["target"].get("tag") != target):
        return None, "DEBT_PRINCIPAL_PERMISSION_INVALID"
    raw_permission = permission.get("raw_inputs")
    request = raw_permission.get("request") if isinstance(raw_permission, Mapping) else None
    world = raw_permission.get("world") if isinstance(raw_permission, Mapping) else None
    expected_date = world.get("date_raw_i32") if isinstance(world, Mapping) else None
    if (not isinstance(request, Mapping) or type(request.get("module_base")) is not int
            or type(expected_date) is not int or not _I32_MIN <= expected_date <= _I32_MAX):
        return None, "DEBT_PRINCIPAL_PERMISSION_CONTEXT_INVALID"
    if (not isinstance(state, Mapping) or state.get("schema") != _leaf.SCHEMA
            or state.get("status") != "known"
            or state.get("basis") != _leaf.BASIS
            or state.get("complete_loan_list") is not True
            or state.get("publication_admitted") is not False
            or not isinstance(state.get("value"), Mapping)
            or not isinstance(state.get("raw_inputs"), Mapping)):
        return None, "DEBT_PRINCIPAL_STATE_INVALID"
    trace = state["raw_inputs"].get("ordered_read_trace")
    if not isinstance(trace, list) or len(trace) > _leaf.MAX_READ_CALLS:
        return None, "DEBT_PRINCIPAL_TRACE_LIMIT"
    byte_count = 0
    for row in trace:
        if (not isinstance(row, Mapping) or type(row.get("size")) is not int
                or not 0 < row["size"] <= _leaf.MAX_SINGLE_READ_BYTES
                or not isinstance(row.get("raw_hex"), str)
                or len(row["raw_hex"]) != row["size"] * 2):
            return None, "DEBT_PRINCIPAL_TRACE_INVALID"
        byte_count += row["size"]
    if byte_count > _leaf.MAX_TOTAL_READ_BYTES:
        return None, "DEBT_PRINCIPAL_TRACE_LIMIT"
    base_address = request["module_base"]
    observer_binding = request.get("observer_binding")
    target_binding = request.get("target_binding")
    if (not isinstance(observer_binding, Mapping) or not isinstance(target_binding, Mapping)
            or not _binding_matches(permission, state, base_address)):
        return None, "DEBT_PRINCIPAL_BINDING_MISMATCH"
    replay = _principal_adapter._ReplayReader(trace)
    try:
        derived = _leaf.read_state(replay, base_address,
                                   observer_binding, target_binding)
    except Exception:
        return None, "DEBT_PRINCIPAL_STATE_REPLAY_FAILED"
    if (replay.index != len(trace)
            or not base._strict_equal(state, derived)):
        return None, "DEBT_PRINCIPAL_STATE_REPLAY_MISMATCH"
    return dict(state["value"]), None


def _total_component(base: Any, item: Any, target: str,
                     scope_record: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    unknown = base._unknown("DEBT_PRINCIPAL_FIELD_UNKNOWN")
    unknown_permission = {"status": "unknown", "reason": "DEBT_SCOPE_NOT_EVALUATED"}
    if not isinstance(item, Mapping):
        return unknown, unknown_permission
    field_id = _principal_adapter.FIELD
    if not base._stable(item, field_id):
        reason = "DEBT_PRINCIPAL_FIELD_NOT_STABLE"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    fields = item.get("fields")
    record = fields.get(field_id) if isinstance(fields, Mapping) else None
    if not isinstance(record, Mapping) or record.get("status") != "known":
        reason = _safe_reason(base,
            record.get("reason") if isinstance(record, Mapping) else None,
            "DEBT_PRINCIPAL_FIELD_UNKNOWN")
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    if (set(record) != {"status", "basis", "scope", "partial", "complete", "unit",
                        "scale", "period", "publication_admitted", "raw_inputs", "value"}
            or record.get("basis") != _principal_adapter.BASIS
            or record.get("scope") != _principal_adapter.SCOPE
            or record.get("partial") is not True
            or record.get("complete") is not False
            or record.get("unit") != "loan_principal_totals"
            or type(record.get("scale")) is not int or record.get("scale") != 1
            or record.get("period") != "current"
            or record.get("publication_admitted") is not False
            or not isinstance(record.get("raw_inputs"), Mapping)):
        reason = "DEBT_PRINCIPAL_PRIVATE_DTO_INVALID"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    raw_inputs = record["raw_inputs"]
    permission = raw_inputs.get("permission")
    state = raw_inputs.get("state")
    if (set(raw_inputs) != {"permission", "state"}
            or not isinstance(state, Mapping)
            or not base._strict_equal(record.get("value"), state.get("value"))):
        reason = "DEBT_PRINCIPAL_PRIVATE_VALUE_MISMATCH"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    if (not _principal_adapter.validate_permission(permission)
            or not isinstance(permission, Mapping)
            or permission.get("status") != "known"
            or permission.get("admitted") is not True
            or permission.get("basis") != _principal_adapter.BASIS
            or permission.get("scope") != _principal_adapter.SCOPE
            or not isinstance(permission.get("observer"), Mapping)
            or permission["observer"].get("tag") != _OBSERVER
            or not isinstance(permission.get("target"), Mapping)
            or permission["target"].get("tag") != target):
        reason = "DEBT_PRINCIPAL_PERMISSION_INVALID"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    permission_raw = permission.get("raw_inputs")
    world = permission_raw.get("world") if isinstance(permission_raw, Mapping) else None
    expected_date = world.get("date_raw_i32") if isinstance(world, Mapping) else None
    if type(expected_date) is not int or not _I32_MIN <= expected_date <= _I32_MAX:
        reason = "DEBT_PRINCIPAL_PERMISSION_DATE_INVALID"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    scope_component, public_scope_permission = _scope_gate(
        base, scope_record, target, expected_date)
    if scope_component.get("status") != "known":
        return scope_component, public_scope_permission
    private_value, replay_error = _replay_total_state(permission, state, target, base)
    if replay_error is not None or not isinstance(private_value, Mapping):
        reason = replay_error or "DEBT_PRINCIPAL_STATE_INVALID"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    amount = private_value.get("diplomatic_principal_total")
    if (not isinstance(amount, Mapping)
            or set(amount) != {"status", "raw", "value", "unit", "scale",
                               "signed_bits", "overflowed", "arithmetic"}
            or amount.get("status") != "known"
            or type(amount.get("raw")) is not int
            or not _I32_MIN <= amount["raw"] <= _I32_MAX
            or type(amount.get("value")) is not float
            or amount["value"] != amount["raw"] / 1000.0
            or amount.get("unit") != "ducats"
            or type(amount.get("scale")) is not int or amount.get("scale") != 1000
            or type(amount.get("signed_bits")) is not int or amount["signed_bits"] != 32
            or type(amount.get("overflowed")) is not bool
            or amount.get("arithmetic") != "signed32_wrap_each_principal_times_1000_then_signed32_add"):
        reason = "DEBT_PRINCIPAL_AMOUNT_INVALID"
        return base._unknown(reason), {"status": "unknown", "reason": reason}
    return {
        "status": "known",
        "raw": amount["raw"],
        "value": amount["value"],
        "unit": "ducats",
        "scale": 1000,
        "signed_bits": 32,
        "overflowed": amount["overflowed"],
        "basis": "native_diplomatic_loan_principal_sum",
        "includes_remaining_interest": False,
    }, public_scope_permission


def _subset_component(base: Any, item: Any, target: str, observer: str
                      ) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = base._page_permission(item, base.PAGE_DEBT)
    public_permission = base._page_permission_public(permission)
    if permission.get("status") != "known":
        return base._unknown(public_permission.get(
            "reason", "ECONOMY_PAGE_PERMISSION_UNKNOWN")), public_permission
    if permission.get("admitted") is False:
        return base._invisible("ECONOMY_PAGE_PREDICATE_REJECTED_FOR_OBSERVER"), public_permission
    record, failure = base._known_record(item, "debt")
    if failure is not None or record is None:
        return failure or base._unknown("ECONOMY_FIELD_UNKNOWN"), public_permission
    try:
        projected = base._project_debt(record, target, observer)
    except Exception:
        return base._unknown("OBSERVER_LOAN_SUBSET_PROJECTION_FAILED"), public_permission
    if projected.get("status") != "known" or not isinstance(projected.get("value"), Mapping):
        reason = _safe_reason(base, projected.get("reason"), "OBSERVER_LOAN_SUBSET_UNKNOWN")
        return base._unknown(reason), public_permission
    subset = projected["value"].get("loans_to_observer")
    if not isinstance(subset, Mapping):
        return base._unknown("OBSERVER_LOAN_SUBSET_INVALID"), public_permission
    return dict(subset), public_permission


def project(item: Any, target: str, country_view: Any,
            *, scope_record: Any = None, observer: str = _OBSERVER) -> dict[str, Any]:
    """Project visible total principal and observer-lent subset independently."""
    base = _base_module()
    try:
        view = base._country_view_public(country_view)
        if (not isinstance(target, str) or not _TAG.fullmatch(target)
                or not isinstance(observer, str) or not _TAG.fullmatch(observer) or target == observer):
            return failure_field("DEBT_PROJECTION_TARGET_INVALID", view)
        if view.get("status") != "known":
            reason = _safe_reason(base, view.get("reason"),
                                  "COUNTRY_VIEW_ADMISSION_UNKNOWN")
            unknown = base._unknown(reason)
            permission = {"status": "unknown", "reason": "COUNTRY_VIEW_NOT_ADMITTED"}
            return _assemble(base, unknown, unknown, view, permission, permission)
        if view.get("admitted") is False:
            hidden = base._invisible("COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER")
            permission = {"status": "unknown", "reason": "COUNTRY_VIEW_NOT_ADMITTED"}
            return _assemble(base, hidden, hidden, view, permission, permission)
        if observer == _OBSERVER:
            total, scope_permission = _total_component(base, item, target, scope_record)
        else:
            reason = "DEBT_PRIVATE_TOTAL_OBSERVER_EVIDENCE_UNAVAILABLE"
            total = base._unknown(reason)
            scope_permission = {"status": "unknown", "reason": reason}
        subset, page_permission = _subset_component(base, item, target, observer)
        return _assemble(base, total, subset, view, scope_permission, page_permission)
    except Exception:
        return failure_field("FOREIGN_DEBT_PROJECTION_FAILED", country_view)


__all__ = ["FIELD", "PUBLIC_BASIS", "TOTAL_SCOPE", "project", "failure_field"]
