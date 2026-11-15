"""Public whitelist projection for the bounded foreign-economy capture.

The private capture and its replay validator own process identity and raw
trace integrity.  This module validates the narrow DTOs needed by F03 and
never copies private addresses, pointer bindings, or raw traces to public
results.  It does not claim that a cached value was rendered in the UI.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from . import engine_dates
from . import foreign_economy_visibility_memory as _visibility
from . import foreign_loans_memory as _loans
from .foreign_technology import _country_view
from . import foreign_income_memory as _income
from . import bilateral_reparations_memory as _reparations_leaf
from . import bilateral_subsidies_memory as _subsidies_leaf
from . import observer_reparations_memory as _observer_reparations

TOPIC = "F03"
PUBLIC_FIELDS = ("income", "debt", "bankruptcy_risk", "reparations", "subsidies")
PRIVATE_VISIBILITY_FIELD = "F03.economy_visibility"
PAGE_INCOME = _visibility.INCOME_PAGE
PAGE_DEBT = _visibility.LOANS_PAGE
_PRIVATE_FIELD = {
    "income": _income.FIELD_INCOME,
    "debt": _loans.FIELD,
    "reparations": _income.FIELD_REPARATIONS,
    "subsidies": _income.FIELD_SUBSIDIES,
}
_PRIVATE_REPARATIONS_FIELD = _observer_reparations.FIELD
_PUBLIC_REPARATIONS_BASIS = "native_reparations_independent_scopes"
_PRIVATE_SUBSIDIES_FIELD = "F03.observer_subsidies"
_PUBLIC_SUBSIDIES_BASIS = "native_subsidies_independent_scopes"
_SUBSIDIES_PERMISSION_BASIS = "private_native_fra_own_fiscal_subsidy_pair"
_SUBSIDIES_PERMISSION_SCOPE = "observer_fiscal_bilateral_subsidies"
_PAIR_SCOPE = "observer_target_pair_only"
_FIELD_PAGE = {
    "income": PAGE_INCOME,
    "reparations": PAGE_INCOME,
    "subsidies": PAGE_INCOME,
    "debt": PAGE_DEBT,
}
_TAG = re.compile(r"[A-Z0-9]{3}\Z", re.ASCII)
_SAFE_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z", re.ASCII)
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_MAX_LOAN_RECORDS = 64


def _reason(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and _SAFE_REASON.fullmatch(value) else fallback


def _unknown(reason: Any, fallback: str = "ECONOMY_FIELD_UNKNOWN") -> dict[str, Any]:
    return {"status": "unknown", "reason": _reason(reason, fallback),
            "partial": True, "complete": False}


def _invisible(reason: str) -> dict[str, Any]:
    return {"status": "invisible", "reason": reason,
            "partial": True, "complete": False}


def _i32(value: Any) -> bool:
    return type(value) is int and _I32_MIN <= value <= _I32_MAX


def _strict_equal(left: Any, right: Any) -> bool:
    """Compare JSON DTOs without Python's bool/int equality shortcut."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (left.keys() == right.keys()
                and all(_strict_equal(left[key], right[key]) for key in left))
    if type(left) is list:
        return (len(left) == len(right)
                and all(_strict_equal(a, b) for a, b in zip(left, right)))
    if left is None or type(left) in (str, bool, int, float):
        return left == right
    return False


def _stable(item: Mapping[str, Any], field_id: str) -> bool:
    consistency = item.get("field_consistency")
    value = consistency.get(field_id) if isinstance(consistency, Mapping) else None
    return isinstance(value, Mapping) and value.get("status") == "stable"


def _page_permission(item: Mapping[str, Any], page: str) -> dict[str, Any]:
    if not _stable(item, PRIVATE_VISIBILITY_FIELD):
        return _unknown("ECONOMY_PAGE_PERMISSION_NOT_STABLE")
    fields = item.get("fields")
    record = fields.get(PRIVATE_VISIBILITY_FIELD) if isinstance(fields, Mapping) else None
    if (not isinstance(record, Mapping) or record.get("status") != "known"
            or record.get("basis") != _visibility.BASIS
            or record.get("partial") is not True or record.get("complete") is not False
            or not isinstance(record.get("raw_inputs"), Mapping)):
        return _unknown(_reason(record.get("reason") if isinstance(record, Mapping) else None,
                                "ECONOMY_PAGE_PERMISSION_INVALID"))
    value = record.get("value")
    if not isinstance(value, Mapping) or set(value) != set(_visibility.PAGES):
        return _unknown("ECONOMY_PAGE_PERMISSION_SHAPE_INVALID")
    permission = value.get(page)
    if not isinstance(permission, Mapping):
        return _unknown("ECONOMY_PAGE_PERMISSION_SHAPE_INVALID")
    if permission.get("status") != "known":
        return _unknown(_reason(permission.get("reason"), "ECONOMY_PAGE_PERMISSION_UNKNOWN"))
    admitted = permission.get("admitted")
    mode = permission.get("mode")
    valid_modes = ({"denied", "capital_flag_clear", "observer_high32_byte3_zero",
                    "observer_high32_byte2_seven", "capital_discovery_bitmap"}
                   if page == PAGE_INCOME else {"denied", "observer_lent_loans_candidate"})
    if (type(admitted) is not bool or not isinstance(mode, str)
            or mode not in valid_modes
            or (admitted is False and mode != "denied")
            or (admitted is True and mode == "denied")):
        return _unknown("ECONOMY_PAGE_PERMISSION_INVALID")
    return {"status": "known", "admitted": admitted}


def _known_record(item: Mapping[str, Any], name: str) -> tuple[Mapping[str, Any] | None, dict[str, Any] | None]:
    field_id = _PRIVATE_FIELD[name]
    if not _stable(item, field_id):
        return None, _unknown("ECONOMY_FIELD_NOT_STABLE")
    fields = item.get("fields")
    record = fields.get(field_id) if isinstance(fields, Mapping) else None
    if not isinstance(record, Mapping):
        return None, _unknown("ECONOMY_FIELD_MISSING")
    if record.get("status") != "known":
        return None, _unknown(_reason(record.get("reason"), "ECONOMY_FIELD_UNKNOWN"))
    if not isinstance(record.get("raw_inputs"), Mapping):
        return None, _unknown("ECONOMY_PRIVATE_EVIDENCE_MISSING")
    return record, None


def _check_field_metadata(record: Mapping[str, Any], *, basis: str,
                          unit: str, scale: int, period: str,
                          reference: str | None = None) -> bool:
    if (record.get("basis") != basis or record.get("unit") != unit
            or type(record.get("scale")) is not int or record.get("scale") != scale
            or record.get("period") != period or record.get("partial") is not True
            or record.get("complete") is not False):
        return False
    return reference is None or record.get("reference") == reference


def _public_amount(value: Any, *, unit: str, scale: int,
                   period: str, reference: str) -> dict[str, Any] | None:
    expected = {"value", "raw", "unit", "scale", "period", "reference"}
    if not isinstance(value, Mapping) or set(value) != expected:
        return None
    raw = value.get("raw")
    if (not _i32(raw) or type(value.get("value")) is not int or value.get("value") != raw
            or value.get("unit") != unit or type(value.get("scale")) is not int
            or value.get("scale") != scale or value.get("period") != period
            or value.get("reference") != reference):
        return None
    return {"value": raw / scale, "raw": raw, "unit": unit,
            "scale": scale, "period": period, "reference": reference}


def _project_income(record: Mapping[str, Any]) -> dict[str, Any]:
    if not _check_field_metadata(record, basis=_income.BASIS, unit="ducats",
                                 scale=1000, period="month", reference="previous_month"):
        return _unknown("INCOME_PRIVATE_FIELD_INVALID")
    value = record.get("value")
    if (not isinstance(value, Mapping)
            or set(value) != {"native_ledger_total", "visible_categories",
                              "total_includes_additional_native_terms"}
            or value.get("total_includes_additional_native_terms") is not True):
        return _unknown("INCOME_PRIVATE_VALUE_INVALID")
    total = _public_amount(value.get("native_ledger_total"), unit="ducats", scale=1000,
                           period="month", reference="previous_month")
    categories = value.get("visible_categories")
    if total is None or not isinstance(categories, list) or len(categories) != len(_income.VISIBLE_CATEGORY_KEYS):
        return _unknown("INCOME_PRIVATE_VALUE_INVALID")
    projected_categories = []
    for category, (index, key) in zip(categories, _income.VISIBLE_CATEGORY_KEYS):
        if (not isinstance(category, Mapping)
                or set(category) != {"index", "localization_key", "amount"}
                or type(category.get("index")) is not int or category.get("index") != index
                or category.get("localization_key") != key):
            return _unknown("INCOME_CATEGORY_SET_INVALID")
        amount = _public_amount(category.get("amount"), unit="ducats", scale=1000,
                                period="month", reference="previous_month")
        if amount is None:
            return _unknown("INCOME_CATEGORY_AMOUNT_INVALID")
        projected_categories.append({"index": index, "localization_key": key,
                                     "amount": amount})
    public_value = {"native_ledger_total": total,
                    "visible_categories": projected_categories,
                    "total_includes_additional_native_terms": True}
    return _known(public_value, unit="ducats", scale=1000, period="month",
                  reference="previous_month", basis=_income.BASIS)


def _unknown_obligation(value: Any) -> bool:
    return (isinstance(value, Mapping) and set(value) == {"status", "reason"}
            and value.get("status") == "unknown"
            and bool(_SAFE_REASON.fullmatch(value.get("reason", ""))))


def _project_received(record: Mapping[str, Any], *, index: int, label: str,
                      unknown_reasons: tuple[str, str]) -> dict[str, Any]:
    if not _check_field_metadata(record, basis=_income.BASIS, unit="ducats",
                                 scale=1000, period="month", reference="previous_month"):
        return _unknown(f"{label}_PRIVATE_FIELD_INVALID")
    value = record.get("value")
    if (not isinstance(value, Mapping)
            or set(value) != {"received_previous_month", "current_payment_obligations", "active_contracts"}
            or not _unknown_obligation(value.get("current_payment_obligations"))
            or not _unknown_obligation(value.get("active_contracts"))):
        return _unknown(f"{label}_OBLIGATION_SCOPE_INVALID")
    amount = _public_amount(value.get("received_previous_month"), unit="ducats", scale=1000,
                            period="month", reference="previous_month")
    if amount is None:
        return _unknown(f"{label}_RECEIVED_AMOUNT_INVALID")
    return _known({"received_previous_month": amount,
                   "current_payment_obligations": {"status": "unknown", "reason": unknown_reasons[0]},
                   "active_contracts": {"status": "unknown", "reason": unknown_reasons[1]}},
                  unit="ducats", scale=1000, period="month", reference="previous_month",
                  basis=_income.BASIS)


def _unknown_contract_component(reason: Any) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": _reason(reason, "OBSERVER_REPARATIONS_PRIVATE_FIELD_INVALID"),
        "scope": _PAIR_SCOPE,
        "unit": "bilateral_reparations_relation",
        "scale": 1,
        "period": "current",
        "complete_country_contracts": False,
        "visibility": {
            "scope": _observer_reparations.SCOPE,
            "basis": _observer_reparations.BASIS,
            "actual_UI_observed": False,
        },
    }


def _private_binding_matches(state_binding: Any, permission_binding: Any,
                             expected_tag: str) -> bool:
    fields = {"tag", "slot", "country_pointer", "fullref", "fullref_raw_hex"}
    return (
        isinstance(state_binding, Mapping) and isinstance(permission_binding, Mapping)
        and set(state_binding) == fields and set(permission_binding) == fields
        and state_binding.get("tag") == expected_tag
        and _strict_equal(dict(state_binding), dict(permission_binding))
    )


def _permission_pair_row_owners(permission: Mapping[str, Any]) -> bool:
    raw = permission.get("raw_inputs")
    rows = raw.get("pair_row_bindings") if isinstance(raw, Mapping) else None
    observer = permission.get("observer")
    target = permission.get("target")
    if (not isinstance(rows, list) or len(rows) != 2
            or not isinstance(observer, Mapping) or not isinstance(target, Mapping)):
        return False
    expected = []
    try:
        expected = [
            (hex(int(observer.get("country_pointer"), 0) + 0x14F8),
             observer.get("fullref"), target.get("fullref")),
            (hex(int(target.get("country_pointer"), 0) + 0x14F8),
             target.get("fullref"), observer.get("fullref")),
        ]
    except (TypeError, ValueError):
        return False
    for row, label, (owner, self_ref, other_ref) in zip(
            rows, ("observer_to_target", "target_to_observer"), expected):
        if (not isinstance(row, Mapping) or row.get("label") != label
                or row.get("status") != "known" or row.get("owner") != owner
                or row.get("expected_owner") != owner
                or row.get("self_fullref") != self_ref
                or row.get("other_fullref") != other_ref):
            return False
    return True


def _safe_contract_party(value: Any, permission_binding: Mapping[str, Any]) -> dict[str, str] | None:
    expected_keys = {"tag", "fullref", "fullref_raw_hex"}
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        return None
    tag = value.get("tag")
    fullref_text = value.get("fullref")
    raw_hex = value.get("fullref_raw_hex")
    if (tag != permission_binding.get("tag") or type(fullref_text) is not str
            or type(raw_hex) is not str or len(raw_hex) != 16
            or not re.fullmatch(r"[0-9a-fA-F]{16}", raw_hex, re.ASCII)):
        return None
    try:
        fullref = int(fullref_text, 0)
        raw_bytes = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if (not 0 <= fullref <= 0xFFFFFFFFFFFFFFFF
            or fullref_text != hex(fullref)
            or raw_bytes != fullref.to_bytes(8, "little")
            or fullref_text != permission_binding.get("fullref")
            or raw_hex.lower() != permission_binding.get("fullref_raw_hex")):
        return None
    return {"tag": tag}


def _safe_contract_date(value: Any) -> tuple[int, dict[str, Any]] | None:
    if (not isinstance(value, Mapping)
            or set(value) != {"raw", "unit", "scale", "calendar"}
            or value.get("unit") != "eu4_hour_tick"
            or type(value.get("scale")) is not int or value.get("scale") != 1):
        return None
    raw = value.get("raw")
    calendar = value.get("calendar")
    if not _i32(raw) or not isinstance(calendar, Mapping):
        return None
    try:
        expected = engine_dates.project_engine_date(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if not _strict_equal(dict(calendar), expected):
        return None
    safe_keys = ("status", "year_index", "month", "day", "date")
    if (expected.get("status") != "derived"
            or type(expected.get("year_index")) is not int
            or type(expected.get("month")) is not int
            or type(expected.get("day")) is not int
            or type(expected.get("date")) is not str
            or any(type(calendar.get(key)) is not type(expected[key])
                   or calendar.get(key) != expected[key] for key in safe_keys)):
        return None
    return raw, {key: expected[key] for key in safe_keys}


def _validate_reparations_contract_field(item: Mapping[str, Any], target: str
                                         ) -> dict[str, Any]:
    if not _stable(item, _PRIVATE_REPARATIONS_FIELD):
        return _unknown_contract_component("OBSERVER_REPARATIONS_FIELD_NOT_STABLE")
    fields = item.get("fields")
    record = fields.get(_PRIVATE_REPARATIONS_FIELD) if isinstance(fields, Mapping) else None
    if not isinstance(record, Mapping):
        return _unknown_contract_component("OBSERVER_REPARATIONS_FIELD_MISSING")
    if record.get("status") != "known":
        return _unknown_contract_component(record.get("reason"))
    if (not _check_field_metadata(
            record, basis=_observer_reparations.BASIS,
            unit="bilateral_reparations_relation", scale=1, period="current")
            or not isinstance(record.get("raw_inputs"), Mapping)):
        return _unknown_contract_component("OBSERVER_REPARATIONS_PRIVATE_FIELD_INVALID")

    raw_inputs = record["raw_inputs"]
    if set(raw_inputs) != {"permission", "state"}:
        return _unknown_contract_component("OBSERVER_REPARATIONS_PRIVATE_INPUTS_INVALID")
    permission = raw_inputs.get("permission")
    if (not isinstance(permission, Mapping)
            or not _observer_reparations.validate_permission(permission)
            or permission.get("schema") != _observer_reparations.SCHEMA
            or permission.get("basis") != _observer_reparations.BASIS
            or permission.get("scope") != _observer_reparations.SCOPE
            or permission.get("status") != "known"
            or permission.get("admitted") is not True
            or type(permission.get("admitted")) is not bool):
        return _unknown_contract_component("OBSERVER_REPARATIONS_PERMISSION_INVALID")
    observer_binding = permission.get("observer")
    target_binding = permission.get("target")
    if (not isinstance(observer_binding, Mapping)
            or not isinstance(target_binding, Mapping)
            or observer_binding.get("tag") != "FRA"
            or target_binding.get("tag") != target
            or target_binding.get("tag") == "FRA"):
        return _unknown_contract_component("OBSERVER_REPARATIONS_PAIR_INVALID")

    request = permission.get("raw_inputs", {}).get("request")
    world = permission.get("raw_inputs", {}).get("world")
    if (not isinstance(request, Mapping) or type(request.get("module_base")) is not int
            or not isinstance(world, Mapping)):
        return _unknown_contract_component("OBSERVER_REPARATIONS_PERMISSION_CONTEXT_INVALID")
    observed_date = world.get("date_raw_i32")
    if (not _i32(observed_date)
            or type(world.get("fresh_date_raw_i32")) is not int
            or world.get("fresh_date_raw_i32") != observed_date
            or world.get("pointer") != world.get("fresh_pointer")):
        return _unknown_contract_component("OBSERVER_REPARATIONS_DATE_INVALID")
    if not _permission_pair_row_owners(permission):
        return _unknown_contract_component("OBSERVER_REPARATIONS_PAIR_ROW_INVALID")

    state = raw_inputs.get("state")
    if (not isinstance(state, Mapping)
            or state.get("schema") != _reparations_leaf.SCHEMA
            or state.get("basis") != _reparations_leaf.BASIS
            or state.get("status") != "known"
            or state.get("partial") is not True
            or state.get("complete") is not False
            or state.get("complete_country_contracts") is not False
            or not _strict_equal(record.get("value"), state.get("contract"))):
        return _unknown_contract_component("OBSERVER_REPARATIONS_STATE_INVALID")
    state_raw = state.get("raw_inputs")
    observed_pair = state.get("observed_pair")
    if (not isinstance(state_raw, Mapping)
            or state_raw.get("module_base") != hex(request["module_base"])
            or type(state_raw.get("date_raw")) is not int
            or state_raw.get("date_raw") != observed_date
            or not isinstance(observed_pair, Mapping)
            or observed_pair.get("fullref_echo_verified") is not True
            or not _private_binding_matches(observed_pair.get("observer"),
                                            observer_binding, "FRA")
            or not _private_binding_matches(observed_pair.get("target"),
                                            target_binding, target)):
        return _unknown_contract_component("OBSERVER_REPARATIONS_STATE_BINDING_INVALID")
    directions = state_raw.get("pair_directions")
    if not isinstance(directions, list) or len(directions) != 2:
        return _unknown_contract_component("OBSERVER_REPARATIONS_PAIR_DIRECTIONS_INVALID")
    expected_directions = (
        ("observer_to_target", observer_binding, target_binding),
        ("target_to_observer", target_binding, observer_binding),
    )
    read_trace = state_raw.get("ordered_read_trace")
    if not isinstance(read_trace, list):
        return _unknown_contract_component("OBSERVER_REPARATIONS_PAIR_TRACE_INVALID")
    for direction, (label, subject, other) in zip(directions, expected_directions):
        try:
            expected_owner = hex(int(subject.get("country_pointer"), 0) + 0x14F8)
        except (TypeError, ValueError):
            return _unknown_contract_component("OBSERVER_REPARATIONS_PAIR_OWNER_INVALID")
        row_label = f"pair.{label}.row"
        row_traces = [row for row in read_trace
                      if isinstance(row, Mapping) and row.get("label") == row_label]
        if (not isinstance(direction, Mapping) or direction.get("label") != label
                or direction.get("owner") != expected_owner or len(row_traces) != 1
                or row_traces[0].get("status") != "ok"
                or row_traces[0].get("decode") != "pair_row"
                or row_traces[0].get("owner") != expected_owner
                or row_traces[0].get("self_fullref") != subject.get("fullref")
                or row_traces[0].get("other_fullref") != other.get("fullref")):
            return _unknown_contract_component("OBSERVER_REPARATIONS_PAIR_OWNER_INVALID")

    contract = record.get("value")
    if not isinstance(contract, Mapping):
        return _unknown_contract_component("OBSERVER_REPARATIONS_CONTRACT_INVALID")
    if contract.get("status") == "absent":
        if (set(contract) != {"status", "present", "scope", "reason",
                              "active_payment_obligation", "payment_amount"}
                or contract.get("present") is not False
                or contract.get("scope") != "explicit_observer_target_pair_only"
                or contract.get("reason") != "NO_MATCHING_PAIR_ENTRY"
                or not _unknown_obligation(contract.get("active_payment_obligation"))
                or contract["active_payment_obligation"].get("reason") != "PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED"
                or not _unknown_obligation(contract.get("payment_amount"))
                or contract["payment_amount"].get("reason") != "PAYMENT_AMOUNT_OR_PERCENTAGE_NOT_CAPTURED"):
            return _unknown_contract_component("OBSERVER_REPARATIONS_ABSENCE_INVALID")
        return {
            "status": "known", "scope": _PAIR_SCOPE,
            "unit": "bilateral_reparations_relation", "scale": 1,
            "period": "current",
            "complete_country_contracts": False,
            "pair_relation": {"status": "known", "present": False},
            "contracts": [],
            "visibility": {"scope": _observer_reparations.SCOPE,
                           "basis": _observer_reparations.BASIS,
                           "actual_UI_observed": False},
        }

    expected_present_keys = {
        "status", "present", "payer", "claimant", "start_date", "end_date",
        "date_window_contains_observed_date", "active_payment_obligation",
        "payment_amount", "relation_flag_0x28",
    }
    if (set(contract) != expected_present_keys or contract.get("status") != "known"
            or contract.get("present") is not True
            or not _unknown_obligation(contract.get("active_payment_obligation"))
            or contract["active_payment_obligation"].get("reason") != "PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED"
            or not _unknown_obligation(contract.get("payment_amount"))
            or contract["payment_amount"].get("reason") != "PAYMENT_AMOUNT_OR_PERCENTAGE_NOT_CAPTURED"
            or not _unknown_obligation(contract.get("relation_flag_0x28"))
            or contract["relation_flag_0x28"].get("reason") != "RELATION_FLAG_0X28_SEMANTICS_UNCLOSED"):
        return _unknown_contract_component("OBSERVER_REPARATIONS_CONTRACT_INVALID")

    payer_value = contract.get("payer")
    claimant_value = contract.get("claimant")
    payer_tag = payer_value.get("tag") if isinstance(payer_value, Mapping) else None
    claimant_tag = claimant_value.get("tag") if isinstance(claimant_value, Mapping) else None
    payer = _safe_contract_party(payer_value,
        observer_binding if payer_tag == "FRA" else target_binding)
    claimant = _safe_contract_party(claimant_value,
        observer_binding if claimant_tag == "FRA" else target_binding)
    if (payer is None or claimant is None or payer["tag"] == claimant["tag"]
            or {payer["tag"], claimant["tag"]} != {"FRA", target}):
        return _unknown_contract_component("OBSERVER_REPARATIONS_PARTIES_INVALID")
    start = _safe_contract_date(contract.get("start_date"))
    end = _safe_contract_date(contract.get("end_date"))
    contains = contract.get("date_window_contains_observed_date")
    if (start is None or end is None or end[0] <= start[0] or type(contains) is not bool
            or contains != (start[0] <= observed_date < end[0])):
        return _unknown_contract_component("OBSERVER_REPARATIONS_DATE_WINDOW_INVALID")
    return {
        "status": "known", "scope": _PAIR_SCOPE,
        "unit": "bilateral_reparations_relation", "scale": 1,
        "period": "current",
        "complete_country_contracts": False,
        "pair_relation": {"status": "known", "present": True},
        "contracts": [{
            "payer": payer, "claimant": claimant,
            "start_date": {"calendar": start[1]},
            "end_date": {"calendar": end[1]},
            "date_window_contains_observed_date": contains,
        }],
        "visibility": {"scope": _observer_reparations.SCOPE,
                       "basis": _observer_reparations.BASIS,
                       "actual_UI_observed": False},
    }


def _unknown_subsidies_contract_component(reason: Any) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": _reason(reason, "OBSERVER_SUBSIDIES_PRIVATE_FIELD_INVALID"),
        "scope": _PAIR_SCOPE,
        "unit": "bilateral_subsidies_relation",
        "scale": 1,
        "period": "current",
        "complete_country_contracts": False,
        "visibility": {
            "scope": _SUBSIDIES_PERMISSION_SCOPE,
            "basis": _SUBSIDIES_PERMISSION_BASIS,
            "actual_UI_observed": False,
        },
    }


def _safe_subsidy_calendar(raw: Any, raw_hex: Any, calendar: Any
                           ) -> tuple[int, dict[str, Any]] | None:
    if (not _i32(raw) or type(raw_hex) is not str
            or raw_hex != raw.to_bytes(4, "little", signed=True).hex()
            or not isinstance(calendar, Mapping)):
        return None
    try:
        expected = engine_dates.project_engine_date(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if not _strict_equal(dict(calendar), expected):
        return None
    safe_keys = ("status", "year_index", "month", "day", "date")
    if (expected.get("status") != "derived"
            or type(expected.get("year_index")) is not int
            or type(expected.get("month")) is not int
            or type(expected.get("day")) is not int
            or type(expected.get("date")) is not str):
        return None
    return raw, {key: expected[key] for key in safe_keys}


def _signed32_wrap(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _known_unknown_status(value: Any, reason: str) -> bool:
    return (isinstance(value, Mapping) and set(value) == {"status", "reason"}
            and value.get("status") == "unknown" and value.get("reason") == reason)


def _validate_subsidies_contract_field(item: Mapping[str, Any], target: str
                                       ) -> dict[str, Any]:
    """Validate and whitelist the FRA/target subsidy relation component.

    The public output is built from a short allowlist. The private field and
    permission adapter are imported lazily so risk-only queries and source
    imports do not depend on an adapter that may still be under development.
    """
    try:
        from . import observer_subsidies_memory as _observer_subsidies
    except ImportError:
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PERMISSION_ADAPTER_UNAVAILABLE")

    if not _stable(item, _PRIVATE_SUBSIDIES_FIELD):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_FIELD_NOT_STABLE")
    fields = item.get("fields")
    record = fields.get(_PRIVATE_SUBSIDIES_FIELD) if isinstance(fields, Mapping) else None
    if not isinstance(record, Mapping):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_FIELD_MISSING")
    if record.get("status") != "known":
        return _unknown_subsidies_contract_component(record.get("reason"))
    if (not _check_field_metadata(
            record, basis=_observer_subsidies.BASIS,
            unit="bilateral_subsidies_relation", scale=1, period="current")
            or not isinstance(record.get("raw_inputs"), Mapping)):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PRIVATE_FIELD_INVALID")

    raw_inputs = record["raw_inputs"]
    if set(raw_inputs) != {"permission", "state"}:
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PRIVATE_INPUTS_INVALID")
    permission = raw_inputs.get("permission")
    if (not isinstance(permission, Mapping)
            or not callable(getattr(_observer_subsidies, "validate_permission", None))
            or not _observer_subsidies.validate_permission(permission)
            or permission.get("schema") != _observer_subsidies.SCHEMA
            or permission.get("basis") != _observer_subsidies.BASIS
            or permission.get("scope") != _observer_subsidies.SCOPE
            or permission.get("status") != "known"
            or permission.get("admitted") is not True
            or type(permission.get("admitted")) is not bool):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PERMISSION_INVALID")

    observer_binding = permission.get("observer")
    target_binding = permission.get("target")
    if (not isinstance(observer_binding, Mapping)
            or not isinstance(target_binding, Mapping)
            or observer_binding.get("tag") != "FRA"
            or target_binding.get("tag") != target
            or target_binding.get("tag") == "FRA"):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PAIR_INVALID")

    permission_inputs = permission.get("raw_inputs")
    request = permission_inputs.get("request") if isinstance(permission_inputs, Mapping) else None
    world = permission_inputs.get("world") if isinstance(permission_inputs, Mapping) else None
    if (not isinstance(request, Mapping) or type(request.get("module_base")) is not int
            or not isinstance(world, Mapping)):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PERMISSION_CONTEXT_INVALID")
    observed_date = world.get("date_raw_i32")
    if (not _i32(observed_date)
            or type(world.get("fresh_date_raw_i32")) is not int
            or world.get("fresh_date_raw_i32") != observed_date
            or world.get("pointer") != world.get("fresh_pointer")):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_DATE_INVALID")
    if not _permission_pair_row_owners(permission):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PAIR_ROW_INVALID")

    state = raw_inputs.get("state")
    if (not isinstance(state, Mapping)
            or state.get("schema") != _subsidies_leaf.SCHEMA
            or state.get("basis") != _subsidies_leaf.BASIS
            or state.get("status") != "known"
            or state.get("partial") is not True
            or state.get("complete") is not False
            or state.get("complete_country_contracts") is not False
            or state.get("visibility_evaluated") is not False
            or not _strict_equal(record.get("value"), state.get("contract"))):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_STATE_INVALID")

    state_raw = state.get("raw_inputs")
    observed_pair = state.get("observed_pair")
    if (not isinstance(state_raw, Mapping)
            or state_raw.get("module_base") != hex(request["module_base"])
            or not isinstance(observed_pair, Mapping)
            or observed_pair.get("fullref_echo_verified") is not True
            or not _private_binding_matches(observed_pair.get("observer"),
                                            observer_binding, "FRA")
            or not _private_binding_matches(observed_pair.get("target"),
                                            target_binding, target)
            or not isinstance(state_raw.get("bindings"), Mapping)
            or not _private_binding_matches(state_raw["bindings"].get("observer"),
                                            observer_binding, "FRA")
            or not _private_binding_matches(state_raw["bindings"].get("target"),
                                            target_binding, target)):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_STATE_BINDING_INVALID")

    directions = state_raw.get("pair_directions")
    read_trace = state_raw.get("ordered_read_trace")
    if not isinstance(directions, list) or len(directions) != 2 or not isinstance(read_trace, list):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PAIR_TRACE_INVALID")
    expected_directions = (
        ("observer_to_target", observer_binding, target_binding),
        ("target_to_observer", target_binding, observer_binding),
    )
    for direction, (label, subject, other) in zip(directions, expected_directions):
        try:
            expected_owner = hex(int(subject.get("country_pointer"), 0) + 0x14F8)
        except (TypeError, ValueError):
            return _unknown_subsidies_contract_component(
                "OBSERVER_SUBSIDIES_PAIR_OWNER_INVALID")
        expected_row_label = f"pair.{label}.row"
        row_traces = [row for row in read_trace
                      if isinstance(row, Mapping) and row.get("label") == expected_row_label]
        if (not isinstance(direction, Mapping) or direction.get("label") != label
                or direction.get("owner") != expected_owner
                or direction.get("self_fullref") != subject.get("fullref")
                or direction.get("other_fullref") != other.get("fullref")
                or type(other.get("slot")) is not int
                or direction.get("other_slot_signed16") != hex(other.get("slot"))
                or len(row_traces) != 1 or row_traces[0].get("status") != "ok"
                or row_traces[0].get("decode") != "subsidy_pair_row"
                or row_traces[0].get("owner") != expected_owner
                or row_traces[0].get("expected_owner") != expected_owner
                or row_traces[0].get("self_fullref") != subject.get("fullref")
                or row_traces[0].get("other_fullref") != other.get("fullref")):
            return _unknown_subsidies_contract_component(
                "OBSERVER_SUBSIDIES_PAIR_OWNER_INVALID")

    contract = state.get("contract")
    if not isinstance(contract, Mapping) or contract.get("scope") != "explicit_observer_target_pair_only":
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_CONTRACT_INVALID")
    observer_tag = "FRA"
    target_tag = target
    if contract.get("status") == "absent":
        if (set(contract) != {"status", "present", "scope", "reason",
                              "active_payment_obligation", "relation_flag_0x28"}
                or contract.get("present") is not False
                or contract.get("reason") != "NO_MATCHING_PAIR_ENTRY"
                or not _known_unknown_status(
                    contract.get("active_payment_obligation"),
                    "SUBSIDY_PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED")
                or not _known_unknown_status(
                    contract.get("relation_flag_0x28"),
                    "SUBSIDY_FLAG_0X28_SEMANTICS_UNCLOSED")):
            return _unknown_subsidies_contract_component(
                "OBSERVER_SUBSIDIES_ABSENCE_INVALID")
        result = _subsidies_pair_result(
            present=False, contracts=[], scope=_observer_subsidies.SCOPE,
            basis=_observer_subsidies.BASIS)
        vectors = state_raw.get("owner_vectors")
        if not _subsidies_vectors_match(vectors, expected_directions, present=False):
            return _unknown_subsidies_contract_component(
                "OBSERVER_SUBSIDIES_ABSENCE_VECTOR_INVALID")
        return result

    expected_contract_keys = {
        "status", "present", "scope", "payer", "recipient", "observer_role",
        "monthly_nominal_amount", "start_date", "duration_years", "displayed_end_date",
        "active_payment_obligation", "relation_flag_0x28", "term_legality",
    }
    if (set(contract) != expected_contract_keys or contract.get("status") != "known"
            or contract.get("present") is not True
            or not _known_unknown_status(
                contract.get("active_payment_obligation"),
                "SUBSIDY_PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED")
            or not _known_unknown_status(
                contract.get("relation_flag_0x28"), "SUBSIDY_FLAG_0X28_SEMANTICS_UNCLOSED")
            or not _known_unknown_status(
                contract.get("term_legality"), "SUBSIDY_AMOUNT_OR_DURATION_LEGALITY_NOT_CAPTURED")):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_CONTRACT_INVALID")

    payer_value = contract.get("payer")
    recipient_value = contract.get("recipient")
    payer_tag = payer_value.get("tag") if isinstance(payer_value, Mapping) else None
    recipient_tag = recipient_value.get("tag") if isinstance(recipient_value, Mapping) else None
    payer = _safe_contract_party(
        payer_value, observer_binding if payer_tag == observer_tag else target_binding)
    recipient = _safe_contract_party(
        recipient_value, observer_binding if recipient_tag == observer_tag else target_binding)
    if (payer is None or recipient is None or payer["tag"] == recipient["tag"]
            or {payer["tag"], recipient["tag"]} != {observer_tag, target_tag}
            or contract.get("observer_role") != ("payer" if payer["tag"] == observer_tag else "recipient")):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PARTIES_INVALID")

    amount_value = contract.get("monthly_nominal_amount")
    if (not isinstance(amount_value, Mapping)
            or set(amount_value) != {"raw", "value", "unit", "scale", "period", "basis"}):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_AMOUNT_INVALID")
    amount_raw = amount_value.get("raw")
    if (not _i32(amount_raw) or type(amount_value.get("value")) is not float
            or amount_value.get("value") != amount_raw / 1000.0
            or amount_value.get("unit") != "ducats"
            or type(amount_value.get("scale")) is not int or amount_value.get("scale") != 1000
            or amount_value.get("period") != "month"
            or amount_value.get("basis") != "native_subsidy_object_monthly_amount"):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_AMOUNT_INVALID")

    start_value = contract.get("start_date")
    if (not isinstance(start_value, Mapping)
            or set(start_value) != {"raw", "raw_hex", "unit", "scale", "calendar"}
            or start_value.get("unit") != "eu4_hour_tick"
            or type(start_value.get("scale")) is not int or start_value.get("scale") != 1):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_START_DATE_INVALID")
    start = _safe_subsidy_calendar(
        start_value.get("raw"), start_value.get("raw_hex"), start_value.get("calendar"))
    if start is None or start[0] == _subsidies_leaf.SUBSIDY_START_DATE_SENTINEL:
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_START_DATE_INVALID")

    duration_value = contract.get("duration_years")
    if (not isinstance(duration_value, Mapping)
            or set(duration_value) != {"raw", "raw_hex", "unit", "scale"}
            or not _i32(duration_value.get("raw"))
            or duration_value.get("raw_hex") != duration_value["raw"].to_bytes(4, "little", signed=True).hex()
            or duration_value.get("unit") != "years"
            or type(duration_value.get("scale")) is not int or duration_value.get("scale") != 1):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_DURATION_INVALID")

    end_value = contract.get("displayed_end_date")
    expected_end_keys = {"raw", "raw_hex", "unit", "scale", "calendar", "derivation"}
    if (not isinstance(end_value, Mapping) or set(end_value) != expected_end_keys
            or end_value.get("unit") != "eu4_hour_tick"
            or type(end_value.get("scale")) is not int or end_value.get("scale") != 1):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_END_DATE_INVALID")
    end = _safe_subsidy_calendar(
        end_value.get("raw"), end_value.get("raw_hex"), end_value.get("calendar"))
    duration_raw = duration_value["raw"]
    ticks_per_year = _subsidies_leaf.TICKS_PER_SUBSIDY_YEAR
    product_raw = _signed32_wrap(duration_raw * ticks_per_year)
    expected_end_raw = _signed32_wrap(start[0] + product_raw)
    derivation = end_value.get("derivation")
    expected_derivation = {
        "status": "derived_from_native_tooltip_date_composition",
        "formula": "signed32_wrap(start_raw + signed32_wrap(duration_years_raw * 8760))",
        "duration_product_raw_i32": product_raw,
        "ticks_per_subsidy_year": ticks_per_year,
        "intermediate_and_final_wrap": "low_32_bits_interpreted_as_signed_i32",
        "static_evidence_id": "ev_e0253c163eeb06480ec3c8f15e82a5a8530c3ca7676d03f6fc30a0bbc84ef581",
    }
    if (end is None or end[0] != expected_end_raw
            or not _strict_equal(dict(derivation) if isinstance(derivation, Mapping) else derivation,
                                 expected_derivation)):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_END_DATE_INVALID")

    vectors = state_raw.get("owner_vectors")
    if not _subsidies_vectors_match(vectors, expected_directions, present=True):
        return _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PAIR_VECTOR_INVALID")

    safe_contract = {
        "payer": payer,
        "recipient": recipient,
        "observer_role": contract["observer_role"],
        "monthly_nominal_amount": {
            "raw": amount_raw, "value": amount_raw / 1000.0,
            "unit": "ducats", "scale": 1000, "period": "month",
        },
        "start_date": {"calendar": start[1]},
        "duration_years": {
            "raw": duration_raw, "value": duration_raw,
            "unit": "years", "scale": 1,
        },
        "displayed_end_date": {
            "calendar": end[1],
            "derivation": {
                "status": "derived",
                "formula": "signed32_wrap(start + signed32_wrap(years * 8760))",
                "ticks_per_subsidy_year": ticks_per_year,
            },
        },
        "active_payment_obligation": {
            "status": "unknown", "reason": "SUBSIDY_PAYMENT_OBLIGATION_SEMANTICS_NOT_CAPTURED"},
        "relation_flag": {
            "status": "unknown", "reason": "SUBSIDY_RELATION_FLAG_SEMANTICS_UNCLOSED"},
        "term_legality": {
            "status": "unknown", "reason": "SUBSIDY_AMOUNT_OR_DURATION_LEGALITY_NOT_CAPTURED"},
    }
    return _subsidies_pair_result(
        present=True, contracts=[safe_contract], scope=_observer_subsidies.SCOPE,
        basis=_observer_subsidies.BASIS)


def _subsidies_pair_result(*, present: bool, contracts: list[dict[str, Any]],
                           scope: str, basis: str) -> dict[str, Any]:
    return {
        "status": "known",
        "scope": _PAIR_SCOPE,
        "unit": "bilateral_subsidies_relation",
        "scale": 1,
        "period": "current",
        "complete_country_contracts": False,
        "pair_relation": {"status": "known", "present": present},
        "contracts": contracts,
        "visibility": {"scope": scope, "basis": basis,
                       "actual_UI_observed": False},
    }


def _subsidies_vectors_match(vectors: Any,
                             expected_directions: tuple[tuple[str, Mapping[str, Any], Mapping[str, Any]], ...],
                             *, present: bool) -> bool:
    if not isinstance(vectors, list) or len(vectors) != 2:
        return False
    target_pointers = []
    for vector, (label, subject, other) in zip(vectors, expected_directions):
        try:
            owner = int(subject.get("country_pointer"), 0) + 0x14F8
            expected_row = int(vector.get("row_address"), 0)
            vector_base = int(vector.get("vector_base"), 0)
            data_pointer = int(vector.get("data_pointer"), 0)
        except (TypeError, ValueError, AttributeError):
            return False
        capacity, count = vector.get("capacity"), vector.get("count")
        matches, target_slot = vector.get("target_match_count"), vector.get("target_slot_signed16")
        if (not isinstance(vector, Mapping) or vector.get("label") != label
                or vector.get("owner") != hex(owner)
                or vector_base != owner + 0x108
                or not _i32(capacity) or not _i32(count)
                or not 0 <= count <= capacity <= 4096
                or type(matches) is not int or matches not in (0, 1)
                or type(target_slot) is not int or target_slot != other.get("slot")):
            return False
        pointer_text = vector.get("target_pointer")
        if matches == 0:
            if pointer_text is not None:
                return False
        else:
            if type(pointer_text) is not str:
                return False
            try:
                pointer_value = int(pointer_text, 0)
            except ValueError:
                return False
            if pointer_value <= 0:
                return False
            target_pointers.append(pointer_value)
        if data_pointer == 0 and (capacity != 0 or count != 0):
            return False
        if data_pointer != 0 and capacity == 0:
            return False
    if present:
        return all(v.get("target_match_count") == 1 for v in vectors) and len(target_pointers) == 2 and target_pointers[0] == target_pointers[1]
    return all(v.get("target_match_count") == 0 for v in vectors) and not target_pointers


def _received_reparations_component(item: Mapping[str, Any],
                                    permission: Mapping[str, Any]) -> dict[str, Any]:
    if permission.get("status") != "known":
        return _unknown(permission.get("reason"), "REPARATIONS_RECEIVED_PERMISSION_UNKNOWN")
    if permission.get("admitted") is False:
        return _invisible("ECONOMY_PAGE_PREDICATE_REJECTED_FOR_OBSERVER")
    record, failure = _known_record(item, "reparations")
    if failure is not None or record is None:
        return failure or _unknown("REPARATIONS_RECEIVED_FIELD_UNKNOWN")
    try:
        projected = _project_received(record, index=_income.REPARATIONS_INDEX,
            label="REPARATIONS", unknown_reasons=("CURRENT_REPARATION_OBLIGATIONS_NOT_CAPTURED",
                                                  "ACTIVE_REPARATION_CONTRACTS_NOT_CAPTURED"))
    except Exception:
        return _unknown("REPARATIONS_RECEIVED_PRIVATE_FIELD_INVALID")
    if projected.get("status") != "known":
        return projected
    amount = projected.get("value", {}).get("received_previous_month")
    if not isinstance(amount, Mapping):
        return _unknown("REPARATIONS_RECEIVED_AMOUNT_INVALID")
    return {"status": "known", **dict(amount)}


def _component_status(record: Mapping[str, Any]) -> dict[str, str]:
    status = record.get("status")
    if status not in ("known", "unknown", "invisible"):
        return {"status": "unknown", "reason": "ECONOMY_COMPONENT_STATUS_INVALID"}
    result = {"status": status}
    reason = record.get("reason")
    if type(reason) is str:
        result["reason"] = _reason(reason, "ECONOMY_COMPONENT_UNKNOWN")
    return result


def _reparations_visibility(view: Mapping[str, Any],
                            received_permission: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "country_view": dict(view),
        "received_previous_month": {
            "page": PAGE_INCOME,
            "page_permission": _page_permission_public(received_permission),
            "basis": _visibility.BASIS,
        },
        "observer_involved_contracts": {
            "scope": _observer_reparations.SCOPE,
            "basis": _observer_reparations.BASIS,
            "actual_UI_observed": False,
        },
    }


def _received_subsidies_component(item: Mapping[str, Any],
                                 permission: Mapping[str, Any]) -> dict[str, Any]:
    if permission.get("status") != "known":
        return _unknown(permission.get("reason"), "SUBSIDIES_RECEIVED_PERMISSION_UNKNOWN")
    if permission.get("admitted") is False:
        return _invisible("ECONOMY_PAGE_PREDICATE_REJECTED_FOR_OBSERVER")
    record, failure = _known_record(item, "subsidies")
    if failure is not None or record is None:
        return failure or _unknown("SUBSIDIES_RECEIVED_FIELD_UNKNOWN")
    try:
        projected = _project_received(record, index=_income.SUBSIDIES_INDEX,
            label="SUBSIDIES", unknown_reasons=("CURRENT_PAYMENT_OBLIGATIONS_NOT_CAPTURED",
                                                "TARGET_COMPLETE_ACTIVE_CONTRACTS_NOT_ESTABLISHED"))
    except Exception:
        return _unknown("SUBSIDIES_RECEIVED_PRIVATE_FIELD_INVALID")
    if projected.get("status") != "known":
        return projected
    amount = projected.get("value", {}).get("received_previous_month")
    if not isinstance(amount, Mapping):
        return _unknown("SUBSIDIES_RECEIVED_AMOUNT_INVALID")
    return {"status": "known", **dict(amount)}


def _subsidies_visibility(view: Mapping[str, Any],
                          received_permission: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "country_view": dict(view),
        "received_previous_month": {
            "page": PAGE_INCOME,
            "page_permission": _page_permission_public(received_permission),
            "basis": _visibility.BASIS,
        },
        "observer_involved_contracts": {
            "scope": _SUBSIDIES_PERMISSION_SCOPE,
            "basis": _SUBSIDIES_PERMISSION_BASIS,
            "actual_UI_observed": False,
        },
    }


def _project_reparations(item: Mapping[str, Any], target: str,
                         view: Mapping[str, Any]) -> dict[str, Any]:
    try:
        received_permission = _page_permission(item, PAGE_INCOME)
    except Exception:
        received_permission = _unknown("REPARATIONS_RECEIVED_PERMISSION_UNKNOWN")
    try:
        received = _received_reparations_component(item, received_permission)
    except Exception:
        received = _unknown("REPARATIONS_RECEIVED_PRIVATE_FIELD_INVALID")
    try:
        contracts = _validate_reparations_contract_field(item, target)
    except Exception:
        contracts = _unknown_contract_component("OBSERVER_REPARATIONS_PRIVATE_FIELD_INVALID")
    visibility = _reparations_visibility(view, received_permission)
    if received.get("status") != "known" and contracts.get("status") != "known":
        return {
            "status": "unknown",
            "reason": "NO_REPARATIONS_COMPONENT_AVAILABLE",
            "partial": True,
            "complete": False,
            "component_statuses": {
                "received_previous_month": _component_status(received),
                "observer_involved_contracts": _component_status(contracts),
            },
            "visibility": visibility,
        }
    public_value = {
        "received_previous_month": received,
        "observer_involved_contracts": contracts,
        "current_payment_obligations": {
            "status": "unknown", "reason": "CURRENT_REPARATION_OBLIGATIONS_NOT_CAPTURED"},
        "active_contracts": {
            "status": "unknown", "reason": "ACTIVE_REPARATION_CONTRACTS_NOT_CAPTURED"},
    }
    result = _known(public_value, unit="reparations_information", scale=1,
                    period="mixed", basis=_PUBLIC_REPARATIONS_BASIS)
    result["visibility"] = visibility
    return result


def _project_subsidies(item: Mapping[str, Any], target: str,
                       view: Mapping[str, Any]) -> dict[str, Any]:
    try:
        received_permission = _page_permission(item, PAGE_INCOME)
    except Exception:
        received_permission = _unknown("SUBSIDIES_RECEIVED_PERMISSION_UNKNOWN")
    try:
        received = _received_subsidies_component(item, received_permission)
    except Exception:
        received = _unknown("SUBSIDIES_RECEIVED_PRIVATE_FIELD_INVALID")
    try:
        contracts = _validate_subsidies_contract_field(item, target)
    except Exception:
        contracts = _unknown_subsidies_contract_component(
            "OBSERVER_SUBSIDIES_PRIVATE_FIELD_INVALID")
    visibility = _subsidies_visibility(view, received_permission)
    if received.get("status") != "known" and contracts.get("status") != "known":
        return {
            "status": "unknown",
            "reason": "NO_SUBSIDIES_COMPONENT_AVAILABLE",
            "partial": True,
            "complete": False,
            "component_statuses": {
                "received_previous_month": _component_status(received),
                "observer_involved_contracts": _component_status(contracts),
            },
            "visibility": visibility,
        }
    public_value = {
        "received_previous_month": received,
        "observer_involved_contracts": contracts,
        "current_payment_obligations": {
            "status": "unknown", "reason": "CURRENT_PAYMENT_OBLIGATIONS_NOT_CAPTURED"},
        "active_contracts": {
            "status": "unknown", "reason": "TARGET_COMPLETE_ACTIVE_CONTRACTS_NOT_ESTABLISHED"},
    }
    result = _known(public_value, unit="subsidies_information", scale=1,
                    period="mixed", basis=_PUBLIC_SUBSIDIES_BASIS)
    result["visibility"] = visibility
    return result


def _known(value: Any, *, unit: str, scale: int, period: str,
           basis: str, reference: str | None = None) -> dict[str, Any]:
    result = {"status": "known", "value": value, "unit": unit, "scale": scale,
              "period": period, "basis": basis, "partial": True, "complete": False}
    if reference is not None:
        result["reference"] = reference
    return result


def _amount_record(value: Any, *, unit: str, scale: int) -> dict[str, Any] | None:
    if (not isinstance(value, Mapping) or set(value) != {"status", "raw", "value", "unit", "scale"}
            or value.get("status") != "known"):
        return None
    raw = value.get("raw")
    if (not _i32(raw) or type(value.get("value")) is not int or value.get("value") != raw
            or value.get("unit") != unit or type(value.get("scale")) is not int
            or value.get("scale") != scale):
        return None
    return {"value": raw / scale, "raw": raw, "unit": unit, "scale": scale}


def _due_record(value: Any) -> dict[str, Any] | None:
    if (not isinstance(value, Mapping)
            or set(value) != {"status", "raw", "raw_hex", "unit", "scale", "calendar"}
            or value.get("status") != "known" or value.get("unit") != "eu4_hour_tick"
            or type(value.get("scale")) is not int or value.get("scale") != 1):
        return None
    raw = value.get("raw")
    raw_hex = value.get("raw_hex")
    if (not _i32(raw) or not isinstance(raw_hex, str) or len(raw_hex) != 8
            or not re.fullmatch(r"[0-9a-fA-F]{8}", raw_hex, re.ASCII)
            or raw_hex.lower() != (raw & 0xFFFFFFFF).to_bytes(4, "little").hex()):
        return None
    try:
        calendar = engine_dates.project_engine_date(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if (not isinstance(calendar, Mapping) or calendar.get("status") != "derived"
            or type(calendar.get("year_index")) is not int
            or type(calendar.get("month")) is not int or type(calendar.get("day")) is not int
            or not isinstance(calendar.get("date"), str)):
        return None
    return {"raw": raw, "raw_hex": raw_hex.lower(), "unit": "eu4_hour_tick", "scale": 1,
            "calendar": {"status": "derived", "year_index": calendar["year_index"],
                         "month": calendar["month"], "day": calendar["day"],
                         "date": calendar["date"]}}


def _project_debt(record: Mapping[str, Any], target: str) -> dict[str, Any]:
    if (record.get("status") != "known" or record.get("basis") != _loans.BASIS
            or record.get("partial") is not True or record.get("complete") is not False
            or record.get("unit") != "observed_loan_records"
            or type(record.get("scale")) is not int or record.get("scale") != 1
            or record.get("period") != "current" or not isinstance(record.get("raw_inputs"), Mapping)):
        return _unknown("DEBT_PRIVATE_FIELD_INVALID")
    value = record.get("value")
    if (not isinstance(value, Mapping) or set(value) != {"total_debt", "loans_to_observer"}
            or not isinstance(value.get("total_debt"), Mapping)
            or value["total_debt"].get("status") != "unknown"
            or "value" in value["total_debt"]):
        return _unknown("DEBT_PRIVATE_VALUE_INVALID")
    subset = value.get("loans_to_observer")
    if (not isinstance(subset, Mapping) or subset.get("status") != "known"
            or set(subset) != {"status", "records", "record_count", "coverage",
                              "observed_principal_sum", "complete_country_debt"}
            or subset.get("coverage") != "observer_lent_loans_only"
            or subset.get("complete_country_debt") is not False):
        return _unknown("DEBT_OBSERVER_SUBSET_INVALID")
    records = subset.get("records")
    count = subset.get("record_count")
    if (not isinstance(records, list) or len(records) > _MAX_LOAN_RECORDS
            or type(count) is not int or count != len(records)):
        return _unknown("DEBT_RECORD_COUNT_INVALID")
    projected_records = []
    ordinals = set()
    principal_sum = 0
    for loan in records:
        if (not isinstance(loan, Mapping)
                or set(loan) != {"lender", "borrower", "principal", "interest", "due", "source_list_ordinal"}
                or loan.get("lender") != "FRA" or loan.get("borrower") != target
                or type(loan.get("source_list_ordinal")) is not int
                or loan.get("source_list_ordinal") < 0
                or loan.get("source_list_ordinal") in ordinals):
            return _unknown("DEBT_RECORD_IDENTITY_INVALID")
        ordinals.add(loan["source_list_ordinal"])
        principal = _amount_record(loan.get("principal"), unit="ducats", scale=1)
        interest = _amount_record(loan.get("interest"), unit="percent", scale=1000)
        due = _due_record(loan.get("due"))
        if principal is None or interest is None or due is None:
            return _unknown("DEBT_RECORD_VALUE_INVALID")
        principal_sum += principal["raw"]
        projected_records.append({"lender": "FRA", "borrower": target,
                                  "principal": principal, "interest": interest, "due": due})
    sum_record = subset.get("observed_principal_sum")
    if (not isinstance(sum_record, Mapping)
            or set(sum_record) != {"status", "raw", "value", "unit", "scale"}
            or sum_record.get("status") != "known"
            or type(sum_record.get("raw")) is not int
            or type(sum_record.get("value")) is not int
            or sum_record.get("raw") != principal_sum
            or sum_record.get("value") != principal_sum
            or sum_record.get("unit") != "ducats"
            or type(sum_record.get("scale")) is not int or sum_record.get("scale") != 1):
        return _unknown("DEBT_OBSERVED_SUM_INVALID")
    public = {"total_debt": {"status": "unknown", "reason": "TOTAL_FOREIGN_DEBT_NOT_ESTABLISHED"},
              "loans_to_observer": {"status": "known", "records": projected_records,
                                    "record_count": count,
                                    "coverage": "observer_lent_loans_only",
                                    "observed_principal_sum": {
                                        "status": "known", "value": principal_sum,
                                        "raw": principal_sum, "unit": "ducats", "scale": 1},
                                    "complete_country_debt": False}}
    return _known(public, unit="observed_loan_records", scale=1,
                  period="current", basis=_loans.BASIS)


def _public_risk() -> dict[str, Any]:
    return _unknown("NATIVE_BANKRUPTCY_RISK_AND_FOREIGN_VISIBILITY_NOT_ESTABLISHED")


def _country_view_public(value: Any) -> dict[str, Any]:
    if (isinstance(value, Mapping) and value.get("status") == "known"
            and type(value.get("admitted")) is bool):
        return {"status": "known", "admitted": value["admitted"]}
    reason = value.get("reason") if isinstance(value, Mapping) else None
    return {"status": "unknown", "reason": _reason(reason, "COUNTRY_VIEW_ADMISSION_UNKNOWN")}


def _page_permission_public(value: Any) -> dict[str, Any]:
    if (isinstance(value, Mapping) and value.get("status") == "known"
            and type(value.get("admitted")) is bool):
        return {"status": "known", "admitted": value["admitted"]}
    reason = value.get("reason") if isinstance(value, Mapping) else None
    return {"status": "unknown", "reason": _reason(reason, "ECONOMY_PAGE_PERMISSION_UNKNOWN")}


def _with_visibility(field: Mapping[str, Any], *, country_view: Mapping[str, Any],
                     page: str, page_permission: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(field)
    result["visibility"] = {
        "country_view": dict(country_view),
        "page": page,
        "page_permission": dict(page_permission),
        "basis": _visibility.BASIS,
    }
    return result


def failure_field(name: str, reason: Any) -> dict[str, Any]:
    """Return a fail-closed public field with no inferred permission."""
    if name == "bankruptcy_risk":
        return _public_risk()
    if name == "debt":
        from . import foreign_debt_projection
        return foreign_debt_projection.failure_field(reason)
    if name == "reparations":
        safe_reason = _reason(reason, "REPARATIONS_FIELD_UNKNOWN")
        return {
            "status": "unknown", "reason": safe_reason,
            "partial": True, "complete": False,
            "component_statuses": {
                "received_previous_month": {"status": "unknown", "reason": safe_reason},
                "observer_involved_contracts": {"status": "unknown", "reason": safe_reason},
            },
            "visibility": {"country_view": {"status": "unknown", "reason": safe_reason}},
        }
    if name == "subsidies":
        safe_reason = _reason(reason, "SUBSIDIES_FIELD_UNKNOWN")
        return {
            "status": "unknown", "reason": safe_reason,
            "partial": True, "complete": False,
            "component_statuses": {
                "received_previous_month": {"status": "unknown", "reason": safe_reason},
                "observer_involved_contracts": {"status": "unknown", "reason": safe_reason},
            },
            "visibility": {"country_view": {"status": "unknown", "reason": safe_reason}},
        }
    page = _FIELD_PAGE.get(name)
    if page is None:
        return _unknown(reason)
    safe_reason = _reason(reason, "ECONOMY_FIELD_UNKNOWN")
    return _with_visibility(
        _unknown(safe_reason),
        country_view={"status": "unknown", "reason": safe_reason},
        page=page,
        page_permission={"status": "unknown",
                         "reason": "NOT_EVALUATED_COUNTRY_VIEW_NOT_ADMITTED"},
    )


def project(item: Any, target: str, requested: list[str] | tuple[str, ...], *,
            debt_scope: Any = None) -> dict[str, dict[str, Any]]:
    """Project selected F03 fields using independent page scopes.

    ``item`` is one strict-capture backend target.  The capture validator and
    parent own raw trace replay, installation identity, role, ROM and session.
    """
    if not isinstance(item, Mapping) or not isinstance(target, str) or not _TAG.fullmatch(target):
        return {field: failure_field(field, "ECONOMY_CAPTURE_TARGET_INVALID") for field in requested}
    view = _country_view_public(_country_view(item))
    result: dict[str, dict[str, Any]] = {}
    for name in requested:
        if name == "bankruptcy_risk":
            result[name] = _public_risk()
            continue
        page = _FIELD_PAGE.get(name)
        if page is None:
            result[name] = failure_field(name, "ECONOMY_FIELD_UNSUPPORTED")
            continue
        not_evaluated = {"status": "unknown",
                         "reason": "NOT_EVALUATED_COUNTRY_VIEW_NOT_ADMITTED"}
        if view.get("status") != "known":
            if name == "debt":
                from . import foreign_debt_projection
                result[name] = foreign_debt_projection.failure_field(
                    view.get("reason", "COUNTRY_VIEW_ADMISSION_UNKNOWN"), view)
                continue
            if name in ("reparations", "subsidies"):
                result[name] = _unknown(view.get("reason", "COUNTRY_VIEW_ADMISSION_UNKNOWN"))
                result[name]["visibility"] = {"country_view": view}
                continue
            result[name] = _with_visibility(
                _unknown(view.get("reason", "COUNTRY_VIEW_ADMISSION_UNKNOWN")),
                country_view=view, page=page, page_permission=not_evaluated)
            continue
        if view.get("admitted") is False:
            if name == "debt":
                result[name] = _invisible("COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER")
                result[name]["visibility"] = {"country_view": view}
                continue
            if name in ("reparations", "subsidies"):
                result[name] = _invisible("COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER")
                result[name]["visibility"] = {"country_view": view}
                continue
            result[name] = _with_visibility(
                _invisible("COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER"),
                country_view=view, page=page, page_permission=not_evaluated)
            continue
        if name == "reparations":
            result[name] = _project_reparations(item, target, view)
            continue
        if name == "subsidies":
            result[name] = _project_subsidies(item, target, view)
            continue
        if name == "debt":
            from . import foreign_debt_projection
            result[name] = foreign_debt_projection.project(
                item, target, view, scope_record=debt_scope)
            continue
        permission = _page_permission(item, page)
        page_public = _page_permission_public(permission)
        if permission.get("status") != "known":
            result[name] = _with_visibility(
                _unknown(page_public.get("reason", "ECONOMY_PAGE_PERMISSION_UNKNOWN")),
                country_view=view, page=page, page_permission=page_public)
            continue
        if permission.get("admitted") is False:
            result[name] = _with_visibility(
                _invisible("ECONOMY_PAGE_PREDICATE_REJECTED_FOR_OBSERVER"),
                country_view=view, page=page, page_permission=page_public)
            continue
        record, failure = _known_record(item, name)
        if failure is not None or record is None:
            result[name] = _with_visibility(failure or _unknown("ECONOMY_FIELD_UNKNOWN"),
                country_view=view, page=page, page_permission=page_public)
            continue
        try:
            if name == "income":
                projected = _project_income(record)
            elif name == "debt":
                projected = _project_debt(record, target)
            else:
                projected = _project_received(record, index=_income.SUBSIDIES_INDEX,
                    label="SUBSIDIES",
                    unknown_reasons=("CURRENT_SUBSIDY_OBLIGATIONS_NOT_CAPTURED",
                                     "ACTIVE_SUBSIDY_CONTRACTS_NOT_CAPTURED"))
            result[name] = _with_visibility(projected, country_view=view,
                page=page, page_permission=page_public)
        except Exception:
            result[name] = _with_visibility(_unknown("ECONOMY_FIELD_PROJECTION_FAILED"),
                country_view=view, page=page, page_permission=page_public)
    return result


__all__ = ["TOPIC", "PUBLIC_FIELDS", "PRIVATE_VISIBILITY_FIELD", "PAGE_INCOME", "PAGE_DEBT",
           "project", "failure_field"]
