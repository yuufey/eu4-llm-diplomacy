"""Public projection of four previous-month war-related ledger slots.

The projection validates the existing monthly-economy capture, then exposes
only four signed income slots whose native cache labels are documented.  It
does not infer a native total, current receipts, or attribution to a specific
war.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from . import monthly_economy_memory as _monthly


FIELD = "N01.war_income"
SCHEMA = "information.n01.war_income_projection.v1"
BASIS = "native_previous_month_war_related_income_slots"
UNIT = "war_income_information"
PERIOD = "month"
REFERENCE_PERIOD = "previous_month"
SCALE = 1
_AMOUNT_SCALE = 1000
_LEDGER_SIZE = 228
_INCOME_COUNT = 19
_COMPONENT_WIDTH = 4
_LEDGER_OFFSET = 0x770
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_RAW_HEX = re.compile(r"[0-9a-f]{456}\Z", re.ASCII)

# (public component name, income slot, native cache key)
_COMPONENTS = (
    ("war_reparations", 8, "INCOME_WAR_REPARATION"),
    ("spoils_of_war", 12, "SPOILS_OF_WAR_ECOVIEW"),
    ("blockades", 17, "INC_BLOCKADES"),
    ("looting", 18, "INC_LOOTING"),
)


def _unknown(reason: str) -> dict[str, Any]:
    """Return a public unknown without a consumable value."""
    return {
        "status": "unknown",
        "reason": reason,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "reference_period": REFERENCE_PERIOD,
        "basis": BASIS,
        "partial": True,
        "complete": False,
    }


def _i32(value: Any) -> bool:
    return type(value) is int and _I32_MIN <= value <= _I32_MAX


def _capture_inputs(record: Any) -> tuple[list[int], str | None]:
    """Check the bounded DTO shape before invoking the strict leaf validator."""
    if not isinstance(record, Mapping) or record.get("status") != "observed":
        return [], "MONTHLY_ECONOMY_CAPTURE_NOT_OBSERVED"

    expected_profile = _monthly.EXPECTED_PROFILE_SHA256
    observation = record.get("observation")
    static_guard = record.get("static_contract_guard")
    if not isinstance(observation, Mapping) or not isinstance(static_guard, Mapping):
        return [], "MONTHLY_ECONOMY_PROFILE_PROOF_MISSING"
    profile_id = static_guard.get("profile_id")
    if (
        not isinstance(expected_profile, str)
        or record.get("profile_sha256") != expected_profile
        or record.get("basis") != _monthly.BASIS
        or record.get("reference_period") != _monthly.REFERENCE_PERIOD
        or record.get("period") != _monthly.PERIOD
        or record.get("unit") != _monthly.UNIT
        or record.get("scale") != _monthly.SCALE
        or observation.get("profile_sha256") != expected_profile
        or observation.get("profile_id") != profile_id
        or static_guard.get("profile_sha256") != expected_profile
        or record.get("value_semantics") != _monthly.VALUE_SEMANTICS
        or observation.get("basis") != _monthly.BASIS
        or observation.get("reference_period") != _monthly.REFERENCE_PERIOD
        or observation.get("period") != _monthly.PERIOD
        or observation.get("unit") != _monthly.UNIT
        or observation.get("scale") != _monthly.SCALE
        or observation.get("value_semantics") != _monthly.VALUE_SEMANTICS
    ):
        return [], "MONTHLY_ECONOMY_PROFILE_OR_PERIOD_MISMATCH"

    raw_hex = record.get("raw_ledger_hex")
    ledger = observation.get("ledger")
    slots = record.get("income_slots")
    if (
        not isinstance(raw_hex, str)
        or len(raw_hex) != _LEDGER_SIZE * 2
        or _RAW_HEX.fullmatch(raw_hex) is None
        or record.get("raw_payload_hex") != raw_hex
        or type(record.get("raw_payload_size")) is not int
        or record.get("raw_payload_size") != _LEDGER_SIZE
        or not isinstance(ledger, Mapping)
        or ledger.get("offset") != hex(_LEDGER_OFFSET)
        or type(ledger.get("size")) is not int
        or ledger.get("size") != _LEDGER_SIZE
        or ledger.get("raw_payload_hex") != raw_hex
        or not isinstance(slots, list)
        or len(slots) != _INCOME_COUNT
        or not all(_i32(value) for value in slots)
    ):
        return [], "MONTHLY_ECONOMY_LEDGER_SHAPE_INVALID"

    try:
        payload = bytes.fromhex(raw_hex)
    except ValueError:
        return [], "MONTHLY_ECONOMY_LEDGER_HEX_INVALID"
    if len(payload) != _LEDGER_SIZE:
        return [], "MONTHLY_ECONOMY_LEDGER_SIZE_INVALID"
    decoded = [
        int.from_bytes(
            payload[index * _COMPONENT_WIDTH:(index + 1) * _COMPONENT_WIDTH],
            "little", signed=True,
        )
        for index in range(_INCOME_COUNT)
    ]
    if slots != decoded:
        return [], "MONTHLY_ECONOMY_INCOME_SLOTS_DO_NOT_MATCH_LEDGER"
    return decoded, None


def project(record: Any) -> dict[str, Any]:
    """Project four validated prior-month war-related income cache slots.

    The caller remains responsible for fresh process identity, ROM/session/date
    checks, and the FRA own-country/role admission. This function is pure: it
    performs no process reads and does not grant an access permission.
    """
    slots, reason = _capture_inputs(record)
    if reason is not None:
        return _unknown(reason)
    try:
        if _monthly.validate_record(record) is not True:
            return _unknown("MONTHLY_ECONOMY_RECORD_VALIDATION_FAILED")
    except Exception:
        return _unknown("MONTHLY_ECONOMY_RECORD_VALIDATION_FAILED")

    components: dict[str, dict[str, Any]] = {}
    exact_raw_sum = 0
    for name, index, native_key in _COMPONENTS:
        raw = slots[index]
        exact_raw_sum += raw
        components[name] = {
            "status": "known",
            "raw": raw,
            "value": raw / _AMOUNT_SCALE,
            "unit": "ducats",
            "scale": _AMOUNT_SCALE,
            "period": PERIOD,
            "reference_period": REFERENCE_PERIOD,
            "income_slot": index,
            "native_key": native_key,
            "overlaps_monthly_income": index == 8,
            "attribution_scope": "native_category_slot_only",
        }

    public_value = {
        "components": components,
        "observed_components_subtotal": {
            "status": "known",
            "raw": exact_raw_sum,
            "value": exact_raw_sum / _AMOUNT_SCALE,
            "unit": "ducats",
            "scale": _AMOUNT_SCALE,
            "period": PERIOD,
            "reference_period": REFERENCE_PERIOD,
            "native_total": False,
            "four_components_only": True,
        },
        "monthly_income_overlap": {
            "component_indices": [8],
            "additive": False,
        },
        "total_war_income": {
            "status": "unknown",
            "reason": "COMPLETE_WAR_INCOME_TOTAL_NOT_ESTABLISHED",
        },
        "current_war_attribution": {
            "status": "unknown",
            "reason": "CURRENT_WAR_ATTRIBUTION_NOT_ESTABLISHED",
        },
        "current_payment_obligations": {
            "status": "unknown",
            "reason": "CURRENT_PAYMENT_OBLIGATIONS_NOT_CAPTURED",
        },
    }
    return {
        "status": "known",
        "schema": SCHEMA,
        "value": public_value,
        "unit": UNIT,
        "scale": SCALE,
        "period": PERIOD,
        "reference_period": REFERENCE_PERIOD,
        "basis": BASIS,
        "partial": True,
        "complete": False,
    }


__all__ = ["FIELD", "SCHEMA", "BASIS", "project"]
