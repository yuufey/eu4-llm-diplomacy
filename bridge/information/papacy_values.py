"""Pure DTO construction and validation for copied papacy cache values."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import re


_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_TAG = re.compile(r"[A-Z0-9]{3}\Z")

_VALUE_ORIGIN = "copied_native_papacy_state"
NUMBER_SPECS = {
    "papal_influence": {
        "unit": "papal_influence",
        "scale": 1000,
        "basis": "native_current_papal_influence_cache",
        "value_origin": _VALUE_ORIGIN,
        "unavailable_reason": "PAPAL_INFLUENCE_UNAVAILABLE",
    },
    "curia_treasury": {
        "unit": "ducats",
        "scale": 1000,
        "basis": "native_current_curia_treasury_cache",
        "value_origin": _VALUE_ORIGIN,
        "unavailable_reason": "CURIA_TREASURY_UNAVAILABLE",
    },
}

_NUMBER_KEYS = {
    "status", "value", "raw", "raw_hex", "unit", "scale", "period",
    "partial", "complete", "basis", "value_origin",
}
_CONTROLLER_UNRESOLVED = {"status": "unknown", "reason": "PAPACY_CONTROLLER_UNRESOLVED"}


def number_value(name: str, raw: bytes) -> dict:
    """Build the known scalar DTO for one copied four-byte signed cache value."""
    if type(name) is not str or name not in NUMBER_SPECS:
        raise ValueError("unsupported papacy number field")
    if type(raw) is not bytes or len(raw) != 4:
        raise ValueError("papacy number raw value must be exactly four bytes")

    value = int.from_bytes(raw, byteorder="little", signed=True)
    spec = NUMBER_SPECS[name]
    return {
        "status": "known",
        "value": value,
        "raw": value,
        "raw_hex": raw.hex(),
        "unit": spec["unit"],
        "scale": spec["scale"],
        "period": "current",
        "partial": True,
        "complete": False,
        "basis": spec["basis"],
        "value_origin": spec["value_origin"],
    }


def _known_number_is_valid(name: str, value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != _NUMBER_KEYS:
        return False
    if value.get("status") != "known":
        return False
    raw = value.get("raw")
    number = value.get("value")
    raw_hex = value.get("raw_hex")
    if (type(raw) is not int or type(number) is not int
            or not _I32_MIN <= raw <= _I32_MAX or number != raw
            or type(raw_hex) is not str
            or re.fullmatch(r"[0-9a-f]{8}\Z", raw_hex) is None):
        return False
    if int.from_bytes(bytes.fromhex(raw_hex), byteorder="little", signed=True) != raw:
        return False
    spec = NUMBER_SPECS[name]
    return (
        value.get("unit") == spec["unit"]
        and type(value.get("scale")) is int
        and value.get("scale") == 1000
        and value.get("period") == "current"
        and value.get("partial") is True
        and value.get("complete") is False
        and value.get("basis") == spec["basis"]
        and value.get("value_origin") == _VALUE_ORIGIN
    )


def _number_component_is_valid(name: str, value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    status = value.get("status")
    if status == "known":
        return _known_number_is_valid(name, value)
    return (
        status == "unknown"
        and set(value) == {"status", "reason"}
        and value.get("reason") == NUMBER_SPECS[name]["unavailable_reason"]
    )


def _controller_is_valid(value: object, target: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    status = value.get("status")
    if status == "unknown":
        return set(value) == {"status", "reason"} and value.get("reason") == _CONTROLLER_UNRESOLVED["reason"]
    if status != "known" or set(value) != {"status", "country", "is_target_controller"}:
        return False
    country = value.get("country")
    is_target = value.get("is_target_controller")
    return (
        type(country) is str
        and _TAG.fullmatch(country) is not None
        and type(is_target) is bool
        and is_target is (country == target)
    )


def _not_applicable_is_valid(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == {"status", "reason"}
        and value.get("status") == "not_applicable"
        and value.get("reason") == "PAPACY_NOT_USED"
    )


def public_value(value: object, target: str) -> dict:
    """Validate and copy a bounded papacy DTO for the requested target country."""
    if type(target) is not str or _TAG.fullmatch(target) is None:
        raise ValueError("target must be a three-character country tag")
    if not isinstance(value, Mapping) or set(value) != {
        "uses_papacy", "papal_influence", "curia_treasury", "controller"
    }:
        raise ValueError("papacy value has an invalid public shape")

    uses_papacy = value.get("uses_papacy")
    if type(uses_papacy) is not bool:
        raise ValueError("uses_papacy must be a boolean")

    papal_influence = value.get("papal_influence")
    curia_treasury = value.get("curia_treasury")
    controller = value.get("controller")
    if uses_papacy:
        if not _number_component_is_valid("papal_influence", papal_influence):
            raise ValueError("papal influence DTO is invalid")
        if not _number_component_is_valid("curia_treasury", curia_treasury):
            raise ValueError("curia treasury DTO is invalid")
        if not _controller_is_valid(controller, target):
            raise ValueError("papacy controller DTO is invalid")
    else:
        if not all(_not_applicable_is_valid(child) for child in (
            papal_influence, curia_treasury, controller,
        )):
            raise ValueError("papacy children must be not_applicable when papacy is unused")

    # Project into plain dictionaries so callers receive no upstream object or extra key.
    if uses_papacy:
        clean_papal = _project_number("papal_influence", papal_influence)
        clean_treasury = _project_number("curia_treasury", curia_treasury)
        clean_controller = _project_controller(controller)
    else:
        clean_papal = {"status": "not_applicable", "reason": "PAPACY_NOT_USED"}
        clean_treasury = {"status": "not_applicable", "reason": "PAPACY_NOT_USED"}
        clean_controller = {"status": "not_applicable", "reason": "PAPACY_NOT_USED"}
    return deepcopy({
        "uses_papacy": uses_papacy,
        "papal_influence": clean_papal,
        "curia_treasury": clean_treasury,
        "controller": clean_controller,
    })


def _project_number(name: str, value: Mapping) -> dict:
    if value.get("status") == "unknown":
        return {"status": "unknown", "reason": NUMBER_SPECS[name]["unavailable_reason"]}
    return {key: value[key] for key in (
        "status", "value", "raw", "raw_hex", "unit", "scale", "period",
        "partial", "complete", "basis", "value_origin",
    )}


def _project_controller(value: Mapping) -> dict:
    if value.get("status") == "unknown":
        return dict(_CONTROLLER_UNRESOLVED)
    return {
        "status": "known",
        "country": value["country"],
        "is_target_controller": value["is_target_controller"],
    }
