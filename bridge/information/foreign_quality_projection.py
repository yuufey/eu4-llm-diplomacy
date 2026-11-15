"""Public whitelist for foreign quality; native addresses remain private."""
from __future__ import annotations

from collections.abc import Mapping
import math
import re
from typing import Any

from . import mission_texts

BASIS = "native_cached_quality_components_and_projected_modifiers"
VISIBILITY_BASIS = "native_quality_ledger_visibility_predicate_projected"
FIELD = "F02.military_quality"
VISIBILITY_FIELD = "F02.military_quality_visibility"
NUMBERS = {
    ("army", "morale"): ("morale", 1000, 32),
    ("navy", "morale"): ("morale", 1000, 32),
    ("army", "professionalism"): ("ratio", 32768, 64),
    ("army", "tradition"): ("tradition_points", 1000, 32),
    ("navy", "tradition"): ("tradition_points", 1000, 32),
    ("army", "discipline"): ("ratio", 1000, 32),
    ("army", "siege_ability"): ("ratio_modifier", 1000, 32),
    ("army", "defensiveness"): ("ratio_modifier", 1000, 32),
    ("navy", "ship_durability"): ("ratio_modifier", 1000, 32),
}
MODELS = ("heavy_ship_model", "light_ship_model", "galley_model")
COMPONENTS = {
    "army": ("morale", "discipline", "siege_ability", "defensiveness", "professionalism", "tradition"),
    "navy": ("morale", "heavy_ship_model", "light_ship_model", "galley_model", "ship_durability", "tradition"),
}
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z")
_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_LANGUAGE = re.compile(r"l_[A-Za-z0-9_]{1,63}\Z", re.ASCII)


def reason(value: Any, default: str) -> str:
    return value if isinstance(value, str) and _REASON.fullmatch(value) else default


def _unknown(why: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": why}


def permission(item: Mapping[str, Any], view: Mapping[str, Any]) -> dict[str, Any]:
    if view.get("status") != "known":
        return _unknown(reason(view.get("reason"), "COUNTRY_VIEW_ADMISSION_UNKNOWN"))
    if view.get("admitted") is False:
        return _unknown("NOT_EVALUATED_COUNTRY_VIEW_DENIED")
    record = item.get("fields", {}).get(VISIBILITY_FIELD)
    if not isinstance(record, Mapping) or record.get("status") != "known":
        return _unknown(reason(record.get("reason") if isinstance(record, Mapping) else None,
                               "QUALITY_PERMISSION_UNKNOWN"))
    value = record.get("value")
    if (not isinstance(value, Mapping) or type(value.get("admitted")) is not bool
            or value.get("mode") != ("projected_quality_ledger_gate" if value["admitted"] else "denied")):
        return _unknown("QUALITY_PERMISSION_INVALID")
    return {"status": "known", "admitted": value["admitted"], "mode": value["mode"],
            "basis": VISIBILITY_BASIS}


def _name(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("status") != "known":
        return _unknown(reason(value.get("reason") if isinstance(value, Mapping) else None,
                               "MODEL_NAME_UNKNOWN"))
    raw, language = value.get("raw_hex"), value.get("language")
    if (not isinstance(raw, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,4096}", raw)
            or not isinstance(language, str) or not _LANGUAGE.fullmatch(language)
            or b"\0" in bytes.fromhex(raw)):
        return _unknown("MODEL_NAME_INVALID")
    try:
        decoded = mission_texts.decode_template(raw, "eu4_escape")
    except (TypeError, ValueError, UnicodeError):
        return _unknown("MODEL_NAME_INVALID")
    if not isinstance(decoded, Mapping) or decoded.get("status") != "known":
        return _unknown("MODEL_NAME_DYNAMIC_OR_UNDECODABLE")
    text = decoded.get("text")
    if not isinstance(text, str) or not text.strip():
        return _unknown("MODEL_NAME_EMPTY")
    return {"status": "known", "text": text, "raw_hex": raw.lower(), "language": language,
            "encoding": "eu4_escape", "lookup_semantics": "native_FNV1_hash_only",
            "literal_key_collision_excluded": False}


def _component(record: Any, group: str, key: str) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        return _unknown("QUALITY_COMPONENT_MISSING")
    if record.get("status") != "known":
        return _unknown(reason(record.get("reason"), "QUALITY_COMPONENT_UNKNOWN"))
    raw, value = record.get("raw"), record.get("value")
    if group == "navy" and key in MODELS:
        if (not isinstance(value, Mapping) or not isinstance(raw, str) or not _KEY.fullmatch(raw)
                or value.get("localization_key") != raw or record.get("unit") != "ship_model"
                or type(record.get("scale")) is not int or record["scale"] != 1):
            return _unknown("QUALITY_MODEL_INVALID")
        return {"status": "known", "value": {"localization_key": raw, "name": _name(value.get("name"))},
                "raw": raw, "unit": "ship_model", "scale": 1}
    unit, scale, bits = NUMBERS[(group, key)]
    if bits == 64:
        if not isinstance(raw, str) or not re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", raw):
            return _unknown("QUALITY_COMPONENT_RAW_INVALID")
        number = int(raw)
        if raw != str(number):
            return _unknown("QUALITY_COMPONENT_RAW_INVALID")
    elif type(raw) is int:
        number = raw
    else:
        return _unknown("QUALITY_COMPONENT_RAW_INVALID")
    expected_value = number / scale if bits == 64 else number
    if (not -(1 << (bits - 1)) <= number < (1 << (bits - 1))
            or type(value) not in (int, float) or not math.isfinite(value)
            or value != expected_value or record.get("unit") != unit
            or type(record.get("scale")) is not int or record["scale"] != scale):
        return _unknown("QUALITY_COMPONENT_INVALID")
    return {"status": "known", "value": number / scale, "raw": raw, "unit": unit, "scale": scale}


def project(item: Mapping[str, Any], view: Mapping[str, Any],
            gate: Mapping[str, Any]) -> dict[str, Any]:
    if view.get("status") != "known":
        return _unknown(reason(view.get("reason"), "QUALITY_COUNTRY_VIEW_UNKNOWN"))
    if view.get("admitted") is False:
        return {"status": "invisible", "reason": "COUNTRY_VIEW_PREDICATE_REJECTED_FOR_OBSERVER"}
    if gate.get("status") != "known":
        return _unknown(reason(gate.get("reason"), "QUALITY_PERMISSION_UNKNOWN"))
    if gate.get("admitted") is False:
        return {"status": "invisible", "reason": "QUALITY_PERMISSION_DENIED", "visibility_basis": VISIBILITY_BASIS}
    field = item.get("fields", {}).get(FIELD)
    stable = item.get("field_consistency", {}).get(FIELD)
    if (not isinstance(field, Mapping) or field.get("status") != "known"
            or not isinstance(stable, Mapping) or stable.get("status") != "stable"):
        return _unknown(reason(field.get("reason") if isinstance(field, Mapping) else None,
                               "QUALITY_FIELD_UNKNOWN"))
    if (field.get("basis") != BASIS or field.get("complete") is not False
            or field.get("partial") is not True or field.get("unit") != "native_military_quality_components"
            or type(field.get("scale")) is not int or field["scale"] != 1):
        return _unknown("QUALITY_FIELD_INVALID")
    value = field.get("value")
    if not isinstance(value, Mapping):
        return _unknown("QUALITY_FIELD_INVALID")
    output: dict[str, Any] = {}
    known = 0
    for group, keys in COMPONENTS.items():
        values = value.get(group)
        if not isinstance(values, Mapping):
            return _unknown("QUALITY_FIELD_INVALID")
        output[group] = {key: _component(values.get(key), group, key) for key in keys}
        known += sum(component["status"] == "known" for component in output[group].values())
    if not known:
        return _unknown("QUALITY_COMPONENTS_UNKNOWN")
    return {"status": "known", "value": output, "unit": "native_military_quality_components", "scale": 1,
            "period": "current", "basis": BASIS, "complete": False, "partial": True,
            "known_component_count": known, "component_count": 12}
