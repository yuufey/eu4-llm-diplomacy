"""Result-window effect operands for the fixed 1.37.4 capture.

2367A0 and 236DC0 restore summary pairs to original combat-side order.
23B3A0 formats signed thousandths, truncating prestige to two fractional
digits and tradition to one. These are displayed side operands, not a
reconstruction of any individual country's before/after state.
"""
from __future__ import annotations

from copy import deepcopy

from bridge.information.battle_values import SHIP_KINDS, project_outcome


FIELDS = ("ships_captured", "prestige", "army_tradition", "naval_tradition", "war_exhaustion", "war_score")


def _unknown(reason):
    return {field: {"status": "unknown", "reason": reason} for field in FIELDS}


def _decimal(raw, digits, *, positive_sign=False):
    """Format the integer operand without float rounding or negative floor."""
    sign = "-" if raw < 0 else "+" if positive_sign and raw > 0 else ""
    integer, fraction = divmod(abs(raw), 1000)
    if digits:
        fraction_digits = f"{fraction:03d}"[:digits]
        return f"{sign}{integer}.{fraction_digits}"
    return f"{sign}{integer}"


def project_effects(decoded, mapping, observer_ref):
    context = decoded.get("context")
    if not context:
        return _unknown("BATTLE_SIDE_CONTEXT_UNAVAILABLE")
    if len(mapping) != 2 or set(mapping) != {0, 1}:
        return _unknown("BATTLE_EFFECT_SIDE_MAPPING_UNRESOLVED")
    if any(not side["present"] or not side["participants"]["complete"]
           for side in context["sides"]):
        return _unknown("BATTLE_SIDE_CONTEXT_INCOMPLETE")
    participants = [[ref.to_bytes(8, "little")[:3].decode("ascii")
                     for ref in side["participants"]["full_refs"]]
                    for side in context["sides"]]
    raw = decoded["observation"]["summary"]["raw_i32"]

    def scalar(pair, unit, digits):
        return {"status": "known", "value": {
            "unit": unit, "scale": 1000, "scope": "whole_combat_side",
            "quantity": "result_window_side_operand",
            "basis": "native_result_template_fixed_point_operands",
            "display_fraction_digits": digits, "runtime_popup_verified": False,
            "sides": [{"combat_side_index": index,
                       "participants": deepcopy(participants[index]),
                       "raw": value, "amount_decimal": _decimal(value, 3),
                       "display_numeric": _decimal(value, digits, positive_sign=True)}
                      for index, value in enumerate(pair)],
        }}

    result = {"prestige": scalar(raw[2:4], "prestige", 2),
              "war_exhaustion": scalar(raw[4:6], "war_exhaustion", 2)}
    outcome = project_outcome(decoded, mapping, observer_ref)
    if outcome["status"] != "known":
        result["war_score"] = deepcopy(outcome)
    else:
        winner = outcome["value"]["combat_side_index"]
        result_index = outcome["value"]["result_side_index"]
        bonus = decoded["observation"]["result"]["sides"][result_index]["raw_fields"][8]
        score = bonus * 1000 + raw[6]
        if not -(2**31) < score < 2**31:
            result["war_score"] = {"status": "unknown", "reason": "BATTLE_SCORE_OPERAND_OVERFLOW"}
        else:
            pair = [score if index == winner else -score for index in range(2)]
            result["war_score"] = scalar(pair, "war_score", 2)
            result["war_score"]["value"].update(
                basis="native_result_window_score_operands", display_presence="unverified",
                components={"winner_result_side_index": result_index,
                            "winner_integer_bonus": bonus, "summary_fixed_point": raw[6]})
    if context["kind"] == 1:
        result["army_tradition"] = scalar(raw[:2], "army_tradition", 1)
        result["naval_tradition"] = {
            "status": "unsupported", "reason": "NAVAL_TRADITION_REQUIRES_NAVAL_BATTLE"}
        result["ships_captured"] = {
            "status": "unsupported", "reason": "SHIPS_CAPTURED_REQUIRES_NAVAL_BATTLE"}
        return result
    result["army_tradition"] = {
        "status": "unsupported", "reason": "NAVAL_TRADITION_IS_NOT_ARMY_TRADITION"}
    result["naval_tradition"] = scalar(raw[:2], "naval_tradition", 1)
    extension = decoded.get("naval")
    if extension is None:
        result["ships_captured"] = {
            "status": "unknown" if decoded.get("wire", {}).get("version", 0) >= 3 else "unsupported",
            "reason": ("NAVAL_EXTENSION_CAPTURE_UNAVAILABLE"
                       if decoded.get("wire", {}).get("version", 0) >= 3
                       else "CAPTURED_SHIP_ROWS_NOT_CAPTURED"),
        }
        return result

    rows = extension["row_types"]
    counts = {kind: rows.count(index + 3) for index, kind in enumerate(SHIP_KINDS)}
    unclassified = len(rows) - sum(counts.values())
    if outcome["status"] == "known":
        winner = outcome["value"]["combat_side_index"]
        capturing_side = {"status": "known", "value": {
            "combat_side_index": winner, "participants": deepcopy(participants[winner])}}
    else:
        capturing_side = deepcopy(outcome)
    result["ships_captured"] = {"status": "known", "value": {
        "unit": "ships", "scale": 1, "scope": "whole_combat_side",
        "quantity": "native_result_window_capture_count", "total": len(rows),
        "by_unit": counts, "unclassified_type_count": unclassified,
        "unit_breakdown_complete": unclassified == 0,
        "capturing_side": capturing_side,
        "basis": "native_CAPTURE_summary_vector_count",
        "runtime_popup_verified": False,
    }}
    return result
