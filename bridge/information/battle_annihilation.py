"""Whole-side native-overrun evidence from event-bound copied gate bytes."""
from __future__ import annotations

import re
from typing import Any

from .battle_values import project_outcome


_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_U64_MAX = (1 << 64) - 1


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _full_ref(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _U64_MAX


def _tag(value: int) -> str | None:
    try:
        result = value.to_bytes(8, "little")[:3].decode("ascii")
    except (OverflowError, UnicodeError, ValueError):
        return None
    return result if _TAG.fullmatch(result) is not None else None


def _project(decoded: Any, mapping: Any, observer_ref: Any) -> dict[str, Any]:
    if not isinstance(decoded, dict):
        return _unknown("BATTLE_ANNIHILATION_INPUT_INVALID")
    context = decoded.get("context")
    if not isinstance(context, dict):
        return _unknown("BATTLE_SIDE_CONTEXT_UNAVAILABLE")
    if type(context.get("kind")) is not int or context["kind"] not in (1, 2):
        return _unknown("BATTLE_ANNIHILATION_INPUT_INVALID")
    wire9 = decoded.get("wire9")
    generic_end_state = (isinstance(wire9, dict) and wire9.get("version") == 9
                         and wire9.get("base_version") in (7, 8))
    if context["kind"] == 1 and not generic_end_state:
        return _unknown("BATTLE_ANNIHILATION_NAVAL_ONLY")
    if (not isinstance(mapping, (list, tuple)) or len(mapping) != 2
            or any(type(index) is not int or index not in (0, 1) for index in mapping)
            or set(mapping) != {0, 1}):
        return _unknown("BATTLE_ANNIHILATION_SIDE_MAPPING_UNRESOLVED")
    if not _full_ref(observer_ref):
        return _unknown("BATTLE_OBSERVER_SIDE_UNRESOLVED")

    sides = context.get("sides")
    if not isinstance(sides, list) or len(sides) != 2:
        return _unknown("BATTLE_SIDE_CONTEXT_INCOMPLETE")
    participants_by_side: list[list[int]] = []
    participant_tags_by_side: list[list[str]] = []
    all_refs: set[int] = set()
    for side in sides:
        if not isinstance(side, dict) or side.get("present") is not True:
            return _unknown("BATTLE_SIDE_CONTEXT_INCOMPLETE")
        participants = side.get("participants")
        refs = participants.get("full_refs") if isinstance(participants, dict) else None
        if (not isinstance(participants, dict) or participants.get("complete") is not True
                or not isinstance(refs, list) or not refs or len(refs) > 4096
                or any(not _full_ref(ref) for ref in refs)
                or len(set(refs)) != len(refs)
                or any(ref in all_refs for ref in refs)):
            return _unknown("BATTLE_SIDE_CONTEXT_INCOMPLETE")
        tags = [_tag(ref) for ref in refs]
        if any(tag is None for tag in tags):
            return _unknown("BATTLE_PARTICIPANT_TAG_UNRESOLVED")
        all_refs.update(refs)
        participants_by_side.append(list(refs))
        participant_tags_by_side.append([tag for tag in tags if tag is not None])

    result = decoded.get("observation")
    result = result.get("result") if isinstance(result, dict) else None
    observation = decoded.get("observation")
    summary = observation.get("summary") if isinstance(observation, dict) else None
    result_sides = result.get("sides") if isinstance(result, dict) else None
    winner = summary.get("control_byte") if isinstance(summary, dict) else None
    flag108 = result.get("flag108") if isinstance(result, dict) else None
    if (type(winner) is not int or winner not in (0, 1)
            or type(flag108) is not int or flag108 not in (0, 1)
            or not isinstance(result_sides, list) or len(result_sides) != 2):
        return _unknown("BATTLE_OUTCOME_INCONSISTENT")

    # Independently verify that each result-side representative belongs to
    # exactly the combat side supplied by the caller's one-to-one mapping.
    for result_index, result_side in enumerate(result_sides):
        country = result_side.get("country") if isinstance(result_side, dict) else None
        if not _full_ref(country):
            return _unknown("BATTLE_ANNIHILATION_SIDE_MAPPING_UNRESOLVED")
        matches = [index for index, refs in enumerate(participants_by_side) if country in refs]
        if len(matches) != 1 or matches[0] != mapping[result_index]:
            return _unknown("BATTLE_ANNIHILATION_SIDE_MAPPING_UNRESOLVED")

    # Reuse the existing winner/result-side consistency check and observer
    # participation validation.  Its output is not used as evidence of loss.
    try:
        outcome = project_outcome(decoded, mapping, observer_ref)
    except Exception:
        return _unknown("BATTLE_OUTCOME_INCONSISTENT")
    if not isinstance(outcome, dict) or outcome.get("status") != "known":
        reason = outcome.get("reason") if isinstance(outcome, dict) else None
        return _unknown(reason if isinstance(reason, str) else "BATTLE_OUTCOME_INCONSISTENT")
    winner = outcome.get("value", {}).get("combat_side_index")
    if type(winner) is not int or winner not in (0, 1):
        return _unknown("BATTLE_OUTCOME_INCONSISTENT")

    naval = decoded.get("naval")
    naval_sides = naval.get("sides") if isinstance(naval, dict) else None
    end_state = decoded.get("end_state") if generic_end_state else None
    generic_gates = None
    if isinstance(end_state, dict) and end_state.get("status") == "known":
        generic_gates = end_state.get("raw_gates")
        if not isinstance(generic_gates, list) or len(generic_gates) != 2:
            return _unknown("BATTLE_END_STATE_MARKER_INVALID")
    if generic_gates is None and context["kind"] == 1:
        return _unknown("BATTLE_END_STATE_NOT_CAPTURED")
    if generic_gates is None and (not isinstance(naval_sides, list) or len(naval_sides) != 2):
        return _unknown("NAVAL_OVERRUN_MARKER_UNAVAILABLE")
    gates = []
    for index in range(2):
        raw_gate = (generic_gates[index] if generic_gates is not None else
                    naval_sides[index].get("raw_gate") if isinstance(naval_sides[index], dict) else None)
        if type(raw_gate) is not int or raw_gate not in (0, 1):
            return _unknown("NAVAL_OVERRUN_MARKER_INVALID")
        gates.append(raw_gate)
    if generic_gates is not None and context["kind"] == 2 and naval_sides is not None:
        if (not isinstance(naval_sides, list) or len(naval_sides) != 2
                or any(not isinstance(side, dict) or type(side.get("raw_gate")) is not int
                       or side["raw_gate"] != gates[index] for index, side in enumerate(naval_sides))):
            return _unknown("BATTLE_END_STATE_NAVAL_MARKER_CONFLICT")
    if gates[0] == 1 and gates[1] == 1:
        return _unknown("NAVAL_OVERRUN_MARKERS_CONFLICT")
    if gates[winner] == 1:
        return _unknown("NAVAL_OVERRUN_WINNER_SIDE_MARKED")

    output_sides = []
    for index, raw_gate in enumerate(gates):
        annihilated = (
            {"status": "known", "value": True}
            if index != winner and raw_gate == 1
            else _unknown("NON_OVERRUN_ANNIHILATION_PATHS_UNRESOLVED")
        )
        output_sides.append({
            "combat_side_index": index,
            "participants": participant_tags_by_side[index],
            "native_overrun": {"status": "known", "value": raw_gate == 1},
            "annihilated": annihilated,
        })
    value = {
        "basis": "native_combat_side_overrun_marker",
        "scope": "whole_combat_side",
        "classification_scope": "native_overrun_path_only",
        "sides": output_sides,
        "complete": False,
    }
    return {"status": "known", "value": value, "complete": False}


def project_annihilation(decoded: Any, mapping: Any, observer_ref: Any) -> dict[str, Any]:
    """Classify only the proven native overrun-removal path.

    A losing side with ``raw_gate == 1`` is known annihilated. Wire9 supplies
    both land/naval markers; legacy naval records use their NAVL bytes. A zero marker
    leaves annihilation unknown because the ordinary path can retreat or can
    remove a side with no retreat route. Remaining unit counts are not used.
    """
    try:
        return _project(decoded, mapping, observer_ref)
    except Exception:
        return _unknown("BATTLE_ANNIHILATION_INPUT_INVALID")


__all__ = ["project_annihilation"]
