"""Observer-owned retreat state from copied v10 battle evidence.

The projection validates the embedded battle identity and only interprets the
units whose full owner reference exactly matches the observer. A verified
losing-side native overrun makes an uncaptured retreat inapplicable. It does not
infer a destination, arrival, regiment/ship quantity, or persistent unit ID.
"""
from __future__ import annotations

from typing import Any

from .battle_annihilation import _full_ref, _tag, project_annihilation
from .battle_values import project_outcome


_U64_MAX = (1 << 64) - 1
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_MAX_PARTICIPANTS_PER_SIDE = 4096
_MAX_UNITS = 128


def _unknown(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "partial": True,
        "complete": False,
    }


def _wire10_valid(decoded: dict[str, Any]) -> bool:
    wire10 = decoded.get("wire10")
    wire9 = decoded.get("wire9")
    if not isinstance(wire10, dict) or not isinstance(wire9, dict):
        return False
    if (type(wire10.get("version")) is not int or wire10["version"] != 10
            or type(wire10.get("base_version")) is not int
            or wire10["base_version"] != 9
            or type(wire9.get("version")) is not int
            or wire9["version"] != 9
            or wire10.get("extension_magic") != "RETR"
            or type(wire10.get("extension_version")) is not int
            or wire10["extension_version"] not in (1, 2)
            or type(wire10.get("trailing_bytes")) is not int
            or wire10["trailing_bytes"] != 0
            or decoded.get("complete") is not False):
        return False
    byte_counts = (wire10.get("bytes"), wire10.get("base_bytes"),
                   wire10.get("extension_bytes"))
    if any(type(value) is not int or value < 0 for value in byte_counts):
        return False
    total_bytes, base_bytes, extension_bytes = byte_counts
    return (base_bytes > 0 and extension_bytes > 0
            and total_bytes == 10 + base_bytes + 10 + extension_bytes)


def _uncaptured_retreat(decoded: dict[str, Any], mapping: Any,
                        observer_ref: Any) -> dict[str, Any]:
    annihilation = project_annihilation(decoded, mapping, observer_ref)
    if annihilation.get("status") == "known":
        for side in annihilation["value"]["sides"]:
            if side["annihilated"] == {"status": "known", "value": True}:
                return {
                    "status": "not_applicable",
                    "reason": "RETREAT_NOT_APPLICABLE_AFTER_NATIVE_OVERRUN",
                    "basis": "native_combat_side_overrun_marker",
                    "scope": "whole_combat_side",
                    "combat_side_index": side["combat_side_index"],
                }
    return _unknown("RETREAT_NOT_CAPTURED")


def _identity(decoded: dict[str, Any]) -> tuple[dict[str, Any], int, int, int] | None:
    context = decoded.get("context")
    observation = decoded.get("observation")
    if not isinstance(context, dict) or not isinstance(observation, dict):
        return None
    result = observation.get("result")
    if not isinstance(result, dict):
        return None
    sequence = observation.get("sequence")
    raw_date = result.get("raw_date")
    kind = context.get("kind")
    if (type(sequence) is not int or not 0 < sequence <= _U64_MAX
            or type(raw_date) is not int or not _I32_MIN <= raw_date <= _I32_MAX
            or type(kind) is not int or kind not in (1, 2)):
        return None
    return context, sequence, raw_date, kind


def _participants(context: dict[str, Any]) -> tuple[list[list[int]], list[list[str]]] | None:
    sides = context.get("sides")
    if not isinstance(sides, list) or len(sides) != 2:
        return None
    refs_by_side: list[list[int]] = []
    tags_by_side: list[list[str]] = []
    seen: set[int] = set()
    for side in sides:
        if not isinstance(side, dict) or side.get("present") is not True:
            return None
        participants = side.get("participants")
        refs = participants.get("full_refs") if isinstance(participants, dict) else None
        if (not isinstance(participants, dict)
                or participants.get("complete") is not True
                or not isinstance(refs, list) or not refs
                or len(refs) > _MAX_PARTICIPANTS_PER_SIDE
                or any(not _full_ref(ref) for ref in refs)
                or len(set(refs)) != len(refs)
                or any(ref in seen for ref in refs)):
            return None
        tags = [_tag(ref) for ref in refs]
        if any(tag is None for tag in tags):
            return None
        seen.update(refs)
        refs_by_side.append(list(refs))
        tags_by_side.append([tag for tag in tags if tag is not None])
    return refs_by_side, tags_by_side


def _side_mapping(decoded: dict[str, Any], mapping: Any,
                  refs_by_side: list[list[int]], observer_ref: int) -> tuple[int, int] | None:
    if (not isinstance(mapping, (list, tuple)) or len(mapping) != 2
            or any(type(index) is not int or index not in (0, 1) for index in mapping)
            or set(mapping) != {0, 1}):
        return None
    if not _full_ref(observer_ref):
        return None
    observer_sides = [index for index, refs in enumerate(refs_by_side)
                      if observer_ref in refs]
    if len(observer_sides) != 1:
        return None

    observation = decoded["observation"]
    result = observation["result"]
    summary = observation.get("summary")
    winner = summary.get("control_byte") if isinstance(summary, dict) else None
    flag108 = result.get("flag108")
    result_sides = result.get("sides")
    if (type(winner) is not int or winner not in (0, 1)
            or type(flag108) is not int or flag108 not in (0, 1)
            or not isinstance(result_sides, list) or len(result_sides) != 2):
        return None

    for result_index, result_side in enumerate(result_sides):
        country = result_side.get("country") if isinstance(result_side, dict) else None
        if not _full_ref(country):
            return None
        matches = [index for index, refs in enumerate(refs_by_side)
                   if country in refs]
        if len(matches) != 1 or matches[0] != mapping[result_index]:
            return None

    try:
        outcome = project_outcome(decoded, mapping, observer_ref)
    except Exception:
        return None
    if not isinstance(outcome, dict) or outcome.get("status") != "known":
        return None
    value = outcome.get("value")
    outcome_winner = value.get("combat_side_index") if isinstance(value, dict) else None
    if type(outcome_winner) is not int or outcome_winner not in (0, 1):
        return None
    return observer_sides[0], outcome_winner


def _loser_overrun(decoded: dict[str, Any], loser_side: int) -> bool:
    end_state = decoded.get("end_state")
    if not isinstance(end_state, dict) or end_state.get("status") != "known":
        return False
    gates = end_state.get("raw_gates")
    return (isinstance(gates, list) and len(gates) == 2
            and type(gates[loser_side]) is int and gates[loser_side] == 1)


def _own_units(retreat: dict[str, Any], observer_ref: int) -> tuple[int, bool] | None:
    initial_count = retreat.get("initial_unit_count")
    units = retreat.get("units")
    if (type(initial_count) is not int or not 0 <= initial_count <= _MAX_UNITS
            or not isinstance(units, list) or len(units) > _MAX_UNITS
            or len(units) > initial_count):
        return None

    previous_ordinal = -1
    seen_ordinals: set[int] = set()
    own_count = 0
    own_state_matches = True
    for unit in units:
        if not isinstance(unit, dict):
            return None
        ordinal = unit.get("ordinal")
        owner_ref = unit.get("owner_full_ref")
        flags = unit.get("raw_flags")
        if (type(ordinal) is not int or not 0 <= ordinal < initial_count
                or ordinal <= previous_ordinal or ordinal in seen_ordinals
                or not _full_ref(owner_ref)
                or not isinstance(flags, list) or len(flags) != 4
                or any(type(flag) is not int or not 0 <= flag <= 255
                       for flag in flags)):
            return None
        previous_ordinal = ordinal
        seen_ordinals.add(ordinal)
        if owner_ref == observer_ref:
            own_count += 1
            if flags[0] != 0 or flags[1] != 1 or flags[2] != 1:
                own_state_matches = False
    return own_count, own_state_matches


def project_retreat(decoded: Any, mapping: Any, observer_ref: Any) -> dict[str, Any]:
    """Project only verified observer-owned retreat state from a decoded v10.

    Older v1-v9 decoded values have no RETR evidence and remain explicitly
    unknown. Malformed values fail closed; no input object is modified.
    """
    try:
        if not isinstance(decoded, dict):
            return _unknown("BATTLE_RETREAT_INPUT_INVALID")
        if "wire10" not in decoded and "retreat" not in decoded:
            return _unknown("RETREAT_NOT_CAPTURED")
        if not _wire10_valid(decoded):
            return _unknown("BATTLE_RETREAT_WIRE_INVALID")

        retreat = decoded.get("retreat")
        if not isinstance(retreat, dict):
            return _unknown("BATTLE_RETREAT_INPUT_INVALID")
        if retreat.get("status") == "unknown":
            if retreat == {"status": "unknown", "reason": "RETREAT_NOT_CAPTURED"}:
                return _uncaptured_retreat(decoded, mapping, observer_ref)
            return _unknown("BATTLE_RETREAT_INPUT_INVALID")
        if retreat.get("status") != "known":
            return _unknown("BATTLE_RETREAT_INPUT_INVALID")
        capture_source = retreat.get("capture_source", "regular")
        extension_version = decoded["wire10"]["extension_version"]
        if ((extension_version == 1 and capture_source != "regular")
                or (extension_version == 2 and capture_source != "unit_removal_state")):
            return _unknown("BATTLE_RETREAT_SOURCE_INVALID")

        identity = _identity(decoded)
        if identity is None:
            return _unknown("BATTLE_RETREAT_IDENTITY_MISMATCH")
        context, sequence, raw_date, kind = identity
        if (type(retreat.get("sequence")) is not int
                or type(retreat.get("raw_date")) is not int
                or type(retreat.get("kind")) is not int
                or (retreat["sequence"], retreat["raw_date"], retreat["kind"])
                    != (sequence, raw_date, kind)):
            return _unknown("BATTLE_RETREAT_IDENTITY_MISMATCH")

        retreat_side = retreat.get("combat_side_index")
        if type(retreat_side) is not int or retreat_side not in (0, 1):
            return _unknown("BATTLE_RETREAT_SIDE_UNRESOLVED")
        if not _full_ref(observer_ref):
            return _unknown("BATTLE_OBSERVER_SIDE_UNRESOLVED")

        participants = _participants(context)
        if participants is None:
            return _unknown("BATTLE_SIDE_CONTEXT_INCOMPLETE")
        refs_by_side, _tags_by_side = participants
        mapped_sides = _side_mapping(decoded, mapping, refs_by_side, observer_ref)
        if mapped_sides is None:
            return _unknown("BATTLE_RETREAT_SIDE_MAPPING_UNRESOLVED")
        observer_side, winner_side = mapped_sides
        loser_side = 1 - winner_side
        if retreat_side != loser_side:
            return _unknown("BATTLE_RETREAT_LOSING_SIDE_INCONSISTENT")

        # Do not even inspect the unit vector for a foreign retreat. The
        # captured flags only have verified visibility for the observer's own
        # full-reference-owned units.
        if observer_side != retreat_side:
            return _unknown("FOREIGN_RETREAT_VISIBILITY_UNVERIFIED")

        own = _own_units(retreat, observer_ref)
        if own is None:
            return _unknown("BATTLE_RETREAT_SNAPSHOT_INVALID")
        own_count, own_state_matches = own
        if own_count == 0:
            return _unknown("OWN_RETREAT_NOT_OBSERVED")
        if _loser_overrun(decoded, loser_side):
            return _unknown("RETREAT_OVERRUN_CONFLICT")
        if not own_state_matches:
            return _unknown("OWN_RETREAT_STATE_UNVERIFIED")

        observer_tag = _tag(observer_ref)
        if observer_tag is None:
            return _unknown("BATTLE_OBSERVER_SIDE_UNRESOLVED")
        return {
            "status": "known",
            "value": {
                "observer": observer_tag,
                "combat_side_index": retreat_side,
                "retreating": True,
                "observed_unit_count": own_count,
                "count_is_lower_bound": True,
                "unit": "native_army_or_fleet_objects",
                "scope": ("observer_owned_units_before_combat_removal"
                          if capture_source == "unit_removal_state"
                          else "observer_owned_units_at_regular_battle_end"),
                "identity_scope": "captured_operation_not_persistent_unit_id",
                "destinations": _unknown("RETREAT_DESTINATION_NOT_CAPTURED"),
                "arrival": _unknown("RETREAT_ARRIVAL_NOT_CAPTURED"),
            },
            "partial": True,
            "complete": False,
        }
    except Exception:
        return _unknown("BATTLE_RETREAT_INPUT_INVALID")


__all__ = ["project_retreat"]
