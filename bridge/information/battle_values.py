"""Force counts and outcome direction for the fixed 1.37.4 battle capture.

REA land formatter 232A80 binds +118/+11C/+120 to infantry/cavalry/
artillery START and +134/+138/+13C to LOST. CFCD0 truncates each signed
integer toward zero after division by 1000. END subtracts those converted
operands. This projection preserves raw combat sides, never OUR/ENEMY roles.

Evidence: information-battle-layout-20261025-001/unit-display-ledger-001.json
and information-battle-scalar-writers-20261025-001/scalar-field-writer-001.json.
Summary+44/+48 retain the independently truncated aggregate-loss operands.
Actual popup text remains separate evidence.
"""
from __future__ import annotations

from copy import deepcopy

from work.information_battle_observation_wire import SUMMARY_RAW_COUNT
from .battle_display_sides import project_side_identity


FIELDS = ("initial_forces", "losses", "remaining_forces", "unit_breakdown")
KINDS = ("infantry", "cavalry", "artillery")
SHIP_KINDS = ("heavy_ship", "light_ship", "galley", "transport")
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def _unknown(reason, status="unknown"):
    return {field: {"status": status, "reason": reason} for field in FIELDS}


def _divide(value):
    # Python // rounds negatives down; the native signed division truncates.
    return (1 if value >= 0 else -1) * (abs(value) // 1000)


def project_aggregate_losses(decoded):
    """Read the already-divided summary operands in original combat order.

    237FC0 copies combat+20/+28 side+1C /1000 to summary+44/+48.
    Its later result-object side swap does not change the summary buffer.
    These operands are independent of the three displayed unit-loss counts.
    """
    try:
        observation = decoded['observation']
        sequence = observation['sequence']
        date = observation['result']['raw_date']
        if (type(sequence) is not int or not 0 < sequence < 1 << 64
                or type(date) is not int or not 0 <= date < 1 << 31
                or type(decoded['context']['kind']) is not int
                or decoded['context']['kind'] != 1):
            raise ValueError('event identity')
        identity = project_side_identity(decoded)
        if identity['status'] != 'known':
            raise ValueError('combat sides')
        raw = observation['summary']['raw_i32']
        if not isinstance(raw, (list, tuple)) or len(raw) != SUMMARY_RAW_COUNT:
            raise ValueError('summary shape')
        sides = []
        for index, side in enumerate(identity['value']['sides']):
            operand = raw[9 + index]
            count = ({'status': 'known', 'value': operand}
                     if type(operand) is int and 0 <= operand < 1 << 31 else
                     {'status': 'unknown', 'reason': 'AGGREGATE_LOSS_OPERAND_INVALID'})
            sides.append({'combat_side_index': index,
                          'participants': deepcopy(side['participants']),
                          'count': count, 'summary_offset': hex(0x44 + index * 4)})
        return {'status': 'known', 'value': {
            'sides': sides, 'sequence': sequence, 'raw_date': date,
            'unit': 'men', 'scale': 1, 'scope': 'whole_combat_side',
            'basis': 'native_summary_combat_aggregate_loss_divided_by_1000',
            'writer_rva': '0x237fc0', 'exe_sha256': GAME_SHA256,
            'runtime_popup_verified': False}}
    except (KeyError, TypeError, ValueError, IndexError, OverflowError):
        return {'status': 'unknown', 'reason': 'AGGREGATE_LOSS_CONTEXT_OR_SUMMARY_INVALID'}


def project_outcome(decoded, mapping, observer_ref):
    """Project the native winning combat side, checking result reordering.

    Fixed-build 22C0B0/22ACE0 pass the surviving side's raw index through
    22BED0/22B5D0 to 23A020 and summary+4C. 237FC0 initializes flag108 to
    (index == 0), then flips it when result sides are swapped. These are
    two representations of the same direction, not attacker/defender roles.
    See information-battle-outcome-20261026-001/outcome-contract-001.json.
    """
    def unknown(reason):
        return {"status": "unknown", "reason": reason}

    if len(mapping) != 2 or set(mapping) != {0, 1}:
        return unknown("OUTCOME_SIDE_MAPPING_UNRESOLVED")
    observation = decoded["observation"]
    winner = observation["summary"]["control_byte"]
    flag = observation["result"]["flag108"]
    if winner not in (0, 1) or flag not in (0, 1):
        return unknown("BATTLE_OUTCOME_INCONSISTENT")
    result_index = 0 if flag == 1 else 1
    if mapping[result_index] != winner:
        return unknown("BATTLE_OUTCOME_INCONSISTENT")
    sides = decoded["context"]["sides"]
    observer_sides = [i for i, side in enumerate(sides)
                      if observer_ref in side["participants"]["full_refs"]]
    if len(observer_sides) != 1:
        return unknown("BATTLE_OBSERVER_SIDE_UNRESOLVED")
    def tag(ref):
        return ref.to_bytes(8, "little")[:3].decode("ascii")

    return {"status": "known", "value": {
        "combat_side_index": winner, "result_side_index": result_index,
        "representative": tag(observation["result"]["sides"][result_index]["country"]),
        "participants": [tag(ref) for ref in sides[winner]["participants"]["full_refs"]],
        "scope": "whole_combat_side",
        "observer_outcome": "victory" if observer_sides[0] == winner else "defeat",
        "basis": "native_combat_end_direction", "runtime_popup_verified": False,
    }}


def project_land_forces(decoded):
    """Return partial B02 field states without assigning winner or side roles."""
    context = decoded.get("context")
    if not context:
        return _unknown("BATTLE_SIDE_CONTEXT_UNAVAILABLE")
    if context["kind"] != 1:
        return _unknown("NAVAL_FORCE_FIELDS_NOT_CAPTURED", "unsupported")
    sides = []
    for index, side in enumerate(context["sides"]):
        if not side["present"] or not side["participants"]["complete"]:
            return _unknown("BATTLE_SIDE_CONTEXT_INCOMPLETE")
        raw = side["raw_fields"]
        # Do not silently clamp inconsistent native counts or replace a
        # missing side by a real zero. The rest of the battle stays usable.
        if any(value < 0 for value in raw) or any(raw[i + 3] > raw[i] for i in range(3)):
            return _unknown("LAND_FORCE_COUNTS_INCONSISTENT")
        start = [_divide(value) for value in raw[:3]]
        lost = [_divide(value) for value in raw[3:]]
        remaining = [initial - loss for initial, loss in zip(start, lost)]
        sides.append({
            "combat_side_index": index,
            "participants": [ref.to_bytes(8, "little")[:3].decode("ascii")
                             for ref in side["participants"]["full_refs"]],
            "units": {kind: {"initial": start[i], "lost": lost[i], "remaining": remaining[i]}
                      for i, kind in enumerate(KINDS)},
        })
    common = {"unit": "men", "scale": 1, "scope": "whole_combat_side",
              "basis": "native_land_result_template_integer_operands",
              "runtime_popup_verified": False}
    result = {}
    for field, phase in (("initial_forces", "initial"), ("losses", "lost"),
                         ("remaining_forces", "remaining")):
        value = dict(deepcopy(common), sides=[])
        for side in sides:
            counts = {kind: side["units"][kind][phase] for kind in KINDS}
            value["sides"].append({"combat_side_index": side["combat_side_index"],
                                   "participants": deepcopy(side["participants"]),
                                   "by_unit": counts, "component_sum": sum(counts.values())})
        if field == "losses":
            value["aggregate_display"] = project_aggregate_losses(decoded)
        result[field] = {"status": "known", "value": value}
    result["unit_breakdown"] = {"status": "known", "value": dict(deepcopy(common), sides=sides)}
    return result


def project_forces(decoded, mapping):
    """Use captured land operands or the already-normalized naval starts.

    237FC0 writes +124/+128/+12C/+130 /1000 into result raw_fields[3:7].
    22E6B0 -> 8CA460 binds the corresponding START keys to naval popup
    columns whose shared sprite frames identify the four ship classes.
    See information-battle-naval-20261026-001/naval-initial-binding-001.json.
    The optional v3 extension supplies net-change and remaining operands;
    legacy v2 records retain their initial-count-only projection.
    """
    context = decoded.get("context")
    if not context or context["kind"] != 2:
        return project_land_forces(decoded)
    result = {
        "losses": {"status": "unsupported", "reason": "NAVAL_LOSS_FIELDS_NOT_CAPTURED"},
        "remaining_forces": {"status": "unsupported", "reason": "NAVAL_REMAINING_FIELDS_NOT_CAPTURED"},
    }

    def incomplete(reason):
        fields = FIELDS if decoded.get("naval") is not None else ("initial_forces", "unit_breakdown")
        return dict(result, **{field: {"status": "unknown", "reason": reason} for field in fields})

    if len(mapping) != 2 or set(mapping) != {0, 1}:
        return incomplete("NAVAL_SIDE_MAPPING_UNRESOLVED")
    if any(not side["present"] or not side["participants"]["complete"]
           for side in context["sides"]):
        return incomplete("BATTLE_SIDE_CONTEXT_INCOMPLETE")
    starts = [side["raw_fields"][3:7] for side in decoded["observation"]["result"]["sides"]]
    if any(value < 0 for side in starts for value in side):
        return incomplete("NAVAL_INITIAL_COUNTS_INCONSISTENT")
    sides, breakdown = [None, None], [None, None]
    for result_index, combat_index in enumerate(mapping):
        participants = [ref.to_bytes(8, "little")[:3].decode("ascii")
                        for ref in context["sides"][combat_index]["participants"]["full_refs"]]
        counts = dict(zip(SHIP_KINDS, starts[result_index]))
        sides[combat_index] = {"combat_side_index": combat_index, "participants": participants,
                               "by_unit": counts, "component_sum": sum(counts.values())}
        breakdown[combat_index] = {
            "combat_side_index": combat_index, "participants": deepcopy(participants),
            "units": {kind: {"initial": count} for kind, count in counts.items()},
        }
    common = {"unit": "ships", "scale": 1, "scope": "whole_combat_side",
              "basis": "native_result_start_counts_gui_mapping", "runtime_popup_verified": False}
    result["initial_forces"] = {"status": "known", "value": dict(deepcopy(common), sides=sides)}
    result["unit_breakdown"] = {"status": "known", "value": dict(
        deepcopy(common), sides=breakdown, available_phases=["initial"],
        unavailable_phases=["lost", "remaining"])}
    if decoded.get("naval") is not None:
        _complete_naval_forces(result, decoded)
    elif decoded.get("wire", {}).get("version", 0) >= 3:
        for field in ("losses", "remaining_forces"):
            result[field] = {"status": "unknown", "reason": "NAVAL_EXTENSION_CAPTURE_UNAVAILABLE"}
    return result


def _complete_naval_forces(result, decoded):
    """Apply the native signed LOST/END operands from a complete v3 copy.

    Native LOST is a net change: -trunc(raw_loss/1000), plus captured-row
    quantities on the winning side and minus them on the losing side.
    A nonzero side+169 overrides it to -initial and END to zero. This does
    not classify annihilation/retreat or turn net change into gross losses.
    """
    def unknown(reason):
        for field in ("losses", "remaining_forces"):
            result[field] = {"status": "unknown", "reason": reason}

    winner = decoded["observation"]["summary"]["control_byte"]
    if winner not in (0, 1):
        unknown("NAVAL_OUTCOME_CONTROL_UNRESOLVED")
        return
    extension = decoded["naval"]
    rows = extension["row_types"]
    row_counts = [rows.count(index + 3) for index in range(4)]
    starts = result["initial_forces"]["value"]["sides"]
    net_sides, end_sides, units = [], [], []
    for index, side in enumerate(extension["sides"]):
        raw = side["raw_loss_i32"]
        if len(raw) != 4 or any(type(value) is not int or not -(2**31) <= value < 2**31 for value in raw):
            unknown("NAVAL_FORCE_COUNTS_INCONSISTENT")
            return
        initial = starts[index]["by_unit"]
        change = {kind: (-initial[kind] if side["raw_gate"] != 0 else
                          -_divide(raw[i]) + row_counts[i] * (1 if index == winner else -1))
                  for i, kind in enumerate(SHIP_KINDS)}
        remaining = {kind: initial[kind] + change[kind] for kind in SHIP_KINDS}
        if any(not 0 <= value < 2**31 for value in remaining.values()):
            unknown("NAVAL_FORCE_COUNTS_INCONSISTENT")
            return
        identity = {"combat_side_index": index, "participants": deepcopy(starts[index]["participants"])}
        net_sides.append(dict(identity, by_unit=change, component_sum=sum(change.values())))
        end_sides.append(dict(deepcopy(identity), by_unit=remaining, component_sum=sum(remaining.values())))
        units.append(dict(deepcopy(identity), units={kind: {
            "initial": initial[kind], "net_change": change[kind], "remaining": remaining[kind],
        } for kind in SHIP_KINDS}))
    common = {"unit": "ships", "scale": 1, "scope": "whole_combat_side",
              "basis": "native_naval_result_template_integer_operands", "runtime_popup_verified": False}
    result["losses"] = {"status": "known", "value": dict(
        deepcopy(common), sides=net_sides, quantity="net_ship_change",
        sign_convention="negative_loss_positive_gain",
        aggregate_display={"status": "unknown", "reason": "NAVAL_AGGREGATE_DISPLAY_UNRESOLVED"})}
    result["remaining_forces"] = {"status": "known", "value": dict(deepcopy(common), sides=end_sides)}
    result["unit_breakdown"] = {"status": "known", "value": dict(
        deepcopy(common), sides=units, available_phases=["initial", "net_change", "remaining"],
        unavailable_phases=[])}
