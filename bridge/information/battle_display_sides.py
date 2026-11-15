"""Attach copied participants to fixed-build formatter input sides.

232A80 and 22E6B0 read direct OUR rows from combat+20 and ENEMY
rows from combat+28. The summary pairs are restored to that same order
before formatting. Result slots may be reversed; their representatives
must be matched by full reference. Fixed-build combat save keys establish
combat0 as attacker and combat1 as defender, independently of result order.

Evidence: information-battle-title-20261026-001/template-side-binding-001.
Role evidence: information-battle-roles-20261107-248-001/native-role-contract.json.
"""
from __future__ import annotations

import re


PROVENANCE = {
    "game_version": "1.37.4",
    "exe_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
    "land_evidence_id": "ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89",
    "naval_evidence_id": "ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e",
    "battle_role_basis": "fixed1374_combat_save_keys",
    "battle_role_contract": "work/runtime/information-battle-roles-20261107-248-001/native-role-contract.json",
}
COMBAT_ROLES = ("attacker", "defender")
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_COMMON = {"PRESTIGE", "TRADITION", "EXHAUSTION", "LEADER", "LEADERICON",
           "FIRE", "SHOCK", "MANEUVER"}
_SUFFIXES = {
    "land": _COMMON | {"SIEGE", "LOST"} | {
        unit + phase for unit in ("CAV", "INF", "ART")
        for phase in ("START", "LOST", "END")},
    "naval": _COMMON | {
        unit + phase for unit in ("CAV", "INF", "ART", "TRANS")
        for phase in ("START", "LOST", "END")},
}


def _unknown(reason):
    return {"status": "unknown", "reason": reason}


def _tag(ref):
    if type(ref) is not int or not 0 < ref < 2**64:
        return None
    try:
        tag = ref.to_bytes(8, "little")[:3].decode("ascii")
    except UnicodeError:
        return None
    return tag if _TAG.fullmatch(tag) else None


def control_side_binding(key: str, kind: str) -> dict:
    # An explicit suffix set prevents a new OUR-prefixed key (for example
    # an icon, flag or outcome control) acquiring an unproved side binding.
    for index, label in enumerate(("OUR", "ENEMY")):
        if key.startswith(label) and key[len(label):] in _SUFFIXES.get(kind, ()):
            return {"status": "known", "value": {
                "template_label": label, "combat_side_index": index,
                "scope": "whole_combat_side", "basis": "fixed1374_formatter_input",
            }}
    return _unknown("CONTROL_SIDE_BINDING_UNRESOLVED")


def project_side_identity(decoded: dict, mapping=None, observer_ref=None) -> dict:
    context = decoded.get("context") or {}
    sides = context.get("sides")
    if (context.get("known_router") is not True or context.get("kind") not in (1, 2)
            or not isinstance(sides, list) or len(sides) != 2):
        return _unknown("TEMPLATE_SIDE_CONTEXT_UNRESOLVED")
    refs = []
    for side in sides:
        participants = side.get("participants") or {}
        values = participants.get("full_refs")
        if (side.get("present") is not True or participants.get("complete") is not True
                or not isinstance(values, list) or not values
                or any(_tag(ref) is None for ref in values)):
            return _unknown("TEMPLATE_SIDE_CONTEXT_UNRESOLVED")
        refs.append(values)
    if set(refs[0]) & set(refs[1]):
        return _unknown("TEMPLATE_SIDE_CONTEXT_UNRESOLVED")

    result_sides = (decoded.get("observation", {}).get("result") or {}).get("sides", [])
    derived = []
    if len(result_sides) == 2:
        for result in result_sides:
            ref = result.get("country")
            matches = [i for i, members in enumerate(refs) if ref in members]
            if _tag(ref) is None or len(matches) != 1:
                break
            derived.append(matches[0])
    valid_mapping = len(derived) == 2 and set(derived) == {0, 1}
    if mapping is not None:
        valid_mapping = (valid_mapping and isinstance(mapping, (list, tuple))
                         and len(mapping) == 2
                         and all(type(index) is int for index in mapping)
                         and list(mapping) == derived)
    observer_sides = ([i for i, members in enumerate(refs) if observer_ref in members]
                      if _tag(observer_ref) is not None else [])
    observer_index = observer_sides[0] if len(observer_sides) == 1 else None
    labels = ("OUR", "ENEMY")
    return {"status": "known", "value": {
        "basis": "native_formatter_combat_sides_with_copied_participants",
        "binding_provenance": dict(PROVENANCE), "scope": "whole_combat_side",
        "sides": [{
            "template_label": labels[i], "combat_side_index": i,
            "participants": [_tag(ref) for ref in members],
            "participant_full_refs": [f"{ref:016x}" for ref in members],
            "result_side_index": ({"status": "known", "value": derived.index(i)}
                                  if valid_mapping else _unknown("RESULT_SIDE_MAPPING_UNRESOLVED")),
            "observer_participated": i == observer_index if observer_index is not None else None,
        } for i, members in enumerate(refs)],
        "observer_template_label": ({"status": "known", "value": labels[observer_index]}
                                    if observer_index is not None
                                    else _unknown("TEMPLATE_OBSERVER_SIDE_UNRESOLVED")),
        "attack_defend_roles": {"status": "known", "value": {"attacker": 0, "defender": 1}},
    }}
