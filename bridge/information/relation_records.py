"""Pure projection of selected-pair native diplomatic relation records.

The native diplomacy readers return an inspection for one action and one
country pair.  This module only projects the already returned object; it does
not call a game reader, infer a relation from an offer, or enumerate the
world.  A relation is publishable only when the family-specific
``relationship_state`` is complete and contains the matching boolean.

The public projection deliberately keeps selected endpoints separate from
the role fields.  ``selected_recipient`` is the endpoint requested from the
native inspection.  ``recipient`` is the relation role and is therefore
unknown unless the native role proof establishes it (currently only the
exclusive vassalization flags do so).
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping


_COUNTRY = re.compile(r"[A-Z0-9]{3}\Z")

SUPPORTED_FAMILIES = (
    "vassalization",
    "guarantee",
    "support_independence",
    "military_access",
    "rival",
)

# These are the query actions that the existing diplomacy readers use.  The
# projection still requires a family-specific relationship_state; an action
# id alone never establishes a current relation.
ACTION_MAPPING = {
    "offer_vassalization": "vassalization",
    "revoke_vassalization": "vassalization",
    "proclaim_guarantee": "guarantee",
    "revoke_guarantee": "guarantee",
    "support_independence": "support_independence",
    "revoke_support_independence": "support_independence",
    "ask_military_access": "military_access",
    "cancel_military_access": "military_access",
    "set_rival": "rival",
    "remove_rival": "rival",
}

_STATE_KEYS = {
    "vassalization": "vassal_active",
    "guarantee": "guarantee_active",
    "support_independence": "support_independence_active",
    "military_access": "military_access_active",
    "rival": "rival_active",
}
_VERIFIED_KEYS = {
    "vassalization": "vassal_state_verified",
    "guarantee": "guarantee_state_verified",
    "support_independence": "support_independence_state_verified",
    "military_access": "military_access_state_verified",
    "rival": "rival_state_verified",
}


def _known(value: Any) -> dict[str, Any]:
    return {"status": "known", "value": deepcopy(value)}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _not_applicable(reason: str) -> dict[str, Any]:
    return {"status": "not_applicable", "reason": reason}


def _country(value: Any) -> bool:
    return isinstance(value, str) and _COUNTRY.fullmatch(value) is not None


def _source_ref(inspection: Mapping[str, Any], source_ref: Any) -> dict[str, Any] | None:
    """Return a bounded provenance reference without retaining the inspection."""
    if isinstance(source_ref, str):
        return {"path": source_ref}
    if isinstance(source_ref, Mapping):
        return deepcopy(dict(source_ref))
    for key in ("source_ref", "raw_source_ref"):
        value = inspection.get(key)
        if isinstance(value, Mapping):
            return deepcopy(dict(value))
        if isinstance(value, str):
            return {"path": value}
    path = None
    for key in ("raw_sourcepath", "raw_source_path", "source_path"):
        if isinstance(inspection.get(key), str):
            path = inspection[key]
            break
    pointer = None
    for key in ("raw_json_pointer", "json_pointer", "source_pointer"):
        if isinstance(inspection.get(key), str):
            pointer = inspection[key]
            break
    if path is None and pointer is None:
        return None
    result: dict[str, Any] = {}
    if path is not None:
        result["path"] = path
    if pointer is not None:
        result["json_pointer"] = pointer
    return result


def _family_from_state(action_id: str, inspection: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Resolve family from an explicit family or one unique state key.

    Public archived inspections for the three non-vassal readers omit the
    redundant top-level ``family`` field.  Their unique state key is the
    native proof retained by ``inspect_diplomatic_action``.  This fallback is
    intentionally narrower than action-id mapping and rejects ambiguity.
    """
    explicit = inspection.get("family")
    if explicit is not None:
        if not isinstance(explicit, str) or explicit not in SUPPORTED_FAMILIES:
            return None, "UNSUPPORTED_RELATION_FAMILY", "explicit_family"
        family = explicit
        source = "inspection.family"
    else:
        state = inspection.get("relationship_state")
        if not isinstance(state, Mapping):
            return None, "RELATIONSHIP_STATE_UNREAD", "none"
        candidates = [family for family, key in _STATE_KEYS.items() if key in state]
        if len(candidates) != 1:
            return None, "RELATIONSHIP_FAMILY_AMBIGUOUS", "relationship_state"
        family = candidates[0]
        source = "relationship_state." + _STATE_KEYS[family]
    expected = ACTION_MAPPING.get(action_id)
    if expected is not None and expected != family:
        return None, "ACTION_FAMILY_MISMATCH", source
    return family, None, source


def _state_result(action_id: str, family: str, inspection: Mapping[str, Any]) -> tuple[bool | None, str | None]:
    state = inspection.get("relationship_state")
    if not isinstance(state, Mapping):
        return None, "RELATIONSHIP_STATE_UNREAD"
    active_key = _STATE_KEYS[family]
    active = state.get(active_key)
    if type(active) is not bool:
        return None, "RELATIONSHIP_ACTIVE_UNREAD"
    if state.get("complete") is not True:
        return None, "RELATIONSHIP_STATE_INCOMPLETE"

    # The semantic public object normally exposes ``complete`` as the
    # state-verified guard.  If the lower-level verifier is also present,
    # require it and require the duplicated top-level boolean to agree.
    top_active = inspection.get(active_key)
    if active_key in inspection:
        if type(top_active) is not bool:
            return None, "TOP_LEVEL_RELATIONSHIP_ACTIVE_INVALID"
        if top_active != active:
            return None, "RELATIONSHIP_ACTIVE_MISMATCH"
    verified_key = _VERIFIED_KEYS[family]
    if verified_key in inspection and inspection.get(verified_key) is not True:
        return None, "RELATIONSHIP_STATE_GUARD_FAILED"
    return active, None


def _role_fields(family: str, active: bool, actor: str, selected_recipient: str,
                 inspection: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    if not active:
        return (
            _not_applicable("NO_ACTIVE_RELATION_FOR_SELECTED_PAIR"),
            _not_applicable("NO_ACTIVE_RELATION_FOR_SELECTED_PAIR"),
            [],
        )
    if family != "vassalization":
        if family == "rival":
            reason = "RIVAL_HAS_NO_GRANTOR_RECIPIENT_ROLE"
            return _not_applicable(reason), _not_applicable(reason), []
        return _unknown("RELATION_ROLE_DIRECTION_UNPROVEN"), _unknown(
            "RELATION_ROLE_DIRECTION_UNPROVEN"), ["RELATION_ROLE_DIRECTION_UNPROVEN"]

    overlord = inspection.get("actor_is_overlord")
    subject = inspection.get("actor_is_subject")
    if type(overlord) is not bool or type(subject) is not bool:
        return _unknown("VASSAL_ROLE_FLAGS_UNREAD"), _unknown("VASSAL_ROLE_FLAGS_UNREAD"), [
            "VASSAL_ROLE_FLAGS_UNREAD"
        ]
    if overlord is True and subject is False:
        return _known(actor), _known(selected_recipient), []
    if overlord is False and subject is True:
        return _known(selected_recipient), _known(actor), []
    return _unknown("VASSAL_ROLE_FLAGS_NOT_EXCLUSIVE"), _unknown(
        "VASSAL_ROLE_FLAGS_NOT_EXCLUSIVE"), ["VASSAL_ROLE_FLAGS_NOT_EXCLUSIVE"]


def _empty_result(missing: list[str], source: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "records": [],
        "missing": list(dict.fromkeys(missing)),
        "source_refs": [source] if source is not None else [],
    }


def project(action_id: str, inspection: Mapping[str, Any], actor: str,
            recipient: str, *, source_ref: Any = None) -> dict[str, Any]:
    """Project one real ``inspect_diplomatic_action`` object.

    The function is intentionally side-effect free.  It returns one selected
    pair row when the input has valid endpoints, including an unknown row for
    an unsupported or incomplete relation state.  Invalid endpoints return no
    row so a caller cannot accidentally publish a relation for a different
    pair.
    """
    source = _source_ref(inspection, source_ref) if isinstance(inspection, Mapping) else None
    if not isinstance(action_id, str) or not action_id:
        return _empty_result(["ACTION_ID_INVALID"], source)
    if not isinstance(inspection, Mapping):
        return _empty_result(["INSPECTION_INVALID"], source)
    if not _country(actor) or not _country(recipient) or actor == recipient:
        return _empty_result(["COUNTRY_PAIR_INVALID"], source)
    for key, wanted in (("actor", actor), ("recipient", recipient)):
        if key in inspection and inspection.get(key) != wanted:
            return _empty_result(["INSPECTION_ENDPOINT_MISMATCH"], source)

    family, family_reason, family_source = _family_from_state(action_id, inspection)
    missing: list[str] = ["RELATION_EXPIRY_UNREAD"]
    if family_reason is not None or family is None:
        missing.extend([family_reason or "RELATION_FAMILY_UNREAD",
                        "RELATION_TYPE_UNVERIFIED", "RELATION_STATUS_UNVERIFIED"])
        relation_type = _unknown("RELATION_TYPE_UNVERIFIED")
        status = _unknown("RELATION_STATUS_UNVERIFIED")
        grantor = _unknown("RELATION_ROLE_UNPROVEN")
        role_recipient = _unknown("RELATION_ROLE_UNPROVEN")
        family_name = None
    else:
        family_name = family
        active, state_reason = _state_result(action_id, family, inspection)
        if state_reason is not None or active is None:
            missing.extend([state_reason or "RELATION_STATE_UNVERIFIED",
                            "RELATION_TYPE_UNVERIFIED", "RELATION_STATUS_UNVERIFIED"])
            relation_type = _unknown("RELATION_TYPE_UNVERIFIED")
            status = _unknown("RELATION_STATUS_UNVERIFIED")
            grantor = _unknown("RELATION_ROLE_UNPROVEN")
            role_recipient = _unknown("RELATION_ROLE_UNPROVEN")
        else:
            relation_type = _known(family)
            status = _known("active" if active else "inactive")
            grantor, role_recipient, role_missing = _role_fields(
                family, active, actor, recipient, inspection)
            missing.extend(role_missing)

    visibility = inspection.get("visibility")
    if isinstance(visibility, Mapping):
        visibility_value: Any = deepcopy(dict(visibility))
    else:
        visibility_value = _unknown("VISIBILITY_UNREAD")
        missing.append("VISIBILITY_UNREAD")

    row: dict[str, Any] = {
        "actor": actor,
        "selected_recipient": recipient,
        "relation_type": relation_type,
        "status": status,
        "grantor": grantor,
        "recipient": role_recipient,
        "expires_at": _unknown("RELATION_EXPIRY_UNREAD"),
        "visibility": visibility_value,
    }
    if family_name is not None:
        row["family_source"] = family_source
    if source is not None:
        row["raw_sourcepath"] = source.get("path")
        if source.get("json_pointer") is not None:
            row["raw_json_pointer"] = source["json_pointer"]
    return {
        "records": [row],
        "missing": list(dict.fromkeys(missing)),
        "source_refs": [source] if source is not None else [],
    }


__all__ = ["ACTION_MAPPING", "SUPPORTED_FAMILIES", "project"]
