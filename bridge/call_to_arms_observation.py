"""Public projection of fixed-build, pre-executor CallAction observations."""
from copy import deepcopy
import hashlib
import json
import re


CAPABILITY = "native_call_to_arms_observation"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_FLAG_NAMES = ("defensive_war_with", "replace", "autojoin", "full_ally", "union", "promised_land", "ignore")


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def public_observation(event, session_id, *, controlled_country):
    if not isinstance(event, dict):
        return None
    actor, recipient = event.get("actor"), event.get("recipient")
    flags, enemies = event.get("flags_raw"), event.get("specific_enemies")
    if (event.get("event") != "native_call_to_arms_observed"
            or event.get("session_id") != session_id
            or event.get("action_id") != "call_to_arms"
            or not isinstance(actor, str) or not _TAG.fullmatch(actor)
            or not isinstance(controlled_country, str) or not _TAG.fullmatch(controlled_country)
            or recipient != controlled_country or actor == recipient
            or event.get("capture_stage") != "before_native_executor"
            or event.get("recipient_verified") is not True
            or event.get("ai_response_held") is not False
            or not _integer(event.get("observation_id"), 1, 2**63 - 1)
            or not _integer(event.get("date_raw"), 1, 2**31 - 1)
            or any(not _integer(event.get(key), -(2**31), 2**31 - 1)
                   for key in ("native_date28", "native_date2c", "native_token3c", "call_type_raw"))
            or not isinstance(flags, list) or len(flags) != 7
            or any(not _integer(value, 0, 255) for value in flags)
            or type(event.get("versus_verified")) is not bool
            or type(event.get("specific_enemies_verified")) is not bool
            or not isinstance(enemies, list) or len(enemies) > 128
            or any(not isinstance(tag, str) or not _TAG.fullmatch(tag) for tag in enemies)
            or not _integer(event.get("specific_enemies_count"), 0, 128)):
        return None
    versus = event.get("versus")
    if event["versus_verified"] and (not isinstance(versus, str)
                                    or (versus != "---" and not _TAG.fullmatch(versus))):
        return None
    if event["specific_enemies_verified"] and len(enemies) != event["specific_enemies_count"]:
        return None
    try:
        serialized = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return None
    public_id = hashlib.sha256((session_id + "\0call\0" + serialized).encode("utf-8")).hexdigest()[:32]
    gaps = ["CALL_TO_ARMS_AI_RESPONSE_NOT_HELD", "CALL_TO_ARMS_CURRENT_PENDING_UNKNOWN",
            "CALL_TO_ARMS_CALL_TYPE_SEMANTICS_UNKNOWN", "CALL_TO_ARMS_WAR_ID_UNRESOLVED"]
    opponent = None if versus == "---" else versus
    parameters = {
        "versus": ({"status": "known", "value": opponent} if event["versus_verified"] else
                   {"status": "unknown", "reason": "VERSUS_COUNTRY_UNRESOLVED"}),
        "specific_enemies": ({"status": "known", "value": list(enemies)} if event["specific_enemies_verified"] else
                             {"status": "unknown", "reason": "SPECIFIC_ENEMIES_UNRESOLVED",
                              "native_count": event["specific_enemies_count"]}),
        "call_type": {"status": "unknown", "raw": event["call_type_raw"], "reason": "CALL_TYPE_ENUM_UNRESOLVED"},
        "response_control": {"ai_response_held": False, "response_supported": False},
        "native_date_fields": {"date28": event["native_date28"], "date2c": event["native_date2c"],
                               "semantics": "uninterpreted_native_dates"},
    }
    for index, name in enumerate(_FLAG_NAMES):
        value = bool(flags[index]) if name == "replace" else flags[index] == 0
        parameters[name] = {"status": "known", "value": value, "raw": flags[index],
                            "basis": "fixed1374_native_save_field"}
    if not event["versus_verified"]:
        gaps.append("CALL_TO_ARMS_VERSUS_UNRESOLVED")
    if not event["specific_enemies_verified"]:
        gaps.append("CALL_TO_ARMS_SPECIFIC_ENEMIES_UNRESOLVED")
    return {"proposal_id": public_id, "action_id": "call_to_arms", "family": "call_to_arms",
            "actor": actor, "recipient": recipient, "phase": "initiate",
            "date_raw": event["date_raw"], "observer_status": "observed_before_native_processing",
            "identity_scope": "captured_observation", "parameters": deepcopy(parameters),
            "complete": False, "gaps": gaps}
