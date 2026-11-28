"""Select a current observer war from the reviewed read-only country index.

The source establishes the two opposing membership vectors, not which side is
attacking or defending.  Its optional war IDs are scoped to the observer
session and are available only when the shared native registry has an entry.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
from typing import Any, Mapping

from . import map_live_capture as _map
from .information import country_scale_capture as _capture
from .information import country_wars_memory as _wars
from .information import foreign_technology_capture as _owner
from .information.country_scale import NativeCountryScaleSource
from .information.truce_date_math import decode_date


SCHEMA = "eu4.map_military_war_scope.v1"
_WAR_ID = re.compile(r"war_[0-9a-f]{16}_([0-9a-f]{8})\Z", re.ASCII)


def _empty(reason: str, *, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": "unavailable", "date": None,
        "date_raw": None, "identity": None, "world_token": None,
        "war_id": None, "participants": [], "sides": None, "reason": reason,
        **(dict(context) if context is not None else {}),
    }


def _project_wars(field: Any) -> dict[str, Any]:
    """Use the reviewed projection with registry-recycling serials preserved.

    The country-index leaf accepts lifetime serials beyond 256 for reusable
    registry slots. Its older public projection still limits the serial to a
    slot number. After replay has verified the real registry, give that shape
    validator unique temporary slot-sized IDs and restore the verified IDs.
    """
    value = field.get("value") if isinstance(field, Mapping) else None
    wars = value.get("wars") if isinstance(value, Mapping) else None
    if not isinstance(wars, list) or len(wars) > 32:
        return NativeCountryScaleSource._project_value("wars", field)
    real_ids: dict[int, str] = {}
    used: set[str] = set()
    for index, war in enumerate(wars):
        identity = war.get("war_id") if isinstance(war, Mapping) else None
        if not isinstance(identity, Mapping) or identity.get("status") != "known":
            continue
        identifier = identity.get("value")
        match = _WAR_ID.fullmatch(identifier) if isinstance(identifier, str) else None
        if match is None or int(match.group(1), 16) == 0 or identifier in used:
            return NativeCountryScaleSource._project_value("wars", field)
        used.add(identifier)
        real_ids[index] = identifier
    normalized = deepcopy(field)
    for index, identifier in real_ids.items():
        if int(identifier[-8:], 16) <= 256:
            continue
        prefix = identifier[:-8]
        replacement = next(prefix + f"{serial:08x}" for serial in range(1, 257)
                           if prefix + f"{serial:08x}" not in used)
        used.add(replacement)
        normalized["value"]["wars"][index]["war_id"]["value"] = replacement
    projected = NativeCountryScaleSource._project_value("wars", normalized)
    if projected.get("status") == "known":
        for index, identifier in real_ids.items():
            projected["value"]["wars"][index]["war_id"]["value"] = identifier
    return projected


def capture_war_scope(installation: str | Path, observer: str,
                      war_id: str | None = None) -> dict[str, Any]:
    """Return the verified participants in one of the observer's current wars.

    With one war, its participants can be selected even when the session's
    war registry has no ID. With several, the caller must specify a known ID.
    An explicit ID can select only an ID bound by the shared registry. Unknown
    member identities reject the whole selection. A country at peace returns
    an empty known scope when no ID was requested. The read does not call game
    functions or write game memory.
    """
    path = Path(installation).expanduser()
    if not path.is_file():
        raise _map.MapLiveCaptureError("MAP_LIVE_INSTALLATION_MISSING")
    if not isinstance(observer, str) or _map._TAG.fullmatch(observer) is None:
        raise _map.MapLiveCaptureError("MAP_LIVE_OBSERVER_INVALID")
    if war_id is not None:
        match = _WAR_ID.fullmatch(war_id) if isinstance(war_id, str) else None
        if match is None or int(match.group(1), 16) == 0:
            raise _map.MapLiveCaptureError("MAP_MILITARY_WAR_ID_INVALID")

    report = _capture.capture(path, observer, observer=observer)
    if (not isinstance(report, Mapping) or report.get("status") != "observed"
            or report.get("completed") is not True):
        return _empty("WAR_SCOPE_CAPTURE_FAILED_OR_UNSTABLE")

    try:
        request = report["request"]
        observation = report["observation"]
        before = observation["context_before"]
        after = observation["context_after"]
        if (not isinstance(request, Mapping) or not isinstance(observation, Mapping)
                or observation.get("stable") is not True
                or not isinstance(before, Mapping) or not isinstance(after, Mapping)
                or before != after
                or observation.get("runtime_code_before") != observation.get("runtime_code_after")):
            raise ValueError("unstable observation")
        date_raw = after["game_date"]
        year, month, day, _ = decode_date(date_raw)
        identity = {key: request.get(key) for key in ("pid", "creation_filetime", "session_id")}
        if (type(identity["pid"]) is not int or identity["pid"] <= 0
                or type(identity["creation_filetime"]) is not int or identity["creation_filetime"] <= 0
                or not isinstance(identity["session_id"], str) or not identity["session_id"]):
            raise ValueError("invalid process identity")
        world_token = _map._world_token(after)
        if world_token is None:
            raise ValueError("missing world identity")

        replay_context = {
            "observer": observer, "session_id": identity["session_id"],
            "game_version": "1.37.4", "game_sha256": _owner.EXE_SHA256,
            "game_date": date_raw,
        }
        if not _capture.validate_capture(report, replay_context, identity["creation_filetime"], observer):
            raise ValueError("capture replay failed")
        backend = observation["backend"]
        targets = backend["targets"]
        if (backend.get("status") != "observed" or backend["observer"].get("tag") != observer
                or not isinstance(targets, list) or len(targets) != 1
                or targets[0].get("tag") != observer):
            raise ValueError("invalid observer target")
        target = targets[0]
        if target["field_consistency"][_wars.FIELD_WARS].get("status") != "stable":
            raise ValueError("wars field unstable")
        projected = _project_wars(target["fields"][_wars.FIELD_WARS])
        if projected.get("status") != "known":
            raise ValueError("wars field unavailable")
        current = projected["value"]["wars"]
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return _empty("WAR_SCOPE_CAPTURE_INVALID")

    context = {"date": f"{year}.{month}.{day}", "date_raw": date_raw,
               "identity": identity, "world_token": world_token}
    if war_id is None:
        if not current:
            return {**_empty("OBSERVER_NO_ACTIVE_WARS", context=context), "status": "known"}
        if len(current) != 1:
            return _empty("WAR_SELECTION_REQUIRED", context=context)
        selected = current[0]
    else:
        matches = [war for war in current
                   if war["war_id"].get("status") == "known" and war["war_id"].get("value") == war_id]
        if len(matches) != 1:
            reason = ("WAR_ID_UNRESOLVED" if any(war["war_id"].get("status") != "known"
                                                 for war in current)
                      else "WAR_ID_NOT_ACTIVE_FOR_OBSERVER")
            return _empty(reason, context=context)
        selected = matches[0]

    if selected["identities_complete"] is not True:
        return _empty("WAR_PARTICIPANTS_INCOMPLETE", context=context)
    sides = {side: [member["country"] for member in selected[side]]
             for side in ("side_a", "side_b")}
    if observer not in sides[selected["target_side"]]:
        return _empty("WAR_OBSERVER_MEMBERSHIP_INVALID", context=context)
    selected_id = selected["war_id"]
    known_id = selected_id.get("value") if selected_id.get("status") == "known" else None
    return {
        "schema": SCHEMA, "status": "known", **context,
        "war_id": known_id,
        "participants": [*sides["side_a"], *sides["side_b"]],
        "sides": sides,
        "reason": selected_id.get("reason") if known_id is None else None,
    }
