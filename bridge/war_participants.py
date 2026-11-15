"""Pointer-free validation of QUERY1's optional native side membership."""
from __future__ import annotations

from copy import deepcopy
import re


SOURCE = "native_war_side_vectors"
_KEYS = {"source", "status", "complete", "side_a", "side_b",
         "actor_side", "recipient_side", "reason"}
_COUNTRY = re.compile(r"[A-Z0-9]{3}\Z")
_REASON = re.compile(r"[A-Z0-9_]{1,80}\Z")


def project_war_participants(raw: object, actor: str, recipient: str) -> dict | None:
    """Validate one already-bound row; side labels imply no leader or role.

    Missing extension data remains distinct from a genuine empty collection.
    Native failures carry no retained partial countries.  This helper never
    promotes an incomplete read to a complete participant list.
    """
    if (not isinstance(raw, dict) or set(raw) != _KEYS
            or raw.get("source") != SOURCE
            or not isinstance(actor, str) or _COUNTRY.fullmatch(actor) is None
            or not isinstance(recipient, str) or _COUNTRY.fullmatch(recipient) is None
            or actor == recipient):
        return None
    if raw.get("status") == "unknown":
        reason = raw.get("reason")
        if (raw.get("complete") is not False or raw.get("side_a") != []
                or raw.get("side_b") != [] or raw.get("actor_side") is not None
                or raw.get("recipient_side") is not None or not isinstance(reason, str)
                or _REASON.fullmatch(reason) is None):
            return None
        return deepcopy(raw)
    if (raw.get("status") != "available" or raw.get("complete") is not True
            or raw.get("reason") is not None):
        return None
    seen: set[str] = set()
    sides = {}
    for name in ("side_a", "side_b"):
        tags = raw.get(name)
        if not isinstance(tags, list) or not 1 <= len(tags) <= 256:
            return None
        for tag in tags:
            if not isinstance(tag, str) or _COUNTRY.fullmatch(tag) is None or tag in seen:
                return None
            seen.add(tag)
        sides[name] = set(tags)
    actor_side, recipient_side = raw.get("actor_side"), raw.get("recipient_side")
    if (not isinstance(actor_side, str) or actor_side not in sides
            or not isinstance(recipient_side, str) or recipient_side not in sides
            or actor_side == recipient_side or actor not in sides[actor_side]
            or recipient not in sides[recipient_side]):
        return None
    return deepcopy(raw)
