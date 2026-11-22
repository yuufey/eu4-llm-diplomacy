"""Identity-bound capture and strict trace validation for R04 modifiers."""
from __future__ import annotations

from collections.abc import Mapping
from functools import partial
import re
from typing import Any

from . import foreign_technology_capture as _owner
from . import opinion_modifiers_memory as _memory


OBSERVER = _memory.OBSERVER
SCHEMA = _memory.SCHEMA
PROFILE_FILE = _memory.PROFILE_FILE
PROFILE_SHA256 = _memory.PROFILE_SHA256
PROFILE_ID = _memory.PROFILE_ID
FIELDS = _memory.FIELDS
_TAG = re.compile(r"[A-Z0-9]{3}\Z")


def capture(installation, country: str, *, observer: str = OBSERVER) -> dict[str, Any]:
    """Capture one selected non-observer country through the shared owner."""
    if (not isinstance(observer, str) or _TAG.fullmatch(observer) is None
            or not isinstance(country, str) or _TAG.fullmatch(country) is None or country == observer):
        raise ValueError("OPINION_MODIFIERS_REQUEST_SCOPE")
    return _owner._capture_common(
        installation,
        country,
        observer=observer,
        schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_memory._load_profile,
        observe=partial(_memory._observe, observer=observer), observer_scoped=True,
    )


def validate_capture(report: Any, context: Mapping[str, Any], creation: int,
                     country: str) -> bool:
    """Recompute the saved raw trace without attaching to a process."""
    if not isinstance(report, Mapping) or report.get("schema") != SCHEMA:
        return False
    return _owner._validate_capture_common(
        report,
        context,
        creation,
        country,
        schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_memory._load_profile,
        observe=partial(_memory._observe, observer=context.get('observer')), observer_scoped=True,
        require_access=True,
    )


__all__ = [
    "capture", "validate_capture", "SCHEMA", "PROFILE_FILE", "PROFILE_SHA256",
    "PROFILE_ID", "FIELDS", "OBSERVER",
]
