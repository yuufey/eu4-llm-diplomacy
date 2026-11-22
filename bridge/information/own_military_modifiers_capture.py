"""Identity-bound aggregate military-modifier capture and projection.

This is an independent public wrapper around the already pinned foreign-quality
observation.  It deliberately keeps the quality reader/profile and the shared
read-only capture/replay lifecycle intact, while using a separate outer schema
and a small public whitelist.  The wrapper does not infer a complete modifier
table or expose native addresses/raw-input traces.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import partial
import math
import re
from typing import Any

from . import foreign_quality_capture as _quality_capture
from . import foreign_quality_projection as _quality_projection
from . import foreign_technology as _technology
from . import foreign_technology_capture as _owner


OBSERVER = "FRA"
SCHEMA = "information.own_military_modifiers_capture.v1"
FIELD = "military_modifiers"

# The old quality profile is intentionally reused, not edited or repinned.  It
# supplies the ROM/process/NPC/country-view/quality-ledger/two-pass guards that
# this self-target wrapper requires.
PROFILE_FILE = _quality_capture.PROFILE_FILE
PROFILE_SHA256 = _quality_capture.PROFILE_SHA256
PROFILE_ID = _quality_capture.PROFILE_ID

_SELECTED = {
    "army": ("siege_ability", "defensiveness"),
    "navy": ("ship_durability",),
}
_SELECTED_KEYS = tuple(
    f"{group}.{key}" for group, keys in _SELECTED.items() for key in keys
)
_REASON = _quality_projection._REASON
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1


def capture(installation, *, observer: str = OBSERVER) -> dict[str, Any]:
    """Capture the logical observer through the shared readonly owner."""
    return _owner._capture_common(
        installation,
        observer,
        observer=observer,
        schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_quality_capture._load_profile,
        observe=partial(_quality_capture._observe, observer=observer),
        allow_observer_target=True,
        observer_scoped=True,
    )


def validate_capture(report: Any, context: Mapping[str, Any], creation: int) -> bool:
    """Strictly replay a saved self-target capture without attaching."""
    if not isinstance(report, dict) or not isinstance(context, Mapping) or report.get("schema") != SCHEMA:
        return False
    observer = context.get('observer')
    return _owner._validate_capture_common(
        report,
        context,
        creation,
        observer,
        schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_quality_capture._load_profile,
        observe=partial(_quality_capture._observe, observer=observer),
        allow_observer_target=True,
        require_access=True,
        observer_scoped=True,
    )


def _safe_reason(value: Any, default: str) -> str:
    return value if isinstance(value, str) and _REASON.fullmatch(value) else default


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _target(report: Any) -> Mapping[str, Any] | None:
    """Return only the stable observer target from a completed report.

    Full saved-trace validation is owned by :func:`validate_capture` and its
    caller supplies the bound session context/creation time.  This projection
    gate still rejects incomplete, unstable, wrong-schema, wrong-target, or
    wrong-profile packets before consulting the public quality projection.
    """
    if (not isinstance(report, Mapping)
            or report.get("schema") != SCHEMA
            or report.get("status") != "observed"
            or report.get("completed") is not True
            or report.get("profile_sha256") != PROFILE_SHA256):
        return None
    request = report.get("request")
    cleanup = report.get("cleanup")
    observer = request.get("observer") if isinstance(request, Mapping) else None
    if (not isinstance(observer, str) or not re.fullmatch(r"[A-Z0-9]{3}", observer)
            or request.get("country") != observer
            or not isinstance(cleanup, Mapping)
            or cleanup.get("status") != "closed"
            or cleanup.get("closed") is not True
            or cleanup.get("success") is not True):
        return None
    observation = report.get("observation")
    if (not isinstance(observation, Mapping)
            or observation.get("stable") is not True):
        return None
    backend = observation.get("backend")
    if (not isinstance(backend, Mapping)
            or backend.get("status") != "observed"
            or not isinstance(backend.get("consistency"), Mapping)
            or backend["consistency"].get("status") != "stable"):
        return None
    try:
        item = _technology._backend_item(report, observer)
    except (KeyError, TypeError, ValueError, IndexError):
        return None
    if not isinstance(item, Mapping):
        return None
    return item


def _safe_component(component: Any) -> dict[str, Any]:
    """Copy one already validated quality component without private fields."""
    if not isinstance(component, Mapping):
        return _unknown("QUALITY_COMPONENT_MISSING")
    if component.get("status") != "known":
        return _unknown(_safe_reason(component.get("reason"), "QUALITY_COMPONENT_UNKNOWN"))
    raw = component.get("raw")
    value = component.get("value")
    if (type(raw) is not int or not _I32_MIN <= raw <= _I32_MAX
            or component.get("unit") != "ratio_modifier"
            or type(component.get("scale")) is not int
            or component.get("scale") != 1000
            or type(value) not in (int, float)
            or not math.isfinite(value)
            or value != raw / 1000):
        return _unknown("QUALITY_COMPONENT_INVALID")
    return {
        "status": "known",
        "value": value,
        "raw": raw,
        "unit": "ratio_modifier",
        "scale": 1000,
    }


def _selected_unknowns(reason: str) -> dict[str, dict[str, dict[str, Any]]]:
    return {
        group: {key: _unknown(reason) for key in keys}
        for group, keys in _SELECTED.items()
    }


def project_field(report: Any) -> dict[str, Any]:
    """Whitelist the three selected aggregate modifiers from the validated observer.

    The quality projection may know any subset of its twelve components.  This
    function reports ``known`` only if at least one of the three selected
    components is known, and keeps each other selected component independently
    ``unknown``.  The returned field is explicitly a key subset, not a claim of
    complete modifiers or instance-level contribution.
    """
    item = _target(report)
    if item is None:
        return _unknown("OWN_MILITARY_MODIFIERS_CAPTURE_NOT_VALIDATED")
    try:
        view = _technology._country_view(item)
        permission = _quality_projection.permission(item, view)
        quality = _quality_projection.project(item, view, permission)
    except (KeyError, TypeError, ValueError, IndexError):
        return _unknown("OWN_MILITARY_MODIFIERS_CAPTURE_INVALID")

    status = quality.get("status") if isinstance(quality, Mapping) else None
    if status == "invisible":
        return {"status": "invisible",
                "reason": _safe_reason(quality.get("reason"),
                                        "QUALITY_PERMISSION_DENIED")}
    if status != "known":
        return _unknown(_safe_reason(
            quality.get("reason") if isinstance(quality, Mapping) else None,
            "QUALITY_COMPONENTS_UNKNOWN"))

    values = quality.get("value")
    if not isinstance(values, Mapping):
        return _unknown("QUALITY_FIELD_INVALID")
    selected = _selected_unknowns("QUALITY_COMPONENT_UNKNOWN")
    known_count = 0
    for group, keys in _SELECTED.items():
        group_values = values.get(group)
        for key in keys:
            component = group_values.get(key) if isinstance(group_values, Mapping) else None
            public = _safe_component(component)
            selected[group][key] = public
            if public.get("status") == "known":
                known_count += 1

    if not known_count:
        return _unknown("SELECTED_MILITARY_MODIFIERS_UNKNOWN")
    return {
        "status": "known",
        "value": selected,
        "key_subset": list(_SELECTED_KEYS),
        "unit": "military_modifier_map",
        "scale": 1,
        "period": "current",
        "complete": False,
        "partial": True,
        "basis": "native_selected_military_modifier_cache",
        "value_origin": "derived_from_copied_native_aggregate_modifiers",
    }


__all__ = [
    "capture", "validate_capture", "project_field", "SCHEMA", "FIELD",
    "PROFILE_FILE", "PROFILE_SHA256", "PROFILE_ID", "OBSERVER",
]
