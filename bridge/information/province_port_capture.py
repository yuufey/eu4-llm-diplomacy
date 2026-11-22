"""Read a province has-port predicate for the configured observer.

The shared foreign-technology owner supplies process/session identity, a
read-only handle, code guards, two-pass replay, and cleanup. The province
reader supplies admission/discovery checks; this module only selects the
bounded ``G02.has_port`` leaf for the requested canonical province ID.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import foreign_technology_capture as _owner
from . import province_state_capture as _base
from . import province_port_memory as _leaf
from . import province_state_memory as _province


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "province-port-memory-1374-v1-sampling-r1.json"
PROFILE_SHA256 = "61be2796a7f2a48eab97675cc41d2cd821e04a849f14e3e182e226d6f57f9fad"
SCHEMA = "information.province_port_capture.v1"
INNER_SCHEMA = "information.province_port_observer_snapshot.v1"
_PROFILE_ID = "province-port-memory-1374"
_PROFILE_VERSION = 1


def _valid_id(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 0xFFFF


def _load_profile() -> dict[str, Any]:
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError("PROVINCE_PORT_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("PROVINCE_PORT_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != _PROFILE_ID
            or profile.get("profile_version") != _PROFILE_VERSION
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != _owner.EXE_SHA256):
        raise ValueError("PROVINCE_PORT_PROFILE_BUILD")
    for item in profile["source_evidence"] + profile["layout_dependencies"]:
        if not _base._matches_reviewed_layout(item):
            raise ValueError("PROVINCE_PORT_PROFILE_DEPENDENCY")
    return profile


def _observe_for(province_id: int, observer='FRA'):
    def observe(reader, module_base, country, profile):
        if country != observer or not _valid_id(province_id):
            raise ValueError("PROVINCE_PORT_OBSERVER_SCOPE")

        def backend(read, base, observer_country):
            if observer_country != observer:
                raise ValueError("PROVINCE_PORT_OBSERVER_SCOPE")
            return _province.read_two_pass(
                read,
                base,
                province_id,
                observer=observer,
                observer_scoped=True,
                fields=(_leaf.FIELD_HAS_PORT,),
                read_fields=_leaf.read_fields,
            )

        return _owner._observe(
            reader,
            module_base,
            country,
            profile,
            backend_reader=backend,
        )

    return observe


def capture(installation: Path, province_id: int, *, observer: str = "FRA") -> dict[str, Any]:
    if not _valid_id(province_id) or not isinstance(observer, str) or not _owner._TAG.fullmatch(observer):
        raise ValueError("PROVINCE_PORT_REQUEST_SCOPE")
    inner = _owner._capture_common(
        installation,
        observer,
        observer=observer,
        schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe_for(province_id, observer),
        allow_observer_target=True, observer_scoped=True,
    )
    return {
        "schema": SCHEMA,
        "observer": observer,
        "object": {"type": "province", "province_id": province_id},
        "capture": inner,
    }


def validate_capture(report: Any, context: dict[str, Any], creation: int,
                     province_id: int) -> bool:
    observer = context.get('observer') if isinstance(context, dict) else None
    if (not _valid_id(province_id) or not isinstance(report, dict)
            or not isinstance(observer, str) or not _owner._TAG.fullmatch(observer)):
        return False
    if set(report) != {"schema", "observer", "object", "capture"}:
        return False
    if report["schema"] != SCHEMA or report["observer"] != observer:
        return False
    expected = {"type": "province", "province_id": province_id}
    if not _owner._same(report["object"], expected):
        return False
    return _owner._validate_capture_common(
        report["capture"],
        context,
        creation,
        observer,
        schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe_for(province_id, observer),
        allow_observer_target=True, observer_scoped=True,
        require_access=True,
    )


__all__ = ["capture", "validate_capture"]
