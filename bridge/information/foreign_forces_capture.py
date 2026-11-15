"""Identity-bound observation of foreign army and navy statistic inputs.

The shared parent owns process/session identity, ROM guards, the complete
country scan, FRA non-player admission, and ordered two-pass replay. The
military-stat permission and the two force leaves remain field-local; they do
not alter admission for unrelated fields. This module does not call game
functions or open process handles itself.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import foreign_country_memory as _backend
from . import foreign_force_statistics_memory as _forces
from . import foreign_manpower_capture as _manpower_capture
from . import foreign_military_visibility_memory as _visibility
from . import foreign_technology_capture as _owner
from . import mission_memory as _mm

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "foreign-force-statistics-memory-1374-sampling-r1.json"
PROFILE_SHA256 = "eaede9a7159181fb55e46d7d0a48fc29e4122cd12cb24f7df25a3c441e0e024e"
PROFILE_ID = "foreign-force-statistics-memory-1374"
EXE_SHA256 = _owner.EXE_SHA256
SCHEMA = "information.foreign_forces_capture.v1"
OBSERVER = "FRA"
ARMY_FIELD = "F02.visible_army"
NAVY_FIELD = "F02.visible_navy"
VISIBILITY_FIELD = "F02.military_resource_visibility"
FORCE_FIELDS = (ARMY_FIELD, NAVY_FIELD)
FIELDS = (ARMY_FIELD, NAVY_FIELD, VISIBILITY_FIELD)
VISIBILITY_BASIS = _manpower_capture.VISIBILITY_BASIS
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
MAX_PROFILE_BYTES = 128 * 1024


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    size = PROFILE_FILE.stat().st_size
    if not 0 < size <= MAX_PROFILE_BYTES:
        raise ValueError("FOREIGN_FORCES_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("FOREIGN_FORCES_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != PROFILE_ID
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != EXE_SHA256):
        raise ValueError("FOREIGN_FORCES_PROFILE_BUILD")
    for item in profile.get("source_evidence", []) + profile.get("layout_dependencies", []):
        # Keep this Python source reference as history, independent of its text.
        # The native, field-layout and evidence contracts remain pinned below.
        if item["path"] == "bridge/information/foreign_technology_capture.py":
            continue
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item["bytes"] or _sha(path) != item["sha256"]:
            raise ValueError("FOREIGN_FORCES_PROFILE_DEPENDENCY")
    if not profile.get("code_guards"):
        raise ValueError("FOREIGN_FORCES_PROFILE_CODE_GUARDS")
    if not isinstance(profile.get("force_predicates"), Mapping):
        raise ValueError("FOREIGN_FORCES_PROFILE_FORCE_PREDICATES")
    return profile


def _field_unknown(reason: str, permission: Any) -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": reason,
        "complete": False,
        "partial": True,
        "raw_inputs": {"permission": deepcopy(permission)},
    }


def _read_backend(reader: Any, module_base: int, country: str,
                  profile: Mapping[str, Any]) -> dict[str, Any]:
    # Retain the exact full scan supplied to this pass. The force leaf receives
    # its observer binding from this scan; no synthetic or second scan is made.
    scan_for_target: dict[str, Mapping[str, Any]] = {}

    def admission_reader(read, base, full_scan, observer, target):
        scan_for_target[target] = full_scan
        gate = _owner._bound_admission(read, base, full_scan, observer, target)
        role = gate.get("observer_nonplayer_role") if isinstance(gate, Mapping) else None
        if not isinstance(role, Mapping) or role.get("verified") is not True:
            rejected = deepcopy(dict(gate)) if isinstance(gate, Mapping) else {}
            rejected.update({
                "status": "unknown",
                "admitted": None,
                "reason": "OBSERVER_NONPLAYER_ROLE_UNVERIFIED",
            })
            return rejected
        return gate

    def read_fields(limiter, base, target_binding, fields):
        full_scan = scan_for_target.get(country)
        requested = full_scan.get("requested") if isinstance(full_scan, Mapping) else None
        observer_binding = requested.get(OBSERVER) if isinstance(requested, Mapping) else None
        if not isinstance(observer_binding, Mapping):
            permission: dict[str, Any] = {
                "schema": _visibility.SCHEMA,
                "status": "unknown",
                "admitted": None,
                "reason": "OBSERVER_BINDING_MISSING",
            }
        else:
            try:
                permission = _visibility.read_permission(
                    limiter, base, observer_binding, target_binding)
            except Exception:
                # Keep permission failure field-local. The trace records the
                # failed read; neither force leaf is allowed to read resources
                # with an unknown permission.
                permission = {
                    "schema": _visibility.SCHEMA,
                    "status": "unknown",
                    "admitted": None,
                    "reason": "MILITARY_STATS_PERMISSION_READ_FAILED",
                }

        output: dict[str, dict[str, Any]] = {}
        requested_force = tuple(field for field in fields if field in FORCE_FIELDS)
        if requested_force:
            try:
                values = _forces.read_fields(
                    limiter, base, target_binding, requested_force,
                    permission=permission,
                    predicate_profile=profile["force_predicates"],
                )
            except Exception:
                values = {
                    field: _field_unknown("FORCE_LEAF_READ_FAILED", permission)
                    for field in requested_force
                }
            if isinstance(values, Mapping):
                for field in requested_force:
                    value = values.get(field)
                    if isinstance(value, Mapping) and value.get("status") in {
                            "known", "unknown", "invisible"}:
                        output[field] = deepcopy(dict(value))
                    else:
                        output[field] = _field_unknown("FORCE_LEAF_FIELD_INVALID", permission)
        if VISIBILITY_FIELD in fields:
            output[VISIBILITY_FIELD] = _manpower_capture._visibility_field(permission)
        return output

    backend = _backend.read_two_pass(
        reader, module_base, OBSERVER, [country], FIELDS,
        read_fields=read_fields,
        admission_reader=admission_reader,
    )
    _restore_stable_force_invisible(backend, country)
    return backend


def _restore_stable_force_invisible(backend: dict[str, Any], country: str) -> None:
    """Restore stable field-level permission denial after generic replay.

    The generic backend intentionally keeps only known and unknown collector
    results. A leaf's stable `invisible` result is retained only if the whole
    backend and shared country/admission evidence remained observed and stable.
    """
    if (backend.get("status") != "observed"
            or backend.get("consistency", {}).get("status") != "stable"):
        return
    evidence = backend.get("pass_evidence")
    if not isinstance(evidence, Mapping):
        return
    first, second = evidence.get("pass1"), evidence.get("pass2")
    if not isinstance(first, Mapping) or not isinstance(second, Mapping):
        return
    raw1 = first.get("fields_raw_by_tag", {}).get(country)
    raw2 = second.get("fields_raw_by_tag", {}).get(country)
    if not isinstance(raw1, Mapping) or not isinstance(raw2, Mapping):
        return
    if not _owner._same(first.get("country_scan"), second.get("country_scan")):
        return
    target = next((item for item in backend.get("targets", [])
                   if isinstance(item, Mapping) and item.get("tag") == country), None)
    if target is None:
        return
    for field in FORCE_FIELDS:
        if not _owner._same(raw1.get(field), raw2.get(field)):
            continue
        denied = raw2.get(field)
        if not isinstance(denied, Mapping) or denied.get("status") != "invisible":
            continue
        target.setdefault("fields", {})[field] = deepcopy(dict(denied))
        target.setdefault("field_consistency", {})[field] = {
            "status": "invisible",
            "reason": denied.get("reason", "stats_permission_denied"),
        }


def _observe(reader: Any, module_base: int, country: str,
             profile: Mapping[str, Any]) -> dict[str, Any]:
    return _owner._observe(
        reader, module_base, country, profile,
        backend_reader=lambda r, base, target: _read_backend(r, base, target, profile),
    )


def capture(installation: Path, country: str, *, observer: str = OBSERVER) -> dict[str, Any]:
    return _owner._capture_common(
        installation,
        country,
        observer=observer,
        schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe,
    )


def validate_capture(report: Any, context: Mapping[str, Any], creation: int,
                     country: str) -> bool:
    return _owner._validate_capture_common(
        report,
        context,
        creation,
        country,
        schema=SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe,
        require_access=True,
    )


__all__ = [
    "capture", "validate_capture", "SCHEMA", "PROFILE_FILE", "PROFILE_SHA256",
    "PROFILE_ID", "FIELDS", "ARMY_FIELD", "NAVY_FIELD", "VISIBILITY_FIELD",
]
