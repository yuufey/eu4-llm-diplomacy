"""Identity-bound, two-pass foreign quality observations for logical FRA.

The shared owner supplies the read-only handle and process/session guards.
Country-view admission and FRA's non-player role remain independent of the
quality-ledger permission. No physical UI selection is changed or assumed.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from . import foreign_country_memory as _backend
from . import foreign_quality_memory as _quality
from . import foreign_quality_visibility_memory as _visibility
from . import foreign_technology_capture as _owner

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "foreign-quality-memory-1374-v2.json"
PROFILE_SHA256 = "97866049085cd687f5d66c46a8884526ea6efc3897d99be1fe7234610439d7f6"
PROFILE_ID = "foreign-quality-memory-1374"
SCHEMA = "information.foreign_quality_capture.v2"
EXE_SHA256 = _owner.EXE_SHA256
OBSERVER = "FRA"
QUALITY_FIELD = "F02.military_quality"
VISIBILITY_FIELD = "F02.military_quality_visibility"
FIELDS = (QUALITY_FIELD, VISIBILITY_FIELD)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    if not 0 < PROFILE_FILE.stat().st_size <= 256 * 1024:
        raise ValueError("FOREIGN_QUALITY_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("FOREIGN_QUALITY_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != PROFILE_ID
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != EXE_SHA256
            or not isinstance(profile.get("model_profile"), dict)
            or not profile.get("code_guards")):
        raise ValueError("FOREIGN_QUALITY_PROFILE_CONTRACT")
    for item in profile.get("source_evidence", []) + profile.get("layout_dependencies", []):
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item["bytes"] or _sha(path) != item["sha256"]:
            raise ValueError("FOREIGN_QUALITY_PROFILE_DEPENDENCY")
    return profile


def _unknown(reason: str, permission: Any = None) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason, "partial": True,
            "complete": False, "raw_inputs": {"permission": deepcopy(permission)}}


def _permission_field(permission: Any) -> dict[str, Any]:
    if not _visibility.validate_permission(permission):
        return _unknown("QUALITY_PERMISSION_INVALID", permission)
    if permission["status"] != "known":
        return _unknown(permission.get("reason") or "QUALITY_PERMISSION_UNKNOWN", permission)
    return {"status": "known", "complete": False, "partial": True,
            "basis": _visibility.BASIS,
            "value": {"admitted": permission["admitted"], "mode": permission["mode"]},
            "raw_inputs": {"permission": deepcopy(permission)}}


def _read_backend(reader: Any, base: int, country: str,
                  profile: Mapping[str, Any]) -> dict[str, Any]:
    scans: dict[str, Mapping[str, Any]] = {}

    def admission(read, module_base, scan, observer, target):
        scans[target] = scan
        gate = _owner._bound_admission(read, module_base, scan, observer, target)
        role = gate.get("observer_nonplayer_role") if isinstance(gate, Mapping) else None
        if not isinstance(role, Mapping) or role.get("verified") is not True:
            gate = deepcopy(dict(gate)) if isinstance(gate, Mapping) else {}
            gate.update(status="unknown", admitted=None,
                        reason="OBSERVER_NONPLAYER_ROLE_UNVERIFIED")
        return gate

    def fields(read, module_base, target_binding, requested):
        scan = scans.get(country)
        observer = scan.get("requested", {}).get(OBSERVER) if isinstance(scan, Mapping) else None
        permission = None
        if isinstance(observer, Mapping):
            permission = _visibility.read_permission(read, module_base, observer, target_binding)
        output: dict[str, Any] = {}
        if QUALITY_FIELD in requested:
            try:
                values = _quality.read_fields(read, module_base, target_binding, (QUALITY_FIELD,),
                                              permission=permission,
                                              model_profile=profile["model_profile"])
                item = values.get(QUALITY_FIELD) if isinstance(values, Mapping) else None
                if not isinstance(item, Mapping) or item.get("status") not in {"known", "unknown", "invisible"}:
                    item = _unknown("QUALITY_LEAF_FIELD_INVALID", permission)
                output[QUALITY_FIELD] = deepcopy(dict(item))
            except Exception:
                output[QUALITY_FIELD] = _unknown("QUALITY_LEAF_READ_FAILED", permission)
        if VISIBILITY_FIELD in requested:
            output[VISIBILITY_FIELD] = _permission_field(permission)
        return output

    return _backend.read_two_pass(reader, base, OBSERVER, [country], FIELDS,
                                  read_fields=fields, admission_reader=admission)


def _observe(reader, base, country, profile):
    return _owner._observe(reader, base, country, profile,
        backend_reader=lambda read, module_base, target: _read_backend(read, module_base, target, profile))


def capture(installation: Path, country: str, *, observer: str = OBSERVER) -> dict[str, Any]:
    return _owner._capture_common(installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe)


def validate_capture(report: Any, context: Mapping[str, Any], creation: int,
                     country: str) -> bool:
    return _owner._validate_capture_common(report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile, observe=_observe, require_access=True)


__all__ = ["capture", "validate_capture", "SCHEMA", "PROFILE_FILE", "PROFILE_SHA256",
           "PROFILE_ID", "QUALITY_FIELD", "VISIBILITY_FIELD", "FIELDS"]
