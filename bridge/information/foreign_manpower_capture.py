"""Identity-bound capture for foreign manpower and its stats permission.

The shared parent owns process/session identity, ROM guards, the full country
scan, FRA non-player admission and ordered two-pass replay.  The military
stats predicate is retained inside its two dependent fields; it is not folded
into the shared admission used by unrelated country observations.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import foreign_country_memory as _backend
from . import foreign_manpower_memory as _manpower
from . import foreign_military_visibility_memory as _visibility
from . import foreign_technology_capture as _owner
from . import mission_memory as _mm

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "foreign-manpower-memory-1374-sampling-r1.json"
PROFILE_SHA256 = "a2951ba02805db29f898b334dbe2a65262107ba5135b89cec21cc33fde8e2ff2"
PROFILE_ID = "foreign-manpower-memory-1374"
EXE_SHA256 = _owner.EXE_SHA256
SCHEMA = "information.foreign_manpower_capture.v1"
OBSERVER = "FRA"
FIELDS = (_manpower.FIELD_ID, "F02.military_resource_visibility")
VISIBILITY_FIELD = "F02.military_resource_visibility"
VISIBILITY_BASIS = "native_country_military_stats_visibility_permission"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
MAX_PROFILE_BYTES = 65_536


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    size = PROFILE_FILE.stat().st_size
    if not 0 < size <= MAX_PROFILE_BYTES:
        raise ValueError("FOREIGN_MANPOWER_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("FOREIGN_MANPOWER_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != PROFILE_ID
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != EXE_SHA256):
        raise ValueError("FOREIGN_MANPOWER_PROFILE_BUILD")
    for item in profile.get("source_evidence", []) + profile.get("layout_dependencies", []):
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        if path.stat().st_size != item["bytes"] or _sha(path) != item["sha256"]:
            raise ValueError("FOREIGN_MANPOWER_PROFILE_DEPENDENCY")
    if not profile.get("code_guards"):
        raise ValueError("FOREIGN_MANPOWER_PROFILE_CODE_GUARDS")
    return profile


def _visibility_field(permission: Any) -> dict[str, Any]:
    raw_inputs = {"permission": deepcopy(permission)}
    if (not isinstance(permission, Mapping)
            or permission.get("schema") != _visibility.SCHEMA
            or permission.get("status") != "known"
            or type(permission.get("admitted")) is not bool):
        reason = (permission.get("reason") if isinstance(permission, Mapping)
                  and isinstance(permission.get("reason"), str)
                  else "MILITARY_STATS_PERMISSION_UNKNOWN")
        return {
            "status": "unknown", "reason": reason,
            "complete": False, "partial": True, "basis": VISIBILITY_BASIS,
            "raw_inputs": raw_inputs,
        }
    mode = permission.get("mode")
    if (type(mode) is not str or mode not in {
            "public_options", "active_timed_entry",
            "expired_timed_entry", "no_timed_entry"}):
        return {
            "status": "unknown", "reason": "MILITARY_STATS_PERMISSION_MODE_INVALID",
            "complete": False, "partial": True, "basis": VISIBILITY_BASIS,
            "raw_inputs": raw_inputs,
        }
    return {
        "status": "known",
        "value": {"admitted": permission["admitted"], "mode": mode,
                  "basis": VISIBILITY_BASIS},
        "complete": False, "partial": True, "basis": VISIBILITY_BASIS,
        "raw_inputs": raw_inputs,
    }


def _restore_stable_manpower_invisible(backend: dict[str, Any], country: str) -> None:
    """Keep a stable leaf-level denial distinct from an unknown projection."""
    if (backend.get("status") != "observed"
            or backend.get("consistency", {}).get("status") != "stable"):
        return
    evidence = backend.get("pass_evidence")
    if not isinstance(evidence, Mapping):
        return
    first = evidence.get("pass1")
    second = evidence.get("pass2")
    if not isinstance(first, Mapping) or not isinstance(second, Mapping):
        return
    raw1 = first.get("fields_raw_by_tag", {}).get(country)
    raw2 = second.get("fields_raw_by_tag", {}).get(country)
    if (not isinstance(raw1, Mapping) or not isinstance(raw2, Mapping)
            or not _owner._same(raw1.get(_manpower.FIELD_ID), raw2.get(_manpower.FIELD_ID))):
        return
    denied = raw2.get(_manpower.FIELD_ID)
    if not isinstance(denied, Mapping) or denied.get("status") != "invisible":
        return
    target = next((item for item in backend.get("targets", [])
                   if isinstance(item, Mapping) and item.get("tag") == country), None)
    if target is None:
        return
    target.setdefault("fields", {})[_manpower.FIELD_ID] = deepcopy(dict(denied))
    target.setdefault("field_consistency", {})[_manpower.FIELD_ID] = {
        "status": "invisible", "reason": denied.get("reason", "stats_permission_denied")}


def _read_backend(reader: Any, module_base: int, country: str) -> dict[str, Any]:
    scan_for_target: dict[str, Mapping[str, Any]] = {}

    def admission_reader(read, base, full_scan, observer, target):
        # The generic backend calls admission once for this target in each
        # pass. Retain that exact complete scan for the subsequent leaf call;
        # never synthesize or rescan a country binding here.
        scan_for_target[target] = full_scan
        gate = _owner._bound_admission(read, base, full_scan, observer, target)
        role = gate.get("observer_nonplayer_role") if isinstance(gate, Mapping) else None
        if not isinstance(role, Mapping) or role.get("verified") is not True:
            rejected = deepcopy(dict(gate)) if isinstance(gate, Mapping) else {}
            rejected.update({"status": "unknown", "admitted": None,
                             "reason": "OBSERVER_NONPLAYER_ROLE_UNVERIFIED"})
            return rejected
        return gate

    def read_fields(limiter, base, target_binding, fields):
        full_scan = scan_for_target.get(country)
        requested = full_scan.get("requested") if isinstance(full_scan, Mapping) else None
        observer_binding = requested.get(OBSERVER) if isinstance(requested, Mapping) else None
        if not isinstance(observer_binding, Mapping):
            return {field: {"status": "unknown", "reason": "OBSERVER_BINDING_MISSING"}
                    for field in fields}

        # This field-specific predicate is evidence for the two F02 fields,
        # not part of the shared country-view admission.
        permission = _visibility.read_permission(
            limiter, base, observer_binding, target_binding)
        output: dict[str, dict[str, Any]] = {}
        if _manpower.FIELD_ID in fields:
            output.update(_manpower.read_fields(
                limiter, base, target_binding, (_manpower.FIELD_ID,), permission=permission))
        if VISIBILITY_FIELD in fields:
            output[VISIBILITY_FIELD] = _visibility_field(permission)
        return output

    backend = _backend.read_two_pass(
        reader, module_base, OBSERVER, [country], FIELDS,
        read_fields=read_fields, admission_reader=admission_reader)
    _restore_stable_manpower_invisible(backend, country)
    return backend


def _observe(reader: Any, module_base: int, country: str,
             profile: Mapping[str, Any]) -> dict[str, Any]:
    return _owner._observe(
        reader, module_base, country, profile,
        backend_reader=_read_backend)


def capture(installation: Path, country: str, *, observer: str = OBSERVER) -> dict[str, Any]:
    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe)


def validate_capture(report: Any, context: Mapping[str, Any], creation: int,
                     country: str) -> bool:
    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe, require_access=True)


__all__ = ["capture", "validate_capture", "SCHEMA", "PROFILE_FILE",
           "PROFILE_SHA256", "FIELDS"]
