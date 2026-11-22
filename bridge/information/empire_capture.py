"""Capture and replay the current global HRE emperor/elector references."""
from __future__ import annotations

from collections.abc import Mapping
from functools import partial
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from . import empire_memory as _memory
from . import foreign_technology_capture as _owner
from .province_state_capture import _matches_reviewed_layout


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "empire-memory-1374-v1-sampling-r1.json"
PROFILE_SHA256 = "376f208317bf2c635f262f3296f35576578ed2598070d32045e5ca61068e0e60"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
SCHEMA = "information.empire_capture.v1"
INNER_SCHEMA = "information.empire_observer_snapshot.v1"
_OBSERVER = "FRA"
_OBJECT = {"type": "country", "country": "HRE"}
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_REQUIRED_GUARDS = {
    "hre_world_ctor_to_vtable",
    "hre_world_global_store",
    "hre_embedded_world_plus_15d0_init",
    "hre_vtable_init",
    "hre_ui_global_embedded_identity",
    "hre_ui_global_plus_15d0_provenance",
    "hre_ui_emperor_reference_consumer",
    "hre_ui_elector_container_lookup",
    "hre_ui_elector_population",
    "hre_ui_elector_membership_consumer",
}


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    # Reuse the established process/PE/session dependency chain before loading
    # the narrower global-HRE profile.
    _owner._load_profile()
    if not 0 < PROFILE_FILE.stat().st_size <= 64 * 1024:
        raise ValueError("EMPIRE_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("EMPIRE_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != "empire-memory-1374-v1"
            or profile.get("profile_version") != 1
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != EXE_SHA256
            or profile.get("object_scope") != "single_global_hre_record"
            or profile.get("framework_profile_sha256") != _owner.PROFILE_SHA256
            or profile.get("visibility", {}).get("actual_ui_observed") is not False):
        raise ValueError("EMPIRE_PROFILE_BUILD")
    source_evidence = profile.get("source_evidence")
    layout_dependencies = profile.get("layout_dependencies")
    if not isinstance(source_evidence, list) or not isinstance(layout_dependencies, list):
        raise ValueError("EMPIRE_PROFILE_DEPENDENCIES_SHAPE")
    for item in source_evidence + layout_dependencies:
        if (not isinstance(item, dict)
                or not {"path", "bytes", "sha256"} <= set(item)):
            raise ValueError("EMPIRE_PROFILE_DEPENDENCY_SHAPE")
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        if (type(item["bytes"]) is not int or item["bytes"] < 0
                or not isinstance(item["sha256"], str)
                or not _matches_reviewed_layout(item)):
            raise ValueError("EMPIRE_PROFILE_DEPENDENCY")
    guards = profile.get("code_guards")
    if not isinstance(guards, list) or len(guards) < len(_REQUIRED_GUARDS):
        raise ValueError("EMPIRE_PROFILE_GUARDS_MISSING")
    names = set()
    for guard in guards:
        try:
            body = bytes.fromhex(guard["bytes"])
            start = int(guard["rva"], 0)
            end = int(guard["end_rva_exclusive"], 0)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("EMPIRE_PROFILE_GUARD_SHAPE") from exc
        if (not isinstance(guard.get("name"), str) or guard["name"] in names
                or not body or end != start + len(body)
                or guard.get("length") != len(body)
                or hashlib.sha256(body).hexdigest() != guard.get("sha256")
                or guard.get("relocation_sites") != []):
            raise ValueError("EMPIRE_PROFILE_GUARD_INVALID")
        names.add(guard["name"])
    if not _REQUIRED_GUARDS <= names:
        raise ValueError("EMPIRE_PROFILE_GUARD_SET")
    return profile


def _valid_observer(observer: Any) -> bool:
    return isinstance(observer, str) and _TAG.fullmatch(observer) is not None


def _observe(reader, module_base: int, country: str, profile: dict[str, Any],
             *, observer: str = _OBSERVER) -> dict[str, Any]:
    if country != "HRE":
        raise ValueError("EMPIRE_CAPTURE_OBJECT_SCOPE")
    bounded = _memory._BudgetReader(reader)
    guards_before = _owner._guards(bounded, module_base, profile)
    context_before = _owner._context(bounded, module_base)
    first = _memory._read_state(bounded, module_base, observer, "pass1")
    second = _memory._read_state(bounded, module_base, observer, "pass2")
    context_after = _owner._context(bounded, module_base)
    guards_after = _owner._guards(bounded, module_base, profile)
    role_ok = all(
        item.get("observer_nonplayer", {}).get("verified") is True
        for item in (first, second)
    )
    stable = (
        _owner._same(context_before, context_after)
        and _owner._same(first, second)
        and _owner._same(guards_before, guards_after)
        and role_ok
    )
    result = {
        "status": "observed" if stable else "unknown",
        "stable": stable,
        "basis": "native_global_hre_country_references_with_static_ui_binding",
        "visibility_evaluated": False,
        "actual_ui_observed": False,
        "publication_admitted": False,
        "context_before": context_before,
        "passes": [first, second],
        "context_after": context_after,
        "runtime_code_before": guards_before,
        "runtime_code_after": guards_after,
        "read_budget": {
            "calls": bounded.calls,
            "bytes_requested": bounded.bytes,
            "max_single_read": bounded.max_single,
            "limits": {
                "max_calls": _memory.MAX_READ_CALLS,
                "max_bytes": _memory.MAX_READ_BYTES,
                "max_single_read": _memory.MAX_SINGLE_READ,
            },
        },
        "atomic_snapshot": False,
        "native_function_invoked": False,
        "game_memory_written": False,
    }
    failures = getattr(reader, "read_failures", None)
    if failures:
        from copy import deepcopy
        result["read_failures"] = deepcopy(failures)
    return result


def capture(installation: Path, *, observer: str = _OBSERVER) -> dict[str, Any]:
    if not _valid_observer(observer):
        raise ValueError("EMPIRE_OBSERVER_SCOPE")
    inner = _owner._capture_common(
        installation, "HRE", observer=observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True,
        allow_observer_target=True,
    )
    return {
        "schema": SCHEMA,
        "observer": observer,
        "object": dict(_OBJECT),
        "capture": inner,
    }


def validate_capture(report: Any, context: Mapping[str, Any], creation: int) -> bool:
    observer = context.get("observer") if isinstance(context, Mapping) else None
    if (not _valid_observer(observer) or not isinstance(report, dict)
            or set(report) != {"schema", "observer", "object", "capture"}
            or report.get("schema") != SCHEMA or report.get("observer") != observer
            or not _owner._same(report.get("object"), _OBJECT)
            or type(creation) is not int or creation <= 0):
        return False
    inner = report.get("capture")
    if not isinstance(inner, dict):
        return False
    request = inner.get("request")
    identity = inner.get("identity")
    identity_after = inner.get("identity_after")
    if not isinstance(request, dict) or not isinstance(identity, dict) or not isinstance(identity_after, dict):
        return False
    if type(request.get("creation_filetime")) is not int or request["creation_filetime"] <= 0:
        return False
    for record in (identity, identity_after):
        if (type(record.get("installation_creation_filetime")) is not int
                or record["installation_creation_filetime"] <= 0
                or type(record.get("process_creation_filetime")) is not int
                or record["process_creation_filetime"] <= 0):
            return False
    return _owner._validate_capture_common(
        inner, context, creation, "HRE", schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True,
        allow_observer_target=True, require_access=True,
    )


def project_fields(report: Any) -> dict[str, Any]:
    """Whitelist the stable HRE tags; the caller owns visibility/publication policy."""
    observer = report.get("observer") if isinstance(report, dict) else None
    if (not _valid_observer(observer) or report.get("schema") != SCHEMA
            or not _owner._same(report.get("object"), _OBJECT)):
        raise ValueError("EMPIRE_PROJECTION_SCOPE")
    inner = report.get("capture")
    observation = inner.get("observation") if isinstance(inner, dict) else None
    passes = observation.get("passes") if isinstance(observation, dict) else None
    cleanup = inner.get("cleanup") if isinstance(inner, dict) else None
    if (not isinstance(inner, dict)
            or not isinstance(inner.get("request"), dict)
            or inner["request"].get("observer") != observer
            or inner.get("status") != "observed" or inner.get("completed") is not True
            or inner.get("profile_sha256") != PROFILE_SHA256
            or not isinstance(cleanup, dict) or cleanup.get("status") != "closed"
            or cleanup.get("closed") is not True or cleanup.get("success") is not True
            or not isinstance(observation, dict) or observation.get("status") != "observed"
            or observation.get("stable") is not True
            or observation.get("visibility_evaluated") is not False
            or observation.get("actual_ui_observed") is not False
            or not isinstance(observation.get("context_before"), dict)
            or not _owner._same(observation.get("context_before"), observation.get("context_after"))
            or not isinstance(passes, list) or len(passes) != 2
            or any(not isinstance(state, dict) for state in passes)
            or not _owner._same(passes[0], passes[1])):
        raise ValueError("EMPIRE_CAPTURE_NOT_STABLE")
    for state in passes:
        role = state.get("observer_nonplayer") if isinstance(state, dict) else None
        if (not isinstance(state, dict) or state.get("status") != "known" or state.get("observer") != observer
                or not isinstance(role, dict) or role.get("tag") != observer
                or role.get("verified") is not True):
            raise ValueError("EMPIRE_ROLE_NOT_VERIFIED")
        physical = state.get("physical_client")
        if (not isinstance(physical, dict) or physical.get("tag") == observer
                or not isinstance(physical.get("tag"), str)
                or _TAG.fullmatch(physical["tag"]) is None
                or not isinstance(physical.get("fullref_raw_hex"), str)
                or len(physical["fullref_raw_hex"]) != 16):
            raise ValueError("EMPIRE_PHYSICAL_CLIENT_BINDING_INVALID")
        try:
            _physical_ref, physical_tag = _memory._fullref(
                bytes.fromhex(physical["fullref_raw_hex"]), "project_physical")
        except (ValueError, TypeError) as exc:
            raise ValueError("EMPIRE_PHYSICAL_CLIENT_BINDING_INVALID") from exc
        if physical_tag != physical["tag"]:
            raise ValueError("EMPIRE_PHYSICAL_CLIENT_BINDING_INVALID")
    emperor_row = passes[0].get("emperor")
    elector_rows = passes[0].get("electors")
    container = passes[0].get("elector_container")
    if (not isinstance(emperor_row, dict) or not isinstance(elector_rows, list)
            or not isinstance(container, dict) or container.get("node_plus_8_read") is not False
            or type(container.get("count")) is not int
            or container["count"] != len(elector_rows)
            or not isinstance(container.get("entries"), list)
            or len(container["entries"]) != len(elector_rows)):
        raise ValueError("EMPIRE_CAPTURE_MEMBER_SHAPE")
    emperor = emperor_row.get("tag")
    if any(not isinstance(row, dict) for row in elector_rows):
        raise ValueError("EMPIRE_ELECTOR_ROW_SHAPE")
    electors = [row.get("tag") for row in elector_rows]
    if not isinstance(emperor, str) or _TAG.fullmatch(emperor) is None:
        raise ValueError("EMPIRE_EMPEROR_TAG_INVALID")
    if (len(electors) > _memory.MAX_ELECTOR_NODES
            or any(not isinstance(tag, str) or _TAG.fullmatch(tag) is None for tag in electors)
            or len(electors) != len(set(electors))):
        raise ValueError("EMPIRE_ELECTOR_TAGS_INVALID")
    try:
        _emperor_ref, emperor_ref_tag = _memory._fullref(
            bytes.fromhex(emperor_row.get("fullref_raw_hex", "")), "project_emperor")
    except (ValueError, TypeError) as exc:
        raise ValueError("EMPIRE_EMPEROR_TAG_INVALID") from exc
    if emperor_ref_tag != emperor:
        raise ValueError("EMPIRE_EMPEROR_TAG_INVALID")
    for row in elector_rows:
        try:
            _elector_ref, ref_tag = _memory._fullref(
                bytes.fromhex(row.get("fullref_raw_hex", "")), "project_elector")
        except (ValueError, TypeError) as exc:
            raise ValueError("EMPIRE_ELECTOR_TAGS_INVALID") from exc
        if ref_tag != row.get("tag"):
            raise ValueError("EMPIRE_ELECTOR_TAGS_INVALID")
    common = {
        "status": "known",
        "unit": "country_tag",
        "scale": 1,
        "period": "current",
        "complete": False,
        "basis": "native_global_hre_country_references_with_static_ui_binding",
        "value_origin": "copied_native_canonical_country_references",
    }
    return {
        "emperor": {**common, "value": emperor},
        "electors": {**common, "value": sorted(electors)},
    }


__all__ = ["capture", "validate_capture", "project_fields", "PROFILE_SHA256"]
