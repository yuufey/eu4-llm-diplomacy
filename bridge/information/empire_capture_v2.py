"""Two-pass HRE capture with an independently failable reforms field."""
from __future__ import annotations

from collections.abc import Mapping
from functools import partial
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from . import empire_capture as _v1_capture
from . import empire_memory as _base_memory
from . import empire_reforms_memory as _memory
from . import foreign_technology_capture as _owner


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "empire-memory-1374-v2-sampling-r1.json"
# The v2 profile pin is filled only after the ordinary serializer and UI guard
# evidence is reviewed. Until then _load_profile fails closed.
PROFILE_SHA256 = "8b18d918622f9583b5ab0e75ec2d775eabf2996f99229cdcc6b3cd43ab5a5018"
EXE_SHA256 = _v1_capture.EXE_SHA256
SCHEMA = "information.empire_capture.v2"
INNER_SCHEMA = "information.empire_observer_snapshot.v2"
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
    "hre_passed_reforms_table_consumer",
    "hre_passed_reform_string_nul_serializer",
}


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    _owner._load_profile()
    if not re.fullmatch(r"[0-9a-f]{64}", PROFILE_SHA256):
        raise ValueError("EMPIRE_V2_PROFILE_NOT_FINALIZED")
    if not 0 < PROFILE_FILE.stat().st_size <= 64 * 1024:
        raise ValueError("EMPIRE_V2_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("EMPIRE_V2_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != "empire-memory-1374-v2"
            or profile.get("profile_version") != 2
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != EXE_SHA256
            or profile.get("object_scope") != "single_global_hre_record"
            or profile.get("profile_scope") != "private_capture_only"
            or profile.get("publication_admitted") is not False
            or profile.get("reforms_publication_admitted") is not False
            or profile.get("framework_profile_sha256") != _owner.PROFILE_SHA256
            or profile.get("visibility", {}).get("actual_ui_observed") is not False
            or profile.get("visibility", {}).get("reforms_publication_admitted") is not False
            or profile.get("ui_binding", {}).get("status") != "unresolved"):
        raise ValueError("EMPIRE_V2_PROFILE_BUILD")
    source_evidence = profile.get("source_evidence")
    layout_dependencies = profile.get("layout_dependencies")
    if not isinstance(source_evidence, list) or not isinstance(layout_dependencies, list):
        raise ValueError("EMPIRE_V2_PROFILE_DEPENDENCIES_SHAPE")
    source_paths = {item["path"] for item in source_evidence
                    if isinstance(item, dict) and isinstance(item.get("path"), str)}
    dependency_paths = {item["path"] for item in layout_dependencies
                        if isinstance(item, dict) and isinstance(item.get("path"), str)}
    required_source_paths = {
        "work/runtime/information-live-empire-reforms-20261102-115-001/static-evidence-001/report.json",
        "work/runtime/information-live-empire-reforms-20261102-115-001/static-evidence-001/serializer-byte-report.json",
        "work/runtime/information-live-empire-reforms-20261102-115-001/static-evidence-001/serializer-1707cc0.bin",
        "work/runtime/information-live-empire-reforms-20261102-115-001/static-evidence-001/ui-reform-binding-001/report.json",
        "work/runtime/information-live-empire-20261102-114-reform-seeds-001/report-003.json",
        "work/runtime/information-live-empire-20261102-114-reform-seeds-001/function.bin",
    }
    required_dependency_paths = {
        "bridge/information/foreign_technology_capture.py",
        "bridge/information/country_reference_memory.py",
        "bridge/information/empire_memory.py",
        "bridge/information/empire_capture.py",
        "bridge/information/empire_reforms_memory.py",
    }
    expected_layout = {
        "table_pointer_offset": "0x28",
        "signed_count_offset": "0x34",
        "slot_stride_bytes": 8,
        "slot_value": "pointer_to_string32_object",
        "string_storage_offset": "0x10",
        "string_capacity_offset": "0x28",
        "inline_capacity_threshold": 16,
        "serializer_rva": "0x1707cc0",
        "nul_terminated": True,
        "unverified_length_offset": "0x20",
        "unverified_length_read": False,
        "negative_or_large_native_count_guard": "not_observed; reader applies bounded signed-count validation",
    }
    expected_limits = {
        "maximum_signed_reform_count": _memory.MAX_REFORMS,
        "maximum_id_bytes": _memory.MAX_REFORM_ID_BYTES,
        "per_pass_reform_bytes": _memory.MAX_REFORM_READ_BYTES_PER_PASS,
        "per_pass_reform_calls": _memory.MAX_REFORM_READ_CALLS_PER_PASS,
        "maximum_single_read": _base_memory.MAX_SINGLE_READ,
        "maximum_capture_bytes": _owner.MAX_READ_BYTES,
    }
    if (not required_source_paths <= source_paths
            or not required_dependency_paths <= dependency_paths
            or profile.get("reform_layout") != expected_layout
            or profile.get("read_limits") != expected_limits):
        raise ValueError("EMPIRE_V2_PROFILE_LAYOUT_OR_SCOPE")
    for item in source_evidence + layout_dependencies:
        if not isinstance(item, dict) or not {"path", "bytes", "sha256"} <= set(item):
            raise ValueError("EMPIRE_V2_PROFILE_DEPENDENCY_SHAPE")
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        if (type(item["bytes"]) is not int or item["bytes"] < 0
                or not isinstance(item["sha256"], str)
                or not _v1_capture._matches_reviewed_layout(item)):
            raise ValueError("EMPIRE_V2_PROFILE_DEPENDENCY")
    guards = profile.get("code_guards")
    if not isinstance(guards, list) or len(guards) < len(_REQUIRED_GUARDS):
        raise ValueError("EMPIRE_V2_PROFILE_GUARDS_MISSING")
    names = set()
    for guard in guards:
        try:
            body = bytes.fromhex(guard["bytes"])
            start = int(guard["rva"], 0)
            end = int(guard["end_rva_exclusive"], 0)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("EMPIRE_V2_PROFILE_GUARD_SHAPE") from exc
        if (not isinstance(guard.get("name"), str) or guard["name"] in names
                or not body or end != start + len(body)
                or guard.get("length") != len(body)
                or hashlib.sha256(body).hexdigest() != guard.get("sha256")
                or guard.get("relocation_sites") != []):
            raise ValueError("EMPIRE_V2_PROFILE_GUARD_INVALID")
        names.add(guard["name"])
    if not _REQUIRED_GUARDS <= names:
        raise ValueError("EMPIRE_V2_PROFILE_GUARD_SET")
    return profile


def _base_state(state: dict[str, Any]) -> dict[str, Any]:
    result = dict(state)
    result.pop("reforms", None)
    return result


def _field_reason(first: dict[str, Any], second: dict[str, Any]) -> str:
    if first.get("status") != "known" or second.get("status") != "known":
        reasons = [row.get("reason") for row in (first, second)
                   if isinstance(row.get("reason"), str)]
        return reasons[0] if reasons else "EMPIRE_REFORMS_FIELD_UNKNOWN"
    return "EMPIRE_REFORMS_CHANGED_BETWEEN_PASSES"


def _observe(reader, module_base: int, country: str, profile: dict[str, Any],
             *, observer: str = _OBSERVER) -> dict[str, Any]:
    if country != "HRE":
        raise ValueError("EMPIRE_V2_CAPTURE_OBJECT_SCOPE")
    bounded = _base_memory._BudgetReader(reader)
    guards_before = _owner._guards(bounded, module_base, profile)
    context_before = _owner._context(bounded, module_base)
    first = _memory._read_pass(bounded, module_base, observer, "pass1")
    second = _memory._read_pass(bounded, module_base, observer, "pass2")
    context_after = _owner._context(bounded, module_base)
    guards_after = _owner._guards(bounded, module_base, profile)

    base_stable = (
        _owner._same(context_before, context_after)
        and _owner._same(_base_state(first), _base_state(second))
        and _owner._same(guards_before, guards_after)
        and all(item.get("observer_nonplayer", {}).get("verified") is True
                for item in (first, second))
    )
    first_reforms = first.get("reforms", {})
    second_reforms = second.get("reforms", {})
    reforms_stable = (
        isinstance(first_reforms, dict) and isinstance(second_reforms, dict)
        and first_reforms.get("status") == second_reforms.get("status") == "known"
        and _owner._same(first_reforms, second_reforms)
    )
    if reforms_stable:
        reforms_field = {
            "status": "known",
            "value": list(first_reforms["value"]),
            "count": first_reforms["count"],
            "basis": first_reforms["basis"],
            "complete": False,
        }
    else:
        reforms_field = {
            "status": "unknown",
            "reason": _field_reason(first_reforms, second_reforms),
            "basis": "bounded_nul_terminated_hre_passed_reform_string_table",
            "complete": False,
        }

    result = {
        "status": "observed" if base_stable else "unknown",
        "stable": base_stable,
        "field_stability": {
            "emperor": base_stable,
            "electors": base_stable,
            "reforms": reforms_stable,
        },
        "basis": "native_global_hre_country_references_and_passed_reform_table",
        "visibility_evaluated": False,
        "actual_ui_observed": False,
        "context_before": context_before,
        "passes": [first, second],
        "reforms": reforms_field,
        "context_after": context_after,
        "runtime_code_before": guards_before,
        "runtime_code_after": guards_after,
        "read_budget": {
            "calls": bounded.calls,
            "bytes_requested": bounded.bytes,
            "max_single_read": bounded.max_single,
            "limits": {
                "max_calls": _base_memory.MAX_READ_CALLS,
                "max_bytes": _base_memory.MAX_READ_BYTES,
                "max_single_read": _base_memory.MAX_SINGLE_READ,
                "reform_count": _memory.MAX_REFORMS,
                "reform_bytes_per_pass": _memory.MAX_REFORM_READ_BYTES_PER_PASS,
                "reform_calls_per_pass": _memory.MAX_REFORM_READ_CALLS_PER_PASS,
                "reform_id_bytes": _memory.MAX_REFORM_ID_BYTES,
            },
        },
        "atomic_snapshot": False,
        "native_function_invoked": False,
        "game_memory_written": False,
    }
    failures = getattr(reader, "read_failures", None)
    if failures:
        result["read_failures"] = deepcopy(failures)
    return result


def capture(installation: Path, *, observer: str = _OBSERVER) -> dict[str, Any]:
    if not _v1_capture._valid_observer(observer):
        raise ValueError("EMPIRE_V2_OBSERVER_SCOPE")
    inner = _owner._capture_common(
        installation, "HRE", observer=observer, schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True,
        allow_observer_target=True,
    )
    return {"schema": SCHEMA, "observer": observer, "object": dict(_OBJECT), "capture": inner}


def validate_capture(report: Any, context: Mapping[str, Any], creation: int) -> bool:
    observer = context.get("observer") if isinstance(context, Mapping) else None
    if (not _v1_capture._valid_observer(observer) or not isinstance(report, dict)
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
    for row in (identity, identity_after):
        for key in ("installation_creation_filetime", "process_creation_filetime"):
            if type(row.get(key)) is not int or row[key] <= 0:
                return False
    return _owner._validate_capture_common(
        inner, context, creation, "HRE", schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=partial(_observe, observer=observer), observer_scoped=True,
        allow_observer_target=True, require_access=True,
    )


def _v1_projection_report(report: dict[str, Any]) -> dict[str, Any]:
    """Reuse the frozen v1 tag projection checks for its unchanged fields."""
    inner = deepcopy(report["capture"])
    observation = inner.get("observation")
    if not isinstance(observation, dict) or not isinstance(observation.get("passes"), list):
        raise ValueError("EMPIRE_V2_CAPTURE_SHAPE")
    for state in observation["passes"]:
        if not isinstance(state, dict):
            raise ValueError("EMPIRE_V2_CAPTURE_SHAPE")
        state.pop("reforms", None)
        state["schema"] = _base_memory.SCHEMA
    # The v1 checker only consumes this synthetic envelope locally. The real
    # v2 profile hash is checked before construction and is never projected.
    inner["schema"] = _v1_capture.INNER_SCHEMA
    inner["profile_sha256"] = _v1_capture.PROFILE_SHA256
    return {"schema": _v1_capture.SCHEMA, "observer": report["observer"],
            "object": dict(_OBJECT), "capture": inner}


def project_fields(report: Any) -> dict[str, Any]:
    """Project the two unchanged tags and reforms as a separate partial field."""
    if (not isinstance(report, dict) or set(report) != {"schema", "observer", "object", "capture"}
            or report.get("schema") != SCHEMA
            or not _v1_capture._valid_observer(report.get("observer"))
            or not _owner._same(report.get("object"), _OBJECT)):
        raise ValueError("EMPIRE_V2_PROJECTION_SCOPE")
    inner = report.get("capture")
    if not isinstance(inner, dict):
        raise ValueError("EMPIRE_V2_CAPTURE_SHAPE")
    if inner.get("profile_sha256") != PROFILE_SHA256:
        raise ValueError("EMPIRE_V2_PROFILE_MISMATCH")
    observation = inner.get("observation")
    cleanup = inner.get("cleanup")
    if (inner.get("status") != "observed" or inner.get("completed") is not True
            or not isinstance(cleanup, dict) or cleanup.get("status") != "closed"
            or cleanup.get("closed") is not True or cleanup.get("success") is not True
            or not isinstance(observation, dict) or observation.get("status") != "observed"
            or observation.get("stable") is not True
            or observation.get("visibility_evaluated") is not False
            or observation.get("actual_ui_observed") is not False
            or not isinstance(observation.get("context_before"), dict)
            or not _owner._same(observation.get("context_before"), observation.get("context_after"))
            or not isinstance(observation.get("passes"), list) or len(observation["passes"]) != 2):
        raise ValueError("EMPIRE_V2_CAPTURE_NOT_STABLE")
    legacy = _v1_capture.project_fields(_v1_projection_report(report))
    reforms = observation.get("reforms")
    if not isinstance(reforms, dict) or reforms.get("status") != "known":
        reason = reforms.get("reason") if isinstance(reforms, dict) else None
        return {
            **legacy,
            "reforms": {
                "status": "unknown",
                "reason": reason if isinstance(reason, str) else "EMPIRE_REFORMS_FIELD_UNKNOWN",
                "unit": "reform_id",
                "scale": 1,
                "period": "current",
                "complete": False,
                "basis": "bounded_nul_terminated_hre_passed_reform_string_table",
            },
        }
    values = reforms.get("value")
    if (not isinstance(values, list) or type(reforms.get("count")) is not int
            or reforms["count"] != len(values) or len(values) > _memory.MAX_REFORMS
            or any(not isinstance(value, str) or _memory._IDENTIFIER.fullmatch(value) is None
                   for value in values)
            or len(values) != len(set(values))):
        raise ValueError("EMPIRE_V2_REFORMS_FIELD_INVALID")
    return {
        **legacy,
        "reforms": {
            "status": "known",
            "value": list(values),
            "unit": "reform_id",
            "scale": 1,
            "period": "current",
            "complete": False,
            "basis": "bounded_nul_terminated_hre_passed_reform_string_table",
        },
    }


__all__ = ["capture", "validate_capture", "project_fields", "PROFILE_SHA256"]
