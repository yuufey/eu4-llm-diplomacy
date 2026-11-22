"""Own the strict, read-only capture for province modifier predicates.

The foreign-technology owner supplies process identity, RPM, pinned code
guards, strict replay, and handle cleanup.  The existing province-state owner
supplies the observer role, canonical province binding, discovery admission, and two
passes.  This wrapper binds an ordered key request and projects the internal
modifier leaf without turning any per-key unknown into false.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
import re
from typing import Any

from . import foreign_technology_capture as _owner
from . import province_state_capture as _base
from . import province_modifiers_memory as _leaf
from . import province_state_memory as _province


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "province-modifiers-memory-1374-v2-sampling-r1.json"
PROFILE_SHA256 = "de3212324498cd7b3422a389ea4a6023175a806164314b754c376426792f9ed9"
SCHEMA = "information.province_modifiers_capture.v1"
INNER_SCHEMA = "information.province_modifiers_observer_snapshot.v1"
FIELD = "G02.province_modifier_predicates"
BASIS = "native_has_province_modifier_predicates"
_PROFILE_ID = "province-modifiers-memory-1374"
_PROFILE_VERSION = 2
_MAX_PROFILE_BYTES = 256 * 1024
_MAX_KEYS = 64
_MAX_PROVINCE_ID = 0xFFFF
_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,255}\Z", re.ASCII)
_GAPS = [
    "ONLY_LITERAL_KEYS_AND_TWO_SUPPORTED_KIND_METHODS",
    "EFFECTIVE_SCRIPTED_ESTUARY_OR_VOCABULARY_NOT_BOUND",
    "PARENT_OBSERVER_ADMISSION_DISCOVERY_AND_NONATOMIC_TWO_PASS",
    "NO_FULL_MODIFIER_EFFECT_EXPIRATION_OR_RENDERING",
]

_PROFILE_LAYOUT_EXPECTED = {
    "primary_definition_global_rva": _leaf.PRIMARY_MANAGER_GLOBAL_RVA,
    "secondary_definition_global_rva": _leaf.SECONDARY_MANAGER_GLOBAL_RVA,
    "primary_unmatched_sentinel_global_rva": _leaf.PRIMARY_UNMATCHED_SENTINEL_GLOBAL_RVA,
    "manager_bucket_count_offset": _leaf.MANAGER_BUCKET_COUNT_OFFSET,
    "manager_buckets_pointer_offset": _leaf.MANAGER_BUCKETS_POINTER_OFFSET,
    "hash_node_definition_offset": _leaf.HASH_NODE_DEFINITION_OFFSET,
    "hash_node_next_offset": _leaf.HASH_NODE_NEXT_OFFSET,
    "definition_key_string32_offset": _leaf.DEFINITION_KEY_OFFSET,
    "key_length_offset": _leaf.DEFINITION_KEY_LENGTH_OFFSET,
    "key_capacity_offset": _leaf.DEFINITION_KEY_CAPACITY_OFFSET,
    "definition_kind_slot": _leaf.DEFINITION_KIND_SLOT_OFFSET,
    "supported_true_method_rva": _leaf.SUPPORTED_TRUE_METHOD_RVA,
    "supported_false_method_rva": _leaf.SUPPORTED_FALSE_METHOD_RVA,
    "province_primary_instances_begin_offset": _leaf.PROVINCE_PRIMARY_BEGIN_OFFSET,
    "province_primary_instances_end_offset": _leaf.PROVINCE_PRIMARY_END_OFFSET,
    "instance_definition_offset": _leaf.INSTANCE_DEFINITION_OFFSET,
    "province_secondary_array_pointer_offset": _leaf.PROVINCE_SECONDARY_ARRAY_OFFSET,
    "province_secondary_count_offset": _leaf.PROVINCE_SECONDARY_COUNT_OFFSET,
    "pointer_stride": _leaf.POINTER_SIZE,
}


def _valid_id(value: Any) -> bool:
    return type(value) is int and 1 <= value <= _MAX_PROVINCE_ID


def _keys(value: Any) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or not 1 <= len(value) <= _MAX_KEYS:
        raise ValueError("PROVINCE_MODIFIERS_KEYS_SHAPE")
    if any(type(key) is not str or not _KEY_RE.fullmatch(key) for key in value):
        raise ValueError("PROVINCE_MODIFIERS_KEY_INVALID")
    if len(set(value)) != len(value):
        raise ValueError("PROVINCE_MODIFIERS_KEYS_DUPLICATE")
    return tuple(value)


def _load_profile() -> dict[str, Any]:
    try:
        size = PROFILE_FILE.stat().st_size
    except OSError as exc:
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_UNAVAILABLE") from exc
    if not 0 < size <= _MAX_PROFILE_BYTES:
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_PIN")
    try:
        profile = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_JSON") from exc
    executable = profile.get("executable") if isinstance(profile, dict) else None
    if (not isinstance(profile, dict)
            or profile.get("profile_id") != _PROFILE_ID
            or profile.get("profile_version") != _PROFILE_VERSION
            or profile.get("game_version") != "1.37.4"
            or not isinstance(executable, dict)
            or executable.get("sha256") != _owner.EXE_SHA256):
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_BUILD")
    semantics = profile.get("semantics")
    if (not isinstance(semantics, dict)
            or semantics.get("supported_fields") != [FIELD]
            or semantics.get("observer_role") != "Human count1 and FRA controller0, separately from physical UI ref"):
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_SEMANTICS")
    layout = profile.get("layout")
    predicate_layout = layout.get("province_modifier_predicates") if isinstance(layout, dict) else None
    if not isinstance(predicate_layout, dict):
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_LAYOUT")
    for name, expected in _PROFILE_LAYOUT_EXPECTED.items():
        value = predicate_layout.get(name)
        try:
            actual = int(value, 0) if isinstance(value, str) else value
        except ValueError as exc:
            raise ValueError("PROVINCE_MODIFIERS_PROFILE_LAYOUT") from exc
        if type(actual) is not int or actual != expected:
            raise ValueError("PROVINCE_MODIFIERS_PROFILE_LAYOUT")

    evidence = profile.get("source_evidence")
    dependencies = profile.get("layout_dependencies")
    if (not isinstance(evidence, list) or not evidence
            or not isinstance(dependencies, list) or not dependencies):
        raise ValueError("PROVINCE_MODIFIERS_PROFILE_DEPENDENCY_SHAPE")
    for item in (*evidence, *dependencies):
        if (not isinstance(item, dict)
                or not isinstance(item.get("path"), str)
                or type(item.get("bytes")) is not int
                or item["bytes"] < 0
                or not isinstance(item.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("PROVINCE_MODIFIERS_PROFILE_DEPENDENCY_SHAPE")
        try:
            if not _base._matches_reviewed_layout(item):
                raise ValueError("PROVINCE_MODIFIERS_PROFILE_DEPENDENCY")
        except (OSError, ValueError) as exc:
            if isinstance(exc, ValueError) and str(exc) == "PROVINCE_MODIFIERS_PROFILE_DEPENDENCY":
                raise
            raise ValueError("PROVINCE_MODIFIERS_PROFILE_DEPENDENCY") from exc
    return profile


def _field_unknown(reason: str, raw_inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "reason": reason,
        "basis": BASIS,
        "raw_inputs": raw_inputs if raw_inputs is not None else {},
        "gaps": list(_GAPS),
    }


def _project_leaf_result(result: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if (not isinstance(result, dict)
            or result.get("schema") != _leaf.SCHEMA
            or result.get("complete") is not False
            or result.get("basis") != _leaf.BASIS):
        return _field_unknown("PROVINCE_MODIFIER_LEAF_RESULT_INVALID", {"leaf_result": result})
    predicates = result.get("predicates")
    if (not isinstance(predicates, dict)
            or tuple(predicates.keys()) != keys):
        return _field_unknown("PROVINCE_MODIFIER_LEAF_KEYS_MISMATCH", {"leaf_result": result})
    projected: dict[str, dict[str, Any]] = {}
    for key in keys:
        row = predicates.get(key)
        if not isinstance(row, dict):
            return _field_unknown("PROVINCE_MODIFIER_LEAF_PREDICATE_INVALID", {"leaf_result": result})
        status = row.get("status")
        if status == "known" and type(row.get("value")) is bool and "reason" not in row:
            projected[key] = {"status": "known", "value": row["value"]}
        elif status == "unknown" and "value" not in row:
            reason = row.get("reason")
            if not isinstance(reason, str) or not reason or len(reason) > 256:
                return _field_unknown("PROVINCE_MODIFIER_LEAF_PREDICATE_INVALID", {"leaf_result": result})
            projected[key] = {"status": "unknown", "reason": reason}
        else:
            return _field_unknown("PROVINCE_MODIFIER_LEAF_PREDICATE_INVALID", {"leaf_result": result})
    raw_gaps = result.get("gaps")
    gaps = list(raw_gaps) if isinstance(raw_gaps, list) and all(type(item) is str for item in raw_gaps) else list(_GAPS)
    return {
        "status": "known",
        "complete": False,
        "value": {"predicates": projected},
        "basis": BASIS,
        "raw_inputs": {"leaf_result": deepcopy(result)},
        "gaps": gaps,
    }


def _read_fields_for(keys: tuple[str, ...]):
    def read_fields(reader, module_base, province_binding, fields):
        if not isinstance(fields, (tuple, list)) or tuple(fields) != (FIELD,):
            if isinstance(fields, (tuple, list)):
                return {field: _field_unknown("UNSUPPORTED_FIELD") for field in fields if type(field) is str}
            return {}
        try:
            result = _leaf.read_predicates(reader, module_base, province_binding, keys)
        except Exception as exc:
            return {FIELD: _field_unknown(
                f"PROVINCE_MODIFIER_LEAF_FAILED:{type(exc).__name__}",
                {"error": str(exc)[:256], "keys": list(keys)},
            )}
        return {FIELD: _project_leaf_result(result, keys)}

    return read_fields


def _observe_for(province_id: int, keys: tuple[str, ...], observer: str = "FRA"):
    read_fields = _read_fields_for(keys)

    def observe(reader, module_base, country, profile):
        if country != observer or not _valid_id(province_id):
            raise ValueError("PROVINCE_MODIFIERS_OBSERVER_SCOPE")

        def backend(read, base, observer_country):
            if observer_country != observer:
                raise ValueError("PROVINCE_MODIFIERS_OBSERVER_SCOPE")
            return _province.read_two_pass(
                read,
                base,
                province_id,
                observer=observer,
                observer_scoped=True,
                fields=(FIELD,),
                read_fields=read_fields,
            )

        return _owner._observe(
            reader,
            module_base,
            country,
            profile,
            backend_reader=backend,
        )

    return observe


def capture(
    installation: Path,
    province_id: int,
    keys: list[str] | tuple[str, ...],
    *,
    observer: str = "FRA",
) -> dict[str, Any]:
    if not _valid_id(province_id) or not isinstance(observer, str) or not _owner._TAG.fullmatch(observer):
        raise ValueError("PROVINCE_MODIFIERS_REQUEST_SCOPE")
    normalized_keys = _keys(keys)
    inner = _owner._capture_common(
        installation,
        observer,
        observer=observer,
        schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe_for(province_id, normalized_keys, observer),
        allow_observer_target=True, observer_scoped=True,
    )
    return {
        "schema": SCHEMA,
        "observer": observer,
        "object": {"type": "province", "province_id": province_id},
        "modifier_keys": list(normalized_keys),
        "capture": inner,
    }


def validate_capture(
    report: Any,
    context: dict[str, Any],
    creation: int,
    province_id: int,
    keys: list[str] | tuple[str, ...],
) -> bool:
    if (not _valid_id(province_id) or type(creation) is not int
            or not isinstance(context, dict) or not isinstance(report, dict)):
        return False
    try:
        normalized_keys = _keys(keys)
    except ValueError:
        return False
    if set(report) != {"schema", "observer", "object", "modifier_keys", "capture"}:
        return False
    observer = context.get("observer")
    if (not isinstance(observer, str) or not _owner._TAG.fullmatch(observer)
            or report.get("schema") != SCHEMA or report.get("observer") != observer):
        return False
    expected_object = {"type": "province", "province_id": province_id}
    if not _owner._same(report.get("object"), expected_object):
        return False
    if type(report.get("modifier_keys")) is not list or not _owner._same(
        report.get("modifier_keys"), list(normalized_keys)
    ):
        return False
    return _owner._validate_capture_common(
        report["capture"],
        context,
        creation,
        observer,
        schema=INNER_SCHEMA,
        profile_sha256=PROFILE_SHA256,
        load_profile=_load_profile,
        observe=_observe_for(province_id, normalized_keys, observer),
        allow_observer_target=True, observer_scoped=True,
        require_access=True,
    )


__all__ = ["BASIS", "FIELD", "INNER_SCHEMA", "PROFILE_FILE", "PROFILE_SHA256", "SCHEMA",
           "capture", "validate_capture"]
