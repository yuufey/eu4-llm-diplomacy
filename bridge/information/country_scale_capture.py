"""Identity-bound, two-pass capture of selected country-scale fields."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from . import country_scale_development_memory as _development
from . import country_scale_flag_memory as _flag
from . import country_wars_memory as _wars
from . import country_territory_memory as _territory
from . import foreign_country_memory as _backend
from . import foreign_technology_capture as _owner
from . import observer_module_binding as _module_binding
from . import observer_registry_memory as _registry
from . import observer_registry_layout as _registry_layout


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "country-scale-memory-1374-v4-sampling-r1.json"
PROFILE_SHA256 = "f77bc58fc7187cc0c360532036b280f1a62cedaaaf21056c32b6710049765128"
PROFILE_MAX_BYTES = 256 * 1024
PROFILE_ID = "country-scale-memory-1374"
PROFILE_VERSION = 4
SCHEMA = "information.country_scale_capture.v1"
FIELDS = (
    _development.FIELD_DEVELOPMENT,
    _development.FIELD_SUBJECT_SCALE,
    _flag.FIELD_ID,
    _territory.FIELD_ID,
    _wars.FIELD_WARS,
)


def _load_profile() -> dict[str, Any]:
    size = PROFILE_FILE.stat().st_size
    if not 0 < size <= PROFILE_MAX_BYTES:
        raise ValueError("COUNTRY_SCALE_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("COUNTRY_SCALE_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != PROFILE_ID
            or profile.get("profile_version") != PROFILE_VERSION
            or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != _owner.EXE_SHA256):
        raise ValueError("COUNTRY_SCALE_PROFILE_BUILD")
    for item in profile["source_evidence"] + profile["layout_dependencies"]:
        path = (ROOT / item["path"]).resolve()
        path.relative_to(ROOT)
        # Python hashes retain the analysis implementation's historical version.
        # Runtime admission uses the pinned layout data and native code guards.
        if path.suffix == ".py":
            continue
        if path.stat().st_size != item["bytes"] or _owner._sha(path) != item["sha256"]:
            raise ValueError("COUNTRY_SCALE_PROFILE_DEPENDENCY")
    return profile


def _admission(read: Any, base: int, bindings: Mapping[str, Any],
               observer: str, target: str) -> dict[str, Any]:
    gate = _owner._bound_admission(read, base, bindings, observer, target)
    return gate


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _read_fields(reader: Any, base: int, binding: Mapping[str, Any],
                 fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    """Dispatch only the requested fields to their independent raw leaves."""
    result: dict[str, dict[str, Any]] = {}
    development_fields = tuple(field for field in fields if field in _development.FIELDS)
    major_power_fields = tuple(field for field in fields if field == _flag.FIELD_ID)
    territory_fields = tuple(field for field in fields if field in _territory.FIELDS)

    if development_fields:
        try:
            values = _development.read_fields(reader, base, binding, development_fields)
            for field in development_fields:
                item = values.get(field)
                result[field] = (deepcopy(dict(item)) if isinstance(item, Mapping)
                                 else _unknown("development_leaf_result_missing"))
        except Exception as exc:
            for field in development_fields:
                result[field] = _unknown(
                    f"development_leaf_failed:{type(exc).__name__}:{str(exc)[:120]}")

    if major_power_fields:
        try:
            values = _flag.read_fields(reader, base, binding, major_power_fields)
            for field in major_power_fields:
                item = values.get(field)
                result[field] = (deepcopy(dict(item)) if isinstance(item, Mapping)
                                 else _unknown("major_power_leaf_result_missing"))
        except Exception as exc:
            for field in major_power_fields:
                result[field] = _unknown(
                    f"major_power_leaf_failed:{type(exc).__name__}:{str(exc)[:120]}")

    if territory_fields:
        try:
            values = _territory.read_fields(reader, base, binding, territory_fields)
            for field in territory_fields:
                item = values.get(field)
                result[field] = (deepcopy(dict(item)) if isinstance(item, Mapping)
                                 else _unknown("territory_leaf_result_missing"))
        except Exception as exc:
            for field in territory_fields:
                result[field] = _unknown(
                    f"territory_leaf_failed:{type(exc).__name__}:{str(exc)[:120]}")

    # Never allow a leaf to leak a private or unrequested field into the
    # parent's ordered field record.
    return {field: result.get(field, _unknown("field_reader_missing"))
            for field in fields}


_UNKNOWN_MODULE_BINDING = {
    "status": "unknown", "reason": "OBSERVER_MODULE_BINDING_UNAVAILABLE",
}


def _module_consistency(before: Mapping[str, Any], after: Mapping[str, Any],
                        descriptor: Mapping[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Validate and compare the two private DLL observations without OS access."""
    first = _module_binding.validate_binding(dict(before), descriptor)
    second = _module_binding.validate_binding(dict(after), descriptor)
    return ("stable" if _owner._same(first, second) else "changed", first, second)


def _retract_wars(backend: dict[str, Any], reason: str) -> None:
    for target in backend.get("targets", []):
        fields = target.get("fields")
        consistency = target.get("field_consistency")
        if isinstance(fields, dict) and isinstance(fields.get(_wars.FIELD_WARS), Mapping):
            old = fields[_wars.FIELD_WARS]
            replacement = {"status": "unknown", "reason": reason}
            if isinstance(old.get("raw_inputs"), Mapping):
                replacement["raw_inputs"] = deepcopy(dict(old["raw_inputs"]))
            fields[_wars.FIELD_WARS] = replacement
        if isinstance(consistency, dict):
            consistency[_wars.FIELD_WARS] = {"status": "unknown", "reason": reason}


def _observe_with_metadata(reader: Any, base: int, country: str,
                           profile: Mapping[str, Any], *,
                           module_before: Mapping[str, Any],
                           module_after: Mapping[str, Any],
                           expected_creation: int,
                           registry_descriptor: Mapping[str, Any] | None = None,
                           war_details_reader=None, observer: str = "FRA") -> dict[str, Any]:
    descriptor = profile["observer_registry"] if registry_descriptor is None else registry_descriptor
    consistency, before, after = _module_consistency(
        module_before, module_after, descriptor)
    admission_state: dict[str, Any] = {}

    def backend(read: Any, module_base: int, target: str) -> dict[str, Any]:
        def admission_reader(limited_read: Any, current_base: int,
                             full_scan: Mapping[str, Any], observer: str,
                             current_target: str) -> dict[str, Any]:
            gate = _admission(limited_read, current_base, full_scan, observer, current_target)
            # read_fields follows this callback for the same target and pass.
            # Keep the complete scan: the war leaf uses it to bind each member
            # through the already captured country table, without another scan.
            admission_state["current"] = {
                "scan": deepcopy(dict(full_scan)), "gate": deepcopy(gate),
                "observer": observer, "target": current_target,
            }
            return gate

        def read_fields(limited_reader: Any, current_base: int,
                        target_binding: Mapping[str, Any],
                        requested: tuple[str, ...]) -> dict[str, dict[str, Any]]:
            ordinary = tuple(field for field in requested if field != _wars.FIELD_WARS)
            result = _read_fields(limited_reader, current_base, target_binding, ordinary)
            if _wars.FIELD_WARS in requested:
                current = admission_state.get("current")
                scan = current.get("scan") if isinstance(current, Mapping) else None
                requested_scan = scan.get("requested") if isinstance(scan, Mapping) else None
                observer_binding = (requested_scan.get(observer)
                                    if isinstance(requested_scan, Mapping) else None)
                if not isinstance(scan, Mapping) or not isinstance(observer_binding, Mapping):
                    result[_wars.FIELD_WARS] = _unknown("parent_country_scan_unavailable")
                else:
                    def registry_reader(registry_read: Any, registry_base: int) -> dict[str, Any]:
                        return _registry.read_registry(
                            registry_read, registry_base, binding=before,
                            layout=descriptor, expected_creation=expected_creation)

                    try:
                        values = _wars.read_fields(
                            limited_reader, current_base, target_binding,
                            (_wars.FIELD_WARS,), observer_binding=observer_binding,
                            expected_observer=observer,
                            registry_reader=registry_reader,
                            member_admission_reader=_owner._bound_admission,
                            admission_bindings=scan)
                        item = values.get(_wars.FIELD_WARS)
                        result[_wars.FIELD_WARS] = (
                            deepcopy(dict(item)) if isinstance(item, Mapping)
                            else _unknown("war_leaf_result_missing"))
                        war_field = result[_wars.FIELD_WARS]
                        if war_details_reader is not None and war_field.get("status") == "known":
                            war_field["value"]["details"] = war_details_reader(
                                limited_reader, current_base, war_field, profile)
                    except Exception as exc:
                        result[_wars.FIELD_WARS] = _unknown(
                            f"war_leaf_failed:{type(exc).__name__}:{str(exc)[:120]}")
            return {field: result.get(field, _unknown("field_reader_missing"))
                    for field in requested}

        return _backend.read_two_pass(
            read, module_base, observer, [target], FIELDS,
            read_fields=read_fields, admission_reader=admission_reader,
        )

    observation = _owner._observe(reader, base, country, profile, backend_reader=backend)
    observation["observer_module_binding"] = {
        "before": deepcopy(before), "after": deepcopy(after),
        "consistency": consistency,
    }
    if consistency != "stable":
        _retract_wars(observation.get("backend", {}), "observer_module_binding_changed")
    return observation


def _observe(reader: Any, base: int, country: str,
             profile: Mapping[str, Any], *,
             module_bindings: Mapping[str, Any] | None = None,
             expected_creation: int = 0) -> dict[str, Any]:
    """Observe with supplied metadata; the default is a stable unknown DLL."""
    supplied = (module_bindings if module_bindings is not None else
                {"before": _UNKNOWN_MODULE_BINDING,
                 "after": _UNKNOWN_MODULE_BINDING})
    return _observe_with_metadata(
        reader, base, country, profile,
        module_before=supplied["before"], module_after=supplied["after"],
        expected_creation=expected_creation)


def _capture_observe(reader: Any, base: int, country: str,
                     profile: Mapping[str, Any], creation: int,
                     registry_descriptor: Mapping[str, Any] | None = None,
                     war_details_reader=None, observer: str = "FRA") -> dict[str, Any]:
    """Read DLL metadata only inside the parent's admitted held-reader scope."""
    if (registry_descriptor is not None
            and registry_descriptor["module_file"] == profile["observer_registry"]["module_file"]):
        registry_descriptor = None
    descriptor = profile["observer_registry"] if registry_descriptor is None else registry_descriptor
    before = _module_binding.from_held_reader(reader, descriptor)
    # Use a stable temporary second value while the ordinary observation runs;
    # the actual post-observation lookup is recorded below and can retract wars.
    observation = _observe_with_metadata(
        reader, base, country, profile, module_before=before, module_after=before,
        expected_creation=creation, registry_descriptor=registry_descriptor,
        war_details_reader=war_details_reader, observer=observer)
    after = _module_binding.from_held_reader(reader, descriptor)
    consistency, before, after = _module_consistency(before, after, descriptor)
    observation["observer_module_binding"] = {
        "before": deepcopy(before), "after": deepcopy(after),
        "consistency": consistency,
    }
    if consistency != "stable":
        _retract_wars(observation.get("backend", {}), "observer_module_binding_changed")
    return observation


def capture(installation: Path, country: str, *, observer: str = "FRA") -> dict[str, Any]:
    # The installation document is the expected observer epoch source.  This
    # local bounded read does not open or enumerate a process; module metadata
    # remains inside the parent's validated observe callback.
    try:
        document = _owner._identity._load_installation(Path(installation))
        creation = document.get("creation_filetime")
        if type(creation) is not int or not 0 < creation < 2**64:
            creation = 0
    except Exception:
        creation = 0
    descriptor = _registry_layout.descriptor_for_installation(installation)

    def observe(reader: Any, base: int, requested_country: str,
                profile: Mapping[str, Any]) -> dict[str, Any]:
        if creation == 0:
            raise ValueError("COUNTRY_SCALE_INSTALLATION_CREATION")
        return _capture_observe(reader, base, requested_country, profile, creation, descriptor,
                                observer=observer)

    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=observe, allow_observer_target=True, observer_scoped=True,
    )


def validate_capture(report: Any, context: Mapping[str, Any],
                     creation: int, country: str) -> bool:
    try:
        observer = context['observer']
        observation = report["observation"]
        metadata = observation["observer_module_binding"]
        if not isinstance(metadata, Mapping) or set(metadata) != {"before", "after", "consistency"}:
            return False
        profile = _load_profile()
        descriptor = None
        if metadata["before"].get("file") != profile["observer_registry"]["module_file"]:
            descriptor = _registry_layout.descriptor_for_installation(report["request"].get("installation"))
        expected_descriptor = profile["observer_registry"] if descriptor is None else descriptor
        expected_consistency, before, after = _module_consistency(
            metadata["before"], metadata["after"], expected_descriptor)
        if metadata["consistency"] != expected_consistency:
            return False
    except Exception:
        return False

    def replay_observe(reader: Any, base: int, requested_country: str,
                      replay_profile: Mapping[str, Any]) -> dict[str, Any]:
        return _observe_with_metadata(
            reader, base, requested_country, replay_profile,
            module_before=before, module_after=after, expected_creation=creation,
            registry_descriptor=descriptor, observer=observer)

    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=replay_observe, allow_observer_target=True, require_access=True,
        observer_scoped=True,
    )


__all__ = ["SCHEMA", "FIELDS", "PROFILE_FILE", "PROFILE_SHA256",
           "capture", "validate_capture"]
