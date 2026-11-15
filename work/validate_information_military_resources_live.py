"""Bounded N02 sailors/force-limit acceptance.

``--preflight-only`` is an offline check: it reads pinned JSON artifacts and
the current Python catalog/schema, but it does not start MCP, inspect a game
process, or perform RPM.  ``--run`` is the only live entry point.  It requires
the frozen preflight receipt, captures the production memory reader once
directly, then checks one combined MCP query and one real two-second periodic
result against independently reconstructed expected values.

The expected projection is built from the Batch 69 save reference and raw RPM
receipt.  This file deliberately does not import the production projection to
construct its oracle.  The production memory module is imported only inside
the explicitly guarded live run, for capture and strict validation.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information.catalog import InformationError  # noqa: E402
from bridge.information.composite import CompositeSource  # noqa: E402
from bridge.information.country_forces import NativeCountryForcesSource  # noqa: E402
from bridge.information.country_state import NativeCountryStateSource  # noqa: E402
from bridge.information.military_resources import NativeMilitaryResourcesSource  # noqa: E402
from bridge.information.model import canonical  # noqa: E402
from bridge.information.sources import DiplomacySource  # noqa: E402
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema  # noqa: E402


COUNTRY = "FRA"
EXPECTED_PID = 27716
EXPECTED_CREATION_FILETIME = 134376348223436218
EXPECTED_SESSION = "27716-1dd6693a61275ba"
EXPECTED_VERSION = "1.37.4"
EXPECTED_DATE = 56562768
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA256 = "92fa4ea3b158e2ff42a69bce1cbbf7053b7f3a0ac128b25c9e5b7d1fb4bdc3ce"
INSTALLATION_SHA256 = "8669d71cfcf351ba7b53b394414930886002afac217efdbffab2f1c4f951d21b"
MANIFEST_SHA256 = "753e456808fec521600a9ded95a6151e6a0e492a3577558d9c97e7ec139408a2"
SAVE_REFERENCE_SHA256 = "44f935a26aca429af6b5508d9e02b5cdf8c6d1eb62f078620dcbcbf08fbf2ed7"
FORCE_REFERENCE_SHA256 = "238c344c966619118fd2d42e738b5e2b1ebadddd35e35b980aa80b728695a272"
RESOURCE_ROOT = Path("work/runtime/information-country-force-resources-20261027-001")
FORCE_PROBE_PATH = Path(
    "work/runtime/information-country-force-resources-20261027-001/69/"
    "force-limit-rpm-002/capture_force_limits_raw_rpm.py"
)
FORCE_PROBE_SHA256 = "b9c253a56c12171f275aa2e42a22a73c2f1578c4c7c2cf9ebdfb1b1baf7cee28"
FORCE_SOURCE_LOCATION = RESOURCE_ROOT / "force-limit-rpm-002-source-location-001.json"
FORCE_SOURCE_LOCATION_SHA256 = "ac3ca56d4f73aab39168f184af1e0b72cf74a0409616ee81f50bc86c9dce91f2"
INSTALLATION_DEFAULT = Path(
    "work/runtime/diplomacy-observer-20261028-information-resources-v30-005/installation.json"
)
SAVE_REFERENCE_DEFAULT = RESOURCE_ROOT / "save-reference-001/save-reference-001.json"
FORCE_REFERENCE_DEFAULT = RESOURCE_ROOT / "force-limit-raw-rpm-002.json"
REVIEW_ROOT = RESOURCE_ROOT / "acceptance-helper-review-003"
PREFLIGHT_DEFAULT = REVIEW_ROOT / "acceptance-helper-preflight-001.json"
FROZEN_PREFLIGHT_DEFAULT = PREFLIGHT_DEFAULT
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_LOG_SUFFIX = 2 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = ("sailors", "force_limits")
N02_FIELDS = (
    "army_size", "navy_size", "army_composition", "navy_composition",
    "manpower", "sailors", "force_limits",
)
N02_FIELD_OWNERS = {
    "army_size": "NativeCountryForcesSource",
    "navy_size": "NativeCountryForcesSource",
    "army_composition": "NativeCountryForcesSource",
    "navy_composition": "NativeCountryForcesSource",
    "manpower": "NativeCountryStateSource",
    "sailors": "NativeMilitaryResourcesSource",
    "force_limits": "NativeMilitaryResourcesSource",
}
N02_COVERAGE = {
    "army_size": "partial",
    "navy_size": "partial",
    "army_composition": "partial",
    "navy_composition": "partial",
    "manpower": "available",
    "sailors": "available",
    "force_limits": "partial",
}
FORCE_GAPS = [
    "DYNAMIC_PROCESSOR_VARIANTS_NOT_QUALIFIED",
    "NAVAL_GUI_SAMPLE_NOT_AUDITED",
    "CACHE_FRESHNESS_NOT_ATOMIC",
]
FORCE_IDS = {
    "0x36": 37777,
    "0x37": 16946,
    "0x38": 500,
    "0x39": 500,
}


class AcceptanceError(RuntimeError):
    """A pin, offline schema, live-read, or lifecycle check failed."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    size = path.stat().st_size
    _require(0 < size <= limit, f"json_size_out_of_bound:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _write_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _read_file_pin(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    digest = _sha256(resolved)
    _require(digest.lower() == expected_sha256.lower(), f"{label}_sha256_mismatch")
    return {"path": str(resolved), "bytes": resolved.stat().st_size,
            "sha256": digest}


def _load_identity(installation: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    identity = _read_json(installation)
    _require(isinstance(identity, dict), "installation_not_object")
    expected = {
        "pid": EXPECTED_PID,
        "creation_filetime": EXPECTED_CREATION_FILETIME,
        "session_id": EXPECTED_SESSION,
        "game_sha256": GAME_SHA256,
        "dll_sha256": DLL_SHA256,
    }
    for key, value in expected.items():
        actual = identity.get(key)
        if isinstance(value, str):
            _require(str(actual).lower() == value.lower(), f"installation_{key}_mismatch")
        else:
            _require(actual == value, f"installation_{key}_mismatch")
    _require(identity.get("installation_returncode") == 0,
             "installation_not_successful")
    _require(_sha256(installation) == INSTALLATION_SHA256,
             "installation_file_sha_mismatch")
    manifest_path = installation.parent / "build-manifest.json"
    manifest = _read_json(manifest_path)
    _require(isinstance(manifest, dict), "build_manifest_not_object")
    manifest_pin = {"path": str(manifest_path.resolve()),
                    "sha256": _sha256(manifest_path),
                    "bytes": manifest_path.stat().st_size}
    _require(manifest_pin["sha256"].lower() == MANIFEST_SHA256,
             "build_manifest_sha_mismatch")
    _require(manifest.get("version") == 30
             and manifest.get("compiled") is True
             and manifest.get("runtime_verified") is False,
             "build_manifest_contract_mismatch")
    _require(str(manifest.get("game_sha256", "")).lower() == GAME_SHA256,
             "build_manifest_game_sha_mismatch")
    _require(str(manifest.get("dll_sha256", "")).lower() == DLL_SHA256,
             "build_manifest_dll_sha_mismatch")
    sources = manifest.get("sources")
    _require(isinstance(sources, list) and len(sources) == 119,
             "build_manifest_source_count_mismatch")
    modules = identity.get("modules_after_install", [])
    _require(isinstance(modules, list) and any(
        isinstance(item, Mapping)
        and str(item.get("sha256", "")).lower() == DLL_SHA256
        for item in modules), "installed_dll_identity_missing")
    return identity, manifest, manifest_pin


def _load_battle_status(installation: Path) -> dict[str, Any]:
    path = installation.parent / "information-battle-status.json"
    value = _read_json(path)
    _require(isinstance(value, dict), "battle_status_not_object")
    _require(value.get("state") == "ready", "battle_source_not_ready")
    _require(value.get("code_patch_installed") is False,
             "battle_source_patch_was_enabled")
    _require(value.get("dll_pinned") is False
             and value.get("unwind_registered") is False,
             "battle_source_runtime_resources_present")
    _require(value.get("capture_complete") is False,
             "battle_capture_was_already_active")
    return {
        "path": str(path.resolve()),
        "sha256": _sha256(path),
        "state": value.get("state"),
        "code_patch_installed": value.get("code_patch_installed"),
        "dll_pinned": value.get("dll_pinned"),
        "unwind_registered": value.get("unwind_registered"),
        "capture_complete": value.get("capture_complete"),
        "publication_stage": value.get("publication_stage"),
    }


def _native_events_since(path: Path, offset: int) -> dict[str, Any]:
    """Read a bounded appended suffix; do not scan the existing log prefix."""
    _require(path.is_file(), f"observer_log_missing:{path}")
    size = path.stat().st_size
    _require(size >= offset, "observer_log_went_backwards")
    length = size - offset
    _require(length <= MAX_LOG_SUFFIX, f"native_suffix_over_bound:{length}")
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    events: list[dict[str, Any]] = []
    for line in data.splitlines():
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, ValueError):
            continue
        if not isinstance(value, dict):
            continue
        name = value.get("event")
        if isinstance(name, str) and (
                name.startswith("native_") or "query" in name.lower()
                or "inspection" in name.lower()):
            events.append(value)
    return {"offset": offset, "end": size, "bytes": length,
            "native_events": events}


def _reject_native_query_events(suffix: Mapping[str, Any]) -> None:
    events = suffix.get("native_events")
    _require(isinstance(events, list), "native_event_suffix_invalid")
    forbidden = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        name = event.get("event")
        if isinstance(name, str) and (
                "query" in name.lower() or "inspection" in name.lower()):
            forbidden.append(name)
    _require(not forbidden,
             "native_query_or_inspection_event_observed:" + ",".join(forbidden[:8]))


def _signed_i32(raw_hex: Any, label: str) -> int:
    _require(isinstance(raw_hex, str) and re.fullmatch(r"[0-9a-fA-F]{8}", raw_hex) is not None,
             f"{label}_raw_hex_invalid")
    return int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True)


def _trunc_div_toward_zero(value: int, divisor: int) -> int:
    _require(type(value) is int and type(divisor) is int and divisor > 0,
             "invalid_signed_division_input")
    quotient = abs(value) // divisor
    return -quotient if value < 0 else quotient


def _derive_force_count(base: int, percentage: int) -> tuple[int, int]:
    """Independent fixed-point derivation from signed raw inputs."""
    factor = 1000 + percentage
    rescaled = _trunc_div_toward_zero(base * factor, 1000)
    rounded = _trunc_div_toward_zero(rescaled, 1000) * 1000
    if rounded < 1000:
        rounded = 1000
    return rounded // 1000, rounded


def _little_i32_hex(value: int) -> str:
    _require(-(1 << 31) <= value < (1 << 31), "expected_raw_outside_i32")
    return value.to_bytes(4, "little", signed=True).hex()


def _resource_query(fields: tuple[str, ...] | list[str] = FIELDS) -> dict[str, Any]:
    return {"topic": "N02", "object": {"type": "country", "country": COUNTRY},
            "fields": list(fields), "parameters": {}}


def _catalog_contract() -> dict[str, Any]:
    """Build the real current N02 catalog in memory without service/RPC I/O."""
    primary = DiplomacySource(observer=COUNTRY)
    forces = NativeCountryForcesSource(primary)
    resources = NativeMilitaryResourcesSource(primary)
    state = NativeCountryStateSource(primary)
    adapters = [forces, resources, state]
    source = CompositeSource(primary, adapters)
    rows = source.catalog()
    topic = next((row for row in rows if row.get("topic_id") == "N02"), None)
    _require(isinstance(topic, Mapping), "current_n02_catalog_missing")
    _require(topic.get("status") == "available", "n02_catalog_status_not_available")
    _require(topic.get("source") == "CompositeSource",
             "n02_catalog_source_not_composite")
    _require(set(topic.get("fields", {})) == set(N02_FIELDS),
             "n02_catalog_field_routes_not_all_seven")
    _require(set(topic.get("adapter_sources", [])) == set(N02_FIELD_OWNERS.values()),
             "n02_catalog_adapter_sources_mismatch")
    for field, coverage in N02_COVERAGE.items():
        metadata = topic["fields"].get(field)
        _require(isinstance(metadata, Mapping)
                 and metadata.get("coverage") == coverage,
                 f"n02_{field}_catalog_coverage_mismatch")

    tool = next((item for item in TOOL_DEFINITIONS
                 if item.get("name") == "information_query"), None)
    _require(isinstance(tool, Mapping), "information_query_tool_schema_missing")
    resource_query = _resource_query()
    arguments = {"request_id": "mil-resources-offline-preflight",
                 "queries": [resource_query]}
    validate_schema(arguments, tool["inputSchema"], "arguments")
    normalized = source.validate_query(resource_query)
    _require(normalized == resource_query,
             "resource_only_query_not_normalized_without_recipient")
    routes: dict[str, Any] = {}
    for field, expected_owner in N02_FIELD_OWNERS.items():
        query = {"topic": "N02", "object": resource_query["object"],
                 "fields": [field], "parameters": {}}
        owner_row = source.query_catalog(query)
        capabilities = source.query_capabilities(query)
        _require(len(capabilities) == 1
                 and capabilities[0][0].get("fields") == [field],
                 f"n02_{field}_route_capability_missing")
        route_entry = capabilities[0][1]
        actual_owners = [type(adapter).__name__ for adapter in adapters
                         if any(canonical(route_entry) == canonical(candidate)
                                for candidate in adapter.catalog())]
        _require(actual_owners == [expected_owner]
                 and isinstance(owner_row, Mapping)
                 and owner_row.get("fields", {}).get(field, {}).get("coverage")
                 == N02_COVERAGE[field],
                 f"n02_{field}_route_owner_mismatch")
        routes[field] = {"owner": actual_owners[0],
                         "field_source": owner_row.get("fields", {}).get(field, {}).get("source"),
                         "coverage": owner_row.get("fields", {}).get(field, {}).get("coverage")}

    manpower_query = {"topic": "N02", "object": resource_query["object"],
                      "fields": ["manpower"], "parameters": {}}
    recipient_required = False
    try:
        source.validate_query(manpower_query)
    except InformationError:
        recipient_required = True
    _require(recipient_required, "existing_manpower_recipient_guard_missing")
    with_recipient = dict(manpower_query, parameters={"reference_recipient": "PAP"})
    _require(source.validate_query(with_recipient) == with_recipient,
             "existing_manpower_route_not_preserved")

    return {
        "topic_id": "N02", "status": topic.get("status"),
        "source": topic.get("source"),
        "adapter_sources": list(topic.get("adapter_sources", [])),
        "field_count": len(topic["fields"]),
        "coverage": {field: topic["fields"][field]["coverage"]
                     for field in N02_FIELDS},
        "routes": routes,
        "resource_query_schema": {"validated": True,
                                  "parameters": normalized["parameters"],
                                  "reference_recipient_required": False},
        "manpower_query_schema": {"validated_with_recipient": True,
                                  "recipient_required": True},
        "trigger_union": list(topic.get("triggers", [])),
        "offline_only": True,
    }


def _load_independent_expected(save_path: Path, force_path: Path,
                               installation: Path, expected_date: int
                               ) -> tuple[dict[str, Any], dict[str, Any]]:
    save_ref = _read_json(save_path)
    _require(isinstance(save_ref, Mapping)
             and save_ref.get("schema") == "information.country_force_resources.save_reference.v1"
             and save_ref.get("batch") == 69
             and save_ref.get("status") == "offline_reference_complete_with_unresolved_fields",
             "save_reference_contract_invalid")
    scope = save_ref.get("scope")
    _require(isinstance(scope, Mapping) and scope.get("country") == COUNTRY
             and scope.get("player") == "POR" and scope.get("save_date") == "1456.12.9"
             and scope.get("reference_kind") == "saved_checkpoint_snapshot"
             and scope.get("not_live") is True,
             "save_reference_scope_mismatch")
    sailors = save_ref.get("observed_resources", {}).get("sailors")
    _require(isinstance(sailors, Mapping) and sailors.get("derived") is False
             and sailors.get("present") is True,
             "save_reference_sailors_missing_or_derived")
    try:
        sailors_decimal = Decimal(str(sailors.get("raw_value")))
    except (InvalidOperation, ValueError) as exc:
        raise AcceptanceError("save_reference_sailors_decimal_invalid") from exc
    raw_decimal = sailors_decimal * Decimal(1000)
    _require(sailors_decimal.is_finite() and raw_decimal == raw_decimal.to_integral_value(),
             "save_reference_sailors_not_exact_scale1000")
    sailors_raw = int(raw_decimal)
    _require(0 <= sailors_raw < (1 << 31), "save_reference_sailors_outside_signed32")
    # This save value is well below the float32 integer precision boundary;
    # Decimal truncation of its scaled UI value gives the same signed cvtt result.
    sailors_display = int(Decimal(sailors_raw) / Decimal(1000))
    save_pin = _read_file_pin(save_path, SAVE_REFERENCE_SHA256, "save_reference")

    force_ref = _read_json(force_path)
    _require(isinstance(force_ref, Mapping)
             and force_ref.get("schema") == "information_country_force_limits_raw_rpm.v1"
             and force_ref.get("audit_id") == "force-limit-raw-rpm-002"
             and force_ref.get("batch") == 69
             and force_ref.get("status") == "observed_raw_candidate"
             and force_ref.get("read_only") is True
             and force_ref.get("completed") is True,
             "force_reference_contract_invalid")
    probe_script = force_ref.get("probe_script")
    _require(probe_script == FORCE_PROBE_PATH.as_posix()
             and str(force_ref.get("probe_script_sha256", "")).lower() == FORCE_PROBE_SHA256,
             "force_reference_probe_script_path_or_hash_mismatch")
    probe_path = (ROOT / FORCE_PROBE_PATH).resolve(strict=True)
    probe_pin = _read_file_pin(probe_path, FORCE_PROBE_SHA256,
                               "force_reference_probe_script")
    try:
        probe_path.relative_to((ROOT / RESOURCE_ROOT / "69").resolve())
    except ValueError as exc:
        raise AcceptanceError("force_reference_probe_script_not_under_69") from exc
    source_location = _read_json(ROOT / FORCE_SOURCE_LOCATION)
    _require(isinstance(source_location, Mapping)
             and source_location.get("status") == "preserved"
             and source_location.get("source") == {
                 "path": "work/runtime/information-country-force-resources-20261027-001/69/force-limit-raw-rpm-002.json",
                 "bytes": 121886,
                 "sha256": FORCE_REFERENCE_SHA256,
             }
             and source_location.get("snapshot") == {
                 "path": "work/runtime/information-country-force-resources-20261027-001/force-limit-raw-rpm-002.json",
                 "bytes": 121886,
                 "sha256": FORCE_REFERENCE_SHA256,
             }
             and source_location.get("capture_count") == 1
             and source_location.get("recaptured_or_replayed") is False,
             "force_reference_source_location_record_invalid")
    source_location_pin = _read_file_pin(
        ROOT / FORCE_SOURCE_LOCATION, FORCE_SOURCE_LOCATION_SHA256,
        "force_reference_source_location")
    target = force_ref.get("target_build")
    _require(isinstance(target, Mapping)
             and target.get("version") == EXPECTED_VERSION
             and str(target.get("exe_sha256", "")).lower() == GAME_SHA256
             and str(target.get("dll_sha256", "")).lower() == DLL_SHA256
             and target.get("installation") == str(
                 installation.resolve().relative_to(ROOT.resolve()).as_posix())
             and target.get("build_manifest") == str(
                 (installation.resolve().parent / "build-manifest.json")
                 .relative_to(ROOT.resolve()).as_posix()),
             "force_reference_build_mismatch")
    request = force_ref.get("request")
    _require(isinstance(request, Mapping) and request.get("country") == COUNTRY
             and request.get("passes") == 2
             and request.get("no_retry") is True
             and request.get("no_native_function_calls") is True
             and request.get("no_target_memory_writes") is True,
             "force_reference_request_contract_invalid")
    installation_pin = force_ref.get("installation_pin")
    installation_pin_after = force_ref.get("installation_pin_after")
    manifest_pin = force_ref.get("manifest_pin")
    manifest_pin_after = force_ref.get("manifest_pin_after")
    _require(isinstance(installation_pin, Mapping)
             and isinstance(installation_pin_after, Mapping)
             and installation_pin == installation_pin_after
             and installation_pin.get("sha256") == INSTALLATION_SHA256
             and installation_pin.get("path") == str(
                 installation.resolve().relative_to(ROOT.resolve()).as_posix()),
             "force_reference_installation_pin_mismatch")
    _require(isinstance(manifest_pin, Mapping)
             and isinstance(manifest_pin_after, Mapping)
             and manifest_pin == manifest_pin_after
             and manifest_pin.get("sha256") == MANIFEST_SHA256
             and manifest_pin.get("path") == str(
                 (installation.resolve().parent / "build-manifest.json")
                 .relative_to(ROOT.resolve()).as_posix()),
             "force_reference_manifest_pin_mismatch")
    double = force_ref.get("doublepass")
    cleanup = force_ref.get("cleanup", {}).get("handle_close") if isinstance(force_ref.get("cleanup"), Mapping) else None
    _require(isinstance(double, Mapping) and double.get("performed") is True
             and double.get("consistent") is True and double.get("mismatches") == []
             and cleanup == {"status": "closed", "success": True, "closed": True},
             "force_reference_doublepass_or_cleanup_invalid")

    for name in ("identity_before", "identity_after"):
        identity = force_ref.get(name)
        _require(isinstance(identity, Mapping)
                 and identity.get("pid") == EXPECTED_PID
                 and identity.get("creation_filetime") == EXPECTED_CREATION_FILETIME
                 and identity.get("process_creation_filetime") == EXPECTED_CREATION_FILETIME
                 and identity.get("session_id") == EXPECTED_SESSION
                 and identity.get("process_creation_matches_installation") is True
                 and identity.get("binding_verified") is True
                 and str(identity.get("process_path_sha256", "")).lower() == GAME_SHA256,
                 f"force_reference_{name}_identity_mismatch")

    snapshots = []
    for name in ("snapshot_before", "snapshot_after"):
        snapshot = force_ref.get(name)
        _require(isinstance(snapshot, Mapping)
                 and snapshot.get("game_date") == expected_date
                 and snapshot.get("game_date_matches_expected") is True,
                 f"force_reference_{name}_date_mismatch")
        country_row = snapshot.get("country")
        _require(isinstance(country_row, Mapping)
                 and country_row.get("status") == "observed"
                 and country_row.get("current_country_tag") == COUNTRY,
                 f"force_reference_{name}_country_mismatch")
        modifier = snapshot.get("modifier_inputs")
        ids = modifier.get("ids") if isinstance(modifier, Mapping) else None
        _require(isinstance(ids, Mapping)
                 and set(ids) == set(FORCE_IDS),
                 f"force_reference_{name}_modifier_ids_invalid")
        decoded: dict[str, int] = {}
        for ident, expected_raw in FORCE_IDS.items():
            row = ids.get(ident)
            _require(isinstance(row, Mapping)
                     and row.get("id") == int(ident, 16)
                     and row.get("private_candidate") is True
                     and row.get("semantic_claim") is not True,
                     f"force_reference_{name}_{ident}_metadata_invalid")
            signed_raw = _signed_i32(row.get("raw_hex"), f"{name}_{ident}")
            _require(signed_raw == expected_raw
                     and row.get("raw_u32_candidate") == expected_raw,
                     f"force_reference_{name}_{ident}_signed_value_mismatch")
            decoded[ident] = signed_raw
        processors = snapshot.get("processor_inputs", {}).get("slots")
        _require(isinstance(processors, Mapping)
                 and set(processors) == set(FORCE_IDS),
                 f"force_reference_{name}_processors_invalid")
        for ident, row in processors.items():
            _require(isinstance(row, Mapping)
                     and row.get("processor_pointer") is None
                     and row.get("processor_pointer_raw_hex") == "0000000000000000"
                     and row.get("slot_raw_hex") == "0000000000000000"
                     and row.get("status") == "absent",
                     f"force_reference_{name}_{ident}_processor_not_null")
        snapshots.append(decoded)
    _require(snapshots[0] == snapshots[1], "force_reference_two_pass_raw_values_differ")
    force_pin = _read_file_pin(force_path, FORCE_REFERENCE_SHA256, "force_reference")

    land_count, land_raw = _derive_force_count(snapshots[0]["0x36"], snapshots[0]["0x38"])
    naval_count, naval_raw = _derive_force_count(snapshots[0]["0x37"], snapshots[0]["0x39"])
    _require((land_count, land_raw, naval_count, naval_raw) == (56, 56000, 25, 25000),
             "independent_force_formula_unexpected_result")
    memory_fields = {
        "sailors": {
            "status": "known", "value": sailors_raw, "raw": sailors_raw,
            "raw_hex": _little_i32_hex(sailors_raw),
            "display_value": sailors_display, "unit": "sailors", "scale": 1000,
            "period": "current", "basis": "native_country_current_sailors_raw_field",
            "complete": True, "partial": False,
        },
        "force_limits": {
            "status": "partial",
            "value": {
                "land": {"status": "known", "value": land_count,
                         "raw": land_raw, "raw_hex": _little_i32_hex(land_raw),
                         "unit": "regiments", "scale": 1000,
                         "period": "current", "complete": True, "partial": False,
                         "basis": "native_force_limit_getter_numeric_path"},
                "naval": {"status": "known", "value": naval_count,
                          "raw": naval_raw, "raw_hex": _little_i32_hex(naval_raw),
                          "unit": "ships", "scale": 1000,
                          "period": "current", "complete": True, "partial": False,
                          "basis": "native_force_limit_getter_numeric_path"},
            },
            "unit": "mixed", "scale": 1000, "period": "current",
            "basis": "native_force_limit_getter_numeric_path",
            "complete": False, "partial": True, "unknown_conditions": {},
        },
    }
    _require(memory_fields["force_limits"]["status"] == "partial"
             and all(memory_fields["force_limits"]["value"][kind]["status"] == "known"
                     for kind in ("land", "naval")),
             "independent_force_shape_not_partial_with_known_children")
    public_fields = {
        "sailors": {
            "status": "known", "value": sailors_raw, "raw": sailors_raw,
            "raw_hex": _little_i32_hex(sailors_raw),
            "display_value": sailors_display, "unit": "sailors", "scale": 1000,
            "period": "current", "basis": "native_country_sailors_reserve",
            "value_origin": "copied_native_cache", "complete": True, "partial": False,
        },
        "force_limits": {
            "status": "known",
            "value": {
                "land": {"value": land_count, "raw": land_raw,
                         "unit": "regiments", "scale": 1000},
                "naval": {"value": naval_count, "raw": naval_raw,
                          "unit": "ships", "scale": 1000},
            },
            "unit": "force_limit_counts", "scale": 1, "period": "current",
            "basis": "native_country_land_naval_force_limits",
            "value_origin": "derived_from_copied_native_inputs",
            "complete": False, "partial": True, "gaps": list(FORCE_GAPS),
        },
    }
    expected = {
        "sailors": {"value": sailors_raw, "raw": sailors_raw,
                    "display_value": sailors_display, "unit": "sailors", "scale": 1000},
        "force_limits": {
            "status": "partial",
            "land": {"value": land_count, "raw": land_raw,
                     "unit": "regiments", "scale": 1000},
            "naval": {"value": naval_count, "raw": naval_raw,
                      "unit": "ships", "scale": 1000},
        },
    }
    return ({"memory_fields": memory_fields, "public_fields": public_fields,
             "summary": expected},
            {"save_reference": save_pin, "force_reference": force_pin,
             "force_reference_source_location": source_location_pin,
             "force_probe_script": {
                 **probe_pin, "recorded_path": probe_script,
                 "recorded_sha256": force_ref.get("probe_script_sha256"),
                 "resolved_absolute_path": str(probe_path.resolve()),
                 "under_69_original_capture_directory": True,
             },
             "save_reference_scope": dict(scope),
             "force_reference_status": force_ref.get("status"),
             "force_reference_doublepass": {"performed": double.get("performed"),
                                            "consistent": double.get("consistent")},
             "expected_game_date": expected_date,
             "signed_modifier_values": snapshots[0],
             "processors_null": True,
             "force_formula": {
                 "factor": "1000 + signed percentage",
                 "rescaled": "truncate toward zero(base * factor / 1000)",
                 "raw_count_floor": "truncate toward zero(rescaled / 1000) * 1000",
                 "minimum_raw": 1000,
                 "arithmetic_source": "independent fixed-point implementation in this helper",
             }})


DEPENDENCY_PATHS = (
    "bridge/diplomacy.py",
    "bridge/information/catalog.py",
    "bridge/information/composite.py",
    "bridge/information/country_forces.py",
    "bridge/information/country_state.py",
    "bridge/information/military_resources.py",
    "bridge/information/military_resources_memory.py",
    "bridge/information/model.py",
    "bridge/information/service.py",
    "bridge/information/sources.py",
    "bridge/information/tools.py",
    "bridge/information/profiles/military-resources-memory-1374.json",
    "tools/serve_information.py",
    "work/local_config.py",
    "work/run_alliance_inbound_response.py",
    "work/validate_information_live.py",
    "work/validate_information_peace_overextension_live.py",
    "work/validate_information_trade_power_live.py",
)


def _dependency_pins() -> list[dict[str, Any]]:
    result = []
    for relative in DEPENDENCY_PATHS:
        path = ROOT / relative
        _require(path.is_file(), f"acceptance_dependency_missing:{relative}")
        result.append({"path": relative, "bytes": path.stat().st_size,
                       "sha256": _sha256(path)})
    result.append({"path": str(Path(__file__).resolve().relative_to(ROOT).as_posix()),
                   "bytes": Path(__file__).stat().st_size,
                   "sha256": _sha256(Path(__file__)), "role": "acceptance_helper"})
    return result


def _build_preflight(installation: Path, save_reference: Path,
                     force_reference: Path, expected_date: int) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "information.country_force_resources.acceptance_helper_preflight.v1",
        "status": "running", "mode": "offline-preflight-only",
        "live_guard": "--run", "installation": str(installation.resolve()),
        "expected_date": expected_date,
        "checks": {}, "side_effects": {
            "mcp_started": False, "rpm_capture_performed": False,
            "native_game_calls": False, "target_memory_writes": False,
            "information_tick_sent": False, "diplomacy_dispatched": False,
        },
    }
    try:
        identity, manifest, manifest_pin = _load_identity(installation)
        report["installation_identity"] = {
            "path": str(installation.resolve()), "sha256": _sha256(installation),
            "pid": identity.get("pid"),
            "creation_filetime": identity.get("creation_filetime"),
            "session_id": identity.get("session_id"),
            "game_sha256": identity.get("game_sha256"),
            "dll_sha256": identity.get("dll_sha256"),
            "manifest": manifest_pin,
            "manifest_version": manifest.get("version"),
            "native_source_count": len(manifest.get("sources", [])),
        }
        report["checks"]["installation_and_build_hashes"] = True
        report["battle_status"] = _load_battle_status(installation)
        report["checks"]["battle_ready_unpatched_and_unmanaged"] = True

        expected, reference_audit = _load_independent_expected(
            save_reference, force_reference, installation, expected_date)
        report["references"] = reference_audit
        report["independent_expected"] = expected
        report["checks"]["saved_sailors_decimal_exact_scale1000"] = True
        report["checks"]["signed_force_modifiers_and_null_processors"] = True
        report["checks"]["force_limit_shape_partial_known_children"] = True
        report["checks"]["independent_force_formula_56_and_25"] = True

        report["catalog_route_schema"] = _catalog_contract()
        report["checks"]["current_real_catalog_all_seven_n02_routes"] = True
        report["checks"]["resource_only_query_schema_without_recipient"] = True
        report["checks"]["manpower_recipient_guard_preserved"] = True

        report["helper"] = {
            "path": str(Path(__file__).resolve().relative_to(ROOT).as_posix()),
            "bytes": Path(__file__).stat().st_size,
            "sha256": _sha256(Path(__file__)),
            "cli_live": (
                "python work/validate_information_military_resources_live.py "
                "--installation work/runtime/diplomacy-observer-20261028-information-resources-v30-005/installation.json "
                "--save-reference work/runtime/information-country-force-resources-20261027-001/save-reference-001/save-reference-001.json "
                "--force-reference work/runtime/information-country-force-resources-20261027-001/force-limit-raw-rpm-002.json "
                "--output work/runtime/information-country-force-resources-20261027-001/live-acceptance-003 "
                "--preflight-receipt work/runtime/information-country-force-resources-20261027-001/acceptance-helper-review-003/acceptance-helper-preflight-001.json "
                "--expected-date 56562768 --run"
            ),
            "explicit_live_guard": "--run",
        }
        report["dependency_pins"] = _dependency_pins()
        report["checks"]["acceptance_dependency_pins_recorded"] = True
        report["status"] = "passed"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    return report


def _assert_frozen_preflight(receipt_path: Path, current: Mapping[str, Any]) -> None:
    receipt = _read_json(receipt_path)
    _require(isinstance(receipt, Mapping)
             and receipt.get("schema") == "information.country_force_resources.acceptance_helper_preflight.v1"
             and receipt.get("status") == "passed"
             and receipt.get("mode") == "offline-preflight-only",
             "frozen_preflight_receipt_invalid")
    _require(receipt.get("helper") == current.get("helper"),
             "helper_changed_since_frozen_preflight")
    _require(receipt.get("dependency_pins") == current.get("dependency_pins"),
             "dependency_changed_since_frozen_preflight")
    _require(receipt.get("installation_identity") == current.get("installation_identity")
             and receipt.get("references") == current.get("references")
             and receipt.get("independent_expected") == current.get("independent_expected")
             and receipt.get("catalog_route_schema") == current.get("catalog_route_schema"),
             "preflight_inputs_changed_since_freeze")


def _write_call_request(output: Path, label: str, name: str,
                        arguments: Mapping[str, Any]) -> None:
    _write_exclusive(output / f"{label}-request.json",
                     {"name": name, "arguments": dict(arguments)})


def _check_result(value: Mapping[str, Any], query: Mapping[str, Any],
                  expected_fields: Mapping[str, Any], identity: Mapping[str, Any],
                  expected_date: int, *, subscription_id: str | None = None
                  ) -> dict[str, Any]:
    _require(value.get("status") == "partial" and value.get("complete") is False,
             "resource_result_not_partial")
    delivery = value.get("delivery")
    _require(isinstance(delivery, Mapping)
             and delivery.get("status") == "delivered"
             and delivery.get("llm_read") == "unknown",
             "resource_result_delivery_or_llm_read_invalid")
    context = value.get("context")
    _require(isinstance(context, Mapping)
             and context.get("session_id") == identity.get("session_id")
             and context.get("observer") == COUNTRY
             and context.get("game_version") == EXPECTED_VERSION
             and context.get("game_sha256") == GAME_SHA256
             and context.get("game_date") == expected_date,
             "resource_result_context_mismatch")
    items = value.get("items")
    _require(isinstance(items, list) and len(items) == 1
             and isinstance(items[0], Mapping), "resource_result_item_invalid")
    item = items[0]
    echoed = item.get("query")
    _require(isinstance(echoed, Mapping)
             and echoed.get("topic") == query["topic"]
             and echoed.get("object") == query["object"]
             and echoed.get("fields") == query["fields"]
             and echoed.get("parameters", {}) == query["parameters"],
             "resource_query_echo_mismatch")
    _require(item.get("objects") == [query["object"]],
             "resource_result_object_mismatch")
    fields = item.get("fields")
    _require(isinstance(fields, Mapping) and set(fields) == set(FIELDS),
             "resource_result_fields_invalid")
    _require(dict(fields) == dict(expected_fields),
             "resource_result_fields_differ_from_independent_expected")
    force = fields.get("force_limits")
    _require(isinstance(force, Mapping) and force.get("status") == "known"
             and force.get("complete") is False and force.get("partial") is True,
             "public_force_limits_not_partial")
    source = item.get("source")
    _require(isinstance(source, Mapping)
             and source.get("name") == "CompositeSource",
             "resource_result_source_not_composite")
    source_rows = source.get("sources")
    _require(isinstance(source_rows, list)
             and any(isinstance(row, Mapping)
                     and row.get("fields") == list(FIELDS)
                     and isinstance(row.get("source"), Mapping)
                     and row["source"].get("name") == "NativeMilitaryResourcesSource"
                     for row in source_rows),
             "resource_result_owner_provenance_missing")
    if subscription_id is not None:
        _require(value.get("subscription_id") == subscription_id,
                 "resource_periodic_subscription_mismatch")
    return {
        "result_id": value.get("result_id"),
        "subscription_id": value.get("subscription_id"),
        "delivery": {"status": delivery.get("status"),
                      "adapter": delivery.get("adapter"),
                      "llm_read": delivery.get("llm_read")},
        "field_values_exact": True,
        "force_limits_status": force.get("status"),
        "force_limits_complete": force.get("complete"),
        "force_limits_partial": force.get("partial"),
        "outbox_delivery_does_not_prove_llm_read": True,
    }


def _check_subscription_list(value: Mapping[str, Any], *, no_active: bool) -> list[dict[str, Any]]:
    rows = value.get("subscriptions")
    _require(isinstance(rows, list), "subscription_list_missing")
    simplified = []
    for row in rows:
        _require(isinstance(row, Mapping), "subscription_list_row_invalid")
        subscription = row.get("subscription") if isinstance(row.get("subscription"), Mapping) else row
        state = subscription.get("state") if isinstance(subscription, Mapping) else None
        if no_active:
            _require(state != "active", "active_subscription_remains")
        simplified.append({"id": subscription.get("id") if isinstance(subscription, Mapping) else None,
                           "state": state})
    return simplified


def _run_live(args: argparse.Namespace) -> int:
    installation = args.installation
    output = args.output
    runtime_root = (ROOT / "work/runtime").resolve()
    output_resolved = output.resolve()
    try:
        output_resolved.relative_to(runtime_root)
    except ValueError as exc:
        raise AcceptanceError("output_must_be_under_work_runtime") from exc
    output_resolved.mkdir(parents=True, exist_ok=False)

    report: dict[str, Any] = {
        "schema": "information.country_force_resources.live_acceptance.v1",
        "status": "running", "mode": "test-only-live-read",
        "read_only": True, "run_guard": "--run",
        "identity_pins": {"pid": EXPECTED_PID,
                           "creation_filetime": EXPECTED_CREATION_FILETIME,
                           "session_id": EXPECTED_SESSION,
                           "game_sha256": GAME_SHA256,
                           "dll_sha256": DLL_SHA256,
                           "manifest_sha256": MANIFEST_SHA256,
                           "game_version": EXPECTED_VERSION,
                           "game_date": args.expected_date},
        "inputs": {"installation": str(installation.resolve()),
                   "save_reference": str(args.save_reference.resolve()),
                   "force_reference": str(args.force_reference.resolve()),
                   "output": str(output_resolved),
                   "frozen_preflight": str(args.preflight_receipt.resolve())},
        "checks": {},
        "query_contract": _resource_query(),
        "business_dispatch": False, "native_game_calls": False,
        "information_tick_sent": False, "date_advance_save_reload": False,
        "computer_use": False, "llm_read": "unknown",
        "outbox_delivered_is_not_llm_read": True,
        "cancel_started": False,
        "active_subscription_count_after": None,
        "limitations": [
            "The save reference preserves sailors as a scaled raw value; it does not prove a person count.",
            "The force-limit projection is partial and retains dynamic processor, naval GUI, and cache-freshness gaps.",
            "The raw modifier IDs and zero processor slots are independently pinned inputs; no getter or processor is called.",
            "A durable outbox delivery is not evidence that an LLM read the result.",
        ],
    }
    client = None
    subscription: dict[str, Any] | None = None
    cancel_started = False
    session = None
    before_control: dict[str, Any] | None = None
    initial_log_offset: int | None = None
    log_path = installation.resolve().parent / "control-probe.jsonl"
    identity: dict[str, Any] | None = None
    memory = None

    def call(label: str, name: str, **arguments: Any) -> Any:
        _require(client is not None, "mcp_client_not_started")
        definition = next((item for item in TOOL_DEFINITIONS
                           if item.get("name") == name), None)
        _require(isinstance(definition, Mapping), f"tool_definition_missing:{name}")
        validate_schema(arguments, definition["inputSchema"], "arguments")
        _write_call_request(output_resolved, label, name, arguments)
        offset = log_path.stat().st_size
        try:
            value = client.call(name, **arguments)
        except Exception as exc:
            _write_exclusive(output_resolved / f"{label}-failure.json",
                             {"type": type(exc).__name__, "message": str(exc)})
            try:
                suffix = _native_events_since(log_path, offset)
                _write_exclusive(output_resolved / f"{label}-native-events.json", suffix)
                _reject_native_query_events(suffix)
            except Exception as suffix_error:
                _write_exclusive(output_resolved / f"{label}-native-events-failure.json",
                                 {"type": type(suffix_error).__name__,
                                  "message": str(suffix_error)})
            raise
        _write_exclusive(output_resolved / f"{label}-response.json", value)
        suffix = _native_events_since(log_path, offset)
        _write_exclusive(output_resolved / f"{label}-native-events.json", suffix)
        _reject_native_query_events(suffix)
        return value

    try:
        preflight = _build_preflight(installation, args.save_reference,
                                     args.force_reference, args.expected_date)
        _write_exclusive(output_resolved / "preflight-recheck.json", preflight)
        _require(preflight.get("status") == "passed", "live_preflight_failed")
        _assert_frozen_preflight(args.preflight_receipt, preflight)
        report["preflight_status"] = "passed"
        report["dependency_pins"] = preflight["dependency_pins"]
        report["reference_audit"] = preflight["references"]
        expected = preflight["independent_expected"]
        report["expected"] = expected["summary"]
        report["checks"]["frozen_preflight_and_all_dependency_pins"] = True

        identity, manifest, manifest_pin = _load_identity(installation)
        report["identity"] = {
            "pid": identity.get("pid"),
            "creation_filetime": identity.get("creation_filetime"),
            "session_id": identity.get("session_id"),
            "game_sha256": identity.get("game_sha256"),
            "dll_sha256": identity.get("dll_sha256"),
            "installation_sha256": _sha256(installation),
        }
        report["build_manifest"] = {**manifest_pin,
                                     "version": manifest.get("version"),
                                     "native_source_count": len(manifest.get("sources", []))}
        _write_exclusive(output_resolved / "installation-identity.json",
                         {"identity": identity, "manifest": manifest,
                          "manifest_pin": manifest_pin})
        report["battle_status"] = _load_battle_status(installation)
        _write_exclusive(output_resolved / "battle-status.json", report["battle_status"])

        from bridge.diplomacy import ObserverSession
        from work.local_config import game_exe
        from work.run_alliance_inbound_response import control_snapshot
        from bridge.information import military_resources_memory as memory

        session = ObserverSession(installation, game_exe())
        before_health = session.health()
        _write_exclusive(output_resolved / "before-health.json", before_health)
        _require(before_health.get("status") == "ready"
                 and before_health.get("date_raw") == args.expected_date,
                 "before_health_not_ready_same_date")
        report["checks"]["before_health_ready_same_date"] = True
        before_control = control_snapshot(EXPECTED_PID,
                                          output_resolved / "before-control.json")
        _require((before_control.get("player_slot"), before_control.get("date_raw"),
                  before_control.get("speed"), before_control.get("paused_flag"))
                 == (189, args.expected_date, 0, 1),
                 "before_control_not_paused_por")
        report["before_control"] = before_control
        report["checks"]["before_control_paused_por_date"] = True

        capture = memory.capture(installation, country=COUNTRY)
        _write_exclusive(output_resolved / "production-memory-capture.json", capture)
        context = {"session_id": identity["session_id"],
                   "game_sha256": GAME_SHA256, "observer": COUNTRY,
                   "game_version": EXPECTED_VERSION,
                   "game_date": args.expected_date}
        valid_capture = memory.validate_capture(
            capture, context, EXPECTED_CREATION_FILETIME, COUNTRY)
        _require(valid_capture is True, "production_capture_strict_validation_failed")
        memory_expected = expected["memory_fields"]
        before_record = capture.get("before", {}).get("record", {})
        after_record = capture.get("after", {}).get("record", {})
        _require(isinstance(before_record, Mapping)
                 and isinstance(after_record, Mapping),
                 "production_capture_record_missing")
        before_fields = before_record.get("fields")
        after_fields = after_record.get("fields")
        _require(isinstance(before_fields, Mapping)
                 and isinstance(after_fields, Mapping)
                 and set(before_fields) == set(FIELDS)
                 and set(after_fields) == set(FIELDS),
                 "production_capture_before_record_fields_invalid")
        _require(dict(before_fields) == memory_expected
                 and dict(after_fields) == memory_expected
                 and capture.get("fields") == memory_expected,
                 "production_capture_fields_differ_from_independent_reference")
        underlying_force = before_fields.get("force_limits")
        _require(isinstance(underlying_force, Mapping)
                 and underlying_force.get("status") == "partial"
                 and isinstance(underlying_force.get("value"), Mapping)
                 and all(isinstance(underlying_force["value"].get(kind), Mapping)
                         and underlying_force["value"][kind].get("status") == "known"
                         for kind in ("land", "naval")),
                 "production_force_limits_not_partial_with_known_land_naval")
        report["production_capture"] = {
            "status": capture.get("status"),
            "strict_validate_capture": True,
            "complete_report_sha256": _sha256_value(capture),
            "before_record_fields": list(before_fields),
            "fields_match_independent_expected": True,
            "force_limits_status": underlying_force.get("status"),
            "force_limit_children": {
                kind: {"status": underlying_force["value"][kind].get("status"),
                       "value": underlying_force["value"][kind].get("value"),
                       "raw": underlying_force["value"][kind].get("raw"),
                       "unit": underlying_force["value"][kind].get("unit"),
                       "scale": underlying_force["value"][kind].get("scale")}
                for kind in ("land", "naval")},
        }
        report["checks"].update({
            "production_capture_strictly_validated": True,
            "production_capture_fields_equal_independent_expected": True,
            "before_record_contains_sailors_and_force_limits": True,
            "underlying_force_limits_partial_known_children": True,
            "production_capture_no_game_function_or_memory_write": (
                capture.get("access", {}).get("native_game_calls") is False
                and capture.get("access", {}).get("target_memory_writes") is False),
        })
        _require(report["checks"]["production_capture_no_game_function_or_memory_write"],
                 "production_capture_game_call_or_write_observed")

        _require(log_path.is_file(), "observer_log_missing_before_mcp")
        initial_log_offset = log_path.stat().st_size
        from work.validate_information_peace_overextension_live import _ImmediateClient
        client = _ImmediateClient(installation, output_resolved, tick=2)
        namespace = "n02-military-resources-" + hashlib.sha256(
            str(output_resolved).encode("utf-8")).hexdigest()[:16]

        initial_subs = call("00-existing-subscriptions", "information_manage_subscription",
                            request_id=namespace + "-subscriptions-before",
                            operation="list")
        before_rows = _check_subscription_list(initial_subs, no_active=True)
        report["subscriptions_before"] = before_rows
        report["checks"]["no_existing_active_subscription"] = True

        query = _resource_query()
        active = call("01-active-query", "information_query",
                      request_id=namespace + "-active-query", queries=[query])
        active_summary = _check_result(active, query, expected["public_fields"],
                                       identity, args.expected_date)
        _write_exclusive(output_resolved / "active-comparison.json", active_summary)
        report["active"] = active_summary
        report["checks"]["one_combined_active_query_exact_expected"] = True

        report_config = {"name": "N02 military resources live acceptance",
                         "queries": [query], "detail": "raw"}
        configured = call("02-report-create", "information_manage_report",
                          request_id=namespace + "-report-create",
                          operation="create", config=report_config)
        report_value = configured.get("report") if isinstance(configured, Mapping) else None
        _require(isinstance(report_value, Mapping)
                 and isinstance(report_value.get("id"), str),
                 "report_id_missing")
        _require(report_value.get("queries") == [query]
                 and report_value.get("detail") == "raw",
                 "report_configuration_did_not_preserve_combined_query")
        report["report_id"] = report_value["id"]
        report["checks"]["report_configuration_same_query"] = True

        subscription_config = {
            "name": "N02 military resources two-second periodic",
            "kind": "periodic", "report_id": report_value["id"],
            "enabled": True,
            "schedule": {"basis": "real", "every": 2,
                         "unit": "seconds", "missed": "coalesce"},
        }
        created = call("03-periodic-create", "information_manage_subscription",
                       request_id=namespace + "-periodic-create",
                       operation="create", config=subscription_config)
        created_subscription = (created.get("subscription")
                                if isinstance(created, Mapping) else None)
        if isinstance(created_subscription, Mapping):
            subscription = dict(created_subscription)
            report["subscription"] = {
                "id": subscription.get("id"),
                "version": subscription.get("version"),
                "state": subscription.get("state"),
                "schedule": subscription.get("schedule"),
            }
        _require(isinstance(subscription, Mapping)
                 and isinstance(subscription.get("id"), str)
                 and type(subscription.get("version")) is int
                 and subscription.get("state") == "active",
                 "periodic_subscription_not_active")
        _require(subscription.get("report_id") == report_value["id"]
                 and subscription.get("schedule") == subscription_config["schedule"],
                 "periodic_subscription_config_mismatch")

        periodic_result: Mapping[str, Any] | None = None
        periodic_summary: dict[str, Any] | None = None
        attempts = []
        for index in range(30):
            time.sleep(0.5)
            listed = call(f"04-results-{index + 1:02d}",
                          "information_list_results", limit=100)
            rows = listed.get("results") if isinstance(listed, Mapping) else None
            _require(isinstance(rows, list), "periodic_results_missing")
            candidate = next((row for row in rows
                              if isinstance(row, Mapping)
                              and row.get("subscription_id") == subscription["id"]), None)
            attempts.append({"attempt": index + 1, "result_count": len(rows),
                             "found": candidate is not None})
            if candidate is not None:
                periodic_result = candidate
                periodic_summary = _check_result(
                    candidate, query, expected["public_fields"], identity,
                    args.expected_date, subscription_id=subscription["id"])
                _write_exclusive(output_resolved / "periodic-first-result.json",
                                 candidate)
                _write_exclusive(output_resolved / "periodic-comparison.json",
                                 periodic_summary)
                break
        _require(periodic_result is not None and periodic_summary is not None,
                 "periodic_first_real_result_missing")
        active_fields = active.get("items", [{}])[0].get("fields")
        periodic_fields = periodic_result.get("items", [{}])[0].get("fields")
        _require(active_fields == periodic_fields,
                 "active_and_periodic_fields_differ")
        report["periodic"] = dict(periodic_summary, attempts=attempts,
                                  interval={"basis": "real", "every": 2,
                                            "unit": "seconds"})
        report["checks"]["first_real_periodic_result_exact_expected"] = True
        report["checks"]["active_periodic_fields_equal"] = True

        # Latch before the single cancel request.  No timeout/error path may
        # replay this cancel or any earlier request.
        cancel_started = True
        report["cancel_started"] = True
        cancelled = call("05-cancel", "information_manage_subscription",
                         request_id=namespace + "-cancel", operation="cancel",
                         subscription_id=subscription["id"],
                         expected_version=subscription["version"])
        cancelled_subscription = (cancelled.get("subscription")
                                  if isinstance(cancelled, Mapping) else None)
        if isinstance(cancelled_subscription, Mapping):
            subscription = dict(cancelled_subscription)
        _require(isinstance(subscription, Mapping)
                 and subscription.get("state") == "cancelled",
                 "subscription_not_cancelled")

        states = call("06-subscriptions-after", "information_manage_subscription",
                      request_id=namespace + "-subscriptions-after",
                      operation="list")
        after_rows = _check_subscription_list(states, no_active=True)
        report["subscriptions_after"] = after_rows
        status = call("07-status-after", "information_status")
        status_rows = status.get("subscriptions") if isinstance(status, Mapping) else None
        _require(isinstance(status_rows, list)
                 and all(isinstance(row, Mapping)
                         and isinstance(row.get("subscription"), Mapping)
                         and row["subscription"].get("state") != "active"
                         and row.get("runtime", {}).get("state") != "active"
                         for row in status_rows),
                 "status_reports_active_subscription")
        report["active_subscription_count_after"] = 0
        report["checks"]["cancelled_once_no_active_subscription"] = True
        report["checks"]["status_reports_no_active_subscription"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__,
                                                "message": str(exc)})
    finally:
        if (subscription is not None and subscription.get("state") == "active"
                and client is not None and not cancel_started):
            try:
                cancel_started = True
                report["cancel_started"] = True
                cleanup = call(
                    "cleanup-cancel", "information_manage_subscription",
                    request_id=("n02-military-resources-cleanup-" +
                                hashlib.sha256(str(output_resolved).encode()).hexdigest()[:16]),
                    operation="cancel", subscription_id=subscription["id"],
                    expected_version=subscription["version"],
                )
                cleaned = cleanup.get("subscription") if isinstance(cleanup, Mapping) else None
                if isinstance(cleaned, Mapping):
                    subscription = dict(cleaned)
                _require(subscription.get("state") == "cancelled",
                         "cleanup_subscription_not_cancelled")
                report["cleanup_cancel"] = "cancelled_once"
            except Exception as exc:
                report["cleanup_error"] = {"type": type(exc).__name__,
                                            "message": str(exc)}
                report["status"] = "failed"
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                report["close_error"] = {"type": type(exc).__name__,
                                          "message": str(exc)}
                report["status"] = "failed"
            report["server_exit_code"] = client.process.returncode
            report["checks"]["server_exit_zero"] = client.process.returncode == 0
            if client.process.returncode != 0:
                report["status"] = "failed"
        if session is not None and before_control is not None:
            try:
                after_health = session.health()
                _write_exclusive(output_resolved / "after-health.json", after_health)
                health_ok = (after_health.get("status") == "ready"
                             and after_health.get("date_raw") == args.expected_date)
                report["checks"]["after_health_ready_same_date"] = health_ok
                if not health_ok:
                    report["status"] = "failed"
            except Exception as exc:
                report["after_health_error"] = {"type": type(exc).__name__,
                                                 "message": str(exc)}
                report["status"] = "failed"
            try:
                after_control = control_snapshot(
                    EXPECTED_PID, output_resolved / "after-control.json")
                preserved = all(before_control.get(key) == after_control.get(key)
                                for key in ("date_raw", "paused_flag", "speed",
                                            "player_slot"))
                report["after_control"] = after_control
                report["checks"]["after_control_preserved"] = preserved
                if not preserved:
                    report["status"] = "failed"
            except Exception as exc:
                report["after_control_error"] = {"type": type(exc).__name__,
                                                  "message": str(exc)}
                report["status"] = "failed"
        if initial_log_offset is not None:
            try:
                suffix = _native_events_since(log_path, initial_log_offset)
                _write_exclusive(output_resolved / "native-events.json", suffix)
                _reject_native_query_events(suffix)
                report["native_events"] = suffix
                report["checks"]["native_query_event_count_unchanged"] = True
            except Exception as exc:
                report["native_events_error"] = {"type": type(exc).__name__,
                                                  "message": str(exc)}
                report["status"] = "failed"
        report["cancel_started"] = cancel_started
        try:
            final_pins = _dependency_pins()
            report["checks"]["dependency_pins_unchanged_after_run"] = (
                final_pins == report.get("dependency_pins"))
            if not report["checks"]["dependency_pins_unchanged_after_run"]:
                report["status"] = "failed"
            report["final_dependency_pins"] = final_pins
        except Exception as exc:
            report["dependency_pin_error"] = {"type": type(exc).__name__,
                                              "message": str(exc)}
            report["status"] = "failed"
        _write_exclusive(output_resolved / "report.json", report)
    print(json.dumps({key: report.get(key) for key in
                      ("status", "checks", "error", "server_exit_code", "expected")},
                     ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def _preflight_only(args: argparse.Namespace) -> int:
    report = _build_preflight(args.installation, args.save_reference,
                              args.force_reference, args.expected_date)
    path = args.preflight_report
    _write_exclusive(path, report)
    print(json.dumps({"status": report["status"], "path": str(path.resolve()),
                      "checks": report.get("checks"), "error": report.get("error")},
                     ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, default=ROOT / INSTALLATION_DEFAULT,
                        help="pinned v30-005 installation.json")
    parser.add_argument("--save-reference", type=Path, default=ROOT / SAVE_REFERENCE_DEFAULT,
                        help="pinned Batch 69 save reference JSON")
    parser.add_argument("--force-reference", type=Path, default=ROOT / FORCE_REFERENCE_DEFAULT,
                        help="pinned Batch 69 raw RPM force-limit reference JSON")
    parser.add_argument("--expected-date", type=int, default=EXPECTED_DATE,
                        help="expected paused game date raw value")
    parser.add_argument("--preflight-only", action="store_true",
                        help="offline-only input, real catalog, and route schema checks")
    parser.add_argument("--preflight-report", type=Path, default=ROOT / PREFLIGHT_DEFAULT,
                        help="new receipt path for --preflight-only")
    parser.add_argument("--preflight-receipt", type=Path,
                        default=ROOT / FROZEN_PREFLIGHT_DEFAULT,
                        help="passed, frozen offline preflight required by --run")
    parser.add_argument("--output", type=Path,
                        help="new work/runtime acceptance directory; required with --run")
    parser.add_argument("--run", action="store_true",
                        help="explicitly enable one TEST_ONLY production capture and MCP acceptance")
    args = parser.parse_args(argv)
    _require(args.preflight_only != args.run,
             "choose_exactly_one_of_--preflight-only_or_--run")
    if args.preflight_only:
        return _preflight_only(args)
    _require(args.output is not None, "--output_is_required_with_--run")
    return _run_live(args)


if __name__ == "__main__":
    raise SystemExit(main())
