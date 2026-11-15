"""TEST_ONLY live acceptance for the N02 country-forces adapter.

The helper has one explicit live guard (``--run``).  It performs one direct
bounded RPM capture for an independent production-capture receipt, then one
MCP active query and one real two-second periodic subscription.  It never
enables the battle producer, sends ``information_tick``, calls a game
function, advances time, saves, reloads, or submits diplomacy.

The direct capture is compared record by record with the Batch 68 offline
RPM/save join.  The MCP reads are checked against an independently built
projection of that reference; the production reader's projection is never
used to construct the expected value.
"""
from __future__ import annotations

import argparse
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

from bridge.diplomacy import ObserverSession
from bridge.information.model import canonical
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from bridge.information import country_forces_memory as _memory
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_peace_overextension_live import _ImmediateClient


GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
DLL_SHA256 = (
    "92fa4ea3b158e2ff42a69bce1cbbf7053b7f3a0ac128b25c9e5b7d1fb4bdc3ce"
)
MANIFEST_SHA256 = (
    "325d2ae561a24b41ad619f9c874be1168c6085d1fd90c998250ae868da05a152"
)
EXPECTED_PID = 42960
EXPECTED_CREATION_FILETIME = 134375854500787403
EXPECTED_SESSION = "42960-1dd6620b1e8b4cb"
EXPECTED_VERSION = "1.37.4"
COUNTRY = "FRA"
FIELDS = ("army_size", "navy_size", "army_composition", "navy_composition")
# Manpower is an existing available N02 route owned by
# NativeCountryStateSource.  This helper validates only the newly queried
# force fields; it must not accidentally downgrade that existing route.
PLANNED_FIELDS = ("sailors", "force_limits")
REFERENCE_DEFAULT = (
    ROOT
    / "work/runtime/information-country-forces-20261027-001"
    / "country-forces-unit-join-001.json"
)
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_LOG_SUFFIX = 2 * 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")

# This mapping is part of the independent expected projection.  It is kept
# here rather than imported from the production adapter so a production
# projection cannot silently become the acceptance oracle.
KIND_NAMES = {
    0: "infantry",
    1: "cavalry",
    2: "native_kind_2",
    3: "heavy_ship",
    4: "light_ship",
    5: "native_kind_5",
    6: "transport",
}
ARMY_KINDS = (0, 1, 2)
NAVY_KINDS = (3, 4, 5, 6)
GAPS = [
    "COMBAT_READY_STATUS_UNREAD",
    "UNIT_TYPE_NAMES_UNREAD",
    "UNOBSERVED_KIND_LABELS_UNRESOLVED",
]


class AcceptanceError(RuntimeError):
    """A bounded identity, source, wire, or lifecycle check failed."""


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


def _native_events_since(path: Path, offset: int) -> dict[str, Any]:
    """Read only a bounded suffix and retain native query-like events."""
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
                name.startswith("native_") or "query" in name
                or "inspection" in name):
            events.append(value)
    return {"offset": offset, "end": size, "bytes": length,
            "native_events": events}


def _reject_native_inspection_or_game_query(suffix: Mapping[str, Any]) -> None:
    """Reject native inspection/query events in this pure-RPM N02 run."""
    events = suffix.get("native_events")
    _require(isinstance(events, list), "native_event_suffix_invalid")
    forbidden: list[str] = []
    for value in events:
        if not isinstance(value, Mapping):
            continue
        name = value.get("event")
        if not isinstance(name, str):
            continue
        lowered = name.lower()
        if ("inspection" in lowered or "game_query" in lowered
                or "gamequery" in lowered
                or (lowered.startswith("native_") and lowered.endswith("_query"))):
            forbidden.append(name)
    _require(not forbidden,
             "native_inspection_or_game_query_event_observed:" + ",".join(forbidden[:8]))


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
            _require(str(actual).lower() == value.lower(),
                     f"installation_{key}_mismatch")
        else:
            _require(actual == value, f"installation_{key}_mismatch")
    _require(identity.get("installation_returncode") == 0,
             "installation_not_successful")
    manifest_path = installation.parent / "build-manifest.json"
    manifest = _read_json(manifest_path)
    _require(isinstance(manifest, dict), "build_manifest_not_object")
    manifest_pin = {"path": str(manifest_path), "sha256": _sha256(manifest_path),
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
    # The helper is intentionally ingest-only from the information service's
    # point of view.  A ready, unpatched status is evidence that no battle
    # producer control was requested; it is not a permission to enable one.
    _require(value.get("state") == "ready", "battle_source_not_ready")
    _require(value.get("code_patch_installed") is False,
             "battle_source_patch_was_enabled")
    _require(value.get("dll_pinned") is False
             and value.get("unwind_registered") is False,
             "battle_source_runtime_resources_present")
    _require(value.get("capture_complete") is False,
             "battle_capture_was_already_active")
    return {
        "path": str(path),
        "sha256": _sha256(path),
        "state": value.get("state"),
        "code_patch_installed": value.get("code_patch_installed"),
        "dll_pinned": value.get("dll_pinned"),
        "unwind_registered": value.get("unwind_registered"),
        "capture_complete": value.get("capture_complete"),
        "publication_stage": value.get("publication_stage"),
    }


def _load_reference(path: Path, installation: Path,
                    identity: Mapping[str, Any], expected_date: int
                    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    value = _read_json(path)
    _require(isinstance(value, dict) and value.get("schema") == 1,
             "reference_schema_invalid")
    _require(value.get("evidence_kind") ==
             "offline join of independently captured RPM and existing checkpoint; no new runtime read",
             "reference_evidence_kind_invalid")
    _require(value.get("unique_save_units") == 60
             and value.get("unique_native_records") == 60
             and value.get("one_to_one") is True,
             "reference_count_contract_invalid")
    pins = value.get("source_pins")
    _require(isinstance(pins, list) and len(pins) == 2,
             "reference_source_pins_invalid")
    pin_by_name: dict[str, dict[str, Any]] = {}
    root = ROOT.resolve()
    for pin in pins:
        _require(isinstance(pin, Mapping), "reference_source_pin_not_object")
        raw_path, expected_sha = pin.get("path"), pin.get("sha256")
        _require(isinstance(raw_path, str) and isinstance(expected_sha, str)
                 and SHA_RE.fullmatch(expected_sha.lower()) is not None,
                 "reference_source_pin_shape_invalid")
        relative = Path(raw_path.replace("\\", "/"))
        resolved = (root / relative).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise AcceptanceError("reference_source_pin_outside_workspace") from exc
        _require(resolved.is_file(), f"reference_source_pin_missing:{resolved}")
        actual_sha = _sha256(resolved)
        _require(actual_sha.lower() == expected_sha.lower(),
                 f"reference_source_pin_sha_mismatch:{resolved}")
        _require(resolved.name not in pin_by_name,
                 "reference_source_pin_duplicate")
        pin_by_name[resolved.name] = {
            "path": str(resolved), "sha256": actual_sha,
            "bytes": resolved.stat().st_size,
        }
    expected_names = {
        "country-forces-checkpoint-reference-001.json",
        "country-forces-raw-rpm-001.json",
    }
    _require(set(pin_by_name) == expected_names,
             "reference_source_pin_file_set_mismatch")
    checkpoint_path = Path(pin_by_name[
        "country-forces-checkpoint-reference-001.json"]["path"])
    raw_path = Path(pin_by_name["country-forces-raw-rpm-001.json"]["path"])
    checkpoint = _read_json(checkpoint_path)
    _require(isinstance(checkpoint, Mapping), "checkpoint_reference_not_object")
    save_identity = checkpoint.get("save_identity")
    _require(isinstance(save_identity, Mapping)
             and save_identity.get("date") == "1456.12.9"
             and save_identity.get("requested_observer") == COUNTRY,
             "checkpoint_reference_identity_mismatch")
    rpm_document = _read_json(raw_path)
    _require(isinstance(rpm_document, Mapping)
             and rpm_document.get("schema") == "information_country_forces_raw_rpm.v1"
             and rpm_document.get("status") == "observed_raw_candidate"
             and rpm_document.get("completed") is True,
             "raw_rpm_receipt_status_invalid")
    target = rpm_document.get("target_build")
    _require(isinstance(target, Mapping)
             and target.get("version") == EXPECTED_VERSION
             and str(target.get("exe_sha256", "")).lower() == GAME_SHA256
             and str(target.get("dll_sha256", "")).lower() == DLL_SHA256,
             "raw_rpm_target_build_identity_mismatch")
    target_installation = target.get("installation")
    _require(isinstance(target_installation, str)
             and (ROOT / target_installation).resolve() == installation.resolve(),
             "raw_rpm_target_installation_mismatch")
    installation_sha = _sha256(installation)
    installation_pin_checks: dict[str, Any] = {}
    for key in ("installation_pin", "installation_pin_after"):
        pin = rpm_document.get(key)
        _require(isinstance(pin, Mapping), f"raw_rpm_{key}_missing")
        _require(Path(str(pin.get("path", ""))).resolve() == installation.resolve()
                 and pin.get("bytes") == installation.stat().st_size
                 and str(pin.get("sha256", "")).lower() == installation_sha,
                 f"raw_rpm_{key}_does_not_match_current_installation")
        installation_pin_checks[key] = {
            "path": str(pin.get("path")), "bytes": pin.get("bytes"),
            "sha256": str(pin.get("sha256")).lower(),
        }
    identity_checks: dict[str, Any] = {}
    for key in ("identity_before", "identity_after"):
        observed = rpm_document.get(key)
        _require(isinstance(observed, Mapping), f"raw_rpm_{key}_missing")
        _require(observed.get("pid") == identity.get("pid")
                 and observed.get("creation_filetime") == identity.get("creation_filetime")
                 and observed.get("session_id") == identity.get("session_id")
                 and observed.get("process_creation_filetime") == identity.get("creation_filetime")
                 and str(observed.get("process_path_sha256", "")).lower() == GAME_SHA256
                 and observed.get("process_path_sha256_matches_expected") is True
                 and observed.get("process_creation_matches_installation") is True
                 and observed.get("binding_verified") is True,
                 f"raw_rpm_{key}_identity_mismatch")
        dll_candidates = observed.get("dll_candidates")
        _require(isinstance(dll_candidates, list) and len(dll_candidates) == 1
                 and str(dll_candidates[0].get("sha256", "")).lower() == DLL_SHA256
                 and dll_candidates[0].get("sha256_matches_expected") is True
                 and dll_candidates[0].get("path_matches_expected") is True,
                 f"raw_rpm_{key}_dll_identity_mismatch")
        identity_checks[key] = {
            "pid": observed.get("pid"),
            "creation_filetime": observed.get("creation_filetime"),
            "session_id": observed.get("session_id"),
            "process_path_sha256": observed.get("process_path_sha256"),
            "dll_sha256": dll_candidates[0].get("sha256"),
        }
    request = rpm_document.get("request")
    _require(isinstance(request, Mapping)
             and request.get("country") == COUNTRY
             and request.get("passes") == 2
             and request.get("no_retry") is True,
             "raw_rpm_request_contract_invalid")
    for key in ("snapshot_before", "snapshot_after"):
        snapshot = rpm_document.get(key)
        _require(isinstance(snapshot, Mapping)
                 and snapshot.get("game_date") == expected_date,
                 f"raw_rpm_{key}_date_mismatch")
        country = snapshot.get("country")
        _require(isinstance(country, Mapping)
                 and country.get("current_country_tag") == COUNTRY,
                 f"raw_rpm_{key}_country_mismatch")
    doublepass = rpm_document.get("doublepass")
    _require(isinstance(doublepass, Mapping)
             and doublepass.get("performed") is True
             and doublepass.get("consistent") is True,
             "raw_rpm_doublepass_invalid")
    access = rpm_document.get("access")
    _require(isinstance(access, Mapping)
             and access.get("native_game_calls") is False
             and access.get("target_memory_writes") is False
             and access.get("mcp_query") is False
             and access.get("control_or_business_dispatch") is False,
             "raw_rpm_access_contract_invalid")
    cleanup = rpm_document.get("cleanup")
    _require(isinstance(cleanup, Mapping)
             and cleanup.get("handle_close") ==
             {"status": "closed", "success": True, "closed": True},
             "raw_rpm_cleanup_invalid")
    rows = value.get("rows")
    _require(isinstance(rows, list) and len(rows) == 60, "reference_rows_count_invalid")
    clean: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for row in rows:
        _require(isinstance(row, Mapping), "reference_row_not_object")
        key = (row.get("id_type"), row.get("id"))
        _require(all(type(v) is int and v > 0 for v in key),
                 "reference_row_identity_invalid")
        _require(key not in seen, "reference_row_identity_duplicate")
        seen.add(key)
        kind = row.get("native_kind")
        strength_raw = row.get("native_strength_raw")
        _require(type(kind) is int and kind in KIND_NAMES,
                 "reference_row_kind_invalid")
        _require(type(strength_raw) is int and 0 <= strength_raw < (1 << 31),
                 "reference_row_strength_invalid")
        _require(row.get("container") ==
                 ("army" if kind in ARMY_KINDS else "navy"),
                 "reference_row_container_invalid")
        clean.append({"id_type": key[0], "id": key[1],
                      "native_kind": kind, "native_strength_raw": strength_raw,
                      "container": row.get("container"),
                      "type": row.get("type")})
    clean.sort(key=lambda row: (row["id_type"], row["id"]))
    audit = {
        "source_pins_verified": True,
        "files": pin_by_name,
        "checkpoint_date": save_identity.get("date"),
        "checkpoint_observer": save_identity.get("requested_observer"),
        "raw_rpm_schema": rpm_document.get("schema"),
        "raw_rpm_status": rpm_document.get("status"),
        "raw_rpm_installation_pins": installation_pin_checks,
        "raw_rpm_identity": identity_checks,
        "raw_rpm_date": expected_date,
        "raw_rpm_target_build": {
            "version": target.get("version"),
            "exe_sha256": target.get("exe_sha256"),
            "dll_sha256": target.get("dll_sha256"),
        },
        "raw_rpm_doublepass_consistent": True,
        "raw_rpm_read_only_flags": True,
    }
    return value, clean, audit


def _expected_fields(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {kind: 0 for kind in KIND_NAMES}
    strengths = {kind: 0 for kind in KIND_NAMES}
    for row in rows:
        counts[row["native_kind"]] += 1
        strengths[row["native_kind"]] += row["native_strength_raw"]

    def base() -> dict[str, Any]:
        return {"status": "known", "scale": 1, "period": "current",
                "basis": "native_country_existing_unit_records",
                "partial": True, "complete": False,
                "scope": "direct_country_existing_unit_records",
                "gaps": list(GAPS)}

    fields: dict[str, Any] = {}
    for family, kinds, count_unit, strength_unit in (
            ("army", ARMY_KINDS, "regiments", "serialized_regiment_strength"),
            ("navy", NAVY_KINDS, "ships", "serialized_ship_strength")):
        composition = []
        for kind in kinds:
            composition.append({
                "category": KIND_NAMES[kind],
                "native_kind": kind,
                "category_name_status": "unknown" if kind in (2, 5) else "known",
                "count": counts[kind],
                "count_unit": count_unit,
                "strength": {"raw": strengths[kind], "scale": 1000,
                              "unit": strength_unit},
            })
        size = base()
        size.update(
            value=sum(counts[kind] for kind in kinds),
            unit=count_unit,
            strength={"raw": sum(strengths[kind] for kind in kinds),
                      "scale": 1000, "unit": strength_unit},
        )
        composition_value = base()
        composition_value.update(value=composition, unit="unit_category_counts")
        fields[family + "_size"] = size
        fields[family + "_composition"] = composition_value
    return fields


def _capture_rows(capture: Mapping[str, Any]) -> list[dict[str, int]]:
    before = capture.get("before")
    record = before.get("record") if isinstance(before, Mapping) else None
    rows = record.get("records") if isinstance(record, Mapping) else None
    _require(isinstance(rows, list) and len(rows) <= 1024,
             "production_capture_records_invalid")
    result: list[dict[str, int]] = []
    for row in rows:
        _require(isinstance(row, Mapping), "production_capture_row_not_object")
        values = {key: row.get(key) for key in
                  ("id_type", "id", "type_kind", "strength_raw")}
        _require(type(values["id_type"]) is int and values["id_type"] > 0
                 and type(values["id"]) is int and values["id"] > 0,
                 "production_capture_identity_invalid")
        _require(type(values["type_kind"]) is int
                 and values["type_kind"] in KIND_NAMES,
                 "production_capture_kind_invalid")
        _require(type(values["strength_raw"]) is int
                 and 0 <= values["strength_raw"] < (1 << 31),
                 "production_capture_strength_invalid")
        result.append({"id_type": values["id_type"], "id": values["id"],
                       "type_kind": values["type_kind"],
                       "strength_raw": values["strength_raw"]})
    result.sort(key=lambda row: (row["id_type"], row["id"]))
    return result


def _compare_capture(reference_rows: list[dict[str, Any]],
                     capture: Mapping[str, Any]) -> dict[str, Any]:
    actual = _capture_rows(capture)
    expected = [{"id_type": row["id_type"], "id": row["id"],
                "type_kind": row["native_kind"],
                "strength_raw": row["native_strength_raw"]}
               for row in reference_rows]
    _require(actual == expected, "production_capture_rows_do_not_match_reference")
    return {"reference_count": len(expected), "capture_count": len(actual),
            "sort_key": ["id_type", "id"],
            "compared": ["id_type", "id", "type_kind", "strength_raw"],
            "addresses_compared": False, "exact": True}


def _find_capture_hashes(value: Any) -> list[str]:
    found: list[str] = []
    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                if key == "capture_report_sha256" and isinstance(child, str):
                    if SHA_RE.fullmatch(child.lower()):
                        found.append(child.lower())
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(value)
    return sorted(set(found))


def _check_result(value: Mapping[str, Any], query: Mapping[str, Any],
                  expected_fields: Mapping[str, Any], identity: Mapping[str, Any],
                  expected_date: int, *, subscription_id: str | None = None) -> dict[str, Any]:
    _require(value.get("status") == "partial", "n02_result_status_not_partial")
    _require(value.get("complete") is False, "n02_result_claimed_complete")
    delivery = value.get("delivery")
    _require(isinstance(delivery, Mapping)
             and delivery.get("status") == "delivered",
             "n02_result_not_delivered")
    _require(delivery.get("llm_read") == "unknown", "n02_llm_read_claimed")
    context = value.get("context")
    _require(isinstance(context, Mapping), "n02_result_context_missing")
    _require(context.get("session_id") == identity.get("session_id")
             and context.get("observer") == COUNTRY
             and context.get("game_version") == EXPECTED_VERSION
             and context.get("game_date") == expected_date,
             "n02_result_context_mismatch")
    items = value.get("items")
    _require(isinstance(items, list) and len(items) == 1,
             "n02_result_item_count_invalid")
    item = items[0]
    _require(isinstance(item, Mapping), "n02_result_item_invalid")
    echoed = item.get("query")
    # InformationService._queries/CompositeSource.validate_query preserve the
    # caller's field order while adding the explicit empty parameters object;
    # compare that public contract, rather than assuming an implementation
    # detail such as an internal route order.
    _require(isinstance(echoed, Mapping)
             and echoed.get("topic") == query["topic"]
             and echoed.get("object") == query["object"]
             and echoed.get("fields") == query["fields"]
             and echoed.get("parameters", {}) == query["parameters"],
             "n02_query_echo_mismatch")
    _require(item.get("objects") == [query["object"]],
             "n02_result_object_mismatch")
    fields = item.get("fields")
    _require(isinstance(fields, Mapping)
             and set(fields) == set(FIELDS), "n02_result_fields_mismatch")
    for field in FIELDS:
        actual = fields[field]
        _require(isinstance(actual, Mapping)
                 and actual.get("status") == "known",
                 f"n02_{field}_not_known")
        _require(dict(actual) == dict(expected_fields[field]),
                 f"n02_{field}_projection_mismatch")
    provenance_hashes = _find_capture_hashes(item)
    _require(provenance_hashes, "n02_capture_report_sha_missing")
    if subscription_id is not None:
        _require(value.get("subscription_id") == subscription_id,
                 "periodic_subscription_identity_mismatch")
    source = item.get("source")
    return {
        "result_id": value.get("result_id"),
        "subscription_id": value.get("subscription_id"),
        "capture_report_sha256": provenance_hashes,
        "delivery": {"status": delivery.get("status"),
                      "adapter": delivery.get("adapter"),
                      "llm_read": delivery.get("llm_read")},
        "source_provenance_present": isinstance(source, Mapping),
        "fields_exact": True,
        "partial": value.get("complete") is False,
    }


def _validate_discovery(value: Mapping[str, Any]) -> dict[str, Any]:
    topics = value.get("topics")
    _require(isinstance(topics, list), "discovery_topics_missing")
    topic = next((row for row in topics
                  if isinstance(row, Mapping) and row.get("topic_id") == "N02"), None)
    _require(isinstance(topic, Mapping), "n02_discovery_missing")
    _require(topic.get("status") == "available", "n02_topic_not_available")
    _require(topic.get("source") == "CompositeSource",
             "n02_source_identity_mismatch")
    adapter_sources = topic.get("adapter_sources")
    _require(isinstance(adapter_sources, list)
             and "NativeCountryForcesSource" in adapter_sources
             and "NativeCountryStateSource" in adapter_sources,
             "n02_adapter_sources_missing")
    fields = topic.get("fields")
    _require(isinstance(fields, Mapping), "n02_discovery_fields_missing")
    for field in FIELDS:
        _require(isinstance(fields.get(field), Mapping)
                 and fields[field].get("coverage") == "partial",
                 f"n02_{field}_coverage_not_partial")
    _require(isinstance(fields.get("manpower"), Mapping)
             and fields["manpower"].get("coverage") == "available",
             "n02_manpower_was_downgraded")
    for field in PLANNED_FIELDS:
        _require(isinstance(fields.get(field), Mapping)
                 and fields[field].get("coverage") == "planned",
                 f"n02_{field}_was_not_planned")
    _require("query" in topic.get("triggers", [])
             and "periodic" in topic.get("triggers", []),
             "n02_query_periodic_trigger_missing")
    return {"topic_id": topic.get("topic_id"), "source": topic.get("source"),
            "adapter_sources": list(adapter_sources),
            "status": topic.get("status"),
            "partial_fields": list(FIELDS),
            "planned_fields": list(PLANNED_FIELDS),
            "triggers": list(topic.get("triggers", []))}


def run(args: argparse.Namespace) -> int:
    _require(args.run is True, "--run is required for live acceptance")
    installation = args.installation.resolve(strict=True)
    reference = args.reference.resolve(strict=True)
    output = args.output.resolve()
    _require(not output.exists(), f"refusing_to_overwrite_output:{output}")
    runtime_root = (ROOT / "work/runtime").resolve()
    try:
        output.relative_to(runtime_root)
    except ValueError as exc:
        raise AcceptanceError("output_must_be_under_work_runtime") from exc
    output.mkdir(parents=True, exist_ok=False)

    report: dict[str, Any] = {
        "schema": "information.country_forces.live_acceptance.v1",
        "status": "running",
        "mode": "test-only-live-read",
        "read_only": True,
        "run_guard": "--run",
        "identity_pins": {
            "pid": EXPECTED_PID,
            "creation_filetime": EXPECTED_CREATION_FILETIME,
            "session_id": EXPECTED_SESSION,
            "game_sha256": GAME_SHA256,
            "dll_sha256": DLL_SHA256,
            "manifest_sha256": MANIFEST_SHA256,
            "game_version": EXPECTED_VERSION,
            "game_date": args.expected_date,
        },
        "inputs": {"installation": str(installation),
                   "reference": str(reference), "output": str(output)},
        "checks": {},
        "capture_modes": {
            "production_capture": "one direct country_forces_memory.capture pure RPM; independent of MCP active/periodic",
            "mcp_active": "NativeCountryForcesSource through service",
            "mcp_periodic": "real two-second scheduler through service",
        },
        "business_dispatch": False,
        "native_game_calls": False,
        "information_tick_sent": False,
        "date_advance_save_reload": False,
        "computer_use": False,
        "llm_read": "unknown",
        "outbox_delivered_is_not_llm_read": True,
        "limitations": [
            "N02 remains partial: existing unit records do not prove combat-ready/deployed status.",
            "Unit labels for native kinds 2 and 5 remain unresolved; the reference has no kind-2 or kind-5 sample.",
            "The independent join does not prove that strength raw is physical men or that navy strength is ship count.",
            "A successful MCP response/outbox receipt records delivery, not that an LLM read the result.",
        ],
    }
    client: _ImmediateClient | None = None
    subscription: dict[str, Any] | None = None
    cancel_started = False
    session: ObserverSession | None = None
    before_control: dict[str, Any] | None = None
    log_path = installation.parent / "control-probe.jsonl"
    initial_log_offset: int | None = None
    identity: dict[str, Any] | None = None
    expected_rows: list[dict[str, Any]] | None = None
    expected_fields: dict[str, Any] | None = None
    namespace = "n02-country-forces-" + hashlib.sha256(str(output).encode()).hexdigest()[:16]

    def save_control(label: str) -> dict[str, Any]:
        return control_snapshot(EXPECTED_PID, output / f"{label}-control.json")

    def call(label: str, name: str, **arguments: Any) -> Any:
        definition = next(tool for tool in TOOL_DEFINITIONS if tool["name"] == name)
        validate_schema(arguments, definition["inputSchema"], "arguments")
        _write_exclusive(output / f"{label}-request.json",
                         {"name": name, "arguments": arguments})
        offset = log_path.stat().st_size
        try:
            value = client.call(name, **arguments)
        except Exception as exc:
            _write_exclusive(output / f"{label}-failure.json",
                             {"type": type(exc).__name__, "message": str(exc)})
            try:
                suffix = _native_events_since(log_path, offset)
                _write_exclusive(output / f"{label}-native-events.json", suffix)
                _reject_native_inspection_or_game_query(suffix)
            except Exception as suffix_error:
                _write_exclusive(output / f"{label}-native-events-failure.json",
                                 {"type": type(suffix_error).__name__,
                                  "message": str(suffix_error)})
            raise
        # Persist a successful raw response before any semantic assertion.
        _write_exclusive(output / f"{label}-response.json", value)
        suffix = _native_events_since(log_path, offset)
        _write_exclusive(output / f"{label}-native-events.json", suffix)
        _reject_native_inspection_or_game_query(suffix)
        return value

    try:
        identity, manifest, manifest_pin = _load_identity(installation)
        report["identity"] = identity
        report["build_manifest"] = manifest_pin
        _write_exclusive(output / "installation-identity.json", {
            "identity": identity, "manifest": manifest,
            "manifest_pin": manifest_pin,
        })
        battle_status = _load_battle_status(installation)
        report["battle_status"] = battle_status
        _write_exclusive(output / "battle-status.json", battle_status)
        report["checks"]["battle_ready_zero_unpatched_not_managed"] = True

        reference_doc, expected_rows, reference_audit = _load_reference(
            reference, installation, identity, args.expected_date)
        expected_fields = _expected_fields(expected_rows)
        report["reference"] = {
            "sha256": _sha256(reference),
            "schema": reference_doc.get("schema"),
            "unique_rows": len(expected_rows),
            "source_pins": reference_doc.get("source_pins"),
            "independent_expected_kind_counts": {
                str(kind): sum(row["native_kind"] == kind for row in expected_rows)
                for kind in KIND_NAMES
            },
            "validation": reference_audit,
        }
        _write_exclusive(output / "independent-expected-projection.json",
                         {"basis": "independent reference rows and explicit kind/strength sums",
                          "fields": expected_fields,
                          "rows": expected_rows})

        before_control = save_control("before")
        _require((before_control.get("player_slot"), before_control.get("date_raw"),
                  before_control.get("speed"), before_control.get("paused_flag"))
                 == (189, args.expected_date, 0, 1),
                 "before_control_not_paused_por")
        report["checks"]["before_control_paused_por_date"] = True

        session = ObserverSession(installation, game_exe())
        health = session.health()
        _write_exclusive(output / "before-health.json", health)
        _require(health.get("status") == "ready"
                 and health.get("date_raw") == args.expected_date,
                 "before_health_not_ready_same_date")
        report["checks"]["before_health_ready_same_date"] = True

        # The direct production capture is exactly one helper-owned capture.
        capture = _memory.capture(installation, country=COUNTRY)
        _write_exclusive(output / "production-capture.json", capture)
        capture_context = {
            "session_id": identity["session_id"],
            "game_sha256": GAME_SHA256,
            "observer": COUNTRY,
            "game_version": EXPECTED_VERSION,
            "game_date": args.expected_date,
        }
        _require(_memory.validate_capture(
            capture, capture_context, EXPECTED_CREATION_FILETIME, COUNTRY) is True,
            "production_capture_validate_failed")
        report["production_capture_report_sha256"] = _sha256_value(capture)
        report["production_capture"] = _compare_capture(expected_rows, capture)
        report["checks"].update({
            "production_capture_validated": True,
            "production_capture_exact_reference_rows": True,
            "production_capture_no_native_game_calls": capture.get("access", {}).get("native_game_calls") is False,
            "production_capture_no_writes_or_business_dispatch": (
                capture.get("access", {}).get("target_memory_writes") is False
                and capture.get("access", {}).get("control_or_business_dispatch") is False),
        })
        _require(report["checks"]["production_capture_no_native_game_calls"],
                 "production_capture_native_game_call_observed")
        _require(report["checks"]["production_capture_no_writes_or_business_dispatch"],
                 "production_capture_write_or_dispatch_observed")

        _require(log_path.is_file(), "observer_log_missing_before_mcp")
        initial_log_offset = log_path.stat().st_size
        client = _ImmediateClient(installation, output, tick=2)

        discovery = call("01-discover", "information_discover")
        report["discovery"] = _validate_discovery(discovery)
        report["checks"]["n02_discovery_partial_and_remaining_planned"] = True

        query = {"topic": "N02", "object": {"type": "country", "country": COUNTRY},
                 "fields": list(FIELDS), "parameters": {}}
        active = call("02-active-query", "information_query",
                      request_id=namespace + "-active-query", queries=[query])
        active_summary = _check_result(active, query, expected_fields, identity,
                                       args.expected_date)
        _write_exclusive(output / "active-comparison.json", active_summary)
        report["active"] = active_summary
        report["checks"]["active_query_exact_independent_projection"] = True

        configured = call(
            "03-report-create", "information_manage_report",
            request_id=namespace + "-report-create", operation="create",
            config={"name": "N02 country forces live acceptance",
                    "queries": [query], "detail": "raw"},
        )
        report_value = configured.get("report") if isinstance(configured, Mapping) else None
        _require(isinstance(report_value, Mapping)
                 and isinstance(report_value.get("id"), str),
                 "report_id_missing")
        report["report_id"] = report_value["id"]

        created = call(
            "04-periodic-create", "information_manage_subscription",
            request_id=namespace + "-periodic-create", operation="create",
            config={"name": "N02 country forces two-second periodic",
                    "kind": "periodic", "report_id": report_value["id"],
                    "enabled": True,
                    "schedule": {"basis": "real", "every": 2,
                                 "unit": "seconds", "missed": "coalesce"}},
        )
        subscription = created.get("subscription") if isinstance(created, Mapping) else None
        _require(isinstance(subscription, Mapping)
                 and isinstance(subscription.get("id"), str)
                 and subscription.get("state") == "active",
                 "periodic_subscription_not_active")
        subscription = dict(subscription)
        report["subscription"] = {
            "id": subscription["id"], "version": subscription.get("version"),
            "state": subscription.get("state"),
        }

        periodic_value: Mapping[str, Any] | None = None
        periodic_summary: dict[str, Any] | None = None
        attempts: list[dict[str, Any]] = []
        # Polling list_results is the scheduler observation path.  It is
        # deliberately bounded and never invokes information_tick.
        for index in range(30):
            time.sleep(0.5)
            listed = call(f"05-results-{index + 1:02d}",
                          "information_list_results", limit=100)
            results = listed.get("results") if isinstance(listed, Mapping) else None
            _require(isinstance(results, list), "periodic_results_missing")
            candidate = next((row for row in results
                              if isinstance(row, Mapping)
                              and row.get("subscription_id") == subscription["id"]), None)
            attempts.append({"attempt": index + 1,
                             "result_count": len(results),
                             "found": candidate is not None})
            if candidate is not None:
                periodic_value = candidate
                periodic_summary = _check_result(
                    candidate, query, expected_fields, identity, args.expected_date,
                    subscription_id=subscription["id"])
                _write_exclusive(output / "periodic-first-result.json", candidate)
                _write_exclusive(output / "periodic-comparison.json", periodic_summary)
                break
        _require(periodic_value is not None and periodic_summary is not None,
                 "periodic_first_real_result_missing")
        report["periodic"] = dict(periodic_summary, attempts=attempts)
        report["checks"].update({
            "one_real_two_second_periodic_first_result": True,
            "periodic_exact_independent_projection": True,
            "active_periodic_field_values_equal": (
                active.get("items", [{}])[0].get("fields")
                == periodic_value.get("items", [{}])[0].get("fields")),
        })
        _require(report["checks"]["active_periodic_field_values_equal"],
                 "active_periodic_fields_differ")

        # Set the latch before dispatch.  A failed cancel is never retried by
        # this helper or by cleanup, preserving the no-repeat policy.
        cancel_started = True
        cancelled = call(
            "06-cancel", "information_manage_subscription",
            request_id=namespace + "-cancel", operation="cancel",
            subscription_id=subscription["id"],
            expected_version=subscription["version"],
        )
        cancelled_subscription = cancelled.get("subscription") if isinstance(cancelled, Mapping) else None
        _require(isinstance(cancelled_subscription, Mapping)
                 and cancelled_subscription.get("state") == "cancelled",
                 "subscription_not_cancelled")
        subscription = dict(cancelled_subscription)

        states = call("07-subscriptions", "information_manage_subscription",
                      request_id=namespace + "-subscriptions", operation="list")
        _require(isinstance(states.get("subscriptions"), list)
                 and all(isinstance(row, Mapping)
                         and row.get("state") != "active"
                         for row in states["subscriptions"]),
                 "active_subscription_remains")
        status = call("08-status", "information_status")
        status_rows = status.get("subscriptions") if isinstance(status, Mapping) else None
        _require(isinstance(status_rows, list)
                 and all(isinstance(row, Mapping)
                         and isinstance(row.get("subscription"), Mapping)
                         and row["subscription"].get("state") != "active"
                         and row.get("runtime", {}).get("state") != "active"
                         for row in status_rows),
                 "status_reports_active_subscription")
        report["checks"]["cancelled_once_no_active_subscription"] = True
        report["status"] = "passed"
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__,
                                                "message": str(exc)})
    finally:
        if (subscription is not None and subscription.get("state") == "active"
                and client is not None and not cancel_started):
            try:
                cancel_started = True
                cleanup = call(
                    "cleanup-cancel", "information_manage_subscription",
                    request_id=namespace + "-cleanup-cancel", operation="cancel",
                    subscription_id=subscription["id"],
                    expected_version=subscription["version"],
                )
                subscription = dict(cleanup.get("subscription", subscription))
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
                health = session.health()
                _write_exclusive(output / "after-health.json", health)
                report["checks"]["after_health_ready_same_date"] = (
                    health.get("status") == "ready"
                    and health.get("date_raw") == args.expected_date)
                if not report["checks"]["after_health_ready_same_date"]:
                    report["status"] = "failed"
            except Exception as exc:
                report["after_health_error"] = {"type": type(exc).__name__,
                                                 "message": str(exc)}
                report["status"] = "failed"
            try:
                after = save_control("after")
                preserved = all(before_control.get(key) == after.get(key)
                                for key in ("date_raw", "paused_flag", "speed", "player_slot"))
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
                _write_exclusive(output / "native-events.json", suffix)
                _reject_native_inspection_or_game_query(suffix)
                report["checks"]["native_log_suffix_bounded"] = True
                report["checks"]["no_native_inspection_or_game_query_events"] = True
            except Exception as exc:
                report["native_events_error"] = {"type": type(exc).__name__,
                                                 "message": str(exc)}
                report["status"] = "failed"
        _write_exclusive(output / "report.json", report)
    print(json.dumps({key: report.get(key) for key in
                      ("status", "checks", "error", "server_exit_code")},
                     ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True,
                        help="current verified observer installation.json")
    parser.add_argument("--reference", type=Path, default=REFERENCE_DEFAULT,
                        help="Batch 68 independent country-forces join JSON")
    parser.add_argument("--output", type=Path, required=True,
                        help="new, non-existing work/runtime acceptance directory")
    parser.add_argument("--expected-date", type=int, default=56562768,
                        help="expected paused game date raw value")
    parser.add_argument("--run", action="store_true",
                        help="required explicit guard before any live process/RPM/MCP action")
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
