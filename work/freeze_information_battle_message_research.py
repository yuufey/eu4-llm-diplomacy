"""Freeze bounded static evidence for the battle message research batch.

The freeze consumes five completed fixed-build read-only REA dossiers, the
bounded ordinary PE vtable window, and the separately generated static message
lifetime ledger.  It never queries REA, starts a game, invokes native code, or
promotes a callback/lifetime inference into a runtime contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-message-20261025-001"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_SIZE = 38_463_016
IMAGE_BASE = 0x140000000
EXPECTED_ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
EXPECTED_MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
EXPECTED_DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
EXPECTED_PRESET = "eu4-persistent-default-analysis-v1"
EXPECTED_VTABLE_PATH = "work/runtime/information-battle-message-20261025-001/message-vtable-window-001.json"
EXPECTED_VTABLE_SHA256 = "6adf74e12e95d4721cb54bb012433bc2c7e55f3fb65d5fdf06330a082ca5c596"
EXPECTED_VTABLE_SCRIPT_PATH = "work/probe_information_message_vtable.py"
EXPECTED_VTABLE_SCRIPT_SHA256 = "fccc7ef747b79df79765b6d5e69aecc2631ce57237409f4e51f688e19836ade6"
EXPECTED_LIFETIME_LEDGER_SHA256 = "1affeab5db5f76f0a3350a71596053ec3e0f1b72c1d3394e1e270c63b8fc777f"
EXPECTED_LIFETIME_SCRIPT_PATH = "work/probe_information_battle_message_lifetime.py"
EXPECTED_LIFETIME_SCRIPT_SHA256 = "663749c1d55f901999a9a62c5f3424b86ed58da20e0ce07a6b240e6c3ac4cd59"
EXPECTED_LIFETIME_IMPORT_PATH = "work/probe_information_battle_side_identity.py"
EXPECTED_LIFETIME_IMPORT_SHA256 = "69ce71cca8c6bced3fe3c3c7d1c0dbe9845bb348a9d03c56425e8b89a7301e64"
EXPECTED_ALIAS_SOURCE_PINS = (
    {
        "path": "work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/selected-evidence-001.json",
        "bytes": 109103,
        "sha256": "82455e0f1f9fe27bc3dba2e3bea176743ce21d89b076f5e789a8b7f5cef83242",
    },
    {
        "path": "work/runtime/information-battles-20261025-001/rea-message-dispatch-001/selected-evidence-001.json",
        "bytes": 124699,
        "sha256": "ca5bf66fa2682e6e066d8ee75d6b5e56a325cbd67654c25b9a6d51509a576d6b",
    },
)
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


EVIDENCE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "message_instance",
        "directory": "rea-message-instance-001",
        "expected_id": "ev_3d93e7a0b9c66ea6a4fc361d80868c62dc546c73c0fa1f8b963ea30c47ba0b73",
        "expected_procedure": "0x1408d44a0",
        "expected_rva": "0x8d44a0",
        "body": {
            "ranges": [("0x1408d44a0", "0x1408d4658")],
            "total_bytes": 441,
            "span_bytes": 441,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
    {
        "name": "result_delivery",
        "directory": "rea-result-delivery-001",
        "expected_id": "ev_3e8d5882cbd806cf067d34b97665b40eaecb95cdf25935fca5d923d1ebdadbf9",
        "expected_procedure": "0x140244630",
        "expected_rva": "0x244630",
        "body": {
            "ranges": [("0x140244630", "0x1402446ed")],
            "total_bytes": 190,
            "span_bytes": 190,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
    {
        "name": "message_move",
        "directory": "rea-message-move-001",
        "expected_id": "ev_4d63427b63ccf62f291119bc8a8fe5dfd4d152de9182151f454dce7750fb5aa7",
        "expected_procedure": "0x1401af380",
        "expected_rva": "0x1af380",
        "body": {
            "ranges": [("0x1401af380", "0x1401af45a")],
            "total_bytes": 219,
            "span_bytes": 219,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
    {
        "name": "message_consumer",
        "directory": "rea-message-consumer-001",
        "expected_id": "ev_7c83800baf700500a9000917e68dbbc53387cb49d61a9f8ba977378feb2801d1",
        "expected_procedure": "0x1408c05f0",
        "expected_rva": "0x8c05f0",
        "body": {
            "ranges": [
                ("0x1408c05f0", "0x1408c1074"),
                ("0x1408c1076", "0x1408c107a"),
                ("0x1408c107c", "0x1408c1080"),
                ("0x1408c1082", "0x1408c1086"),
            ],
            "total_bytes": 2708,
            "span_bytes": 2711,
            "non_contiguous": True,
            "contains_entry": True,
        },
    },
    {
        "name": "message_logtext",
        "directory": "rea-message-logtext-001",
        "expected_id": "ev_a59809c0f69256c01009ad31b139ed149c94fd9fbb6a9a3e6e202d1c10a4d34f",
        "expected_procedure": "0x1408d4660",
        "expected_rva": "0x8d4660",
        "body": {
            "ranges": [
                ("0x1408d4660", "0x1408d4afc"),
                ("0x1408d4afe", "0x1408d4b02"),
                ("0x1408d4b04", "0x1408d4b08"),
                ("0x1408d4b0a", "0x1408d4b0e"),
                ("0x1408d4b10", "0x1408d4b14"),
                ("0x1408d4b16", "0x1408d4b1a"),
            ],
            "total_bytes": 1206,
            "span_bytes": 1211,
            "non_contiguous": True,
            "contains_entry": True,
        },
    },
    {
        "name": "message_presenter",
        "directory": "rea-message-presenter-001",
        "expected_id": "ev_6ff807ae2f2177c75bbbacd5f0ba6dff3417221a2d086c677dbb49cc19077ae2",
        "expected_procedure": "0x1408c1270",
        "expected_rva": "0x8c1270",
        "body": {
            "ranges": [("0x1408c1270", "0x1408c1941")],
            "total_bytes": 1746,
            "span_bytes": 1746,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
    {
        "name": "message_popup_constructor",
        "directory": "rea-popup-instance-001",
        "expected_id": "ev_e1e4b9eda31a62e4c07fa1dfe03224c3a795713f4c2d80283485ade03f433cae",
        "expected_procedure": "0x1408c1dc0",
        "expected_rva": "0x8c1dc0",
        "body": {
            "ranges": [("0x1408c1dc0", "0x1408c20dd")],
            "total_bytes": 798,
            "span_bytes": 798,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"JSON input exceeds bound: {path} ({size} > {max_bytes})")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value, raw


def _body_descriptor(procedure: dict[str, Any], expected: dict[str, Any], path: Path) -> dict[str, Any]:
    body = procedure.get("body")
    if not isinstance(body, dict):
        raise ValueError(f"REA body missing: {path}")
    ranges = body.get("ranges")
    if not isinstance(ranges, list) or len(ranges) != len(expected["ranges"]):
        raise ValueError(f"REA body range count changed: {path}")
    converted: list[dict[str, Any]] = []
    total = 0
    for item, (expected_start, expected_end) in zip(ranges, expected["ranges"]):
        if not isinstance(item, dict) or item.get("start") != expected_start or item.get("end") != expected_end:
            raise ValueError(f"REA body range changed: {path}")
        start = int(item["start"], 16)
        end = int(item["end"], 16)
        if end < start:
            raise ValueError(f"REA body range reversed: {path}")
        length = end - start + 1
        total += length
        converted.append(
            {
                "start_va": hex(start),
                "end_va_inclusive": hex(end),
                "start_rva": hex(start - IMAGE_BASE),
                "end_rva_inclusive": hex(end - IMAGE_BASE),
                "bytes_inclusive": length,
            }
        )
    for key in ("total_bytes", "span_bytes", "non_contiguous", "contains_entry"):
        if body.get(key) != expected[key]:
            raise ValueError(f"REA body {key} changed: {path}")
    if total != expected["total_bytes"]:
        raise ValueError(f"REA body inclusive total changed: {path}")
    return {
        "ranges_inclusive": converted,
        "total_bytes": body["total_bytes"],
        "span_bytes": body["span_bytes"],
        "non_contiguous": body["non_contiguous"],
        "contains_entry": body["contains_entry"],
        "provenance": body.get("provenance"),
    }


def _validate_shared_params(
    request: dict[str, Any],
    run: dict[str, Any],
    profile_params: dict[str, Any],
    path: Path,
    shared: dict[str, Any] | None,
) -> dict[str, Any]:
    request_keys = (
        "target_sha256",
        "cache",
        "preset",
        "adapter_sha256",
        "completed_manifest_sha256",
        "completed_database_sha256",
        "query_reanalysis",
        "java_heap",
        "process_memory_limit_bytes",
        "timeout_seconds",
    )
    for key in request_keys:
        if request.get(key) != run.get(key):
            raise ValueError(f"request/run parameter mismatch {key}: {path.parent}")
    expected_request = {
        "target_sha256": EXPECTED_EXE_SHA256,
        "preset": EXPECTED_PRESET,
        "adapter_sha256": EXPECTED_ADAPTER_SHA256,
        "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": 1024 * 1024 * 1024,
    }
    for key, expected in expected_request.items():
        if request.get(key) != expected:
            raise ValueError(f"REA request {key} changed: {path.parent}")
    if not isinstance(request.get("cache"), str) or not request["cache"]:
        raise ValueError(f"REA cache path missing: {path.parent}")
    expected_profile = {
        "analyzer_preset": EXPECTED_PRESET,
        "local_adapter_sha256": EXPECTED_ADAPTER_SHA256,
        "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        "query_reanalysis": False,
        "database_mutation": "read-only-no-save",
        "import_mode": "persistent-completed-project-read-only",
    }
    for key, expected in expected_profile.items():
        if profile_params.get(key) != expected:
            raise ValueError(f"REA profile {key} changed: {path}")
    current = {
        "cache": request["cache"],
        "preset": request["preset"],
        "adapter_sha256": request["adapter_sha256"],
        "completed_manifest_sha256": request["completed_manifest_sha256"],
        "completed_database_sha256": request["completed_database_sha256"],
    }
    if shared is not None and current != shared:
        raise ValueError(f"REA shared cache/profile pins changed: {path.parent}")
    return current


def _evidence_descriptor(spec: dict[str, Any], shared: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    directory = STAGE / spec["directory"]
    evidence_path = directory / "evidence.json"
    request_path = directory / "request.json"
    run_path = directory / "run.json"
    evidence, evidence_raw = _load_json(evidence_path, max_bytes=MAX_EVIDENCE_BYTES)
    request, request_raw = _load_json(request_path)
    run, run_raw = _load_json(run_path)
    if evidence.get("evidence_id") != spec["expected_id"]:
        raise ValueError(f"Evidence ID changed: {evidence_path}")
    target_sha = evidence.get("subject", {}).get("digest", {}).get("sha256")
    if target_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"Evidence target SHA changed: {evidence_path}")
    raw_result = evidence.get("raw_result")
    normalized_result = evidence.get("normalized_result")
    if not isinstance(raw_result, dict) or not isinstance(raw_result.get("value"), dict) or not isinstance(normalized_result, dict):
        raise ValueError(f"REA raw/normalized result missing: {evidence_path}")
    raw_value = raw_result["value"]
    if raw_value != normalized_result:
        raise ValueError(f"REA raw/normalized result mismatch: {evidence_path}")
    procedure = raw_value.get("procedure")
    if not isinstance(procedure, dict) or procedure.get("address") != spec["expected_procedure"]:
        raise ValueError(f"REA procedure changed: {evidence_path}")
    if request.get("node") != spec["expected_rva"] or request.get("procedure") != spec["expected_procedure"]:
        raise ValueError(f"REA request address changed: {request_path}")
    if run.get("node") != spec["expected_rva"] or run.get("procedure") != spec["expected_procedure"]:
        raise ValueError(f"REA run address changed: {run_path}")
    if run.get("exit_code") != 0 or run.get("reason") != "completed" or run.get("database_unchanged") is not True:
        raise ValueError(f"REA run did not complete read-only: {run_path}")
    processes = run.get("processes")
    if (
        not isinstance(processes, list)
        or not processes
        or any(not isinstance(item, dict) for item in processes)
        or any(item.get("still_running_same_process") is not False for item in processes)
        or any(item.get("peak_committed_bytes", 2**31) >= 1024 * 1024 * 1024 for item in processes)
    ):
        raise ValueError(f"REA process closure/memory guard failed: {run_path}")
    profile = evidence.get("analysis_profile")
    if not isinstance(profile, dict) or not isinstance(profile.get("parameters"), dict):
        raise ValueError(f"REA profile missing: {evidence_path}")
    provider = profile.get("provider")
    if not isinstance(provider, dict) or provider.get("id") != "ghidra" or provider.get("version") != "12.1.4":
        raise ValueError(f"REA provider changed: {evidence_path}")
    shared = _validate_shared_params(request, run, profile["parameters"], evidence_path, shared)
    if not any("-readOnly" in str(item) and "-noanalysis" in str(item) for item in evidence.get("limitations", [])):
        raise ValueError(f"REA readOnly/noanalysis limitation missing: {evidence_path}")
    body = _body_descriptor(procedure, spec["body"], evidence_path)
    procedure_va = int(procedure["address"], 16)
    descriptor = {
        "name": spec["name"],
        "evidence": {
            "path": _relative(evidence_path),
            "bytes": len(evidence_raw),
            "sha256": _sha256_file(evidence_path),
            "evidence_id": evidence["evidence_id"],
            "target_exe_sha256": target_sha,
            "raw_normalized_equal": True,
            "raw_value_canonical_sha256": _canonical_sha(raw_value),
            "normalized_value_canonical_sha256": _canonical_sha(normalized_result),
            "authority": "shipped-artifact-static-analysis_only",
        },
        "procedure": {
            "name": procedure.get("name"),
            "address_va": hex(procedure_va),
            "rva": hex(procedure_va - IMAGE_BASE),
            "body": body,
        },
        "request": {
            "path": _relative(request_path),
            "bytes": len(request_raw),
            "sha256": _sha256_file(request_path),
            "node": request.get("node"),
            "procedure": request.get("procedure"),
            "cache": request.get("cache"),
            "preset": request.get("preset"),
            "adapter_sha256": request.get("adapter_sha256"),
            "completed_manifest_sha256": request.get("completed_manifest_sha256"),
            "completed_database_sha256": request.get("completed_database_sha256"),
            "query_reanalysis": request.get("query_reanalysis"),
            "java_heap": request.get("java_heap"),
            "process_memory_limit_bytes": request.get("process_memory_limit_bytes"),
            "timeout_seconds": request.get("timeout_seconds"),
        },
        "run": {
            "path": _relative(run_path),
            "bytes": len(run_raw),
            "sha256": _sha256_file(run_path),
            "exit_code": run.get("exit_code"),
            "reason": run.get("reason"),
            "elapsed_seconds": run.get("elapsed_seconds"),
            "database_unchanged": run.get("database_unchanged"),
            "processes": run.get("processes"),
        },
        "profile": {
            "digest": profile.get("digest"),
            "provider": provider,
            "analyzer_preset": profile["parameters"].get("analyzer_preset"),
            "local_adapter_sha256": profile["parameters"].get("local_adapter_sha256"),
            "completed_manifest_sha256": profile["parameters"].get("completed_manifest_sha256"),
            "completed_database_sha256": profile["parameters"].get("completed_database_sha256"),
            "query_reanalysis": profile["parameters"].get("query_reanalysis"),
            "database_mutation": profile["parameters"].get("database_mutation"),
            "import_mode": profile["parameters"].get("import_mode"),
        },
        "query_policy": {
            "read_only": True,
            "noanalysis": True,
            "native_function_invoked": False,
            "runtime_observed": False,
        },
    }
    return descriptor, shared


def _vtable_descriptor() -> dict[str, Any]:
    report_path = ROOT / EXPECTED_VTABLE_PATH
    report, raw = _load_json(report_path)
    actual_sha = _sha256_file(report_path)
    if actual_sha != EXPECTED_VTABLE_SHA256:
        raise ValueError(f"message vtable report SHA changed: {report_path}")
    if report.get("schema") != "information_battle_message_vtable_window_v1" or report.get("status") != "observed_static_pe_window":
        raise ValueError(f"message vtable report schema/status changed: {report_path}")
    if report.get("evidence_kind") != "ordinary_PE_bytes_and_pdata_metadata":
        raise ValueError(f"message vtable report evidence kind changed: {report_path}")
    if report.get("read_only") is not True or report.get("runtime_observed") is not False or report.get("native_function_invoked") is not False:
        raise ValueError(f"message vtable report read-only guard changed: {report_path}")
    target = report.get("target")
    if not isinstance(target, dict) or target.get("sha256") != EXPECTED_EXE_SHA256 or target.get("size_bytes") != EXPECTED_EXE_SIZE or target.get("image_base") != hex(IMAGE_BASE):
        raise ValueError(f"message vtable target guard changed: {report_path}")
    if target.get("fixed_sha_guard") is not True or target.get("fixed_size_guard") is not True:
        raise ValueError(f"message vtable fixed target guard missing: {report_path}")
    window = report.get("window")
    if not isinstance(window, dict) or window.get("rva") != "0x1c426e0" or window.get("bytes") != 128:
        raise ValueError(f"message vtable window changed: {report_path}")
    slots = report.get("slots")
    limits = report.get("layout_limits")
    if not isinstance(slots, list) or len(slots) != 16 or not isinstance(limits, dict):
        raise ValueError(f"message vtable slot bounds changed: {report_path}")
    if limits.get("all_slots_asserted_same_table") is not False or limits.get("slot_semantics_inferred") is not False:
        raise ValueError(f"message vtable semantic guard changed: {report_path}")
    pdata = report.get("pdata")
    if not isinstance(pdata, dict) or pdata.get("instructions_decoded") is not False:
        raise ValueError(f"message vtable decode guard changed: {report_path}")
    script_path = ROOT / EXPECTED_VTABLE_SCRIPT_PATH
    if not script_path.is_file() or _sha256_file(script_path) != EXPECTED_VTABLE_SCRIPT_SHA256:
        raise ValueError(f"message vtable probe script changed: {script_path}")
    return {
        "path": EXPECTED_VTABLE_PATH,
        "bytes": len(raw),
        "sha256": actual_sha,
        "schema": report["schema"],
        "status": report["status"],
        "evidence_kind": report["evidence_kind"],
        "target_exe_sha256": target["sha256"],
        "window_rva": window["rva"],
        "window_bytes": window["bytes"],
        "window_sha256": window.get("sha256"),
        "slot_count": len(slots),
        "pdata_rows_observed": pdata.get("row_count_observed"),
        "instructions_decoded": pdata.get("instructions_decoded"),
        "probe_script": {
            "path": EXPECTED_VTABLE_SCRIPT_PATH,
            "bytes": script_path.stat().st_size,
            "sha256": EXPECTED_VTABLE_SCRIPT_SHA256,
        },
    }


def _resolve_workspace_file(relative_path: str, *, max_bytes: int = MAX_JSON_BYTES) -> Path:
    if not isinstance(relative_path, str) or not relative_path or Path(relative_path).is_absolute():
        raise ValueError(f"workspace source path is not relative: {relative_path!r}")
    path = (ROOT / relative_path).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"workspace source path escapes root: {relative_path}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"workspace source exceeds bound: {path} ({size} > {max_bytes})")
    return path


def _lifetime_descriptor() -> dict[str, Any]:
    path = STAGE / "message-lifetime-ledger-001.json"
    ledger, raw = _load_json(path)
    ledger_sha = _sha256_file(path)
    if ledger_sha != EXPECTED_LIFETIME_LEDGER_SHA256:
        raise ValueError(f"message lifetime ledger SHA changed: {path}")
    if ledger.get("schema") != "information_battle_message_lifetime_ledger_v1":
        raise ValueError(f"message lifetime ledger schema changed: {path}")
    if ledger.get("status") != "bounded_static_move_consume_popup_findings":
        raise ValueError(f"message lifetime ledger status changed: {path}")
    if ledger.get("target_exe_sha256") != EXPECTED_EXE_SHA256 or ledger.get("static_image_base") != hex(IMAGE_BASE):
        raise ValueError(f"message lifetime ledger target guard changed: {path}")
    if ledger.get("runtime_observed") is not False:
        raise ValueError(f"message lifetime ledger runtime guard changed: {path}")
    if type(ledger.get("native_game_functions_called")) is not int or ledger.get("native_game_functions_called") != 0:
        raise ValueError(f"message lifetime ledger native-call guard changed: {path}")
    if type(ledger.get("hooks_installed")) is not int or ledger.get("hooks_installed") != 0:
        raise ValueError(f"message lifetime ledger hook guard changed: {path}")
    if ledger.get("catalog_promotion") is not False:
        raise ValueError(f"message lifetime ledger promotion guard changed: {path}")
    if not isinstance(ledger.get("facts"), list) or len(ledger["facts"]) < 7:
        raise ValueError(f"message lifetime ledger facts missing: {path}")
    if not isinstance(ledger.get("limitations"), list) or not ledger["limitations"]:
        raise ValueError(f"message lifetime ledger limitations missing: {path}")

    source_key_to_spec = {
        "instance": "message_instance",
        "delivery": "result_delivery",
        "move": "message_move",
        "consumer": "message_consumer",
        "logtext": "message_logtext",
        "presenter": "message_presenter",
        "popup": "message_popup_constructor",
    }
    spec_by_name = {spec["name"]: spec for spec in EVIDENCE_SPECS}
    rea_sources = ledger.get("rea_sources")
    if not isinstance(rea_sources, dict) or set(rea_sources) != set(source_key_to_spec):
        raise ValueError(f"message lifetime ledger REA source set changed: {path}")
    rea_pins: list[dict[str, Any]] = []
    for source_key, spec_name in source_key_to_spec.items():
        source = rea_sources[source_key]
        spec = spec_by_name[spec_name]
        if not isinstance(source, dict):
            raise ValueError(f"message lifetime ledger REA source malformed: {path}")
        expected_path = _relative(STAGE / spec["directory"] / "evidence.json")
        source_path = _resolve_workspace_file(source.get("path"), max_bytes=MAX_EVIDENCE_BYTES)
        if source.get("path") != expected_path or source.get("evidence_id") != spec["expected_id"] or source.get("rva") != spec["expected_rva"] or source.get("static_va") != spec["expected_procedure"]:
            raise ValueError(f"message lifetime ledger REA source identity changed: {source_key}")
        actual_size = source_path.stat().st_size
        actual_sha = _sha256_file(source_path)
        if type(source.get("bytes")) is not int or source["bytes"] != actual_size or source.get("sha256") != actual_sha:
            raise ValueError(f"message lifetime ledger REA source pin changed: {source_key}")
        body = source.get("body_inclusive")
        if not isinstance(body, dict):
            raise ValueError(f"message lifetime ledger body pin missing: {source_key}")
        expected_body = spec["body"]
        expected_ranges = [{"start": start, "end": end} for start, end in expected_body["ranges"]]
        if body.get("ranges") != expected_ranges or any(body.get(key) != expected_body[key] for key in ("total_bytes", "span_bytes", "non_contiguous", "contains_entry")):
            raise ValueError(f"message lifetime ledger body pin changed: {source_key}")
        rea_pins.append(
            {
                "name": source_key,
                "path": source["path"],
                "bytes": actual_size,
                "sha256": actual_sha,
                "evidence_id": source["evidence_id"],
                "rva": source["rva"],
                "static_va": source["static_va"],
                "body_inclusive": body,
            }
        )

    alias_report = ledger.get("late_manager_alias_correction")
    alias_sources = alias_report.get("source_pins") if isinstance(alias_report, dict) else None
    if not isinstance(alias_sources, list) or len(alias_sources) != len(EXPECTED_ALIAS_SOURCE_PINS):
        raise ValueError(f"message lifetime alias correction source pins changed: {path}")
    alias_pins: list[dict[str, Any]] = []
    for expected, source in zip(EXPECTED_ALIAS_SOURCE_PINS, alias_sources):
        if not isinstance(source, dict) or source.get("path") != expected["path"] or source.get("bytes") != expected["bytes"] or source.get("sha256") != expected["sha256"]:
            raise ValueError(f"message lifetime alias source pin changed: {path}")
        source_path = _resolve_workspace_file(expected["path"])
        actual_size = source_path.stat().st_size
        actual_sha = _sha256_file(source_path)
        if actual_size != expected["bytes"] or actual_sha != expected["sha256"]:
            raise ValueError(f"message lifetime alias source changed: {source_path}")
        alias_pins.append({"path": expected["path"], "bytes": actual_size, "sha256": actual_sha, "matches": source.get("matches")})

    ordinary = ledger.get("ordinary_pe_report")
    if not isinstance(ordinary, dict) or ordinary.get("path") != EXPECTED_VTABLE_PATH or ordinary.get("sha256") != EXPECTED_VTABLE_SHA256:
        raise ValueError(f"message lifetime ordinary PE pin changed: {path}")
    if not isinstance(ordinary.get("kind"), str) or "ordinary" not in ordinary["kind"].lower():
        raise ValueError(f"message lifetime ordinary PE kind missing: {path}")

    generator_path = _resolve_workspace_file(EXPECTED_LIFETIME_SCRIPT_PATH, max_bytes=MAX_JSON_BYTES)
    generator_sha = _sha256_file(generator_path)
    if generator_sha != EXPECTED_LIFETIME_SCRIPT_SHA256:
        raise ValueError(f"message lifetime generator SHA changed: {generator_path}")
    generator_text = generator_path.read_text(encoding="utf-8")
    if "from probe_information_battle_side_identity import excerpt" not in generator_text:
        raise ValueError(f"message lifetime generator import changed: {generator_path}")
    import_path = _resolve_workspace_file(EXPECTED_LIFETIME_IMPORT_PATH, max_bytes=MAX_JSON_BYTES)
    import_sha = _sha256_file(import_path)
    if import_sha != EXPECTED_LIFETIME_IMPORT_SHA256:
        raise ValueError(f"message lifetime imported source SHA changed: {import_path}")
    return {
        "path": _relative(path),
        "bytes": len(raw),
        "sha256": ledger_sha,
        "schema": ledger["schema"],
        "status": ledger["status"],
        "target_exe_sha256": ledger["target_exe_sha256"],
        "runtime_observed": ledger["runtime_observed"],
        "native_game_functions_called": ledger["native_game_functions_called"],
        "hooks_installed": ledger["hooks_installed"],
        "catalog_promotion": ledger["catalog_promotion"],
        "rea_source_pins": rea_pins,
        "late_manager_alias_source_pins": alias_pins,
        "ordinary_pe_report": ordinary,
        "generator_script": {"path": EXPECTED_LIFETIME_SCRIPT_PATH, "bytes": generator_path.stat().st_size, "sha256": generator_sha},
        "imported_source": {"path": EXPECTED_LIFETIME_IMPORT_PATH, "bytes": import_path.stat().st_size, "sha256": import_sha},
    }


def _write_json(path: Path, document: dict[str, Any]) -> None:
    encoded = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError(f"generated report exceeds 4 MiB: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(encoded)
    json.loads(temporary.read_text(encoding="utf-8"))
    temporary.replace(path)


def build_reports(*, stage: Path = STAGE) -> tuple[Path, Path]:
    stage = stage.resolve()
    index_path = stage / "research-index-001.json"
    audit_path = stage / "source-audit-001.json"
    if index_path.exists() or audit_path.exists():
        raise FileExistsError(f"refusing to overwrite existing freeze output: {index_path} / {audit_path}")
    script_path = Path(__file__).resolve()
    shared: dict[str, Any] | None = None
    rea_descriptors: list[dict[str, Any]] = []
    for spec in EVIDENCE_SPECS:
        descriptor, shared = _evidence_descriptor(spec, shared)
        rea_descriptors.append(descriptor)
    vtable = _vtable_descriptor()
    lifetime = _lifetime_descriptor()
    script_sha = _sha256_file(script_path)
    limits = [
        "The seven REA records are fixed-build static observations only; no native function was invoked and no runtime message was observed.",
        "The ordinary PE window records only 16 qwords and bounded .pdata containment; it does not prove a complete vtable, slot roles, ABI, ownership, or message semantics.",
        "The message lifetime ledger is a static source pin; callback reentrancy, pointer validity, thread affinity, and runtime retention remain unverified.",
        "Formatted text, move/consumer/presenter behavior, and any native wire or Python transport reports remain separate evidence and are not promoted by this freeze.",
    ]
    index = {
        "schema": "information-battle-message-research-index-001",
        "status": "static_research_frozen_runtime_unresolved",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "dispatch_authorized": False,
        "goal_complete": False,
        "target_build": {
            "game_version": "1.37.4",
            "executable_sha256": EXPECTED_EXE_SHA256,
            "executable_size": EXPECTED_EXE_SIZE,
            "image_base": hex(IMAGE_BASE),
            "address_convention": "fixed-build RVA/VA; REA body ranges are inclusive",
        },
        "analysis_identity": {
            "provider": "Ghidra",
            "provider_version": "12.1.4",
            "preset": EXPECTED_PRESET,
            "adapter_sha256": EXPECTED_ADAPTER_SHA256,
            "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
            "completed_database_sha256": EXPECTED_DATABASE_SHA256,
            "database_mode": "persistent-completed-project-read-only",
        },
        "script": {"path": _relative(script_path), "sha256": script_sha},
        "rea_evidence": rea_descriptors,
        "ordinary_pe_vtable": vtable,
        "message_lifetime_ledger": lifetime,
        "interpretation_limits": limits,
    }
    _write_json(index_path, index)
    index_sha = _sha256_file(index_path)
    checks = [
        {"name": "fixed_target_executable", "passed": all(item["evidence"]["target_exe_sha256"] == EXPECTED_EXE_SHA256 for item in rea_descriptors)},
        {"name": "seven_expected_evidence_ids", "passed": len(rea_descriptors) == 7},
        {"name": "raw_normalized_match", "passed": all(item["evidence"]["raw_normalized_equal"] for item in rea_descriptors)},
        {"name": "request_run_profile_cache_pins", "passed": len({item["request"]["cache"] for item in rea_descriptors}) == 1},
        {"name": "all_rea_runs_completed_and_closed", "passed": all(item["run"]["exit_code"] == 0 and all(p["still_running_same_process"] is False for p in item["run"]["processes"]) for item in rea_descriptors)},
        {"name": "all_read_only_noanalysis", "passed": all(item["query_policy"]["read_only"] and item["query_policy"]["noanalysis"] and not item["query_policy"]["native_function_invoked"] for item in rea_descriptors)},
        {"name": "inclusive_body_ranges_pinned", "passed": all(item["procedure"]["body"]["ranges_inclusive"] for item in rea_descriptors)},
        {"name": "ordinary_vtable_pinned", "passed": vtable["sha256"] == EXPECTED_VTABLE_SHA256 and vtable["slot_count"] == 16},
        {"name": "message_lifetime_ledger_static", "passed": lifetime["runtime_observed"] is False and lifetime["native_game_functions_called"] == 0 and lifetime["hooks_installed"] == 0},
    ]
    audit = {
        "schema": "information-battle-message-source-audit-001",
        "status": "passed_static_source_audit_runtime_unresolved",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "dispatch_authorized": False,
        "goal_complete": False,
        "target_exe_sha256": EXPECTED_EXE_SHA256,
        "script": {"path": _relative(script_path), "sha256": script_sha},
        "research_index": {"path": _relative(index_path), "sha256": index_sha},
        "rea_evidence": rea_descriptors,
        "ordinary_pe_vtable": vtable,
        "message_lifetime_ledger": lifetime,
        "checks": checks,
        "all_checks_passed": all(item["passed"] for item in checks),
        "limitations": limits,
    }
    _write_json(audit_path, audit)
    return index_path, audit_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=STAGE)
    args = parser.parse_args(argv)
    index_path, audit_path = build_reports(stage=args.stage)
    print(json.dumps({
        "index": _relative(index_path),
        "index_sha256": _sha256_file(index_path),
        "audit": _relative(audit_path),
        "audit_sha256": _sha256_file(audit_path),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
