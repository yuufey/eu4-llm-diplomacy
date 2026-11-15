"""Freeze bounded static evidence for the battle-popup field research.

This is an offline pinning step.  It reads the four completed fixed-build
REA dossiers and the bounded selected/readback products made by
``extract_information_battle_popup_evidence.py``.  It never invokes REA,
native code, the game, or a dispatch.  A later root-produced ledger and its
explicitly named source files can be added with ``--ledger`` and
``--ledger-script``/``--source-doc``; the freeze never creates those files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-popup-20261025-001"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_SIZE = 38_463_016
IMAGE_BASE = 0x140000000
EXPECTED_ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
EXPECTED_MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
EXPECTED_DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
EXPECTED_PRESET = "eu4-persistent-default-analysis-v1"
EXPECTED_HELPER_PATH = "work/extract_information_battle_popup_evidence.py"
# This pin is refreshed only when the bounded extractor is intentionally
# changed; the freeze then fails closed until the expected pin is updated.
EXPECTED_HELPER_SHA256 = "24b7e3f4d2ea6c5b04f1d302ea2236c585afcef38b071ff51492238029d010a7"
EXPECTED_LEDGER_PATH = "work/runtime/information-battle-popup-20261025-001/popup-field-ledger-001.json"
EXPECTED_LEDGER_SHA256 = "84d18633f9612129579d9b35a9a56faf4ecdcbbb341540fa3c53cff04b6ed007"
EXPECTED_LEDGER_SCRIPT_PATH = "work/probe_information_battle_popup_fields.py"
EXPECTED_LEDGER_SCRIPT_SHA256 = "116e33b117dd71edba9451f3223f2eab2eca3c778a365d939c0f9bc16e1c7bf0"
EXPECTED_VTABLE_SCRIPT_PATH = "work/probe_information_message_vtable.py"
EXPECTED_VTABLE_SCRIPT_SHA256 = "fccc7ef747b79df79765b6d5e69aecc2631ce57237409f4e51f688e19836ade6"

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CONTEXT_LINES = 7

_LAND_TAIL_RANGES = tuple(
    (f"0x{0x1408CA36D + 6 * i:x}", f"0x{0x1408CA371 + 6 * i:x}")
    for i in range(27)
)

EVIDENCE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "popup_message_copy",
        "directory": "rea-popup-message-copy-001",
        "expected_id": "ev_51d6347595d0a8d8b6a9436bf23fd1e269096574bce32a9ae105935c16a7bbbe",
        "expected_procedure": "0x140598dc0",
        "expected_rva": "0x598dc0",
        "body": {
            "ranges": [("0x140598dc0", "0x140598ee8")],
            "total_bytes": 297,
            "span_bytes": 297,
            "non_contiguous": False,
            "contains_entry": True,
        },
    },
    {
        "name": "land_popup_fields",
        "directory": "rea-land-popup-fields-001",
        "expected_id": "ev_c7a8b8253d9ca7139375ba824564871a0309cb6e70d7c0bea72f53008b80ea74",
        "expected_procedure": "0x1408c75d0",
        "expected_rva": "0x8c75d0",
        "body": {
            "ranges": [("0x1408c75d0", "0x1408ca36b"), *_LAND_TAIL_RANGES],
            "total_bytes": 11811,
            "span_bytes": 11838,
            "non_contiguous": True,
            "contains_entry": True,
        },
    },
    {
        "name": "naval_popup_fields",
        "directory": "rea-naval-popup-fields-001",
        "expected_id": "ev_9036822f562930ea96fe3af5ba6a6a7224db478e73afd13a898cba83f50c273e",
        "expected_procedure": "0x1408ca460",
        "expected_rva": "0x8ca460",
        "body": {
            "ranges": [
                ("0x1408ca460", "0x1408cbec7"),
                ("0x1408cbec9", "0x1408cbecd"),
                ("0x1408cbecf", "0x1408cbed3"),
                ("0x1408cbed5", "0x1408cbed9"),
            ],
            "total_bytes": 6775,
            "span_bytes": 6778,
            "non_contiguous": True,
            "contains_entry": True,
        },
    },
    {
        "name": "template_node_copy",
        "directory": "rea-template-node-copy-001",
        "expected_id": "ev_4582c75bb5b831a70732042fe45b85e723646f30e12d5c8d64a6287719f11ab7",
        "expected_procedure": "0x1405b29c0",
        "expected_rva": "0x5b29c0",
        "body": {
            "ranges": [("0x1405b29c0", "0x1405b2ac6")],
            "total_bytes": 263,
            "span_bytes": 263,
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
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_json(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> tuple[dict[str, Any], bytes]:
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


def _resolve_workspace_file(value: str, *, max_bytes: int = MAX_INPUT_BYTES) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError(f"source path must be a non-empty relative path: {value!r}")
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"source path escapes workspace: {value}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"source exceeds bound: {path}")
    return path


def _body_descriptor(procedure: dict[str, Any], expected: dict[str, Any], path: Path) -> dict[str, Any]:
    body = procedure.get("body")
    if not isinstance(body, dict):
        raise ValueError(f"REA body missing: {path}")
    ranges = body.get("ranges")
    expected_ranges = expected["ranges"]
    if not isinstance(ranges, list) or len(ranges) != len(expected_ranges):
        raise ValueError(f"REA body range count changed: {path}")
    converted: list[dict[str, Any]] = []
    total = 0
    for item, (start_text, end_text) in zip(ranges, expected_ranges):
        if not isinstance(item, dict) or item.get("start") != start_text or item.get("end") != end_text:
            raise ValueError(f"REA body range changed: {path}")
        start = int(start_text, 16)
        end = int(end_text, 16)
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


def _validate_shared(request: dict[str, Any], run: dict[str, Any], profile: dict[str, Any], path: Path, shared: dict[str, Any] | None) -> dict[str, Any]:
    for key in (
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
    ):
        if request.get(key) != run.get(key):
            raise ValueError(f"request/run parameter mismatch {key}: {path.parent}")
    expected = {
        "target_sha256": EXPECTED_EXE_SHA256,
        "preset": EXPECTED_PRESET,
        "adapter_sha256": EXPECTED_ADAPTER_SHA256,
        "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        "query_reanalysis": False,
        "java_heap": "512M",
        "process_memory_limit_bytes": 1024 * 1024 * 1024,
    }
    for key, value in expected.items():
        if request.get(key) != value:
            raise ValueError(f"REA request {key} changed: {path.parent}")
    if not isinstance(request.get("cache"), str) or not request["cache"]:
        raise ValueError(f"REA cache path missing: {path.parent}")
    profile_expected = {
        "analyzer_preset": EXPECTED_PRESET,
        "local_adapter_sha256": EXPECTED_ADAPTER_SHA256,
        "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "completed_database_sha256": EXPECTED_DATABASE_SHA256,
        "query_reanalysis": False,
        "database_mutation": "read-only-no-save",
        "import_mode": "persistent-completed-project-read-only",
    }
    for key, value in profile_expected.items():
        if profile.get(key) != value:
            raise ValueError(f"REA profile {key} changed: {path}")
    current = {key: request[key] for key in ("cache", "preset", "adapter_sha256", "completed_manifest_sha256", "completed_database_sha256")}
    if shared is not None and current != shared:
        raise ValueError(f"REA shared cache/profile pins changed: {path.parent}")
    return current


def _evidence_descriptor(spec: dict[str, Any], shared: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    directory = STAGE / spec["directory"]
    evidence_path, request_path, run_path = directory / "evidence.json", directory / "request.json", directory / "run.json"
    evidence, evidence_raw = _load_json(evidence_path)
    request, request_raw = _load_json(request_path)
    run, run_raw = _load_json(run_path)
    if evidence.get("evidence_id") != spec["expected_id"]:
        raise ValueError(f"Evidence ID changed: {evidence_path}")
    target_sha = evidence.get("subject", {}).get("digest", {}).get("sha256")
    if target_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"Evidence target SHA changed: {evidence_path}")
    raw_result, normalized_result = evidence.get("raw_result"), evidence.get("normalized_result")
    if not isinstance(raw_result, dict) or not isinstance(raw_result.get("value"), dict) or not isinstance(normalized_result, dict):
        raise ValueError(f"REA raw/normalized result missing: {evidence_path}")
    raw_value = raw_result["value"]
    if raw_value != normalized_result:
        raise ValueError(f"REA raw/normalized result mismatch: {evidence_path}")
    procedure = raw_value.get("procedure")
    if not isinstance(procedure, dict) or procedure.get("address") != spec["expected_procedure"]:
        raise ValueError(f"REA procedure changed: {evidence_path}")
    if request.get("node") != spec["expected_rva"] or request.get("procedure") != spec["expected_procedure"] or run.get("node") != spec["expected_rva"] or run.get("procedure") != spec["expected_procedure"]:
        raise ValueError(f"REA address changed: {directory}")
    if run.get("exit_code") != 0 or run.get("reason") != "completed" or run.get("database_unchanged") is not True:
        raise ValueError(f"REA run did not complete read-only: {run_path}")
    processes = run.get("processes")
    if not isinstance(processes, list) or not processes or any(not isinstance(item, dict) for item in processes) or any(item.get("still_running_same_process") is not False for item in processes) or any(item.get("peak_committed_bytes", 2**31) >= 1024 * 1024 * 1024 for item in processes):
        raise ValueError(f"REA process closure/memory guard failed: {run_path}")
    profile = evidence.get("analysis_profile")
    if not isinstance(profile, dict) or not isinstance(profile.get("parameters"), dict):
        raise ValueError(f"REA profile missing: {evidence_path}")
    provider = profile.get("provider")
    if not isinstance(provider, dict) or provider.get("id") != "ghidra" or provider.get("version") != "12.1.4":
        raise ValueError(f"REA provider changed: {evidence_path}")
    shared = _validate_shared(request, run, profile["parameters"], evidence_path, shared)
    if not any("-readOnly" in str(item) and "-noanalysis" in str(item) for item in evidence.get("limitations", [])):
        raise ValueError(f"REA readOnly/noanalysis limitation missing: {evidence_path}")
    body = _body_descriptor(procedure, spec["body"], evidence_path)
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
            "address_va": procedure["address"],
            "rva": hex(int(procedure["address"], 16) - IMAGE_BASE),
            "body": body,
        },
        "request": {
            "path": _relative(request_path),
            "bytes": len(request_raw),
            "sha256": _sha256_file(request_path),
            **{key: request.get(key) for key in ("node", "procedure", "cache", "preset", "adapter_sha256", "completed_manifest_sha256", "completed_database_sha256", "query_reanalysis", "java_heap", "process_memory_limit_bytes", "timeout_seconds")},
        },
        "run": {
            "path": _relative(run_path),
            "bytes": len(run_raw),
            "sha256": _sha256_file(run_path),
            **{key: run.get(key) for key in ("exit_code", "reason", "elapsed_seconds", "database_unchanged", "processes")},
        },
        "profile": {
            "digest": profile.get("digest"),
            "provider": provider,
            **{key: profile["parameters"].get(key) for key in ("analyzer_preset", "local_adapter_sha256", "completed_manifest_sha256", "completed_database_sha256", "query_reanalysis", "database_mutation", "import_mode")},
        },
        "query_policy": {"read_only": True, "noanalysis": True, "native_function_invoked": False, "runtime_observed": False},
    }
    return descriptor, shared


def _selected_descriptor(spec: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    directory = STAGE / spec["directory"]
    selected_path, readback_path = directory / "selected-evidence-001.json", directory / "readback-recovery-001.json"
    selected, selected_raw = _load_json(selected_path)
    readback, readback_raw = _load_json(readback_path)
    if selected.get("status") != "observed" or readback.get("status") != "observed":
        raise ValueError(f"selected/readback status changed: {directory}")
    source = selected.get("source")
    if not isinstance(source, dict) or source.get("sha256") != evidence["evidence"]["sha256"] or source.get("size_bytes") != evidence["evidence"]["bytes"] or source.get("stable_before_after") is not True:
        raise ValueError(f"selected source pin changed: {selected_path}")
    request = selected.get("request")
    if not isinstance(request, dict) or request.get("sha256") != evidence["request"]["sha256"] or request.get("all_fixed_checks_pass") is not True:
        raise ValueError(f"selected request pin changed: {selected_path}")
    runtime = selected.get("provider_runtime")
    audit = runtime.get("audit") if isinstance(runtime, dict) else None
    if not isinstance(audit, dict) or audit.get("sha256") != evidence["run"]["sha256"] or runtime.get("status") != "passed" or runtime.get("provider_exit_code") != 0 or runtime.get("provider_peak_committed_bytes", 2**31) >= 1024 * 1024 * 1024:
        raise ValueError(f"selected provider run pin changed: {selected_path}")
    query = selected.get("query")
    if not isinstance(query, dict) or query.get("authorised_rva") != spec["expected_rva"] or query.get("authorised_procedure") != spec["expected_procedure"] or query.get("target_sha256") != EXPECTED_EXE_SHA256:
        raise ValueError(f"selected query identity changed: {selected_path}")
    identity = selected.get("identity_audit")
    if not isinstance(identity, dict) or identity.get("status") != "passed" or identity.get("subject_sha256") != EXPECTED_EXE_SHA256:
        raise ValueError(f"selected identity guard changed: {selected_path}")
    raw_value = selected.get("raw_result_value")
    required = {"procedure", "pseudocode", "assembly", "callers", "callees", "limitations"}
    if not isinstance(raw_value, dict) or not required.issubset(raw_value):
        raise ValueError(f"selected fields incomplete: {selected_path}")
    top_evidence = selected.get("top_level", {}).get("evidence_id", {}).get("value")
    if top_evidence != spec["expected_id"]:
        raise ValueError(f"selected evidence ID missing: {selected_path}")
    readback_request = readback.get("request")
    readback_runtime = readback.get("provider_runtime")
    readback_audit = readback_runtime.get("audit") if isinstance(readback_runtime, dict) else None
    if not isinstance(readback_request, dict) or readback_request.get("sha256") != evidence["request"]["sha256"] or not isinstance(readback_audit, dict) or readback_audit.get("sha256") != evidence["run"]["sha256"] or readback_runtime.get("status") != "passed":
        raise ValueError(f"readback source pin changed: {readback_path}")
    return {
        "selected": {"path": _relative(selected_path), "bytes": len(selected_raw), "sha256": _sha256_file(selected_path)},
        "readback": {"path": _relative(readback_path), "bytes": len(readback_raw), "sha256": _sha256_file(readback_path)},
        "source_sha256": source["sha256"],
        "request_sha256": request["sha256"],
        "run_sha256": audit["sha256"],
        "selected_status": selected["status"],
        "readback_status": readback["status"],
        "selected_fields": sorted(required),
        "parser": selected.get("parser"),
    }


def _optional_pin(path_value: str, role: str) -> dict[str, Any]:
    path = _resolve_workspace_file(path_value)
    return {"role": role, "path": _relative(path), "bytes": path.stat().st_size, "sha256": _sha256_file(path), "source_pin_only": True}


def _context_artifact(evidence_descriptors: dict[str, dict[str, Any]], revision: str) -> tuple[Path, str]:
    path = STAGE / f"popup-template-widget-context-{revision}.json"
    if path.exists():
        raise FileExistsError(f"refusing to overwrite context artifact: {path}")
    groups = {
        "land_popup_fields": {
            "directory": "rea-land-popup-fields-001",
            "selected_sha256": evidence_descriptors["land_popup_fields"]["selected"]["sha256"],
            "raw_evidence_sha256": evidence_descriptors["land_popup_fields"]["source_sha256"],
            "template_matches": [("WINORLOSE", 1035, "winORLose", 1038)],
            "widget_literals": ("AgreeButton", "CenterOK", "DeclineButton"),
            "tail_window": (1371, 1429),
        },
        "naval_popup_fields": {
            "directory": "rea-naval-popup-fields-001",
            "selected_sha256": evidence_descriptors["naval_popup_fields"]["selected"]["sha256"],
            "raw_evidence_sha256": evidence_descriptors["naval_popup_fields"]["source_sha256"],
            "template_matches": [("WINORLOSE", 279, "winORLose", 282), ("CAPTURE", 789, "captured_ships_amount", 793)],
            "widget_literals": ("AgreeButton", "CenterOK", "DeclineButton"),
            "tail_window": (859, 1012),
        },
    }
    result: dict[str, Any] = {
        "schema": f"information-battle-popup-template-widget-context-{revision}",
        "status": "observed_static_pseudocode_context",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "target_build": {"game_version": "1.37.4", "executable_sha256": EXPECTED_EXE_SHA256, "address_convention": "fixed-build RVA/VA; pseudocode lines are 1-based"},
        "limits": {"source": "bounded selected-evidence outputs", "max_context_lines_per_window": MAX_CONTEXT_LINES, "semantic_inference": False},
        "findings": [],
        "unresolved": ["No title literal was promoted: the selected pseudocode contains no literal named title key; tail calls are retained mechanically.", "Ship type, OUR side, and participant identity were not inferred from these strings."],
    }
    for name, group in groups.items():
        selected_path = STAGE / group["directory"] / "selected-evidence-001.json"
        selected, _ = _load_json(selected_path)
        pseudo = selected["raw_result_value"]["pseudocode"]["value"]
        if not isinstance(pseudo, str):
            raise ValueError(f"pseudocode is not text: {selected_path}")
        lines = pseudo.splitlines()

        def window(start: int, end: int) -> dict[str, Any]:
            if start < 1 or end < start or end > len(lines) or end - start + 1 > MAX_CONTEXT_LINES * 30:
                raise ValueError(f"context window out of bound: {selected_path}:{start}-{end}")
            return {"line_start": start, "line_end": end, "lines": lines[start - 1:end]}

        finding = {"function": name, "directory": group["directory"], "selected_sha256": group["selected_sha256"], "raw_evidence_sha256": group["raw_evidence_sha256"], "template_to_widget_context": [], "widget_context": [], "tail_context": window(*group["tail_window"])}
        for template_key, template_line, widget, widget_line in group["template_matches"]:
            finding["template_to_widget_context"].append({"template_key": template_key, "template_line": template_line, "widget_name": widget, "widget_line": widget_line, "context": window(template_line - 2, widget_line + 2)})
        for literal in group["widget_literals"]:
            occurrences = []
            for number, line in enumerate(lines, 1):
                if literal in line:
                    occurrences.append({"line": number, "context": window(max(1, number - 2), min(len(lines), number + 2))})
            finding["widget_context"].append({"literal": literal, "occurrences": occurrences})
        result["findings"].append(finding)
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("context artifact exceeds output bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    json.loads(path.read_text(encoding="utf-8"))
    return path, hashlib.sha256(encoded).hexdigest()


def _write_json(path: Path, document: dict[str, Any]) -> None:
    encoded = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError(f"generated report exceeds bound: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(encoded)
    json.loads(temporary.read_text(encoding="utf-8"))
    temporary.replace(path)


def build_reports(*, stage: Path = STAGE, revision: str = "001", ledger: str | None = None, ledger_script: str | None = None, vtable_script: str | None = None, source_docs: tuple[str, ...] = ()) -> tuple[Path, Path]:
    global STAGE
    STAGE = stage.resolve()
    if not isinstance(revision, str) or len(revision) != 3 or not revision.isdigit() or int(revision) < 1:
        raise ValueError(f"revision must be a positive three-digit string: {revision!r}")
    if revision != "001" and (not ledger or not ledger_script or not vtable_script):
        raise ValueError("revisions after 001 require explicit ledger, ledger-script, and vtable-script pins")
    index_path, audit_path = STAGE / f"research-index-{revision}.json", STAGE / f"source-audit-{revision}.json"
    if index_path.exists() or audit_path.exists():
        raise FileExistsError(f"refusing to overwrite existing freeze output: {index_path} / {audit_path}")
    helper_path = _resolve_workspace_file(EXPECTED_HELPER_PATH)
    helper_sha = _sha256_file(helper_path)
    if EXPECTED_HELPER_SHA256.startswith("__") or helper_sha != EXPECTED_HELPER_SHA256:
        raise ValueError(f"popup extractor SHA is not pinned: {helper_sha}")
    shared: dict[str, Any] | None = None
    rea: list[dict[str, Any]] = []
    selected: dict[str, dict[str, Any]] = {}
    for spec in EVIDENCE_SPECS:
        descriptor, shared = _evidence_descriptor(spec, shared)
        descriptor["selected_products"] = _selected_descriptor(spec, descriptor)
        rea.append(descriptor)
        selected[spec["name"]] = descriptor["selected_products"]
    context_path, context_sha = _context_artifact(selected, revision)
    optional: list[dict[str, Any]] = []
    if ledger:
        pin = _optional_pin(ledger, "root_popup_field_ledger")
        if pin["path"] != EXPECTED_LEDGER_PATH or pin["sha256"] != EXPECTED_LEDGER_SHA256:
            raise ValueError(f"root ledger pin changed: {ledger}")
        optional.append(pin)
    if ledger_script:
        pin = _optional_pin(ledger_script, "root_popup_field_ledger_generator")
        if pin["path"] != EXPECTED_LEDGER_SCRIPT_PATH or pin["sha256"] != EXPECTED_LEDGER_SCRIPT_SHA256:
            raise ValueError(f"root ledger generator pin changed: {ledger_script}")
        optional.append(pin)
    if vtable_script:
        pin = _optional_pin(vtable_script, "ordinary_pe_vtable_probe_dependency")
        if pin["path"] != EXPECTED_VTABLE_SCRIPT_PATH or pin["sha256"] != EXPECTED_VTABLE_SCRIPT_SHA256:
            raise ValueError(f"vtable dependency pin changed: {vtable_script}")
        optional.append(pin)
    optional.extend(_optional_pin(doc, "root_popup_source_doc") for doc in source_docs)
    script_path = Path(__file__).resolve()
    limits = [
        "The four REA dossiers and selected/readback products are fixed-build static observations; no native function, game process, or runtime popup was invoked.",
        "The selected pseudocode context artifact mechanically preserves nearby template/widget literals and tail calls; it does not infer title semantics, ship type, OUR side, participant identity, ABI, ownership, or UI visibility.",
        "The fourth 0x5b29c0 dossier is a template-node copy and is pinned as a separate static function; it is not promoted to a runtime copy contract.",
        "Root ledger/script/docs are optional explicit source pins only; this freeze never creates, rewrites, or treats them as runtime evidence.",
    ]
    index = {
        "schema": f"information-battle-popup-research-index-{revision}",
        "status": "static_research_frozen_runtime_unresolved",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "dispatch_authorized": False,
        "goal_complete": False,
        "target_build": {"game_version": "1.37.4", "executable_sha256": EXPECTED_EXE_SHA256, "executable_size": EXPECTED_EXE_SIZE, "image_base": hex(IMAGE_BASE), "address_convention": "fixed-build RVA/VA; REA body ranges are inclusive"},
        "analysis_identity": {"provider": "Ghidra", "provider_version": "12.1.4", "preset": EXPECTED_PRESET, "adapter_sha256": EXPECTED_ADAPTER_SHA256, "completed_manifest_sha256": EXPECTED_MANIFEST_SHA256, "completed_database_sha256": EXPECTED_DATABASE_SHA256, "database_mode": "persistent-completed-project-read-only"},
        "script": {"path": _relative(script_path), "sha256": _sha256_file(script_path)},
        "extractor": {"path": EXPECTED_HELPER_PATH, "sha256": helper_sha},
        "rea_evidence": rea,
        "template_widget_context": {"path": _relative(context_path), "bytes": context_path.stat().st_size, "sha256": context_sha},
        "optional_root_pins": optional,
        "interpretation_limits": limits,
    }
    _write_json(index_path, index)
    index_sha = _sha256_file(index_path)
    checks = [
        {"name": "fixed_target_executable", "passed": len(rea) == 4 and all(item["evidence"]["target_exe_sha256"] == EXPECTED_EXE_SHA256 for item in rea)},
        {"name": "four_expected_evidence_ids", "passed": len(rea) == 4 and {item["evidence"]["evidence_id"] for item in rea} == {spec["expected_id"] for spec in EVIDENCE_SPECS}},
        {"name": "raw_normalized_match", "passed": all(item["evidence"]["raw_normalized_equal"] for item in rea)},
        {"name": "request_run_profile_cache_pins", "passed": len({item["request"]["cache"] for item in rea}) == 1},
        {"name": "all_rea_runs_completed_and_closed", "passed": all(item["run"]["exit_code"] == 0 and all(p["still_running_same_process"] is False for p in item["run"]["processes"]) for item in rea)},
        {"name": "all_read_only_noanalysis", "passed": all(item["query_policy"]["read_only"] and item["query_policy"]["noanalysis"] and not item["query_policy"]["native_function_invoked"] for item in rea)},
        {"name": "inclusive_body_ranges_pinned", "passed": all(item["procedure"]["body"]["ranges_inclusive"] for item in rea)},
        {"name": "selected_readback_pinned", "passed": all(item["selected_products"]["selected_status"] == "observed" and item["selected_products"]["readback_status"] == "observed" for item in rea)},
        {"name": "template_widget_context_static", "passed": context_sha == _sha256_file(context_path)},
    ]
    audit = {
        "schema": f"information-battle-popup-source-audit-{revision}",
        "status": "passed_static_source_audit_runtime_unresolved",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "dispatch_authorized": False,
        "goal_complete": False,
        "target_exe_sha256": EXPECTED_EXE_SHA256,
        "script": {"path": _relative(script_path), "sha256": _sha256_file(script_path)},
        "extractor": {"path": EXPECTED_HELPER_PATH, "sha256": helper_sha},
        "research_index": {"path": _relative(index_path), "sha256": index_sha},
        "rea_evidence": rea,
        "template_widget_context": {"path": _relative(context_path), "bytes": context_path.stat().st_size, "sha256": context_sha},
        "optional_root_pins": optional,
        "checks": checks,
        "all_checks_passed": all(item["passed"] for item in checks),
        "limitations": limits,
    }
    _write_json(audit_path, audit)
    return index_path, audit_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=STAGE)
    parser.add_argument("--revision", default="001", help="three-digit output revision; 001 is the initial freeze")
    parser.add_argument("--ledger", help="explicit later root ledger path; pin only")
    parser.add_argument("--ledger-script", help="explicit later root ledger generator path; pin only")
    parser.add_argument("--vtable-script", help="explicit ordinary PE helper dependency path; pin only")
    parser.add_argument("--source-doc", action="append", default=[], help="explicit later root source document path; may repeat")
    args = parser.parse_args(argv)
    index_path, audit_path = build_reports(stage=args.stage, revision=args.revision, ledger=args.ledger, ledger_script=args.ledger_script, vtable_script=args.vtable_script, source_docs=tuple(args.source_doc))
    print(json.dumps({"index": _relative(index_path), "index_sha256": _sha256_file(index_path), "audit": _relative(audit_path), "audit_sha256": _sha256_file(audit_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
