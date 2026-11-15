"""Audit and optionally archive the HTTP rejection recovery batch.

This entry point composes the bounded checks from
``audit_information_recovery_delivery.py`` without changing that historical
audit or its delivery.  It keeps the old recovery evidence, verifies exactly
three HTTP production files and three HTTP test files, and requires the next
full-test source snapshot to contain only those six controlled additions.

No game, process, DLL, HTTP dispatch, REA, or business action is performed.
Every source is bounded to 16 MiB and an archive is bounded to 128 MiB.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import audit_information_recovery_delivery as base


MAX_SINGLE_BYTES = base.MAX_SINGLE_BYTES
MAX_TOTAL_BYTES = base.MAX_TOTAL_BYTES
EXPECTED_HTTP_PRODUCTION = {
    "bridge/http_rejection.py",
    "bridge/diplomacy_observer_service.py",
    "bridge/tag_command_service.py",
}
EXPECTED_HTTP_TESTS = {
    "bridge/tests/test_http_rejection.py",
    "bridge/tests/test_diplomacy_observer_service.py",
    "bridge/tests/test_tag_command_service.py",
}
EXPECTED_HTTP_PATHS = EXPECTED_HTTP_PRODUCTION | EXPECTED_HTTP_TESTS
EXPECTED_HTTP_REPORT_SCHEMA = "information_http_rejection_20261025_002"
EXPECTED_HTTP_REPORT_SHA256 = "e41987e1bf378d87eeb5cb68fb8ea06a4e97d5235b9af692de4418bf009695fa"
EXPECTED_OLD_RECOVERY_ERROR = "new test summary has failure/error nodes absent from previous baseline"
EXPECTED_OLD_OBSERVER_NODE = (
    "bridge.tests.test_diplomacy_observer_service.ObserverHTTPTests::"
    "test_unauthenticated_write_methods_are_refused_without_observation [failure]"
)
EXPECTED_HELPER_CONSTANTS = {
    "MAX_REJECTION_BODY": 64 * 1024,
    "READ_CHUNK": 8192,
    "REJECTION_DEADLINE_SECONDS": 0.2,
}
EXPECTED_RELATION_AUDIT_SCHEMA = "information-http-rejection/relation-source-pin-audit/1"
EXPECTED_RELATION_AUDIT_STATUS = "historical_relation_pin_mismatch_confirmed"
EXPECTED_RELATION_NODE_ID = (
    "bridge.tests.test_relation_state_service.ServiceSourceTests::"
    "test_manifest_graph_and_offline_catalog [failure]"
)
EXPECTED_RELATION_MANIFEST_PATH = "bridge/relation_state_service_manifest_1375.json"
EXPECTED_RELATION_MANIFEST_SHA256 = "48326793008996616bf3685c7cac207a5d2528bfe89b6b2feedb724ee088bf39"
EXPECTED_RELATION_MESSAGE_IDS = {
    EXPECTED_RELATION_NODE_ID,
    "bridge.tests.test_research_tools.ResearchToolsTests::"
    "test_enable_disable_preserves_other_mods_and_unknown_settings [failure]",
    "bridge.tests.test_v12_experiment_review.V12ReviewTests::"
    "test_actual_streaming_save_and_independent_reload_path_can_verify [failure]",
    "bridge.tests.test_v12_experiment_review.V12ReviewTests::"
    "test_artifacts_are_bounded_unique_content_addressed_and_confined [failure]",
}
EXPECTED_RELATION_OLD_MESSAGE = "FileNotFoundError: [WinError 3]"
EXPECTED_RELATION_NEW_MESSAGE = "ValueError: Relation host source differs: bridge/diplomacy_observer_service.py"
SCALAR_STAGE = "work/runtime/information-battle-scalar-writers-20261025-001"
SCALAR_INDEX = f"{SCALAR_STAGE}/research-index-001.json"
SCALAR_SOURCE_AUDIT = f"{SCALAR_STAGE}/source-audit-001.json"
SCALAR_WRITER_LEDGER = f"{SCALAR_STAGE}/scalar-field-writer-001.json"
SCALAR_INDEX_SHA256 = "b3a2c7003ad98a7ea5f0c52f8c262da8a10841883487afcc328e167569eae8ce"
SCALAR_SOURCE_AUDIT_SHA256 = "944b3ad60a9a29b4d277508ed9ccaaaf9958ae2b2e4214b9bd86c8e66273f27c"
SCALAR_WRITER_LEDGER_SHA256 = "3bd495ce9575b7f4a3134512f7fb27fd9ad6594632b1afd4026e9a419b574400"
SCALAR_PROFILE_SHA256 = "b0cb1a440ffe654cdb6c8d5c62e7f6ce6a5b45b422ea7bce2096e5af759482bb"
SCALAR_ADAPTER_SHA256 = "93620e986ea9ea17f5b6a8e56a5077772af0090a8d0eb467019aea40d38a689d"
SCALAR_MANIFEST_SHA256 = "de1c738fa2bc9027ceacadabb7828d9890f5f9ff57ec4cde60494968f927333a"
SCALAR_DATABASE_SHA256 = "8eec1cad93cce37d2f958c100570550bc7212c5aa86b92b7cf03950f85a83161"
UNIT_DISPLAY_LEDGER = "work/runtime/information-battle-layout-20261025-001/unit-display-ledger-001.json"
UNIT_DISPLAY_LEDGER_SHA256 = "20ba4eb0a313bf369c0afba2d79b7541620d932ef70724b105b6282ab0e85d41"
SCALAR_REA_DIRS = (
    f"{SCALAR_STAGE}/rea-scalar-writer-001",
    f"{SCALAR_STAGE}/rea-count-conversion-001",
    f"{SCALAR_STAGE}/rea-count-display-001",
)
SCALAR_REA_FILES = ("evidence.json", "request.json", "run.json", "ghidra-tail.log", "script-tail.log", "stderr.log")
SCALAR_SCRIPTS = (
    "work/freeze_information_battle_scalar_research.py",
    "work/probe_information_battle_scalar_writes.py",
    "work/probe_information_battle_unit_display.py",
)
SCALAR_SCRIPT_SHA256 = {
    "work/freeze_information_battle_scalar_research.py": "16bc1157e8acffcce6960cc82c671081278230834847ed3c70d998481874d643",
    "work/probe_information_battle_scalar_writes.py": "f32b57cd65e4e0ccb85a8bf95c6207c06961b53fb9d799e2d1ea7cef9fff1593",
    "work/probe_information_battle_unit_display.py": "20d74de4c16689b626a13ffc7288d89c638df41aa566faedde619cd6ebc073dd",
}
HTTP_RUNTIME_CHECK = "work/runtime/information-http-rejection-20261025-001/runtime-check-001.json"
HTTP_RUNTIME_CONTROL = "work/runtime/information-http-rejection-20261025-001/runtime-control-001.json"
HTTP_DOCUMENTATION = "docs/HTTP拒绝请求的连接处理.md"
BATTLE_DOCUMENTATION = "docs/逐场战报原生来源.md"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _lf_sha256(path: Path) -> str:
    data = path.read_bytes()
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(data).hexdigest()


def _load_json(path: str | Path) -> tuple[str, Path, Any]:
    return base._load_json(path)


def _is_int(value: Any) -> bool:
    return type(value) is int


def _record_input(audit: base.Audit, label: str, path: str | Path) -> dict[str, Any] | None:
    try:
        rel, file = base._bounded_path(path)
        record = {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file)}
        audit.inputs[label] = record
        return record
    except base.AuditError as exc:
        audit.errors.append(f"{label}: {exc}")
        return None


def _pin_current(audit: base.Audit, value: Any, label: str) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        audit.errors.append(f"{label}: missing path/SHA/bytes pin")
        return None
    return base._validate_pinned_file(audit, value, label)


def _pin_path_sha(audit: base.Audit, value: Any, label: str) -> dict[str, Any] | None:
    """Validate a path/SHA pin whose producer did not record byte length."""

    if not isinstance(value, dict):
        audit.errors.append(f"{label}: missing path/SHA pin")
        return None
    try:
        rel, file = base._bounded_path(value.get("path"))
        expected = base._hex_sha(value.get("sha256"), f"{label}.sha256")
        actual = _sha256(file)
        audit.require(actual == expected, f"{label} SHA mismatch: {rel}")
        if "bytes" in value:
            audit.require(_is_int(value.get("bytes")) and value.get("bytes") == file.stat().st_size, f"{label} byte count mismatch: {rel}")
        return {"path": rel, "bytes": file.stat().st_size, "sha256": actual}
    except base.AuditError as exc:
        audit.errors.append(f"{label}: {exc}")
        return None


def _static_number(node: ast.AST) -> Any:
    """Evaluate only the small numeric expressions used by helper constants."""

    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
        left = _static_number(node.left)
        right = _static_number(node.right)
        if type(left) in (int, float) and type(right) in (int, float):
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            return left / right
    return None


def _validate_old_recovery(audit: base.Audit, path: str) -> dict[str, Any]:
    rel, file, old = _load_json(path)
    audit.inputs["base_recovery_audit"] = {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file)}
    audit.require(old.get("schema") == "information_recovery_delivery_audit_v1", "base recovery audit schema changed")
    audit.require(old.get("status") == "failed" and old.get("goal_complete") is False, "base recovery audit status boundary changed")
    audit.require(old.get("errors") == [EXPECTED_OLD_RECOVERY_ERROR], "base recovery audit must retain exactly the historical HTTP gate failure")
    inputs = base._dict(old.get("inputs"), "base recovery audit.inputs", audit)
    checks = base._dict(old.get("checks"), "base recovery audit.checks", audit)
    profile_check = base._dict(checks.get("profile_contract"), "base recovery audit.profile_contract", audit)
    audit.require(profile_check.get("profile_version") == 3 and profile_check.get("contract_id") == "native-domestic-pressure-contract-003", "N04 profile/contract identity changed")
    live_check = base._dict(checks.get("live"), "base recovery audit.live", audit)
    audit.require(live_check.get("status") == "passed" and live_check.get("schema") == "information_domestic_pressure_live_acceptance_004", "MCP-005 live evidence changed")
    subscription = base._dict(live_check.get("subscription"), "base recovery audit.subscription", audit)
    audit.require(subscription.get("state") == "cancelled", "MCP-005 subscription cancellation evidence changed")
    comparison = base._dict(base._dict(checks.get("tests"), "base recovery audit.tests", audit).get("comparison"), "base recovery audit.tests.comparison", audit)
    added = comparison.get("added_nodes")
    audit.require(isinstance(added, list) and len(added) == 1 and added[0].get("id") == EXPECTED_OLD_OBSERVER_NODE, "historical HTTP gate node changed")

    critical: dict[str, Any] = {
        "reader": inputs.get("native_reader"),
        "profile": inputs.get("profile"),
        "contract": inputs.get("contract"),
        "mcp_base_validator": inputs.get("mcp_base_validator"),
        "mcp_live_runner": inputs.get("mcp_live_runner"),
        "mcp005_live_report": inputs.get("live_report"),
        "mcp005_wire": inputs.get("mcp_wire_audit"),
        "installation": inputs.get("installation"),
        "native_capture": inputs.get("native_capture"),
        "native_report": inputs.get("native_report"),
        "fixture": inputs.get("fixture"),
        "serve": base._dict(inputs.get("mcp_closure_sources"), "base recovery mcp_closure_sources", audit).get("tools/serve_information.py"),
        "closure": inputs.get("mcp_server_closure"),
    }
    pins: dict[str, dict[str, Any]] = {}
    for label, item in critical.items():
        record = _pin_current(audit, item, f"base recovery {label}")
        if record:
            pins[label] = record
    audit.inputs["base_recovery_critical_pins"] = pins
    audit.require(pins.get("reader", {}).get("sha256") == inputs.get("native_reader", {}).get("sha256"), "N04 reader changed from recovery audit")
    audit.require(pins.get("profile", {}).get("sha256") == inputs.get("profile", {}).get("sha256"), "N04 profile changed from recovery audit")
    audit.require(pins.get("contract", {}).get("sha256") == inputs.get("contract", {}).get("sha256"), "N04 contract changed from recovery audit")
    audit.require(pins.get("serve", {}).get("sha256") == base._dict(inputs.get("mcp_closure_sources"), "base recovery mcp_closure_sources", audit).get("tools/serve_information.py", {}).get("sha256"), "information serve source changed from recovery audit")
    return old


def _validate_helper_and_hooks(audit: base.Audit, source_paths: set[str]) -> None:
    helper = ROOT / "bridge/http_rejection.py"
    try:
        tree = ast.parse(helper.read_text(encoding="utf-8"), filename=str(helper))
    except (OSError, UnicodeError, SyntaxError) as exc:
        audit.errors.append(f"HTTP rejection helper AST invalid: {exc}")
        return
    constants: dict[str, Any] = {}
    function = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value_node = node.value
            for target in targets:
                if isinstance(target, ast.Name) and target.id in EXPECTED_HELPER_CONSTANTS:
                    constants[target.id] = _static_number(value_node)
        if isinstance(node, ast.FunctionDef) and node.name == "discard_rejected_body":
            function = node
    audit.require(constants == EXPECTED_HELPER_CONSTANTS, "HTTP rejection helper constants/signature contract changed")
    if function is None:
        audit.errors.append("HTTP rejection helper discard_rejected_body is missing")
    else:
        positional = function.args.posonlyargs + function.args.args
        audit.require([arg.arg for arg in positional] == ["handler"], "HTTP rejection helper must expose discard_rejected_body(handler) only")
        audit.require(function.args.vararg is None and function.args.kwarg is None and not function.args.kwonlyargs, "HTTP rejection helper has configurable body/deadline parameters")
    for path_value in ("bridge/diplomacy_observer_service.py", "bridge/tag_command_service.py"):
        try:
            path = ROOT / Path(*path_value.split("/"))
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
            imports = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == "bridge.http_rejection" and any(alias.name == "discard_rejected_body" for alias in node.names)]
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "discard_rejected_body"]
            audit.require(bool(imports) and bool(calls), f"HTTP rejection hook missing from {path_value}")
        except (OSError, UnicodeError, SyntaxError) as exc:
            audit.errors.append(f"HTTP rejection hook invalid {path_value}: {exc}")
    audit.require(source_paths == EXPECTED_HTTP_PATHS, "HTTP report source path set is not exactly 3 production plus 3 test files")


def _validate_http_report(audit: base.Audit, report_path: str, old_report_path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rel, file, report = _load_json(report_path)
    report_sha = _sha256(file)
    audit.inputs["http_report"] = {"path": rel, "bytes": file.stat().st_size, "sha256": report_sha}
    audit.require(report_sha == EXPECTED_HTTP_REPORT_SHA256, "HTTP report-002 SHA changed")
    audit.require(report.get("schema") == EXPECTED_HTTP_REPORT_SCHEMA, "HTTP report schema changed")
    implementation = base._dict(report.get("implementation"), "HTTP report.implementation", audit)
    audit.require(implementation.get("backend_observe_publish_called_by_cleanup") is False and implementation.get("business_behavior_preserved") is True, "HTTP cleanup business-behavior guard failed")
    audit.require(implementation.get("fixed_deadline_seconds") == 0.2 and implementation.get("fixed_max_rejection_body") == 65536 and implementation.get("fixed_read_chunk") == 8192, "HTTP cleanup limits changed")
    audit.require(implementation.get("public_helper_parameters") == "handler only; body and deadline limits are not caller-configurable", "HTTP helper public signature narrative changed")
    verification = base._dict(report.get("verification"), "HTTP report.verification", audit)
    for key, expected in (("passed", 36), ("subtests", 113), ("failed", 0), ("errors", 0)):
        audit.require(verification.get(key) == expected, f"HTTP report verification {key} changed")
    audit.require(verification.get("py_compile") is True and verification.get("diff_check") is True and verification.get("game_or_business_dispatch") is False and verification.get("full_suite") is False, "HTTP report verification guard failed")
    source_files = base._dict(report.get("source_files"), "HTTP report.source_files", audit)
    source_paths = set(source_files)
    _validate_helper_and_hooks(audit, source_paths)
    records: list[dict[str, Any]] = []
    for path_value, pin in source_files.items():
        label = f"HTTP report.source_files.{path_value}"
        try:
            if path_value not in EXPECTED_HTTP_PATHS:
                raise base.AuditError("unexpected HTTP source path")
            if not isinstance(pin, dict):
                raise base.AuditError("source pin is not an object")
            rel_source, source = base._bounded_path(path_value)
            expected_bytes = pin.get("bytes")
            audit.require(_is_int(expected_bytes) and source.stat().st_size == expected_bytes, f"HTTP source byte count mismatch: {rel_source}")
            raw_sha = base._hex_sha(pin.get("raw_sha256"), label + ".raw_sha256")
            lf_sha = base._hex_sha(pin.get("lf_normalized_sha256"), label + ".lf_normalized_sha256")
            audit.require(_sha256(source) == raw_sha, f"HTTP source raw SHA mismatch: {rel_source}")
            audit.require(_lf_sha256(source) == lf_sha, f"HTTP source LF-normalized SHA mismatch: {rel_source}")
            records.append({"path": rel_source, "bytes": source.stat().st_size, "sha256": raw_sha, "role": "http-controlled-source", "kind": "http_production_or_test"})
        except base.AuditError as exc:
            audit.errors.append(str(exc))
    prior = base._dict(report.get("prior_diagnostic"), "HTTP report.prior_diagnostic", audit)
    prior_record = _pin_path_sha(audit, prior, "HTTP prior diagnostic")
    if prior_record:
        audit.inputs["http_prior_diagnostic"] = prior_record
    supersedes = report.get("supersedes")
    try:
        old_rel, old_file = base._bounded_path(supersedes)
        old_record = {"path": old_rel, "bytes": old_file.stat().st_size, "sha256": _sha256(old_file), "role": "http_previous_report", "kind": "historical_http_diagnostic"}
        audit.inputs["http_previous_report"] = old_record
        audit.require(old_rel == old_report_path.replace("\\", "/"), "HTTP report supersedes path changed")
    except base.AuditError as exc:
        audit.errors.append(f"HTTP report supersedes: {exc}")
    report_files = [*records]
    if prior_record:
        report_files.append({**prior_record, "role": "http_prior_diagnostic", "kind": "historical_http_diagnostic"})
    if source_paths != EXPECTED_HTTP_PATHS or len(records) != len(EXPECTED_HTTP_PATHS):
        audit.errors.append("HTTP report source pins are incomplete")
    audit.inputs["http_source_files"] = records
    return report, report_files


def _collect_pins(value: Any, label: str, out: list[tuple[str, dict[str, Any]]], depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and ("sha256" in value or "bytes" in value):
            out.append((label, value))
            return
        for key, child in value.items():
            _collect_pins(child, f"{label}.{key}", out, depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _collect_pins(child, f"{label}[{index}]", out, depth + 1)


def _validate_http_source_snapshot(
    audit: base.Audit,
    summary: dict[str, Any],
    old_audit: dict[str, Any],
    http_source_pins: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    source = base._dict(summary.get("source_files"), "HTTP test summary.source_files", audit)
    # This batch's full run is full001; full002 belongs to the preceding
    # recovery batch and must not be substituted silently.
    required = {"before_full001", "after_full001", "changed", "missing_after", "before_snapshot", "after_snapshot", "count", "all_unchanged"}
    audit.require(required <= set(source), "HTTP test summary source_files metadata is incomplete")
    before = source.get("before_full001")
    after = source.get("after_full001")
    audit.require(isinstance(before, dict) and isinstance(after, dict), "HTTP test summary before/after source maps are missing")
    audit.require(_is_int(source.get("count")) and source.get("count") == 82, "HTTP test summary source pin count is not 82")
    audit.require(source.get("changed") == [] and source.get("missing_after") == [] and source.get("all_unchanged") is True, "HTTP test summary source snapshot changed/missing guard failed")
    old_files = base._dict(base._dict(old_audit.get("inputs"), "base recovery inputs", audit).get("test_summary_source_snapshot"), "base recovery source snapshot", audit).get("files")
    old_map: dict[str, str] = {}
    if isinstance(old_files, list):
        for row in old_files:
            if isinstance(row, dict) and isinstance(row.get("path"), str) and isinstance(row.get("sha256"), str):
                old_map[row["path"]] = row["sha256"].lower()
    expected_paths = set(old_map) | EXPECTED_HTTP_PATHS
    audit.require(len(old_map) == 76 and set(before or {}) == expected_paths and set(after or {}) == expected_paths, "HTTP test summary source path set is not old76 plus HTTP6")
    source_records: list[dict[str, Any]] = []
    if isinstance(before, dict) and isinstance(after, dict):
        for path_value in sorted(expected_paths):
            try:
                before_sha = base._hex_sha(before.get(path_value), f"HTTP source snapshot before {path_value}")
                after_sha = base._hex_sha(after.get(path_value), f"HTTP source snapshot after {path_value}")
                audit.require(before_sha == after_sha, f"HTTP source snapshot changed: {path_value}")
                expected_sha = http_source_pins.get(path_value, old_map.get(path_value))
                audit.require(expected_sha is not None and before_sha == expected_sha.lower(), f"HTTP source snapshot SHA does not match controlled source: {path_value}")
                rel, file = base._bounded_path(path_value)
                actual_sha = _sha256(file)
                audit.require(actual_sha == before_sha, f"HTTP source current SHA mismatch: {rel}")
                source_records.append({"path": rel, "bytes": file.stat().st_size, "sha256": actual_sha, "role": "full-test-source-snapshot", "kind": "source_code_or_fixture"})
            except base.AuditError as exc:
                audit.errors.append(str(exc))
    snapshots: list[dict[str, Any]] = []
    for name in ("before_snapshot", "after_snapshot"):
        pin = source.get(name)
        record = _pin_current(audit, pin, f"HTTP test summary.source_files.{name}") if isinstance(pin, dict) else None
        if record:
            snapshots.append({**record, "role": f"http-test-summary-{name}", "kind": "source_pin_snapshot"})
    audit.inputs["http_test_source_snapshot"] = {
        "count": source.get("count"),
        "all_unchanged": source.get("all_unchanged"),
        "changed": source.get("changed"),
        "missing_after": source.get("missing_after"),
        "before_snapshot": snapshots[0] if snapshots else None,
        "after_snapshot": snapshots[1] if len(snapshots) > 1 else None,
        "files": source_records,
    }
    return source_records, snapshots


def _validate_relation_source_audit(
    audit: base.Audit,
    path: str,
    old_audit: dict[str, Any],
    http_source_pins: dict[str, str],
) -> dict[str, Any]:
    """Validate the one explained relation pin transition explicitly.

    The changed relation message is retained as evidence.  It is accepted
    only after checking its old 1.375 manifest pin and the current 1.37.4
    information adapter independently; this is narrower than ignoring all
    semantic message changes.
    """

    rel, file, report = _load_json(path)
    audit.inputs["relation_source_audit"] = {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file)}
    audit.require(report.get("schema") == EXPECTED_RELATION_AUDIT_SCHEMA, "relation source audit schema changed")
    audit.require(report.get("status") == EXPECTED_RELATION_AUDIT_STATUS, "relation source audit status changed")
    node = base._dict(report.get("node"), "relation source audit.node", audit)
    audit.require(node.get("id") == EXPECTED_RELATION_NODE_ID, "relation source semantic node changed")
    old_node = base._dict(node.get("old"), "relation source audit.node.old", audit)
    new_node = base._dict(node.get("new"), "relation source audit.node.new", audit)
    audit.require(str(old_node.get("message", "")).startswith(EXPECTED_RELATION_OLD_MESSAGE), "relation old exception changed")
    audit.require(new_node.get("message") == EXPECTED_RELATION_NEW_MESSAGE, "relation new exception changed")
    for label, xml in (("old relation XML", old_node.get("xml_file")), ("new relation XML", new_node.get("xml_file"))):
        _pin_current(audit, xml, label)

    manifest = base._dict(report.get("old_1375_host_manifest"), "relation source audit.old_1375_host_manifest", audit)
    audit.require(manifest.get("path") == EXPECTED_RELATION_MANIFEST_PATH, "old 1.375 manifest path changed")
    manifest_file = _pin_current(audit, manifest.get("file"), "old 1.375 relation host manifest")
    audit.require(manifest_file is not None and manifest_file.get("sha256") == EXPECTED_RELATION_MANIFEST_SHA256, "old 1.375 relation host manifest changed")
    audit.require(manifest.get("schema") == "EU4-RELATION-STATE-HOST-MANIFEST/1", "old relation host manifest schema changed")
    audit.require(manifest.get("read_only") is True and manifest.get("native_calls") == 0, "old relation host manifest read-only boundary changed")
    manifest_pins = base._dict(manifest.get("source_pins"), "old relation host manifest.source_pins", audit)
    old_observer_pin = base._dict(manifest_pins.get("bridge/diplomacy_observer_service.py"), "old relation observer manifest pin", audit)
    audit.require(old_observer_pin.get("bytes") == 4598 and old_observer_pin.get("sha256") == "139727da50f8357418fb9885b7b0415b146081de8fd05b9497835d6b5a5066ec", "old relation observer manifest pin changed")

    current = base._dict(report.get("current_1374_information_r02"), "relation source audit.current_1374_information_r02", audit)
    adapter = base._dict(current.get("adapter"), "current R02 adapter", audit)
    audit.require(adapter.get("game_version") == "1.37.4" and adapter.get("game_sha256") == "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77", "current R02 identity changed")
    audit.require(adapter.get("public_reader") == "DiplomacyTools.inspect_diplomatic_action", "current R02 public reader changed")
    audit.require(adapter.get("profile_paths") == [] and adapter.get("relation_manifest_paths") == [], "current R02 acquired an old relation/profile dependency")
    direct_imports = base._dict(adapter.get("direct_http_or_relation_host_imports"), "current R02 old-host dependency checks", audit)
    audit.require(direct_imports == {key: False for key in direct_imports}, "current R02 old HTTP/relation host dependency detected")
    adapter_file = _pin_current(audit, adapter.get("file"), "current R02 relation adapter")
    audit.require(adapter.get("path") == "bridge/information/subject_relations.py", "current R02 adapter path changed")
    serve = base._dict(current.get("serve_wiring"), "current R02 serve wiring", audit)
    serve_file = _pin_current(audit, serve.get("file"), "current R02 information serve")
    audit.require(serve.get("path") == "tools/serve_information.py", "current R02 serve path changed")
    base_source = base._dict(current.get("base_source"), "current R02 base source", audit)
    base_file = _pin_current(audit, base_source.get("file"), "current R02 information base source")

    observer_pin = base._dict(manifest.get("observer_source_pin"), "old observer source pin", audit)
    current_worktree = _pin_current(audit, observer_pin.get("current_worktree"), "current observer HTTP source")
    audit.require(current_worktree is not None and http_source_pins.get("bridge/diplomacy_observer_service.py") == current_worktree.get("sha256"), "relation audit observer pin differs from HTTP report-002")
    helper = base._dict(observer_pin.get("http_helper"), "relation observer HTTP helper pin", audit)
    helper_record = _pin_current(audit, helper, "current HTTP rejection helper")
    audit.require(helper_record is not None and http_source_pins.get("bridge/http_rejection.py") == helper_record.get("sha256"), "relation audit HTTP helper pin differs from HTTP report-002")

    old_inputs = base._dict(old_audit.get("inputs"), "base recovery inputs for relation compatibility", audit)
    old_serve = base._dict(base._dict(old_inputs.get("mcp_closure_sources"), "base recovery closure sources", audit).get("tools/serve_information.py"), "base recovery serve pin", audit)
    audit.require(serve_file is not None and serve_file.get("sha256") == old_serve.get("sha256"), "current R02 serve changed from recovery pin")
    audit.require(adapter_file is not None and base_file is not None, "current R02 source pins are incomplete")
    decision = base._dict(current.get("decision"), "current R02 decision", audit)
    audit.require(decision.get("http_source_pin_rejected_by_current_r02_live_reader") is False, "current R02 incorrectly rejected by old HTTP source pin")
    audit.require(decision.get("new_information_profile_or_real_capture_needed_for_this_node") is False, "relation audit incorrectly requires a new R02 capture")
    verification = base._dict(report.get("verification"), "relation source audit.verification", audit)
    audit.require(verification.get("pins_or_hashes_updated") is False and verification.get("existing_reports_modified") is False and verification.get("native_or_game_run") is False and verification.get("rea_run") is False, "relation audit performed an unapproved mutation or runtime action")
    audit.inputs["relation_semantic_transition"] = {
        "node_id": node.get("id"),
        "old_message": old_node.get("message"),
        "new_message": new_node.get("message"),
        "old_manifest": manifest_file,
        "current_observer": current_worktree,
        "current_adapter": adapter_file,
        "current_serve": serve_file,
        "current_base_source": base_file,
        "compatibility": "historical 1.375 relation guard only; current 1.37.4 R02 path remains independent",
    }
    return report


def _validate_semantic_message_set(audit: base.Audit, comparison: dict[str, Any]) -> list[dict[str, Any]]:
    raw = comparison.get("raw_message_changed_nodes")
    audit.require(isinstance(raw, list) and set(raw) == EXPECTED_RELATION_MESSAGE_IDS and len(raw) == len(EXPECTED_RELATION_MESSAGE_IDS), "semantic message node set changed")
    semantic = comparison.get("semantic_message_changes")
    audit.require(isinstance(semantic, list) and {item.get("id") for item in semantic if isinstance(item, dict)} == EXPECTED_RELATION_MESSAGE_IDS and len(semantic) == len(EXPECTED_RELATION_MESSAGE_IDS), "semantic message records are incomplete")
    for item in semantic:
        if not isinstance(item, dict):
            audit.errors.append("semantic message record is not an object")
            continue
        identifier = item.get("id")
        messages = item.get("messages")
        audit.require(item.get("raw_message_changed") is True and isinstance(messages, list) and len(messages) == 1, f"semantic message record malformed: {identifier}")
        if identifier == EXPECTED_RELATION_NODE_ID:
            audit.require(item.get("semantic_equal_after_tempdir_and_address_normalization") is False, "relation semantic change was silently normalized away")
            if isinstance(messages, list) and messages and isinstance(messages[0], dict):
                msg = messages[0]
                audit.require(msg.get("baseline_sha256") == "d77c452a8ede69a978b569abca0964c1847d5d7268f59bbcb92dc36d2c2b0ce7" and msg.get("current_sha256") == "a45e377cef1317671772cc20c126c20386396d780d2c920f4c26155c19aa9143", "relation semantic message hashes changed")
        else:
            audit.require(item.get("semantic_equal_after_tempdir_and_address_normalization") is True, f"unexpected semantic change in {identifier}")
            if isinstance(messages, list) and messages and isinstance(messages[0], dict):
                msg = messages[0]
                audit.require(msg.get("semantic_equal") is True and msg.get("baseline_normalized_sha256") == msg.get("current_normalized_sha256"), f"non-semantic traceback change not normalized for {identifier}")
    return semantic


def _validate_http_test_summary(audit: base.Audit, path: str, old_audit: dict[str, Any], http_source_pins: dict[str, str]) -> dict[str, Any]:
    rel, file, summary = _load_json(path)
    audit.inputs["http_test_summary"] = {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file)}
    audit.require(isinstance(summary.get("schema"), str), "HTTP test summary schema is missing")
    info = base._dict(summary.get("information"), "HTTP test summary.information", audit)
    info_result = base._dict(info.get("reported_result"), "HTTP test summary.information.reported_result", audit)
    audit.require(info_result.get("failed") == 0 and info_result.get("errors") == 0, "HTTP information tests contain failures/errors")
    full = base._dict(summary.get("full"), "HTTP test summary.full", audit)
    full_result = base._dict(full.get("reported_result"), "HTTP test summary.full.reported_result", audit)
    audit.require(_is_int(full_result.get("failed")) and _is_int(full_result.get("errors")), "HTTP full test counts are missing")
    audit.require(summary.get("full_suite_passed") is False and summary.get("full_exit_code") == 1, "HTTP full-test negative status boundary changed")
    comparison_parent = base._dict(summary.get("comparison_to_previous_batch"), "HTTP test summary.comparison_to_previous_batch", audit)
    comparison = base._dict(comparison_parent.get("failure_error_nodes"), "HTTP test summary.failure_error_nodes", audit)
    added = comparison.get("new_failure_or_error_nodes")
    audit.require(isinstance(added, list) and not added, "HTTP full run introduced a new failure/error node")
    audit.require(comparison.get("baseline_nodes") == 142 and comparison.get("current_nodes") == 142 and comparison.get("persistent_nodes") == 142, "HTTP full failure/error baseline counts changed")
    semantic_messages = _validate_semantic_message_set(audit, comparison_parent)
    http_source_records, snapshots = _validate_http_source_snapshot(audit, summary, old_audit, http_source_pins)
    artifact_candidates: list[tuple[str, dict[str, Any]]] = []
    for name in ("artifacts_preserved", "previous_recovery", "full", "information", "artifacts"):
        if name in summary:
            _collect_pins(summary.get(name), f"HTTP test summary.{name}", artifact_candidates)
    artifact_records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in snapshots:
        if record["path"] not in seen:
            artifact_records.append({**record, "name": "HTTP test summary source snapshot"})
            seen.add(record["path"])
    for label, item in artifact_candidates:
        record = _pin_current(audit, item, label)
        if record and record["path"] not in seen:
            artifact_records.append({**record, "name": label})
            seen.add(record["path"])
    preserved = summary.get("artifacts_preserved")
    audit.require(isinstance(preserved, dict) and bool(preserved), "HTTP test summary artifacts_preserved is missing")
    audit.inputs["http_test_artifact_pins"] = artifact_records
    audit.inputs["semantic_message_changes"] = semantic_messages
    return {"summary": summary, "source_records": http_source_records, "artifacts": artifact_records, "semantic_message_changes": semantic_messages}


def _validate_runtime_reuse(audit: base.Audit) -> dict[str, Any]:
    """Pin the read-only game health/control receipts used by this batch."""

    check_rel, check_file, check = _load_json(HTTP_RUNTIME_CHECK)
    control_rel, control_file, control = _load_json(HTTP_RUNTIME_CONTROL)
    check_record = {"path": check_rel, "bytes": check_file.stat().st_size, "sha256": _sha256(check_file)}
    control_record = {"path": control_rel, "bytes": control_file.stat().st_size, "sha256": _sha256(control_file)}
    audit.require(check.get("schema") == "information-http-recovery-runtime-check-v1" and check.get("status") == "passed", "runtime check receipt changed")
    audit.require(check.get("pid") == 42328 and check.get("creation_filetime") == 134373859476226811 and check.get("session_id") == "42328-1dd6450312dc2fb", "runtime identity receipt changed")
    audit.require(check.get("installation_sha256") == "2740d869fa4d0a615a57dc328349f00416e4bcaf1e8c3c890e8d9d81a697cba9", "runtime installation receipt changed")
    health = base._dict(check.get("health"), "runtime check health", audit)
    audit.require(health.get("status") == "ready" and health.get("date_raw") == 56553384 and health.get("complete") is True and health.get("reasons") == [], "runtime health/date receipt changed")
    audit.require(check.get("control_file") == HTTP_RUNTIME_CONTROL, "runtime check/control link changed")
    audit.require(control.get("pid") == 42328 and control.get("read_only") is True and control.get("player_slot") == 189 and control.get("date_raw") == 56553384 and control.get("speed") == 0 and control.get("paused_flag") == 1, "runtime control receipt changed")
    audit.require(control.get("pause_vector_begin") == "0x0" and control.get("pause_vector_end") == "0x0", "runtime pause receipt changed")
    audit.inputs["runtime_reuse"] = {"check": check_record, "control": control_record, "scope": check.get("scope")}
    return {"check": check_record, "control": control_record}


def _validate_scalar_research(audit: base.Audit) -> dict[str, Any]:
    """Validate the three static scalar REA records without reading caches."""

    index_rel, index_file, index = _load_json(SCALAR_INDEX)
    source_rel, source_file, source = _load_json(SCALAR_SOURCE_AUDIT)
    writer_rel, writer_file, writer = _load_json(SCALAR_WRITER_LEDGER)
    index_record = {"path": index_rel, "bytes": index_file.stat().st_size, "sha256": _sha256(index_file), "role": "scalar_research_index", "kind": "static_research_index"}
    source_record = {"path": source_rel, "bytes": source_file.stat().st_size, "sha256": _sha256(source_file), "role": "scalar_source_audit", "kind": "static_source_audit"}
    writer_record = {"path": writer_rel, "bytes": writer_file.stat().st_size, "sha256": _sha256(writer_file), "role": "scalar_writer_ledger", "kind": "static_derived_ledger"}
    audit.require(index_record["sha256"] == SCALAR_INDEX_SHA256, "scalar research index SHA changed")
    audit.require(source_record["sha256"] == SCALAR_SOURCE_AUDIT_SHA256, "scalar source audit SHA changed")
    audit.require(writer_record["sha256"] == SCALAR_WRITER_LEDGER_SHA256, "scalar writer ledger SHA changed")
    target_sha = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
    audit.require(index.get("status") == "static_research_frozen" and index.get("read_only") is True and index.get("runtime_observed") is False, "scalar index status/runtime boundary changed")
    audit.require(base._dict(index.get("target_build"), "scalar index target_build", audit).get("executable_sha256") == target_sha, "scalar index EXE identity changed")
    audit.require(source.get("status") == "passed_static_source_audit" and source.get("runtime_observed") is False and source.get("target_exe_sha256") == target_sha, "scalar source audit status/identity changed")
    audit.require(writer.get("status") == "static_evidence_collected" and writer.get("runtime_observed") is False and writer.get("target_build", {}).get("executable_sha256") == target_sha, "scalar writer ledger status/identity changed")
    audit.require(base._dict(source.get("research_index"), "scalar source audit research_index", audit).get("sha256") == SCALAR_INDEX_SHA256, "scalar source audit index pin changed")

    evidence_rows = index.get("rea_evidence")
    audit.require(isinstance(evidence_rows, list) and len(evidence_rows) == 3, "scalar REA evidence count changed")
    rea_records: list[dict[str, Any]] = []
    cache_paths: list[str] = []
    for number, row in enumerate(evidence_rows if isinstance(evidence_rows, list) else []):
        item = base._dict(row, f"scalar rea_evidence[{number}]", audit)
        evidence = base._dict(item.get("evidence"), f"scalar rea_evidence[{number}].evidence", audit)
        request = base._dict(item.get("request"), f"scalar rea_evidence[{number}].request", audit)
        run = base._dict(item.get("run"), f"scalar rea_evidence[{number}].run", audit)
        evidence_rel, evidence_file = base._bounded_path(evidence.get("path"))
        request_rel, request_file = base._bounded_path(request.get("path"))
        run_rel, run_file = base._bounded_path(run.get("path"))
        evidence_sha = _sha256(evidence_file)
        request_sha = _sha256(request_file)
        run_sha = _sha256(run_file)
        audit.require(evidence_sha == evidence.get("sha256"), f"scalar evidence SHA mismatch: {evidence_rel}")
        audit.require(request_sha == request.get("sha256"), f"scalar request SHA mismatch: {request_rel}")
        audit.require(run_sha == run.get("sha256"), f"scalar run SHA mismatch: {run_rel}")
        audit.require(evidence.get("target_exe_sha256") == target_sha and isinstance(evidence.get("evidence_id"), str), f"scalar evidence identity changed: {evidence_rel}")
        audit.require(request.get("java_heap") == "512M" and request.get("query_reanalysis") is False and request.get("process_memory_limit_bytes") == 1073741824, f"scalar request guard changed: {request_rel}")
        profile = base._dict(item.get("profile"), f"scalar rea_evidence[{number}].profile", audit)
        cache = base._dict(item.get("cache"), f"scalar rea_evidence[{number}].cache", audit)
        cache_paths.append(cache.get("path"))
        audit.require(profile.get("sha256") == SCALAR_PROFILE_SHA256 and profile.get("completed_manifest_sha256") == SCALAR_MANIFEST_SHA256 and profile.get("completed_database_sha256") == SCALAR_DATABASE_SHA256 and profile.get("query_reanalysis") is False, f"scalar profile guard changed: {evidence_rel}")
        audit.require(cache.get("adapter_sha256") == SCALAR_ADAPTER_SHA256 and cache.get("completed_manifest_sha256") == SCALAR_MANIFEST_SHA256 and cache.get("completed_database_sha256") == SCALAR_DATABASE_SHA256, f"scalar cache guard changed: {evidence_rel}")
        request_payload = json.loads(request_file.read_text(encoding="utf-8"))
        run_payload = json.loads(run_file.read_text(encoding="utf-8"))
        audit.require(request_payload.get("target_sha256") == target_sha and request_payload.get("cache") == cache.get("path") and request_payload.get("adapter_sha256") == SCALAR_ADAPTER_SHA256 and request_payload.get("completed_manifest_sha256") == SCALAR_MANIFEST_SHA256 and request_payload.get("completed_database_sha256") == SCALAR_DATABASE_SHA256, f"scalar request provenance changed: {request_rel}")
        audit.require(run_payload.get("exit_code") == 0 and run_payload.get("reason") == "completed" and run_payload.get("database_unchanged") is True and run_payload.get("evidence_id") == evidence.get("evidence_id"), f"scalar run guard changed: {run_rel}")
        processes = run_payload.get("processes")
        audit.require(isinstance(processes, list) and len(processes) == 1 and processes[0].get("still_running_same_process") is False and type(processes[0].get("peak_committed_bytes")) is int and processes[0].get("peak_committed_bytes") < 1073741824, f"scalar process guard changed: {run_rel}")
        rea_records.extend([
            {"path": evidence_rel, "bytes": evidence_file.stat().st_size, "sha256": evidence_sha, "role": "scalar_rea_evidence", "kind": "rea_evidence"},
            {"path": request_rel, "bytes": request_file.stat().st_size, "sha256": request_sha, "role": "scalar_rea_request", "kind": "rea_request"},
            {"path": run_rel, "bytes": run_file.stat().st_size, "sha256": run_sha, "role": "scalar_rea_run", "kind": "rea_run"},
        ])
    audit.require(len(set(cache_paths)) == 1 and isinstance(cache_paths[0], str), "scalar REA cache provenance changed")
    for directory in SCALAR_REA_DIRS:
        for name in SCALAR_REA_FILES:
            rel_path = f"{directory}/{name}"
            try:
                rel, file = base._bounded_path(rel_path)
                audit.require(file.is_file(), f"scalar REA tail/source missing: {rel}")
                rea_records.append({"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file), "role": "scalar_rea_support", "kind": "rea_tail_or_log"})
            except base.AuditError as exc:
                audit.errors.append(str(exc))
    unique_rea_records: dict[str, dict[str, Any]] = {}
    for record in rea_records:
        unique_rea_records.setdefault(record["path"], record)
    rea_records = list(unique_rea_records.values())
    audit.require(len(rea_records) == 18, "scalar REA source record set is incomplete")
    script_records: list[dict[str, Any]] = []
    for path_value in SCALAR_SCRIPTS:
        rel, file = base._bounded_path(path_value)
        digest = _sha256(file)
        audit.require(digest == SCALAR_SCRIPT_SHA256[path_value], f"scalar research script SHA changed: {rel}")
        script_records.append({"path": rel, "bytes": file.stat().st_size, "sha256": digest, "role": "scalar_research_script", "kind": "reproducibility_script"})
    unit_rel, unit_file = base._bounded_path(UNIT_DISPLAY_LEDGER)
    unit_sha = _sha256(unit_file)
    audit.require(unit_sha == UNIT_DISPLAY_LEDGER_SHA256, "unit display ledger SHA changed")
    unit_record = {"path": unit_rel, "bytes": unit_file.stat().st_size, "sha256": unit_sha, "role": "battle_unit_display_ledger", "kind": "static_derived_ledger"}
    audit.inputs["scalar_static_research"] = {
        "index": index_record,
        "source_audit": source_record,
        "writer_ledger": writer_record,
        "rea_records": rea_records,
        "scripts": script_records,
        "unit_display_ledger": unit_record,
        "target_exe_sha256": target_sha,
        "runtime_observed": False,
        "profile_cache_guard": {
            "profile_sha256": SCALAR_PROFILE_SHA256,
            "adapter_sha256": SCALAR_ADAPTER_SHA256,
            "completed_manifest_sha256": SCALAR_MANIFEST_SHA256,
            "completed_database_sha256": SCALAR_DATABASE_SHA256,
            "cache_path": cache_paths[0],
            "query_reanalysis": False,
            "cache_copied": False,
        },
    }
    return {"index": index_record, "source_audit": source_record, "writer_ledger": writer_record, "rea_records": rea_records, "scripts": script_records, "unit_display_ledger": unit_record}


def _build_old_recovery_records(audit: base.Audit, old_summary_path: str) -> list[dict[str, Any]]:
    """Reconstruct the old explicit recovery source list without writing it."""

    args = base._parser().parse_args(["--test-summary", old_summary_path])
    subaudit = base.Audit()
    profile, contract, profile_deps, profile_refs = base._validate_profile_contract(subaudit, args.profile, args.contract)
    capture, native_report, native_meta = base._validate_native_capture(subaudit, args.native_capture, args.native_report, args.installation, profile)
    live_report, live_meta = base._validate_live(subaudit, args.live_report, args.live_dir, capture, native_meta, args.installation)
    test_data = base._validate_test_summary(subaudit, args.test_summary, args.test_summary_baseline)
    battle = base._validate_battle_pins(subaudit, args.battle_index, args.battle_source_audit, args.queue_report)
    unexpected = [error for error in subaudit.errors if error != EXPECTED_OLD_RECOVERY_ERROR]
    audit.require(not unexpected, f"base recovery source revalidation errors changed: {unexpected}")
    records = base._archive_sources(subaudit, args, profile_refs, native_meta, battle, test_data)
    return records


def _add_record(audit: base.Audit, records: dict[str, dict[str, Any]], path: str | Path, *, role: str, kind: str) -> None:
    try:
        rel, file = base._bounded_path(path)
        records.setdefault(rel, {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file), "role": role, "kind": kind})
    except base.AuditError as exc:
        audit.errors.append(f"archive source {path}: {exc}")


def _copy_archive(stage: Path, records: list[dict[str, Any]], metadata: dict[str, Any], revision: str) -> Path:
    delivery = stage / "delivery"
    if delivery.exists():
        raise base.AuditError(f"refusing to overwrite existing delivery: {delivery}")
    total = sum(record["bytes"] for record in records)
    if any(record["bytes"] > MAX_SINGLE_BYTES for record in records):
        raise base.AuditError("HTTP archive contains a file over the 16 MiB bound")
    if total > MAX_TOTAL_BYTES:
        raise base.AuditError(f"HTTP archive exceeds 128 MiB: {total}")
    temp = stage / f".delivery-{revision}.tmp"
    if temp.exists():
        raise base.AuditError(f"refusing to overwrite temporary delivery: {temp}")
    temp.mkdir(parents=True)
    copied: list[dict[str, Any]] = []
    try:
        for record in records:
            source = ROOT / Path(*record["path"].split("/"))
            destination = temp / "files" / Path(*record["path"].split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            copied_sha = _sha256(destination)
            if copied_sha != record["sha256"] or destination.stat().st_size != record["bytes"]:
                raise base.AuditError(f"source changed while archiving: {record['path']}")
            copied.append({**record, "archive_path": (Path("files") / Path(*record["path"].split("/"))).as_posix()})
        manifest = {
            "schema": "information_http_recovery_delivery_manifest_v1",
            "revision": revision,
            "mode": "bounded_http_recovery_with_historical_information_evidence",
            "goal_complete": False,
            "base_recovery": metadata.get("base_recovery"),
            "http": metadata.get("http"),
            "tests": metadata.get("tests"),
            "evidence_boundaries": {
                "old_recovery": "historical N04/live/MCP evidence; old HTTP gate retained",
                "http_report_002": "bounded source and targeted test evidence; no full-suite claim",
                "full_tests": "old failure/error baseline must remain explicit; no new node gate",
                "goal_complete": False,
            },
            "file_count": len(copied),
            "total_bytes": total,
            "files": copied,
        }
        (temp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(delivery)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise
    return delivery


def run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    audit = base.Audit()
    stage = (ROOT / Path(*str(args.stage).replace("\\", "/").split("/"))).resolve()
    if ROOT not in stage.parents and stage != ROOT:
        raise base.AuditError("stage escapes workspace")
    try:
        stage.mkdir(parents=True, exist_ok=True)
        old_audit = _validate_old_recovery(audit, args.old_recovery_audit)
        http_report, http_report_files = _validate_http_report(audit, args.http_report, args.old_http_report)
        http_source_pins = {row["path"]: row["sha256"] for row in audit.inputs.get("http_source_files", [])}
        relation_report = _validate_relation_source_audit(audit, args.relation_source_audit, old_audit, http_source_pins)
        test_data = _validate_http_test_summary(audit, args.test_summary, old_audit, http_source_pins)
        runtime_records = _validate_runtime_reuse(audit)
        scalar_records = _validate_scalar_research(audit)
        old_records = _build_old_recovery_records(audit, args.old_test_summary)
        records_by_path: dict[str, dict[str, Any]] = {row["path"]: row for row in old_records}
        old_record_paths = set(records_by_path)
        for path_value, role, kind in (
            (args.old_recovery_audit, "base_recovery_audit", "historical_audit"),
            (args.old_http_report, "http_previous_report", "historical_http_diagnostic"),
            (args.http_report, "http_report_002", "http_report"),
            (args.relation_source_audit, "relation_source_pin_audit", "compatibility_audit"),
            (args.http_source_snapshot, "http_source_snapshot_before", "source_pin_snapshot"),
            ("work/audit_information_http_recovery_delivery.py", "http_audit_script", "reproducibility_script"),
        ):
            _add_record(audit, records_by_path, path_value, role=role, kind=kind)
        archive_delta: list[dict[str, Any]] = []
        for row in http_report_files:
            _add_record(audit, records_by_path, row["path"], role=row.get("role", "http_evidence"), kind=row.get("kind", "http_evidence"))
        for row in test_data.get("source_records", []):
            _add_record(audit, records_by_path, row["path"], role="full_test_source", kind="source_code_or_fixture")
        for row in test_data.get("artifacts", []):
            _add_record(audit, records_by_path, row["path"], role=row.get("role", "test_artifact"), kind=row.get("kind", "test_artifact"))
        _add_record(audit, records_by_path, args.test_summary, role="http_test_summary", kind="test_summary")
        for record in runtime_records.values():
            _add_record(audit, records_by_path, record["path"], role="runtime_reuse_receipt", kind="read_only_runtime_receipt")
        for key in ("index", "source_audit", "writer_ledger", "unit_display_ledger"):
            record = scalar_records[key]
            _add_record(audit, records_by_path, record["path"], role=record["role"], kind=record["kind"])
        for record in scalar_records["rea_records"] + scalar_records["scripts"]:
            _add_record(audit, records_by_path, record["path"], role=record["role"], kind=record["kind"])
        for path_value, role, kind in (
            (HTTP_DOCUMENTATION, "http_documentation", "documentation"),
            (BATTLE_DOCUMENTATION, "battle_source_documentation", "documentation"),
        ):
            _add_record(audit, records_by_path, path_value, role=role, kind=kind)
        archive_delta = [records_by_path[path] for path in sorted(set(records_by_path) - old_record_paths)]
        audit.inputs["archive_delta"] = {
            "description": "explicit HTTP, runtime, scalar-research, unit-display and documentation additions; no recursive old delivery",
            "source_count": len(archive_delta),
            "total_bytes": sum(row["bytes"] for row in archive_delta),
            "files": archive_delta,
        }
        audit_record: dict[str, Any] = {
            "schema": "information_http_recovery_delivery_audit_v1",
            "status": "passed" if not audit.errors else "failed",
            "mode": "offline_bounded_http_audit",
            "goal_complete": False,
            "bounds": {"max_single_file_bytes": MAX_SINGLE_BYTES, "max_archive_bytes": MAX_TOTAL_BYTES},
            "inputs": audit.inputs,
            "checks": {
                "base_recovery": {"status": "historical_failed_expected_http_gate", "old_error": EXPECTED_OLD_RECOVERY_ERROR},
                "http": {"status": http_report.get("schema"), "verification": http_report.get("verification"), "source_count": len(audit.inputs.get("http_source_files", []))},
                "relation_compatibility": {"status": relation_report.get("status"), "node_id": relation_report.get("node", {}).get("id"), "old_manifest_sha256": EXPECTED_RELATION_MANIFEST_SHA256},
                "runtime_reuse": {"status": "passed", "same_pid": 42328, "date_raw": 56553384, "paused": 1, "read_only": True},
                "scalar_static_research": {"status": "passed", "rea_count": 3, "runtime_observed": False, "target_exe_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"},
                "tests": {"status": "full_negative_baseline_guard", "comparison": test_data.get("summary", {}).get("comparison_to_previous_batch"), "semantic_message_changes": test_data.get("semantic_message_changes")},
            },
            "archive": {"status": "not_requested", "source_count": 0, "total_bytes": 0},
            "warnings": audit.warnings,
            "errors": audit.errors,
        }
        if (args.archive or args.plan_archive) and not audit.errors:
            records = list(records_by_path.values())
            audit_record["archive"] = {"status": "planned", "source_count": len(records), "total_bytes": sum(row["bytes"] for row in records)}
            if args.archive:
                delivery = _copy_archive(stage, records, {"base_recovery": audit.inputs.get("base_recovery_audit"), "http": audit.inputs.get("http_report"), "tests": audit.inputs.get("http_test_summary")}, args.revision)
                audit_record["archive"] = {"status": "created", "path": delivery.relative_to(ROOT).as_posix(), "source_count": len(records), "total_bytes": sum(row["bytes"] for row in records)}
        output = stage / f"source-audit-{args.revision}.json"
        if output.exists():
            raise base.AuditError(f"refusing to overwrite audit output: {output}")
        output.write_text(json.dumps(audit_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return audit_record, 0 if audit_record["status"] == "passed" else 1
    except (base.AuditError, OSError, ValueError) as exc:
        record = {"schema": "information_http_recovery_delivery_audit_v1", "status": "failed", "mode": "offline_bounded_http_audit", "goal_complete": False, "bounds": {"max_single_file_bytes": MAX_SINGLE_BYTES, "max_archive_bytes": MAX_TOTAL_BYTES}, "errors": [str(exc)]}
        output = stage / f"source-audit-{args.revision}.json"
        if not output.exists():
            stage.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return record, 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", default="work/runtime/information-http-rejection-20261025-001")
    parser.add_argument("--revision", default="001", choices=[f"{i:03d}" for i in range(1, 1000)])
    parser.add_argument("--test-summary", required=True, help="new full/information summary after the HTTP fix")
    parser.add_argument("--old-recovery-audit", default="work/runtime/information-recovery-20261025-001/audit-002.json")
    parser.add_argument("--old-test-summary", default="work/runtime/information-recovery-20261025-001/test-summary-002.json")
    parser.add_argument("--http-report", default="work/runtime/information-http-rejection-20261025-001/report-002.json")
    parser.add_argument("--old-http-report", default="work/runtime/information-http-rejection-20261025-001/report.json")
    parser.add_argument("--http-source-snapshot", default="work/runtime/information-http-rejection-20261025-001/source-pins-before-001.json")
    parser.add_argument("--relation-source-audit", default="work/runtime/information-http-rejection-20261025-001/relation-source-pin-audit-001.json")
    parser.add_argument("--plan-archive", action="store_true", help="calculate the exact archive source count/size without copying files")
    parser.add_argument("--archive", action="store_true", help="create a new delivery only after every guard passes")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    record, code = run(args)
    print(json.dumps({"status": record.get("status"), "audit": str((ROOT / Path(*str(args.stage).replace("\\", "/").split("/")) / f"source-audit-{args.revision}.json").relative_to(ROOT)), "errors": len(record.get("errors", [])), "archive": record.get("archive", {}).get("status")}, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
