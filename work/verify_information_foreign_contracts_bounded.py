"""Prepare and run the batch-90 bridge suite serially in bounded pytest processes.

The accepted batch-89 baseline records 141 pre-existing bad occurrences. This
runner preserves actual collected node IDs and compares the full result against
that XML without treating the suite as all-green. Collection and test execution
are inert unless the explicit --run flag is supplied.
"""
from __future__ import annotations

import argparse
import collections
import copy
import ctypes
import ctypes.wintypes as wintypes
import datetime as dt
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work import verify_information_foreign_forces as parent_verifier  # noqa: E402

common = parent_verifier.common
DEFAULT_STAGE = ROOT / "work/runtime/information-foreign-economy-contracts-20261031-001"
DEFAULT_BASELINE_STAGE = ROOT / "work/runtime/information-foreign-economy-20261029-001"
DEFAULT_BASELINE_FREEZE = DEFAULT_BASELINE_STAGE / "source-freeze-001.json"
DEFAULT_BASELINE_COMPARISON = DEFAULT_BASELINE_STAGE / "regression-comparison-001.json"
DEFAULT_BASELINE_POSTVERIFY = DEFAULT_BASELINE_STAGE / "source-post-run-verification-001.json"
DEFAULT_BASELINE_XML = DEFAULT_BASELINE_STAGE / "bounded-full-001/regression-full-001.xml"
STAGE = DEFAULT_STAGE
PREPARATION = STAGE / "stage90/harness-adaptation-001"
OUT = STAGE / "bounded-full-001"
BASELINE_FREEZE = DEFAULT_BASELINE_FREEZE
BASELINE_COMPARISON = DEFAULT_BASELINE_COMPARISON
BASELINE_POSTVERIFY = DEFAULT_BASELINE_POSTVERIFY
BASELINE_XML = DEFAULT_BASELINE_XML
NEW_FREEZE = STAGE / "source-freeze-001.json"
FULL_XML = OUT / "regression-full-001.xml"
FULL_LOG = OUT / "regression-full-001.log"
COMPARISON_REPORT = STAGE / "regression-comparison-001.json"
POSTVERIFY_REPORT = STAGE / "source-post-run-verification-001.json"
RESERVATION_REPORT = OUT / "full-execution-reservation-001.json"
BOUNDARY_REPORT = OUT / "full-execution-boundary-001.json"
PROGRESS_REPORT = OUT / "batch-progress-001.jsonl"
NODEID_COVERAGE = OUT / "nodeid-coverage-001.json"
SOURCE_SNAPSHOTS = STAGE / "source-snapshots-001"
RUNNER = "work/verify_information_foreign_contracts_bounded.py"
PUBLISHER = "work/finalize_information_foreign_contracts_bounded.py"
PLUGIN_NAME = "work.verify_information_foreign_contracts_bounded"
COLLECTION_ENV = "INFORMATION_FOREIGN_CONTRACTS_NODEID_OUTPUT"
# The accepted batch-89 run peaked at 990,474,240 B. Keep the 1 GB stop
# ceiling and use a 100-node per-process cap to add memory headroom.
MAX_BATCH_ITEMS = 100
MAX_DIRECT_COMMAND_CHARS = 26000
MEMORY_STOP_BYTES = 1_000_000_000
MONITOR_INTERVAL_SECONDS = 0.5
COLLECTION_SCHEMA = "information.foreign_contracts.bounded_collection.v1"
PLAN_SCHEMA = "information.foreign_contracts.bounded_execution_plan.v1"
FREEZE_SCHEMA = "information.foreign_contracts.bounded_source_freeze.v1"
HARD_MEMORY_SCHEMA = "information.foreign_contracts.bounded_memory_sample.v1"
RESEARCH_PYTHON = common.PYTHON
pin = common.pin
read_json = common.read_json
write_new = common.write_new
copy_stream = common.copy_stream
_SOURCE_ARGUMENTS: list[str] = []
_SOURCE_LIST_PATH: Path | None = None

def _workspace_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    path.relative_to(ROOT)
    return path

def configure_paths(args: argparse.Namespace) -> None:
    global STAGE, PREPARATION, OUT, BASELINE_FREEZE, BASELINE_COMPARISON
    global BASELINE_POSTVERIFY, BASELINE_XML, NEW_FREEZE, FULL_XML, FULL_LOG
    global COMPARISON_REPORT, POSTVERIFY_REPORT, RESERVATION_REPORT, BOUNDARY_REPORT
    global PROGRESS_REPORT, NODEID_COVERAGE, SOURCE_SNAPSHOTS, _SOURCE_ARGUMENTS
    global _SOURCE_LIST_PATH
    STAGE = _workspace_path(args.stage)
    PREPARATION = STAGE / "stage90/harness-adaptation-001"
    OUT = STAGE / "bounded-full-001"
    BASELINE_FREEZE = _workspace_path(args.baseline_freeze)
    BASELINE_COMPARISON = _workspace_path(args.baseline_comparison)
    BASELINE_POSTVERIFY = _workspace_path(args.baseline_postverify)
    BASELINE_XML = _workspace_path(args.baseline_xml)
    NEW_FREEZE = _workspace_path(args.current_freeze or (STAGE / "source-freeze-001.json"))
    FULL_XML = _workspace_path(args.full_xml or (OUT / "regression-full-001.xml"))
    FULL_LOG = _workspace_path(args.full_log or (OUT / "regression-full-001.log"))
    COMPARISON_REPORT = _workspace_path(args.comparison_report or (STAGE / "regression-comparison-001.json"))
    POSTVERIFY_REPORT = _workspace_path(args.postverify_report or (STAGE / "source-post-run-verification-001.json"))
    RESERVATION_REPORT = OUT / "full-execution-reservation-001.json"
    BOUNDARY_REPORT = _workspace_path(args.boundary_report or (OUT / "full-execution-boundary-001.json"))
    PROGRESS_REPORT = OUT / "batch-progress-001.jsonl"
    NODEID_COVERAGE = OUT / "nodeid-coverage-001.json"
    SOURCE_SNAPSHOTS = STAGE / "source-snapshots-001"
    _SOURCE_ARGUMENTS = list(args.source or [])
    _SOURCE_LIST_PATH = _workspace_path(args.source_list) if args.source_list else None

def add_path_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--stage", default=DEFAULT_STAGE.relative_to(ROOT).as_posix())
    parser.add_argument("--baseline-freeze", default=DEFAULT_BASELINE_FREEZE.relative_to(ROOT).as_posix())
    parser.add_argument("--baseline-comparison", default=DEFAULT_BASELINE_COMPARISON.relative_to(ROOT).as_posix())
    parser.add_argument("--baseline-postverify", default=DEFAULT_BASELINE_POSTVERIFY.relative_to(ROOT).as_posix())
    parser.add_argument("--baseline-xml", default=DEFAULT_BASELINE_XML.relative_to(ROOT).as_posix())
    parser.add_argument("--current-freeze")
    parser.add_argument("--full-xml")
    parser.add_argument("--full-log")
    parser.add_argument("--comparison-report")
    parser.add_argument("--postverify-report")
    parser.add_argument("--boundary-report")
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--source-list", help="JSON object with a sources array; used only by --freeze")

# Pytest imports this file as a plugin in the collector and in every batch.
# Recording the actual selected item ids lets the runner prove both full-suite
# collection and each explicit node-id slice without altering test execution.
def pytest_collection_finish(session):
    destination = os.environ.get(COLLECTION_ENV)
    if not destination:
        return
    nodeids = [item.nodeid for item in session.items]
    if any(not isinstance(nodeid, str) or not nodeid for nodeid in nodeids):
        raise RuntimeError("pytest_collected_invalid_nodeid")
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump({"schema": COLLECTION_SCHEMA, "count": len(nodeids),
                   "nodeids": nodeids}, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _mkdir_new(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)


def _read_json(path: Path) -> dict:
    return read_json(path)


def _verify_parent() -> tuple[dict, dict, dict]:
    baseline = _read_json(BASELINE_FREEZE)
    comparison = _read_json(BASELINE_COMPARISON)
    postverify = _read_json(BASELINE_POSTVERIFY)
    freeze_pin = pin(BASELINE_FREEZE)
    comparison_pin = pin(BASELINE_COMPARISON)
    postverify_pin = pin(BASELINE_POSTVERIFY)
    xml_pin = pin(BASELINE_XML)
    if (baseline.get("schema") != "information.foreign_economy.bounded_source_freeze.v1"
            or baseline.get("batch") != 89 or baseline.get("revision") != "001"
            or baseline.get("status") != "passed" or baseline.get("count") != 1010
            or baseline.get("freeze_path") != BASELINE_FREEZE.relative_to(ROOT).as_posix()
            or len(baseline.get("files", [])) != 1010):
        raise ValueError("accepted_89_freeze_001_invalid")
    source_paths = [row.get("source", {}).get("path") for row in baseline["files"]]
    if any(not isinstance(path, str) for path in source_paths) or len(set(source_paths)) != 1010:
        raise ValueError("accepted_89_freeze_001_file_union_invalid")
    totals = comparison.get("terminal_totals", {})
    junit = comparison.get("junit_summary", {})
    coverage = comparison.get("collection_coverage", {})
    if (comparison.get("schema") != "information.foreign_economy.bounded_regression_comparison.v1"
            or comparison.get("batch") != 89 or comparison.get("revision") != "001"
            or comparison.get("parent_baseline_batch") != 88
            or comparison.get("status") != "passed_no_new_bad"
            or comparison.get("no_new_bad") is not True
            or comparison.get("new_bad") != []
            or comparison.get("resolved_bad") != []
            or comparison.get("whole_suite_passed") is not False
            or comparison.get("freeze") != freeze_pin
            or comparison.get("current") != xml_pin
            or comparison.get("baseline_bad_occurrences") != 141
            or comparison.get("current_bad_occurrences") != 141
            or comparison.get("nodeid_count") != 4796
            or comparison.get("part_count") != 41
            or totals != {"passed": 4674, "failed": 106, "errors": 35, "subtests": 2014}
            or junit.get("tests") != 6829 or junit.get("failures") != 106
            or junit.get("errors") != 35 or junit.get("skipped") != 0):
        raise ValueError("accepted_89_full_001_comparison_invalid")
    if (coverage.get("status") != "complete"
            or coverage.get("expected_node_count") != 4796
            or coverage.get("executed_node_count") != 4796
            or coverage.get("missing_node_ids") != []
            or coverage.get("duplicate_node_ids") != []):
        raise ValueError("accepted_89_nodeid_coverage_invalid")
    if (postverify.get("schema") != "information.foreign_economy.bounded_postverify.v1"
            or postverify.get("batch") != 89 or postverify.get("revision") != "001"
            or postverify.get("status") != "passed_no_new_bad"
            or postverify.get("count") != 1010
            or postverify.get("freeze") != freeze_pin
            or postverify.get("regression_comparison") != comparison_pin
            or postverify.get("nodeid_coverage") != comparison.get("nodeid_coverage")
            or postverify.get("current_sources_match_snapshots") is not True
            or postverify.get("no_new_bad") is not True
            or postverify.get("whole_suite_passed") is not False):
        raise ValueError("accepted_89_postverify_001_invalid")
    bad = common.bad_cases(BASELINE_XML)
    if sum(bad.values()) != 141:
        raise ValueError("accepted_89_full_001_bad_counter_mismatch")
    return baseline, comparison, {
        "baseline_freeze": freeze_pin, "baseline_comparison": comparison_pin,
        "baseline_postverify": postverify_pin, "baseline_xml": xml_pin,
    }


def prepare_harness() -> dict:
    baseline, comparison, pins = _verify_parent()
    return {
        "schema": "information.foreign_contracts.bounded_harness_preparation.v1",
        "status": "prepared_inert", "batch": 90, "revision": "001",
        "baseline": pins, "baseline_terminal_totals": comparison["terminal_totals"],
        "baseline_nodeid_count": comparison["nodeid_count"],
        "baseline_part_count": comparison["part_count"],
        "baseline_junit_summary": comparison["junit_summary"],
        "baseline_bad_occurrences": comparison["current_bad_occurrences"],
        "baseline_source_count": len(baseline["files"]),
        "limits": {"max_batch_items": MAX_BATCH_ITEMS,
                   "max_direct_command_chars": MAX_DIRECT_COMMAND_CHARS,
                   "memory_stop_bytes": MEMORY_STOP_BYTES,
                   "memory_sample_interval_seconds": MONITOR_INTERVAL_SECONDS},
        "test_collection": "authoritative pytest collection from bridge/tests; duplicates rejected",
        "execution": "serial direct-argv batches; merged JUnit suites preserve cases and subtest counters",
        "current_source_set": "accepted_batch_89_source_union_plus_explicit_reviewed_changes_and_additions_selected_by_root_before_freeze",
        "no_source_freeze_created": True,
        "no_collection_started": True, "no_pytest_test_bodies_started": True,
        "no_full_execution_started": True,
        "run_requires_explicit_flag": "--run",
    }


def write_preparation_receipt() -> dict:
    if PREPARATION.exists():
        raise FileExistsError("harness_adaptation_001_already_exists")
    prepared = prepare_harness()
    PREPARATION.mkdir(parents=True, exist_ok=False)
    prepared["runner_source"] = pin(RUNNER)
    prepared["finalizer_source"] = pin(PUBLISHER)
    prepared["preparation_receipt"] = (
        PREPARATION / "preparation-receipt-001.json").relative_to(ROOT).as_posix()
    write_new(PREPARATION / "preparation-receipt-001.json", prepared)
    return prepared

class _PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def _open_memory_handle(pid: int):
    if os.name != "nt":
        raise OSError("bounded_runner_requires_windows_process_memory_api")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_PROCESS_MEMORY_COUNTERS_EX), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x0400 | 0x1000, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess")
    return kernel32, psapi, handle


def _sample_memory(psapi, handle) -> dict:
    counters = _PROCESS_MEMORY_COUNTERS_EX()
    counters.cb = ctypes.sizeof(counters)
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo")
    return {"current_private_usage_bytes": int(counters.PrivateUsage),
            "current_pagefile_usage_bytes": int(counters.PagefileUsage),
            "peak_pagefile_usage_bytes": int(counters.PeakPagefileUsage),
            "working_set_bytes": int(counters.WorkingSetSize),
            "peak_working_set_bytes": int(counters.PeakWorkingSetSize)}


def _terminate_exact(process: subprocess.Popen) -> int:
    if process.poll() is None:
        process.terminate()
    try:
        return process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=3)


def _run_monitored(argv: list[str], *, cwd: Path, log_path: Path,
                   sample_path: Path, env: dict[str, str]) -> dict:
    """Run one exact pytest child; sample private commit at 0.5s intervals."""
    if log_path.exists() or sample_path.exists():
        raise FileExistsError("bounded_child_output_already_exists")
    if len(subprocess.list2cmdline(argv)) >= 32767:
        raise ValueError("windows_command_line_limit_exceeded")
    start = _stamp()
    with log_path.open("xb") as output, sample_path.open("x", encoding="utf-8", newline="\n") as monitor:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    close_fds=True)
        try:
            kernel32, psapi, handle = _open_memory_handle(process.pid)
        except Exception:
            _terminate_exact(process)
            raise
        peak_private = 0
        peak_pagefile = 0
        peak_working_set = 0
        samples = 0
        cap_hit = False
        query_error = None
        try:
            while True:
                now = time.monotonic()
                status = process.poll()
                try:
                    measured = _sample_memory(psapi, handle)
                except OSError as exc:
                    if status is None:
                        query_error = f"{type(exc).__name__}:{exc}"
                        _terminate_exact(process)
                        break
                    measured = None
                if measured is not None:
                    samples += 1
                    peak_private = max(peak_private, measured["current_private_usage_bytes"])
                    peak_pagefile = max(peak_pagefile, measured["peak_pagefile_usage_bytes"])
                    peak_working_set = max(peak_working_set, measured["peak_working_set_bytes"])
                    monitor.write(json.dumps({"at_utc": _stamp(), "pid": process.pid,
                                              **measured}, separators=(",", ":")) + "\n")
                    monitor.flush()
                    if (measured["peak_pagefile_usage_bytes"] > MEMORY_STOP_BYTES
                            or measured["current_private_usage_bytes"] > MEMORY_STOP_BYTES):
                        cap_hit = True
                        _terminate_exact(process)
                        break
                if status is not None:
                    # The retained process handle remains queryable after exit,
                    # so this final read catches a short peak between samples.
                    try:
                        measured = _sample_memory(psapi, handle)
                        samples += 1
                        peak_private = max(peak_private, measured["current_private_usage_bytes"])
                        peak_pagefile = max(peak_pagefile, measured["peak_pagefile_usage_bytes"])
                        peak_working_set = max(peak_working_set, measured["peak_working_set_bytes"])
                        monitor.write(json.dumps({"at_utc": _stamp(), "pid": process.pid,
                                                  "final_sample": True, **measured},
                                                 separators=(",", ":")) + "\n")
                        monitor.flush()
                        if measured["peak_pagefile_usage_bytes"] > MEMORY_STOP_BYTES:
                            cap_hit = True
                    except OSError as exc:
                        query_error = f"final:{type(exc).__name__}:{exc}"
                    break
                elapsed = time.monotonic() - now
                time.sleep(max(0.0, MONITOR_INTERVAL_SECONDS - elapsed))
        finally:
            kernel32.CloseHandle(handle)
        return {"pid": process.pid, "argv": argv,
                "returncode": process.wait(), "started_at": start,
                "finished_at": _stamp(), "sample_count": samples,
                "max_private_usage_bytes": peak_private,
                "peak_pagefile_usage_bytes": peak_pagefile,
                "peak_working_set_bytes": peak_working_set,
                "memory_cap_bytes": MEMORY_STOP_BYTES, "cap_hit": cap_hit,
                "memory_query_error": query_error,
                "log": pin(log_path), "monitor": pin(sample_path)}




def _next_collection_attempt() -> tuple[int, Path]:
    for number in range(1, 100):
        folder = OUT / f"collection-{number:03d}"
        if not folder.exists():
            return number, folder
    raise RuntimeError("bounded_collection_attempt_limit")


def _collector_command(output: Path) -> list[str]:
    return [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "--collect-only",
            "-p", PLUGIN_NAME, "bridge/tests"]


def _chunks(nodeids: list[str]) -> list[dict]:
    chunks: list[dict] = []
    start = 0
    current: list[str] = []
    for nodeid in nodeids:
        candidate = current + [nodeid]
        argv = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "-p", PLUGIN_NAME,
                "--junitxml", str(OUT / "parts/part-0001/part.xml")] + candidate
        size = len(subprocess.list2cmdline(argv))
        if current and (len(candidate) > MAX_BATCH_ITEMS or size > MAX_DIRECT_COMMAND_CHARS):
            chunks.append({"index": len(chunks) + 1, "start": start, "stop": start + len(current),
                           "nodeid_count": len(current),
                           "direct_command_chars": len(subprocess.list2cmdline(
                               argv[:-len(candidate)] + current))})
            start += len(current)
            current = [nodeid]
        else:
            current = candidate
        single = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "-p", PLUGIN_NAME,
                  "--junitxml", str(OUT / "parts/part-0001/part.xml"), nodeid]
        if len(subprocess.list2cmdline(single)) > MAX_DIRECT_COMMAND_CHARS:
            raise ValueError("single_nodeid_exceeds_safe_windows_argv")
    if current:
        argv = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "-p", PLUGIN_NAME,
                "--junitxml", str(OUT / "parts/part-0001/part.xml")] + current
        chunks.append({"index": len(chunks) + 1, "start": start, "stop": start + len(current),
                       "nodeid_count": len(current),
                       "direct_command_chars": len(subprocess.list2cmdline(argv))})
    return chunks


def prepare_collection() -> dict:
    _baseline, _comparison, baseline_pins = _verify_parent()
    verify_sources()
    if not RESEARCH_PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{RESEARCH_PYTHON}")
    OUT.mkdir(parents=True, exist_ok=True)
    plan_path = OUT / "collection-plan-001.json"
    if plan_path.exists():
        raise FileExistsError("collection_plan_001_already_exists")
    attempt, folder = _next_collection_attempt()
    _mkdir_new(folder)
    node_output = folder / "collected-nodeids.json"
    log_path = folder / "collect-only.log"
    monitor = folder / "memory-monitor.jsonl"
    env = os.environ.copy()
    env[COLLECTION_ENV] = str(node_output)
    argv = _collector_command(node_output)
    run = _run_monitored(argv, cwd=ROOT, log_path=log_path,
                         sample_path=monitor, env=env)
    if run["cap_hit"]:
        result = {"schema": COLLECTION_SCHEMA + ".receipt", "status": "aborted_resource_threshold",
                  "attempt": attempt, "baseline": baseline_pins,
                  "freeze": pin(NEW_FREEZE), "child": run}
        write_new(folder / "collection-receipt.json", result)
        return result
    if run["memory_query_error"]:
        raise RuntimeError(f"collection_memory_monitor_failed:{run['memory_query_error']}")
    if run["returncode"] != 0 or not node_output.is_file():
        result = {"schema": COLLECTION_SCHEMA + ".receipt", "status": "failed_collection",
                  "attempt": attempt, "baseline": baseline_pins,
                  "freeze": pin(NEW_FREEZE), "child": run,
                  "nodeids_written": node_output.is_file()}
        write_new(folder / "collection-receipt.json", result)
        return result
    captured = _read_json(node_output)
    nodeids = captured.get("nodeids")
    if (captured.get("schema") != COLLECTION_SCHEMA
            or not isinstance(nodeids, list) or captured.get("count") != len(nodeids)
            or not nodeids or any(not isinstance(item, str) or not item for item in nodeids)
            or len(set(nodeids)) != len(nodeids)):
        raise ValueError("collection_plugin_output_invalid_or_duplicate_nodeids")
    chunks = _chunks(nodeids)
    if (not chunks or any(row["nodeid_count"] > MAX_BATCH_ITEMS
                          or row["direct_command_chars"] > MAX_DIRECT_COMMAND_CHARS for row in chunks)
            or sum(row["nodeid_count"] for row in chunks) != len(nodeids)):
        raise ValueError("bounded_chunk_plan_invalid")
    plan = {"schema": PLAN_SCHEMA, "attempt": attempt,
            "collection_receipt": pin(node_output), "nodeid_count": len(nodeids),
            "unique_nodeid_count": len(set(nodeids)), "nodeids": nodeids,
            "chunks": chunks, "max_batch_items": MAX_BATCH_ITEMS,
            "max_direct_command_chars": MAX_DIRECT_COMMAND_CHARS,
            "argfile_used": False, "collection_command": argv,
            "collection_log": pin(log_path), "collection_monitor": pin(monitor),
            "collection_child": run, "freeze": pin(NEW_FREEZE),
            "baseline": baseline_pins, "created_at": _stamp()}
    write_new(plan_path, plan)
    result = {"schema": COLLECTION_SCHEMA + ".receipt", "status": "passed",
              "attempt": attempt, "nodeid_count": len(nodeids),
              "unique_nodeid_count": len(set(nodeids)), "batch_count": len(chunks),
              "max_batch_items": max(row["nodeid_count"] for row in chunks),
              "max_command_chars": max(row["direct_command_chars"] for row in chunks),
              "argfile_used": False, "collection_plan": pin(plan_path), "child": run}
    write_new(folder / "collection-receipt.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result

def _load_collection_plan() -> tuple[dict, dict]:
    plan_path = OUT / "collection-plan-001.json"
    plan = _read_json(plan_path)
    receipt = _read_json(OUT / f"collection-{plan['attempt']:03d}/collection-receipt.json")
    if (plan.get("schema") != PLAN_SCHEMA or receipt.get("status") != "passed"
            or receipt.get("collection_plan") != pin(plan_path)
            or plan.get("nodeid_count") != len(plan.get("nodeids", []))
            or plan.get("unique_nodeid_count") != plan.get("nodeid_count")
            or plan.get("freeze") != pin(NEW_FREEZE)):
        raise ValueError("collection_plan_or_receipt_mismatch")
    if pin(plan["collection_receipt"]["path"]) != plan["collection_receipt"]:
        raise ValueError("collection_nodeid_file_pin_mismatch")
    nodeids = plan["nodeids"]
    chunks = plan.get("chunks")
    if (not isinstance(nodeids, list) or len(set(nodeids)) != len(nodeids)
            or not isinstance(chunks, list)
            or sum(row.get("nodeid_count", 0) for row in chunks) != len(nodeids)
            or any(row.get("nodeid_count", MAX_BATCH_ITEMS + 1) > MAX_BATCH_ITEMS
                   or row.get("direct_command_chars", MAX_DIRECT_COMMAND_CHARS + 1) > MAX_DIRECT_COMMAND_CHARS
                   for row in chunks)
            or chunks != _chunks(nodeids)):
        raise ValueError("collection_plan_shape_invalid")
    return plan, receipt

def _requested_sources() -> tuple[list[str], dict | None]:
    requested = {RUNNER, PUBLISHER, *(_SOURCE_ARGUMENTS or [])}
    manifest_pin = None
    if _SOURCE_LIST_PATH is not None:
        if _SOURCE_LIST_PATH.stat().st_size > 1024 * 1024:
            raise ValueError("source_list_too_large")
        manifest = _read_json(_SOURCE_LIST_PATH)
        rows = manifest.get("sources")
        if not isinstance(rows, list) or any(not isinstance(row, str) for row in rows):
            raise ValueError("source_list_schema_invalid")
        requested.update(rows)
        manifest_pin = pin(_SOURCE_LIST_PATH)
    normalized = sorted({_workspace_path(path).relative_to(ROOT).as_posix() for path in requested})
    for path in normalized:
        if not (ROOT / path).is_file():
            raise FileNotFoundError(f"freeze_source_missing:{path}")
    return normalized, manifest_pin


def _snapshot_source(source_path: str) -> tuple[dict, dict]:
    source = ROOT / source_path
    snapshot = SOURCE_SNAPSHOTS / Path(source_path)
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    before = pin(source)
    copy_stream(source, snapshot)
    after = pin(source)
    snapshot_pin = pin(snapshot)
    if (before != after or (after["bytes"], after["sha256"]) !=
            (snapshot_pin["bytes"], snapshot_pin["sha256"])):
        raise RuntimeError(f"source_changed_during_snapshot:{source_path}")
    return after, snapshot_pin


def freeze() -> dict:
    baseline, _comparison, baseline_pins = _verify_parent()
    receipt_path = STAGE / "source-freeze-receipt-001.json"
    if NEW_FREEZE.exists() or receipt_path.exists() or SOURCE_SNAPSHOTS.exists():
        raise FileExistsError("current_source_freeze_already_started")
    NEW_FREEZE.parent.mkdir(parents=True, exist_ok=True)
    requested, manifest_pin = _requested_sources()
    requested_set = set(requested)
    baseline_rows = {row["source"]["path"]: row for row in baseline["files"]}
    rows: list[dict] = []
    changed_existing: list[dict] = []
    added_rows: list[dict] = []
    snapshots_created = False
    for path, original in baseline_rows.items():
        current = pin(path)
        if current == original["source"]:
            rows.append(original)
            continue
        if path not in requested_set:
            raise ValueError(f"unreviewed_baseline_source_change:{path}")
        if not snapshots_created:
            SOURCE_SNAPSHOTS.mkdir(parents=True, exist_ok=False)
            snapshots_created = True
        source_pin, snapshot_pin = _snapshot_source(path)
        row = {"source": source_pin, "snapshot": snapshot_pin}
        rows.append(row)
        changed_existing.append({"path": path, "before": original, "after": row})
    for path in requested:
        if path in baseline_rows:
            continue
        if not snapshots_created:
            SOURCE_SNAPSHOTS.mkdir(parents=True, exist_ok=False)
            snapshots_created = True
        source_pin, snapshot_pin = _snapshot_source(path)
        row = {"source": source_pin, "snapshot": snapshot_pin}
        rows.append(row)
        added_rows.append(row)
    rows.sort(key=lambda row: row["source"]["path"])
    expected_count = len(baseline["files"]) + len(added_rows)
    if (len(rows) != expected_count
            or len({row["source"]["path"] for row in rows}) != expected_count):
        raise ValueError("current_freeze_union_count_or_duplicate_mismatch")
    value = {"schema": FREEZE_SCHEMA, "batch": 90, "revision": "001",
             "status": "passed", "count": len(rows), "files": rows,
             "freeze_path": NEW_FREEZE.relative_to(ROOT).as_posix(),
             "baseline_freeze": baseline_pins["baseline_freeze"],
             "baseline_comparison": baseline_pins["baseline_comparison"],
             "baseline_postverify": baseline_pins["baseline_postverify"],
             "baseline_full_xml": baseline_pins["baseline_xml"],
             "inherited_file_count": len(baseline["files"]),
             "added_file_count": len(added_rows), "added_sources": added_rows,
             "reviewed_existing_source_changes": changed_existing,
             "requested_source_paths": requested,
             "source_list_manifest": manifest_pin,
             "source_snapshot_policy":
        "reuse unchanged accepted batch-89 source rows; snapshot only explicitly reviewed changed or added sources",
             "created_at": _stamp()}
    write_new(NEW_FREEZE, value)
    result = {"schema": FREEZE_SCHEMA + ".receipt", "status": "passed",
              "count": len(rows), "path": NEW_FREEZE.relative_to(ROOT).as_posix(),
              "freeze": pin(NEW_FREEZE), "added_file_count": len(added_rows),
              "reviewed_existing_changes": [row["path"] for row in changed_existing],
              "baseline": baseline_pins}
    write_new(receipt_path, result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


def verify_sources() -> dict:
    baseline, _comparison, baseline_pins = _verify_parent()
    frozen = _read_json(NEW_FREEZE)
    if (frozen.get("schema") != FREEZE_SCHEMA or frozen.get("batch") != 90
            or frozen.get("revision") != "001" or frozen.get("status") != "passed"
            or frozen.get("freeze_path") != NEW_FREEZE.relative_to(ROOT).as_posix()
            or frozen.get("baseline_freeze") != baseline_pins["baseline_freeze"]
            or frozen.get("baseline_comparison") != baseline_pins["baseline_comparison"]
            or frozen.get("baseline_postverify") != baseline_pins["baseline_postverify"]
            or frozen.get("baseline_full_xml") != baseline_pins["baseline_xml"]):
        raise ValueError("current_freeze_metadata_invalid")
    old_by_path = {row["source"]["path"]: row for row in baseline["files"]}
    added_rows = frozen.get("added_sources")
    reviewed_rows = frozen.get("reviewed_existing_source_changes")
    if (not isinstance(added_rows, list) or any(not isinstance(row, dict) for row in added_rows)
            or not isinstance(reviewed_rows, list)
            or any(not isinstance(row, dict) for row in reviewed_rows)):
        raise ValueError("current_freeze_delta_rows_invalid")
    added_by_path = {row.get("source", {}).get("path"): row for row in added_rows}
    reviewed_by_path = {row.get("path"): row for row in reviewed_rows}
    if len(added_by_path) != len(added_rows) or len(reviewed_by_path) != len(reviewed_rows):
        raise ValueError("current_freeze_delta_rows_duplicate")
    added_paths = set(added_by_path)
    reviewed = set(reviewed_by_path)
    rows = frozen.get("files", [])
    if (not isinstance(rows, list) or frozen.get("inherited_file_count") != len(old_by_path)
            or frozen.get("added_file_count") != len(added_paths)
            or len(rows) != len(old_by_path) + len(added_paths)
            or frozen.get("count") != len(rows)
            or None in added_paths or reviewed - set(old_by_path)
            or len({row.get("source", {}).get("path") for row in rows}) != len(rows)):
        raise ValueError("current_freeze_union_invalid")
    row_by_path = {row["source"]["path"]: row for row in rows}
    if set(row_by_path) != set(old_by_path) | added_paths:
        raise ValueError("current_freeze_path_union_mismatch")
    for path, row in added_by_path.items():
        if path not in row_by_path or row_by_path[path] != row:
            raise ValueError(f"added_source_row_mismatch:{path}")
    for path, old_row in old_by_path.items():
        row = row_by_path[path]
        if path not in reviewed and row != old_row:
            raise ValueError(f"unreviewed_inherited_row_change:{path}")
        if path in reviewed and row == old_row:
            raise ValueError(f"reviewed_source_change_not_pinned:{path}")
        if path in reviewed:
            delta = reviewed_by_path[path]
            if delta.get("before") != old_row or delta.get("after") != row:
                raise ValueError(f"reviewed_source_change_receipt_mismatch:{path}")
    for path, row in row_by_path.items():
        source, snapshot = row["source"], row["snapshot"]
        if pin(source["path"]) != source or pin(snapshot["path"]) != snapshot:
            raise ValueError(f"source_or_snapshot_pin_mismatch:{path}")
        if (source["bytes"], source["sha256"]) != (snapshot["bytes"], snapshot["sha256"]):
            raise ValueError(f"source_snapshot_bytes_mismatch:{path}")
    requested_rows = frozen.get("requested_source_paths")
    if (not isinstance(requested_rows, list)
            or any(not isinstance(path, str) for path in requested_rows)
            or requested_rows != sorted(set(requested_rows))):
        raise ValueError("requested_source_paths_invalid")
    requested = set(requested_rows)
    if requested - (added_paths | reviewed | set(old_by_path)):
        raise ValueError("requested_source_paths_not_accounted")
    source_list_manifest = frozen.get("source_list_manifest")
    if (source_list_manifest is not None
            and pin(source_list_manifest["path"]) != source_list_manifest):
        raise ValueError("source_list_manifest_pin_mismatch")
    return {"schema": frozen["schema"], "count": frozen["count"],
            "path": NEW_FREEZE.relative_to(ROOT).as_posix(), "freeze": pin(NEW_FREEZE),
            "baseline": baseline_pins, "added_file_count": len(added_paths),
            "reviewed_existing_changes": sorted(reviewed)}

def _command_for_batch(nodeids: list[str], xml_path: Path) -> list[str]:
    argv = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "-p", PLUGIN_NAME,
            "--junitxml", str(xml_path)] + nodeids
    if len(subprocess.list2cmdline(argv)) > MAX_DIRECT_COMMAND_CHARS:
        raise ValueError("batch_command_line_exceeds_recorded_limit")
    return argv


def _write_expected_ids(path: Path, nodeids: list[str]) -> dict:
    write_new(path, {"schema": COLLECTION_SCHEMA, "count": len(nodeids), "nodeids": nodeids})
    return pin(path)


def _run_part(index: int, nodeids: list[str]) -> dict:
    folder = OUT / "parts" / f"part-{index:04d}"
    _mkdir_new(folder)
    expected_path = folder / "expected-nodeids.json"
    actual_path = folder / "actual-nodeids.json"
    log_path = folder / "pytest.log"
    xml_path = folder / "part.xml"
    monitor_path = folder / "memory-monitor.jsonl"
    expected_pin = _write_expected_ids(expected_path, nodeids)
    argv = _command_for_batch(nodeids, xml_path)
    env = os.environ.copy()
    env[COLLECTION_ENV] = str(actual_path)
    run = _run_monitored(argv, cwd=ROOT, log_path=log_path,
                         sample_path=monitor_path, env=env)
    if run["cap_hit"]:
        receipt = {"schema": "information.foreign_contracts.bounded_part.v1",
                   "status": "aborted_resource_threshold", "index": index,
                   "expected_ids": expected_pin, "child": run,
                   "xml_created": xml_path.is_file(), "actual_collection_created": actual_path.is_file()}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    if run["memory_query_error"]:
        receipt = {"schema": "information.foreign_contracts.bounded_part.v1",
                   "status": "aborted_memory_monitor_error", "index": index,
                   "expected_ids": expected_pin, "child": run,
                   "xml_created": xml_path.is_file(), "actual_collection_created": actual_path.is_file()}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    if not actual_path.is_file() or not xml_path.is_file():
        receipt = {"schema": "information.foreign_contracts.bounded_part.v1",
                   "status": "failed_missing_xml_or_collection", "index": index,
                   "expected_ids": expected_pin, "child": run,
                   "xml_created": xml_path.is_file(), "actual_collection_created": actual_path.is_file()}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    actual = _read_json(actual_path)
    actual_ids = actual.get("nodeids")
    match = (actual.get("schema") == COLLECTION_SCHEMA
             and isinstance(actual_ids, list)
             and actual.get("count") == len(actual_ids)
             and collections.Counter(actual_ids) == collections.Counter(nodeids))
    if not match:
        receipt = {"schema": "information.foreign_contracts.bounded_part.v1",
                   "status": "failed_collected_ids_mismatch", "index": index,
                   "expected_ids": expected_pin, "actual_ids": pin(actual_path),
                   "expected_count": len(nodeids),
                   "actual_count": len(actual_ids) if isinstance(actual_ids, list) else None,
                   "child": run, "xml": pin(xml_path)}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    try:
        junit = ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        receipt = {"schema": "information.foreign_contracts.bounded_part.v1",
                   "status": "failed_invalid_junit_xml", "index": index,
                   "expected_ids": expected_pin, "actual_ids": pin(actual_path),
                   "child": run, "xml": pin(xml_path),
                   "error": f"{type(exc).__name__}:{exc}"}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    if junit.tag not in ("testsuite", "testsuites"):
        raise ValueError("bounded_part_junit_root_invalid")
    receipt = {"schema": "information.foreign_contracts.bounded_part.v1",
               "status": "completed", "index": index,
               "expected_count": len(nodeids), "expected_ids": expected_pin,
               "actual_ids": pin(actual_path), "actual_count": len(actual_ids),
               "collection_multiset_matches": True, "child": run,
               "xml": pin(xml_path), "log": pin(log_path),
               "memory_monitor": pin(monitor_path),
               "junit_summary": common.junit_summary(xml_path),
               "returncode": run["returncode"]}
    write_new(folder / "part-receipt.json", receipt)
    return receipt


def _part_suites(xml_path: Path) -> list[ET.Element]:
    root = ET.parse(xml_path).getroot()
    if root.tag == "testsuite":
        return [copy.deepcopy(root)]
    return [copy.deepcopy(child) for child in root if child.tag == "testsuite"]


def _merge_junit(part_receipts: list[dict], destination: Path) -> dict:
    if destination.exists():
        raise FileExistsError("bounded_merged_junit_already_exists")
    suite_nodes: list[ET.Element] = []
    totals = {name: 0 for name in ("tests", "failures", "errors", "skipped")}
    for receipt in part_receipts:
        if receipt.get("status") != "completed":
            raise ValueError("cannot_merge_incomplete_part")
        xml_path = common.workspace(receipt["xml"]["path"])
        for suite in _part_suites(xml_path):
            suite_nodes.append(suite)
            for name in totals:
                totals[name] += int(suite.get(name, "0"))
    merged = ET.Element("testsuites", {"name": "pytest bridge/tests bounded batch-90 full",
                                        **{key: str(value) for key, value in totals.items()}})
    for suite in suite_nodes:
        merged.append(suite)
    tree = ET.ElementTree(merged)
    tree.write(destination, encoding="utf-8", xml_declaration=True)
    return {"summary": common.junit_summary(destination),
            "suite_count": len(suite_nodes), "xml": pin(destination)}


def _combine_logs(part_receipts: list[dict], destination: Path) -> dict:
    if destination.exists():
        raise FileExistsError("bounded_combined_log_already_exists")
    with destination.open("xb") as out:
        for receipt in part_receipts:
            header = (f"\n===== PART {receipt['index']:04d} "
                      f"STATUS {receipt['status']} RC {receipt.get('returncode')} =====\n")
            out.write(header.encode("utf-8"))
            path = common.workspace(receipt["log"]["path"])
            with path.open("rb") as source:
                while block := source.read(1024 * 1024):
                    out.write(block)
    return pin(destination)


_TERMINAL_COUNT_PATTERNS = {
    "passed": re.compile(r"(?<![\w])([0-9]+) passed\b"),
    "failed": re.compile(r"(?<![\w])([0-9]+) failed\b"),
    "errors": re.compile(r"(?<![\w])([0-9]+) errors?\b"),
    "skipped": re.compile(r"(?<![\w])([0-9]+) skipped\b"),
    "subtests_passed": re.compile(r"(?<![\w])([0-9]+) subtests passed\b"),
}


def _part_terminal_summary(path: Path) -> dict:
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - 65536))
        text = stream.read().decode("utf-8", errors="replace")
    result = {name: 0 for name in _TERMINAL_COUNT_PATTERNS}
    summary_line = ""
    for line in text.splitlines():
        if " in " in line and any(token in line for token in
                                 (" passed", " failed", " error", " skipped", " subtests")):
            summary_line = line.strip("= \t")
    for key, pattern in _TERMINAL_COUNT_PATTERNS.items():
        match = pattern.search(summary_line)
        if match:
            result[key] = int(match.group(1))
    return {**result, "summary_line": summary_line}


def full() -> int:
    frozen = verify_sources()
    if not (OUT / "collection-plan-001.json").is_file():
        collection = prepare_collection()
        if collection.get("status") != "passed":
            return 3
    plan, _collection = _load_collection_plan()
    reservation = RESERVATION_REPORT
    boundary = BOUNDARY_REPORT
    progress = PROGRESS_REPORT
    receipts: list[dict] = []
    if any(path.exists() for path in (reservation, boundary, progress,
                                      FULL_XML,
                                      FULL_LOG,
                                      COMPARISON_REPORT,
                                      POSTVERIFY_REPORT)):
        raise FileExistsError("bounded_full_001_already_started")
    for path in (FULL_XML, FULL_LOG, COMPARISON_REPORT, POSTVERIFY_REPORT,
                 boundary, progress, NODEID_COVERAGE, reservation):
        path.parent.mkdir(parents=True, exist_ok=True)
    chunks = plan["chunks"]
    write_new(reservation, {"schema": "information.foreign_contracts.bounded_full_reservation.v1",
                            "runs": 1, "batch_count": len(chunks),
                            "nodeid_count": plan["nodeid_count"],
                            "max_batch_items": MAX_BATCH_ITEMS,
                            "freeze": pin(NEW_FREEZE),
                            "collection_plan": pin(OUT / "collection-plan-001.json"),
                            "memory_stop_bytes": MEMORY_STOP_BYTES,
                            "monitor_interval_seconds": MONITOR_INTERVAL_SECONDS,
                            "execution": "serial pytest children; all nodeids exactly once; no filters/skip/maxfail",
                            "started_at": _stamp()})
    with progress.open("x", encoding="utf-8", newline="\n"):
        pass
    try:
        for chunk in chunks:
            start, stop = chunk["start"], chunk["stop"]
            part_ids = plan["nodeids"][start:stop]
            receipt = _run_part(chunk["index"], part_ids)
            receipts.append(receipt)
            with progress.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps({"at_utc": _stamp(), "index": chunk["index"],
                                         "status": receipt["status"],
                                         "returncode": receipt.get("returncode"),
                                         "nodeid_count": receipt.get("expected_count"),
                                         "peak_pagefile_usage_bytes":
                                         receipt.get("child", {}).get("peak_pagefile_usage_bytes"),
                                         "peak_private_usage_bytes":
                                         receipt.get("child", {}).get("max_private_usage_bytes")},
                                        separators=(",", ":")) + "\n")
                stream.flush()
            print(json.dumps({"phase": "part", "index": chunk["index"],
                              "batch_count": len(chunks), "status": receipt["status"],
                              "nodeid_count": chunk["nodeid_count"],
                              "returncode": receipt.get("returncode"),
                              "peak_pagefile_usage_bytes":
                              receipt.get("child", {}).get("peak_pagefile_usage_bytes")},
                             ensure_ascii=False), flush=True)
            if receipt["status"] != "completed":
                write_new(boundary, {"schema": "information.foreign_contracts.bounded_full_boundary.v1",
                                     "status": receipt["status"], "stopped_at_part": chunk["index"],
                                     "freeze": pin(NEW_FREEZE), "partial_parts": receipts,
                                     "progress": pin(progress), "finished_at": _stamp()})
                return 3 if receipt["status"].startswith("aborted_resource") else 4
        actual_lists = []
        for receipt in receipts:
            data = _read_json(receipt["actual_ids"]["path"])
            actual_lists.extend(data["nodeids"])
        expected_ids = plan["nodeids"]
        if collections.Counter(actual_lists) != collections.Counter(expected_ids):
            write_new(boundary, {"schema": "information.foreign_contracts.bounded_full_boundary.v1",
                                 "status": "failed_nodeid_union_mismatch",
                                 "expected_count": len(expected_ids), "actual_count": len(actual_lists),
                                 "freeze": pin(NEW_FREEZE), "partial_parts": receipts,
                                 "progress": pin(progress), "finished_at": _stamp()})
            return 4
        expected_counts = collections.Counter(expected_ids)
        actual_counts = collections.Counter(actual_lists)
        missing_ids = sorted(node for node, count in expected_counts.items()
                             if actual_counts[node] < count)
        duplicate_ids = sorted(node for node, count in actual_counts.items()
                               if count > expected_counts[node])
        node_coverage = {"schema": "information.foreign_contracts.bounded_nodeid_coverage.v1",
                         "status": "complete", "expected_node_count": len(expected_ids),
                         "executed_node_count": len(actual_lists),
                         "missing_node_ids": missing_ids,
                         "duplicate_node_ids": duplicate_ids,
                         "expected_multiset_matches_actual_union": True,
                         "unique_expected_count": len(set(expected_ids)),
                         "part_count": len(receipts),
                         "part_receipts": [pin(OUT / "parts" / f"part-{r['index']:04d}" /
                                               "part-receipt.json") for r in receipts],
                         "collection_plan": pin(OUT / "collection-plan-001.json"),
                         "created_at": _stamp()}
        write_new(NODEID_COVERAGE, node_coverage)
        xml = FULL_XML
        log = FULL_LOG
        merge = _merge_junit(receipts, xml)
        log_pin = _combine_logs(receipts, log)
        junit_summary = merge["summary"]
        terminal = {name: 0 for name in _TERMINAL_COUNT_PATTERNS}
        terminal_parts = []
        for receipt in receipts:
            row = _part_terminal_summary(common.workspace(receipt["log"]["path"]))
            terminal_parts.append({"index": receipt["index"], **row})
            for key in terminal:
                terminal[key] += row[key]
        baseline_common = parent_verifier.common
        old_bad = baseline_common.bad_cases(BASELINE_XML)
        new_bad = baseline_common.bad_cases(xml)
        added, resolved = new_bad - old_bad, old_bad - new_bad
        total_returncode_nonzero = [r["index"] for r in receipts if r.get("returncode") != 0]
        complete = {"schema": "information.foreign_contracts.bounded_full_boundary.v1",
                    "status": "completed", "returncode_nonzero_parts": total_returncode_nonzero,
                    "part_count": len(receipts), "nodeid_count": len(actual_lists),
                    "xml": pin(xml), "log": log_pin, "nodeid_coverage": pin(NODEID_COVERAGE),
                    "finished_at": _stamp()}
        write_new(boundary, complete)
        # Reverify every frozen source after the final part and XML merge.
        verified = verify_sources()
        comparison = {"schema": "information.foreign_contracts.bounded_regression_comparison.v1",
                      "status": "passed_no_new_bad" if not added else "failed_new_bad",
                      "batch": 90, "revision": "001", "parent_baseline_batch": 89,
                      "parent_baseline_full": pin(BASELINE_XML),
                      "freeze": pin(NEW_FREEZE), "current": pin(xml), "log": log_pin,
                      "nodeid_coverage": pin(NODEID_COVERAGE),
                      "nodeid_count": len(actual_lists), "part_count": len(receipts),
                      "junit_summary": junit_summary,
                      "terminal_summary": terminal,
                      "terminal_totals": {"passed": terminal["passed"],
                                          "failed": terminal["failed"],
                                          "errors": terminal["errors"],
                                          "subtests": terminal["subtests_passed"]},
                      "collection_coverage": {
                          "status": "complete", "expected_node_count": len(expected_ids),
                          "executed_node_count": len(actual_lists),
                          "missing_node_ids": missing_ids,
                          "duplicate_node_ids": duplicate_ids},
                      "terminal_part_summaries": terminal_parts,
                      "baseline_bad_occurrences": sum(old_bad.values()),
                      "current_bad_occurrences": sum(new_bad.values()),
                      "new_bad": baseline_common.counter_rows(added),
                      "resolved_bad": baseline_common.counter_rows(resolved),
                      "no_new_bad": not added,
                      "whole_suite_passed": (not total_returncode_nonzero
                                             and junit_summary["failures"] == 0
                                             and junit_summary["errors"] == 0),
                      "part_returncode_nonzero": total_returncode_nonzero,
                      "bounded_execution": True,
                      "resource_stop_bytes": MEMORY_STOP_BYTES}
        comparison_path = COMPARISON_REPORT
        write_new(comparison_path, comparison)
        postverify = {"schema": "information.foreign_contracts.bounded_postverify.v1",
                      "status": comparison["status"], "batch": 90, "revision": "001",
                      "count": verified["count"], "freeze": pin(NEW_FREEZE),
                      "regression_comparison": pin(comparison_path),
                      "nodeid_coverage": pin(NODEID_COVERAGE),
                      "current_sources_match_snapshots": True,
                      "no_new_bad": not added,
                      "whole_suite_passed": comparison["whole_suite_passed"],
                      "created_at": _stamp()}
        write_new(POSTVERIFY_REPORT, postverify)
        print(json.dumps(comparison, ensure_ascii=False), flush=True)
        return 0 if not added else 2
    except Exception as exc:
        if not boundary.exists():
            write_new(boundary, {"schema": "information.foreign_contracts.bounded_full_boundary.v1",
                                 "status": "failed_harness_exception",
                                 "error": f"{type(exc).__name__}:{exc}",
                                 "freeze": pin(NEW_FREEZE), "partial_parts": receipts,
                                 "progress": pin(progress) if progress.is_file() else None,
                                 "finished_at": _stamp()})
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare", action="store_true", help="verify accepted baseline and write only an inert preparation receipt")
    modes.add_argument("--freeze", action="store_true", help="pin the explicitly supplied source set")
    modes.add_argument("--verify", action="store_true", help="verify baseline and current source freeze")
    modes.add_argument("--run", action="store_true", help="explicitly collect and run all bridge/tests in bounded batches")
    add_path_arguments(parser)
    args = parser.parse_args(argv)
    configure_paths(args)
    if args.prepare:
        print(json.dumps(write_preparation_receipt(), ensure_ascii=False), flush=True)
        return 0
    if args.run:
        return full()
    if args.verify:
        print(json.dumps({"status": "passed", **verify_sources()}, ensure_ascii=False))
        return 0
    if args.freeze:
        freeze()
        return 0
    print(json.dumps(prepare_harness(), ensure_ascii=False), flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
