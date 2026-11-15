"""Run the batch-87 bridge suite serially in bounded pytest processes.

Revision 001 exceeded the committed-memory stop threshold during one full
pytest process. This runner preserves the complete collected node-id multiset
and executes every collected item once in ordered, serial batches. It does not
change tests, pytest configuration, or the inherited 86 baseline.
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
STAGE = ROOT / "work/runtime/information-foreign-forces-20261029-001"
OUT = STAGE / "bounded-full-002"
PREPARATION = OUT / "preparation-001"
PARENT_FREEZE = STAGE / "source-freeze-001.json"
NEW_FREEZE = STAGE / "source-freeze-002.json"
STOP_RECEIPT = STAGE / "full-harness-preparation-001/full-resource-stop-001.json"
BASE = ROOT / "work/runtime/information-foreign-military-resources-20261029-001"
PUBLISHER = "work/finalize_information_foreign_forces_bounded.py"
RUNNER = "work/verify_information_foreign_forces_bounded.py"
ADDED_SOURCES = (RUNNER, PUBLISHER)
PLUGIN_NAME = "work.verify_information_foreign_forces_bounded"
COLLECTION_ENV = "INFORMATION_FOREIGN_FORCES_NODEID_OUTPUT"
MAX_BATCH_ITEMS = 150
MAX_DIRECT_COMMAND_CHARS = 26000
MEMORY_STOP_BYTES = 1_000_000_000
MONITOR_INTERVAL_SECONDS = 0.5
COLLECTION_SCHEMA = "information.foreign_forces.bounded_collection.v1"
PLAN_SCHEMA = "information.foreign_forces.bounded_execution_plan.v1"
FREEZE_SCHEMA = "information.foreign_forces.bounded_source_freeze.v1"
HARD_MEMORY_SCHEMA = "information.foreign_forces.bounded_memory_sample.v1"

RESEARCH_PYTHON = common.PYTHON
pin = common.pin
read_json = common.read_json
write_new = common.write_new
copy_stream = common.copy_stream


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
    frozen = _read_json(PARENT_FREEZE)
    if (frozen.get("schema") != "information.foreign_forces.source_freeze.v1"
            or frozen.get("batch") != 87 or frozen.get("revision") != "001"
            or frozen.get("status") != "passed" or frozen.get("count") != 886
            or len(frozen.get("files", [])) != 886):
        raise ValueError("parent_freeze_001_schema_or_count_invalid")
    current_parent_pin = pin(PARENT_FREEZE)
    # This reruns only the old harness's read-only input/source/snapshot checks.
    # It does not run test bodies, a server, an RPM, or the old full suite.
    verified = parent_verifier.verify_sources()
    if verified.get("count") != 886:
        raise ValueError("parent_freeze_001_verify_count_invalid")
    stop = _read_json(STOP_RECEIPT)
    stop_pin = pin(STOP_RECEIPT)
    peak = stop.get("memory_measurement", {}).get("peak_pagefile_usage_bytes")
    if (stop.get("schema") != "information.foreign_forces.full_resource_stop.v1"
            or stop.get("status") != "aborted_resource_threshold"
            or stop.get("full_not_completed") is not True
            or stop.get("xml_created") is not False
            or stop.get("comparison_created") is not False
            or stop.get("postverify_created") is not False
            or stop.get("freeze") != current_parent_pin
            or stop.get("reservation") != pin(STAGE / "full-execution-reservation-001.json")
            or stop.get("incomplete_log") != pin(STAGE / "regression-full-001.log")
            or isinstance(peak, bool) or not isinstance(peak, int)
            or peak <= MEMORY_STOP_BYTES):
        raise ValueError("resource_stop_001_receipt_invalid")
    if any(path.exists() for path in (
            STAGE / "regression-full-001.xml",
            STAGE / "regression-comparison-001.json",
            STAGE / "source-post-run-verification-001.json")):
        raise ValueError("revision_001_must_remain_incomplete")
    return frozen, stop, {"parent_freeze": current_parent_pin, "resource_stop": stop_pin}


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


def _argfile_probe() -> dict:
    folder = PREPARATION / "pytest-argfile-probe-001"
    folder.mkdir(parents=True, exist_ok=True)
    args_file = folder / "args.txt"
    if not args_file.is_file():
        args_file.write_text("--version\n", encoding="utf-8", newline="\n")
    probe_path = folder / "probe.json"
    stop_path = folder / "stop-receipt-001.json"
    from _pytest.config.argparsing import PytestArgumentParser
    parser = PytestArgumentParser(None, {})
    parser_support = getattr(parser, "fromfile_prefix_chars", None) == "@"
    if probe_path.is_file():
        existing = _read_json(probe_path)
        if "parser_support" in existing:
            return existing
        review_path = folder / "parser-support-review-001.json"
        if review_path.is_file():
            return _read_json(review_path)
        result = {"schema": "information.foreign_forces.pytest_argfile_probe_review.v1",
                  "parser_support": parser_support,
                  "runtime_probe_status": "stopped_ambiguous",
                  "runtime_probe": pin(stop_path) if stop_path.is_file() else None,
                  "legacy_incomplete_probe": pin(probe_path),
                  "args_file": pin(args_file), "argfile_used": False,
                  "direct_argv_fallback": True,
                  "argv_safety_cap_chars": MAX_DIRECT_COMMAND_CHARS,
                  "usage": "Installed parser declares @ support, but the runtime probe was ambiguous; use bounded direct argv."}
        write_new(review_path, result)
        return result
    result = {"schema": "information.foreign_forces.pytest_argfile_probe.v1",
              "parser_support": parser_support,
              "runtime_probe_status": "stopped_ambiguous" if stop_path.is_file() else "not_run",
              "runtime_probe": pin(stop_path) if stop_path.is_file() else None,
              "args_file": pin(args_file), "argfile_used": False,
              "direct_argv_fallback": True,
              "argv_safety_cap_chars": MAX_DIRECT_COMMAND_CHARS,
              "usage": "Response-file parser support recorded statically; the runtime probe was ambiguous, so bounded direct argv is used."}
    write_new(probe_path, result)
    return result


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
    parent, stop, parent_pins = _verify_parent()
    if not RESEARCH_PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{RESEARCH_PYTHON}")
    OUT.mkdir(parents=True, exist_ok=True)
    argfile = _argfile_probe()
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
        result = {"schema": "information.foreign_forces.bounded_collection_receipt.v1",
                  "status": "aborted_resource_threshold", "attempt": attempt,
                  "parent_freeze_001": parent_pins["parent_freeze"],
                  "resource_stop_001": parent_pins["resource_stop"],
                  "argfile_probe": argfile, "child": run}
        write_new(folder / "collection-receipt.json", result)
        return result
    if run["memory_query_error"]:
        raise RuntimeError(f"collection_memory_monitor_failed:{run['memory_query_error']}")
    if run["returncode"] != 0 or not node_output.is_file():
        result = {"schema": "information.foreign_forces.bounded_collection_receipt.v1",
                  "status": "failed_collection", "attempt": attempt,
                  "parent_freeze_001": parent_pins["parent_freeze"],
                  "resource_stop_001": parent_pins["resource_stop"],
                  "argfile_probe": argfile, "child": run,
                  "nodeids_written": node_output.is_file()}
        write_new(folder / "collection-receipt.json", result)
        return result
    captured = _read_json(node_output)
    nodeids = captured.get("nodeids")
    if (captured.get("schema") != COLLECTION_SCHEMA
            or not isinstance(nodeids, list) or captured.get("count") != len(nodeids)
            or not nodeids or any(not isinstance(item, str) or not item for item in nodeids)):
        raise ValueError("collection_plugin_output_invalid")
    chunks = _chunks(nodeids)
    if (not chunks or any(row["nodeid_count"] > MAX_BATCH_ITEMS for row in chunks)
            or sum(row["nodeid_count"] for row in chunks) != len(nodeids)):
        raise ValueError("bounded_chunk_plan_invalid")
    plan = {"schema": PLAN_SCHEMA, "attempt": attempt,
            "collection_receipt": pin(node_output), "nodeid_count": len(nodeids),
            "unique_nodeid_count": len(set(nodeids)), "nodeids": nodeids,
            "chunks": chunks, "max_batch_items": MAX_BATCH_ITEMS,
            "max_direct_command_chars": MAX_DIRECT_COMMAND_CHARS,
            "argfile_support": argfile["parser_support"],
            "argfile_runtime_probe_status": argfile["runtime_probe_status"],
            "argfile_used": False,
            "collection_command": argv,
            "collection_log": pin(log_path), "collection_monitor": pin(monitor),
            "collection_child": run, "parent_freeze_001": parent_pins["parent_freeze"],
            "resource_stop_001": parent_pins["resource_stop"],
            "created_at": _stamp()}
    plan_path = OUT / "collection-plan-001.json"
    write_new(plan_path, plan)
    result = {"schema": "information.foreign_forces.bounded_collection_receipt.v1",
              "status": "passed", "attempt": attempt,
              "nodeid_count": len(nodeids), "unique_nodeid_count": len(set(nodeids)),
              "batch_count": len(chunks), "max_batch_items": max(r["nodeid_count"] for r in chunks),
              "max_command_chars": max(r["direct_command_chars"] for r in chunks),
              "argfile_supported": argfile["parser_support"], "argfile_used": False,
              "collection_plan": pin(plan_path), "child": run}
    write_new(folder / "collection-receipt.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


def _load_collection_plan() -> tuple[dict, dict]:
    plan_path = OUT / "collection-plan-001.json"
    plan = _read_json(plan_path)
    receipt = _read_json(OUT / f"collection-{plan['attempt']:03d}/collection-receipt.json")
    if (plan.get("schema") != PLAN_SCHEMA or receipt.get("status") != "passed"
            or receipt.get("collection_plan") != pin(plan_path)
            or plan.get("nodeid_count") != len(plan.get("nodeids", []))):
        raise ValueError("collection_plan_or_receipt_mismatch")
    if pin(plan["collection_receipt"]["path"]) != plan["collection_receipt"]:
        raise ValueError("collection_nodeid_file_pin_mismatch")
    nodeids = plan["nodeids"]
    chunks = plan.get("chunks")
    if (not isinstance(nodeids, list) or not isinstance(chunks, list)
            or sum(row.get("nodeid_count", 0) for row in chunks) != len(nodeids)
            or any(row.get("nodeid_count", MAX_BATCH_ITEMS + 1) > MAX_BATCH_ITEMS
                   for row in chunks)):
        raise ValueError("collection_plan_shape_invalid")
    return plan, receipt


def freeze() -> dict:
    parent, stop, parent_pins = _verify_parent()
    plan, collection = _load_collection_plan()
    if not (ROOT / PUBLISHER).is_file():
        raise FileNotFoundError(f"bounded_publisher_missing:{PUBLISHER}")
    if NEW_FREEZE.exists() or (OUT / "source-snapshots-002").exists():
        raise FileExistsError("bounded_source_freeze_002_already_started")
    parent_rows = parent["files"]
    if len(parent_rows) != 886:
        raise ValueError("parent_source_rows_count_mismatch")
    snapshot_dir = OUT / "source-snapshots-002"
    _mkdir_new(snapshot_dir)
    rows = list(parent_rows)
    added_before = {source: pin(source) for source in ADDED_SOURCES}
    added_rows = []
    for source in ADDED_SOURCES:
        snapshot = snapshot_dir / Path(source)
        copy_stream(source, snapshot)
        source_after = pin(source)
        snapshot_pin = pin(snapshot)
        if (source_after != added_before[source]
                or (source_after["bytes"], source_after["sha256"]) !=
                (snapshot_pin["bytes"], snapshot_pin["sha256"])):
            raise RuntimeError(f"bounded_added_source_changed:{source}")
        added_rows.append({"source": source_after, "snapshot": snapshot_pin})
    rows.extend(added_rows)
    rows.sort(key=lambda row: row["source"]["path"])
    if len(rows) != 888 or len({row["source"]["path"] for row in rows}) != 888:
        raise ValueError("bounded_freeze_union_count_or_duplicate_mismatch")
    value = {"schema": FREEZE_SCHEMA, "batch": 87, "revision": "002",
             "status": "passed", "count": len(rows), "files": rows,
             "freeze_path": NEW_FREEZE.relative_to(ROOT).as_posix(),
             "parent_freeze_001": parent_pins["parent_freeze"],
             "resource_stop_001": parent_pins["resource_stop"],
             "inherited_file_count": len(parent_rows), "added_file_count": len(added_rows),
             "added_sources": added_rows,
             "collection_plan": pin(OUT / "collection-plan-001.json"),
             "collection_receipt": collection,
             "inherited_snapshots_reused_without_copy": True,
             "source_snapshot_policy":
                 "reuse the exact 886-file batch-87 revision-001 freeze; snapshot only this bounded runner and the bounded publisher",
             "created_at": _stamp()}
    write_new(NEW_FREEZE, value)
    result = {"schema": FREEZE_SCHEMA, "status": "passed", "count": len(rows),
              "path": NEW_FREEZE.relative_to(ROOT).as_posix(),
              "freeze": pin(NEW_FREEZE), "added_sources": added_rows,
              "parent_freeze_001": parent_pins["parent_freeze"],
              "resource_stop_001": parent_pins["resource_stop"]}
    write_new(OUT / "source-freeze-receipt-002.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


def verify_sources() -> dict:
    parent, stop, parent_pins = _verify_parent()
    frozen = _read_json(NEW_FREEZE)
    if (frozen.get("schema") != FREEZE_SCHEMA or frozen.get("batch") != 87
            or frozen.get("revision") != "002" or frozen.get("status") != "passed"
            or frozen.get("freeze_path") != NEW_FREEZE.relative_to(ROOT).as_posix()
            or frozen.get("count") != 888 or len(frozen.get("files", [])) != 888
            or frozen.get("parent_freeze_001") != parent_pins["parent_freeze"]
            or frozen.get("resource_stop_001") != parent_pins["resource_stop"]
            or frozen.get("collection_plan") != pin(OUT / "collection-plan-001.json")):
        raise ValueError("bounded_freeze_002_metadata_invalid")
    if frozen.get("inherited_file_count") != 886 or frozen.get("added_file_count") != 2:
        raise ValueError("bounded_freeze_002_counts_invalid")
    old_by_path = {row["source"]["path"]: row for row in parent["files"]}
    new_paths = set(ADDED_SOURCES)
    seen = set()
    for row in frozen["files"]:
        source = row["source"]
        snapshot = row["snapshot"]
        path = source["path"]
        if path in seen:
            raise ValueError(f"bounded_freeze_duplicate:{path}")
        seen.add(path)
        if path in old_by_path:
            if row != old_by_path[path]:
                raise ValueError(f"bounded_inherited_row_changed:{path}")
        elif path in new_paths:
            if pin(path) != source or pin(snapshot["path"]) != snapshot:
                raise ValueError(f"bounded_added_source_pin_changed:{path}")
            if (source["bytes"], source["sha256"]) != (snapshot["bytes"], snapshot["sha256"]):
                raise ValueError(f"bounded_added_snapshot_mismatch:{path}")
        else:
            raise ValueError(f"bounded_unapproved_source:{path}")
        if path not in new_paths:
            if pin(source["path"]) != source or pin(snapshot["path"]) != snapshot:
                raise ValueError(f"bounded_inherited_source_pin_changed:{path}")
    if seen != set(old_by_path) | new_paths:
        raise ValueError("bounded_source_union_mismatch")
    return {"schema": frozen["schema"], "count": frozen["count"],
            "path": NEW_FREEZE.relative_to(ROOT).as_posix(),
            "freeze": pin(NEW_FREEZE),
            "parent_freeze_001": parent_pins["parent_freeze"],
            "resource_stop_001": parent_pins["resource_stop"]}


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
        receipt = {"schema": "information.foreign_forces.bounded_part.v1",
                   "status": "aborted_resource_threshold", "index": index,
                   "expected_ids": expected_pin, "child": run,
                   "xml_created": xml_path.is_file(), "actual_collection_created": actual_path.is_file()}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    if run["memory_query_error"]:
        receipt = {"schema": "information.foreign_forces.bounded_part.v1",
                   "status": "aborted_memory_monitor_error", "index": index,
                   "expected_ids": expected_pin, "child": run,
                   "xml_created": xml_path.is_file(), "actual_collection_created": actual_path.is_file()}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    if not actual_path.is_file() or not xml_path.is_file():
        receipt = {"schema": "information.foreign_forces.bounded_part.v1",
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
        receipt = {"schema": "information.foreign_forces.bounded_part.v1",
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
        receipt = {"schema": "information.foreign_forces.bounded_part.v1",
                   "status": "failed_invalid_junit_xml", "index": index,
                   "expected_ids": expected_pin, "actual_ids": pin(actual_path),
                   "child": run, "xml": pin(xml_path),
                   "error": f"{type(exc).__name__}:{exc}"}
        write_new(folder / "part-receipt.json", receipt)
        return receipt
    if junit.tag not in ("testsuite", "testsuites"):
        raise ValueError("bounded_part_junit_root_invalid")
    receipt = {"schema": "information.foreign_forces.bounded_part.v1",
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
    merged = ET.Element("testsuites", {"name": "pytest bridge/tests bounded full 002",
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
    plan, _collection = _load_collection_plan()
    reservation = OUT / "full-execution-reservation-002.json"
    boundary = OUT / "full-execution-boundary-002.json"
    progress = OUT / "batch-progress-002.jsonl"
    receipts: list[dict] = []
    if any(path.exists() for path in (reservation, boundary, progress,
                                      OUT / "regression-full-002.xml",
                                      OUT / "regression-full-002.log",
                                      STAGE / "regression-comparison-002.json",
                                      STAGE / "source-post-run-verification-002.json")):
        raise FileExistsError("bounded_full_002_already_started")
    chunks = plan["chunks"]
    write_new(reservation, {"schema": "information.foreign_forces.bounded_full_reservation.v1",
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
                write_new(boundary, {"schema": "information.foreign_forces.bounded_full_boundary.v1",
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
            write_new(boundary, {"schema": "information.foreign_forces.bounded_full_boundary.v1",
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
        node_coverage = {"schema": "information.foreign_forces.bounded_nodeid_coverage.v1",
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
        write_new(OUT / "nodeid-coverage-002.json", node_coverage)
        xml = OUT / "regression-full-002.xml"
        log = OUT / "regression-full-002.log"
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
        batch87_common = parent_verifier.common
        old_bad = batch87_common.bad_cases(BASE / "regression-full-001.xml")
        new_bad = batch87_common.bad_cases(xml)
        added, resolved = new_bad - old_bad, old_bad - new_bad
        total_returncode_nonzero = [r["index"] for r in receipts if r.get("returncode") != 0]
        complete = {"schema": "information.foreign_forces.bounded_full_boundary.v1",
                    "status": "completed", "returncode_nonzero_parts": total_returncode_nonzero,
                    "part_count": len(receipts), "nodeid_count": len(actual_lists),
                    "xml": pin(xml), "log": log_pin, "nodeid_coverage": pin(OUT / "nodeid-coverage-002.json"),
                    "finished_at": _stamp()}
        write_new(boundary, complete)
        # Reverify every frozen source after the final part and XML merge.
        verified = verify_sources()
        comparison = {"schema": "information.foreign_forces.bounded_regression_comparison.v1",
                      "status": "passed_no_new_bad" if not added else "failed_new_bad",
                      "batch": 87, "revision": "002", "parent_baseline_batch": 86,
                      "parent_baseline_full": pin(BASE / "regression-full-001.xml"),
                      "freeze": pin(NEW_FREEZE), "current": pin(xml), "log": log_pin,
                      "nodeid_coverage": pin(OUT / "nodeid-coverage-002.json"),
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
                      "new_bad": batch87_common.counter_rows(added),
                      "resolved_bad": batch87_common.counter_rows(resolved),
                      "no_new_bad": not added,
                      "whole_suite_passed": (not total_returncode_nonzero
                                             and junit_summary["failures"] == 0
                                             and junit_summary["errors"] == 0),
                      "part_returncode_nonzero": total_returncode_nonzero,
                      "bounded_execution": True,
                      "resource_stop_bytes": MEMORY_STOP_BYTES}
        comparison_path = STAGE / "regression-comparison-002.json"
        write_new(comparison_path, comparison)
        postverify = {"schema": "information.foreign_forces.bounded_postverify.v1",
                      "status": comparison["status"], "batch": 87, "revision": "002",
                      "count": verified["count"], "freeze": pin(NEW_FREEZE),
                      "regression_comparison": pin(comparison_path),
                      "nodeid_coverage": pin(OUT / "nodeid-coverage-002.json"),
                      "current_sources_match_snapshots": True,
                      "no_new_bad": not added,
                      "whole_suite_passed": comparison["whole_suite_passed"],
                      "created_at": _stamp()}
        write_new(STAGE / "source-post-run-verification-002.json", postverify)
        print(json.dumps(comparison, ensure_ascii=False), flush=True)
        return 0 if not added else 2
    except Exception as exc:
        if not boundary.exists():
            write_new(boundary, {"schema": "information.foreign_forces.bounded_full_boundary.v1",
                                 "status": "failed_harness_exception",
                                 "error": f"{type(exc).__name__}:{exc}",
                                 "freeze": pin(NEW_FREEZE), "partial_parts": receipts,
                                 "progress": pin(progress) if progress.is_file() else None,
                                 "finished_at": _stamp()})
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "freeze", "verify", "full"))
    args = parser.parse_args(argv)
    if args.operation == "prepare":
        result = prepare_collection()
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0 if result.get("status") == "passed" else 3
    if args.operation == "freeze":
        freeze()
        return 0
    if args.operation == "verify":
        frozen = verify_sources()
        print(json.dumps({"status": "passed", **frozen}, ensure_ascii=False))
        return 0
    return full()


if __name__ == "__main__":
    raise SystemExit(main())
