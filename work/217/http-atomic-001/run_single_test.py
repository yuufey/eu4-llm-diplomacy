"""Run and receipt the one offline HTTP atomicity regression case."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

import psutil
import pytest


EVIDENCE = Path(__file__).resolve().parent
ROOT = EVIDENCE.parents[2]
NODE_ID = (
    "bridge/tests/test_diplomacy_lab_http.py::ResearchHTTPTests::"
    "test_concurrent_requests_in_one_instance_never_double_publish"
)
LIMIT_BYTES = 1024**3


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def in_evidence(path: Path) -> str:
    resolved = path.resolve()
    resolved.relative_to(EVIDENCE)
    return str(resolved)


def terminate_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        root = psutil.Process(process.pid)
        targets = root.children(recursive=True) + [root]
    except psutil.Error:
        targets = []
    for target in targets:
        try:
            target.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(targets, timeout=5)
    for target in alive:
        try:
            target.kill()
        except psutil.Error:
            pass
    process.wait(timeout=5)


def main() -> int:
    source = ROOT / "bridge" / "diplomacy_lab_http.py"
    test = ROOT / "bridge" / "tests" / "test_diplomacy_lab_http.py"
    basetemp = EVIDENCE / "pytest-basetemp"
    os_temp = EVIDENCE / "os-temp"
    pycache = EVIDENCE / "pycache"
    for path in (EVIDENCE, basetemp, os_temp, pycache):
        path.mkdir(parents=True, exist_ok=True)
        in_evidence(path)

    junit = EVIDENCE / "junit.xml"
    merged_log = EVIDENCE / "merged-stdout-stderr.txt"
    receipt_path = EVIDENCE / "run-receipt.json"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        f"--basetemp={basetemp}",
        f"--junitxml={junit}",
        NODE_ID,
    ]
    env = os.environ.copy()
    for name in ("TEMP", "TMP", "TMPDIR"):
        env[name] = str(os_temp)
    env["PYTHONPYCACHEPREFIX"] = str(pycache)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    try:
        pytest_version = pytest.__version__
        psutil_version = psutil.__version__
    except Exception as error:
        raise RuntimeError(f"Cannot record runner dependencies: {error}") from error

    started_at = utc_now()
    started = time.monotonic()
    peak_by_pid: dict[str, dict[str, object]] = {}
    exceeded_limit = False
    timeout = False
    with merged_log.open("w", encoding="utf-8", newline="") as log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        while process.poll() is None:
            try:
                root_process = psutil.Process(process.pid)
                processes = root_process.children(recursive=True) + [root_process]
            except psutil.Error:
                processes = []
            for observed in processes:
                try:
                    rss = observed.memory_info().rss
                    key = str(observed.pid)
                    item = peak_by_pid.setdefault(
                        key,
                        {"pid": observed.pid, "name": observed.name(), "peak_rss_bytes": 0},
                    )
                    item["peak_rss_bytes"] = max(int(item["peak_rss_bytes"]), rss)
                    if rss >= LIMIT_BYTES:
                        exceeded_limit = True
                except psutil.Error:
                    continue
            if exceeded_limit:
                terminate_tree(process)
                break
            if time.monotonic() - started > 60:
                timeout = True
                terminate_tree(process)
                break
            time.sleep(0.1)
        actual_exit_code = process.wait()

    completed_at = utc_now()
    output = merged_log.read_text(encoding="utf-8", errors="replace")
    receipt = {
        "schema": "http-atomic-001-single-test-run-v1",
        "started_at_utc": started_at,
        "completed_at_utc": completed_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "working_directory": str(ROOT),
        "node_id": NODE_ID,
        "command": command,
        "subprocess_exit_code": actual_exit_code,
        "resource_limit_bytes_per_process": LIMIT_BYTES,
        "per_process_peak_rss": list(peak_by_pid.values()),
        "memory_limit_exceeded": exceeded_limit,
        "runner_timeout": timeout,
        "environment": {
            "python": sys.version,
            "python_executable": sys.executable,
            "pytest": pytest_version,
            "psutil": psutil_version,
            "platform": platform.platform(),
            "TEMP": str(os_temp),
            "TMP": str(os_temp),
            "TMPDIR": str(os_temp),
            "pytest_basetemp": str(basetemp),
            "PYTHONPYCACHEPREFIX": str(pycache),
        },
        "inputs": {
            str(source.relative_to(ROOT)): sha256(source),
            str(test.relative_to(ROOT)): sha256(test),
        },
        "artifacts": {
            "junit_xml": in_evidence(junit) if junit.exists() else None,
            "merged_stdout_stderr": in_evidence(merged_log),
            "pytest_basetemp": in_evidence(basetemp),
            "os_temp": in_evidence(os_temp),
        },
        "source_review": {
            "test_class": "ResearchHTTPTests",
            "test_fixture": "SyntheticRuntime plus TemporaryDirectory",
            "live_process_guard": "LiveLabProcess patched to raise AssertionError if called",
            "scope": "fake in-memory runtime and temporary synthetic mailbox; no HTTP listener or game process",
        },
        "existing_baseline_context": (
            "The current handoff records the existing broad 200-failure baseline. "
            "This receipt is a focused current-environment run; it does not infer "
            "which environment change explains any difference from that historical run."
        ),
        "merged_output_bytes": len(output.encode("utf-8")),
    }
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(output, end="")
    print(json.dumps({"actual_pytest_exit_code": actual_exit_code, "receipt": str(receipt_path)}))
    return actual_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
