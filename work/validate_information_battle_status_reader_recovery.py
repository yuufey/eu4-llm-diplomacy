"""Hold one read handle briefly and verify native heartbeat publication recovers."""
from __future__ import annotations
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.control_information_battle_observer import run_control
from work.verify_information_battle_autonomous import put


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--installation", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--test-only", action="store_true", required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    before = run_control(args.installation, "status")
    put(args.output / "before.json", before)
    native = before["native"]
    if native["state"] != "disabled" or native["status_publication_pending"] is not False:
        raise ValueError("quiescent_disabled_source_required")
    count = native["status_publication_failures"]
    put(args.output / "intent.json", {"test_only": True, "read_handle_ms": 1300,
        "native_control_dispatched": False, "target": "information-battle-status.json", "retry_authorized": False})
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
    kernel.CreateFileW.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    kernel.CloseHandle.restype = W.BOOL
    path = args.installation.parent / "information-battle-status.json"
    handle = kernel.CreateFileW(str(path.resolve()), 0x80000000, 1, None, 3, 0x80, None)
    if handle == W.HANDLE(-1).value:
        raise C.WinError(C.get_last_error())
    started = time.time_ns()
    try:
        time.sleep(1.3)
    finally:
        kernel.CloseHandle(handle)
    released = time.time_ns()
    deadline = time.monotonic() + 3.0
    while True:
        after = run_control(args.installation, "status")
        current = after["native"]
        if after["observed_at_ns"] > released and current["status_publication_pending"] is False:
            break
        if time.monotonic() >= deadline:
            put(args.output / "after-timeout.json", after)
            raise ValueError("heartbeat_not_recovered_no_retry")
        time.sleep(0.1)
    put(args.output / "after.json", after)
    checks = {"source_stayed_disabled": current["state"] == "disabled",
        "failure_recorded": current["status_publication_failures"] > count,
        "replace_error_preserved": current["status_write_stage"] == "replace" and current["status_write_error"] in (5, 32, 33),
        "published_after_release": after["observed_at_ns"] > released,
        "no_control_or_capture": current["last_sequence"] == native["last_sequence"] and current["captured"] == native["captured"]}
    report = {"status": "passed" if all(checks.values()) else "failed", "checks": checks,
        "native_control_dispatched": False, "started_at_ns": started, "released_at_ns": released,
        "publication_failures_before": count, "publication_failures_after": current["status_publication_failures"]}
    put(args.output / "report.json", report)
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
