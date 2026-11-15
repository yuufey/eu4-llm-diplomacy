"""Build and verify the fixed 1.37.4 message-entry trampoline plans.

The native fixture exercises the header's three fixed plans, bounded copied
prefixes, projected unwind rows, RtlVirtualUnwind, and an actual RX
trampoline-to-owned-body call.  This runner additionally pins the exact
bounded PE windows used by the contract.  It never opens EU4 or uses REA.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = (ROOT / "work" / "runtime" / "information-battle-container-20261026-001"
         / "message-entry-test-001")
HEADER = NATIVE / "information-battle-message-entry-plan.h"
CPP = NATIVE / "tests" / "information-battle-message-entry-test.cpp"
SCRIPT = Path(__file__).resolve()
CONTRACT = (ROOT / "work" / "runtime" / "information-battle-text-20261026-001"
            / "formatter-template-gate-001.json")
TARGET = (ROOT / "work" / "runtime" / "ghidra-full"
          / "b23fa0e1f698d31b-20261014T054913Z-6dda97"
          / "input" / "eu4.exe")
EXE = STAGE / "test-information-battle-message-entry.exe"
REPORT = STAGE / "report.json"

EXPECTED_TARGET_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)

EXPECTED_WINDOWS: dict[str, tuple[int, bytes]] = {
    "router_prefix": (
        0x23A020,
        bytes.fromhex(
            "48895c24105556574154415541564157488bec4881ec80000000"
        ),
    ),
    "router_unwind": (
        0x1DE6D8C,
        bytes.fromhex(
            "111a0a001a3419001af210f00ee00cd00ac00870076006509c4da301"
        ),
    ),
    "message_prefix": (
        0x244630,
        bytes.fromhex("4889542410534881ec00010000488bda"),
    ),
    "message_unwind": (
        0x1DE7940,
        bytes.fromhex("110d03000d012000063000009c4da301"),
    ),
    "cleanup_prefix": (
        0x1AF740,
        bytes.fromhex("48895c2410564883ec20488b19488bf1"),
    ),
    "cleanup_unwind": (
        0x1DCAD04,
        bytes.fromhex("010a04000a3407000a320660"),
    ),
}

EXPECTED_FILE_WINDOWS: dict[str, tuple[int, bytes]] = {
    "cleanup_pdata": (
        0x233D0BC,
        bytes.fromhex("40f71a0055f71a0004addc01"),
    ),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def read_at(path: Path, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or size > 1024 * 1024:
        raise ValueError("bounded_read_requested_outside_limit")
    with path.open("rb") as stream:
        stream.seek(offset)
        value = stream.read(size)
    if len(value) != size:
        raise ValueError("bounded_read_truncated")
    return value


def parse_pe_sections(path: Path) -> tuple[int, list[dict[str, int]]]:
    dos = read_at(path, 0, 64)
    if dos[:2] != b"MZ":
        raise ValueError("missing_mz")
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    file_header = read_at(path, pe_offset, 24)
    if file_header[:4] != b"PE\0\0":
        raise ValueError("missing_pe_signature")
    section_count = struct.unpack_from("<H", file_header, 6)[0]
    optional_size = struct.unpack_from("<H", file_header, 20)[0]
    optional = read_at(path, pe_offset + 24, optional_size)
    magic = struct.unpack_from("<H", optional, 0)[0]
    if magic != 0x20B:
        raise ValueError("not_pe32_plus")
    image_base = struct.unpack_from("<Q", optional, 24)[0]
    section_table = pe_offset + 24 + optional_size
    raw = read_at(path, section_table, section_count * 40)
    sections: list[dict[str, int]] = []
    for index in range(section_count):
        start = index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", raw, start + 8
        )
        sections.append({
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_pointer": raw_pointer,
        })
    return image_base, sections


def rva_window(path: Path, sections: list[dict[str, int]], rva: int,
               size: int) -> bytes:
    if rva < 0 or size < 0 or size > 1024:
        raise ValueError("bounded_rva_window_invalid")
    for section in sections:
        va = section["virtual_address"]
        raw_size = section["raw_size"]
        if va <= rva and rva - va <= raw_size and rva - va + size <= raw_size:
            return read_at(path, section["raw_pointer"] + rva - va, size)
    raise ValueError(f"rva_window_unmapped:{rva:x}:{size}")


def check_pe_windows() -> dict[str, Any]:
    actual_sha = sha256_file(TARGET)
    image_base, sections = parse_pe_sections(TARGET)
    windows: dict[str, Any] = {}
    failures: list[str] = []
    for name, (rva, expected) in EXPECTED_WINDOWS.items():
        actual = rva_window(TARGET, sections, rva, len(expected))
        passed = actual == expected
        windows[name] = {
            "rva": hex(rva),
            "bytes": len(expected),
            "expected_hex": expected.hex(),
            "actual_hex": actual.hex(),
            "pass": passed,
        }
        if not passed:
            failures.append(name)
    # The message prefix is the exact first 16 bytes from the ledger.  The
    # following instruction is outside the copied patch window and remains a
    # separate body check; cleanup has the same 16-byte boundary contract.
    message_body_rva = 0x244640
    message_body = rva_window(TARGET, sections, message_body_rva, 3)
    windows["message_body_after_patch_window"] = {
        "rva": hex(message_body_rva),
        "actual_hex": message_body.hex(),
        "expected_hex": "4c8bd1",
        "pass": message_body == bytes.fromhex("4c8bd1"),
        "meaning": "message body instruction begins after the exact 16-byte prefix",
    }
    if message_body != bytes.fromhex("4c8bd1"):
        failures.append("message_body_after_patch_window")
    for name, (offset, expected) in EXPECTED_FILE_WINDOWS.items():
        actual = read_at(TARGET, offset, len(expected))
        passed = actual == expected
        windows[name] = {
            "file_offset": hex(offset),
            "bytes": len(expected),
            "expected_hex": expected.hex(),
            "actual_hex": actual.hex(),
            "pass": passed,
        }
        if not passed:
            failures.append(name)
    return {
        "target_sha256": actual_sha,
        "target_sha256_expected": EXPECTED_TARGET_SHA256,
        "target_sha256_pass": actual_sha == EXPECTED_TARGET_SHA256,
        "image_base": hex(image_base),
        "section_count": len(sections),
        "windows": windows,
        "failures": failures,
    }


def run() -> dict[str, Any]:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "information_battle_message_entry_plan_test_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rea_access": False,
            "remote_process_access": False,
            "native_execution": True,
            "target_pe_access": "bounded_headers_and_windows_plus_streaming_sha256",
            "claim": "fixed-build synthetic RX trampoline fixture; not a production installation",
        },
        "source_pins": {},
        "compile": {},
        "run": {},
        "pe_checks": {},
    }
    for path in (HEADER, CPP, SCRIPT, CONTRACT):
        if path.exists():
            report["source_pins"][path.name] = pin(path)
    if not TARGET.exists():
        report["status"] = "blocked_missing_target"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report
    report["source_pins"]["eu4.exe"] = pin(TARGET)
    try:
        report["pe_checks"] = check_pe_windows()
    except (OSError, ValueError, struct.error) as exc:
        report["status"] = "pe_check_failed"
        report["pe_checks"] = {"error": str(exc)}
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report
    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report
    command = [
        compiler,
        "-std=c++17",
        "-fno-exceptions",
        "-fno-rtti",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        "-I",
        str(NATIVE),
        str(CPP),
        "-o",
        str(EXE),
        "-lkernel32",
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    compile_stdout = compiled.stdout.decode("utf-8", errors="replace")
    compile_stderr = compiled.stderr.decode("utf-8", errors="replace")
    (STAGE / "compile.stdout.log").write_text(compile_stdout, encoding="utf-8")
    (STAGE / "compile.stderr.log").write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "compiler": compiler,
        "returncode": compiled.returncode,
        "stdout": compile_stdout,
        "stderr": compile_stderr,
    }
    if compiled.returncode != 0 or not EXE.exists():
        report["status"] = "compile_failed"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report
    report["artifact"] = pin(EXE)
    executed = subprocess.run([str(EXE)], cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=90, check=False)
    run_stdout = executed.stdout.decode("utf-8", errors="replace")
    run_stderr = executed.stderr.decode("utf-8", errors="replace")
    (STAGE / "run.stdout.log").write_text(run_stdout, encoding="utf-8")
    (STAGE / "run.stderr.log").write_text(run_stderr, encoding="utf-8")
    checks = [line for line in run_stdout.splitlines()
              if line.startswith("CHECK ")]
    result_line = next((line for line in run_stdout.splitlines()
                        if line.startswith("RESULT ")), "")
    report["run"] = {
        "command": [str(EXE)],
        "returncode": executed.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "check_count": len(checks),
        "check_failures": [line for line in checks if not line.endswith(" PASS")],
        "result_line": result_line,
    }
    pe_ok = bool(report["pe_checks"].get("target_sha256_pass")) \
        and not report["pe_checks"].get("failures")
    report["status"] = (
        "passed" if executed.returncode == 0 and result_line == "RESULT PASS"
        and checks and not report["run"]["check_failures"] and pe_ok
        else "failed"
    )
    report["elapsed_seconds"] = time.time() - started
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true",
                        help="build and run the native fixture (default action)")
    parser.parse_args()
    result = run()
    print(json.dumps({
        "status": result["status"],
        "report": REPORT.relative_to(ROOT).as_posix(),
        "artifact": result.get("artifact"),
    }, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
