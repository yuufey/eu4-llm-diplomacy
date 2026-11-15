"""Build and verify the fixed-build Line1 setter entry fixture.

The default action is intentionally inert.  ``--run`` is required to perform
bounded mmap PE checks, compile the owned native fixture, and execute its RX
trampoline/RtlVirtualUnwind checks.  The target executable is never started.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = (ROOT / "work" / "runtime" /
         "information-battle-native-text-20261027-001" /
         "line1-entry-test-001")
HEADER = NATIVE / "information-battle-line1-entry-plan.h"
STUB = NATIVE / "information-battle-line1-entry-stub.S"
CPP = NATIVE / "tests" / "information-battle-line1-entry-test.cpp"
ABI = NATIVE / "tests" / "information-battle-line1-abi.S"
SCRIPT = Path(__file__).resolve()
TARGET = (ROOT / "work" / "runtime" / "ghidra-full" /
          "b23fa0e1f698d31b-20261014T054913Z-6dda97" /
          "input" / "eu4.exe")
EXE = STAGE / "test-information-battle-line1-entry.exe"
REPORT = STAGE / "report.json"

EXPECTED_TARGET_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_IMAGE_BASE = 0x140000000
ENTRY_RVA = 0x152AD10
CONTINUATION_RVA = 0x152AD24
FUNCTION_END_RVA = 0x152AD92
UNWIND_RVA = 0x1DCA66C
PDATA_RVA = 0x2465000
PDATA_ROW_FILE_OFFSET = 0x23B3CB8
UNWIND_FILE_OFFSET = 0x1DC986C
EXPECTED_PREFIX = bytes.fromhex(
    "48895c240848896c24104889742418574883ec20"
)
EXPECTED_PDATA_ROW = bytes.fromhex("10ad520192ad52016ca6dc01")
EXPECTED_UNWIND = bytes.fromhex(
    "0114080014640800145407001434060014321070"
)


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


def parse_pe_sections(mapped: mmap.mmap) -> tuple[int, list[dict[str, int]]]:
    def read(offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(mapped):
            raise ValueError("bounded_pe_read_out_of_file")
        value = mapped[offset:offset + size]
        if len(value) != size:
            raise ValueError("bounded_pe_read_truncated")
        return value

    dos = read(0, 64)
    if dos[:2] != b"MZ":
        raise ValueError("missing_mz")
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    file_header = read(pe_offset, 24)
    if file_header[:4] != b"PE\0\0":
        raise ValueError("missing_pe_signature")
    section_count = struct.unpack_from("<H", file_header, 6)[0]
    optional_size = struct.unpack_from("<H", file_header, 20)[0]
    optional_offset = pe_offset + 24
    optional = read(optional_offset, optional_size)
    if struct.unpack_from("<H", optional, 0)[0] != 0x20B:
        raise ValueError("not_pe32_plus")
    image_base = struct.unpack_from("<Q", optional, 24)[0]
    number_of_rva_and_sizes = struct.unpack_from("<I", optional, 108)[0]
    if number_of_rva_and_sizes < 4:
        raise ValueError("missing_exception_directory")
    pdata_rva, pdata_size = struct.unpack_from("<II", optional, 112 + 8 * 3)
    section_table = optional_offset + optional_size
    sections: list[dict[str, int]] = []
    for index in range(section_count):
        row = read(section_table + index * 40, 40)
        name = row[:8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", row, 8)
        sections.append({
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_pointer": raw_pointer,
        })
    return image_base, pdata_rva, pdata_size, sections


def rva_to_file(sections: list[dict[str, int]], rva: int,
                size: int) -> int:
    if size <= 0 or size > 64 * 1024:
        raise ValueError("bounded_rva_window_invalid")
    for section in sections:
        va = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if va <= rva and rva + size <= va + span:
            delta = rva - va
            if delta + size > section["raw_size"]:
                raise ValueError("rva_window_without_raw_bytes")
            return section["raw_pointer"] + delta
    raise ValueError(f"rva_window_unmapped:{rva:x}:{size:x}")


def ordinary_pe_checks() -> dict[str, Any]:
    if not TARGET.exists():
        raise FileNotFoundError(str(TARGET))
    actual_sha = sha256_file(TARGET)
    failures: list[str] = []
    with TARGET.open("rb") as stream, mmap.mmap(
            stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        image_base, pdata_rva, pdata_size, sections = parse_pe_sections(mapped)

        def read_rva(rva: int, size: int) -> tuple[int, bytes]:
            offset = rva_to_file(sections, rva, size)
            return offset, bytes(mapped[offset:offset + size])

        prefix_offset, prefix = read_rva(ENTRY_RVA, len(EXPECTED_PREFIX))
        unwind_offset, unwind = read_rva(UNWIND_RVA, len(EXPECTED_UNWIND))
        pdata_offset, pdata_row = read_rva(PDATA_RVA + 43962 * 12, 12)
        if pdata_offset != PDATA_ROW_FILE_OFFSET:
            failures.append("pdata_row_file_offset")
        if prefix != EXPECTED_PREFIX:
            failures.append("entry_prefix")
        if pdata_row != EXPECTED_PDATA_ROW:
            failures.append("pdata_row")
        if unwind != EXPECTED_UNWIND:
            failures.append("unwind_info")
        if image_base != EXPECTED_IMAGE_BASE:
            failures.append("image_base")
        if pdata_rva != PDATA_RVA:
            failures.append("pdata_directory_rva")

        row_begin, row_end, row_unwind = struct.unpack("<III", pdata_row)
        windows = {
            "entry_prefix": {
                "rva": hex(ENTRY_RVA),
                "file_offset": hex(prefix_offset),
                "bytes": len(prefix),
                "expected_hex": EXPECTED_PREFIX.hex(),
                "actual_hex": prefix.hex(),
                "pass": prefix == EXPECTED_PREFIX,
            },
            "pdata_row": {
                "directory_rva": hex(pdata_rva),
                "directory_size": pdata_size,
                "row_index": 43962,
                "file_offset": hex(pdata_offset),
                "expected_file_offset": hex(PDATA_ROW_FILE_OFFSET),
                "bytes": len(pdata_row),
                "expected_hex": EXPECTED_PDATA_ROW.hex(),
                "actual_hex": pdata_row.hex(),
                "decoded": {
                    "begin_rva": hex(row_begin),
                    "end_rva": hex(row_end),
                    "unwind_rva": hex(row_unwind),
                },
                "pass": pdata_row == EXPECTED_PDATA_ROW
                    and pdata_offset == PDATA_ROW_FILE_OFFSET,
            },
            "unwind_info": {
                "rva": hex(UNWIND_RVA),
                "file_offset": hex(unwind_offset),
                "bytes": len(unwind),
                "expected_hex": EXPECTED_UNWIND.hex(),
                "actual_hex": unwind.hex(),
                "pass": unwind == EXPECTED_UNWIND,
            },
        }
        window_hashes = {
            "entry_prefix_sha256": hashlib.sha256(prefix).hexdigest(),
            "pdata_row_sha256": hashlib.sha256(pdata_row).hexdigest(),
            "unwind_info_sha256": hashlib.sha256(unwind).hexdigest(),
        }
    return {
        "method": "read_only_mmap_bounded_pe_windows",
        "target_sha256": actual_sha,
        "target_sha256_expected": EXPECTED_TARGET_SHA256,
        "target_sha256_pass": actual_sha == EXPECTED_TARGET_SHA256,
        "image_base": hex(image_base),
        "sections": len(sections),
        "windows": windows,
        "window_hashes": window_hashes,
        "failures": failures,
        "no_full_disassembly": True,
    }


def write_report(report: dict[str, Any]) -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")


def run() -> dict[str, Any]:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "information_battle_line1_entry_fixture_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rea_access": False,
            "remote_process_access": False,
            "native_execution": True,
            "target_pe_access": "read_only_mmap_bounded_windows_plus_streaming_sha256",
            "claim": "fixed-build synthetic RX trampoline and RtlVirtualUnwind fixture; not an installed-game hook",
        },
        "source_pins": {},
        "ordinary_pe": {},
        "compile": {},
        "run": {},
        "owned_cleanup": {
            "native_required": [
                "RtlDeleteFunctionTable",
                "VirtualFree(stack)",
                "VirtualFree(trampoline)",
            ],
            "artifact_retained_for_repro": True,
        },
    }
    for path in (HEADER, STUB, CPP, ABI, SCRIPT):
        if path.exists():
            report["source_pins"][path.name] = pin(path)
    if not TARGET.exists():
        report["status"] = "blocked_missing_target"
        report["elapsed_seconds"] = time.time() - started
        write_report(report)
        return report
    report["source_pins"]["eu4.exe"] = pin(TARGET)
    try:
        report["ordinary_pe"] = ordinary_pe_checks()
    except (OSError, ValueError, struct.error) as exc:
        report["status"] = "pe_check_failed"
        report["ordinary_pe"] = {"error": str(exc)}
        report["elapsed_seconds"] = time.time() - started
        write_report(report)
        return report
    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_report(report)
        return report
    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti",
        "-Wall", "-Wextra", "-Werror", "-O2", "-I", str(NATIVE),
        str(CPP), str(STUB), str(ABI), "-o", str(EXE), "-lkernel32",
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
        write_report(report)
        return report
    report["source_pins"][EXE.name] = pin(EXE)
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
    pe_ok = bool(report["ordinary_pe"].get("target_sha256_pass")) \
        and not report["ordinary_pe"].get("failures")
    report["status"] = (
        "passed" if executed.returncode == 0 and result_line == "RESULT PASS"
        and checks and not report["run"]["check_failures"] and pe_ok
        else "failed"
    )
    report["elapsed_seconds"] = time.time() - started
    write_report(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build/run the offline Line1 setter trampoline fixture.")
    parser.add_argument(
        "--run", action="store_true",
        help="mmap bounded PE windows, compile and run the native fixture")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({
            "status": "idle",
            "hint": "pass --run to compile and execute the offline fixture",
        }, ensure_ascii=False))
        return 0
    result = run()
    print(json.dumps({
        "status": result["status"],
        "report": REPORT.relative_to(ROOT).as_posix(),
        "artifact": result.get("source_pins", {}).get(EXE.name),
    }, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
