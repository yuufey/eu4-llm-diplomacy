"""Compile and exercise the template message scope manager fixture.

The executable reuses the existing private 40 MiB context fixture and adds
synthetic land/naval message callers.  This runner decodes the real v4 frames
with the production Python decoder; it never opens EU4, uses REA/RPM, installs
a DLL, or publishes a business event.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
NATIVE = ROOT / "work" / "native"
STAGE = (ROOT / "work" / "runtime" / "information-battle-text-20261026-001"
         / "message-scope-test-001")
OWNER_CONTRACT = STAGE.parent / "scoped-owner-contract-001.json"
FIXED_EXE = (ROOT / "work" / "runtime" / "ghidra-full"
             / "b23fa0e1f698d31b-20261014T054913Z-6dda97" / "input"
             / "eu4.exe")
SCOPED_ENTRY_CONTRACT = STAGE.parent / "scoped-entry-contract-001.json"
CPP = NATIVE / "tests" / "information-battle-message-scope-test.cpp"
STUB = NATIVE / "information-battle-entry-stub.S"
SCRIPT = Path(__file__).resolve()

DIRECT_SOURCES = (
    CPP,
    STUB,
    NATIVE / "test-information-battle-observer-context.cpp",
    NATIVE / "information-battle-observer.inc",
    NATIVE / "information-battle-entry-plan.h",
    NATIVE / "information-battle-message-entry-plan.h",
    NATIVE / "entry-patch-transaction.inc",
    NATIVE / "information-battle-owned-result.h",
    NATIVE / "information-battle-owned-summary.h",
    NATIVE / "information-battle-owned-context.h",
    NATIVE / "information-battle-owned-naval.h",
    NATIVE / "information-battle-owned-template.h",
    NATIVE / "information-battle-observation-wire.h",
    NATIVE / "information-battle-context-wire.h",
    NATIVE / "information-battle-naval-wire.h",
    NATIVE / "information-battle-template-wire.h",
    NATIVE / "information-battle-drain.h",
    NATIVE / "information-battle-log-writer.h",
    NATIVE / "information-battle-fragment.h",
    NATIVE / "information-battle-buffer.h",
    NATIVE / "information-battle-wire.h",
    ROOT / "work" / "information_battle_template_wire.py",
    ROOT / "work" / "information_battle_naval_wire.py",
    SCRIPT,
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def file_pin(path: Path) -> dict[str, Any]:
    relative = path.relative_to(ROOT).as_posix()
    if not path.is_file():
        return {"path": relative, "status": "missing"}
    return {
        "path": relative,
        "status": "observed",
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def write_owner_contract() -> dict[str, Any]:
    """Record the fixed-build router/formatter owner association once.

    The bytes are from the bounded ordinary-PE windows used for this fixture;
    the selected REA artifacts remain provenance for the two formatter bodies.
    This report intentionally does not claim runtime hook safety or visibility.
    """
    if OWNER_CONTRACT.exists():
        return file_pin(OWNER_CONTRACT)
    contract = {
        "schema": "information_battle_scoped_owner_contract/v1",
        "status": "observed_static",
        "read_only": True,
        "mode": "bounded_ordinary_pe_plus_existing_rea",
        "target": {
            "path": FIXED_EXE.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(FIXED_EXE),
            "image_base": "0x140000000",
            "build": "EU4 1.37.4",
        },
        "router": {
            "rva": "0x23a020",
            "entry_rcx_to_rdi": {
                "va": "0x14023a03e",
                "bytes": "488bf9",
                "instruction": "MOV RDI,RCX",
            },
            "window_rva_half_open": ["0x23a3f0", "0x23a460"],
            "formatter_calls": [
                {
                    "kind": "naval",
                    "call_rva": "0x23a425",
                    "call_va": "0x14023a425",
                    "instruction_bytes": "e88642ffff",
                    "target_va": "0x14022e6b0",
                    "return_rva": "0x23a42a",
                    "pre_call": [
                        "MOV R8,R14",
                        "LEA RDX,[RBP-0x50]",
                        "RCX remains RDI from 0x14023a416",
                    ],
                    "rdi_is_router_combat": True,
                },
                {
                    "kind": "land",
                    "call_rva": "0x23a441",
                    "call_va": "0x14023a441",
                    "instruction_bytes": "e83a86ffff",
                    "target_va": "0x140232a80",
                    "return_rva": "0x23a446",
                    "pre_call": [
                        "MOV R8,R14",
                        "LEA RDX,[RBP-0x50]",
                        "MOV RCX,RDI",
                    ],
                    "rdi_is_router_combat": True,
                },
            ],
        },
        "formatter_saved_owner": {
            "land": {
                "formatter_rva": "0x232a80",
                "caller_return_rva": "0x23a446",
                "saved_rdi_frame_offset": "0x1b8",
                "saved_caller_pc_frame_offset": "0x1d8",
                "message_entry_return_rva": "0x236721",
            },
            "naval": {
                "formatter_rva": "0x22e6b0",
                "caller_return_rva": "0x23a42a",
                "saved_rdi_frame_offset": "0x178",
                "saved_caller_pc_frame_offset": "0x198",
                "message_entry_return_rva": "0x232a13",
            },
        },
        "direct_message_calls": {
            "land": {
                "call_rva": "0x23671c",
                "return_rva": "0x236721",
                "instruction_bytes": "e80fdf0000",
            },
            "naval": {
                "call_rva": "0x232a0e",
                "return_rva": "0x232a13",
                "instruction_bytes": "e81d1c0100",
            },
        },
        "evidence": {
            "scoped_entry_contract": file_pin(SCOPED_ENTRY_CONTRACT),
            "land_selected": file_pin(
                ROOT / "work/runtime/information-battle-layout-20261025-001"
                / "rea-land-result-message-001/selected-evidence-001.json") | {
                    "evidence_id": "ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89",
                },
            "naval_selected": file_pin(
                ROOT / "work/runtime/information-battles-20261025-001"
                / "rea-message-dispatch-001/selected-evidence-001.json") | {
                    "evidence_id": "ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e",
                },
            "fixed_exe_bounded_window": {
                "kind": "ordinary_PE_bounded_objdump",
                "router_entry_bytes": 3,
                "router_window_bytes": 0x70,
                "whole_image_disassembly": False,
            },
        },
        "checks": {
            "fixed_exe_sha256_recomputed": True,
            "router_entry_rcx_to_rdi": True,
            "both_formatter_calls_have_rdi_owner": True,
            "both_formatter_return_pcs_recorded": True,
            "new_rea_or_game_access": False,
        },
        "limitations": [
            "The owner association is fixed-build static evidence; no natural runtime execution is claimed.",
            "The router window establishes RCX=RDI at the two formatter calls; it does not prove message publication or visibility.",
            "Saved-RDI frame offsets are used only by the synthetic fixture to exercise the production guard.",
        ],
    }
    OWNER_CONTRACT.parent.mkdir(parents=True, exist_ok=True)
    OWNER_CONTRACT.write_text(json.dumps(contract, ensure_ascii=False,
                                         indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
    return file_pin(OWNER_CONTRACT)


def compiler_path() -> str | None:
    return shutil.which("g++") or r"C:\Strawberry\c\bin\g++.exe"


def parse_native(stdout: bytes) -> tuple[dict[str, Any], dict[str, bytes], list[str]]:
    frames: dict[str, bytes] = {}
    checks: list[str] = []
    result_line: str | None = None
    text = stdout.decode("ascii", errors="strict")
    for line in text.splitlines():
        if line.startswith("CHECK "):
            parts = line.split(" ", 2)
            if len(parts) != 3:
                raise ValueError("native_check_line_malformed")
            checks.append(line)
            if parts[2] != "PASS":
                raise ValueError(f"native_check_failed:{line}")
        elif line.startswith("FRAME_HEX "):
            parts = line.split(" ", 2)
            if len(parts) != 3 or not parts[1] or parts[1] in frames:
                raise ValueError("native_frame_line_malformed_or_duplicate")
            try:
                raw = bytes.fromhex(parts[2])
            except ValueError as exc:
                raise ValueError("native_frame_hex_invalid") from exc
            frames[parts[1]] = raw
        elif line.startswith("{") and line.endswith("}"):
            if result_line is not None:
                raise ValueError("native_result_duplicate")
            result_line = line
    if result_line is None:
        raise ValueError("native_result_missing")
    result = json.loads(result_line)
    if not isinstance(result, dict):
        raise ValueError("native_result_not_object")
    return result, frames, checks


def decode_frames(frames: dict[str, bytes]) -> dict[str, Any]:
    from work.information_battle_template_wire import decode

    expected_names = {
        "deferred_0",
        "nested_0", "nested_1",
        "double_base_0", "double_base_1",
        "double_message_0",
        "unknown_return_0", "wrong_callback_0",
        "wrong_owner_0", "wrong_formatter_caller_0", "kind_mismatch_0",
        "date_mismatch_0", "missing_scope_0", "overflow_0",
    }
    if set(frames) != expected_names:
        raise ValueError(f"frame_cases_mismatch:{sorted(frames)}")

    decoded: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    failures: list[str] = []
    for name, raw in frames.items():
        value = decode(raw)
        decoded[name] = value
        wire = value.get("wire", {})
        checks[f"{name}_v4"] = (
            value.get("schema") == "information_battle_template_wire_v4"
            and wire.get("version") == 4
            and wire.get("base_v3_version") == 3
            and wire.get("trailing_bytes") == 0
        )
        checks[f"{name}_pointer_free"] = "pointer" not in json.dumps(value)
        checks[f"{name}_business_incomplete"] = (
            value.get("complete") is False
            and value.get("business_complete") is False
            and value.get("visibility_verified") is False
        )
        if not all(checks[key] for key in checks
                   if key.startswith(f"{name}_")):
            failures.append(name)

    present_expected = {
        "deferred_0": [
            ("KEY_ONE", "VALUE_ONE"), ("KEY_TWO", "VALUE_TWO"),
        ],
        "nested_0": [
            ("OUTER_A", "OUTER_VALUE_A"), ("OUTER_B", "OUTER_VALUE_B"),
        ],
        "nested_1": [
            ("INNER_A", "INNER_VALUE_A"), ("INNER_B", "INNER_VALUE_B"),
        ],
    }
    for name, pairs in present_expected.items():
        message = decoded[name].get("message_template")
        expected_wire_pairs = [
            {"key_raw_hex": key.encode("ascii").hex(),
             "value_raw_hex": value.encode("ascii").hex()}
            for key, value in pairs
        ]
        ok = (
            decoded[name]["wire"]["template_present"] is True
            and isinstance(message, dict)
            and message["native_date"] == 56553384
            and message["raw_flag_8c"] == 0x11
            and message["raw_flag_8d"] == 0x22
            and message["raw_header_word_20"] == 0xA1B2C3D4
            and message["raw_header_flag_24"] == 0x5A
            and message["auxiliary_text_hex"] == "415558"
            and message["pair_count"] == 2
            and message["pairs"] == expected_wire_pairs
        )
        checks[f"{name}_ordered_template"] = ok
        if not ok:
            failures.append(f"{name}:ordered_template")

    rejected_names = expected_names.difference(present_expected)
    for name in rejected_names:
        message = decoded[name].get("message_template")
        ok = (decoded[name]["wire"]["template_present"] is False
              and message is None)
        checks[f"{name}_template_rejected"] = ok
        if not ok:
            failures.append(f"{name}:template_rejected")

    return {
        "status": "passed" if not failures and all(checks.values()) else "failed",
        "checks": checks,
        "failures": failures,
        "decoded": decoded,
        "wire_bytes": {name: len(raw) for name, raw in frames.items()},
        "wire_sha256": {name: sha256_bytes(raw) for name, raw in frames.items()},
    }


def run(revision: int = 1, output: Path | None = None) -> tuple[int, dict[str, Any]]:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    owner_contract_pin = write_owner_contract()
    report_path = (output or (STAGE / ("report.json" if revision == 1
                                       else f"report-{revision:03d}.json"))).resolve()
    exe = STAGE / f"test-information-battle-message-scope-runner-{revision:03d}.exe"
    compile_stdout = STAGE / f"compile-{revision:03d}.stdout.log"
    compile_stderr = STAGE / f"compile-{revision:03d}.stderr.log"
    run_stdout = STAGE / f"run-{revision:03d}.stdout.log"
    run_stderr = STAGE / f"run-{revision:03d}.stderr.log"
    for path in (report_path, exe, compile_stdout, compile_stderr,
                 run_stdout, run_stderr):
        if path.exists():
            raise FileExistsError(f"refusing_to_overwrite:{path}")

    report: dict[str, Any] = {
        "schema": "information_battle_message_scope_manager_test_v1",
        "status": "blocked",
        "mode": "offline_synthetic_process",
        "scope": {
            "game_access": False,
            "remote_process_access": False,
            "rea_access": False,
            "remote_process_memory_read": False,
            "self_process_read_process_memory": True,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "production_modified": False,
            "fixture_private_initialization": True,
        },
        "contract": {
            "macro": "INFORMATION_BATTLE_TEMPLATE+INFORMATION_BATTLE_NAVAL",
            "record": "information::battle::template_wire::TemplateObservation (v4)",
            "scope_pairing": "router scope defers one base record until its exact land/naval message return PC",
            "message_calls": "typed router/message wrappers call self-owned originals exactly once and preserve LastError",
            "rejection_cases": [
                "duplicate base", "duplicate message", "unknown return PC",
                "wrong callback", "wrong formatter owner",
                "wrong formatter caller", "kind mismatch", "date mismatch",
                "missing scope", "scope overflow",
            ],
            "business_complete": False,
            "visibility_verified": False,
            "private_region_bytes": 0x2800000,
            "max_wire_bytes": 256 * 1024,
        },
        "owner_contract": owner_contract_pin,
        "source_pins": {path.relative_to(ROOT).as_posix(): file_pin(path)
                        for path in DIRECT_SOURCES},
        "compile": {},
        "run": {},
        "wire_decode": {},
        "limitations": [
            "All code, messages, result/context objects and callbacks are self-owned synthetic memory; this does not establish live EU4 visibility, ABI safety, event completeness, or business semantics.",
            "Only the exact fixed return PCs and callback address are accepted; rejected cases retain the base record without a template extension.",
            "The v4 decoder preserves raw key/value bytes and does not infer message kind, winner, units, war identity, or public visibility.",
        ],
    }

    compiler = compiler_path()
    if compiler is None or not Path(compiler).is_file():
        report["status"] = "blocked_missing_compiler"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False,
                                          indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        return 1, report

    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall",
        "-Wextra", "-Werror", "-O2", "-fstack-usage", "-static-libgcc",
        "-static-libstdc++", "-Wl,--no-insert-timestamp", "-I", str(NATIVE),
        "-DINFORMATION_BATTLE_TEMPLATE=1",
        "-o", str(exe), str(STUB), str(CPP), "-ladvapi32",
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120, check=False)
    compile_stdout.write_bytes(compiled.stdout)
    compile_stderr.write_bytes(compiled.stderr)
    report["compile"] = {
        "command": command,
        "returncode": compiled.returncode,
        "stdout_sha256": sha256_bytes(compiled.stdout),
        "stderr_sha256": sha256_bytes(compiled.stderr),
        "exe": file_pin(exe),
    }
    if compiled.returncode != 0 or not exe.is_file():
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False,
                                          indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        return 1, report

    ran = subprocess.run([str(exe)], cwd=ROOT, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=120, check=False)
    run_stdout.write_bytes(ran.stdout)
    run_stderr.write_bytes(ran.stderr)
    report["run"] = {
        "returncode": ran.returncode,
        "stdout_sha256": sha256_bytes(ran.stdout),
        "stderr_sha256": sha256_bytes(ran.stderr),
        "stdout_bytes": len(ran.stdout),
        "stderr_bytes": len(ran.stderr),
    }
    try:
        native_result, frames, native_checks = parse_native(ran.stdout)
        report["run"].update({
            "result": native_result,
            "native_check_count": len(native_checks),
            "native_frame_names": sorted(frames),
        })
        report["wire_decode"] = decode_frames(frames)
        report["run"]["frame_sha256"] = report["wire_decode"]["wire_sha256"]
    except Exception as exc:
        report["run"]["parse_error"] = f"{type(exc).__name__}:{exc}"

    native_ok = report.get("run", {}).get("result", {}).get("passed") is True
    result = report.get("run", {}).get("result", {})
    result_contract_ok = (
        result.get("production_modified") is False
        and result.get("game_access") is False
        and result.get("fixture_private_initialization") is True
        and result.get("router_original_calls") == 2
        and result.get("message_original_calls") == 2
        and result.get("template_copied") == 4
        and result.get("template_copy_failures") == 1
        and result.get("template_ambiguous") == 2
        and result.get("scope_overflow") == 1
    )
    report["native_contract"] = {
        "status": "passed" if native_ok and result_contract_ok else "failed",
        "checks": {
            "native_result_passed": native_ok,
            "counters_and_scope_guards": result_contract_ok,
        },
    }
    report["status"] = "passed" if (
        ran.returncode == 0
        and native_ok
        and result_contract_ok
        and report.get("wire_decode", {}).get("status") == "passed"
    ) else "failed_contract"
    report["artifacts"] = {
        "executable": file_pin(exe),
        "compile_stdout": file_pin(compile_stdout),
        "compile_stderr": file_pin(compile_stderr),
        "run_stdout": file_pin(run_stdout),
        "run_stderr": file_pin(run_stderr),
    }
    report["elapsed_seconds"] = time.time() - started
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                      sort_keys=True) + "\n", encoding="utf-8")
    return (0 if report["status"] == "passed" else 1), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    if not 1 <= args.revision <= 999:
        parser.error("--revision must be between 1 and 999")
    try:
        code, report = run(args.revision, args.output)
    except (FileExistsError, OSError, RuntimeError, ValueError) as exc:
        print(f"message scope fixture runner failed: {exc}", file=sys.stderr)
        return 2
    default_report = STAGE / ("report.json" if args.revision == 1
                              else f"report-{args.revision:03d}.json")
    print(json.dumps({
        "status": report["status"],
        "report": str((args.output or default_report).resolve()),
        "native_returncode": report.get("run", {}).get("returncode"),
        "wire_status": report.get("wire_decode", {}).get("status"),
    }, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
