"""Run the bounded v30 native title-helper observer fixture offline.

The fixture executes the exact hash-pinned helper and owned-string destructor
bytes in a private 40 MiB image.  Its three direct helper callees are private
RX shims; no EU4 process, DLL, game function, RPM, or REA action is used.
Revisions 3+ additionally validate the production plugin-aware title guard in a
private 0x89000-byte image, but never executes the plugin callee.
The command is inert unless ``--run`` is supplied.
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
NATIVE = ROOT / "work" / "native"
STAGE_ROOT = ROOT / "work" / "runtime" / "information-battle-native-title-20261027-001"
CPP = NATIVE / "tests" / "information-battle-native-title-observer-test.cpp"
PLUGIN_EVIDENCE = (
    ROOT / "work" / "runtime" / "plugin-title-hook-source-001" / "source-001.json",
    ROOT / "work" / "runtime" / "plugin-title-hook-source-001" / "source-002.json",
    ROOT / "work" / "runtime" / "plugin-title-hook-source-001" / "source-003.json",
    ROOT / "work" / "runtime" / "plugin-title-hook-source-001"
    / "fun-1800373a0-375cb.bin",
    ROOT / "work" / "runtime" / "plugin-title-hook-source-001"
    / "fun-1800373a0-pdata.bin",
    ROOT / "work" / "runtime" / "plugin-title-hook-source-001"
    / "fun-1800373a0-unwind-7bbb0.bin",
)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DIRECT_SOURCES = (
    CPP,
    NATIVE / "tests" / "information-battle-native-text-observer-test.cpp",
    NATIVE / "information-battle-entry-stub.S",
    NATIVE / "information-battle-line1-observer-stub.S",
    NATIVE / "test-information-battle-observer-context.cpp",
    NATIVE / "information-battle-observer.inc",
    NATIVE / "entry-patch-transaction.inc",
    NATIVE / "information-battle-entry-plan.h",
    NATIVE / "information-battle-message-entry-plan.h",
    NATIVE / "information-battle-line1-entry-plan.h",
    NATIVE / "information-battle-title-query-plan.h",
    NATIVE / "information-battle-owned-title-query.h",
    NATIVE / "information-battle-owned-native-text.h",
    NATIVE / "information-battle-owned-result.h",
    NATIVE / "information-battle-owned-summary.h",
    NATIVE / "information-battle-owned-context.h",
    NATIVE / "information-battle-owned-naval.h",
    NATIVE / "information-battle-owned-template.h",
    NATIVE / "information-battle-war-binding.h",
    NATIVE / "information-battle-war-identity-wire.h",
    NATIVE / "information-battle-native-text-wire.h",
    NATIVE / "information-battle-observation-wire.h",
    NATIVE / "information-battle-context-wire.h",
    NATIVE / "information-battle-naval-wire.h",
    NATIVE / "information-battle-template-wire.h",
    NATIVE / "information-battle-drain.h",
    NATIVE / "information-battle-log-writer.h",
    NATIVE / "information-battle-fragment.h",
    NATIVE / "information-battle-buffer.h",
    NATIVE / "information-battle-wire.h",
    ROOT / "work" / "information_battle_native_text_wire.py",
    Path(__file__).resolve(),
)
DIRECT_SOURCES = DIRECT_SOURCES + PLUGIN_EVIDENCE


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": path.relative_to(ROOT).as_posix(), "status": "missing"}
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "status": "observed",
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def compiler_path() -> str | None:
    return shutil.which("g++") or r"C:\Strawberry\c\bin\g++.exe"


def parse_native(stdout: bytes) -> tuple[dict[str, Any], dict[str, bytes], int]:
    frames: dict[str, bytes] = {}
    result_line: str | None = None
    checks = 0
    for line in stdout.decode("ascii", errors="strict").splitlines():
        if line.startswith("CHECK "):
            checks += 1
            fields = line.split(" ", 2)
            if len(fields) != 3 or fields[2] != "PASS":
                raise ValueError(f"native_check_failed:{line}")
        elif line.startswith("FRAME_HEX "):
            fields = line.split(" ", 2)
            if len(fields) != 3 or fields[1] in frames:
                raise ValueError("native_frame_malformed_or_duplicate")
            frames[fields[1]] = bytes.fromhex(fields[2])
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
    from work.information_battle_native_text_wire import decode

    expected = {
        "valid_0", "valid_kind2_0", "wrong_owner_0", "wrong_date_0",
        "duplicate_0", "conflict_0", "wrong_parent_0", "wrong_popup_0",
        "no_scope_0",
    }
    if set(frames) != expected:
        raise ValueError(f"native_frame_names_mismatch:{sorted(frames)}")
    decoded = {name: decode(raw) for name, raw in frames.items()}
    title_hex = bytes("B Dover", "ascii").hex()
    checks = {
        "kind1_title_known": (
            decoded["valid_0"]["native_text"]["text_fields"]
            ["title_helper_candidate"]["status"] == "known"
            and decoded["valid_0"]["native_text"]["text_fields"]
            ["title_helper_candidate"]["raw_hex"] == title_hex
        ),
        "kind2_title_known": (
            decoded["valid_kind2_0"]["native_text"]["text_fields"]
            ["title_helper_candidate"]["status"] == "known"
            and decoded["valid_kind2_0"]["native_text"]["text_fields"]
            ["title_helper_candidate"]["raw_hex"] == title_hex
        ),
        "base_v5_retained": all(
            bool(decoded[name].get("base_v5_payload_hex"))
            for name in ("valid_0", "valid_kind2_0", "wrong_owner_0")
        ),
    }
    return {
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "decoded": decoded,
        "wire_bytes": {name: len(raw) for name, raw in frames.items()},
        "wire_sha256": {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in frames.items()
        },
    }


def run(output: Path | None = None, revision: int = 1) -> tuple[int, dict[str, Any]]:
    started = time.time()
    if revision < 1 or revision > 999:
        raise ValueError("revision_out_of_range")
    stage = STAGE_ROOT / f"actual-observer-fixture-{revision:03d}"
    report_path = (output or (stage / "report.json")).resolve()
    if report_path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{report_path}")
    stage.mkdir(parents=True, exist_ok=True)
    exe = stage / "information-battle-native-title-observer-test.exe"
    compile_stdout = stage / "compile.stdout.log"
    compile_stderr = stage / "compile.stderr.log"
    run_stdout = stage / "run.stdout.log"
    run_stderr = stage / "run.stderr.log"

    report: dict[str, Any] = {
        "schema": "information_battle_native_title_observer_fixture/v1",
        "status": "blocked",
        "mode": "offline_synthetic_process",
        "scope": {
            "game_access": False,
            "remote_process_access": False,
            "rea_access": False,
            "rpm_access": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "production_modified": False,
            "private_fixture_region": True,
        },
        "contract": {
            "helper_body": "title_query_plan.kHelperBytes_exact_515",
            "destructor_body": "title_query_plan.kDestructorBytes_exact_94",
            "unwind": {
                "helper": "copied_exact_32_bytes_including_chain_row",
                "destructor": "copied_exact_8_bytes",
            },
            "private_image_bytes": 40 * 1024 * 1024,
            "callees": ["0x14b33a0", "0x932f0", "0x95110"],
            "selector_kinds": [1, 2],
            "title": "B Dover",
            "guard_failure": "production_entry_guard_does_not_invoke_or_destroy",
            "plugin_guard_only": True,
            "plugin_image_bytes": 0x89000,
            "plugin_bridge_rva": "0x3dbe7",
            "plugin_callee_rva": "0x373a0",
            "plugin_callee_end_rva_exclusive": "0x375cb",
            "plugin_pdata_rva": "0x83000",
            "plugin_unwind_rva": "0x7bbb0",
            "plugin_call_slot_rva": "0x820d0",
            "plugin_return_slot_rva": "0x820c8",
            "plugin_return_game_rva": "0x23aadd",
            "plugin_helper_patch_offset": 403,
            "plugin_helper_patch_bytes": 14,
            "plugin_callee_execution": "forbidden_in_fixture",
        },
        "source_pins": {path.relative_to(ROOT).as_posix(): file_pin(path)
                        for path in DIRECT_SOURCES},
        "compile": {},
        "run": {},
        "wire_decode": {},
    }
    missing = [pin["path"] for pin in report["source_pins"].values()
               if pin["status"] == "missing"]
    if missing:
        report["status"] = "blocked_missing_source"
        report["missing_sources"] = missing
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n", encoding="utf-8")
        return 1, report

    compiler = compiler_path()
    if compiler is None or not Path(compiler).is_file():
        report["status"] = "blocked_missing_compiler"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n", encoding="utf-8")
        return 1, report

    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall",
        "-Wextra", "-Werror", "-O2", "-fstack-usage", "-static-libgcc",
        "-static-libstdc++", "-Wl,--no-insert-timestamp", "-I", str(NATIVE),
        "-DINFORMATION_BATTLE_TEMPLATE=1", "-o", str(exe),
        str(NATIVE / "information-battle-entry-stub.S"),
        str(NATIVE / "information-battle-line1-observer-stub.S"), str(CPP),
        "-ladvapi32",
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=120, check=False)
    compile_stdout.write_bytes(compiled.stdout)
    compile_stderr.write_bytes(compiled.stderr)
    report["compile"] = {
        "command": command,
        "returncode": compiled.returncode,
        "stdout": file_pin(compile_stdout),
        "stderr": file_pin(compile_stderr),
        "executable": file_pin(exe),
    }
    if compiled.returncode != 0 or not exe.is_file():
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                          sort_keys=True) + "\n", encoding="utf-8")
        return 1, report

    ran = subprocess.run([str(exe)], cwd=ROOT, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=120, check=False)
    run_stdout.write_bytes(ran.stdout)
    run_stderr.write_bytes(ran.stderr)
    report["run"] = {
        "returncode": ran.returncode,
        "stdout": file_pin(run_stdout),
        "stderr": file_pin(run_stderr),
    }
    try:
        native_result, frames, native_checks = parse_native(ran.stdout)
        title_checks = {
            "two_kind_candidates": native_result.get("title_query_candidates", 0) >= 2,
            "two_kind_attempts": native_result.get("title_query_attempted", 0) >= 2,
            "destroy_matches_attempts": (
                native_result.get("title_query_destroyed")
                == native_result.get("title_query_attempted")
            ),
            "two_kind_copies": native_result.get("title_query_copied", 0) >= 2,
            "guard_failure": native_result.get("title_guard_failure") is True,
            "plugin_guard_positive": native_result.get("plugin_guard_positive") is True,
            "plugin_guard_negative": native_result.get("plugin_guard_negative") is True,
            "plugin_guard_restored": native_result.get("plugin_guard_restored") is True,
            "plugin_cleanup": native_result.get("plugin_cleanup") is True,
            "plugin_callee_not_executed": (
                native_result.get("plugin_callee_executed") is False
            ),
        }
        native_result["title_checks"] = title_checks
        report["run"].update({
            "result": native_result,
            "native_check_count": native_checks,
            "native_frame_names": sorted(frames),
        })
        report["wire_decode"] = decode_frames(frames)
        report["run"]["title_checks_passed"] = all(title_checks.values())
    except Exception as error:
        report["run"]["parse_error"] = f"{type(error).__name__}:{error}"

    native_passed = report.get("run", {}).get("result", {}).get("passed") is True
    title_passed = report.get("run", {}).get("title_checks_passed") is True
    report["status"] = "passed" if (
        ran.returncode == 0 and native_passed and title_passed
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
    parser.add_argument("--run", action="store_true",
                        help="compile and run the private title fixture")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--revision", type=int, default=1)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "inert", "run": False}, sort_keys=True))
        return 0
    try:
        code, report = run(args.output, args.revision)
    except (FileExistsError, OSError, RuntimeError, ValueError) as error:
        print(f"native title fixture failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "report": str((args.output or
                        (STAGE_ROOT / f"actual-observer-fixture-{args.revision:03d}"
                         / "report.json")).resolve()),
        "native_returncode": report.get("run", {}).get("returncode"),
        "wire_status": report.get("wire_decode", {}).get("status"),
    }, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
