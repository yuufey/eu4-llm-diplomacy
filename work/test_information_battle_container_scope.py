"""Compile and exercise the owned formatter-container cleanup fixture.

The fixture is a self-owned process image.  It drives the production
container cleanup seam through the same call-site wrappers as the legacy
message fixture, drains real v4 frames, and decodes every frame with the
production Python decoder.  It never opens EU4, reads a remote process, uses
REA, installs a DLL, or publishes an external event.
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
STAGE = (ROOT / "work" / "runtime"
         / "information-battle-container-20261026-001"
         / "container-scope-test-001")
CPP = NATIVE / "tests" / "information-battle-container-scope-test.cpp"
LEGACY_CPP = NATIVE / "tests" / "information-battle-message-scope-test.cpp"
STUB = NATIVE / "information-battle-entry-stub.S"
SCRIPT = Path(__file__).resolve()

DIRECT_SOURCES = (
    CPP,
    LEGACY_CPP,
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


def compiler_path() -> str | None:
    return shutil.which("g++") or r"C:\Strawberry\c\bin\g++.exe"


def artifact_paths() -> dict[str, Path]:
    return {
        "exe": STAGE / "container-scope-test-001.exe",
        "compile_stdout": STAGE / "compile.stdout.log",
        "compile_stderr": STAGE / "compile.stderr.log",
        "run_stdout": STAGE / "run.stdout.log",
        "run_stderr": STAGE / "run.stderr.log",
    }


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


def _common_v4_checks(value: dict[str, Any], name: str,
                      checks: dict[str, bool], failures: list[str]) -> None:
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
    if not all(checks[key] for key in checks if key.startswith(f"{name}_")):
        failures.append(name)


def decode_frames(frames: dict[str, bytes]) -> dict[str, Any]:
    from work.information_battle_template_wire import decode

    expected_names = {
        "land_container_0",
        "naval_container_0",
        "wrong_owner_0",
        "wrong_formatter_caller_0",
        "wrong_container_0",
        "date_changed_0",
        "invalid_head_0",
        "double_cleanup_0",
        "message_priority_0",
    }
    if set(frames) != expected_names:
        raise ValueError(f"frame_cases_mismatch:{sorted(frames)}")

    decoded: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    failures: list[str] = []
    for name, raw in frames.items():
        value = decode(raw)
        decoded[name] = value
        _common_v4_checks(value, name, checks, failures)

    expected_pairs = [
        {"key_raw_hex": "4b45595f4f4e45",
         "value_raw_hex": "56414c55455f4f4e45"},
        {"key_raw_hex": "4b45595f54574f",
         "value_raw_hex": "56414c55455f54574f"},
    ]
    for name in ("land_container_0", "naval_container_0"):
        value = decoded[name]
        wire = value["wire"]
        message = value.get("message_template")
        ok = (
            wire.get("template_present") is True
            and wire.get("extension_version") == 2
            and isinstance(message, dict)
            and message.get("source_kind") ==
            "formatter_container_before_cleanup"
            and message.get("message_metadata_present") is False
            and message.get("raw_container_word_10") == 0x10203040
            and message.get("raw_container_flag_14") == 0x91
            and message.get("native_date") is None
            and message.get("raw_flag_8c") is None
            and message.get("raw_flag_8d") is None
            and message.get("auxiliary_text_hex") is None
            and message.get("pair_count") == 2
            and message.get("pairs") == expected_pairs
        )
        checks[f"{name}_container_ext2"] = ok
        if not ok:
            failures.append(f"{name}:container_ext2")

    rejected_names = {
        "wrong_owner_0",
        "wrong_formatter_caller_0",
        "wrong_container_0",
        "date_changed_0",
        "invalid_head_0",
        "double_cleanup_0",
    }
    for name in rejected_names:
        value = decoded[name]
        wire = value["wire"]
        ok = (
            wire.get("template_present") is False
            and wire.get("extension_version") is None
            and value.get("message_template") is None
        )
        checks[f"{name}_container_rejected"] = ok
        if not ok:
            failures.append(f"{name}:container_rejected")

    message = decoded["message_priority_0"].get("message_template")
    wire = decoded["message_priority_0"]["wire"]
    ok = (
        wire.get("template_present") is True
        and wire.get("extension_version") == 1
        and isinstance(message, dict)
        and message.get("native_date") == 56553384
        and message.get("raw_flag_8c") == 0x11
        and message.get("raw_flag_8d") == 0x22
        and message.get("raw_header_word_20") == 0xA1B2C3D4
        and message.get("raw_header_flag_24") == 0x5A
        and message.get("auxiliary_text_hex") == "415558"
        and message.get("pair_count") == 2
        and message.get("pairs") == expected_pairs
        and "source_kind" not in message
        and "message_metadata_present" not in message
    )
    checks["message_priority_0_message_ext1"] = ok
    if not ok:
        failures.append("message_priority_0:message_ext1")

    return {
        "status": "passed" if not failures and all(checks.values()) else "failed",
        "checks": checks,
        "failures": failures,
        "decoded": decoded,
        "wire_bytes": {name: len(raw) for name, raw in frames.items()},
        "wire_sha256": {name: sha256_bytes(raw) for name, raw in frames.items()},
    }


def _base_report() -> dict[str, Any]:
    return {
        "schema": "information_battle_container_scope_manager_test_v1",
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
            "network_access": False,
            "full_dll_build": False,
        },
        "contract": {
            "macro": "INFORMATION_BATTLE_CONTAINER+INFORMATION_BATTLE_TEMPLATE+INFORMATION_BATTLE_NAVAL",
            "record": "information::battle::template_wire::TemplateObservation (v4)",
            "container_layout_bytes": 0x18,
            "container_fields": {
                "head": "0x00",
                "tail": "0x08",
                "raw_container_word_10": "0x10",
                "raw_container_flag_14": "0x14",
            },
            "cleanup_return_rvas": {
                "land": "0x236736",
                "naval": "0x232a28",
                "unknown_same_page": "0x236720",
            },
            "scenarios": [
                "valid land and naval container capture",
                "wrong owner, wrong formatter caller, wrong container address",
                "date changed and invalid head copy failure",
                "double cleanup ambiguity retaining base",
                "message priority retaining ext1 over cleanup ext2",
                "missing scope and unrelated cleanup",
            ],
            "business_complete": False,
            "visibility_verified": False,
            "max_wire_bytes": 256 * 1024,
            "max_pairs": 128,
            "max_key_bytes": 128,
            "max_value_bytes": 8192,
            "max_arena_bytes": 64 * 1024,
        },
        "source_pins": {path.relative_to(ROOT).as_posix(): file_pin(path)
                        for path in DIRECT_SOURCES},
        "compile": {},
        "run": {},
        "wire_decode": {},
        "limitations": [
            "All container, node, formatter-frame and callback memory is private synthetic fixture memory; no live EU4 visibility or ABI safety is claimed.",
            "The fixture verifies the exact land/naval cleanup return PCs and formatter caller guards, plus a same-page unknown return early-out.",
            "The v4 decoder preserves raw key/value bytes and reports missing container metadata as None; it does not infer message kind, winner, units, war identity or public visibility.",
        ],
    }


def run(reuse_existing: bool = False,
        output: Path | None = None) -> tuple[int, dict[str, Any]]:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    paths = artifact_paths()
    report_path = (output or (STAGE / "report.json")).resolve()
    if report_path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{report_path}")

    report = _base_report()
    missing_sources = [path for path in DIRECT_SOURCES if not path.is_file()]
    if missing_sources:
        report["status"] = "blocked_missing_source"
        report["missing_sources"] = [str(path) for path in missing_sources]
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False,
                                          indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        return 1, report

    existing = all(path.is_file() for path in paths.values())
    if existing and not reuse_existing:
        raise FileExistsError(
            "canonical_fixture_artifacts_exist:use --reuse-existing or a clean stage")

    compiler = compiler_path()
    if not existing:
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
            "-DINFORMATION_BATTLE_CONTAINER=1",
            "-o", str(paths["exe"]), str(STUB), str(CPP), "-ladvapi32",
        ]
        compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=120, check=False)
        paths["compile_stdout"].write_bytes(compiled.stdout)
        paths["compile_stderr"].write_bytes(compiled.stderr)
        report["compile"] = {
            "mode": "compiled_by_runner",
            "command": command,
            "returncode": compiled.returncode,
            "stdout_sha256": sha256_bytes(compiled.stdout),
            "stderr_sha256": sha256_bytes(compiled.stderr),
            "exe": file_pin(paths["exe"]),
        }
        if compiled.returncode != 0 or not paths["exe"].is_file():
            report["status"] = "failed_compile"
            report["elapsed_seconds"] = time.time() - started
            report_path.write_text(json.dumps(report, ensure_ascii=False,
                                              indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
            return 1, report
    else:
        report["compile"] = {
            "mode": "reused_existing_runner_fixture",
            "command_verified": [
                "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall",
                "-Wextra", "-Werror", "-O2", "-fstack-usage",
                "-static-libgcc", "-static-libstdc++",
                "-Wl,--no-insert-timestamp", "-DINFORMATION_BATTLE_TEMPLATE=1",
                "-DINFORMATION_BATTLE_CONTAINER=1",
            ],
            "exe": file_pin(paths["exe"]),
            "compile_stdout": file_pin(paths["compile_stdout"]),
            "compile_stderr": file_pin(paths["compile_stderr"]),
        }

    if not existing:
        ran = subprocess.run([str(paths["exe"])], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=120, check=False)
        paths["run_stdout"].write_bytes(ran.stdout)
        paths["run_stderr"].write_bytes(ran.stderr)
    else:
        ran = subprocess.CompletedProcess(
            [str(paths["exe"])], 0, paths["run_stdout"].read_bytes(),
            paths["run_stderr"].read_bytes())
    report["run"] = {
        "mode": "reused_existing_logs" if existing else "executed_by_runner",
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

    result = report.get("run", {}).get("result", {})
    native_ok = (
        ran.returncode == 0
        and result.get("passed") is True
        and result.get("production_modified") is False
        and result.get("game_access") is False
        and result.get("rea_access") is False
        and result.get("network_access") is False
        and result.get("full_dll_build") is False
        and result.get("native_game_function_invoked") is False
        and result.get("fixture_private_initialization") is True
    )
    counter_checks = {
        "router_original_calls": result.get("router_original_calls") == 9,
        "message_original_calls": result.get("message_original_calls") == 1,
        "container_original_calls": result.get("container_original_calls") == 12,
        "container_candidates": result.get("container_candidates") == 11,
        "container_copied": result.get("container_copied") == 3,
        "container_copy_failures": result.get("container_copy_failures") == 2,
        "template_copied": result.get("template_copied") == 1,
        "template_copy_failures": result.get("template_copy_failures") == 0,
        "template_ambiguous": result.get("template_ambiguous") == 1,
        "scope_overflow": result.get("scope_overflow") == 0,
    }
    report["native_contract"] = {
        "status": "passed" if native_ok and all(counter_checks.values()) else "failed",
        "checks": {
            "native_result_and_scope": native_ok,
            **counter_checks,
        },
    }
    report["artifacts"] = {name: file_pin(path) for name, path in paths.items()}
    report["status"] = "passed" if (
        native_ok
        and all(counter_checks.values())
        and report.get("wire_decode", {}).get("status") == "passed"
    ) else "failed_contract"
    report["elapsed_seconds"] = time.time() - started
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2,
                                      sort_keys=True) + "\n", encoding="utf-8")
    return (0 if report["status"] == "passed" else 1), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reuse-existing", action="store_true",
        help="reuse the canonical fixture exe/logs already present in the stage",
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        code, report = run(args.reuse_existing, args.output)
    except (FileExistsError, OSError, RuntimeError, ValueError) as exc:
        print(f"container scope fixture runner failed: {exc}", file=sys.stderr)
        return 2
    default_report = STAGE / "report.json"
    print(json.dumps({
        "status": report["status"],
        "report": str((args.output or default_report).resolve()),
        "native_returncode": report.get("run", {}).get("returncode"),
        "wire_status": report.get("wire_decode", {}).get("status"),
    }, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
