"""Run the bounded v29 observer/native-text fixture offline.

The fixture uses the production observer include, message entry stubs and the
production v5-to-v6 encoder.  It allocates only a private 40 MiB region and
never opens EU4 or installs a DLL.  Without ``--run`` this command is inert.
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
STAGE_ROOT = ROOT / "work" / "runtime" / "information-battle-native-observer-20261027-001"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
CPP = NATIVE / "tests" / "information-battle-native-text-observer-test.cpp"
ENTRY_STUB = NATIVE / "information-battle-entry-stub.S"
LINE1_STUB = NATIVE / "information-battle-line1-observer-stub.S"

DIRECT_SOURCES = (
    CPP,
    ENTRY_STUB,
    LINE1_STUB,
    NATIVE / "test-information-battle-observer-context.cpp",
    NATIVE / "information-battle-observer.inc",
    NATIVE / "entry-patch-transaction.inc",
    NATIVE / "information-battle-entry-plan.h",
    NATIVE / "information-battle-message-entry-plan.h",
    NATIVE / "information-battle-owned-result.h",
    NATIVE / "information-battle-owned-summary.h",
    NATIVE / "information-battle-owned-context.h",
    NATIVE / "information-battle-owned-naval.h",
    NATIVE / "information-battle-owned-template.h",
    NATIVE / "information-battle-war-binding.h",
    NATIVE / "information-battle-war-identity-wire.h",
    NATIVE / "information-battle-owned-native-text.h",
    NATIVE / "information-battle-native-text-wire.h",
    NATIVE / "information-battle-line1-entry-plan.h",
    NATIVE / "information-battle-observation-wire.h",
    NATIVE / "information-battle-context-wire.h",
    NATIVE / "information-battle-naval-wire.h",
    NATIVE / "information-battle-template-wire.h",
    NATIVE / "information-battle-drain.h",
    NATIVE / "information-battle-log-writer.h",
    NATIVE / "information-battle-fragment.h",
    NATIVE / "information-battle-buffer.h",
    NATIVE / "information-battle-wire.h",
    ROOT / "work" / "information_battle_war_identity_wire.py",
    ROOT / "work" / "information_battle_native_text_wire.py",
    Path(__file__).resolve(),
)


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
    return {"path": relative, "status": "observed",
            "bytes": path.stat().st_size, "sha256": sha256_file(path)}


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
            frames[parts[1]] = bytes.fromhex(parts[2])
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


def decode_and_check(frames: dict[str, bytes]) -> dict[str, Any]:
    from work.information_battle_native_text_wire import decode

    expected = {
        "valid_0", "wrong_owner_0", "wrong_date_0", "duplicate_0",
        "conflict_0",
        "wrong_parent_0", "wrong_popup_0", "no_scope_0",
    }
    if set(frames) != expected:
        raise ValueError(f"native_frame_names_mismatch:{sorted(frames)}")
    decoded = {name: decode(raw) for name, raw in frames.items()}
    checks: dict[str, bool] = {}
    valid = decoded["valid_0"]
    fields = valid["native_text"]["text_fields"]
    metadata = valid["native_text"]["message_metadata"]
    checks["valid_wire6"] = (
        valid.get("schema") == "information_battle_native_text_wire_v6"
        and valid.get("wire6", {}).get("version") == 6
        and valid.get("wire6", {}).get("base_v5_version") == 5
        and valid.get("complete") is False
    )
    checks["valid_definition_key"] = (
        fields["definition_key"]["status"] == "known"
        and fields["definition_key"]["raw_hex"] == b"LANDBATTLEOVER".hex()
    )
    checks["valid_auxiliary_and_metadata"] = (
        fields["auxiliary_text"]["status"] == "known"
        and fields["auxiliary_text"]["raw_hex"] == b"AUX".hex()
        and metadata["native_date"]["value"] == 56553384
        and metadata["raw_flags"]["raw_flag_8c"] == 0x11
        and metadata["raw_flags"]["raw_flag_8d"] == 0x22
    )
    checks["valid_native_line1"] = (
        fields["line1_text"]["status"] == "known"
        and fields["line1_text"]["raw_hex"] == b"LINE1".hex()
    )
    for name in ("wrong_owner_0", "wrong_date_0", "duplicate_0"):
        native = decoded[name]["native_text"]
        invalid_fields = native["text_fields"]
        checks[f"{name}_retains_v5_base"] = bool(decoded[name].get("base_v5_payload_hex"))
        checks[f"{name}_native_unknown"] = (
            native["message_metadata"]["native_date"]["status"] == "unknown"
            and all(field["status"] == "unknown" for field in invalid_fields.values())
        )
    conflict = decoded["conflict_0"]
    conflict_native = conflict["native_text"]
    checks["conflict_retains_v5_base"] = bool(
        conflict.get("base_v5_payload_hex")
    )
    checks["conflict_retracts_line1_only"] = (
        conflict_native["message_metadata"]["native_date"]["status"] == "known"
        and conflict_native["message_metadata"]["raw_flags"]["status"] == "known"
        and conflict_native["text_fields"]["definition_key"]["status"] == "known"
        and conflict_native["text_fields"]["auxiliary_text"]["status"] == "known"
        and conflict_native["text_fields"]["line1_text"]["status"] == "unknown"
    )
    for name in ("wrong_parent_0", "wrong_popup_0"):
        native = decoded[name]["native_text"]
        fields_for_negative = native["text_fields"]
        checks[f"{name}_retains_v5_base"] = bool(decoded[name].get("base_v5_payload_hex"))
        checks[f"{name}_keeps_message_metadata"] = (
            native["message_metadata"]["native_date"]["status"] == "known"
            and fields_for_negative["definition_key"]["status"] == "known"
            and fields_for_negative["auxiliary_text"]["status"] == "known"
            and fields_for_negative["title_helper_candidate"]["status"] == "unknown"
            and fields_for_negative["line1_text"]["status"] == "unknown"
        )
    no_scope = decoded["no_scope_0"]["native_text"]
    checks["no_scope_retains_v5_base"] = bool(
        decoded["no_scope_0"].get("base_v5_payload_hex")
    )
    checks["no_scope_preserves_message_and_line1_unknown"] = (
        no_scope["message_metadata"]["native_date"]["status"] == "known"
        and no_scope["text_fields"]["definition_key"]["status"] == "known"
        and no_scope["text_fields"]["auxiliary_text"]["status"] == "known"
        and no_scope["text_fields"]["line1_text"]["status"] == "unknown"
    )
    return {
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "decoded": decoded,
        "wire_bytes": {name: len(raw) for name, raw in frames.items()},
        "wire_sha256": {name: hashlib.sha256(raw).hexdigest()
                         for name, raw in frames.items()},
    }


def run(output: Path | None = None, revision: int = 1) -> tuple[int, dict[str, Any]]:
    started = time.time()
    if revision < 1 or revision > 999:
        raise ValueError("revision_out_of_range")
    stage = STAGE_ROOT / f"manager-test-{revision:03d}"
    report_path = (output or (stage / "report.json")).resolve()
    if report_path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{report_path}")
    stage.mkdir(parents=True, exist_ok=True)
    exe = stage / "test-information-battle-native-text-observer.exe"
    compile_stdout = stage / "compile.stdout.log"
    compile_stderr = stage / "compile.stderr.log"
    run_stdout = stage / "run.stdout.log"
    run_stderr = stage / "run.stderr.log"
    for path in (exe, compile_stdout, compile_stderr, run_stdout, run_stderr):
        if path.exists():
            raise FileExistsError(f"refusing_to_overwrite:{path}")

    report: dict[str, Any] = {
        "schema": "information_battle_native_text_observer_fixture/v1",
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
            "observer": "INFORMATION_BATTLE_NATIVE_TEXT",
            "base_wire": 5,
            "extension_wire": 6,
            "cases": [
                "valid", "wrong_owner", "wrong_date", "duplicate",
                "conflict",
                "wrong_parent", "wrong_popup", "no_scope",
            ],
            "v5_base_retained_on_native_text_failure": True,
            "line1_capture": "real_observer_capture_line1; popup_and_formatter_guards",
            "line1_callback_abi":
                "(widget,text,uint8,return_pc,original_rbp,original_r13)",
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
        "-DINFORMATION_BATTLE_TEMPLATE=1",
        "-o", str(exe), str(ENTRY_STUB), str(LINE1_STUB), str(CPP), "-ladvapi32",
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
        line1_checks = {
            "real_capture_copied_positive":
                native_result.get("line1_copied") == 2,
            "real_capture_rejected_negative_bindings":
                (native_result.get("line1_binding_rejected", 0) >= 6
                 and native_result.get("conflict_binding_rejected") == 1),
            "real_capture_rejected_no_scope":
                native_result.get("line1_no_scope", 0) >= 1,
            "real_capture_conflict_retracted":
                (native_result.get("line1_copy_failed") == 1
                 and native_result.get("conflict_line1_invalid") is True),
            "real_capture_continuation_count": (
                native_result.get("line1_original_calls") == 10
                and native_result.get("line1_native_continuation_calls") == 10
            ),
        }
        native_result["line1_checks"] = line1_checks
        if not all(line1_checks.values()):
            native_result["passed"] = False
        report["run"].update({
            "result": native_result,
            "native_check_count": len(native_checks),
            "native_frame_names": sorted(frames),
        })
        report["wire_decode"] = decode_and_check(frames)
    except Exception as error:
        report["run"]["parse_error"] = f"{type(error).__name__}:{error}"

    native_passed = report.get("run", {}).get("result", {}).get("passed") is True
    report["status"] = "passed" if (
        ran.returncode == 0 and native_passed
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
                        help="compile and run the private observer fixture")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--revision", type=int, default=1,
                        help="isolated manager-test revision directory")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "inert", "run": False}, sort_keys=True))
        return 0
    try:
        code, report = run(args.output, args.revision)
    except (FileExistsError, OSError, RuntimeError, ValueError) as error:
        print(f"native text observer fixture failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"],
                      "report": str((args.output or
                                     (STAGE_ROOT / f"manager-test-{args.revision:03d}" /
                                      "report.json")).resolve()),
                      "native_returncode": report.get("run", {}).get("returncode"),
                      "wire_status": report.get("wire_decode", {}).get("status")},
                     ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
