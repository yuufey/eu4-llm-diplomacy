"""Compile and exercise the v24/v25 context-enabled observer manager fixture.

This is an offline, self-owned Windows fixture.  It includes the real observer
manager with INFORMATION_BATTLE_CONTEXT, installs the real entry shim against
a private 40 MiB VirtualAlloc image, and exercises the manager callback with
synthetic combat/side/vector/war objects.  No EU4 process, game function,
REA/RPM operation, DLL installation, or production source mutation is used.
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
import zlib

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-context-observer-20261025-001" / "manager-test-001"
NAVAL_STAGE = ROOT / "work" / "runtime" / "information-battle-naval-losses-20261026-001" / "manager-test-001"
CPP = NATIVE / "test-information-battle-observer-context.cpp"
STUB = NATIVE / "information-battle-entry-stub.S"
INC = NATIVE / "information-battle-observer.inc"
V1_HEADER = NATIVE / "information-battle-observation-wire.h"
V2_HEADER = NATIVE / "information-battle-context-wire.h"
CONTEXT_HEADER = NATIVE / "information-battle-owned-context.h"
V1_DECODER = ROOT / "work" / "information_battle_observation_wire.py"
V2_DECODER = ROOT / "work" / "information_battle_context_wire.py"
NAVAL_HEADER = NATIVE / "information-battle-naval-wire.h"
NAVAL_OWNED_HEADER = NATIVE / "information-battle-owned-naval.h"
V3_DECODER = ROOT / "work" / "information_battle_naval_wire.py"
SCRIPT = Path(__file__).resolve()

DIRECT_SOURCES = (
    CPP, STUB, INC,
    NATIVE / "information-battle-entry-plan.h",
    NATIVE / "entry-patch-transaction.inc",
    V1_HEADER, V2_HEADER, CONTEXT_HEADER, NAVAL_HEADER, NAVAL_OWNED_HEADER,
    NATIVE / "information-battle-owned-result.h",
    NATIVE / "information-battle-owned-summary.h",
    NATIVE / "information-battle-drain.h",
    NATIVE / "information-battle-log-writer.h",
    NATIVE / "information-battle-fragment.h",
    NATIVE / "information-battle-buffer.h",
    NATIVE / "information-battle-wire.h",
    V1_DECODER, V2_DECODER, V3_DECODER, SCRIPT,
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
    if not path.is_file():
        return {"path": path.relative_to(ROOT).as_posix(), "status": "missing"}
    return {"path": path.relative_to(ROOT).as_posix(), "status": "observed",
            "bytes": path.stat().st_size, "sha256": sha256_file(path)}


def compiler_path() -> str | None:
    return shutil.which("g++") or r"C:\Strawberry\c\bin\g++.exe"


def parse_native(stdout: str) -> tuple[dict[str, Any], dict[str, bytes], Path | None]:
    frames: dict[str, bytes] = {}
    log_path: Path | None = None
    result_line: str | None = None
    for line in stdout.splitlines():
        if line.startswith("FRAME_HEX "):
            pieces = line.split(" ", 2)
            if len(pieces) != 3 or pieces[1] in frames:
                raise ValueError("invalid_or_duplicate_frame_line")
            frames[pieces[1]] = bytes.fromhex(pieces[2])
        elif line.startswith("LOG_PATH "):
            log_path = Path(line.split(" ", 1)[1].strip())
        elif line.startswith("{") and line.endswith("}"):
            result_line = line
    if result_line is None:
        raise RuntimeError("native_fixture_omitted_result")
    result = json.loads(result_line)
    if not isinstance(result, dict):
        raise ValueError("native_result_not_object")
    expected = {"observed", "naval", "context_failure", "unknown_caller"}
    if set(frames) != expected:
        raise ValueError(f"frame_cases_mismatch:{sorted(frames)}")
    return result, frames, log_path


def decode_frame_cases(frames: dict[str, bytes], naval_mode: bool = False) -> dict[str, Any]:
    sys.path.insert(0, str(ROOT))
    if naval_mode:
        from work.information_battle_naval_wire import decode
        expected_version = 3
    else:
        from work.information_battle_context_wire import decode
        expected_version = 2
    checks: dict[str, bool] = {}
    decoded: dict[str, Any] = {}
    for name, raw in frames.items():
        decoded[name] = decode(raw)
        checks[f"{name}_v{expected_version}_schema"] = (
            decoded[name]["wire"]["version"] == expected_version
        )
        checks[f"{name}_pointer_free"] = "pointer" not in json.dumps(decoded[name])
        checks[f"{name}_business_unknown"] = (
            decoded[name]["complete"] is False
            and decoded[name]["business_complete"] is False
            and decoded[name]["visibility_verified"] is False
        )
    observed = decoded["observed"]
    ctx = observed["context"]
    checks["observed_context_present"] = observed["context_present"] is True
    checks["observed_land_selector"] = (
        ctx["raw_selector"] == 1 and ctx["kind"] == 1
        and ctx["selector_code_hex"] == "b801000000c3"
        and ctx["known_router"] is True
    )
    checks["observed_context_vectors"] = (
        [len(side["participants"]["full_refs"]) for side in ctx["sides"]] == [2, 1]
        and ctx["war_context_status"] == 1
        and ctx["war_members"]["physical_player_membership_known"] is True
        and ctx["war_members"]["physical_player_is_war_member"] is True
    )
    checks["observed_raw_side_fields"] = (
        ctx["sides"][0]["raw_fields"] == [1000, 1001, 1002, 1003, 1004, 1005]
        and ctx["sides"][1]["raw_fields"] == [2000, 2001, 2002, 2003, 2004, 2005]
    )
    naval = decoded["naval"]
    checks["naval_context_present"] = naval["context_present"] is True
    checks["naval_selector"] = naval["context"]["raw_selector"] == 2 and naval["context"]["kind"] == 2
    if naval_mode:
        checks["observed_v3_naval_absent"] = (
            decoded["observed"]["wire"]["naval_present"] is False
            and decoded["observed"]["naval"] is None
        )
        checks["naval_v3_extension_present"] = (
            decoded["naval"]["wire"]["naval_present"] is True
            and decoded["naval"]["naval"] is not None
        )
        extension = decoded["naval"]["naval"]
        checks["naval_raw_losses_and_gates"] = (
            extension["sides"] == [
                {"raw_loss_i32": [140, 141, 142, 143], "raw_gate": 0x69},
                {"raw_loss_i32": [240, 241, 242, 243], "raw_gate": 0x96},
            ]
        )
        checks["naval_summary_row_types"] = extension["row_types"] == [3, 6]
    else:
        checks["naval_v2_context_only"] = "naval" not in decoded["naval"]
    failure = decoded["context_failure"]
    checks["context_failure_keeps_base"] = (
        failure["context_present"] is False
        and failure["context"] is None
        and failure["observation"]["known_router"] is True
    )
    if naval_mode:
        checks["context_failure_keeps_valid_base_without_naval"] = (
            failure["wire"]["naval_present"] is False
            and failure["naval"] is None
        )
    unknown = decoded["unknown_caller"]
    checks["unknown_caller_does_not_use_rbx_war"] = (
        unknown["context_present"] is True
        and unknown["observation"]["known_router"] is False
        and unknown["context"]["war_context_status"] == 0
        and unknown["context"]["war_members"] is None
    )
    checks["all_frames_pointer_free"] = all(
        "pointer" not in json.dumps(value) for value in decoded.values()
    )
    return {
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "decoded": decoded,
        "wire_bytes": {name: len(raw) for name, raw in frames.items()},
        "wire_sha256": {name: sha256_bytes(raw) for name, raw in frames.items()},
    }


def decode_log_fragments(log_path: Path | None, naval_mode: bool = False) -> dict[str, Any]:
    """Read only the bounded checked log and reassemble its fragment payloads."""
    if log_path is None or not log_path.is_file():
        return {"status": "failed", "reason": "checked_log_missing"}
    size = log_path.stat().st_size
    if size <= 0 or size > 8 * 1024 * 1024:
        return {"status": "failed", "reason": "checked_log_over_bound_or_empty", "size_bytes": size}
    raw = log_path.read_bytes()
    lines = raw.splitlines(keepends=True)
    if not lines or not lines[0].startswith(b"EU4_OWNED_BATTLE_WIRE_V1 "):
        return {"status": "failed", "reason": "checked_log_header_mismatch", "size_bytes": size}
    from work.information_battle_reassembly import parse_fragment_payload
    groups: dict[int, dict[int, bytes]] = {}
    metadata: dict[int, tuple[int, int, int]] = {}
    records = 0
    parse_errors: list[str] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            payload = bytes.fromhex(obj["payload_hex"])
            fragment = parse_fragment_payload(payload)
            message_id = int(fragment.message_id)
            groups.setdefault(message_id, {})[fragment.fragment_index] = fragment.fragment_bytes
            metadata[message_id] = (fragment.total_bytes, fragment.fragment_count, fragment.whole_crc32)
            records += 1
        except Exception as exc:
            parse_errors.append(f"{type(exc).__name__}:{exc}")
            if len(parse_errors) >= 8:
                break
    complete = 0
    decoded_expected = 0
    decoded_errors: list[str] = []
    for message_id, parts in groups.items():
        total, count, crc = metadata[message_id]
        if len(parts) != count or set(parts) != set(range(count)):
            continue
        payload = b"".join(parts[index] for index in range(count))
        if len(payload) != total or (zlib.crc32(payload) & 0xffffffff) != crc:
            decoded_errors.append(f"crc_or_length:{message_id}")
            continue
        complete += 1
        try:
            if naval_mode:
                from work.information_battle_naval_wire import decode
            else:
                from work.information_battle_context_wire import decode
            value = decode(payload)
            if value["wire"]["version"] == (3 if naval_mode else 2):
                decoded_expected += 1
        except Exception as exc:
            decoded_errors.append(f"decode:{message_id}:{type(exc).__name__}:{exc}")
    return {
        "status": "passed" if records > 0 and complete > 0 and decoded_expected == complete and not parse_errors and not decoded_errors else "failed",
        "size_bytes": size, "line_count": len(lines), "fragment_records": records,
        "complete_groups": complete,
        "decoded_expected_groups": decoded_expected,
        "decoded_v2_groups": decoded_expected if not naval_mode else 0,
        "decoded_v3_groups": decoded_expected if naval_mode else 0,
        "parse_errors": parse_errors, "decode_errors": decoded_errors,
        "bounded_read_bytes": size,
    }


def run(revision: int = 1, output: Path | None = None,
        naval_mode: bool = False) -> tuple[int, dict[str, Any]]:
    started = time.time()
    default_stage = NAVAL_STAGE if naval_mode else STAGE
    report_path = (output or (default_stage / ("report.json" if revision == 1 else f"report-{revision:03d}.json"))).resolve()
    stage = report_path.parent
    stage.mkdir(parents=True, exist_ok=True)
    exe = stage / f"test-information-battle-observer-context-{revision:03d}.exe"
    compile_stdout = stage / f"compile-{revision:03d}.stdout.log"
    compile_stderr = stage / f"compile-{revision:03d}.stderr.log"
    run_stdout = stage / f"run-{revision:03d}.stdout.log"
    run_stderr = stage / f"run-{revision:03d}.stderr.log"
    for path in (report_path, exe, compile_stdout, compile_stderr, run_stdout, run_stderr):
        if path.exists():
            raise FileExistsError(f"refusing_to_overwrite:{path}")
    report: dict[str, Any] = {
        "schema": "information_battle_context_observer_manager_test_v2",
        "status": "blocked",
        "mode": "offline_synthetic_process",
        "wire_mode": "naval_v3" if naval_mode else "context_v2",
        "scope": {
            "game_access": False, "remote_process_access": False,
            "rea_access": False, "remote_process_memory_read": False,
            "self_process_read_process_memory": True,
            "dll_installation": False, "native_game_function_invoked": False,
            "production_modified": False, "fixture_private_initialization": True,
        },
        "contract": {
            "macro": "INFORMATION_BATTLE_CONTEXT+INFORMATION_BATTLE_NAVAL" if naval_mode else "INFORMATION_BATTLE_CONTEXT",
            "record": "information::battle::naval_wire::NavalObservation (v3; base ContextObservation)" if naval_mode else "information::battle::context_wire::ContextObservation (v2)",
            "context_capture": "any guarded combat kind/side; RBX war only for known caller",
            "wrapper_chain": "land/naval/failure/unknown each use private RX CALL caller -> patched source -> entry shim -> manager -> trampoline -> fixture native body",
            "direct_guard_cases": "busy and foreign-thread drops invoke the manager callback directly by design",
            "context_failure": "valid base retained with context_present=false; naval_present=false in v3; context_copy_failed separate",
            "private_region_bytes": 0x2800000,
            "fixed_entry_rva": hex(0x238620), "fixed_unwind_rva": hex(0x1DE6C98),
            "capture_slots": 8, "wire_version": 3 if naval_mode else 2,
            "max_wire_bytes": 65536 if naval_mode else 32768,
            "naval_extension": "raw side loss i32[4], gate byte, summary row types" if naval_mode else None,
            "fragment_to_python_decoder": True,
        },
        "source_pins": {path.relative_to(ROOT).as_posix(): file_pin(path) for path in DIRECT_SOURCES},
        "compile": {}, "run": {}, "wire_decode": {}, "log_reassembly": {},
        "limitations": [
            "Private objects and code are synthetic; this does not establish live EU4 visibility, identity, lifetime, reentrancy, or battle completeness.",
            "The four context cases use the private RX caller-to-entry-shim path; busy and foreign-thread guard cases call the manager callback directly, all over self-owned memory and never a game function.",
            "Context values remain raw selector, references, vectors and six side slots; no roles, units, winner, war ID or visibility are claimed.",
        ],
    }
    compiler = compiler_path()
    if compiler is None or not Path(compiler).is_file():
        report["status"] = "blocked_missing_compiler"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 1, report
    command = [compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra", "-Werror", "-O2", "-fstack-usage", "-static-libgcc", "-static-libstdc++", "-Wl,--no-insert-timestamp", "-I", str(NATIVE)]
    if naval_mode:
        command.append("-DINFORMATION_BATTLE_NAVAL=1")
    command.extend(["-o", str(exe), str(STUB), str(CPP), "-ladvapi32"])
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    compile_stdout.write_bytes(compiled.stdout); compile_stderr.write_bytes(compiled.stderr)
    report["compile"] = {"command": command, "returncode": compiled.returncode, "stdout_sha256": sha256_bytes(compiled.stdout), "stderr_sha256": sha256_bytes(compiled.stderr)}
    if compiled.returncode != 0 or not exe.is_file():
        report["status"] = "failed_compile"; report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 1, report
    ran = subprocess.run([str(exe)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    run_stdout.write_bytes(ran.stdout); run_stderr.write_bytes(ran.stderr)
    stdout = ran.stdout.decode("ascii", errors="replace")
    report["run"] = {"returncode": ran.returncode, "stdout_sha256": sha256_bytes(ran.stdout), "stderr_sha256": sha256_bytes(ran.stderr), "stdout_bytes": len(ran.stdout), "stderr_bytes": len(ran.stderr)}
    try:
        native_result, frames, log_path = parse_native(stdout)
        report["run"]["result"] = native_result
        report["run"]["frame_names"] = sorted(frames)
        report["run"]["log_path"] = str(log_path) if log_path else None
        report["wire_decode"] = decode_frame_cases(frames, naval_mode)
        report["log_reassembly"] = decode_log_fragments(log_path, naval_mode)
    except Exception as exc:
        report["status"] = "failed_native_output"
        report["run"]["parse_error"] = f"{type(exc).__name__}:{exc}"
    report["native_checks"] = {"passed": native_result.get("passed") is True if "native_result" in locals() else False,
                                "context_copied": native_result.get("context_copied") if "native_result" in locals() else None,
                                "context_copy_failures": native_result.get("context_copy_failures") if "native_result" in locals() else None}
    report["status"] = "passed" if (
        ran.returncode == 0 and report.get("run", {}).get("result", {}).get("passed") is True
        and report.get("wire_decode", {}).get("status") == "passed"
        and report.get("log_reassembly", {}).get("status") == "passed"
    ) else ("failed_contract" if report.get("status") != "failed_native_output" else report["status"])
    report["elapsed_seconds"] = time.time() - started
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return (0 if report["status"] == "passed" else 1), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--naval", action="store_true",
        help="compile the optional INFORMATION_BATTLE_NAVAL v3 fixture",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.revision <= 999:
        parser.error("--revision must be between 1 and 999")
    try:
        code, report = run(args.revision, args.output, args.naval)
    except (FileExistsError, OSError, RuntimeError, ValueError) as exc:
        print(f"context observer fixture runner failed: {exc}", file=sys.stderr)
        return 2
    default_stage = NAVAL_STAGE if args.naval else STAGE
    print(json.dumps({"status": report["status"], "report": str((args.output or (default_stage / ("report.json" if args.revision == 1 else f"report-{args.revision:03d}.json"))).resolve()), "native_returncode": report.get("run", {}).get("returncode"), "wire_status": report.get("wire_decode", {}).get("status"), "log_status": report.get("log_reassembly", {}).get("status")}, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
