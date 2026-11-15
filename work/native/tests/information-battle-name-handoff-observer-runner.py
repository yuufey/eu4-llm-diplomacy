"""One-shot offline NAME observer integration fixture runner."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from work.local_config import load_local_env

NATIVE = ROOT / "work/native"
TEST_DIR = NATIVE / "tests"
STAGE = (ROOT / "work/runtime/information-battle-name-handoff-observer-integration-20261104-158-001").resolve()
CPP_SOURCE = TEST_DIR / "information-battle-name-handoff-observer-test.cpp"
OBSERVER = NATIVE / "information-battle-observer.inc"
GENERATED_HEADER = "information-battle-name-handoff-synthetic-guards.h"
EXPECTED_TESTS = 9
EXPECTED_FRAMES = {
    "land_name_copied_before_move_and_flushed_v8": (1, 1, b"land-result"),
    "naval_name_copied_before_move_and_flushed_v8": (1, 2, b"naval-result"),
    "callback_without_scope_remains_unknown": (0, 0, b""),
    "wrong_combat_owner_remains_unknown": (0, 0, b""),
    "wrong_key_remains_unknown": (0, 0, b""),
    "date_drift_remains_unknown": (0, 0, b""),
    "identical_duplicate_preserves_name": (1, 1, b"land-result"),
    "conflict_latches_unknown_after_original_value_returns": (0, 0, b""),
    "scope_exit_guard_failure_withdraws_name": (0, 0, b""),
}


def pin(path: Path) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return {
        "path": path.resolve().relative_to(ROOT).as_posix(),
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def write_text_exclusive(path: Path, value: str) -> None:
    write_exclusive(path, value.encode("utf-8"))


def checkpoint(path: Path, receipt: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    encoded = (json.dumps(receipt, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def run_redirected(command: list[str], cwd: Path, stdout_path: Path,
                   stderr_path: Path, timeout: int) -> int:
    with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
        process = subprocess.Popen(command, cwd=cwd, stdout=stdout_stream,
                                   stderr=stderr_stream, close_fds=True)
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise TimeoutError("subprocess_timeout:" + Path(command[0]).name)


def local_dependencies() -> list[Path]:
    pending = [CPP_SOURCE]
    found: set[Path] = set()
    include_pattern = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
    while pending:
        current = pending.pop().resolve()
        if current in found or not current.is_file():
            continue
        found.add(current)
        if current.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("local_source_exceeds_10mb:" + str(current))
        text = current.read_text(encoding="utf-8")
        for include in include_pattern.findall(text):
            if include == GENERATED_HEADER:
                continue
            candidates = (current.parent / include, NATIVE / include)
            target = next((item for item in candidates if item.is_file()), None)
            if target is not None:
                pending.append(target)
    return sorted(found)


def display_guard_arrays() -> list[tuple[str, int, list[int]]]:
    text = OBSERVER.read_text(encoding="utf-8")
    marker = "static bool display_context_code_guard() noexcept {"
    start = text.find(marker)
    if start < 0:
        raise ValueError("display_context_code_guard_missing")
    end = text.find("\n}\n#endif", start)
    if end < 0:
        raise ValueError("display_context_code_guard_end_missing")
    body = text[start:end]
    declaration = re.compile(
        r"static\s+constexpr\s+unsigned\s+char\s+(\w+)\[\]\s*=\s*\{(.*?)\};",
        re.DOTALL,
    )
    result: list[tuple[str, int, list[int]]] = []
    for match in declaration.finditer(body):
        after = body[match.end():]
        address = re.search(r"\bif\s*\(\s*(0x[0-9a-fA-F]+)u\s*>", after)
        if address is None:
            raise ValueError("display_guard_address_missing:" + match.group(1))
        values = [int(value, 16) for value in re.findall(
            r"0x([0-9a-fA-F]{1,2})", match.group(2))]
        if not values:
            raise ValueError("display_guard_bytes_missing:" + match.group(1))
        result.append((match.group(1), int(address.group(1), 16), values))
    if len(result) != 6:
        raise ValueError("unexpected_display_guard_array_count:" + str(len(result)))
    return result


def generate_guard_header(path: Path) -> dict:
    arrays = display_guard_arrays()
    lines = [
        "#ifndef INFORMATION_BATTLE_NAME_HANDOFF_SYNTHETIC_GUARDS_H",
        "#define INFORMATION_BATTLE_NAME_HANDOFF_SYNTHETIC_GUARDS_H",
        "#include <cstddef>",
        "#include <cstdint>",
        "namespace synthetic_name_handoff_guards {",
        "struct Range { std::uintptr_t rva; const unsigned char* bytes; std::size_t size; };",
    ]
    for index, (name, _rva, values) in enumerate(arrays):
        lines.append(f"inline constexpr unsigned char bytes_{index}_{name}[] = {{")
        for offset in range(0, len(values), 16):
            row = values[offset:offset + 16]
            lines.append("    " + ", ".join(f"0x{value:02x}u" for value in row) + ",")
        lines.append("};")
    lines.append("inline constexpr Range kDisplayContextRanges[] = {")
    for index, (name, rva, values) in enumerate(arrays):
        lines.append(
            f"    {{0x{rva:x}u, bytes_{index}_{name}, sizeof(bytes_{index}_{name})}},"
        )
    lines.extend(("};", "}  // namespace synthetic_name_handoff_guards", "#endif"))
    content = "\n".join(lines) + "\n"
    write_text_exclusive(path, content)
    return {
        "path": path.resolve().relative_to(ROOT).as_posix(),
        "ranges": len(arrays),
        "bytes": sum(len(item[2]) for item in arrays),
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


def decode_frames(stdout: str) -> dict:
    frames: dict[str, bytes] = {}
    for line in stdout.splitlines():
        if not line.startswith("FRAME_HEX "):
            continue
        parts = line.split(" ", 2)
        if len(parts) != 3 or parts[1] in frames:
            raise ValueError("malformed_or_duplicate_frame_line")
        try:
            frames[parts[1]] = bytes.fromhex(parts[2])
        except ValueError as exc:
            raise ValueError("invalid_frame_hex:" + parts[1]) from exc

    if set(frames) != set(EXPECTED_FRAMES):
        raise ValueError("frame_labels_mismatch:" + ",".join(sorted(frames)))

    decoded: dict[str, dict] = {}
    for label, frame in frames.items():
        if len(frame) < 20 or frame[:4] != b"IBOW" \
                or int.from_bytes(frame[4:6], "little") != 8:
            raise ValueError("outer_v8_header_mismatch:" + label)
        base7_bytes = int.from_bytes(frame[6:10], "little")
        base7_start = 10
        base7_end = base7_start + base7_bytes
        if base7_end + 10 + 24 > len(frame):
            raise ValueError("truncated_v8_frame:" + label)
        base7 = frame[base7_start:base7_end]
        if len(base7) < 20 or base7[:4] != b"IBOW" \
                or int.from_bytes(base7[4:6], "little") != 7:
            raise ValueError("embedded_v7_header_mismatch:" + label)
        base6_bytes = int.from_bytes(base7[6:10], "little")
        dctx = 10 + base6_bytes
        if dctx + 10 > len(base7) or base7[dctx:dctx + 4] != b"DCTX" \
                or int.from_bytes(base7[dctx + 4:dctx + 6], "little") != 1:
            raise ValueError("embedded_dctx_header_mismatch:" + label)
        dctx_body_bytes = int.from_bytes(base7[dctx + 6:dctx + 10], "little")
        if dctx + 10 + dctx_body_bytes != len(base7):
            raise ValueError("embedded_dctx_length_mismatch:" + label)

        extension = frame[base7_end:]
        if extension[:4] != b"NHND" \
                or int.from_bytes(extension[4:6], "little") != 1:
            raise ValueError("nhnd_header_mismatch:" + label)
        body_bytes = int.from_bytes(extension[6:10], "little")
        body = extension[10:]
        if body_bytes != len(body) or len(body) < 24:
            raise ValueError("nhnd_body_length_mismatch:" + label)
        state = body[0]
        kind = body[1]
        reserved = int.from_bytes(body[2:4], "little")
        sequence = int.from_bytes(body[4:12], "little")
        raw_date = int.from_bytes(body[12:20], "little", signed=True)
        value_length = int.from_bytes(body[20:24], "little")
        value = body[24:]
        expected_state, expected_kind, expected_value = EXPECTED_FRAMES[label]
        if reserved != 0 or state != expected_state or kind != expected_kind \
                or value_length != len(value) or value != expected_value:
            raise ValueError("decoded_name_mismatch:" + label)
        if state == 0 and (sequence != 0 or raw_date != 0 or value_length != 0):
            raise ValueError("unknown_name_contains_identity:" + label)
        if state == 1 and (sequence == 0 or raw_date != 56553384):
            raise ValueError("known_name_identity_mismatch:" + label)
        decoded[label] = {
            "state": state,
            "kind": kind,
            "sequence": sequence,
            "raw_date": raw_date,
            "value_hex": value.hex(),
            "frame_bytes": len(frame),
            "sha256": hashlib.sha256(frame).hexdigest(),
        }
    return decoded


def resolve_compiler() -> tuple[str, str]:
    had_process_override = bool(os.environ.get("EU4_CXX", "").strip())
    requested = os.environ.get("EU4_CXX", "").strip()
    if not requested:
        requested = load_local_env().get("EU4_CXX", "").strip()
    if requested:
        resolved = shutil.which(requested)
        if resolved is None and Path(requested).is_file():
            resolved = str(Path(requested).resolve())
        if resolved is None:
            raise FileNotFoundError("EU4_CXX_not_found:" + requested)
        selected_by = (
            "EU4_CXX_process_environment"
            if had_process_override else "work.local_config.load_local_env"
        )
        return str(Path(resolved).resolve()), selected_by
    fallback = shutil.which("g++")
    if fallback is None:
        raise FileNotFoundError("EU4_CXX_unset_and_g++_not_found")
    return str(Path(fallback).resolve()), "g++_fallback_EU4_CXX_unset"


def next_attempt() -> tuple[int, Path]:
    STAGE.mkdir(parents=True, exist_ok=True)
    for number in range(1, 1000):
        attempt = STAGE / f"attempt-{number:03d}"
        if not attempt.exists():
            attempt.mkdir(parents=True, exist_ok=False)
            return number, attempt
    raise RuntimeError("no_unused_attempt_slot")


def run_test_only() -> int:
    number, attempt = next_attempt()
    executable = attempt / "information-battle-name-handoff-observer-test.exe"
    header_path = attempt / GENERATED_HEADER
    log_path = attempt / "run.log"
    receipt_path = attempt / "receipt.json"
    compile_stdout_path = attempt / "compile.stdout.log"
    compile_stderr_path = attempt / "compile.stderr.log"
    fixture_stdout_path = attempt / "fixture.stdout.log"
    fixture_stderr_path = attempt / "fixture.stderr.log"
    dependencies = local_dependencies()
    source_paths = sorted(set(dependencies + [Path(__file__).resolve()]))
    pins_before = [pin(path) for path in source_paths]
    header_pin = generate_guard_header(header_path)
    for output_path in (compile_stdout_path, compile_stderr_path,
                        fixture_stdout_path, fixture_stderr_path):
        write_exclusive(output_path, b"")
    receipt = {
        "status": "incomplete",
        "stage": "prepared",
        "attempt": number,
        "synthetic_fixture_header": header_pin,
        "source_pins_before": pins_before,
        "expected_test_cases": EXPECTED_TESTS,
        "native_game_access": False,
        "real_native_entry_execution": False,
        "compile_stdout": compile_stdout_path.name,
        "compile_stderr": compile_stderr_path.name,
        "fixture_stdout": fixture_stdout_path.name,
        "fixture_stderr": fixture_stderr_path.name,
    }
    write_text_exclusive(receipt_path,
                         json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    log_parts = ["synthetic_name_handoff_fixture=true", "native_execution=false"]
    try:
        compiler, selected_by = resolve_compiler()
        receipt["stage"] = "compiler_identity_probe"
        receipt["compiler_path"] = compiler
        receipt["compiler_selected_by"] = selected_by
        checkpoint(receipt_path, receipt)
        version = subprocess.run([compiler, "--version"], capture_output=True,
                                 text=True, check=False, timeout=10)
        target = subprocess.run([compiler, "-dumpmachine"], capture_output=True,
                                text=True, check=False, timeout=10)
        if version.returncode != 0 or target.returncode != 0:
            raise RuntimeError("compiler_identity_query_failed")
        machine = target.stdout.strip()
        if "x86_64-w64-mingw32" not in machine:
            raise RuntimeError("unexpected_compiler_target:" + machine)
        command = [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra",
                   "-Wpedantic", "-Werror", "-I", str(NATIVE), "-I",
                   str(attempt), str(CPP_SOURCE), "-ladvapi32", "-o",
                   str(executable)]
        receipt["compiler"] = {
            "path": compiler,
            "selected_by": selected_by,
            "version": version.stdout.splitlines()[0] if version.stdout else "unknown",
            "target": machine,
            "compile_command": command,
        }
        receipt["stage"] = "compile_started"
        receipt["compile_started_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        checkpoint(receipt_path, receipt)
        compiled_returncode = run_redirected(
            command, TEST_DIR, compile_stdout_path, compile_stderr_path, 120)
        receipt["compile_returncode"] = compiled_returncode
        receipt["compile_finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        receipt["compile_stdout_pin"] = pin(compile_stdout_path)
        receipt["compile_stderr_pin"] = pin(compile_stderr_path)
        receipt["stage"] = "compiled" if compiled_returncode == 0 else "compile_failed"
        checkpoint(receipt_path, receipt)
        if compiled_returncode != 0:
            raise RuntimeError("compile_failed")

        fixture_command = [str(executable)]
        receipt["fixture_command"] = fixture_command
        receipt["stage"] = "fixture_started"
        receipt["fixture_started_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        checkpoint(receipt_path, receipt)
        fixture_returncode = run_redirected(
            fixture_command, attempt, fixture_stdout_path,
            fixture_stderr_path, 45)
        receipt["test_returncode"] = fixture_returncode
        receipt["fixture_finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        receipt["fixture_stdout_pin"] = pin(fixture_stdout_path)
        receipt["fixture_stderr_pin"] = pin(fixture_stderr_path)
        receipt["stage"] = "fixture_finished"
        checkpoint(receipt_path, receipt)
        if fixture_stdout_path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("fixture_stdout_exceeds_10mb")
        fixture_stdout = fixture_stdout_path.read_text(encoding="utf-8")
        receipt["decoded_v8_frames"] = decode_frames(fixture_stdout)
        check_lines = [line for line in fixture_stdout.splitlines()
                       if line.startswith("CHECK ")]
        checks = [line[6:-5] for line in check_lines if line.endswith(" PASS")]
        failures = [line[6:-5] for line in check_lines if line.endswith(" FAIL")]
        receipt["check_count"] = len(checks)
        receipt["passed_checks"] = checks
        receipt["failed_checks"] = failures
        if fixture_returncode != 0 or len(checks) < EXPECTED_TESTS:
            raise RuntimeError("owned_observer_integration_tests_failed")
        receipt["stage"] = "fixture_passed"
        receipt["status"] = "passed"
    except Exception as exc:
        receipt["status"] = "failed"
        receipt["failure"] = f"{type(exc).__name__}:{exc}"

    pins_after = [pin(path) for path in source_paths]
    receipt["source_pins_after"] = pins_after
    receipt["sources_unchanged"] = pins_before == pins_after
    if not receipt["sources_unchanged"]:
        receipt["status"] = "failed"
        receipt["failure"] = "source_changed_during_test"
    if executable.exists():
        receipt["executable"] = pin(executable)
    receipt["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    log_parts.extend((
        "compile_stdout=" + compile_stdout_path.name,
        "compile_stderr=" + compile_stderr_path.name,
        "fixture_stdout=" + fixture_stdout_path.name,
        "fixture_stderr=" + fixture_stderr_path.name,
    ))
    write_text_exclusive(log_path, "\n".join(log_parts) + "\n")
    receipt["log"] = pin(log_path)
    checkpoint(receipt_path, receipt)
    print(json.dumps({
        "status": receipt["status"],
        "attempt": number,
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "check_count": receipt.get("check_count"),
        "failure": receipt.get("failure"),
    }, ensure_ascii=False))
    return 0 if receipt["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-only", action="store_true")
    args = parser.parse_args()
    if not args.test_only:
        print(json.dumps({"status": "refused",
                          "reason": "explicit_--test-only_required"}))
        return 2
    try:
        return run_test_only()
    except Exception as exc:
        print(json.dumps({"status": "refused",
                          "reason": f"{type(exc).__name__}:{exc}"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
