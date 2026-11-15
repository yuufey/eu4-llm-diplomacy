"""Run the bounded vanilla/plugin title-query plan guard fixture.

The default invocation and --help are inert.  Only an explicit --run compiles
and executes the value-only C++ Reader fixture; it never opens EU4 or uses
REA/RPM.  The plugin SHA is metadata checked by the caller, while this guard
checks the bounded bytes, slots and canonical address ranges.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-native-title-20261027-001" / "title-query-plan-guard-001"
CPP = NATIVE / "tests" / "information-battle-title-query-plan-guard-test.cpp"
HEADER = NATIVE / "information-battle-title-query-plan.h"
SOURCE_DIR = ROOT / "work" / "runtime" / "plugin-title-hook-source-001"
SOURCE_FILES = (
    Path(__file__).resolve(),
    CPP,
    HEADER,
    SOURCE_DIR / "source-001.json",
    SOURCE_DIR / "source-002.json",
    SOURCE_DIR / "source-003.json",
    SOURCE_DIR / "fun-1800373a0-375cb.bin",
    SOURCE_DIR / "fun-1800373a0-pdata.bin",
    SOURCE_DIR / "fun-1800373a0-unwind-7bbb0.bin",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _parse_native(stdout: bytes) -> tuple[list[str], int, int]:
    names: list[str] = []
    passed = failed = None
    for line in stdout.decode("ascii", errors="strict").splitlines():
        if line.startswith("PASS "):
            names.append(line[5:])
        elif line.startswith("SUMMARY "):
            fields = dict(item.split("=", 1) for item in line[8:].split())
            passed = int(fields["passed"])
            failed = int(fields["failed"])
    if passed is None or failed is None:
        raise ValueError("missing_native_summary")
    if len(names) != len(set(names)):
        raise ValueError("duplicate_native_check")
    if passed != len(names):
        raise ValueError("native_pass_count_mismatch")
    return names, passed, failed


def run(output: Path | None = None) -> dict[str, Any]:
    compiler = shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        raise RuntimeError("no_cxx_compiler")
    if any(not path.is_file() for path in SOURCE_FILES):
        raise FileNotFoundError("guard_sources_missing")
    report = output or (STAGE / "report-001.json")
    stage=report.parent
    if stage.exists():
        raise FileExistsError(f"refusing_to_overwrite:{stage}")
    stage.mkdir(parents=True, exist_ok=False)
    executable = stage / "test-information-battle-title-query-plan-guard.exe"
    command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
               "-pedantic", "-O2", "-I", str(NATIVE), str(CPP),
               "-o", str(executable)]
    compile_result = subprocess.run(command, cwd=ROOT, check=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
    if compile_result.returncode != 0:
        raise RuntimeError(f"native_compile_failed:{compile_result.stderr[-4000:]}")
    native = subprocess.run([str(executable)], cwd=ROOT, check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    names, passed, failed = _parse_native(native.stdout)
    checks = {
        "native_exit_zero": native.returncode == 0,
        "all_guard_cases_passed": failed == 0 and passed == 19,
        "vanilla_positive": "vanilla" in names,
        "plugin_positive": "known-plugin" in names,
        "exact_body_and_metadata_negatives": all(
            name in names for name in (
                "wrong-helper-prefix", "wrong-helper-plugin-target",
                "plugin-bound-vanilla-helper",
                "wrong-destructor", "wrong-plugin-bridge",
                "wrong-plugin-helper",
                "wrong-plugin-unwind")),
        "slot_and_range_negatives": all(
            name in names for name in (
                "wrong-plugin-call-slot", "wrong-plugin-return-slot",
                "plugin-address-overflow", "small-image", "bad-game-base",
                "bad-plugin-base")),
    }
    result = {
        "schema": "information_battle_title_query_plan_guard_test.v1",
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "native_checks": {"passed": passed, "failed": failed, "names": names},
        "native_stdout": native.stdout.decode("ascii", errors="strict"),
        "native_stderr": native.stderr.decode("ascii", errors="replace"),
        "compiler": compiler,
        "sources": {
            str(path.relative_to(ROOT)).replace("\\", "/"): {
                "bytes": path.stat().st_size, "sha256": _sha256(path),
            }
            for path in SOURCE_FILES
        },
        "plugin_guard": {
            "sha256": "a73a8b6c82e620fc7d577bdb64df731b779a72bb43c2363a11ed12be23a9d819",
            "size_bytes": 0x89000,
            "identity_hash_checked_outside_guard": True,
        },
        "scope": {"game": False, "rea": False, "rpm": False,
                  "native_call": False, "full_suite": False},
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="compile and run the bounded native fixture")
    parser.add_argument("--output", type=Path,
                        help="exclusive report path used with --run")
    args = parser.parse_args(argv)
    if not args.run:
        return 0
    result = run(args.output)
    print(json.dumps({"status": result["status"], "checks": result["checks"]},
                     ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
