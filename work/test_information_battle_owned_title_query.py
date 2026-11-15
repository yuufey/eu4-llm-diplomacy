"""Run the bounded native title-query fixture explicitly.

The default path and --help only describe the command.  --run requires a new
output directory so a receipt can never silently overwrite an earlier run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "work/native/information-battle-owned-title-query.h"
OWNED_TEXT_HEADER = ROOT / "work/native/information-battle-owned-native-text.h"
FIXTURE = ROOT / "work/native/tests/information-battle-owned-title-query-test.cpp"
RUNNER = Path(__file__).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description=(
            "Compile and run the synthetic bounded native title-query fixture. "
            "No game, process, REA, or test-suite access is performed."
        )
    )
    command.add_argument(
        "--run", action="store_true", help="perform the explicit fixture run"
    )
    command.add_argument(
        "--output", type=Path, help="new directory receiving the compile/run receipt"
    )
    return command


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="")


def main(argv: list[str] | None = None) -> int:
    command = parser()
    arguments = command.parse_args(argv)
    if not arguments.run:
        command.print_help()
        return 0
    if arguments.output is None:
        command.error("--run requires --output <new-directory>")

    output = arguments.output
    if not output.is_absolute():
        output = ROOT / output
    if output.exists():
        command.error(f"output directory already exists: {output}")
    output.mkdir(parents=True, exist_ok=False)

    executable = output / "information-battle-owned-title-query-test.exe"
    compile_command = [
        "g++",
        "-std=c++17",
        "-fno-exceptions",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        "-I",
        str(ROOT / "work/native"),
        str(FIXTURE),
        "-o",
        str(executable),
    ]
    source_paths = [HEADER, OWNED_TEXT_HEADER, FIXTURE, RUNNER]
    report: dict[str, Any] = {
        "schema": "information_battle_owned_title_query_test.v1",
        "status": "failed",
        "scope": {
            "game_access": False,
            "remote_process": False,
            "rea": False,
            "rpm": False,
            "native_game_function_invoked": False,
            "production_modified": False,
        },
        "sources": {
            str(path.relative_to(ROOT)).replace("\\", "/"): sha256(path)
            for path in source_paths
        },
        "compile": {"command": compile_command, "returncode": None},
        "run": {"returncode": None},
        "checks": {"passed": 0, "failed": 0, "result_line": None},
    }

    try:
        compiled = subprocess.run(
            compile_command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        report["compile"]["returncode"] = compiled.returncode
        write_text(output / "compile.stdout.txt", compiled.stdout)
        write_text(output / "compile.stderr.txt", compiled.stderr)
        if compiled.returncode == 0:
            executed = subprocess.run(
                [str(executable)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            report["run"]["returncode"] = executed.returncode
            write_text(output / "run.stdout.txt", executed.stdout)
            write_text(output / "run.stderr.txt", executed.stderr)
            result_line = next(
                (line for line in executed.stdout.splitlines()
                 if line.startswith("RESULT ")),
                None,
            )
            report["checks"]["result_line"] = result_line
            for line in executed.stdout.splitlines():
                if line.startswith("SUMMARY "):
                    for item in line.removeprefix("SUMMARY ").split():
                        key, _, value = item.partition("=")
                        if key in {"passed", "failed"} and value.isdigit():
                            report["checks"][key] = int(value)
            report["status"] = (
                "passed"
                if executed.returncode == 0 and result_line == "RESULT PASS"
                else "failed"
            )
        else:
            write_text(output / "run.stdout.txt", "")
            write_text(output / "run.stderr.txt", "compile failed; run skipped\n")
    except (OSError, subprocess.TimeoutExpired) as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}

    report["source_sha256_after"] = {
        str(path.relative_to(ROOT)).replace("\\", "/"): sha256(path)
        for path in source_paths
    }
    write_text(output / "report.json", json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
