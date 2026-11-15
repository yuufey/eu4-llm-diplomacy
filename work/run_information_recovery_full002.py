#!/usr/bin/env python3
"""Run the one permitted full recovery regression and preserve its raw log."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-recovery-20261025-001"
XML = STAGE / "full-pytest-002.xml"
LOG = STAGE / "full-pytest-002.log"


def main() -> int:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "bridge/tests",
        f"--junitxml={XML.relative_to(ROOT).as_posix()}",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    LOG.write_text(
        "command="
        + repr(command)
        + "\n"
        + completed.stdout
        + completed.stderr
        + f"\nrunner_exit_code={completed.returncode}\n",
        encoding="utf-8",
    )
    print(completed.stdout, end="")
    print(completed.stderr, end="")
    print(f"runner_exit_code={completed.returncode}")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
