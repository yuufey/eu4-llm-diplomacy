"""Run the batch49 full bridge suite into exclusive regression receipts.

The command is intentionally inert on import.  The root agent runs it only
after the live acceptance and source-pin steps are ready; this file itself
does not open a game session or invoke MCP.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"
XML = STAGE / "regression-full-001.xml"
LOG = STAGE / "regression-full-001.log"


def main() -> int:
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")
    if XML.exists() or LOG.exists():
        raise AssertionError("batch49 regression receipts already exist")
    with LOG.open("x", encoding="utf-8", newline="\n") as log:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(XML)],
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    print(f"full regression exit {result.returncode}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
