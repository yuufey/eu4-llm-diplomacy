"""Run the one batch52 full bridge-suite regression into XML and a log.

The command is inert on import.  It is executed only after live acceptance
and pin-before are ready; it starts no game, MCP, RPM, or REA work itself.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-country-records-20261027-001"
XML = STAGE / "regression-full-001.xml"
LOG = STAGE / "regression-full-001.log"


def main() -> int:
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")
    if XML.exists() or LOG.exists():
        raise AssertionError("batch52 regression receipts already exist")
    with LOG.open("x", encoding="utf-8", newline="\n") as log:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "bridge/tests",
                "--junitxml",
                str(XML),
            ],
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    print(f"full regression exit {result.returncode}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
