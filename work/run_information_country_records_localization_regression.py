"""Run the batch53 full bridge-suite regression into XML and a log.

Importing this module is inert.  Execution is reserved for the root worker
after live acceptance and pin-before are ready; this script starts no game,
MCP server, RPM probe, REA query, or business action by itself.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-country-records-localization-20261027-001"
XML = STAGE / "regression-full-002.xml"
LOG = STAGE / "regression-full-002.log"


def main() -> int:
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")
    if XML.exists() or LOG.exists():
        raise AssertionError("batch53 regression receipts already exist")
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    raise SystemExit(main())
