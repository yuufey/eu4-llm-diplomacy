"""Run the batch48 full suite once, with exclusive new receipts."""
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-trade-merchant-task-20261027-001"
XML = STAGE / "regression-full-001.xml"
LOG = STAGE / "regression-full-001.log"

assert STAGE.is_dir()
assert not XML.exists()
assert not LOG.exists()
with LOG.open("x", encoding="utf-8", newline="\n") as log:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(XML)],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
print("full regression exit", result.returncode)
raise SystemExit(result.returncode)
