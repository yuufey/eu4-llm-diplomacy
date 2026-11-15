"""Run the frozen batch46 full suite once with exclusive output files."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
xml = STAGE / "regression-full-001.xml"
assert not xml.exists()
with (STAGE / "regression-full-001.log").open("x", encoding="utf-8", newline="\n") as log:
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)],
                            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
print("full regression exit", result.returncode)
raise SystemExit(result.returncode)
