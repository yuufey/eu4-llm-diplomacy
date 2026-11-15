"""Run batch63 once, or compare its retained XML with batch62 offline."""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work/runtime/information-battle-capture-management-20261027-001"


def put(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("run", "compare"))
    parser.add_argument("--revision", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    revision = f"{args.revision:03d}"
    xml = STAGE / f"regression-full-{revision}.xml"
    if args.phase == "compare":
        from work.compare_information_battle_native_title_regression import compare
        value = compare(ROOT / "work/runtime/information-battle-native-title-20261027-001/regression-full-002.xml", xml)
        value["schema"] = "information.battle.capture_management.regression_comparison.v1"
        put(STAGE / f"regression-comparison-{revision}.json", value)
        print(json.dumps({key: value[key] for key in ("status", "summary_line", "new_failure_nodes", "resolved_failure_nodes", "new_test_failures")}))
        return 0 if value["status"] == "passed_no_new_failure_nodes" else 2
    if xml.exists():
        raise RuntimeError("refusing_to_repeat_full_run")
    command = [sys.executable, "-B", "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with (STAGE / f"regression-full-{revision}.log").open("x", encoding="utf-8", newline="\n") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    put(STAGE / f"full-execution-boundary-{revision}.json", {
        "command": command, "started_at": started,
        "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "returncode": result.returncode, "test_runs": 1,
    })
    print("full regression exit", result.returncode)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
