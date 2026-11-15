"""Freeze, run and compare batch65's full information regression once."""
from __future__ import annotations
import argparse
import datetime as dt
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.verify_information_battle_autonomous import read, pin, put

STAGE = ROOT / "work/runtime/information-war-discovery-20261027-001"
BASELINE = ROOT / "work/runtime/information-battle-autonomous-live-20261027-001"


def verify(revision):
    frozen = read(STAGE / f"source-freeze-{revision}.json")
    for item in frozen["files"]:
        assert pin(ROOT / item["source"]["path"]) == item["source"], item["source"]["path"]
        assert pin(ROOT / item["snapshot"]["path"]) == item["snapshot"]
    return frozen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("freeze", "full", "compare", "verify"))
    parser.add_argument("--revision", type=int, choices=range(1, 10), default=1)
    args = parser.parse_args()
    revision = f"{args.revision:03d}"
    STAGE.mkdir(exist_ok=True)
    if args.phase == "freeze":
        assert not (STAGE / f"source-freeze-{revision}.json").exists()
        baseline = read(BASELINE / "source-freeze-002.json")
        paths = [item["source"]["path"] for item in baseline["files"]] + [
            "bridge/tests/test_information_war_discovery.py", "bridge/tests/test_information_peace_consequence_mapping.py"]
        files = []
        for name in paths:
            source = ROOT / name
            snapshot = STAGE / f"source-snapshots-{revision}" / name
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            before = pin(source)
            with source.open("rb") as src, snapshot.open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            copied = pin(snapshot)
            assert pin(source) == before
            assert all(copied[key] == before[key] for key in ("bytes", "sha256"))
            files.append({"source": before, "snapshot": copied})
        put(STAGE / f"source-freeze-{revision}.json", {"status": "passed", "batch": 65,
            "count": len(files), "timing": "before formal full suite and live acceptance", "files": files})
        print("frozen", len(files))
        return 0
    if args.phase == "verify":
        frozen = verify(revision)
        put(STAGE / f"source-post-run-verification-{revision}.json", {"status": "passed", "count": frozen["count"],
            "freeze": pin(STAGE / f"source-freeze-{revision}.json"), "timing": "after full and live server exit"})
        print("verified", frozen["count"])
        return 0
    if args.phase == "compare":
        from work.compare_information_battle_native_title_regression import compare
        value = compare(BASELINE / "regression-full-002.xml", STAGE / f"regression-full-{revision}.xml")
        put(STAGE / f"regression-comparison-{revision}.json", value)
        print({key: value[key] for key in ("summary_line", "new_failure_nodes", "new_test_failures")})
        return 0 if not value["new_failure_nodes"] and not value["new_test_failures"] else 2
    verify(revision)
    xml = STAGE / f"regression-full-{revision}.xml"
    assert not xml.exists(), "no full retry in same output"
    command = [sys.executable, "-B", "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)]
    start = dt.datetime.now(dt.timezone.utc).isoformat()
    with (STAGE / f"regression-full-{revision}.log").open("x", encoding="utf-8", newline="\n") as out:
        process = subprocess.run(command, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    put(STAGE / f"full-execution-boundary-{revision}.json", {"command": command, "start": start,
        "finished": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": process.returncode, "runs": 1})
    print("full exit", process.returncode)
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
