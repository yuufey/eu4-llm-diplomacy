"""Batch64 source freeze and one formal full-suite execution."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work/runtime/information-battle-autonomous-live-20261027-001"
PREVIOUS = ROOT / "work/runtime/information-battle-capture-management-20261027-001"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": path.resolve().relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": digest}


def put(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def verify_sources(revision="001"):
    frozen = read(STAGE / f"source-freeze-{revision}.json")
    for item in frozen["files"]:
        if pin(ROOT / item["source"]["path"]) != item["source"] or pin(ROOT / item["snapshot"]["path"]) != item["snapshot"]:
            raise ValueError("frozen_source_changed:" + item["source"]["path"])
    return frozen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("freeze", "full", "compare", "verify"))
    parser.add_argument("--revision", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    revision = f"{args.revision:03d}"
    if args.phase == "freeze":
        before = read(PREVIOUS / "source-freeze-002.json")
        if (STAGE / f"source-freeze-{revision}.json").exists():
            raise FileExistsError("source freeze already exists")
        files = []
        paths = list(before["files"])
        if args.revision == 2:
            paths.append({"source": {"path": "bridge/tests/test_information_peace_overextension_mapping.py"}})
        for old in paths:
            source = ROOT / old["source"]["path"]
            target = STAGE / ("source-snapshots" if args.revision == 1 else "source-snapshots-002") / old["source"]["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            current = pin(source)
            with source.open("rb") as src, target.open("xb") as dst:
                while chunk := src.read(1024 * 1024):
                    dst.write(chunk)
            snapshot = pin(target)
            if any(snapshot[key] != current[key] for key in ("bytes", "sha256")) or pin(source) != current:
                raise ValueError("source_changed_during_freeze")
            files.append({"source": current, "snapshot": snapshot})
        put(STAGE / f"source-freeze-{revision}.json", {"status": "passed", "batch": 64, "count": len(files),
            "timing": f"before formal full{revision} and its live acceptance",
            "baseline": pin(PREVIOUS / "source-freeze-002.json"), "files": files})
        print(json.dumps({"status": "passed", "count": len(files)}))
        return 0
    if args.phase == "verify":
        frozen = verify_sources(revision)
        put(STAGE / f"source-post-run-verification-{revision}.json", {"status": "passed", "count": frozen["count"],
            "freeze": pin(STAGE / f"source-freeze-{revision}.json"), "timing": "after full and live server exit"})
        print(json.dumps({"status": "passed", "count": frozen["count"]}))
        return 0
    if args.phase == "compare":
        from work.compare_information_battle_native_title_regression import compare
        value = compare(PREVIOUS / "regression-full-002.xml", STAGE / f"regression-full-{revision}.xml")
        value["schema"] = "information.battle.autonomous.regression_comparison.v1"
        put(STAGE / f"regression-comparison-{revision}.json", value)
        print(json.dumps({key: value[key] for key in ("status", "summary_line", "new_failure_nodes", "new_test_failures")}))
        return 0 if not value["new_failure_nodes"] and not value["new_test_failures"] else 2
    verify_sources(revision)
    xml = STAGE / f"regression-full-{revision}.xml"
    if xml.exists():
        raise FileExistsError("refusing repeated full execution")
    command = [sys.executable, "-B", "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)]
    start = dt.datetime.now(dt.timezone.utc).isoformat()
    with (STAGE / f"regression-full-{revision}.log").open("x", encoding="utf-8", newline="\n") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    put(STAGE / f"full-execution-boundary-{revision}.json", {"command": command, "started_at": start,
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "runs": 1})
    print("full regression exit", result.returncode)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
