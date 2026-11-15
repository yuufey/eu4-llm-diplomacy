"""Freeze the selected sources and compare one full regression with batch72."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-body-source-20261028-001"
BASE = ROOT / "work/runtime/information-battle-gate-trace-20261028-001"
REVISION = "001"
EXTRA = (
    "bridge/information/battle_definition_memory.py",
    "bridge/information/profiles/battle-definition-memory-1374.json",
    "bridge/tests/test_information_battle_definition_memory.py",
    "work/probe_information_battle_body_templates.py",
    "work/research_information_battle_definition_source.py",
    "work/verify_information_battle_body_source.py",
    "work/candidates/information-battle-format-input-1374/format_input_builder.h",
    "work/candidates/information-battle-format-input-1374/format_expansion_plan.h",
    "work/candidates/information-battle-format-input-1374/format_expansion_plan_test.cpp",
    "work/candidates/information-battle-format-input-1374/format_expansion_plan_runner.py",
    "work/candidates/information-battle-format-input-1374/README.md",
)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def pin(path):
    path = path.resolve()
    rel = path.relative_to(ROOT).as_posix()
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            digest.update(chunk)
    return {"path": rel, "bytes": total, "sha256": digest.hexdigest()}


def write_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def freeze():
    previous = STAGE / f"source-freeze-{int(REVISION)-1:03d}.json"
    baseline_path = previous if previous.is_file() else BASE / "source-freeze-001.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    old = {item["source"]["path"]: item["source"] for item in baseline["files"]}
    paths = sorted(set(old) | set(EXTRA))
    destination = STAGE / f"source-snapshots-{REVISION}"
    destination.mkdir(exist_ok=False)
    files, changes = [], []
    for rel in paths:
        source = ROOT / rel
        before = pin(source)
        target = destination / rel
        target.resolve().relative_to(destination.resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as incoming, target.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
        snapshot = pin(target)
        if pin(source) != before or (snapshot["bytes"], snapshot["sha256"]) != (before["bytes"], before["sha256"]):
            raise ValueError("source_changed_during_freeze:" + rel)
        files.append({"source": before, "snapshot": snapshot})
        if rel in old and before != old[rel]:
            changes.append({"before": old[rel], "after": before})
    write_new(STAGE / f"source-freeze-{REVISION}.json", {
        "schema": "information.battle.body_source_freeze.v1", "status": "passed",
        "created_at_utc": stamp(), "count": len(files), "files": files,
        "baseline": pin(baseline_path), "revision": REVISION,
        "existing_source_changes": changes, "hash_chunk_bytes": 1024 * 1024,
    })
    print(json.dumps({"status": "passed", "frozen_sources": len(files), "changed_existing": len(changes)}))


def verify():
    frozen = json.loads((STAGE / f"source-freeze-{REVISION}.json").read_text(encoding="utf-8"))
    checked = []
    for item in frozen["files"]:
        if pin(ROOT / item["source"]["path"]) != item["source"] or pin(ROOT / item["snapshot"]["path"]) != item["snapshot"]:
            raise ValueError("frozen_source_changed:" + item["source"]["path"])
        checked.append(item["source"]["path"])
    return {"status": "passed", "count": len(checked), "checked_at_utc": stamp(),
            "freeze": pin(STAGE / f"source-freeze-{REVISION}.json")}


def bad_cases(path):
    root = ET.parse(path).getroot()
    return Counter((case.get("classname", ""), case.get("name", ""), child.tag)
                   for case in root.iter("testcase") for child in case
                   if child.tag in ("failure", "error"))


def full():
    verify()
    xml, log = STAGE / f"regression-full-{REVISION}.xml", STAGE / f"regression-full-{REVISION}.log"
    command = [sys.executable, "-B", "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)]
    reservation = STAGE / f"full-execution-reservation-{REVISION}.json"
    write_new(reservation, {"started_at_utc": stamp(), "command": command,
                            "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"), "runs": 1,
                            "revision": REVISION})
    if xml.exists():
        raise FileExistsError(xml)
    with log.open("xb") as stream:
        completed = subprocess.run(command, cwd=ROOT, stdout=stream,
                                   stderr=subprocess.STDOUT, check=False)
    write_new(STAGE / f"full-execution-boundary-{REVISION}.json", {
        "status": "completed", "runs": 1, "finished_at_utc": stamp(),
        "command": command, "returncode": completed.returncode,
        "reservation": pin(reservation), "xml": pin(xml), "log": pin(log)})
    old, current = bad_cases(BASE / "regression-full-001.xml"), bad_cases(xml)
    new = current - old
    with log.open("rb") as stream:
        stream.seek(max(0, log.stat().st_size - 65536))
        tail = stream.read().decode("utf-8", "replace")
    summaries = [line.strip() for line in tail.splitlines()
                 if re.search(r"\d+ passed", line) and re.search(r"\d+ (failed|errors)", line)]
    comparison = {
        "status": "failed_new_bad" if new else "passed_no_new_bad",
        "baseline": pin(BASE / "regression-full-001.xml"), "current": pin(xml),
        "baseline_bad_occurrences": sum(old.values()), "current_bad_occurrences": sum(current.values()),
        "new_bad": [{"node": list(key), "count": count} for key, count in sorted(new.items())],
        "resolved_bad": [{"node": list(key), "count": count} for key, count in sorted((old-current).items())],
        "summary_line": summaries[-1] if summaries else None,
        "whole_suite_passed": completed.returncode == 0,
    }
    write_new(STAGE / f"regression-comparison-{REVISION}.json", comparison)
    write_new(STAGE / f"source-post-run-verification-{REVISION}.json", verify())
    print(json.dumps(comparison))
    return 1 if new else 0


def main():
    global REVISION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("freeze", "full"))
    parser.add_argument("--revision", default="001")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9]{3}", args.revision) is None or int(args.revision) == 0:
        parser.error("revision must be 001..999")
    REVISION = args.revision
    STAGE.mkdir(exist_ok=True)
    if args.operation == "freeze":
        freeze()
        return 0
    return full()


if __name__ == "__main__":
    raise SystemExit(main())
