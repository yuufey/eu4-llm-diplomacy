"""Batch 66 freeze, full-suite, comparison, and source verification.

The phase commands are deliberately separate.  ``freeze`` and ``full`` each
write new receipts with exclusive creation, so a later invocation cannot
silently replace a source snapshot, JUnit XML, log, or execution boundary.
This module does not start anything at import time; the game and MCP are not
used by any phase here.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
# Keep the requested absolute stage boundary explicit.  ROOT is used only for
# locating source paths and for stable relative pins in the receipts.
BASELINE = Path(
    r"C:/Users/wangyufei/Documents/ChatGPT/欧陆风云4/"
    r"work/runtime/information-war-discovery-20261027-001"
).resolve()
STAGE = Path(
    r"C:/Users/wangyufei/Documents/ChatGPT/欧陆风云4/"
    r"work/runtime/information-war-score-20261027-001"
).resolve()
BASELINE_FREEZE = BASELINE / "source-freeze-001.json"
BASELINE_FULL = BASELINE / "regression-full-001.xml"
CHUNK_BYTES = 1024 * 1024

ADDITIONAL_SOURCES = (
    "bridge/war_score.py",
    "bridge/tests/test_war_score.py",
    "bridge/tests/test_information_war_score.py",
    "bridge/tests/fixtures/r74_live_war_score_real.json",
    "work/runtime/r74-live-war-queries-20261020-003/cases/selected_forward/public.json",
)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relative_path(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def pin(path: Path) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return {"path": relative_path(path), "bytes": size, "sha256": digest.hexdigest()}


def write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _baseline_sources() -> tuple[dict, list[str]]:
    baseline = read_json(BASELINE_FREEZE)
    items = baseline.get("files")
    if baseline.get("status") != "passed" or not isinstance(items, list):
        raise ValueError("invalid_batch65_source_freeze")
    if baseline.get("count") != 154 or len(items) != 154:
        raise ValueError(f"batch65_source_count_changed:{baseline.get('count')}:{len(items)}")

    paths: list[str] = []
    seen: set[str] = set()
    for item in items:
        source = item.get("source")
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise ValueError("invalid_batch65_source_entry")
        name = source["path"]
        if name in seen:
            raise ValueError(f"duplicate_batch65_source:{name}")
        seen.add(name)
        paths.append(name)
    for name in ADDITIONAL_SOURCES:
        if name not in seen:
            seen.add(name)
            paths.append(name)
    return baseline, paths


def _copy_stream(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, target.open("xb") as dst:
        while True:
            chunk = src.read(CHUNK_BYTES)
            if not chunk:
                break
            dst.write(chunk)


def _verify_frozen(revision: str) -> tuple[dict, int]:
    freeze_path = STAGE / f"source-freeze-{revision}.json"
    frozen = read_json(freeze_path)
    files = frozen.get("files")
    if frozen.get("status") != "passed" or not isinstance(files, list):
        raise ValueError("invalid_batch66_source_freeze")
    mismatches: list[str] = []
    for item in files:
        source = item["source"]
        snapshot = item["snapshot"]
        if pin(ROOT / source["path"]) != source:
            mismatches.append(source["path"] + ":source")
        if pin(ROOT / snapshot["path"]) != snapshot:
            mismatches.append(snapshot["path"] + ":snapshot")
    if mismatches:
        raise ValueError("frozen_source_changed:" + ",".join(mismatches))
    return frozen, len(files)


def freeze(revision: str) -> int:
    output = STAGE / f"source-freeze-{revision}.json"
    if output.exists():
        raise FileExistsError(output)
    baseline, paths = _baseline_sources()
    files = []
    for name in paths:
        source = ROOT / name
        if not source.is_file():
            raise FileNotFoundError(source)
        before = pin(source)
        snapshot = STAGE / f"source-snapshots-{revision}" / name
        _copy_stream(source, snapshot)
        copied = pin(snapshot)
        if any(copied[key] != before[key] for key in ("bytes", "sha256")):
            raise ValueError("snapshot_hash_mismatch:" + name)
        if pin(source) != before:
            raise ValueError("source_changed_during_freeze:" + name)
        files.append({"source": before, "snapshot": copied})

    value = {
        "schema": "information.war_score.source_freeze.v1",
        "status": "passed",
        "batch": 66,
        "count": len(files),
        "baseline": {
            "freeze": pin(BASELINE_FREEZE),
            "full": pin(BASELINE_FULL),
            "source_count": baseline["count"],
        },
        "additional_sources": list(ADDITIONAL_SOURCES),
        "deduplicated": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "files": files,
    }
    write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "freeze", "count": len(files)}))
    return 0


def verify(revision: str) -> int:
    frozen, count = _verify_frozen(revision)
    output = STAGE / f"source-post-run-verification-{revision}.json"
    if output.exists():
        raise FileExistsError(output)
    value = {
        "schema": "information.war_score.source_post_run_verification.v1",
        "status": "passed",
        "batch": 66,
        "count": count,
        "freeze": pin(STAGE / f"source-freeze-{revision}.json"),
        "current_matches_snapshots": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "timing": "after batch66 full and acceptance processes have exited",
        "source_freeze_status": frozen["status"],
    }
    write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "verify", "count": count}))
    return 0


def compare(revision: str) -> int:
    current = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    output = STAGE / f"regression-comparison-{revision}.json"
    if not BASELINE_FULL.is_file() or not current.is_file() or not log.is_file():
        raise FileNotFoundError("baseline/current XML and log are required")
    if output.exists():
        raise FileExistsError(output)
    from work.compare_information_battle_native_title_regression import compare as compare_xml

    value = compare_xml(BASELINE_FULL, current)
    value["schema"] = "information.war_score.regression_comparison.v1"
    value["batch"] = 66
    value["baseline_batch"] = 65
    value["baseline_full_path"] = relative_path(BASELINE_FULL)
    value["no_new_bad"] = not value["new_failure_nodes"] and not value["new_test_failures"]
    write_new(output, value)
    print(json.dumps({
        "status": value["status"],
        "phase": "compare",
        "new_failure_nodes": len(value["new_failure_nodes"]),
        "new_test_failures": len(value["new_test_failures"]),
    }))
    return 0 if value["no_new_bad"] else 2


def full(revision: str) -> int:
    _verify_frozen(revision)
    xml = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    receipt = STAGE / f"full-execution-boundary-{revision}.json"
    if any(path.exists() for path in (xml, log, receipt)):
        raise FileExistsError("refusing repeated full execution")
    command = [sys.executable, "-B", "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)]
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    STAGE.mkdir(parents=True, exist_ok=True)
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    write_new(receipt, {
        "schema": "information.war_score.full_execution_boundary.v1",
        "batch": 66,
        "command": command,
        "started_at": started_at,
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "returncode": result.returncode,
        "runs": 1,
        "xml": pin(xml) if xml.exists() else None,
        "log": pin(log),
    })
    print(json.dumps({"phase": "full", "returncode": result.returncode, "runs": 1}))
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("freeze", "full", "compare", "verify"))
    parser.add_argument("--revision", type=int, choices=(1,), default=1,
                        help="exclusive receipt revision; batch66 permits one full run")
    args = parser.parse_args()
    revision = f"{args.revision:03d}"
    if args.phase == "freeze":
        return freeze(revision)
    if args.phase == "full":
        return full(revision)
    if args.phase == "compare":
        return compare(revision)
    return verify(revision)


if __name__ == "__main__":
    raise SystemExit(main())
