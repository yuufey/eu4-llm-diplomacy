"""Batch 69 freeze, full-suite, comparison, and source verification.

The phases are deliberately separate.  ``freeze`` and ``full`` each write
exclusive receipts, snapshots, logs, XML, and execution boundaries.  This
runner has no import-time game, MCP, or native activity.  Military resource sources
may be supplied repeatedly with ``--extra-source``; every fixed or explicitly
supplied path is required at freeze time.
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
# Direct execution as ``python -B work/verify_information_military_resources.py``
# must also be able to import the comparison helper as a package module.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = (
    ROOT / "work/runtime/information-country-forces-20261027-001"
).resolve()
STAGE = (
    ROOT / "work/runtime/information-country-force-resources-20261027-001"
).resolve()
BASELINE_FREEZE = BASELINE / "source-freeze-001.json"
BASELINE_FULL = BASELINE / "regression-full-001.xml"
BASELINE_COMPARISON = BASELINE / "regression-comparison-001.json"
CHUNK_BYTES = 1024 * 1024

ADDITIONAL_SOURCES = (
    "bridge/information/military_resources.py",
    "bridge/information/military_resources_memory.py",
    "bridge/information/profiles/military-resources-memory-1374.json",
    "bridge/tests/test_information_military_resources.py",
    "bridge/tests/test_information_military_resources_memory.py",
)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relative_path(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def normalize_source(raw: str) -> str:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    try:
        return candidate.relative_to(ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"source_outside_root:{raw}") from exc


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
    return {
        "path": relative_path(path),
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _baseline_sources(extra_sources: list[str]) -> tuple[dict, list[str]]:
    baseline = read_json(BASELINE_FREEZE)
    items = baseline.get("files")
    if (
        baseline.get("status") != "passed"
        or baseline.get("batch") != 68
        or not isinstance(items, list)
    ):
        raise ValueError("invalid_batch68_source_freeze")
    if baseline.get("count") != 171 or len(items) != 171:
        raise ValueError(
            f"batch68_source_count_changed:{baseline.get('count')}:{len(items)}"
        )

    paths: list[str] = []
    seen: set[str] = set()
    for item in items:
        source = item.get("source")
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise ValueError("invalid_batch68_source_entry")
        name = normalize_source(source["path"])
        if name in seen:
            raise ValueError(f"duplicate_batch68_source:{name}")
        seen.add(name)
        paths.append(name)

    optional_names = [*ADDITIONAL_SOURCES, *extra_sources]
    for raw_name in optional_names:
        name = normalize_source(raw_name)
        if name in seen:
            continue
        if not (ROOT / name).is_file():
            raise FileNotFoundError(ROOT / name)
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
    if (
        frozen.get("status") != "passed"
        or frozen.get("batch") != 69
        or not isinstance(files, list)
    ):
        raise ValueError("invalid_batch69_source_freeze")
    if frozen.get("count") != len(files):
        raise ValueError("batch69_source_count_mismatch")

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


def freeze(revision: str, extra_sources: list[str]) -> int:
    output = STAGE / f"source-freeze-{revision}.json"
    if output.exists():
        raise FileExistsError(output)
    baseline, paths = _baseline_sources(extra_sources)
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
        "schema": "information.military_resources.source_freeze.v1",
        "status": "passed",
        "batch": 69,
        "count": len(files),
        "baseline": {
            "freeze": pin(BASELINE_FREEZE),
            "full": pin(BASELINE_FULL),
            "source_count": baseline["count"],
            "batch": baseline["batch"],
        },
        "additional_sources": list(ADDITIONAL_SOURCES),
        "extra_sources_requested": list(extra_sources),
        "deduplicated": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "files": files,
    }
    write_new(output, value)
    print(
        json.dumps(
            {
                "status": "passed",
                "phase": "freeze",
                "count": len(files),
            },
            ensure_ascii=False,
        )
    )
    return 0


def verify(revision: str) -> int:
    frozen, count = _verify_frozen(revision)
    output = STAGE / f"source-post-run-verification-{revision}.json"
    if output.exists():
        raise FileExistsError(output)
    value = {
        "schema": "information.military_resources.source_post_run_verification.v1",
        "status": "passed",
        "batch": 69,
        "count": count,
        "freeze": pin(STAGE / f"source-freeze-{revision}.json"),
        "current_matches_snapshots": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "timing": "after batch69 full and acceptance processes have exited",
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
    if not BASELINE_COMPARISON.is_file():
        raise FileNotFoundError("batch68 baseline comparison is required")
    if output.exists():
        raise FileExistsError(output)

    baseline_comparison = read_json(BASELINE_COMPARISON)
    baseline_no_new_bad = baseline_comparison.get("no_new_bad")
    if not isinstance(baseline_no_new_bad, bool):
        raise ValueError("invalid_batch68_baseline_no_new_bad")

    # ROOT is inserted into sys.path above so this works when invoked by path,
    # not only when imported from a package-aware test runner.
    from work.compare_information_battle_native_title_regression import (
        compare as compare_xml,
    )

    value = compare_xml(BASELINE_FULL, current)
    value["schema"] = "information.military_resources.regression_comparison.v1"
    value["batch"] = 69
    value["baseline_batch"] = 68
    value["baseline_full_path"] = relative_path(BASELINE_FULL)
    value["baseline_comparison_path"] = relative_path(BASELINE_COMPARISON)
    value["baseline_no_new_bad"] = baseline_no_new_bad
    value["no_new_bad"] = (
        baseline_no_new_bad
        and not value["new_failure_nodes"]
        and not value["new_test_failures"]
    )
    if not baseline_no_new_bad:
        value["status"] = "baseline_has_new_bad"
    write_new(output, value)
    print(
        json.dumps(
            {
                "status": value["status"],
                "phase": "compare",
                "baseline_no_new_bad": baseline_no_new_bad,
                "new_failure_nodes": len(value["new_failure_nodes"]),
                "new_test_failures": len(value["new_test_failures"]),
            }
        )
    )
    return 0 if value["no_new_bad"] else 2


def full(revision: str) -> int:
    # Verify every current source and snapshot before starting the one allowed
    # full execution.  This also refuses a full run without a freeze receipt.
    _verify_frozen(revision)
    xml = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    receipt = STAGE / f"full-execution-boundary-{revision}.json"
    if any(path.exists() for path in (xml, log, receipt)):
        raise FileExistsError("refusing repeated full execution")
    command = [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "-q",
        "bridge/tests",
        "--junitxml",
        str(xml),
    ]
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    STAGE.mkdir(parents=True, exist_ok=True)
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    write_new(
        receipt,
        {
            "schema": "information.military_resources.full_execution_boundary.v1",
            "batch": 69,
            "command": command,
            "started_at": started_at,
            "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "returncode": result.returncode,
            "runs": 1,
            "xml": pin(xml) if xml.exists() else None,
            "log": pin(log),
        },
    )
    print(json.dumps({"phase": "full", "returncode": result.returncode, "runs": 1}))
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("freeze", "full", "compare", "verify"))
    parser.add_argument(
        "--revision",
        type=int,
        choices=(1, 2, 3, 4),
        default=1,
        help="revision2 corrects the full001 fixture; revision3 amends metadata; revision4 corrects inline modifier layout",
    )
    parser.add_argument(
        "--extra-source",
        action="append",
        default=[],
        metavar="PATH",
        help="repeatable required source path; missing paths fail freeze",
    )
    args = parser.parse_args()
    revision = f"{args.revision:03d}"
    if args.revision == 3 and args.phase in ("full", "compare"):
        raise ValueError("revision3_is_metadata_only_use_qualified_full002_and_source_equivalence")
    extra_sources = [normalize_source(path) for path in args.extra_source]
    if args.phase == "freeze":
        return freeze(revision, extra_sources)
    if args.phase == "full":
        return full(revision)
    if args.phase == "compare":
        return compare(revision)
    return verify(revision)


if __name__ == "__main__":
    raise SystemExit(main())
