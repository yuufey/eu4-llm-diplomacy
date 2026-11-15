"""Freeze and independently verify the information battle capture sources.

This script has two explicit, offline phases:

``freeze``
    Read the 147 runtime source paths frozen before batch 62 full002, add the
    capture manager module and the three capture integration tests, then copy
    each source to a new, path-preserving snapshot directory.  The existing
    source files and all existing stage artifacts are read-only inputs.

``verify``
    Re-hash the source files and their exact snapshots and write a separate
    verification receipt.  It never runs pytest, starts the game, or invokes
    MCP/REA.

The batch-62 pins are retained as provenance.  A current source can differ
from its batch-62 pin because the capture-management production integration
was added after that freeze; the current source and snapshot are the values
verified by this batch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BATCH62_PINS = ROOT / "work/runtime/information-battle-native-title-20261027-001/runtime-source-pins-before-002.json"
STAGE = ROOT / "work/runtime/information-battle-capture-management-20261027-001"
CHUNK_SIZE = 1024 * 1024

EXTRA_RUNTIME = (
    "bridge/information/battle_capture.py",
)
EXTRA_TESTS = (
    "bridge/tests/test_information_battle_capture.py",
    "bridge/tests/test_information_battle_capture_service.py",
    "bridge/tests/test_information_capture_runtime.py",
)
EXTRAS = EXTRA_RUNTIME + EXTRA_TESTS
REQUIRED_BATCH62_PATHS = (
    "bridge/information/battles.py",
    "bridge/information/service.py",
    "bridge/information/tools.py",
    "bridge/tests/test_control_information_battle_observer.py",
    "tools/control_information_battle_observer.py",
    "tools/serve_information.py",
)


def _revision_paths(revision: int) -> tuple[Path, Path, Path]:
    if revision not in (1, 2):
        raise ValueError(f"unsupported_revision:{revision}")
    suffix = "" if revision == 1 else "-002"
    receipt_suffix = f"{revision:03d}"
    return (
        STAGE / f"source-snapshots{suffix}",
        STAGE / f"source-freeze-{receipt_suffix}.json",
        STAGE / f"source-freeze-verify-{receipt_suffix}.json",
    )


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def _resolve_workspace_path(relative_path: str) -> Path:
    candidate = (ROOT / relative_path).resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path_outside_workspace:{relative_path}") from exc
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(CHUNK_SIZE)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _pin(path: Path) -> dict[str, Any]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    return {
        "path": _relative(path),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def _load_json(path: Path, *, max_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"json_too_large:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{path}")
    return value


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(encoded)


def _batch62_paths() -> tuple[list[str], dict[str, dict[str, Any]], dict[str, Any]]:
    document = _load_json(BATCH62_PINS)
    rows = document.get("files")
    if not isinstance(rows, list):
        raise ValueError("batch62_files_missing")
    baseline: dict[str, dict[str, Any]] = {}
    ordered: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("batch62_invalid_file_pin")
        relative = row["path"]
        if relative in baseline:
            raise ValueError(f"batch62_duplicate_path:{relative}")
        _resolve_workspace_path(relative)
        baseline[relative] = {
            "path": relative,
            "bytes": row.get("bytes"),
            "sha256": row.get("sha256"),
        }
        ordered.append(relative)
    if len(ordered) != 147 or len(set(ordered)) != 147:
        raise ValueError(f"batch62_expected_147:{len(ordered)}")
    missing_required = sorted(set(REQUIRED_BATCH62_PATHS) - set(ordered))
    if missing_required:
        raise ValueError("batch62_required_paths_missing:" + ",".join(missing_required))
    return ordered, baseline, document


def _current_paths() -> tuple[list[str], dict[str, dict[str, Any]], dict[str, Any]]:
    batch62, baseline, document = _batch62_paths()
    paths = list(batch62)
    for relative in EXTRAS:
        _resolve_workspace_path(relative)
        if relative not in paths:
            paths.append(relative)
    if len(paths) != 151 or len(set(paths)) != 151:
        raise ValueError(f"expected_151_unique_paths:{len(paths)}")
    return paths, baseline, document


def _copy_snapshot(source: Path, target: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    before = _pin(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(f"refusing_to_overwrite_snapshot:{target}")
    with source.open("rb") as input_stream, target.open("xb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, length=CHUNK_SIZE)
    after = _pin(source)
    if after != before:
        raise ValueError(f"source_changed_during_copy:{before['path']}")
    copied = _pin(target)
    if copied["bytes"] != before["bytes"] or copied["sha256"] != before["sha256"]:
        raise ValueError(f"snapshot_mismatch:{before['path']}")
    return before, copied


def freeze(revision: int = 1) -> dict[str, Any]:
    snapshot_root, freeze_receipt, _verify_receipt = _revision_paths(revision)
    if freeze_receipt.exists():
        raise FileExistsError(freeze_receipt)
    paths, baseline, batch62_document = _current_paths()
    # The stage already contains preflight/ingest artifacts.  Do not recreate
    # it, and do not use an exclusive mkdir for the stage itself.
    STAGE.mkdir(parents=True, exist_ok=True)
    if snapshot_root.exists() and any(snapshot_root.iterdir()):
        raise FileExistsError(f"snapshot_directory_not_empty:{snapshot_root}")
    snapshot_root.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    for relative in paths:
        source = _resolve_workspace_path(relative)
        target = snapshot_root / Path(relative)
        source_pin, snapshot_pin = _copy_snapshot(source, target)
        entry: dict[str, Any] = {
            "source": source_pin,
            "snapshot": snapshot_pin,
            "origin": "batch62_runtime" if relative in baseline else "capture_management_addition",
        }
        if relative in baseline:
            entry["batch62_pin"] = baseline[relative]
        entries.append(entry)

    source_paths = [entry["source"]["path"] for entry in entries]
    snapshot_paths = [entry["snapshot"]["path"] for entry in entries]
    if len(source_paths) != len(set(source_paths)) or len(snapshot_paths) != len(set(snapshot_paths)):
        raise ValueError("freeze_paths_not_unique")
    manifest = {
        "schema": "information.battle.capture_management.source_freeze.v1",
        "batch": 63,
        "revision": revision,
        "status": "passed",
        "timing": "before capture-management full regression; production sources stable",
        "count": len(entries),
        "batch62_runtime_count": len(baseline),
        "new_runtime_count": len(EXTRA_RUNTIME),
        "new_test_count": len(EXTRA_TESTS),
        "new_paths": list(EXTRAS),
        "batch62_pins": _pin(BATCH62_PINS),
        "batch62_pin_revision": batch62_document.get("revision"),
        "files": entries,
        "policy": {
            "source_files_unchanged": True,
            "snapshots_are_exact_copies": True,
            "original_paths_overwritten": False,
            "game_mcp_rea_access": False,
            "pytest_invoked": False,
        },
    }
    _write_new_json(freeze_receipt, manifest)
    return {
        "status": "passed",
        "manifest": _relative(freeze_receipt),
        "source_snapshots": _relative(snapshot_root),
        "revision": revision,
        "count": len(entries),
        "batch62_runtime_count": len(baseline),
        "new_runtime_count": len(EXTRA_RUNTIME),
        "new_test_count": len(EXTRA_TESTS),
    }


def _verify_entry(entry: dict[str, Any]) -> dict[str, Any]:
    source_pin = entry.get("source")
    snapshot_pin = entry.get("snapshot")
    if not isinstance(source_pin, dict) or not isinstance(snapshot_pin, dict):
        raise ValueError("invalid_freeze_entry")
    source = _resolve_workspace_path(source_pin["path"])
    snapshot = _resolve_workspace_path(snapshot_pin["path"])
    if source.resolve() == snapshot.resolve():
        raise ValueError(f"snapshot_aliases_source:{source_pin['path']}")
    current_source = _pin(source)
    current_snapshot = _pin(snapshot)
    if current_source != source_pin:
        raise ValueError(f"source_changed_since_freeze:{source_pin['path']}")
    if current_snapshot != snapshot_pin:
        raise ValueError(f"snapshot_changed_since_freeze:{snapshot_pin['path']}")
    if current_source["bytes"] != current_snapshot["bytes"] or current_source["sha256"] != current_snapshot["sha256"]:
        raise ValueError(f"source_snapshot_content_mismatch:{source_pin['path']}")
    return {
        "path": source_pin["path"],
        "source": current_source,
        "snapshot": current_snapshot,
        "origin": entry.get("origin"),
    }


def verify(revision: int = 1) -> dict[str, Any]:
    snapshot_root, freeze_receipt, verify_receipt = _revision_paths(revision)
    if not freeze_receipt.exists():
        raise FileNotFoundError(freeze_receipt)
    if verify_receipt.exists():
        raise FileExistsError(verify_receipt)
    manifest = _load_json(freeze_receipt)
    if manifest.get("schema") != "information.battle.capture_management.source_freeze.v1":
        raise ValueError("unexpected_freeze_schema")
    entries = manifest.get("files")
    if not isinstance(entries, list) or manifest.get("count") != len(entries):
        raise ValueError("freeze_count_mismatch")
    checked = [_verify_entry(entry) for entry in entries]
    expected_snapshots = {item["snapshot"]["path"] for item in checked}
    actual_snapshots = {
        _relative(path)
        for path in snapshot_root.rglob("*")
        if path.is_file()
    }
    if actual_snapshots != expected_snapshots:
        raise ValueError("snapshot_directory_contents_mismatch")
    if len({item["path"] for item in checked}) != len(checked):
        raise ValueError("verified_source_paths_not_unique")

    receipt = {
        "schema": "information.battle.capture_management.source_freeze_verify.v1",
        "batch": 63,
        "revision": revision,
        "status": "passed",
        "freeze_manifest": _pin(freeze_receipt),
        "source_snapshots": _relative(snapshot_root),
        "count": len(checked),
        "files": checked,
        "checks": {
            "source_sha256_and_size_unchanged": True,
            "snapshot_sha256_and_size_unchanged": True,
            "source_snapshot_bytes_equal": True,
            "source_snapshot_hashes_equal": True,
            "snapshot_directory_exact": True,
            "unique_original_paths": True,
            "pytest_invoked": False,
            "game_mcp_rea_access": False,
        },
    }
    _write_new_json(verify_receipt, receipt)
    return {
        "status": "passed",
        "manifest": _relative(freeze_receipt),
        "verification": _relative(verify_receipt),
        "revision": revision,
        "count": len(checked),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", nargs="?", choices=("freeze", "verify"))
    parser.add_argument("--revision", type=int, choices=(1, 2), default=1)
    args = parser.parse_args(argv)
    if args.phase is None:
        print(json.dumps({"status": "inert"}))
        return 0
    result = freeze(args.revision) if args.phase == "freeze" else verify(args.revision)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
