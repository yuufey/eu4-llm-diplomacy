"""Prepare a fresh v24 context-observer artifact directory by file copy only.

The source build is already compiled and pinned.  This helper verifies that
build and its 105 source pins, copies exactly those sources plus the v24 DLL to
a new runtime directory, and writes an explicit artifact-reuse manifest.  It
never starts EU4, opens a process, installs a DLL, sends a command, or copies
installation/status/request files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "work" / "runtime"
SOURCE_NAME = "diplomacy-observer-20261025-information-battle-v24-001"
DEST_NAME = "diplomacy-observer-20261025-information-battle-context-live-001"
SOURCE = RUNTIME / SOURCE_NAME
DEST = RUNTIME / DEST_NAME
SOURCE_MANIFEST = SOURCE / "build-manifest.json"
TRUSTED_MANIFEST_SHA = (
    "3989adeb71771b2f8ca362824a2e662b7554947524468d44381214ae55a58bcd"
)
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "c920495a2d61d91fffc7cbbcd026febcf56d29a352dfc07cc803c0be1034aecb"
DLL_NAME = "eu4_bridge_diplomacy_observer_v24.dll"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
STAGE = RUNTIME / "information-battle-context-live-20261025-001"
DEFAULT_COPY_REPORT = STAGE / "prepare-install-001.json"
DEFAULT_VERIFY_REPORT = STAGE / "verify-existing-001.json"
NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,160}\Z")


class PrepareError(RuntimeError):
    """A fail-closed source, copy, or manifest validation error."""


def sha256_file(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PrepareError(f"stat_failed:{path}:{exc}") from exc
    if not path.is_file() or size > MAX_ARTIFACT_BYTES:
        raise PrepareError(f"missing_or_oversize_artifact:{path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise PrepareError(f"read_failed:{path}:{exc}") from exc
    return digest.hexdigest()


def _absolute_runtime_child(path: Path, *, expected_name: str | None = None) -> Path:
    try:
        resolved = path.resolve(strict=False)
        runtime = RUNTIME.resolve()
        if resolved.parent != runtime:
            raise PrepareError("path_must_be_direct_runtime_child")
        if expected_name is not None and resolved.name != expected_name:
            raise PrepareError("unexpected_experiment_directory_name")
        return resolved
    except OSError as exc:
        raise PrepareError(f"path_resolution_failed:{path}:{exc}") from exc


def _load_trusted_manifest() -> dict[str, Any]:
    if sha256_file(SOURCE_MANIFEST) != TRUSTED_MANIFEST_SHA:
        raise PrepareError("trusted_v24_manifest_changed")
    try:
        manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PrepareError(f"trusted_manifest_unreadable:{exc}") from exc
    if not isinstance(manifest, dict):
        raise PrepareError("trusted_manifest_not_object")
    if manifest.get("version") != 24:
        raise PrepareError("trusted_manifest_version_mismatch")
    if manifest.get("game_sha256") != EXE_SHA:
        raise PrepareError("trusted_manifest_exe_sha_mismatch")
    if manifest.get("dll_sha256") != DLL_SHA:
        raise PrepareError("trusted_manifest_dll_sha_mismatch")
    if manifest.get("experiment_id") != SOURCE_NAME:
        raise PrepareError("trusted_manifest_experiment_mismatch")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or len(sources) != 105:
        raise PrepareError("trusted_manifest_source_count_mismatch")
    seen: set[str] = set()
    for item in sources:
        if not isinstance(item, dict):
            raise PrepareError("trusted_manifest_source_entry_not_object")
        name = item.get("name")
        expected_sha = item.get("sha256")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise PrepareError("invalid_source_name")
        if name in seen or name in {"build-manifest.json", DLL_NAME}:
            raise PrepareError("duplicate_or_reserved_source_name")
        if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise PrepareError(f"invalid_source_sha:{name}")
        seen.add(name)
        source_path = SOURCE / name
        if sha256_file(source_path) != expected_sha:
            raise PrepareError(f"trusted_source_changed:{name}")
    if sha256_file(SOURCE / DLL_NAME) != DLL_SHA:
        raise PrepareError("trusted_v24_dll_changed")
    return manifest


def _pin(path: Path, expected_sha: str | None = None) -> dict[str, Any]:
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "expected_sha256": expected_sha,
    }


def _artifact_reuse() -> dict[str, Any]:
    source_manifest_path = str(SOURCE_MANIFEST.resolve())
    source_dll_path = str((SOURCE / DLL_NAME).resolve())
    return {
        "source_manifest": source_manifest_path,
        "source_manifest_path": source_manifest_path,
        "source_manifest_sha256": TRUSTED_MANIFEST_SHA,
        "source_dll": source_dll_path,
        "source_dll_path": source_dll_path,
        "source_dll_sha256": DLL_SHA,
        "verified_source_count": 105,
        "recompiled": False,
        "compiled_in_this_directory": False,
        "reason": "Reuse the trusted compiled v24 artifact; runtime installation remains pending.",
    }


def _new_manifest(original: dict[str, Any], destination: Path) -> dict[str, Any]:
    manifest = dict(original)
    manifest["experiment_id"] = destination.name
    manifest["runtime_verified"] = False
    manifest["dll"] = str((destination / DLL_NAME).resolve())
    manifest["artifact_reuse"] = _artifact_reuse()
    return manifest


def _write_json_once(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise PrepareError(f"refusing_to_overwrite:{path}")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _source_pins(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        _pin(SOURCE / item["name"], item["sha256"])
        for item in manifest["sources"]
    ]


def _verify_destination(destination: Path, original: dict[str, Any]) -> dict[str, Any]:
    destination = _absolute_runtime_child(destination, expected_name=DEST_NAME)
    if not destination.is_dir():
        raise PrepareError("destination_directory_missing")
    expected_names = {item["name"] for item in original["sources"]}
    expected_names.update({DLL_NAME, "build-manifest.json"})
    actual_names = {entry.name for entry in destination.iterdir()}
    extras = sorted(actual_names - expected_names)
    missing = sorted(expected_names - actual_names)
    if extras or missing:
        raise PrepareError(f"destination_file_set_mismatch:extras={extras}:missing={missing}")
    manifest_path = destination / "build-manifest.json"
    try:
        current = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PrepareError(f"destination_manifest_unreadable:{exc}") from exc
    expected_manifest = _new_manifest(original, destination)
    checks = {
        "experiment_id": current.get("experiment_id") == DEST_NAME,
        "version": current.get("version") == 24,
        "game_sha256": current.get("game_sha256") == EXE_SHA,
        "dll_sha256": current.get("dll_sha256") == DLL_SHA,
        "dll_path": Path(current.get("dll", "")).resolve() == (destination / DLL_NAME).resolve(),
        "sources": current.get("sources") == original.get("sources"),
        "runtime_verified_false": current.get("runtime_verified") is False,
        "artifact_reuse": current.get("artifact_reuse") == expected_manifest["artifact_reuse"],
    }
    if not all(checks.values()):
        raise PrepareError("destination_manifest_contract_mismatch")
    source_results: list[dict[str, Any]] = []
    for item in original["sources"]:
        source_results.append(_pin(destination / item["name"], item["sha256"]))
    dll_result = _pin(destination / DLL_NAME, DLL_SHA)
    if any(item["sha256"] != item["expected_sha256"] for item in source_results):
        raise PrepareError("destination_source_hash_mismatch")
    if dll_result["sha256"] != DLL_SHA:
        raise PrepareError("destination_dll_hash_mismatch")
    manifest_sha = sha256_file(manifest_path)
    return {
        "status": "passed",
        "destination": str(destination),
        "manifest": {
            "path": str(manifest_path),
            "sha256": manifest_sha,
            "checks": checks,
        },
        "source_count": len(source_results),
        "source_hashes_match": True,
        "dll": dll_result,
        "source_results": source_results,
        "unexpected_files": [],
        "excluded_from_copy": [
            "installation.json", "status files", "requests", "responses", "raw logs"
        ],
    }


def prepare(destination: Path, report_path: Path) -> dict[str, Any]:
    original = _load_trusted_manifest()
    destination = _absolute_runtime_child(destination, expected_name=DEST_NAME)
    if destination.exists():
        raise PrepareError("destination_already_exists")
    destination.mkdir()
    try:
        for item in original["sources"]:
            shutil.copy2(SOURCE / item["name"], destination / item["name"])
        shutil.copy2(SOURCE / DLL_NAME, destination / DLL_NAME)
        manifest = _new_manifest(original, destination)
        _write_json_once(destination / "build-manifest.json", manifest)
        verification = _verify_destination(destination, original)
    except Exception:
        # Keep any partial directory for explicit forensic inspection; never
        # silently replace or delete an existing experiment.
        raise
    report = {
        "schema": "information_battle_context_live_install_prepare_v1",
        "status": "passed",
        "mode": "offline_file_copy_only",
        "scope": {
            "game_access": False,
            "process_access": False,
            "dll_installed": False,
            "control_command_sent": False,
            "requests_or_status_copied": False,
            "runtime_verified": False,
            "compiled_in_this_directory": False,
        },
        "trusted_source": {
            "directory": str(SOURCE.resolve()),
            "manifest_path": str(SOURCE_MANIFEST.resolve()),
            "manifest_sha256": TRUSTED_MANIFEST_SHA,
            "version": original["version"],
            "game_sha256": EXE_SHA,
            "dll_sha256": DLL_SHA,
            "source_count": len(original["sources"]),
            "source_pins": _source_pins(original),
        },
        "destination": verification,
        "artifact_reuse": _artifact_reuse(),
        "limitations": [
            "This prepares an uninstalled artifact directory; it is not live-accepted.",
            "The copied manifest retains runtime_verified=false and no installation/status/request files are present.",
        ],
    }
    _write_json_once(report_path, report)
    return report


def verify_existing(destination: Path, report_path: Path) -> dict[str, Any]:
    original = _load_trusted_manifest()
    verification = _verify_destination(destination, original)
    report = {
        "schema": "information_battle_context_live_install_verify_v1",
        "status": "passed",
        "mode": "offline_file_verification_only",
        "scope": {
            "game_access": False,
            "process_access": False,
            "dll_installed": False,
            "control_command_sent": False,
            "runtime_verified": False,
        },
        "trusted_source": {
            "manifest_path": str(SOURCE_MANIFEST.resolve()),
            "manifest_sha256": TRUSTED_MANIFEST_SHA,
            "game_sha256": EXE_SHA,
            "dll_sha256": DLL_SHA,
            "source_count": len(original["sources"]),
        },
        "destination": verification,
        "artifact_reuse": _artifact_reuse(),
    }
    _write_json_once(report_path, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--experiment", help=f"create the fixed experiment {DEST_NAME}")
    mode.add_argument("--verify-existing", type=Path, help="verify the new experiment without changing it")
    parser.add_argument("--output", type=Path, help="exclusive JSON report path")
    args = parser.parse_args(argv)
    if args.experiment is not None and args.experiment != DEST_NAME:
        raise PrepareError("experiment_name_must_match_v24_context_target")
    report_path = (args.output or (DEFAULT_COPY_REPORT if args.experiment else DEFAULT_VERIFY_REPORT)).resolve()
    if args.experiment:
        report = prepare(DEST, report_path)
    else:
        report = verify_existing(args.verify_existing.resolve(strict=True), report_path)
    print(json.dumps({
        "status": report["status"],
        "report": str(report_path),
        "destination": str(DEST if args.experiment else args.verify_existing.resolve()),
        "source_count": report["trusted_source"]["source_count"],
        "dll_sha256": DLL_SHA,
        "runtime_verified": False,
        "installed": False,
        "game_accessed": False,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PrepareError as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, ensure_ascii=False))
        raise SystemExit(1)
