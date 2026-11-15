"""Copy the pinned, runtime-accepted v22 artifact into a fresh experiment.

This does not compile, launch a game, inject a DLL, or create requests. It
verifies the immutable archive before copying and keeps installation records
out of the new directory. The original archive is never modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "work/runtime"
SOURCE = RUNTIME / "diplomacy-observer-20261024-information-a"
SOURCE_MANIFEST_SHA = "0e9925aad05ec5d5b16a00ade477c46fbe6874fe9ba25272aeac1dcb8765b944"
DLL_SHA = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_NAME = "eu4_bridge_diplomacy_observer_v22.dll"
MAX_BYTES = 16 * 1024 * 1024


def digest(path: Path) -> str:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(f"missing_or_oversize_artifact:{path}")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def source_manifest() -> dict:
    path = SOURCE / "build-manifest.json"
    if digest(path) != SOURCE_MANIFEST_SHA:
        raise ValueError("validated_manifest_changed")
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    if not (manifest["version"] == 22 and manifest["game_sha256"] == EXE_SHA
            and manifest["dll_sha256"] == DLL_SHA and len(manifest["sources"]) == 92
            and digest(SOURCE / DLL_NAME) == DLL_SHA):
        raise ValueError("validated_build_identity_changed")
    names = set()
    for item in manifest["sources"]:
        name = item["name"]
        if Path(name).name != name or name in names:
            raise ValueError("invalid_or_duplicate_source_name")
        names.add(name)
        if digest(SOURCE / name) != item["sha256"]:
            raise ValueError(f"validated_source_changed:{name}")
    return manifest


def verify_copy(directory: Path, original: dict) -> None:
    if directory.resolve().parent != RUNTIME.resolve() or directory.resolve() == SOURCE.resolve():
        raise ValueError("experiment_outside_runtime_or_is_source")
    current = json.loads((directory / "build-manifest.json").read_text(encoding="utf-8-sig"))
    if not (current["experiment_id"] == directory.name and current["version"] == 22
            and current["dll_sha256"] == DLL_SHA and current["game_sha256"] == EXE_SHA
            and current["sources"] == original["sources"]
            and Path(current["dll"]).resolve() == (directory / DLL_NAME).resolve()
            and current["artifact_reuse"]["recompiled"] is False
            and current["artifact_reuse"]["source_manifest_sha256"] == SOURCE_MANIFEST_SHA):
        raise ValueError("copied_manifest_mismatch")
    if digest(directory / DLL_NAME) != DLL_SHA:
        raise ValueError("copied_dll_mismatch")
    for item in original["sources"]:
        if digest(directory / item["name"]) != item["sha256"]:
            raise ValueError(f"copied_source_mismatch:{item['name']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--experiment", help="New ASCII experiment name directly under work/runtime")
    mode.add_argument("--verify-existing", type=Path, help="Read-only verification of a prior copy")
    args = parser.parse_args()
    manifest = source_manifest()
    if args.verify_existing is not None:
        directory = args.verify_existing.resolve(strict=True)
    else:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", args.experiment):
            raise ValueError("invalid_experiment_name")
        directory = RUNTIME / args.experiment
        directory.mkdir(exist_ok=False)
        for item in manifest["sources"]:
            shutil.copy2(SOURCE / item["name"], directory / item["name"])
        shutil.copy2(SOURCE / DLL_NAME, directory / DLL_NAME)
        manifest = {**manifest, "experiment_id": directory.name, "dll": str(directory / DLL_NAME),
                    "runtime_verified": False,
                    "artifact_reuse": {"recompiled": False,
                                      "source_manifest": str(SOURCE / "build-manifest.json"),
                                      "source_manifest_sha256": SOURCE_MANIFEST_SHA,
                                      "verified_source_count": 92,
                                      "reason": "Reuse pinned runtime-accepted binary; installation must be freshly verified."}}
        with (directory / "build-manifest.json").open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    verify_copy(directory, source_manifest())
    print(json.dumps({"status": "passed", "directory": str(directory), "dll_sha256": DLL_SHA,
                      "verified_source_count": 92, "recompiled": False,
                      "game_accessed": False, "installed": False,
                      "verify_only": args.verify_existing is not None}, ensure_ascii=False))


if __name__ == "__main__":
    main()
