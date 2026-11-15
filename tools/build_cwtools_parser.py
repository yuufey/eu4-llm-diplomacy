"""Build the pinned CWTools CLI into the ignored local dependency directory."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.local_config import get_path


SOURCE_MANIFEST = ROOT / "tools/dotnet/cwtools-script/adapter-manifest.json"
LOCAL_DIRECTORY = ROOT / "work/deps/cwtools-script"
LOCAL_MANIFEST = LOCAL_DIRECTORY / "adapter-manifest.json"
SOURCE_SCHEMA = "eu4.cwtools.parser.source.v1"
LOCAL_SCHEMA = "eu4.cwtools.parser.local.v1"
PACKAGE_VERSION = "0.6.0-alpha"
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024


def _sha(path: Path) -> tuple[int, str]:
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise RuntimeError(f"File changed while building CWTools parser: {path}")
    return after.st_size, digest.hexdigest()


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read CWTools build metadata: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"CWTools build metadata must be a JSON object: {path}")
    return value


def _repo_file(relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or "\\" in relative or ".." in path.parts:
        raise RuntimeError(f"Unsafe path in CWTools source manifest: {relative}")
    resolved = (ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise RuntimeError(f"CWTools source path escapes workspace: {relative}") from exc
    return resolved


def _check_source(manifest: dict) -> tuple[Path, Path, Path, list[Path]]:
    if (manifest.get("schema") != SOURCE_SCHEMA
            or manifest.get("package") != {"id": "CWTools", "version": PACKAGE_VERSION}
            or manifest.get("license") != "MIT"
            or manifest.get("target_framework") != "net8.0"
            or manifest.get("max_batch_files") != 64
            or manifest.get("output_directory") != "work/deps/cwtools-script/publish"
            or manifest.get("assembly") != "work/deps/cwtools-script/publish/CwtoolsScript.dll"):
        raise RuntimeError("CWTools source manifest has an unsupported contract")

    records = manifest.get("files")
    if not isinstance(records, list) or not 5 <= len(records) <= 32:
        raise RuntimeError("CWTools source manifest has an invalid source file list")
    files: list[Path] = []
    seen: set[Path] = set()
    for record in records:
        if (not isinstance(record, dict) or not isinstance(record.get("path"), str)
                or type(record.get("bytes")) is not int or record["bytes"] <= 0
                or not isinstance(record.get("sha256"), str) or len(record["sha256"]) != 64):
            raise RuntimeError("CWTools source manifest contains an invalid file pin")
        path = _repo_file(record["path"])
        if path in seen:
            raise RuntimeError(f"Duplicate CWTools source file pin: {path}")
        seen.add(path)
        size, digest = _sha(path)
        if (size, digest) != (record["bytes"], record["sha256"]):
            raise RuntimeError(f"CWTools source pin mismatch: {path}")
        files.append(path)

    project = _repo_file(manifest.get("project", ""))
    nuget_config = _repo_file("tools/dotnet/cwtools-script/NuGet.Config")
    lock_path = _repo_file("tools/dotnet/cwtools-script/packages.lock.json")
    if project not in seen or nuget_config not in seen or lock_path not in seen:
        raise RuntimeError("CWTools project, NuGet configuration, and package lock must be pinned")
    lock = _read_json(lock_path)
    dependencies = lock.get("dependencies", {}).get("net8.0", {})
    expected = {"CWTools": PACKAGE_VERSION, "FSharp.Core": "9.0.303"}
    if any(dependencies.get(name, {}).get("resolved") != version
           for name, version in expected.items()):
        raise RuntimeError("NuGet lock does not contain the expected CWTools package versions")
    for name, version in expected.items():
        requested = dependencies[name].get("requested")
        if requested and version not in requested:
            raise RuntimeError(f"NuGet lock request for {name} does not match {version}")
    return project, nuget_config, lock_path, files


def _dotnet() -> str:
    configured = get_path("EU4_DOTNET", required=False)
    if configured is not None:
        configured = Path(configured)
        if configured.is_dir():
            for name in ("dotnet.exe", "dotnet"):
                candidate = configured / name
                if candidate.is_file():
                    return str(candidate.resolve())
        elif configured.is_file():
            return str(configured.resolve())
        found = shutil.which(str(configured))
        if found:
            return found
    found = shutil.which("dotnet")
    if found:
        return found
    raise RuntimeError(
        "EU4_DOTNET is missing or unavailable. Set it to dotnet.exe, its containing "
        "directory, or the PATH command name `dotnet`, then run `python "
        "tools/build_cwtools_parser.py`. No SDK download is performed by this script.")


def _dotnet_environment() -> dict[str, str]:
    environment = os.environ.copy()
    if "NUGET_PACKAGES" not in os.environ:
        configured_cache = get_path("EU4_NUGET_PACKAGES", required=False)
        if configured_cache is not None:
            environment["NUGET_PACKAGES"] = str(configured_cache)
    return environment


def _artifact_records(directory: Path) -> list[dict]:
    records = []
    total = 0
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        if path.is_symlink():
            raise RuntimeError(f"Unexpected symbolic link in CWTools output: {path}")
        size, digest = _sha(path)
        total += size
        if size <= 0 or total > MAX_ARTIFACT_BYTES:
            raise RuntimeError("CWTools build output exceeds the 128 MiB artifact limit")
        records.append({"path": path.resolve().relative_to(ROOT).as_posix(),
                        "bytes": size, "sha256": digest})
    if len(records) < 2 or len(records) > 128:
        raise RuntimeError("CWTools build output has an unexpected number of files")
    if not any(record["path"] == "work/deps/cwtools-script/publish/CwtoolsScript.dll"
               for record in records):
        raise RuntimeError("CWTools CLI assembly was not produced")
    return records


def build() -> Path:
    source_manifest = _read_json(SOURCE_MANIFEST)
    project, nuget_config, _lock_path, _files = _check_source(source_manifest)
    dotnet = _dotnet()
    dotnet_environment = _dotnet_environment()

    output = _repo_file(source_manifest["output_directory"])
    # Keep generated output under the explicit ignored local dependency root.
    output.relative_to((ROOT / "work/deps/cwtools-script").resolve())
    output.mkdir(parents=True, exist_ok=True)
    LOCAL_DIRECTORY.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [dotnet, "restore", str(project), "--locked-mode", "--ignore-failed-sources",
         "--configfile", str(nuget_config)],
        cwd=ROOT, check=True, env=dotnet_environment,
    )
    subprocess.run(
        [dotnet, "publish", str(project), "--configuration", "Release", "--no-restore",
         "--self-contained", "false", "--output", str(output)],
        cwd=ROOT, check=True, env=dotnet_environment,
    )

    manifest_size, manifest_hash = _sha(SOURCE_MANIFEST)
    local_manifest = {
        "schema": LOCAL_SCHEMA,
        "package": {"id": "CWTools", "version": PACKAGE_VERSION},
        "license": "MIT",
        "max_batch_files": source_manifest["max_batch_files"],
        "source_manifest": {
            "path": SOURCE_MANIFEST.resolve().relative_to(ROOT.resolve()).as_posix(),
            "bytes": manifest_size,
            "sha256": manifest_hash,
        },
        "artifacts": _artifact_records(output),
    }
    temporary = LOCAL_MANIFEST.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(local_manifest, indent=2) + "\n", encoding="utf-8")
    temporary.replace(LOCAL_MANIFEST)
    return LOCAL_MANIFEST


if __name__ == "__main__":
    try:
        result = build()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"CWTools parser build failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"CWTools parser ready: {result.relative_to(ROOT).as_posix()}")
