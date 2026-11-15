"""Copy a verified immutable observer build into a fresh experiment directory."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--experiment", required=True)
    parser.add_argument("--hardlink", action="store_true",
                        help="Share immutable build files instead of copying their data")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.experiment):
        parser.error("experiment must be a directory name using ASCII letters, digits, _ or -")
    source = args.manifest.resolve(strict=True)
    manifest = json.loads(source.read_text(encoding="utf-8-sig"))
    files: list[Path] = []
    for row in manifest["sources"]:
        name = row["name"]
        if Path(name).name != name:
            raise ValueError("source entry must be a filename")
        path = source.parent / name
        if digest(path) != row["sha256"]:
            raise ValueError(f"source hash mismatch: {name}")
        files.append(path)
    dll = Path(manifest["dll"])
    if digest(dll) != manifest["dll_sha256"]:
        raise ValueError("DLL hash mismatch")
    destination = source.parent.with_name(args.experiment)
    destination.mkdir(exist_ok=False)
    for path in (*files, dll):
        if args.hardlink:
            os.link(path, destination / path.name)
        else:
            shutil.copy2(path, destination / path.name)
    manifest["experiment_id"] = args.experiment
    manifest["dll"] = str(destination / dll.name)
    manifest["runtime_verified"] = False
    manifest["reused_build"] = {
        "manifest_path": str(source), "manifest_sha256": digest(source),
        "dll_sha256": manifest["dll_sha256"],
        "storage": "hardlink" if args.hardlink else "copy",
    }
    output = destination / "build-manifest.json"
    with output.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"manifest": str(output), "sources": len(files),
                      "dll_sha256": manifest["dll_sha256"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
