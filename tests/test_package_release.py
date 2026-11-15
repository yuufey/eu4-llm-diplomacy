"""Relocate an observer build without its old machine or running session."""
import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from tools.package_release import observer_payload, package_observer


def test_observer_archive_keeps_binary_sources_and_uses_relative_metadata(tmp_path):
    build = tmp_path / "old build"
    build.mkdir()
    files = {"eu4_bridge_diplomacy_observer_v64.dll": b"reviewed observer", "observer.cpp": b"source"}
    for name, raw in files.items():
        (build / name).write_bytes(raw)
    manifest = {"version": 64, "experiment_id": "old-experiment",
                "dll": "C:/old machine/observer.dll",
                "dll_sha256": hashlib.sha256(files["eu4_bridge_diplomacy_observer_v64.dll"]).hexdigest(),
                "compiler_arguments": ["-DOBSERVE=1", "C:/old machine/observer.cpp"],
                "sources": [{"name": "observer.cpp", "sha256": hashlib.sha256(b"source").hexdigest()}]}
    path = build / "build-manifest.json"
    original = json.dumps(manifest).encode()
    path.write_bytes(original)
    prefix, payload = observer_payload(path)
    portable = json.loads(payload["build-manifest.json"])
    assert portable["dll"] == "eu4_bridge_diplomacy_observer_v64.dll"
    assert portable["compiler_arguments"] == ["-DOBSERVE=1", "observer.cpp"]
    assert portable["experiment_id"] == prefix
    assert path.read_bytes() == original
    output = tmp_path / "release/observer.zip"
    package_observer(path, output)
    with zipfile.ZipFile(output) as archive:
        assert set(archive.namelist()) == {prefix + "/" + name for name in payload}
        assert archive.read(prefix + "/observer.cpp") == b"source"
        assert archive.read(prefix + "/eu4_bridge_diplomacy_observer_v64.dll") == files["eu4_bridge_diplomacy_observer_v64.dll"]
    assert output.with_suffix(".zip.sha256").read_text().startswith(hashlib.sha256(output.read_bytes()).hexdigest())
    (build / "observer.cpp").write_bytes(b"changed source")
    with pytest.raises(RuntimeError, match="Observer build member changed"):
        observer_payload(path)
