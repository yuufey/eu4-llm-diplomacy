"""Reuse the observer-visible subset of a particular offline save between CLI calls."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from bridge.map_snapshot import MapSnapshotError, TAG_RE, parse_map_snapshot


def load_visible_snapshot(save: Path, observer: str, cache: Path):
    if TAG_RE.fullmatch(observer) is None or observer == "---":
        raise ValueError("Invalid observer tag")
    with save.open("rb") as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = save.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("Save changed while checking the map cache")
    directory = cache / "v1" / digest
    target = directory / (observer + ".json")
    if target.is_file():
        try:
            cached = json.loads(target.read_bytes())
            if cached["observer"] == observer and cached["save_sha256"] == digest:
                owners = {int(pid): owner for pid, owner in cached["owners"].items()}
                return cached["date"], owners, digest, True
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
    data = parse_map_snapshot(save, observer)
    if data["source"]["sha256"] != digest:
        raise MapSnapshotError("Save changed before snapshot compilation")
    if not data["observer_in_country_list"]:
        raise MapSnapshotError("Observer country absent from save")
    visible = set(data["visible_provinces"])
    owners = {row["province_id"]: row["owner"] for row in data["provinces"] if row["province_id"] in visible}
    result = {"observer": observer, "save_sha256": digest, "date": data["date"], "owners": owners}
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as temp:
        name = Path(temp.name)
    try:
        name.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
        os.replace(name, target)
    finally:
        name.unlink(missing_ok=True)
    return data["date"], owners, digest, False
