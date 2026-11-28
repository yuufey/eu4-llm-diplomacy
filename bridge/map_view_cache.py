"""Reuse the observer-visible subset of a particular offline save between CLI calls."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from bridge.map_snapshot import MapSnapshotError, TAG_RE, parse_map_snapshot


def load_visible_snapshot(save: Path, observer: str, cache: Path):
    """Return date, visible owners, known occupations, save hash and cache hit.

    An absent occupation may mean either no occupation or an unknown field.
    """
    if TAG_RE.fullmatch(observer) is None or observer == "---":
        raise ValueError("Invalid observer tag")
    with save.open("rb") as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = save.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("Save changed while checking the map cache")
    # Version 1 stored only owners. Do not reuse it for an occupation map.
    directory = cache / "v2" / digest
    target = directory / (observer + ".json")
    if target.is_file():
        try:
            cached = json.loads(target.read_bytes())
            if cached["observer"] == observer and cached["save_sha256"] == digest:
                owners = {int(pid): owner for pid, owner in cached["owners"].items()}
                controllers = {int(pid): controller for pid, controller in cached["controllers"].items()}
                return cached["date"], owners, controllers, digest, True
        except (ValueError, KeyError, TypeError, AttributeError):
            pass
    data = parse_map_snapshot(save, observer)
    if data["source"]["sha256"] != digest:
        raise MapSnapshotError("Save changed before snapshot compilation")
    if not data["observer_in_country_list"]:
        raise MapSnapshotError("Observer country absent from save")
    visible = set(data["visible_provinces"])
    owners = {row["province_id"]: row["owner"] for row in data["provinces"] if row["province_id"] in visible}
    controllers = {
        row["province_id"]: row["controller"] for row in data["provinces"]
        if row["province_id"] in visible and row["owner"] is not None
        and row["controller"] is not None and row["controller"] != row["owner"]
    }
    result = {"observer": observer, "save_sha256": digest, "date": data["date"],
              "owners": owners, "controllers": controllers}
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as temp:
        name = Path(temp.name)
    try:
        name.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
        os.replace(name, target)
    finally:
        name.unlink(missing_ok=True)
    return data["date"], owners, controllers, digest, False
