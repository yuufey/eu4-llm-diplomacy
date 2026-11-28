"""Persist periodic political-map snapshots for a running EU4 session.

Each published bundle contains the same live snapshot rendered at overview,
region, and local scales.  The bundle directory is installed atomically and a
small ``latest.json`` pointer is switched only after every required file is
complete.  Cleanup only removes directories carrying this module's manifest.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile
from typing import Any
from uuid import uuid4

from PIL import Image

from bridge.map_png import write_png


SCHEMA = "eu4.map_bundle.v1"
_KEEP_BUNDLES = 2


def _atomic_json(path: Path, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":"), indent=2).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".json-",
                                     suffix=".tmp", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _bundle_id(date: str) -> tuple[str, str]:
    created = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    safe_date = "-".join(part for part in date.split(".") if part.isdigit()) or "unknown-date"
    return f"{safe_date}-{created.replace(':', '').replace('-', '')}-{uuid4().hex[:10]}", created


def _linklike(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _validate_bundles(root: Path) -> Path:
    bundles = root / "bundles"
    if _linklike(bundles):
        raise ValueError("MAP_BUNDLE_BUNDLES_EXTERNAL")
    if bundles.exists():
        resolved = bundles.resolve()
        if resolved.parent != root or not resolved.is_dir():
            raise ValueError("MAP_BUNDLE_BUNDLES_EXTERNAL")
    else:
        bundles.mkdir()
    return bundles


def _validate_latest(root: Path) -> Path:
    latest = root / "latest.json"
    if _linklike(latest):
        raise ValueError("MAP_BUNDLE_LATEST_EXTERNAL")
    if latest.exists():
        if not latest.is_file():
            raise ValueError("MAP_BUNDLE_LATEST_CONFLICT")
        try:
            existing = json.loads(latest.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            raise ValueError("MAP_BUNDLE_LATEST_CONFLICT") from None
        if not isinstance(existing, dict) or existing.get("schema") != SCHEMA:
            raise ValueError("MAP_BUNDLE_LATEST_CONFLICT")
    return latest


def _clean_old_bundles(bundles: Path, keep: str) -> list[str]:
    candidates: list[tuple[str, Path]] = []
    for child in bundles.iterdir() if bundles.is_dir() else ():
        if (not child.is_dir() or _linklike(child) or child.name == keep
                or child.resolve().parent != bundles.resolve()):
            continue
        manifest_path = child / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (manifest.get("schema") != SCHEMA
                    or manifest.get("bundle_id") != child.name
                    or not isinstance(manifest.get("created_at"), str)):
                continue
            candidates.append((manifest["created_at"], child))
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    candidates.sort(key=lambda item: item[0], reverse=True)
    removed: list[str] = []
    for _, child in candidates[_KEEP_BUNDLES - 1:]:
        try:
            own_files = {"manifest.json", "snapshot.json", "overview.png", "region.png", "local.png"}
            for name in own_files:
                path = child / name
                if path.exists() and not _linklike(path) and path.is_file():
                    path.unlink()
            child.rmdir()
            removed.append(child.name)
        except OSError:
            continue
    return removed


def _publish_map_bundle_locked(map_service, directory: str | Path, *,
                       center_country: str | None = None,
                       province: int | None = None,
                       xy: tuple[int, int] | None = None,
                       size: str = "compact", layers=(), war_id=None) -> dict[str, Any]:
    """Capture once and publish three map scales under ``directory``.

    ``map_service`` must be a live political-map service exposing
    ``render_bundle``.  The method owns the service lock while capturing and
    rendering.  Disk writes happen after the returned images have been created,
    so all files in one bundle use the same ``snapshot_id``.
    """

    root = Path(directory).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    bundle_data = map_service.render_bundle(
        center_country=center_country, province=province, xy=xy, size=size,
        **({"layers": layers} if layers else {}),
        **({"war_id": war_id} if war_id is not None else {}))
    if not isinstance(bundle_data, dict):
        raise ValueError("MAP_BUNDLE_RESULT_INVALID")
    images = bundle_data.get("images")
    views = bundle_data.get("views")
    snapshot = bundle_data.get("snapshot")
    date = snapshot.get("date") if isinstance(snapshot, dict) else None
    if (not isinstance(images, dict) or not isinstance(views, dict)
            or not isinstance(snapshot, dict) or not isinstance(date, str)):
        raise ValueError("MAP_BUNDLE_RESULT_SHAPE_INVALID")
    if set(images) != {"overview", "region", "local"} or set(views) != set(images):
        raise ValueError("MAP_BUNDLE_SCALES_INVALID")

    bundle_id, created_at = _bundle_id(date)
    bundles = root / "bundles"
    bundles.mkdir(parents=True, exist_ok=True)
    staging = bundles / f".{bundle_id}.tmp"
    final = bundles / bundle_id
    if staging.exists() or final.exists():
        raise ValueError("MAP_BUNDLE_ID_COLLISION")
    staging.mkdir()
    try:
        image_paths: dict[str, str] = {}
        for scale in ("overview", "region", "local"):
            image = images[scale]
            view = views[scale]
            if not isinstance(image, Image.Image) or not isinstance(view, dict):
                raise ValueError("MAP_BUNDLE_SCALE_INVALID")
            relative = f"bundles/{bundle_id}/{scale}.png"
            write_png(staging / f"{scale}.png", image, view)
            image_paths[scale] = relative

        snapshot_path = staging / "snapshot.json"
        _atomic_json(snapshot_path, {
            "date": date, "observer": bundle_data.get("observer"),
            "snapshot_id": bundle_data.get("snapshot_id"), "owners": snapshot["owners"],
            **({"military": snapshot["military"]} if "military" in snapshot else {}),
        })
        manifest = {
            "schema": SCHEMA,
            "bundle_id": bundle_id,
            "created_at": created_at,
            "date": date,
            "observer": bundle_data.get("observer"),
            "snapshot_id": bundle_data.get("snapshot_id"),
            "images": image_paths,
            "snapshot": f"bundles/{bundle_id}/snapshot.json",
            "metrics": bundle_data.get("metrics", {}),
            "center_country": center_country,
            "province": province,
            "xy": list(xy) if xy is not None else None,
            "size": size,
            **({"layers": list(layers)} if layers else {}),
            **({"war_id": war_id} if war_id is not None else {}),
        }
        _atomic_json(staging / "manifest.json", manifest)
        os.replace(staging, final)
        staging = None

        latest = dict(manifest)
        latest["latest"] = True
        _atomic_json(root / "latest.json", latest)
        latest["latest_path"] = str(root / "latest.json")
        latest["removed_bundles"] = _clean_old_bundles(bundles, bundle_id)
        return latest
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def publish_map_bundle(map_service, directory: str | Path, *,
                       center_country: str | None = None,
                       province: int | None = None,
                       xy: tuple[int, int] | None = None,
                       size: str = "compact", layers=(), war_id=None) -> dict[str, Any]:
    """Capture once and atomically publish a three-scale map bundle."""

    root = Path(directory).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    from .information.collection_lock import CollectionLock
    with CollectionLock(root / ".map_bundle").acquire():
        _validate_latest(root)
        _validate_bundles(root)
        return _publish_map_bundle_locked(
            map_service, root, center_country=center_country, province=province,
            xy=xy, size=size, layers=layers, war_id=war_id)


__all__ = ["SCHEMA", "publish_map_bundle"]
