"""Resolve retained document references after the documentation module split."""
from functools import lru_cache
import json
from pathlib import Path


_MAPPING = Path(__file__).resolve().parents[1] / "docs/共用开发/文档路径映射.json"


@lru_cache(maxsize=1)
def _paths():
    return json.loads(_MAPPING.read_text(encoding="utf-8"))["paths"]


def resolve_repo_path(root, relative):
    """Keep existing fixture paths and locate moved historical document inputs."""
    root = Path(root).resolve()
    path = Path(relative)
    original = path if path.is_absolute() else root / path
    if original.exists():
        return original
    try:
        key = original.resolve().relative_to(root).as_posix()
    except ValueError:
        return original
    if not key.startswith("docs/"):
        return original
    return root / _paths().get(key, key)
