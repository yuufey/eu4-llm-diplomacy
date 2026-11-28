"""Atomic PNG writer shared by the political-map CLI and archive publisher."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from PIL import Image, PngImagePlugin


def write_png(path: str | Path, image: Image.Image, view: dict[str, Any]) -> None:
    """Write a PNG with the view metadata and replace the destination atomically."""

    destination = Path(path)
    metadata = PngImagePlugin.PngInfo()
    metadata.add_itxt("eu4_view", json.dumps(view, ensure_ascii=False,
                                               separators=(",", ":")), zip=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".png-",
                                     suffix=".tmp", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        image.save(temporary, format="PNG", pnginfo=metadata)
        with temporary.open("r+b") as written:
            os.fsync(written.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


__all__ = ["write_png"]
