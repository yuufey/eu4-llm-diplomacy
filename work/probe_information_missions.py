"""Thin command-line wrapper for the production mission-memory reader."""
from __future__ import annotations

from pathlib import Path
import sys

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bridge.information.mission_memory import capture, main

__all__ = ["capture", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
