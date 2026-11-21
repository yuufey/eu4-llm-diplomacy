"""Codex stdio entry point for the resident EU4 decision scheduler."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bridge.information.decision_mcp import relay_stdio


if __name__ == "__main__":
    raise SystemExit(relay_stdio(int(sys.argv[1])))
