"""Standalone CLI for the read-only current relation capture seam.

The command delegates only to ``relation_memory.capture``.  That seam uses
QUERY_INFORMATION|VM_READ and never invokes a game function; this script does
not add a second native or UI path.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from bridge.information import relation_memory


def probe(installation: Path, actor: str = "FRA", recipient: str = "", families: list[str] | None = None) -> dict:
    if not recipient:
        raise ValueError("recipient is required")
    return relation_memory.capture(installation, actor, recipient, families)


def _write_once(path: Path, payload: dict) -> None:
    if path.exists():
        raise FileExistsError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture current alliance/royal-marriage state by bounded read-only RPM")
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--actor", default="FRA")
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--families", default="alliance,royal_marriage")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    families = [item.strip() for item in args.families.split(",") if item.strip()]
    try:
        payload = probe(args.installation, args.actor, args.recipient, families)
        _write_once(args.output, payload)
    except (OSError, ValueError, relation_memory.ProbeError) as exc:
        print(f"relation_probe_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": payload.get("status"), "completed": payload.get("completed"), "doublepass": payload.get("doublepass"), "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
