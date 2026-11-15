"""Read the current player/observer roles twice without controlling the game."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.control_information_current_country import _read_world_control_unchecked


def pin(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": path.resolve().relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--expected-date", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.resolve().relative_to(ROOT / "work/runtime")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "information.battle.event_world.v1", "status": "failed",
              "at": datetime.now(timezone.utc).isoformat(),
              "native_calls": 0, "request_writes": 0, "atomic_snapshot_claimed": False}
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        try:
            document = json.loads(args.installation.read_text(encoding="utf-8"))
            context = SimpleNamespace(pid=int(document["pid"]), installation=document)
            sources = [args.installation, Path(__file__),
                       ROOT / "tools/control_information_current_country.py"]
            before = [pin(path) for path in sources]
            passes = [_read_world_control_unchecked(context, "POR", "FRA") for _ in range(2)]
            report.update(pid=context.pid, creation_filetime=document["creation_filetime"],
                          session_id=document["session_id"], source_pins=before, passes=passes)
            if passes[0] != passes[1]:
                raise ValueError("world_changed_between_passes")
            world = passes[0]
            if (world["current_tag"] != "POR" or world["human_count_raw"] != 1
                    or world["date_raw"] != args.expected_date
                    or world["paused"] is not True or world["speed"] != 0):
                raise ValueError("expected_paused_POR_world_differs")
            controllers = world["controller_types_raw"]
            if controllers["status"] != "observed":
                raise ValueError("controllers_unknown")
            for tag, expected in (("POR", 1), ("FRA", 0)):
                if [value for key, value in controllers["slots"].items()
                        if key.startswith(tag + ":")] != [expected]:
                    raise ValueError("controller_role_differs:" + tag)
            if [pin(path) for path in sources] != before:
                raise ValueError("source_changed_during_read")
            report["status"] = "observed_paused_POR_LLM_nonplayer_FRA"
        except Exception as error:
            report["error"] = f"{type(error).__name__}:{error}"
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(json.dumps({"status": report["status"], "output": pin(args.output)}))
    return 0 if report["status"].startswith("observed_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
