"""Read the two battle-body templates and button labels without native calls.

This is a research probe, not a public B04 text source.  It reads the current
localization cache; it cannot attach that current language/template to an old
battle or prove a rendered window.  The underlying readers validate the fixed
executable, process creation identity, bounded RPM, and two-pass consistency.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information.localization_memory import capture  # noqa: E402
from tools.control_information_current_country import (  # noqa: E402
    _read_world_control_unchecked,
)

KEYS = tuple(
    definition + suffix
    for definition in ("LANDBATTLEOVER", "NAVALBATTLEOVER")
    for suffix in ("_1", "_BTN1", "_BTN2", "_BTN3")
)


def pin(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": path.resolve().relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.relative_to(ROOT)
    # Reserve the receipt before any RPM so an existing attempt cannot be
    # replaced and an unexpected exception still leaves its own receipt.
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        report = {
            "schema": "information.battle.body_templates_probe.v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "failed", "game_function_calls": 0,
            "game_memory_writes": 0, "date_advancement_requests": 0,
            "requested_keys": list(KEYS),
            "boundary": "Current literal cache only; no past-event binding, "
                        "rendered text, full B04, or visibility claim.",
        }
        try:
            installation = args.installation.resolve()
            document = json.loads(installation.read_text(encoding="utf-8"))
            context = SimpleNamespace(pid=int(document["pid"]), installation=document)
            report["source_pins"] = [pin(installation)] + [pin(ROOT / rel) for rel in (
                "work/probe_information_battle_body_templates.py",
                "bridge/information/localization_memory.py",
                "bridge/information/mission_memory.py",
                "bridge/information/profiles/localization-memory-1374.json",
                "tools/control_information_current_country.py",
            )]
            before = [_read_world_control_unchecked(context, "POR", "FRA")
                      for _ in range(2)]
            report["world_before"] = before
            if before[0] != before[1]:
                raise ValueError("world_before_doublepass_changed")
            world = before[0]
            if (world.get("current_tag") != "POR"
                    or world.get("human_count_raw") != 1
                    or world.get("paused") is not True
                    or world.get("speed") != 0):
                raise ValueError("expected_paused_POR_with_single_human")
            controllers = world.get("controller_types_raw", {})
            slots = controllers.get("slots", {})
            if controllers.get("status") != "observed" or not isinstance(slots, dict):
                raise ValueError("controller_types_unavailable")
            # The helper reports full-reference-derived slots; do not use
            # installation-era country pointers as current controller proof.
            for tag, value in (("POR", 1), ("FRA", 0)):
                observed = [item for key, item in slots.items() if key.startswith(tag + ":")]
                if len(observed) != 1 or type(observed[0]) is not int or observed[0] != value:
                    raise ValueError("controller_role_mismatch:" + tag)
            report["localization"] = capture(installation, "FRA", KEYS)
            after = [_read_world_control_unchecked(context, "POR", "FRA")
                     for _ in range(2)]
            report["world_after"] = after
            if after[0] != after[1] or after[0] != world:
                raise ValueError("world_changed_around_literal_cache_read")
            if report["localization"].get("status") != "observed":
                raise ValueError("localization_not_observed")
            report["status"] = "observed"
        except Exception as error:
            report["error"] = {"type": type(error).__name__, "message": str(error)}
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "receipt": pin(output)}, ensure_ascii=False))
    return 0 if report["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
