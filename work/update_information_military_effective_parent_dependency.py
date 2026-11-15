"""Retain v2 and bind the new optional military-effective parent in v3."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information import domestic_pressure_memory as memory

STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    old = memory.PROFILE_FILE
    assert old.name == "domestic-pressure-memory-1374-v2.json"
    before = memory._static_contract_guard()
    assert before["status"] == "unknown"
    profile = json.loads(old.read_bytes())
    helper = ROOT / "bridge/information/country_resources_memory.py"
    relative = helper.relative_to(ROOT).as_posix()
    entry = next(row for row in profile["provenance"]["dependencies"] if row["path"] == relative)
    previous = dict(entry)
    entry.update(pin(helper))
    profile["profile_version"] = 3
    profile.setdefault("notes", []).append(
        "The country-resources parent adds the optional military_effective child under the existing strict military flag. Rebind only that source dependency; native layouts, code guards and other dependencies remain unchanged."
    )
    target = old.with_name("domestic-pressure-memory-1374-v3.json")
    write(target, profile)
    write(STAGE / "domestic-parent-dependency-update-001.json", {
        "schema": "information_domestic_parent_dependency_update.v2", "old_profile": pin(old),
        "new_profile": pin(target), "before_guard": before, "old_dependency": previous,
        "new_dependency": pin(helper), "native_layout_and_guards_changed": False,
        "new_profile_enabled_at_receipt_creation": False,
    })
    print(json.dumps(pin(target), ensure_ascii=False))


if __name__ == "__main__":
    main()
