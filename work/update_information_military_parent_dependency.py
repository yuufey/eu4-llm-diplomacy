"""Version the domestic profile after auditing the optional parent extension."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information import domestic_pressure_memory as memory

STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    old = memory.PROFILE_FILE
    assert old.name == "domestic-pressure-memory-1374.json"
    guard = memory._static_contract_guard()
    assert guard["status"] == "unknown"
    profile = json.loads(old.read_bytes())
    helper = ROOT / "bridge/information/country_resources_memory.py"
    baseline = ROOT / "work/runtime/information-trade-merchant-task-20261027-001/source-snapshot/bridge/information/country_resources_memory.py"
    entry = next(item for item in profile["provenance"]["dependencies"] if item["path"] == helper.relative_to(ROOT).as_posix())
    prior_entry = dict(entry)
    assert pin(baseline)["sha256"] != entry["sha256"]
    entry.update(pin(helper))
    profile["profile_version"] = 2
    profile.setdefault("notes", []).append(
        "The country-resources helper dependency is rebound to the audited optional military-child extension; scalar native offsets, code guards and all other dependencies are unchanged. The previous helper hash already differed from batch48's frozen helper."
    )
    target = old.with_name("domestic-pressure-memory-1374-v2.json")
    write(target, profile)
    receipt = {"schema": "information_domestic_parent_dependency_update.v1",
               "old_profile": pin(old), "new_profile": pin(target),
               "before_guard": guard, "old_dependency": prior_entry, "new_dependency": pin(helper),
               "batch48_parent_snapshot": pin(baseline), "mismatch_already_present_in_batch48": True,
               "native_layout_and_guards_changed": False,
               "scope": "Restore domestic source dependency validation while retaining the original profile and receipts.",
               "new_profile_not_yet_enabled": True}
    write(STAGE / "domestic-parent-dependency-update-001.json", receipt)
    print(json.dumps({"new_profile": pin(target), "prior_profile": pin(old)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
