"""Rebind the final parent after the same batch also adds morale caches."""
from __future__ import annotations
import json
from work.update_information_military_effective_parent_dependency import ROOT, STAGE, memory, pin, write


def main():
    old = memory.PROFILE_FILE
    assert old.name == "domestic-pressure-memory-1374-v3.json"
    guard = memory._static_contract_guard()
    assert guard["status"] == "unknown"
    profile = json.loads(old.read_bytes())
    helper = ROOT / "bridge/information/country_resources_memory.py"
    relative = helper.relative_to(ROOT).as_posix()
    entry = next(row for row in profile["provenance"]["dependencies"] if row["path"] == relative)
    previous = dict(entry)
    entry.update(pin(helper))
    profile["profile_version"] = 4
    profile.setdefault("notes", []).append(
        "The final batch50 parent also adds the optional military_morale child. Version3 was an intermediate source rebind before this final parent edit; v2/v3 and their receipts are retained. Native layouts, guards and other dependencies are unchanged."
    )
    target = old.with_name("domestic-pressure-memory-1374-v4.json")
    write(target, profile)
    write(STAGE / "domestic-parent-dependency-update-002.json", {
        "schema": "information_domestic_parent_dependency_update.v2", "old_profile": pin(old),
        "new_profile": pin(target), "before_guard": guard, "old_dependency": previous,
        "new_dependency": pin(helper), "native_layout_and_guards_changed": False,
        "v3_was_intermediate_before_live_acceptance": True,
        "new_profile_enabled_at_receipt_creation": False,
    })
    print(json.dumps(pin(target), ensure_ascii=False))


if __name__ == "__main__":
    main()
