"""Version the remaining four-field prose out of the three-field contract."""
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.freeze_information_country_powers import read_json_bounded, dependency_record, _write_json_new, relpath

STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
PROFILE = ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"


def main():
    profile, _, sha = read_json_bounded(PROFILE)
    if sha != "707056e4653e06e8a65ef71f3991c884e052fe354b4439b46c52577b4a9c56ba":
        raise ValueError("version2_profile_changed")
    old_path = STAGE / "native-domestic-pressure-contract-002.json"
    contract, _, old_sha = read_json_bounded(old_path)
    if old_sha != "15ff0ad19a37248148015fbfaf255adaa27fe281344ea2281075091f820d3414":
        raise ValueError("version2_contract_changed")
    corrected = deepcopy(contract)
    corrected["contract_id"] = "native-domestic-pressure-contract-003"
    replacements = {
        "the four selected records": "the three retained records",
        "all four actual names": "the actual names of all requested retained fields",
    }
    changed = []
    for text in contract["semantic_join"]:
        revised = text
        for old, new in replacements.items():
            revised = revised.replace(old, new)
        changed.append(revised)
    if sum(a != b for a, b in zip(changed, contract["semantic_join"])) != 2:
        raise ValueError("narrative_correction_scope_changed")
    corrected["semantic_join"] = changed
    corrected["narrative_predecessor"] = {"path": relpath(old_path), "sha256": old_sha,
                                          "layout_and_field_scope_unchanged": True}
    new_path = STAGE / "native-domestic-pressure-contract-003.json"
    _, new_sha = _write_json_new(new_path, corrected, overwrite=False)
    saved_profile = STAGE / "pre-contract-narrative-correction-001" / PROFILE.name
    saved_profile.parent.mkdir(parents=True, exist_ok=True)
    with saved_profile.open("xb") as stream:
        stream.write(PROFILE.read_bytes())
    revised_profile = deepcopy(profile)
    revised_profile["profile_version"] = 3
    revised_profile["contract_sha256"] = new_sha
    revised_profile["provenance"]["contract_path"] = relpath(new_path)
    revised_profile["provenance"]["contract_sha256"] = new_sha
    deps = revised_profile["provenance"]["dependencies"]
    revised_profile["provenance"]["dependencies"] = [item for item in deps if item["path"] != relpath(old_path)] + [
        dependency_record(new_path, role="three-scalar contract with corrected narrative"),
        dependency_record(Path(__file__), role="narrative-only correction builder"),
    ]
    raw = (json.dumps(revised_profile, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(raw) > 64 * 1024:
        raise ValueError("profile_too_large")
    PROFILE.write_bytes(raw)
    report = {"status": "narrative_corrected_layout_unchanged_live_pending",
              "previous_profile": dependency_record(saved_profile, role="profile version2"),
              "profile": dependency_record(PROFILE, role="current profile version3"),
              "contract": dependency_record(new_path, role="current semantic contract"),
              "field_layout_unchanged": profile["scalars"] == revised_profile["scalars"],
              "code_guards_unchanged": profile["code_guards"] == revised_profile["code_guards"],
              "save_tokens_unchanged": profile["save_tokens"] == revised_profile["save_tokens"],
              "live_validation_pending": True}
    _write_json_new(STAGE / "contract-narrative-correction-001.json", report, overwrite=False)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
