"""Create the separately pinned F02 quality profile from retained evidence."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.local_config import game_exe
from bridge.information import mission_memory as mm

STAGE = ROOT / "work/runtime/information-foreign-military-quality-20261029-001"
PROFILES = ROOT / "bridge/information/profiles"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
MODEL_CODE_SHA = "490fcba6edcf3852feb6f1fefb6fc58dbd435fe9a2e8e8c98d9ac2885b473544"


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load(path):
    path = Path(path)
    if not 0 < path.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError("bounded JSON size: " + str(path))
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path):
    path = Path(path).resolve()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha(path)}


def build():
    executable = Path(game_exe())
    if sha(executable) != EXE_SHA:
        raise ValueError("EXE build mismatch")
    guards, sources = [], {}

    def source(path):
        row = pin(path)
        sources[row["path"]] = row
        return row

    def guard(row, prefix=""):
        code_hex = row.get("bytes") if isinstance(row.get("bytes"), str) else row.get("hex", row.get("bytes_hex"))
        code = bytes.fromhex(code_hex)
        rva = int(row.get("rva", row.get("rva_start")), 0)
        end = int(row.get("end_rva_exclusive", row.get("rva_end_exclusive")), 0)
        if not code or end != rva + len(code) or hashlib.sha256(code).hexdigest() != row["sha256"]:
            raise ValueError("guard integrity: " + row["name"])
        if mm._read_pe_rva_bytes(executable, rva, len(code)) != code:
            raise ValueError("guard differs from EXE: " + row["name"])
        guards.append({"name": prefix + row["name"], "rva": hex(rva),
            "end_rva_exclusive": hex(end), "bytes": code.hex(), "sha256": row["sha256"]})

    def profile(name, selected=None):
        path = PROFILES / name
        document = load(path)
        if document["executable"]["sha256"] != EXE_SHA:
            raise ValueError("profile build mismatch")
        source(path)
        rows = document.get("source_evidence", [])
        if isinstance(rows, dict):
            rows = list(rows.values())
        rows = list(rows) + document.get("layout_dependencies", [])
        if isinstance(document.get("source_index"), dict):
            rows.append(document["source_index"])
        for expected in rows:
            actual = source(ROOT / expected["path"])
            if actual["sha256"] != expected["sha256"] or ("bytes" in expected and actual["bytes"] != expected["bytes"]):
                raise ValueError("dependency mismatch: " + actual["path"])
        for row in document["code_guards"]:
            if selected is None or row["name"] in selected:
                guard(row, document["profile_id"] + ".")

    profile("foreign-technology-memory-1374-v2.json")
    profile("military-morale-memory-1374.json", {"army_country_scale_consumer", "navy_country_scale_consumer"})
    profile("military-tradition-memory-1374.json")
    profile("military-professionalism-memory-1374.json")
    profile("military-effective-memory-1374-v2.json")
    profile("religious-unity-memory-1374.json", {"effective_unity_cache"})
    profile("localization-memory-1374.json")
    core = load(STAGE / "quality-core-ordinary-review-001.json")
    for row in core["ordinary_code_guards"]:
        if row["relocation_sites"] != [] or row["aslr_invariant"] is not True:
            raise ValueError("core relocation")
        guard(row, "quality.")
    registration = load(STAGE / "quality-registration-ordinary-001.json")
    for row in registration["guard_ranges"]:
        if row["base_relocations_intersecting"] != [] or row["aslr_invariant_for_selected_bytes"] is not True:
            raise ValueError("registration relocation")
        guard(row, "quality.")

    evidence = ["quality-core-ordinary-review-001.json", "quality-core-ordinary-correction-001.json",
        "quality-registration-ordinary-001.json", "quality-page-registration-review-001.json",
        "quality-native-contract-001.json", "quality-native-contract-correction-001.json",
        "quality-modifier-reuse-correction-001.json", "quality-country-filter-reuse-001.json",
        "quality-row-filter-controls-001.json", "research-live-001/research-live-001.json",
        "rea-army-quality-row-builder-001/evidence.json", "rea-naval-quality-cell-builder-001/evidence.json",
        "rea-quality-page-global-gate-001/evidence.json", "rea-quality-country-row-enumerator-001/evidence.json",
        "rea-naval-selected-model-name-001/evidence.json",
        "ordinary-quality-model-name-001/ordinary-quality-model-name-001.json"]
    for name in evidence:
        source(STAGE / name)
    source(ROOT / "work/runtime/information-religious-unity-20261025-001/rea-country-modifier-cache-001/evidence.json")
    model_code = mm._read_pe_rva_bytes(executable, 0xAD8C10, 0xAD8CCD - 0xAD8C10)
    if hashlib.sha256(model_code).hexdigest() != MODEL_CODE_SHA:
        raise ValueError("model getter bytes mismatch")
    guard({"name": "selected_model_name", "rva": "0xad8c10", "end_rva_exclusive": "0xad8ccd",
           "bytes": model_code.hex(), "sha256": MODEL_CODE_SHA}, "quality.")
    model_sources = [source(STAGE / name) for name in (
        "rea-naval-selected-model-name-001/evidence.json",
        "ordinary-quality-model-name-001/ordinary-quality-model-name-001.json",
        "research-live-001/research-live-001.json")]
    if len({row["name"] for row in guards}) != len(guards):
        raise ValueError("duplicate guard names")
    return {"profile_id": "foreign-quality-memory-1374", "profile_version": 1,
        "game_version": "1.37.4", "executable": {"sha256": EXE_SHA, "image_base": "0x140000000"},
        "observer": "FRA", "target_scope": "resolved_foreign_country",
        "source_evidence": sorted(sources.values(), key=lambda row: row["path"]), "layout_dependencies": [],
        "code_guards": guards,
        "model_profile": {"schema": "information.foreign_quality_model_profile.v1", "executable_sha256": EXE_SHA,
            "vt_rva": "0x1ce3700", "method_rva": "0xad8c10", "method_end_rva_exclusive": "0xad8ccd",
            "method_code_hex": model_code.hex(), "method_code_sha256": MODEL_CODE_SHA, "source_pins": model_sources},
        "semantics": {"quality_field": "F02.military_quality", "quality_visibility_field": "F02.military_quality_visibility",
            "component_count": 12, "options_index": "0x17", "options_byte_offset": "0x5c",
            "observer_projection": "independent bound FRA fullref; country-view and quality-ledger conditions",
            "row_control_contract": "explicit target query independent of physical ledger checkbox/search choices",
            "actual_UI_observed": False, "complete": False,
            "gaps": ["cache freshness", "main-thread atomicity", "unsupported processors and TLS",
                     "unsupported selected-model vtables", "localization hash collision not excluded"]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if not args.write:
        parser.error("--write required; no files changed")
    profile = build()
    path = PROFILES / "foreign-quality-memory-1374.json"
    data = (json.dumps(profile, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(data)
    print(json.dumps({"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "guards": len(profile["code_guards"]),
                      "guard_bytes": sum(len(bytes.fromhex(row["bytes"])) for row in profile["code_guards"])}))


if __name__ == "__main__":
    main()
