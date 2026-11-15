"""Check source references, compile information code, and export coverage."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import py_compile
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
STAGE = ROOT / "work/runtime/information-dynamic-text-20261024-001"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024
CUSTOM_PROFILE_REL = "bridge/information/profiles/custom-localization-memory-1374.json"
CONTRACT2_REL = "work/runtime/information-dynamic-text-20261024-001/dynamic-localization-contract-002.json"
CONTRACT2_SHA = "ea13b783902b9a5410aa808ae7956e03732fe57376383cd0d4ea094ac9f1a5f7"
sys.path.insert(0, str(ROOT))


def bounded_file(path, *, max_bytes=MAX_ARCHIVE_BYTES):
    candidate = Path(path)
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Cannot resolve path: {candidate}") from exc
    if not resolved.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"Path is outside workspace: {candidate}")
    if not resolved.is_file():
        raise ValueError(f"Expected regular file: {candidate}")
    if resolved.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds archival budget: {resolved}")
    return resolved


def digest(path):
    path = bounded_file(path)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def write(path, value):
    destination = Path(path).resolve()
    if not destination.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"Output is outside workspace: {path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if destination.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"Output exceeds archival budget: {destination}")


def read(path):
    path = bounded_file(path)
    return json.loads(path.read_text(encoding="utf-8"))


def read_profile(path):
    path = bounded_file(path, max_bytes=MAX_PROFILE_BYTES)
    return json.loads(path.read_text(encoding="utf-8"))


def check_contract2(profile_path, profile):
    if profile_path.relative_to(ROOT_RESOLVED).as_posix() != CUSTOM_PROFILE_REL:
        return False
    if profile.get("contract_sha256") != CONTRACT2_SHA:
        raise ValueError("custom localization profile top-level contract pin mismatch")
    evidence = profile.get("source_evidence")
    if not isinstance(evidence, dict):
        raise ValueError("custom localization source_evidence is not an object")
    contract = evidence.get("dynamic_localization_contract")
    if not isinstance(contract, dict) or contract.get("path") != CONTRACT2_REL or contract.get("sha256") != CONTRACT2_SHA:
        raise ValueError("custom localization contract2 reference mismatch")
    return True


def main():
    # Catalog construction does not create a live session or open a process.
    from bridge.information.sources import DiplomacySource
    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.static_data import StaticTradeSource
    from bridge.information.mission_definitions import MissionDefinitionIndex
    from bridge.information.missions import MissionInformationSource, NativeMissionReader

    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeCountryStateSource(primary),
        StaticTradeSource(context_provider=primary.context),
        MissionInformationSource(primary, MissionDefinitionIndex(), NativeMissionReader(primary))])
    topics = source.catalog()
    coverage = {"schema_version": 1, "topic_count": len(topics),
        "field_count": sum(len(t["fields"]) for t in topics),
        "available_topics": [t["topic_id"] for t in topics if t["status"] == "available"],
        "topics": topics,
        "configuration": {"native_country_state": True, "static_game_data": True,
            "mission_game_data": True, "literal_prerequisite_derivation": True,
            "branch_flag_map_and_domination_inputs": True, "native_loaded_task_objects": True,
            "native_localization_cache": True, "limited_singleton_query_root_text_derivation": True,
            "dynamic_localization_evaluated": False, "actual_ui_root_scope_verified": False,
            "branch_visibility_evaluated": False, "complete_dlc_inventory": False,
            "implementation_coverage_is_not_full_live_acceptance": True}}
    counts = Counter(f["coverage"] for t in topics for f in t["fields"].values())
    if (coverage["topic_count"], coverage["field_count"], len(coverage["available_topics"])) != (74, 397, 32):
        raise ValueError("Information catalog coverage totals changed")
    if counts != {"available": 49, "partial": 101, "planned": 247}:
        raise ValueError("Information catalog coverage classes changed")
    write(STAGE / "coverage.json", coverage)
    write(ROOT / "docs/信息字段覆盖.json", coverage)

    sources = sorted(set((ROOT / "bridge/information").glob("*.py"))
                     | set((ROOT / "bridge/tests").glob("test_information*.py"))
                     | {ROOT / p for p in ("tools/serve_information.py",
                         "work/validate_information_custom_texts.py", "work/verify_information_custom_texts.py",
                         "work/finalize_information_custom_texts.py", "work/audit_information_custom_text_tests.py", "work/probe_information_common_promotions.py",
                         "work/probe_information_country_builtin_text.py", "work/probe_information_country_builtin_text_complete.py",
                         "work/probe_information_custom_localization.py", "work/probe_information_custom_localization_weights.py",
                         "work/research_information_custom_localization.py", "work/research_information_custom_localization_root.py")})
    compiled = []
    for path in sources:
        path = bounded_file(path)
        py_compile.compile(str(path), doraise=True)
        compiled.append({"path": path.relative_to(ROOT_RESOLVED).as_posix(), "sha256": digest(path), "bytes": path.stat().st_size})
    write(STAGE / "compile-audit.json", {"status": "passed", "file_count": len(compiled), "files": compiled})
    refs = []
    contract2_seen = False
    for profile in sorted((ROOT / "bridge/information/profiles").glob("*.json")):
        profile = bounded_file(profile, max_bytes=MAX_PROFILE_BYTES)
        data = read_profile(profile)
        contract2_seen = check_contract2(profile, data) or contract2_seen
        for name, record in data.get("source_evidence", {}).items():
            if isinstance(record, str):
                path = ROOT / "work/runtime/information-missions-20261024-001" / name
                expected = record
            else:
                path, expected = ROOT / record["path"], record["sha256"]
            path = bounded_file(path)
            actual = digest(path)
            if actual != expected:
                raise ValueError(f"Profile reference changed: {profile.name}/{name}")
            refs.append({"profile": profile.relative_to(ROOT_RESOLVED).as_posix(), "name": name,
                         "path": path.relative_to(ROOT_RESOLVED).as_posix(), "sha256": actual})
    if not contract2_seen:
        raise ValueError("custom localization profile contract2 reference was not found")
    current = [{"path": p.relative_to(ROOT_RESOLVED).as_posix(), "sha256": digest(p)}
               for p in sorted((ROOT / "bridge/information").glob("*.py"))]
    write(STAGE / "source-audit-final.json", {"status": "passed", "profile_reference_count": len(refs),
        "profile_references": refs, "current_production_sources": current})
    print(json.dumps({"status": "passed", "compiled": len(compiled), "profile_references": len(refs),
                      "field_counts": counts}))


if __name__ == "__main__":
    main()
