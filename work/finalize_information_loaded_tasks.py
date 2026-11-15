"""Freeze loaded child-task source, tests and separately typed evidence."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-loaded-tasks-20261024-001"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def read(path):
    if path.stat().st_size > 16*1024*1024:
        raise ValueError(f"JSON read exceeds archival budget: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    acceptance = read(STAGE / "live-acceptance-001/report.json")
    post_reference = read(STAGE / "branch-reference-acceptance-002/report.json")
    branch_manual = read(STAGE / "branch-reference-acceptance-002/manual-result.json")
    branch_provenance = branch_manual["items"][0]["fields"]["unlock_conditions"]["value"]["captured_inputs"]["provenance"]
    capture = read(STAGE / "loaded-tasks-runtime-001.json")
    tests = read(STAGE / "test-summary.json")
    coverage = read(STAGE / "coverage.json")
    if (acceptance["status"] != "passed" or capture["status"] != "observed"
            or capture["loaded_tasks"]["status"] != "observed"
            or not capture["doublepass"]["task_consistent"]
            or acceptance["reference_capture_sha256"] != digest(STAGE / "loaded-tasks-runtime-001.json")):
        raise ValueError("MCP acceptance or its independent capture is incomplete")
    if (post_reference["status"] != "passed"
            or branch_provenance["profile_sha256"] != digest(ROOT / "bridge/information/profiles/mission-branch-memory-1374.json")
            or branch_provenance["probe_sha256"] != digest(ROOT / "bridge/information/mission_branch_memory.py")):
        raise ValueError("Post-reference live branch capture differs from frozen source")
    if (digest(ROOT / "bridge/information/mission_memory.py") != capture["probe_script_sha256"]
            or digest(ROOT / "bridge/information/mission_task_memory.py") != capture["task_reader"]["sha256"]
            or digest(ROOT / "bridge/information/profiles/mission-task-memory-1374.json") != capture["task_reader"]["profile_sha256"]):
        raise ValueError("Captured native readers changed after live acceptance")
    paths = set((ROOT / "bridge/information").glob("*.py"))
    profiles = list((ROOT / "bridge/information/profiles").glob("*.json"))
    paths.update(profiles)
    for profile in profiles:
        for name, record in read(profile).get("source_evidence", {}).items():
            if isinstance(record, str):
                source = ROOT / "work/runtime/information-missions-20261024-001" / name
                expected = record
            else:
                source, expected = ROOT / record["path"], record["sha256"]
            if digest(source) != expected:
                raise ValueError(f"Profile evidence reference changed: {profile.name}/{name}")
            paths.add(source)
    paths.update((ROOT / "bridge/tests").glob("test_information*.py"))
    paths.update((ROOT / "bridge/tests/fixtures").glob("information_*.json"))
    paths.update(ROOT / name for name in (
        "HANDOFF.md", "README(agent).md", "tools/serve_information.py",
        "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md", "docs/信息字段覆盖.json",
        "docs/信息接口使用说明.md", "docs/信息服务合同.md", "docs/任务信息接口.md",
        "docs/任务定义接口.md", "docs/任务原生读取合同.md", "docs/任务实际子任务接口.md",
        "docs/任务前置状态接口.md", "docs/任务分支输入接口.md", "docs/任务分支引擎路径.md",
        "docs/任务本地化来源.md", "work/validate_information_live.py",
        "work/validate_information_loaded_tasks.py", "work/research_information_mission_display.py",
        "work/research_information_mission_localization.py", "work/finalize_information_loaded_tasks.py",
        "work/runtime/diplomacy-observer-20261024-information-a/installation.json"))
    paths.update(path for path in STAGE.rglob("*") if path.is_file()
                 and path.suffix in {".json", ".xml", ".log", ".txt", ".py"}
                 and "delivery" not in path.relative_to(STAGE).parts)
    output = args.output.resolve()
    if not output.is_relative_to(STAGE.resolve()) or output.exists():
        raise ValueError("Archive must be a new directory inside this batch")
    for path in paths:
        if not path.resolve().is_relative_to(ROOT) or path.stat().st_size > 16*1024*1024:
            raise ValueError(f"Snapshot source exceeds workspace/budget: {path}")
    output.mkdir(parents=True, exist_ok=False)
    entries = []
    for path in sorted(paths, key=str):
        relative = path.relative_to(ROOT)
        destination = output / "files" / relative
        expected = digest(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        if digest(destination) != expected or digest(path) != expected:
            raise ValueError(f"Source changed during snapshot: {path}")
        entries.append({"path":relative.as_posix(), "bytes":path.stat().st_size, "sha256":expected})
    result = {"format":"information_loaded_tasks_delivery_v1", "status":"source_and_evidence_snapshot_verified",
        "goal_complete":False, "file_count":len(entries), "files":entries, "tests":tests, "acceptance":acceptance,
        "post_reference_acceptance":post_reference,
        "configured_coverage":{"topics":coverage["topic_count"], "fields":coverage["field_count"],
            "partly_routable_topics":len(coverage["available_topics"]),
            "field_counts":dict(Counter(f["coverage"] for t in coverage["topics"] for f in t["fields"].values())),
            "registration_is_not_full_live_acceptance":True},
        "evidence_types_separated":["REA static", "ordinary static", "runtime RPM", "derived information", "fixture tests"],
        "remaining":["current displayed branch selection", "complete trigger evaluation and progress",
                     "runtime localization and dynamic substitutions", "remaining country/relation/trade/modifier fields",
                     "positive live changes and new event capture", "complete per-battle contents", "all target fields in 74-topic plan"]}
    manifest = output / "manifest.json"
    manifest.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key:result[key] for key in ("format","status","goal_complete","file_count","configured_coverage")}))


if __name__ == "__main__":
    main()
