"""Freeze task prerequisites, branch inputs and their separately typed evidence."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-branches-20261024-001"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--acceptance", default="prerequisite-acceptance-003")
    args = parser.parse_args()
    acceptance = json.loads((STAGE / args.acceptance / "report.json").read_text(encoding="utf-8"))
    if acceptance["status"] != "passed":
        raise ValueError("Final MCP acceptance has not passed")
    tests = json.loads((STAGE / "test-summary.json").read_text(encoding="utf-8"))
    coverage = json.loads((STAGE / "coverage.json").read_text(encoding="utf-8"))
    profiles = list((ROOT / "bridge/information/profiles").glob("*.json"))
    for profile in profiles:
        value = json.loads(profile.read_text(encoding="utf-8"))
        for name, record in value.get("source_evidence", {}).items():
            if isinstance(record, str):
                source = ROOT / "work/runtime/information-missions-20261024-001" / name
                expected = record
            else:
                source, expected = ROOT / record["path"], record["sha256"]
            if digest(source) != expected:
                raise ValueError(f"Profile evidence reference changed: {profile.name}/{name}")
    paths = set((ROOT / "bridge/information").glob("*.py"))
    paths.update(profiles)
    paths.update((ROOT / "bridge/tests").glob("test_information*.py"))
    paths.update((ROOT / "bridge/tests/fixtures").glob("information_*.json"))
    paths.update(ROOT / name for name in (
        "HANDOFF.md", "README(agent).md", "tools/serve_information.py",
        "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md", "docs/信息字段覆盖.json",
        "docs/信息接口使用说明.md", "docs/信息服务合同.md", "docs/任务信息接口.md",
        "docs/任务定义接口.md", "docs/任务原生读取合同.md", "docs/任务前置状态接口.md",
        "docs/任务分支输入接口.md", "docs/任务分支求值缺口.md", "docs/任务分支实时输入来源.md",
        "docs/任务分支引擎路径.md", "work/research_information_branch_inputs.py",
        "work/research_information_map_setup.py", "work/research_information_dlc.py",
        "work/research_information_missions.py", "work/validate_information_live.py",
        "work/validate_information_prerequisites.py", "work/finalize_information_branches.py"))
    paths.update(path for path in STAGE.rglob("*") if path.is_file()
                 and path.suffix in {".json", ".xml", ".log", ".txt", ".py"}
                 and "delivery" not in path.relative_to(STAGE).parts)
    paths.update(path for path in (ROOT / "work/runtime/branch-inputs-before-dlc-001").iterdir() if path.is_file())
    paths.add(ROOT / "work/runtime/diplomacy-observer-20261024-information-a/installation.json")
    args.output.mkdir(parents=True, exist_ok=False)
    entries = []
    for path in sorted(paths, key=str):
        size = path.stat().st_size
        if size > 16 * 1024 * 1024:
            raise ValueError(f"Snapshot file exceeds 16 MiB: {path}")
        relative = path.relative_to(ROOT)
        destination = args.output / "files" / relative
        expected = digest(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        if digest(destination) != expected or digest(path) != expected:
            raise ValueError(f"Source changed during snapshot: {path}")
        entries.append({"path": relative.as_posix(), "bytes": size, "sha256": expected})
    result = {
        "format": "information_branch_inputs_delivery_v1", "status": "source_and_evidence_snapshot_verified",
        "goal_complete": False, "file_count": len(entries), "files": entries, "tests": tests,
        "acceptance": acceptance, "evidence_types_separated": ["REA static", "ordinary static", "runtime RPM", "derived information", "fixture tests"],
        "configured_coverage": {"topics": coverage["topic_count"], "fields": coverage["field_count"],
            "partly_routable_topics": len(coverage["available_topics"]),
            "field_counts": dict(Counter(field["coverage"] for topic in coverage["topics"] for field in topic["fields"].values())),
            "registration_is_not_full_live_acceptance": True},
        "remaining": ["root potential relation to displayed branches", "task trigger evaluation and progress",
                      "complete DLC inventory and thread-local DLC paths", "remaining country, relation, trade and modifier fields",
                      "positive live changes and new event capture", "complete per-battle contents", "all target fields in the 74-topic plan"],
        "read_only_archival": True,
    }
    (args.output / "manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("format", "status", "goal_complete", "file_count", "configured_coverage")}))


if __name__ == "__main__":
    main()
