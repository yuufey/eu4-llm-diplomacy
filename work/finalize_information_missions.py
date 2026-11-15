"""Freeze mission source code and bounded evidence without any game operations."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-missions-20261024-001"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    acceptance = json.loads((STAGE / "live-acceptance-003/report.json").read_text(encoding="utf-8"))
    if acceptance["status"] != "passed":
        raise ValueError("The final mission acceptance has not passed")
    summary = json.loads((STAGE / "test-summary.json").read_text(encoding="utf-8"))
    coverage = json.loads((STAGE / "live-acceptance-003/coverage.json").read_text(encoding="utf-8"))
    profile = ROOT / "bridge/information/profiles/mission-memory-1374.json"
    contract = json.loads(profile.read_text(encoding="utf-8"))
    for name, expected in contract["source_evidence"].items():
        if digest(STAGE / name) != expected:
            raise ValueError(f"Static contract evidence changed: {name}")
    paths = set((ROOT / "bridge/information").glob("*.py"))
    paths.update((ROOT / "bridge/information/profiles").glob("*.json"))
    paths.update((ROOT / "bridge/tests").glob("test_information*.py"))
    paths.update((ROOT / "bridge/tests/fixtures").glob("information_*.json"))
    paths.update(ROOT / name for name in (
        "HANDOFF.md", "README(agent).md", "tools/serve_information.py",
        "docs/信息导出开发进展.md", "docs/信息导出与订阅开发计划.md",
        "docs/信息接口使用说明.md", "docs/信息服务合同.md", "docs/信息字段覆盖.json",
        "docs/任务信息接口.md", "docs/任务定义接口.md", "docs/任务信息来源核对.md",
        "docs/任务原生读取合同.md", "docs/任务分支求值缺口.md", "docs/国家资源信息接口.md", "docs/静态贸易信息接口.md",
        "work/probe_information_missions.py", "work/research_information_missions.py",
        "work/validate_information_missions.py", "work/validate_information_live.py",
        "work/finalize_information_missions.py", "work/audit_information_mission_profile.py"))
    paths.update(path for path in STAGE.iterdir() if path.is_file() and path.suffix in {".json", ".xml", ".log"})
    paths.update((STAGE / "profile-reference-before-001").iterdir())
    for name in ("live-acceptance-001", "live-acceptance-002", "live-acceptance-003"):
        paths.update(path for path in (STAGE / name).iterdir()
                     if path.is_file() and path.suffix in {".json", ".jsonl", ".txt", ".log"})
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
            raise ValueError(f"Snapshot changed during copying: {path}")
        entries.append({"path": relative.as_posix(), "bytes": size, "sha256": expected})
    report = {
        "format": "information_missions_delivery_v1", "status": "source_and_evidence_snapshot_verified",
        "goal_complete": False, "file_count": len(entries), "files": entries,
        "acceptance": acceptance, "tests": summary,
        "profile_sha256": digest(profile), "executable_sha256": contract["executable"]["sha256"],
        "configured_coverage": {
            "topics": coverage["topic_count"], "fields": coverage["field_count"],
            "partly_routable_topics": len(coverage["available_topics"]),
            "field_counts": dict(Counter(field["coverage"] for topic in coverage["topics"]
                                         for field in topic["fields"].values())),
            "registration_is_not_full_live_acceptance": True},
        "remaining": ["mission branch visibility and condition evaluation", "mission names and progress",
                      "remaining country, relation, modifier and runtime trade fields",
                      "positive live changes and new lifecycle events", "complete per-battle event contents",
                      "all target fields in the 74-topic plan"],
        "read_only_archival": True,
    }
    (args.output / "manifest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("format", "status", "goal_complete", "file_count", "configured_coverage")}))


if __name__ == "__main__":
    main()
