"""Snapshot information sources and bounded acceptance evidence without game calls."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


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
    args.output.mkdir(parents=True, exist_ok=False)
    stage = ROOT / "work/runtime/information-stage2-20261024-001"
    installation = ROOT / "work/runtime/diplomacy-observer-20261024-information-a"
    paths = set((ROOT / "bridge/information").glob("*.py"))
    paths.update((ROOT / "bridge/tests").glob("test_information*.py"))
    paths.update((ROOT / "bridge/tests/fixtures").glob("information_country*.json"))
    paths.update(ROOT / name for name in (
        "HANDOFF.md", "README(agent).md", "tools/serve_information.py",
        "work/archive_information_live.py", "work/finalize_information_stage2.py",
        "work/validate_information_live.py", "work/validate_information_static.py",
        "work/verify_information_country_save.py", "work/probe_information_startup.py",
        "docs/信息导出开发进展.md", "docs/信息导出与订阅开发计划.md",
        "docs/信息接口使用说明.md", "docs/信息服务合同.md", "docs/信息字段覆盖.json",
        "docs/国家资源信息接口.md", "docs/静态贸易信息接口.md", "docs/任务信息来源核对.md"))
    paths.update(stage / name for name in (
        "test-summary.json", "pytest-information-final.xml", "pytest-full.xml", "pytest-full.log",
        "save-country-crosscheck.json", "mission-source-review.json"))
    for directory in (stage / "live-acceptance-001", stage / "static-acceptance-semantic-final"):
        paths.update(path for path in directory.iterdir() if path.suffix in {".json", ".jsonl", ".txt"})
    paths.update(installation / name for name in (
        "installation.json", "build-manifest.json", "information-preflight-health.json",
        "information-preflight-control.json", "startup-path-20261024-information-a.json",
        "startup-path-rea-capture-block-20261024.json", "current-dialogs-002.json"))
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
        assert digest(destination) == expected and digest(path) == expected, path
        entries.append({"path": relative.as_posix(), "bytes": size, "sha256": expected})
    report = {"format": "information_stage2_delivery_v1", "status": "source_and_evidence_snapshot_verified",
              "goal_complete": False, "file_count": len(entries), "files": entries,
              "acceptance": {"live": "live-acceptance-001/report.json",
                             "static": "static-acceptance-semantic-final/report.json",
                             "country_save": "save-country-crosscheck.json",
                             "information_tests_passed": 108,
                             "all_repository_tests_passed": False},
              "remaining": ["positive live change and new event capture", "actual loaded missions and progress",
                            "remaining country and relation fields", "runtime trade and modifiers",
                            "complete per-battle events", "all 74 topics and target fields"],
              "read_only_archival": True}
    (args.output / "manifest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "files"}))


if __name__ == "__main__":
    main()
