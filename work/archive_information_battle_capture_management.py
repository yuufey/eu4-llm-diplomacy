"""Snapshot and verify batch63 receipts offline after the MCP server exits."""
from __future__ import annotations

import hashlib
import json
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-capture-management-20261027-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261027-information-battle-v30-002"
OLD = ROOT / "work/runtime/information-battle-native-title-20261027-001"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path):
    path = path.resolve()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": digest}


def put(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def copy_new(source, target):
    if source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("snapshot_size_bound:" + str(source))
    target.parent.mkdir(parents=True, exist_ok=True)
    before = pin(source)
    with source.open("rb") as src, target.open("xb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
    after, copied = pin(source), pin(target)
    if before != after or any(copied[k] != before[k] for k in ("bytes", "sha256")):
        raise ValueError("snapshot_changed:" + str(source))
    return {"source": before, "snapshot": copied}


def main():
    if (STAGE / "archive-verification-001.json").exists():
        raise FileExistsError("archive already finalized")
    summary = read(STAGE / "development-summary-001.json")
    if summary["goal"] != "active":
        raise ValueError("full_plan_not_complete")
    freeze = read(STAGE / "source-freeze-002.json")
    if freeze["count"] != 151:
        raise ValueError("source_count")
    for item in freeze["files"]:
        if pin(ROOT / item["source"]["path"]) != item["source"]:
            raise ValueError("runtime_source_changed:" + item["source"]["path"])
        if pin(ROOT / item["snapshot"]["path"]) != item["snapshot"]:
            raise ValueError("runtime_snapshot_changed")
    put(STAGE / "source-post-run-verification-002.json", {
        "status": "passed", "count": 151, "freeze": pin(STAGE / "source-freeze-002.json"),
        "timing": "after formal full002, corrective live002 and retained-log recovery live003 server exits",
    })
    snapshots = []
    for name in ("installation.json", "build-manifest.json", "information-battle-binding.json",
                 "information-battle-status.json", "information-battle-capture-journal.json",
                 "information-battle-raw.jsonl", "control-probe.jsonl"):
        snapshots.append(copy_new(BUILD / name, STAGE / "final-snapshots" / name))
    audits = sorted(BUILD.glob("information-battle-control-audit-*.jsonl"))
    if len(audits) > 128:
        raise ValueError("native_control_audit_count_bound")
    controls = []
    for audit in audits:
        nonce = audit.stem.removeprefix("information-battle-control-audit-")
        files = [audit, BUILD / f"information-battle-started-{nonce}.json",
                 BUILD / f"information-battle-response-{nonce}.json"]
        controls.extend(copy_new(path, STAGE / "native-control-snapshots" / path.name)
                        for path in files if path.is_file())
    journal = read(STAGE / "final-snapshots/information-battle-capture-journal.json")
    native = read(STAGE / "final-snapshots/information-battle-status.json")
    if journal["state"] != "completed-disabled" or journal["owned"] is not False:
        raise ValueError("capture_ownership_not_closed")
    if native["state"] != "disabled":
        raise ValueError("native_source_not_disabled")
    databases = []
    for relative, target_name, role, information in (
        ("managed-live.sqlite3", "managed-live.sqlite3", "live001/002 shared database; ingestion failed", True),
        ("live-acceptance-003/information.sqlite3", "recovered-information.sqlite3", "live003 separate service database", True),
        ("battle-wire6.sqlite", "battle-wire6.sqlite", "live003 separate ingestion database", False),
    ):
        database, target = STAGE / relative, STAGE / "final-snapshots" / target_name
        if target.exists():
            raise FileExistsError(target)
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(target)) as destination:
                source.backup(destination)
                integrity = destination.execute("PRAGMA integrity_check").fetchone()[0]
                active = destination.execute("SELECT COUNT(*) FROM info_config WHERE kind='subscription' AND json_extract(body,'$.state')='active'").fetchone()[0] if information else None
        if integrity != "ok" or (information and active != 0):
            raise ValueError("database_integrity_or_active_subscriptions")
        databases.append({"database": pin(target), "integrity": integrity, "active_subscriptions": active, "role": role})
    put(STAGE / "runtime-snapshots-001.json", {
        "status": "passed", "snapshots": snapshots, "databases": databases,
        "native_control_snapshots": controls,
        "native_source": native["state"], "manager_journal": journal["state"],
    })
    supplements = []
    for name in ("freeze_information_battle_capture_management.py",
                 "run_information_battle_capture_management_regression.py",
                 "validate_information_battle_capture_management_live.py",
                 "validate_information_battle_capture_management_corrective.py",
                 "validate_information_battle_capture_delivery_recovery.py",
                 "finalize_information_battle_capture_management.py",
                 "archive_information_battle_capture_management.py"):
        supplements.append(copy_new(ROOT / "work" / name,
                                    STAGE / "supplemental-source-snapshots" / name))
    put(STAGE / "supplemental-sources-001.json", {
        "status": "passed", "files": supplements,
        "scope": "independent orchestration and acceptance; not part of the frozen bridge/tests full suite",
    })
    previous = read(OLD / "archive-verification-001.json")
    for item in previous["artifacts"]:
        if pin(ROOT / item["path"]) != item:
            raise ValueError("historical_batch62_changed:" + item["path"])
    put(STAGE / "batch62-preservation-001.json", {
        "status": "passed", "artifact_count": len(previous["artifacts"]),
        "verification": pin(OLD / "archive-verification-001.json"),
        "historical_batch61_original_comparison_recovered": False,
    })
    docs = [ROOT / name for name in ("HANDOFF.md", "README(agent).md",
        "docs/信息导出与订阅开发计划.md", "docs/战报订阅采集管理.md", "开发过程自动化.md")]
    if not all("batch63-capture-management-summary" in p.read_text(encoding="utf-8").splitlines()[0]
               for p in docs[:3]):
        raise ValueError("latest_handoff_marker")
    put(STAGE / "document-verification-001.json", {
        "status": "passed", "documents": [pin(p) for p in docs],
        "checks": {"batch63_at_top": True, "goal_active": True,
                   "mature_achievement_warning_automation_retained": "confirm_observed_achievement_warning.py" in docs[-1].read_text(encoding="utf-8")},
    })
    artifacts = [pin(path) for path in sorted(STAGE.rglob("*")) if path.is_file()]
    put(STAGE / "archive-verification-001.json", {
        "status": "passed", "artifact_count": len(artifacts), "artifacts": artifacts,
        "frozen_sources": 151, "goal": "active",
    })
    print(json.dumps({"status": "passed", "artifact_count": len(artifacts)}))


if __name__ == "__main__":
    main()
