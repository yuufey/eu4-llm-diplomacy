"""Freeze batch17 source pointers without changing historical artifacts."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-popup-20261025-001"


def pin(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for part in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(part)
    return {"path": path.relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def load(path: Path) -> dict:
    assert path.stat().st_size <= 2 * 1024 * 1024
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> int:
    output = STAGE / "development-summary-001.json"
    assert not output.exists(), "historical summary must not be overwritten"
    component = load(STAGE / "component-source-audit-001.json")
    assert component["status"] == "passed_current_source_audit"
    assert component["conclusion"]["current_source_pins_have_no_pending"]
    static = load(STAGE / "source-audit-002.json")
    assert static["all_checks_passed"]
    reader = load(STAGE / "python-log-test-001/report-006.json")
    assert reader["exit_code"] == 0 and reader["pytest"]["passed"] == 33
    assert reader["pytest"]["subtests_passed"] == 33
    assert reader["pytest"]["skipped"] == 0
    for name, expected in reader["source_files"].items():
        actual = pin(ROOT / name)
        assert actual["sha256"] == expected["sha256"]
        assert actual["bytes"] == expected["bytes"]

    coverage = load(ROOT / "docs/信息字段覆盖.json")
    counts = Counter(field["coverage"] for topic in coverage["topics"]
                     for field in topic["fields"].values())
    assert len(coverage["topics"]) == 74 and sum(counts.values()) == 397
    assert dict(counts) == {"available": 54, "partial": 107, "planned": 236}

    paths = [Path(__file__).resolve()]
    for name in [
        "HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md", "docs/信息字段覆盖.json",
        "docs/逐场战报消息与传输.md", "docs/逐场战报窗口与本地日志.md",
        "work/probe_information_battle_popup_fields.py",
        "work/probe_information_message_vtable.py",
        "work/extract_information_battle_popup_evidence.py",
        "work/freeze_information_battle_popup_research.py",
        "work/audit_information_battle_popup_components.py",
        "work/native/information-battle-log-writer.h",
        "work/native/tests/information-battle-log-writer-test.cpp",
        "work/native/information-battle-wire.h", "work/native/information-battle-drain.h",
        "work/native/information-battle-buffer.h", "work/information_battle_log_reader.py",
        "work/tests/test_information_battle_log_reader.py",
        "work/information_battle_transport.py", "work/tests/test_information_battle_transport.py",
    ]:
        paths.append(ROOT / name)
    for name in [
        "research-index-001.json", "research-index-002.json",
        "source-audit-001.json", "source-audit-002.json", "popup-field-ledger-001.json",
        "popup-template-widget-context-001.json", "popup-template-widget-context-002.json",
        "production-preservation-001.json", "component-source-audit-001.json",
        "native-log-test-001/report.json", "native-log-test-001/report-002.json",
        "native-log-test-001/information-battle-log-writer-test-002.exe",
        "native-log-test-001/checked-battle-001.log",
        "python-log-test-001/report-004.json", "python-log-test-001/report-005.json",
        "python-log-test-001/report-006.json", "python-log-test-001/pytest-output-006.txt",
    ]:
        paths.append(STAGE / name)
    index = load(STAGE / "research-index-002.json")
    for query in index["rea_evidence"]:
        assert query["run"]["exit_code"] == 0
        assert all(not process["still_running_same_process"]
                   for process in query["run"]["processes"])
        directory = (ROOT / query["evidence"]["path"]).parent
        for name in ["evidence.json", "request.json", "run.json",
                     "selected-evidence-001.json", "readback-recovery-001.json"]:
            paths.append(directory / name)

    linked = []
    doc = ROOT / "docs/逐场战报窗口与本地日志.md"
    for target in re.findall(r"\]\(([^)]+)\)", doc.read_text(encoding="utf-8")):
        if "://" in target or target.startswith("#"):
            continue
        path = (doc.parent / target.split("#", 1)[0]).resolve()
        assert path.is_file(), f"missing document link: {target}"
        linked.append(target)
    check = subprocess.run(["git", "diff", "--check"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8")
    assert check.returncode == 0, check.stdout + check.stderr
    for path in paths:
        if path.suffix in {".py", ".h", ".cpp", ".md"}:
            assert not any(line.rstrip() != line for line in
                           path.read_text(encoding="utf-8-sig").splitlines()), path
    summary = {
        "schema": "information_battle_popup_development_checkpoint_v1",
        "goal_status": "active", "goal_complete": False,
        "turn_classification": "progress",
        "scope": "Full plan: 74 topics, 397 fields, phases 2/3/4 and LLM-managed subscriptions remain required.",
        "coverage": coverage["counts"],
        "accepted_batch_progress": [
            "Four fixed1374 static REA procedures, separate ordinary PE literals and reproducible popup field/copy ledger.",
            "Checked Windows file writer with rollback, bounded tail repair and nonblocking exclusive locks.",
            "Matching shared-lock tailer with receiver-before-cursor acknowledgement and restart/idempotency/CAS guards.",
            "Actual C++ header+A/A/B log consumed as two durable opaque records, including 4096-byte payload.",
        ],
        "validation": {
            "static_audit_checks": static["checks"],
            "component_audit": component["conclusion"],
            "work_pytest": reader["pytest"],
            "production_files_unchanged": 82,
            "git_diff_check_exit_code": check.returncode,
            "git_diff_check_stderr": check.stderr,
            "new_document_local_links_checked": linked,
            "historical_full_pytest": {"passed": 2425, "failed": 107, "errors": 35,
                                       "subtests_passed": 1881, "rerun_this_batch": False},
            "shell_sessions_collected": [44472, 47104, 74909, 17868],
        },
        "limits": {
            "game_or_process_access": False, "installed_DLL_changed": False,
            "production_bridge_changed": False, "business_dispatch": False,
            "B01_B04_available": False, "InformationService_connected": False,
            "power_loss_durability_tested": False,
        },
        "next_required": [
            "Natural capture ABI/thread/reentrancy and observer-visible scope; stable battle/war/observer identities.",
            "Owned complete control/text payload, encoding and lifetime; multipart for payloads exceeding 4096 bytes.",
            "Connect actual capture and persistent records to existing information events/subscriptions; live per-field battle acceptance.",
            "Continue all remaining topics/fields and full plan completion audit; no historical business replay.",
        ],
        "source_pins": [pin(path) for path in dict.fromkeys(paths)],
    }
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"summary": pin(output), "source_count": len(summary["source_pins"]),
                      "goal_complete": False}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
