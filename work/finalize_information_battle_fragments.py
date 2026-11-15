"""Freeze batch18 evidence pointers and verify the current source boundary."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import subprocess

from work.finalize_information_battle_popup import ROOT, load, pin

STAGE = ROOT / "work/runtime/information-battle-fragments-20261025-001"


def main() -> int:
    output = STAGE / "development-summary-001.json"
    assert not output.exists(), "refuse to overwrite a historical checkpoint"
    component = load(STAGE / "component-source-audit-001.json")
    assert component["status"] == "passed_current_fragment_component_audit"
    assert component["conclusion"]["current_fragment_sources_match"]
    preservation = load(STAGE / "production-preservation-001.json")
    assert preservation["conclusion"]["current_mismatch_count"] == 0
    static = load(STAGE / "source-audit-001.json")
    assert static["status"] == "passed_static_research_with_expected_receipt_gap"
    assert len(static["checks"]) == 17 and all(static["checks"].values())
    reassembly = load(STAGE / "python-reassembly-test-001/report-002.json")
    assert reassembly["verification"]["tests_passed"] == 13
    assert reassembly["verification"]["subtests_passed"] == 4
    assert reassembly["verification"]["exit_code"] == 0
    for category in reassembly["source_pins"].values():
        for row in category:
            assert pin(ROOT / row["path"]) == row
    for row in static["source_pins"]:
        actual = pin(ROOT / row["path"])
        assert actual["bytes"] == row["bytes"] and actual["sha256"] == row["sha256"]
    receipt_report = load(STAGE / "query-receipt-test-001/report-002.json")
    assert receipt_report["tests"]["pytest"]["tests"] == 19
    assert receipt_report["tests"]["pytest"]["failures"] == 0
    for row in receipt_report["source_pins"].values():
        assert pin(ROOT / row["path"]) == row

    coverage = load(ROOT / "docs/信息字段覆盖.json")
    counts = Counter(field["coverage"] for topic in coverage["topics"]
                     for field in topic["fields"].values())
    assert len(coverage["topics"]) == 74 and sum(counts.values()) == 397
    assert counts == {"available": 54, "partial": 107, "planned": 236}
    assert not (STAGE / "rea-localized-format-001/run.json").exists()
    paths = {ROOT / row["path"] for row in static["source_pins"]}
    paths.add(Path(__file__).resolve())
    for name in [
        "HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md", "docs/信息字段覆盖.json",
        "docs/逐场战报分片与采集范围.md", "docs/逐场战报窗口与本地日志.md",
        "docs/逐场战报消息与传输.md", "work/finalize_information_battle_popup.py",
        "work/probe_information_battle_capture_scope.py",
        "work/probe_information_message_vtable.py",
        "work/survey_information_battle_capture_gates.py",
        "work/extract_information_battle_fragment_evidence.py",
        "work/freeze_information_battle_fragment_research.py",
        "work/audit_information_battle_fragments_components.py",
        "work/native/information-battle-fragment.h",
        "work/native/tests/information-battle-fragment-test.cpp",
        "work/information_battle_reassembly.py", "work/tests/test_information_battle_reassembly.py",
        "work/native/information-battle-buffer.h", "work/native/information-battle-drain.h",
        "work/native/information-battle-wire.h", "work/native/information-battle-log-writer.h",
        "work/information_battle_log_reader.py", "work/information_battle_transport.py",
        "reverse_engineering/cache_query.py", "reverse_engineering/tests/test_cache_query_postread.py",
    ]:
        paths.add(ROOT / name)
    for name in [
        "research-index-001.json", "source-audit-001.json", "capture-gate-survey-001.json",
        "capture-scope-text-ledger-001.json", "production-preservation-001.json",
        "component-source-audit-001.json", "native-fragment-test-001/report.json",
        "native-fragment-test-001/fragmented-battle-001.log",
        "native-fragment-test-001/python-validation.json",
        "python-reassembly-test-001/report-001.json", "python-reassembly-test-001/report-002.json",
        "python-reassembly-test-001/pytest-output-002.txt",
        "query-receipt-test-001/report.json", "query-receipt-test-001/report-002.json",
    ]:
        paths.add(STAGE / name)
    # Current native executable/report/source dependencies remain independently
    # audited in component-source-audit; preserve its authoritative pointer.
    doc = ROOT / "docs/逐场战报分片与采集范围.md"
    links = []
    for target in re.findall(r"\]\(([^)]+)\)", doc.read_text(encoding="utf-8")):
        if "://" in target or target.startswith("#"):
            continue
        assert (doc.parent / target.split("#", 1)[0]).resolve().is_file(), target
        links.append(target)
    check = subprocess.run(["git", "diff", "--check"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8")
    assert check.returncode == 0, check.stdout + check.stderr
    for path in paths:
        if path.suffix in {".py", ".h", ".cpp", ".md"}:
            assert not any(line.rstrip() != line for line in
                           path.read_text(encoding="utf-8-sig").splitlines()), path
    summary = {
        "schema": "information_battle_fragments_development_checkpoint_v1",
        "goal_status": "active", "goal_complete": False,
        "turn_classification": "progress", "coverage": coverage["counts"],
        "objective_scope": "Full74-topic397-field plan, all phases and LLM-managed subscriptions remain required.",
        "accepted_batch_progress": [
            "Allocation-free native multipart framing with1MiB cap, exact64-byte LE header and whole-payload CRC32.",
            "Persistent reassembly with source binding, same-transaction cursor, conflict/CRC latch and bounded admission/pages.",
            "Actual269-frame checked native log,268 unique outerrecords,5 reconstructed opaque payloads through existing tailer/transport.",
            "Three new static REA sources, exact settings/lookup/formatting and candidate-entry ledger, with one historical receipt gap explicitly retained.",
            "REA postread error receipts repaired without expanding10MiB guard; next new query used fixed runner successfully.",
        ],
        "validation": {
            "static_checks": static["checks"], "component_audit": component["conclusion"],
            "production_preservation": preservation["conclusion"],
            "reassembly": reassembly["verification"],
            "query_runner_tests": receipt_report["tests"],
            "git_diff_check_exit_code": check.returncode,
            "git_diff_check_stderr": check.stderr,
            "document_local_links_checked": links,
            "shell_sessions_collected": [6657, 52519, 79278],
            "historical_full_pytest": {"passed": 2425, "failed": 107,
                                       "errors": 35, "subtests_passed": 1881,
                                       "rerun_this_batch": False},
        },
        "limits": {
            "real_battle_payload_collected": False, "hook_installed": False,
            "game_accessed": False, "InformationService_connected": False,
            "production_information_bridge_changed": False, "B01_B04_available": False,
            "historical_14B33A0_provider_exit_peak_receipt": "unknown_not_backfilled",
            "modified_research_runner": "reverse_engineering/cache_query.py",
            "no_replay_or_business_dispatch": True,
        },
        "next_required": [
            "Investigate181-byte D89A80 from existing router evidence before assuming result-history ownership or war binding.",
            "Close stable war/battle/observer identities and actual eligibility/visibility independently from message settings.",
            "Validate natural hook ABI/unwind/thread/reentrancy and owned complete payload/text lifetime; schedule multipart with retained owned bytes.",
            "Connect actual capture to existing information events/subscriptions and perform per-field live B01-B04 acceptance.",
            "Continue remaining topics/fields and full original plan completion audit.",
        ],
        "source_pins": [pin(path) for path in sorted(paths)],
    }
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"summary": pin(output), "source_count": len(summary["source_pins"]),
                      "goal_complete": False}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
