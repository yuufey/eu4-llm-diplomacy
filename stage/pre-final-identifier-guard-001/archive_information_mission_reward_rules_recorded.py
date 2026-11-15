"""Archive the bounded recorded M04 rule-projection evidence.

This command performs only local hash and shape checks.  It never opens a
game, dispatches an MCP request, or reads the recorded SQLite/native result
dumps.  The output directory must not already exist.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
RECORDED = ROOT / "work/runtime/information-mission-rewards-20261025-001/recorded-mcp-002"
FIXTURE = ROOT / "bridge/tests/fixtures/information_mission_reward_rules_recorded_1374.json"
TEST = ROOT / "bridge/tests/test_information_mission_reward_rules_recorded.py"
HELPER = ROOT / "bridge/information/mission_reward_rules.py"
RUNNER = ROOT / "work/validate_information_mission_reward_rules_recorded.py"
REPORT = RECORDED / "report.json"
INPUTS = RECORDED / "fixture-inputs.json"
AST_EXPECTED = RECORDED / "ast-expected.json"

EXPECTED_REPORT_SHA256 = "bcdc73810b2042820191a878b39b8fe40a12bb2be5788550d2dc1aca16b9636e"
EXPECTED_INPUTS_SHA256 = "fc17d6d3c8e4ae5fd8f475446ba42dc3cc4db12e57573d73d9441794ae95382b"
EXPECTED_HELPER_SHA256 = "35831adc19d8f6cc82b7723efc85c4778234edf449327d5dfdab592985c7b800"
EXPECTED_RUNNER_SHA256 = "dd674158b2316775e0a99c8d8a89cad89aee4d0578ded602b883954e7a6a44a5"

MAX_ARCHIVE_FILE_BYTES = 16 * 1024 * 1024


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            result.update(block)
    return result.hexdigest()


def load_json(path: Path):
    size = path.stat().st_size
    if size > MAX_ARCHIVE_FILE_BYTES:
        raise ValueError(f"Refusing to load an oversized evidence file: {path} ({size} bytes)")
    return json.loads(path.read_text(encoding="utf-8"))


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_sources():
    for path in (FIXTURE, TEST, HELPER, RUNNER, REPORT, INPUTS, AST_EXPECTED):
        _require(path.is_file(), f"Missing archive input: {path}")

    report_sha = digest(REPORT)
    inputs_sha = digest(INPUTS)
    helper_sha = digest(HELPER)
    runner_sha = digest(RUNNER)
    ast_sha = digest(AST_EXPECTED)
    fixture = load_json(FIXTURE)
    report = load_json(REPORT)
    inputs = load_json(INPUTS)
    ast_expected = load_json(AST_EXPECTED)

    _require(report_sha == EXPECTED_REPORT_SHA256, "recorded-mcp-002 report hash changed")
    _require(inputs_sha == EXPECTED_INPUTS_SHA256, "recorded-mcp-002 fixture-inputs hash changed")
    _require(helper_sha == EXPECTED_HELPER_SHA256, "reward-rule helper hash changed")
    _require(runner_sha == EXPECTED_RUNNER_SHA256, "independent validation runner hash changed")
    _require(report.get("status") == "passed", "recorded acceptance report is not passed")
    _require(report.get("mode") == "recorded", "acceptance report is not recorded")
    _require(report.get("save_is_recorded") is True, "acceptance report is not save-recorded")
    _require(report.get("not_a_live_state_fallback") is True, "recorded report lacks live-state guard")
    _require(report.get("native_query_invoked") is False, "recorded report claims native query invocation")

    _require(fixture.get("schema") == "information_mission_reward_rules_recorded_fixture_v2",
             "unexpected recorded fixture schema")
    _require(fixture.get("fixture_kind") == "recorded_current_definition_rule_inventory",
             "fixture is not a current-definition rule inventory")
    _require(fixture.get("mode") == "recorded" and fixture.get("live_state") is False,
             "fixture is not explicitly recorded")
    _require(fixture.get("not_a_live_state_fallback") is True,
             "fixture lacks its non-live fallback guard")
    _require(fixture.get("native_query_invoked") is False,
             "fixture claims native query invocation")
    _require(fixture.get("task_membership_source") == "current_definitions_for_captured_roots",
             "fixture uses an unproven loaded-task membership source")
    _require(fixture.get("loaded_task_membership_verified") is False,
             "fixture claims loaded-task membership verification")
    _require(fixture.get("definition_rules_previously_loaded_verified") is False,
             "fixture claims historical definition loading verification")
    _require(fixture.get("recorded_context", {}).get("session_id") is None,
             "recorded fixture contains a fabricated session")
    _require(fixture.get("save", {}).get("mode") == "recorded",
             "fixture save is not recorded")
    _require(fixture.get("save", {}).get("country") == "FRA", "fixture observer is not FRA")
    _require(len(fixture.get("selected_roots", [])) == 18, "fixture root count changed")
    task_count = sum(len(root.get("tasks", [])) for root in fixture["selected_roots"])
    _require(task_count == 61, "fixture selected task count changed")
    _require(fixture["source"]["recorded_mcp_report_sha256"] == report_sha,
             "fixture does not pin recorded report")
    _require(fixture["source"]["fixture_inputs_sha256"] == inputs_sha,
             "fixture does not pin recorded inputs")
    _require(fixture["source"]["independent_ast_expected_sha256"] == ast_sha,
             "fixture does not pin independent AST expected values")
    _require(fixture["expected"] == report["expected"],
             "fixture expected counts differ from acceptance report")
    _require(fixture["source"]["save_sha256"] == inputs["save"]["sha256"],
             "fixture save provenance differs from recorded inputs")
    _require(ast_expected.get("conditions_evaluated") is False,
             "independent expected artifact claims condition evaluation")
    _require(ast_expected.get("effects_applied") is False,
             "independent expected artifact claims effect application")
    for field, count in (("claims", 24), ("casus_belli", 2), ("trade_modifiers", 2)):
        _require(report["expected"]["full"][field]["occurrence_count"] == count,
                 f"full {field} count changed")
        _require(len(fixture["expected_occurrence_tuples"]["full"][field]) == count,
                 f"independent {field} tuples changed")

    return {
        "fixture": fixture,
        "report": report,
        "hashes": {
            "fixture": digest(FIXTURE),
            "test": digest(TEST),
            "helper": helper_sha,
            "runner": runner_sha,
            "report": report_sha,
            "fixture_inputs": inputs_sha,
            "independent_ast_expected": ast_sha,
        },
        "task_count": task_count,
    }


def copy_streaming(source: Path, destination: Path):
    size = source.stat().st_size
    if size > MAX_ARCHIVE_FILE_BYTES:
        raise ValueError(f"Refusing to archive an oversized file: {source} ({size} bytes)")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, destination.open("wb") as dst:
        shutil.copyfileobj(src, dst, length=65536)
    _require(digest(destination) == digest(source), f"Archive copy changed: {source}")
    return {"path": destination.relative_to(destination.parents[0]).as_posix(),
            "bytes": size, "sha256": digest(source)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory receiving the bounded archive")
    args = parser.parse_args()
    checked = verify_sources()
    output = args.output.resolve()
    _require(not output.exists(), f"Archive output already exists: {output}")
    output.mkdir(parents=True)

    files = [
        (FIXTURE, "fixture/information_mission_reward_rules_recorded_1374.json"),
        (TEST, "tests/test_information_mission_reward_rules_recorded.py"),
        (HELPER, "source/mission_reward_rules.py"),
        (RUNNER, "research/validate_information_mission_reward_rules_recorded.py"),
        (REPORT, "evidence/recorded-mcp-002/report.json"),
        (INPUTS, "evidence/recorded-mcp-002/fixture-inputs.json"),
        (AST_EXPECTED, "evidence/recorded-mcp-002/ast-expected.json"),
        (Path(__file__).resolve(), "archive_information_mission_reward_rules_recorded.py"),
    ]
    entries = []
    for source, relative in files:
        destination = output / relative
        copy_streaming(source, destination)
        entries.append({"path": relative, "bytes": source.stat().st_size, "sha256": digest(source)})

    report = {
        "format": "information_mission_reward_rules_recorded_archive_v1",
        "status": "source_and_recorded_evidence_snapshot_verified",
        "goal_complete": False,
        "recorded_only": True,
        "native_query_invoked": False,
        "file_count": len(entries),
        "files": entries,
        "provenance": {
            "recorded_mcp_report_sha256": checked["hashes"]["report"],
            "fixture_inputs_sha256": checked["hashes"]["fixture_inputs"],
            "independent_ast_expected_sha256": checked["hashes"]["independent_ast_expected"],
            "helper_sha256": checked["hashes"]["helper"],
            "validation_runner_sha256": checked["hashes"]["runner"],
            "save_sha256": checked["fixture"]["save"]["sha256"],
            "observer": "FRA",
            "game_version": "1.37.4",
            "task_membership_source": checked["fixture"]["task_membership_source"],
            "selected_root_count": len(checked["fixture"]["selected_roots"]),
            "selected_task_count": checked["task_count"],
        },
        "expected_full_counts": {
            field: checked["report"]["expected"]["full"][field]
            for field in ("claims", "casus_belli", "trade_modifiers")
        },
        "limitations": [
            "Rules are current static definitions for captured roots, not proof of historical loaded task membership.",
            "Condition triggers and reward effects are not evaluated or applied.",
            "The recorded source has no native session and is query-only.",
            "This archive contains no native/game invocation or live reward result.",
        ],
        "read_only_archival": True,
    }
    (output / "manifest.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: report[key] for key in
                      ("format", "status", "goal_complete", "file_count", "recorded_only")}))


if __name__ == "__main__":
    main()
