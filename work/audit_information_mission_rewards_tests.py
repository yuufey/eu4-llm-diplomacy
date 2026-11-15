"""Compare completed M04 regression artifacts without rerunning tests."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.audit_information_country_powers_tests import _artifact, compare_nodes, parse_junit, parse_log

STAGE = ROOT / "work/runtime/information-mission-rewards-20261025-001"
BASELINE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"


def pin(path):
    result = _artifact(path)
    result["path"] = path.resolve().relative_to(ROOT.resolve()).as_posix()
    return result


def checkpoint(directory, prefix):
    xml, log = directory / f"{prefix}.xml", directory / f"{prefix}.log"
    data = parse_junit(xml)
    return data, {
        "xml": pin(xml), "log": pin(log), "junit_suite": data["junit_suite"],
        "reported_result": parse_log(log), "case_element_statuses": data["case_element_statuses"],
        "information": data["information"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", default="full-pytest-001")
    parser.add_argument("--information", default="information-pytest-001")
    parser.add_argument("--output", default="test-summary-001.json")
    parser.add_argument("--full-exit-code", type=int, required=True)
    args = parser.parse_args()
    for name in (args.full, args.information, args.output):
        if Path(name).name != name:
            raise ValueError("only stage-local artifact names are accepted")
    full, full_report = checkpoint(STAGE, args.full)
    info, info_report = checkpoint(STAGE, args.information)
    if info["case_element_statuses"]["failure"] or info["case_element_statuses"]["error"]:
        raise ValueError("information checkpoint must pass before this audit")
    latest, latest_report = checkpoint(BASELINE, "full-pytest-003")
    stable, stable_report = checkpoint(BASELINE, "full-pytest-002")
    sources = [
        ROOT / "bridge/information/mission_reward_rules.py",
        ROOT / "bridge/information/missions.py",
        ROOT / "tools/serve_information.py",
        ROOT / "work/validate_information_mission_reward_rules_recorded.py",
        Path(__file__).resolve(),
    ]
    sources += sorted((ROOT / "bridge/tests").glob("test_information_mission_reward_rules*.py"))
    fixture = ROOT / "bridge/tests/fixtures/information_mission_reward_rules_recorded_1374.json"
    if fixture.exists():
        sources.append(fixture)
    report = {
        "schema": "information_mission_reward_rules_regression_audit_v1",
        "goal_complete": False,
        "full_suite_passed": not (full["case_element_statuses"]["failure"] or full["case_element_statuses"]["error"]),
        "full_exit_code": args.full_exit_code,
        "full": full_report, "information": info_report,
        "latest_batch_ten_baseline": latest_report,
        "latest_baseline_comparison": compare_nodes(latest, full),
        "stable_142_node_baseline": stable_report,
        "stable_baseline_comparison": compare_nodes(stable, full),
        "source_files": [pin(path) for path in sources],
        "scope": {
            "fields": ["claims", "casus_belli", "trade_modifiers"],
            "semantics": "declared_literal_effect_rules",
            "runtime_conditions_evaluated": False,
            "actual_rewards_verified": False,
            "complete_M04": False,
            "live_acceptance": False,
        },
        "notes": [
            "JUnit is streamed and every duplicate failure/error node and message is compared.",
            "The stable baseline has 142 old failure/error nodes. The latest baseline also contains an intermittent HTTP failure.",
            "A passing isolated HTTP recheck does not prove that intermittent full-suite failures are fixed.",
        ],
    }
    if (STAGE / "http-recheck-001.xml").exists():
        _, report["http_isolated_recheck"] = checkpoint(STAGE, "http-recheck-001")
    with (STAGE / args.output).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "full": full_report["reported_result"],
        "information": info_report["reported_result"],
        "stable_persistent_nodes": report["stable_baseline_comparison"]["persistent_nodes"],
        "stable_added_nodes": report["stable_baseline_comparison"]["added_nodes"],
        "stable_message_changes": report["stable_baseline_comparison"]["message_changed_nodes"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
