#!/usr/bin/env python3
"""Streaming JUnit comparison for the information recovery batch.

The comparison key deliberately keeps duplicate failure/error children:
(testcase classname, testcase name, child tag).  Message counters are compared
separately so a persistent node with changed traceback text is not hidden by
the node key.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


NodeKey = tuple[str, str, str]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, object]:
    return {
        "path": str(path).replace("\\", "/"),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _case_status(case: ET.Element) -> str:
    children = {local_tag(child.tag) for child in case}
    if "error" in children:
        return "error"
    if "failure" in children:
        return "failure"
    if "skipped" in children:
        return "skipped"
    return "passed"


def parse_junit(path: Path, information_prefix: str) -> dict[str, object]:
    suite_attributes: list[dict[str, str]] = []
    cases = 0
    statuses: collections.Counter[str] = collections.Counter()
    information_statuses: collections.Counter[str] = collections.Counter()
    modules: collections.Counter[str] = collections.Counter()
    nodes: collections.Counter[NodeKey] = collections.Counter()
    messages: dict[NodeKey, collections.Counter[str]] = collections.defaultdict(collections.Counter)

    for _event, element in ET.iterparse(path, events=("end",)):
        tag = local_tag(element.tag)
        if tag == "testsuite":
            suite_attributes.append(dict(element.attrib))
            continue
        if tag != "testcase":
            continue

        classname = element.attrib.get("classname", "")
        name = element.attrib.get("name", "")
        status = _case_status(element)
        cases += 1
        statuses[status] += 1
        if classname.startswith(information_prefix):
            information_statuses[status] += 1
            modules[classname] += 1

        for child in element:
            child_tag = local_tag(child.tag)
            if child_tag not in {"failure", "error"}:
                continue
            key = (classname, name, child_tag)
            nodes[key] += 1
            message = child.attrib.get("message", "") + "\n" + (child.text or "")
            messages[key][message] += 1
        element.clear()

    suite = suite_attributes[-1] if suite_attributes else {}
    return {
        "artifact": artifact(path),
        "suite": suite,
        "case_elements": cases,
        "case_element_statuses": dict(statuses),
        "information_case_elements": sum(information_statuses.values()),
        "information_case_element_statuses": dict(information_statuses),
        "information_modules": dict(sorted(modules.items())),
        "failure_error_nodes": nodes,
        "failure_error_messages": messages,
    }


def _node_id(key: NodeKey) -> str:
    return f"{key[0]}::{key[1]} [{key[2]}]"


def _message_fingerprint(message: str) -> dict[str, object]:
    preview = message.replace("\r", "").replace("\n", "\\n")[:240]
    return {
        "sha256": hashlib.sha256(message.encode("utf-8", "replace")).hexdigest(),
        "length": len(message),
        "preview": preview,
    }


def _message_counter(counter: collections.Counter[str]) -> list[dict[str, object]]:
    return [
        {"message": _message_fingerprint(message), "count": count}
        for message, count in sorted(counter.items())
    ]


def compare_nodes(baseline: dict[str, object], current: dict[str, object]) -> dict[str, object]:
    old_nodes = baseline["failure_error_nodes"]
    new_nodes = current["failure_error_nodes"]
    assert isinstance(old_nodes, collections.Counter)
    assert isinstance(new_nodes, collections.Counter)
    added = new_nodes - old_nodes
    resolved = old_nodes - new_nodes
    persistent = old_nodes & new_nodes

    old_messages = baseline["failure_error_messages"]
    new_messages = current["failure_error_messages"]
    assert isinstance(old_messages, dict)
    assert isinstance(new_messages, dict)
    message_changed: list[dict[str, object]] = []
    for key in sorted(set(old_messages) & set(new_messages)):
        old_counter = old_messages[key]
        new_counter = new_messages[key]
        if old_counter == new_counter:
            continue
        message_changed.append(
            {
                "id": _node_id(key),
                "status": key[2],
                "baseline_messages": _message_counter(old_counter),
                "current_messages": _message_counter(new_counter),
            }
        )

    def nodes_json(counter: collections.Counter[NodeKey]) -> list[dict[str, object]]:
        return [
            {"id": _node_id(key), "classname": key[0], "name": key[1], "tag": key[2], "count": count}
            for key, count in sorted(counter.items())
        ]

    return {
        "key": "(testcase classname, testcase name, failure/error child tag)",
        "baseline_nodes": sum(old_nodes.values()),
        "current_nodes": sum(new_nodes.values()),
        "baseline_unique_keys": len(old_nodes),
        "current_unique_keys": len(new_nodes),
        "added_nodes": nodes_json(added),
        "resolved_nodes": nodes_json(resolved),
        "persistent_nodes": sum(persistent.values()),
        "persistent_unique_keys": len(persistent),
        "message_changed_nodes": message_changed,
        "new_failure_or_error_nodes": nodes_json(added),
        "disappeared_failure_or_error_nodes": nodes_json(resolved),
    }


SUMMARY_RE = re.compile(
    r"(?:(?P<failed>\d+) failed, )?"
    r"(?P<passed>\d+) passed"
    r"(?:, (?P<errors>\d+) errors)?"
    r"(?:, (?P<subtests>\d+) subtests passed)?"
    r" in (?P<elapsed>[^\r\n]+)"
)


def parse_log(path: Path) -> dict[str, object]:
    summary: dict[str, object] | None = None
    runner_exit: int | None = None
    command_line: str | None = None
    file_count: int | None = None
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if line.startswith("command="):
                command_line = line.rstrip("\r\n")
            if line.startswith("files="):
                try:
                    file_count = int(line.split("=", 1)[1].strip())
                except ValueError:
                    file_count = None
            match = SUMMARY_RE.search(line)
            if match:
                summary = {
                    "failed": int(match.group("failed") or 0),
                    "passed": int(match.group("passed") or 0),
                    "errors": int(match.group("errors") or 0),
                    "subtests": int(match.group("subtests") or 0),
                    "elapsed": match.group("elapsed"),
                }
            if line.startswith("runner_exit_code="):
                runner_exit = int(line.split("=", 1)[1].strip())
    return {
        "artifact": artifact(path),
        "command_line": command_line,
        "file_count": file_count,
        "reported_result": summary,
        "runner_exit_code": runner_exit,
    }


def module_delta(old: dict[str, int], new: dict[str, int]) -> dict[str, object]:
    old_counter = collections.Counter(old)
    new_counter = collections.Counter(new)
    added = new_counter - old_counter
    removed = old_counter - new_counter
    changed = {
        key: {"baseline": old_counter[key], "current": new_counter[key]}
        for key in sorted(set(old_counter) & set(new_counter))
        if old_counter[key] != new_counter[key]
    }
    return {"added": dict(sorted(added.items())), "removed": dict(sorted(removed.items())), "changed": changed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-xml", required=True, type=Path)
    parser.add_argument("--baseline-summary", required=True, type=Path)
    parser.add_argument("--current-xml", required=True, type=Path)
    parser.add_argument("--current-log", required=True, type=Path)
    parser.add_argument("--information-xml", required=True, type=Path)
    parser.add_argument("--information-log", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    baseline = parse_junit(args.baseline_xml, "bridge.tests.test_information")
    current = parse_junit(args.current_xml, "bridge.tests.test_information")
    directed = parse_junit(args.information_xml, "bridge.tests.test_information")
    current_log = parse_log(args.current_log)
    information_log = parse_log(args.information_log)
    baseline_summary = json.loads(args.baseline_summary.read_text(encoding="utf-8"))

    current_suite = current["suite"]
    assert isinstance(current_suite, dict)
    baseline_suite = baseline["suite"]
    assert isinstance(baseline_suite, dict)
    current_report = current_log["reported_result"] or {}
    baseline_report = baseline_summary["full"]["reported_result"]
    current_exit = current_log["runner_exit_code"]

    current_modules = current["information_modules"]
    baseline_modules = baseline["information_modules"]
    assert isinstance(current_modules, dict)
    assert isinstance(baseline_modules, dict)

    result = {
        "schema": "information_recovery_regression_audit_v1",
        "generated_at": "2026-10-25",
        "goal_complete": False,
        "full_suite_passed": current_exit == 0 and int(current_suite.get("failures", 0)) == 0 and int(current_suite.get("errors", 0)) == 0,
        "full_exit_code": current_exit,
        "full": {
            "xml": current["artifact"],
            "log": current_log["artifact"],
            "command_line": current_log["command_line"],
            "file_count": current_log["file_count"],
            "junit_suite": current_suite,
            "reported_result": current_report,
            "case_element_statuses": current["case_element_statuses"],
            "case_elements": current["case_elements"],
            "implicit_non_case_tests": int(current_suite.get("tests", 0)) - int(current["case_elements"]),
            "information": {
                "case_elements": current["information_case_elements"],
                "case_element_statuses": current["information_case_element_statuses"],
                "modules": current_modules,
            },
        },
        "information": {
            "xml": directed["artifact"],
            "log": information_log["artifact"],
            "command_line": information_log["command_line"],
            "file_count": information_log["file_count"],
            "junit_suite": directed["suite"],
            "reported_result": information_log["reported_result"],
            "case_element_statuses": directed["case_element_statuses"],
            "case_elements": directed["case_elements"],
            "implicit_non_case_tests": int(directed["suite"].get("tests", 0)) - int(directed["case_elements"]),
            "module_count": len(directed["information_modules"]),
            "module_cases": directed["information_modules"],
        },
        "comparison_to_previous_batch": {
            "baseline_summary": artifact(args.baseline_summary),
            "baseline_full": {
                "xml": baseline["artifact"],
                "junit_suite": baseline_suite,
                "reported_result": baseline_report,
                "case_element_statuses": baseline["case_element_statuses"],
                "case_elements": baseline["case_elements"],
                "information": {
                    "case_elements": baseline["information_case_elements"],
                    "case_element_statuses": baseline["information_case_element_statuses"],
                    "modules": baseline_modules,
                },
            },
            "failure_error_nodes": compare_nodes(baseline, current),
            "information_module_delta": module_delta(baseline_modules, current_modules),
        },
        "scope": {
            "baseline": "information-mission-rewards-20261025-001/full-pytest-002.xml",
            "current": "information-recovery-20261025-001/full-pytest-001.xml",
            "comparison_preserves_duplicate_nodes": True,
            "subtests_and_case_elements_reported_separately": True,
            "tests_rerun": True,
            "production_or_test_source_changed_by_audit": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
