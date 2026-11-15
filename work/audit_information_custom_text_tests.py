"""Stream and compare the dynamic-text full-regression JUnit artifacts.

This helper deliberately does not run pytest.  It counts testcase elements and
every direct failure/error child independently, retaining duplicate nodes and
comparing their messages separately.  It is kept outside the bridge package so
the archived audit cannot affect production imports.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


INFO_PREFIX = "bridge.tests.test_information"


def _tag(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _number(value: str | None):
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


def _hash(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def _message(child: ET.Element) -> str:
    message = child.attrib.get("message")
    if message is not None:
        return message
    return "".join(child.itertext()).strip()


def _status(children: list[ET.Element]) -> str:
    tags = {_tag(child.tag) for child in children}
    if "error" in tags:
        return "error"
    if "failure" in tags:
        return "failure"
    if "skipped" in tags:
        return "skipped"
    return "passed"


def parse_junit(path: Path) -> dict:
    """Parse one JUnit XML file with bounded ``iterparse`` memory use."""

    suite: dict = {}
    case_statuses: Counter[str] = Counter()
    module_statuses: dict[str, Counter[str]] = defaultdict(Counter)
    node_counts: Counter[tuple[str, str, str]] = Counter()
    message_counts: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    case_elements = 0

    for _event, elem in ET.iterparse(path, events=("end",)):
        tag = _tag(elem.tag)
        if tag == "testsuite" and not suite:
            suite = {key: _number(value) for key, value in elem.attrib.items()}
        elif tag == "testcase":
            classname = elem.attrib.get("classname", "")
            name = elem.attrib.get("name", "")
            children = list(elem)
            status = _status(children)
            case_elements += 1
            case_statuses[status] += 1
            if classname.startswith(INFO_PREFIX):
                module_statuses[classname][status] += 1
            for child in children:
                child_tag = _tag(child.tag)
                if child_tag not in ("failure", "error"):
                    continue
                node = (classname, name, child_tag)
                node_counts[node] += 1
                message_counts[node][_message(child)] += 1
            elem.clear()

    modules = {}
    for classname in sorted(module_statuses):
        counts = module_statuses[classname]
        modules[classname] = {
            "tests": sum(counts.values()),
            "passed": counts["passed"],
            "failure": counts["failure"],
            "error": counts["error"],
            "skipped": counts["skipped"],
        }
    info_statuses = Counter()
    info_cases = 0
    info_failure_ids: set[str] = set()
    info_error_ids: set[str] = set()
    for classname, counts in module_statuses.items():
        info_statuses.update(counts)
        info_cases += sum(counts.values())
    for classname, name, kind in node_counts:
        if not classname.startswith(INFO_PREFIX):
            continue
        case_id = f"{classname}::{name}"
        if kind == "failure":
            info_failure_ids.add(case_id)
        else:
            info_error_ids.add(case_id)

    return {
        "path": path.as_posix(),
        "sha256": _hash(path)[0],
        "bytes": path.stat().st_size,
        "junit_suite": suite,
        "case_elements": case_elements,
        "case_element_statuses": {
            key: case_statuses[key] for key in ("passed", "failure", "error", "skipped")
        },
        "information": {
            "case_elements": info_cases,
            "case_element_statuses": {
                key: info_statuses[key] for key in ("passed", "failure", "error", "skipped")
            },
            "modules": modules,
            "failure_ids": sorted(info_failure_ids),
            "error_ids": sorted(info_error_ids),
        },
        "_nodes": node_counts,
        "_messages": message_counts,
    }


def parse_log(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if "subtests passed in" in line]
    if not lines:
        return {"summary": None, "failed": None, "passed": None,
                "errors": None, "subtests": None, "elapsed": None}
    summary = lines[-1]
    values = {}
    for key in ("failed", "passed", "errors", "subtests"):
        match = re.search(rf"(\d+) {key}", summary)
        values[key] = int(match.group(1)) if match else 0
    elapsed = re.search(r"subtests passed in (?P<elapsed>[^\r\n]+)$", summary)
    values["elapsed"] = elapsed.group("elapsed") if elapsed else None
    values["summary"] = summary
    return values


def _node_id(node: tuple[str, str, str]) -> str:
    return f"{node[0]}::{node[1]} [{node[2]}]"


def compare_nodes(baseline: dict, current: dict) -> dict:
    old: Counter = baseline["_nodes"]
    new: Counter = current["_nodes"]
    old_messages = baseline["_messages"]
    new_messages = current["_messages"]
    all_nodes = sorted(set(old) | set(new))

    added = []
    resolved = []
    for node in all_nodes:
        difference = new[node] - old[node]
        if difference > 0:
            added.append({"id": _node_id(node), "count": difference})
        difference = old[node] - new[node]
        if difference > 0:
            resolved.append({"id": _node_id(node), "count": difference})

    persistent = sorted(set(old) & set(new))
    changed = []
    details = []
    for node in persistent:
        old_counter = old_messages[node]
        new_counter = new_messages[node]
        if old_counter != new_counter:
            changed.append({
                "id": _node_id(node),
                "baseline_messages": dict(sorted(old_counter.items())),
                "current_messages": dict(sorted(new_counter.items())),
            })
        details.append({
            "id": _node_id(node),
            "status": node[2],
            "baseline_count": old[node],
            "current_count": new[node],
            "messages": dict(sorted(new_counter.items())),
        })

    return {
        "key": "(testcase classname, testcase name, failure/error kind)",
        "baseline_nodes": sum(old.values()),
        "current_nodes": sum(new.values()),
        "baseline_unique_keys": len(old),
        "current_unique_keys": len(new),
        "added_nodes": added,
        "resolved_nodes": resolved,
        "persistent_unique_keys": len(persistent),
        "persistent_nodes": sum(min(old[node], new[node]) for node in persistent),
        "message_changed_nodes": changed,
        "new_failure_or_error_nodes": added,
        "disappeared_failure_or_error_nodes": resolved,
        "persistent_nodes_detail": details,
    }


def _delta(current: dict, baseline: dict) -> dict:
    keys = ("tests", "passed", "failure", "error", "skipped")
    return {key: current.get(key, 0) - baseline.get(key, 0) for key in keys}


def _artifact(path: Path, **extra) -> dict:
    digest, size = _hash(path)
    value = {"path": path.as_posix(), "sha256": digest, "bytes": size}
    value.update(extra)
    return value


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _directed_checkpoint(xml_path: Path | None, log_path: Path | None) -> dict | None:
    if xml_path is None or not xml_path.exists():
        return None
    parsed = parse_junit(xml_path)
    log = parse_log(log_path) if log_path and log_path.exists() else {}
    return {
        "junit_xml": {key: parsed[key] for key in ("path", "sha256", "bytes")},
        "junit_suite": parsed["junit_suite"],
        "case_elements": parsed["case_elements"],
        "case_element_statuses": parsed["case_element_statuses"],
        "information": parsed["information"],
        "reported_result": log.get("summary"),
        "status": "passed" if not any(parsed["case_element_statuses"][key] for key in ("failure", "error")) else "failed",
    }


def build_summary(args: argparse.Namespace) -> dict:
    current_xml = Path(args.current_xml)
    baseline_xml = Path(args.baseline_xml)
    current = parse_junit(current_xml)
    baseline = parse_junit(baseline_xml)
    current_log = parse_log(Path(args.current_log))
    baseline_log = parse_log(Path(args.baseline_log))
    current_suite = current["junit_suite"]
    baseline_suite = baseline["junit_suite"]
    current_info = current["information"]
    baseline_info = baseline["information"]

    current_modules = current_info["modules"]
    baseline_modules = baseline_info["modules"]
    module_deltas = {}
    for name in sorted(set(current_modules) | set(baseline_modules)):
        if name not in current_modules or name not in baseline_modules:
            value = current_modules.get(name, {key: 0 for key in ("tests", "passed", "failure", "error", "skipped")})
            old = baseline_modules.get(name, {key: 0 for key in ("tests", "passed", "failure", "error", "skipped")})
        else:
            value, old = current_modules[name], baseline_modules[name]
        delta = _delta(value, old)
        if any(delta.values()):
            module_deltas[name] = {**value, "delta": delta}

    suite_delta = {}
    for key in ("tests", "failures", "errors", "skipped", "time"):
        current_value = current_suite.get(key, 0)
        baseline_value = baseline_suite.get(key, 0)
        try:
            suite_delta[key] = current_value - baseline_value
        except TypeError:
            suite_delta[key] = None

    artifacts = {
        "current_junit_xml": _artifact(current_xml),
        "current_log": _artifact(Path(args.current_log)),
        "baseline_junit_xml": _artifact(baseline_xml),
        "baseline_log": _artifact(Path(args.baseline_log)),
        "baseline_test_summary": _artifact(Path(args.baseline_summary)),
    }
    optional_artifacts = {
        "directed_information_junit": args.directed_xml,
        "directed_information_log": args.directed_log,
        "recorded_custom_text_fixture": args.fixture,
        "compile_audit": args.compile_audit,
        "source_audit_final": args.source_audit,
        "live_acceptance_003_report": args.live_report,
        "custom_methods_raw": args.custom_methods_raw,
    }
    for label, raw_path in optional_artifacts.items():
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.exists():
            continue
        extra = {}
        if label == "recorded_custom_text_fixture":
            fixture = _read_json(path)
            extra.update({
                "mode": fixture.get("provenance", {}).get("mode"),
                "source_sha256": fixture.get("provenance", {}).get("source_sha256"),
            })
        elif label == "compile_audit" or label == "source_audit_final":
            record = _read_json(path)
            extra["status"] = record.get("status")
            if "file_count" in record:
                extra["file_count"] = record["file_count"]
        elif label == "live_acceptance_003_report":
            record = _read_json(path)
            extra.update({key: record.get(key) for key in (
                "status", "task_count", "key_count", "derived_count", "known_count",
                "unresolved_count", "periodic_results", "custom_capture_sha256",
                "native_cache_sha256", "native_function_invoked", "ui_root_scope_verified",
            ) if key in record})
        artifacts[label] = _artifact(path, **extra)

    comparison = {
        "baseline": {
            "directory": str(Path(args.baseline_xml).parent.as_posix()),
            "junit_suite": baseline_suite,
            "log_summary": baseline_log.get("summary"),
            "log_numbers": baseline_log,
            "case_elements": baseline["case_elements"],
            "case_element_statuses": baseline["case_element_statuses"],
            "information_case_elements": baseline_info["case_elements"],
            "information_case_element_statuses": baseline_info["case_element_statuses"],
            "information_modules": baseline_modules,
        },
        "current": {
            "directory": str(Path(args.current_xml).parent.as_posix()),
            "junit_suite": current_suite,
            "log_summary": current_log.get("summary"),
            "log_numbers": current_log,
            "case_elements": current["case_elements"],
            "case_element_statuses": current["case_element_statuses"],
            "information_case_elements": current_info["case_elements"],
            "information_case_element_statuses": current_info["case_element_statuses"],
            "information_modules": current_modules,
        },
        "overall_delta": {
            "junit_suite_tests": suite_delta.get("tests"),
            "reported_passed": current_log.get("passed", 0) - baseline_log.get("passed", 0),
            "reported_failed": current_log.get("failed", 0) - baseline_log.get("failed", 0),
            "reported_errors": current_log.get("errors", 0) - baseline_log.get("errors", 0),
            "reported_subtests_passed": current_log.get("subtests", 0) - baseline_log.get("subtests", 0),
            "case_elements": current["case_elements"] - baseline["case_elements"],
            "case_element_passed": current["case_element_statuses"]["passed"] - baseline["case_element_statuses"]["passed"],
            "case_element_failure": current["case_element_statuses"]["failure"] - baseline["case_element_statuses"]["failure"],
            "case_element_error": current["case_element_statuses"]["error"] - baseline["case_element_statuses"]["error"],
            "information_case_elements": current_info["case_elements"] - baseline_info["case_elements"],
            "information_case_passed": current_info["case_element_statuses"]["passed"] - baseline_info["case_element_statuses"]["passed"],
            "information_case_failure": current_info["case_element_statuses"]["failure"] - baseline_info["case_element_statuses"]["failure"],
            "information_case_error": current_info["case_element_statuses"]["error"] - baseline_info["case_element_statuses"]["error"],
        },
        "information_module_deltas": module_deltas,
        "new_information_modules": {name: current_modules[name] for name in sorted(set(current_modules) - set(baseline_modules))},
        "removed_information_modules": {name: baseline_modules[name] for name in sorted(set(baseline_modules) - set(current_modules))},
    }

    directed = _directed_checkpoint(
        Path(args.directed_xml) if args.directed_xml else None,
        Path(args.directed_log) if args.directed_log else None,
    )
    summary = {
        "schema": "information-dynamic-text-regression-audit-v1",
        "command": args.command,
        "exit_code": args.exit_code,
        "status": "failed" if args.exit_code else "passed",
        "audit_method": {
            "junit": "streaming xml.etree.ElementTree.iterparse; no full XML materialization",
            "failure_comparison": "Counter of every <failure>/<error> child node keyed by (testcase classname, testcase name, child tag); duplicate nodes retain multiplicity; message counters compared separately",
            "tests_reexecuted": False,
        },
        "artifacts": artifacts,
        "overall": {
            "junit_suite": current_suite,
            "log_summary": current_log.get("summary"),
            "log_numbers": current_log,
            "case_elements": current["case_elements"],
            "case_element_statuses": current["case_element_statuses"],
            "note": "JUnit suite tests/failures counts and the pytest log subtests-passed count include subtest outcomes; module counts and failure-node comparison below count testcase elements and explicit failure/error child nodes.",
        },
        "information": current_info,
        "targeted_information_checkpoint": directed,
        "comparison_to_localization": comparison,
        "failure_error_node_comparison": compare_nodes(baseline, current),
        "evidence_checkpoints": {
            "recorded_custom_text_fixture": artifacts.get("recorded_custom_text_fixture"),
            "compile_audit": artifacts.get("compile_audit"),
            "source_audit_final": artifacts.get("source_audit_final"),
            "live_acceptance_003": artifacts.get("live_acceptance_003_report"),
            "custom_methods_raw": artifacts.get("custom_methods_raw"),
        },
        "notes": [
            f"The full regression is not passing: exit code {args.exit_code} with {current_log.get('failed')} failed and {current_log.get('errors')} errors.",
            f"Information testcase elements increased from {baseline_info['case_elements']} to {current_info['case_elements']} (+{current_info['case_elements'] - baseline_info['case_elements']}); current information testcase elements have {current_info['case_element_statuses']['failure']} failures and {current_info['case_element_statuses']['error']} errors.",
            "Failure/error comparison is node-level and preserves duplicate child nodes; added, resolved, and message-changed nodes are listed separately.",
            "This summary audits already completed regression artifacts and does not rerun the full suite, game, RPM, or REA.",
        ],
    }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current-xml", required=True)
    parser.add_argument("--current-log", required=True)
    parser.add_argument("--baseline-xml", required=True)
    parser.add_argument("--baseline-log", required=True)
    parser.add_argument("--baseline-summary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--directed-xml")
    parser.add_argument("--directed-log")
    parser.add_argument("--fixture")
    parser.add_argument("--compile-audit")
    parser.add_argument("--source-audit")
    parser.add_argument("--live-report")
    parser.add_argument("--custom-methods-raw")
    parser.add_argument("--command", default="python -m pytest -q bridge/tests --junitxml=work/runtime/information-dynamic-text-20261024-001/pytest-full.xml")
    parser.add_argument("--exit-code", type=int, default=1)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_summary(args), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
