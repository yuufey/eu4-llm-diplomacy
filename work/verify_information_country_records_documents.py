"""Verify the batch-52 country-record documentation offline.

The checker is inert on import.  After the live acceptance files exist, its
``main`` validates every JSON tool request in the document, compares the
loan/modifier semantic values with the independent references, checks the
pin-before files, and writes one exclusive receipt.  It never starts MCP,
pytest, RPM, REA, or the game.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.tools import TOOL_DEFINITIONS, validate_schema


STAGE = ROOT / "work/runtime/information-country-records-20261027-001"
LIVE = STAGE / "live-acceptance-001"
DOCUMENT = ROOT / "docs/国家贷款与当前修正只读接口.md"
LIVE_FILES = (
    "loans-query.json",
    "modifiers-query.json",
    "modifier-dates-query.json",
    "report-query.json",
    "periodic-results.json",
)


def _read(path: Path) -> Any:
    return json.loads(path.read_bytes())


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": _sha(path),
    }


def _tool_name(value: Mapping[str, Any]) -> str:
    if "operation" not in value:
        return "information_query"
    config = value.get("config")
    if isinstance(config, Mapping) and "queries" in config:
        return "information_manage_report"
    return "information_manage_subscription"


def _schema_for(name: str) -> Mapping[str, Any]:
    for item in TOOL_DEFINITIONS:
        if item["name"] == name:
            return item["inputSchema"]
    raise AssertionError(f"missing tool schema: {name}")


def _document_blocks() -> list[dict[str, Any]]:
    text = DOCUMENT.read_text(encoding="utf-8")
    blocks = [json.loads(value) for value in re.findall(r"```json\s*(.*?)```", text, re.S)]
    if not blocks:
        raise AssertionError("document contains no JSON examples")
    if not all(isinstance(value, dict) for value in blocks):
        raise AssertionError("document JSON examples must be objects")
    return blocks


def _validate_document_requests(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    request_count = 0
    request_tools: dict[str, int] = {}
    query_topic_sets: list[set[str]] = []
    report_create = False
    periodic_create = False
    for value in blocks:
        if "request_id" not in value:
            continue
        name = _tool_name(value)
        validate_schema(value, _schema_for(name), "arguments")
        request_count += 1
        request_tools[name] = request_tools.get(name, 0) + 1
        if name == "information_query" and "queries" in value:
            queries = value["queries"]
            query_topic_sets.append({query.get("topic") for query in queries})
        elif name == "information_manage_report":
            report_create = report_create or value.get("operation") == "create"
        elif name == "information_manage_subscription":
            config = value.get("config", {})
            periodic_create = periodic_create or (
                value.get("operation") == "create" and config.get("kind") == "periodic"
            )

    if not any("N01" in topics for topics in query_topic_sets):
        raise AssertionError("document is missing an N01 information_query example")
    if not any({"N07", "N08"} <= topics for topics in query_topic_sets):
        raise AssertionError("document is missing combined N07/N08 information_query examples")
    if not report_create:
        raise AssertionError("document is missing report creation")
    if not periodic_create:
        raise AssertionError("document is missing periodic subscription creation")
    return {
        "request_count": request_count,
        "request_tools": request_tools,
        "query_topic_sets": [sorted(topics) for topics in query_topic_sets],
    }


def _local_links(text: str) -> list[str]:
    links = re.findall(r"\]\(([^)]+)\)", text)
    for target in links:
        if target.startswith(("http:", "https:")):
            continue
        local = (DOCUMENT.parent / target.split("#", 1)[0]).resolve()
        if not local.is_file():
            raise AssertionError(f"local documentation link is missing: {target}")
    return links


def _items(response: Any, path: Path) -> list[dict[str, Any]]:
    if not isinstance(response, Mapping):
        raise AssertionError(f"response must be an object: {path}")
    values = response.get("items")
    if not isinstance(values, list) or not values or not all(isinstance(item, Mapping) for item in values):
        raise AssertionError(f"response items are missing: {path}")
    return [dict(item) for item in values]


def _fields_for_topic(response: Any, topic: str, path: Path) -> dict[str, Any]:
    for item in _items(response, path):
        query = item.get("query")
        item_topic = item.get("topic")
        if item_topic is None and isinstance(query, Mapping):
            item_topic = query.get("topic")
        if item_topic == topic:
            fields = item.get("fields")
            if isinstance(fields, Mapping):
                return dict(fields)
    raise AssertionError(f"{topic} item missing: {path}")


def _loan_core(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("principal", {}).get("raw"),
        row.get("interest", {}).get("raw"),
        row.get("due", {}).get("raw"),
        row.get("lender", {}).get("raw_fullref_hex"),
    )


def _assert_loans(response: Any, expected: Mapping[str, Any], path: Path) -> None:
    fields = _fields_for_topic(response, "N01", path)
    field = fields.get("loans")
    expected_field = expected.get("fields", {}).get("loans", {})
    if not isinstance(field, Mapping) or field.get("status") != "known":
        raise AssertionError(f"loans field is not known: {path}")
    if field.get("complete") is not False or field.get("partial") is not True:
        raise AssertionError(f"loans partial contract changed: {path}")
    if field.get("unit") != "loan_records" or field.get("scale") != 1:
        raise AssertionError(f"loans unit changed: {path}")
    actual_rows = field.get("value")
    expected_rows = expected_field.get("value")
    if not isinstance(actual_rows, list) or not isinstance(expected_rows, list):
        raise AssertionError(f"loan rows are missing: {path}")
    if [_loan_core(row) for row in actual_rows] != [_loan_core(row) for row in expected_rows]:
        raise AssertionError(f"loan raw semantics differ from independent reference: {path}")
    if any(row.get("interest", {}).get("unit") != "percent" for row in actual_rows):
        raise AssertionError(f"loan interest unit missing: {path}")
    if any(row.get("due", {}).get("unit") != "engine_date_raw" for row in actual_rows):
        raise AssertionError(f"loan due unit missing: {path}")


def _assert_modifier_fields(
    response: Any,
    expected_queries: Mapping[str, Any],
    topic: str,
    path: Path,
) -> None:
    fields = _fields_for_topic(response, topic, path)
    expected_fields = expected_queries.get(topic, {})
    for field_name, expected_field in expected_fields.items():
        actual_field = fields.get(field_name)
        if not isinstance(actual_field, Mapping):
            raise AssertionError(f"{topic}.{field_name} missing: {path}")
        if actual_field.get("status") != expected_field.get("status"):
            raise AssertionError(f"{topic}.{field_name} status changed: {path}")
        if actual_field.get("complete") is not False:
            raise AssertionError(f"{topic}.{field_name} complete contract changed: {path}")
        if actual_field.get("value") != expected_field.get("value"):
            raise AssertionError(f"{topic}.{field_name} differs from independent reference: {path}")


def _assert_partial_response(response: Any, path: Path) -> None:
    if response.get("complete") is not False:
        raise AssertionError(f"response complete flag changed: {path}")
    delivery = response.get("delivery")
    if delivery is not None and delivery.get("status") != "delivered":
        raise AssertionError(f"response was not delivered: {path}")


def _assert_runtime_pins() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = STAGE / "runtime-source-pins-before-001.json"
    if not path.is_file():
        raise AssertionError(f"pin-before receipt is missing: {path}")
    pins_document = _read(path)
    pins = pins_document.get("files")
    if not isinstance(pins, list) or not pins:
        raise AssertionError("pin-before has no files")
    for item in pins:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise AssertionError("pin-before item is malformed")
        current = _pin(ROOT / item["path"])
        if current["sha256"] != item.get("sha256") or current["bytes"] != item.get("bytes"):
            raise AssertionError(f"runtime source changed after pin-before: {item['path']}")
    return [dict(item) for item in pins], pins_document


def _assert_live_files(expected_loans: Mapping[str, Any], expected_modifiers: Mapping[str, Any]) -> dict[str, Any]:
    paths = {name: LIVE / name for name in LIVE_FILES}
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise AssertionError("live acceptance files are missing: " + ", ".join(missing))

    loans_response = _read(paths["loans-query.json"])
    modifiers_response = _read(paths["modifiers-query.json"])
    dates_response = _read(paths["modifier-dates-query.json"])
    report_response = _read(paths["report-query.json"])
    periodic_response = _read(paths["periodic-results.json"])

    _assert_partial_response(loans_response, paths["loans-query.json"])
    _assert_partial_response(modifiers_response, paths["modifiers-query.json"])
    _assert_partial_response(dates_response, paths["modifier-dates-query.json"])
    _assert_partial_response(report_response, paths["report-query.json"])
    _assert_loans(loans_response, expected_loans, paths["loans-query.json"])
    _assert_modifier_fields(
        modifiers_response,
        expected_modifiers["queries"],
        "N07",
        paths["modifiers-query.json"],
    )
    _assert_modifier_fields(
        dates_response,
        expected_modifiers["queries"],
        "N08",
        paths["modifier-dates-query.json"],
    )
    _assert_loans(report_response, expected_loans, paths["report-query.json"])
    _assert_modifier_fields(report_response, expected_modifiers["queries"], "N07", paths["report-query.json"])
    _assert_modifier_fields(report_response, expected_modifiers["queries"], "N08", paths["report-query.json"])

    if not isinstance(periodic_response, list) or not periodic_response:
        raise AssertionError("periodic-results.json has no delivered result")
    periodic_checked = 0
    for result in periodic_response:
        _assert_partial_response(result, paths["periodic-results.json"])
        _assert_loans(result, expected_loans, paths["periodic-results.json"])
        _assert_modifier_fields(result, expected_modifiers["queries"], "N07", paths["periodic-results.json"])
        _assert_modifier_fields(result, expected_modifiers["queries"], "N08", paths["periodic-results.json"])
        periodic_checked += 1
    return {
        "files": [_pin(path) for path in paths.values()],
        "periodic_results_checked": periodic_checked,
    }


def main() -> None:
    text = DOCUMENT.read_text(encoding="utf-8")
    blocks = _document_blocks()
    request_info = _validate_document_requests(blocks)
    links = _local_links(text)

    expected_loans_path = STAGE / "expected-loans-001.json"
    expected_modifiers_path = STAGE / "expected-country-modifiers-001.json"
    if not expected_loans_path.is_file() or not expected_modifiers_path.is_file():
        raise AssertionError("independent country-record references are missing")
    expected_loans = _read(expected_loans_path)
    expected_modifiers = _read(expected_modifiers_path)

    pins, pins_document = _assert_runtime_pins()
    live_info = _assert_live_files(expected_loans, expected_modifiers)

    receipt = {
        "schema": "information_country_records_document_verification.v1",
        "status": "passed",
        "document": _pin(DOCUMENT),
        "json_examples": len(blocks),
        "tool_request_schemas_valid": request_info["request_count"],
        "tool_request_kinds": request_info["request_tools"],
        "query_topic_sets": request_info["query_topic_sets"],
        "local_links_valid": len(links),
        "independent_references": {
            "loans": _pin(expected_loans_path),
            "country_modifiers": _pin(expected_modifiers_path),
        },
        "live_files": live_info["files"],
        "periodic_results_checked": live_info["periodic_results_checked"],
        "runtime_sources_match_before": True,
        "runtime_source_file_count": len(pins),
        "runtime_source_pins_before": _pin(STAGE / "runtime-source-pins-before-001.json"),
        "pin_before_schema": pins_document.get("schema"),
        "new_game_queries_or_pytest_runs": 0,
    }
    output = STAGE / "document-verification-001.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
