"""Verify the batch50 N03 documentation after root live acceptance.

The script is intentionally inert on import.  It checks the Markdown JSON
examples against the tool schemas, compares the new morale/discipline query
with the live response and independent expected-002 reference, and verifies
the pre-acceptance runtime pins.  It writes one exclusive receipt only when
the root live response and source-pin receipt already exist.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.tools import TOOL_DEFINITIONS, validate_schema


STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"


def _read(path: Path):
    return json.loads(path.read_bytes())


def _pin(path: Path):
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _subset(expected, actual):
    if isinstance(expected, dict):
        assert isinstance(actual, dict), (expected, actual)
        for key, value in expected.items():
            assert key in actual, key
            _subset(value, actual[key])
    elif isinstance(expected, list):
        assert isinstance(actual, list) and len(expected) == len(actual), (expected, actual)
        for wanted, value in zip(expected, actual):
            _subset(wanted, value)
    else:
        assert expected == actual, (expected, actual)


def _tool_name(value):
    if "operation" not in value:
        return "information_query"
    if "queries" in value.get("config", {}):
        return "information_manage_report"
    return "information_manage_subscription"


def _response_fields(path: Path):
    response = _read(path)
    items = response.get("items")
    assert isinstance(items, list) and len(items) == 1, path
    fields = items[0].get("fields")
    assert isinstance(fields, dict), path
    return response, fields


def main():
    document = ROOT / "docs/军事质量只读接口.md"
    text = document.read_text(encoding="utf-8")
    blocks = [json.loads(value) for value in re.findall(r"```json\s*(.*?)```", text, re.S)]
    assert len(blocks) == 8, len(blocks)

    requests = 0
    for value in blocks:
        if "request_id" not in value:
            continue
        schema_name = _tool_name(value)
        schema = next(item["inputSchema"] for item in TOOL_DEFINITIONS if item["name"] == schema_name)
        validate_schema(value, schema, "arguments")
        requests += 1
    assert requests == 7, requests

    new_query = next(
        value
        for value in blocks
        if "queries" in value
        and value["queries"]
        and value["queries"][0].get("topic") == "N03"
        and set(value["queries"][0].get("fields", ())) == {"morale", "discipline"}
    )
    assert new_query["queries"][0]["object"] == {"type": "country", "country": "FRA"}
    assert new_query["queries"][0]["parameters"] == {}

    two_path = STAGE / "live-acceptance-001/two-fields-query.json"
    four_path = STAGE / "live-acceptance-001/four-fields-query.json"
    expected_path = STAGE / "expected-military-effective-002.json"
    before_path = STAGE / "runtime-source-pins-before-001.json"
    for path in (two_path, four_path, expected_path, before_path):
        assert path.is_file(), path

    expected = _read(expected_path)
    expected_fields = expected["fields"]
    two_response, two_fields = _response_fields(two_path)
    _subset(expected_fields, two_fields)
    assert set(two_fields) >= {"morale", "discipline"}
    assert two_response.get("complete") is False

    four_response, four_fields = _response_fields(four_path)
    result_example = next(
        value for value in blocks
        if value.get("topic") == "N03" and "objects" in value and "fields" in value
    )
    _subset(result_example["fields"], four_fields)
    assert four_response.get("complete") is False

    links = re.findall(r"\]\(([^)]+)\)", text)
    for target in links:
        if target.startswith(("http:", "https:")):
            continue
        local = (document.parent / target.split("#", 1)[0]).resolve()
        assert local.is_file(), target

    pins = _read(before_path)["files"]
    assert all(_pin(ROOT / item["path"])["sha256"] == item["sha256"] for item in pins)

    receipt = {
        "schema": "information_military_effective_document_verification.v1",
        "status": "passed",
        "document": _pin(document),
        "json_examples": len(blocks),
        "tool_request_schemas_valid": requests,
        "new_two_field_query_matches_actual_MCP": True,
        "morale_and_discipline_match_expected_002": True,
        "four_field_result_matches_actual_MCP": True,
        "local_links_valid": len(links),
        "runtime_sources_match_before": True,
        "new_game_queries_or_pytest_runs": 0,
    }
    output = STAGE / "document-verification-001.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
