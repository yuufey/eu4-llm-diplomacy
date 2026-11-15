"""Verify the batch-51 military-quality documentation offline.

The checker is intentionally inert on import.  After root has produced the
live acceptance files, ``main`` validates all Markdown JSON request blocks,
the single-field professionalism result, the five-field result, local links,
and the pre-acceptance runtime pins.  It writes one exclusive receipt; it
does not call MCP, RPM, pytest, or the game.
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


STAGE = ROOT / "work/runtime/information-military-professionalism-20261027-001"
LIVE = STAGE / "live-acceptance-001"


def _read(path: Path):
    return json.loads(path.read_bytes())


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pin(path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": _digest(path),
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


def main() -> None:
    document = ROOT / "docs/军事质量只读接口.md"
    text = document.read_text(encoding="utf-8")
    blocks = [json.loads(value) for value in re.findall(r"```json\s*(.*?)```", text, re.S)]
    assert len(blocks) == 9, len(blocks)

    requests = 0
    for value in blocks:
        if "request_id" not in value:
            continue
        schema_name = _tool_name(value)
        schema = next(item["inputSchema"] for item in TOOL_DEFINITIONS if item["name"] == schema_name)
        validate_schema(value, schema, "arguments")
        requests += 1
    assert requests == 8, requests

    professionalism_query = next(
        value
        for value in blocks
        if "queries" in value
        and value["queries"]
        and value["queries"][0].get("topic") == "N03"
        and set(value["queries"][0].get("fields", ())) == {"professionalism"}
    )
    assert professionalism_query["queries"][0]["object"] == {"type": "country", "country": "FRA"}
    assert professionalism_query["queries"][0]["parameters"] == {}

    expected_path = STAGE / "expected-military-professionalism-001.json"
    professionalism_path = LIVE / "professionalism-query.json"
    five_path = LIVE / "five-fields-query.json"
    before_path = STAGE / "runtime-source-pins-before-001.json"
    for path in (expected_path, professionalism_path, five_path, before_path):
        assert path.is_file(), path

    expected = _read(expected_path)
    expected_fields = expected["fields"]
    professionalism_response, professionalism_fields = _response_fields(professionalism_path)
    _subset(expected_fields, professionalism_fields)
    assert set(professionalism_fields) >= {"professionalism"}
    assert professionalism_fields["professionalism"]["status"] == "known"
    assert professionalism_fields["professionalism"]["complete"] is True
    assert professionalism_response.get("complete") is True

    five_response, five_fields = _response_fields(five_path)
    result_example = next(
        value
        for value in blocks
        if value.get("topic") == "N03" and "objects" in value and "fields" in value
    )
    _subset(result_example["fields"], five_fields)
    assert set(five_fields) >= {
        "military_technology", "army_tradition", "morale", "professionalism", "discipline"
    }
    assert five_response.get("complete") is False
    assert result_example.get("complete") is False

    links = re.findall(r"\]\(([^)]+)\)", text)
    for target in links:
        if target.startswith(("http:", "https:")):
            continue
        local = (document.parent / target.split("#", 1)[0]).resolve()
        assert local.is_file(), target

    pins = _read(before_path)["files"]
    assert isinstance(pins, list) and pins
    assert all(_pin(ROOT / item["path"])["sha256"] == item["sha256"] for item in pins)

    receipt = {
        "schema": "information_military_professionalism_document_verification.v1",
        "status": "passed",
        "document": _pin(document),
        "json_examples": len(blocks),
        "tool_request_schemas_valid": requests,
        "professionalism_query_matches_expected_001": True,
        "professionalism_query_complete": True,
        "five_field_result_matches_document_example": True,
        "five_field_result_complete": False,
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
