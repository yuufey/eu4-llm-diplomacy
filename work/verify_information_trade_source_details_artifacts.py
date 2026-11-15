"""Check documented examples against the batch46 response and tool schemas."""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from work.archive_information_trade_source_details import STAGE, pin, read, sha, write


def subset(expected, actual):
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        for key, value in expected.items():
            assert key in actual, key
            subset(value, actual[key])
    elif isinstance(expected, list):
        assert isinstance(actual, list) and len(expected) == len(actual)
        for wanted, value in zip(expected, actual):
            subset(wanted, value)
    else:
        assert expected == actual, (expected, actual)


def main():
    document = ROOT / "docs/贸易竞争力只读接口.md"
    examples = [json.loads(block) for block in re.findall(r"```json\s*(.*?)```", document.read_text(encoding="utf-8"), re.S)]
    assert len(examples) == 7
    requests = 0
    for value in examples:
        if "request_id" not in value:
            continue
        if "operation" not in value:
            name = "information_query"
        elif "queries" in value.get("config", {}):
            name = "information_manage_report"
        else:
            name = "information_manage_subscription"
        schema = next(item["inputSchema"] for item in TOOL_DEFINITIONS if item["name"] == name)
        validate_schema(value, schema, "arguments")
        requests += 1
    response = read(STAGE / "live-acceptance-001/four-fields-query.json")
    actual = response["items"][0]["fields"]
    example = next(value for value in examples if "shares" in value and "sources" in value)
    subset(example, actual)
    pins = read(STAGE / "runtime-source-pins-before-001.json")["files"]
    assert all(sha(ROOT / item["path"]) == item["sha256"] for item in pins)
    value = {"schema": "information_trade_source_document_verification.v1", "status": "passed",
             "document": pin(document), "json_examples": len(examples), "request_examples_schema_valid": requests,
             "shares_and_sources_example_matches_actual_champagne_response": True,
             "runtime_sources_match_pre_acceptance_pins": True,
             "response": pin(STAGE / "live-acceptance-001/four-fields-query.json")}
    write("document-verification-001.json", value)
    print(json.dumps(value, ensure_ascii=False))


if __name__ == "__main__":
    main()
