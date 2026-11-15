"""Check T05 documented JSON against schemas and already captured live output."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from work.archive_information_trade_merchant_task import STAGE, read, write
from work.archive_information_trade_income import pin, sha
from work.verify_information_trade_source_details_artifacts import subset


def main():
    document = ROOT / "docs/贸易收入只读接口.md"
    blocks = [json.loads(block) for block in re.findall(r"```json\s*(.*?)```", document.read_text(encoding="utf-8"), re.S)]
    assert len(blocks) == 10
    request_count = 0
    for value in blocks:
        if "request_id" not in value:
            continue
        name = "information_query" if "operation" not in value else "information_manage_report"
        schema = next(item["inputSchema"] for item in TOOL_DEFINITIONS if item["name"] == name)
        validate_schema(value, schema, "arguments")
        request_count += 1
    mixed = read(STAGE / "live-acceptance-001/three-fields-query.json")["items"]
    collection = [value for value in blocks if value.get("basis") == "native_trade_node_collection_predicate"]
    tasks = [value for value in blocks if value.get("basis") == "native_trade_node_merchant_presence_and_collection_predicate"]
    assert len(collection) == 2 and len(tasks) == 1
    for value in collection:
        subset(value, mixed[0 if isinstance(value["value"], list) else 1]["fields"]["collection"])
    subset(tasks[0], mixed[0]["fields"]["merchant_task"])
    expected = read(STAGE / "expected-trade-merchant-task-001.json")
    assert tasks[0]["value"] == expected["country_merchant_tasks"]
    pins = read(STAGE / "runtime-source-pins-before-001.json")["files"]
    assert all(sha(ROOT / item["path"]) == item["sha256"] for item in pins)
    # T04 was not changed; retain the last completed verification as its witness.
    prior = ROOT / "work/runtime/information-trade-merchant-state-20261027-001/document-verification-001.json"
    old_t04 = next(item for item in read(prior)["documents"] if item["path"] == "docs/贸易竞争力只读接口.md")
    assert sha(ROOT / old_t04["path"]) == old_t04["sha256"]
    receipt = {"schema": "information_trade_merchant_task_document_verification.v1", "status": "passed",
               "document": pin(document), "json_examples": len(blocks), "tool_request_schemas_valid": request_count,
               "collection_and_merchant_country_examples_match_actual_MCP": True,
               "merchant_order_matches_independent_raw_reference": True,
               "runtime_source_pins_match_before": True,
               "unchanged_T04_document": pin(ROOT / old_t04["path"]), "prior_T04_verification": pin(prior),
               "new_game_queries_or_pytest_runs": 0}
    write("document-verification-001.json", receipt)
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
