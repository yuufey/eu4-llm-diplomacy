"""Compare documented field shapes with live and explicitly offline outputs."""
import json
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from work.archive_information_trade_collection import STAGE, pin, read, sha, write
from work.verify_information_trade_source_details_artifacts import subset


def main():
    documents = [ROOT / "docs/贸易收入只读接口.md", ROOT / "docs/贸易竞争力只读接口.md"]
    blocks = [[json.loads(block) for block in re.findall(r"```json\s*(.*?)```", path.read_text(encoding="utf-8"), re.S)] for path in documents]
    assert sum(map(len, blocks)) == 14
    requests = 0
    for value in [value for group in blocks for value in group]:
        if "request_id" not in value:
            continue
        name = ("information_query" if "operation" not in value else
                "information_manage_report" if "queries" in value.get("config", {}) else
                "information_manage_subscription")
        schema = next(item["inputSchema"] for item in TOOL_DEFINITIONS if item["name"] == name)
        validate_schema(value, schema, "arguments")
        requests += 1
    live = read(STAGE / "live-acceptance-001/income-collection-query.json")["items"]
    collection_examples = [value for value in blocks[0] if value.get("basis") == "native_trade_node_collection_predicate"]
    assert len(collection_examples) == 2
    for value in collection_examples:
        subset(value, live[0 if isinstance(value["value"], list) else 1]["fields"]["collection"])
    trade = read(STAGE / "live-acceptance-001/t04-four-fields-query.json")["items"][0]["fields"]
    subset(next(value for value in blocks[1] if "shares" in value and "sources" in value), trade)

    # This is explicitly a fake dynamic item, never a live trade observation.
    # Use the same real child validators and neutral-reader capture seam as
    # the already completed tests to check the documented name shape.
    import pytest
    from bridge.tests import test_information_trade_details as fixture
    example = next(value for value in blocks[1] if value.get("key") == "TRADE_SOURCE_EXAMPLE")
    with pytest.MonkeyPatch.context() as patch, TemporaryDirectory(prefix="eu4-trade-name-doc-") as temporary:
        configured = fixture.configured.__wrapped__(patch)
        key = example["key"]
        source, base, parent_calls, name_calls = fixture._localized_trade_source(
            configured, Path(temporary), [key.encode("ascii") + b"\0"],
            {key: fixture._localization_entry(key, text=example["value"])})
        result = source.read(fixture._query("alpha", ["sources"]), base.context())
        name = result["fields"]["sources"]["value"]["FRA"]["dynamic_sources"]["items"][0]["name"]
        subset(example, name)
        assert len(parent_calls) == 1 and name_calls == [[key]]
        offline = {"schema": "information_dynamic_name_offline_example.v1", "live_game_observation": False,
                   "basis": "bounded_fake_trade_memory_real_child_validators_and_neutral_reader_capture_seam",
                   "key": key, "name": name, "parent_capture_count": len(parent_calls), "localization_calls": name_calls,
                   "counts_as_new_pytest_run": False}
    write("offline-dynamic-name-example-001.json", offline)
    pins = read(STAGE / "runtime-source-pins-before-001.json")["files"]
    assert all(sha(ROOT / item["path"]) == item["sha256"] for item in pins)
    receipt = {"schema": "information_trade_collection_document_verification.v1", "status": "passed",
               "documents": [pin(path) for path in documents], "json_examples": sum(map(len, blocks)),
               "tool_request_schemas_valid": requests, "collection_examples_match_actual_MCP": True,
               "t04_example_matches_actual_MCP": True, "dynamic_name_example_is_offline": True,
               "offline_name_output": pin(STAGE / "offline-dynamic-name-example-001.json"),
               "runtime_source_pins_match_before": True}
    write("document-verification-001.json", receipt)
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
