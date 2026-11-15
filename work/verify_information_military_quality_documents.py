"""Verify N03 documentation against saved live output and public schemas."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.tools import TOOL_DEFINITIONS, validate_schema
from work.verify_information_trade_source_details_artifacts import subset

STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    path = ROOT / "docs/军事质量只读接口.md"
    text = path.read_text(encoding="utf-8")
    blocks = [json.loads(value) for value in re.findall(r"```json\s*(.*?)```", text, re.S)]
    assert len(blocks) == 7
    requests = 0
    for value in blocks:
        if "request_id" not in value:
            continue
        name = ("information_query" if "operation" not in value else
                "information_manage_report" if "queries" in value.get("config", {}) else "information_manage_subscription")
        validate_schema(value, next(item["inputSchema"] for item in TOOL_DEFINITIONS if item["name"] == name), "arguments")
        requests += 1
    live = json.loads((STAGE / "live-acceptance-001/two-fields-query.json").read_bytes())
    example = next(value for value in blocks if value.get("topic") == "N03" and "fields" in value)
    subset(example, live["items"][0])
    reference = json.loads((STAGE / "expected-military-quality-001.json").read_bytes())
    for field in ("military_technology", "army_tradition"):
        assert example["fields"][field]["raw_hex"] == reference["fields"][field]["raw_hex"]
    links = re.findall(r"\]\(([^)]+)\)", text)
    for target in links:
        if not target.startswith(("http:", "https:")):
            assert (path.parent / target.split("#", 1)[0]).resolve().is_file(), target
    pins = json.loads((STAGE / "runtime-source-pins-before-001.json").read_bytes())["files"]
    assert all(pin(ROOT / item["path"])["sha256"] == item["sha256"] for item in pins)
    receipt = {"schema": "information_military_quality_document_verification.v1", "status": "passed",
               "document": pin(path), "json_examples": len(blocks), "tool_request_schemas_valid": requests,
               "local_links_valid": len(links), "field_examples_match_actual_MCP": True,
               "raw_fields_match_independent_reference": True, "runtime_sources_match_before": True,
               "new_game_queries_or_pytest_runs": 0}
    output = STAGE / "document-verification-001.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
