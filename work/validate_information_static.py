"""Verify configured static trade files through the actual information CLI.

Does not open a game process or issue native commands. The top-level game
context stays unready; only static definition items can be complete.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.catalog import coverage_report
from bridge.information.composite import CompositeSource
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.sources import DiplomacySource
from bridge.information.static_data import StaticTradeSource


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    base = DiplomacySource()
    static = StaticTradeSource(context_provider=base.context)
    source = CompositeSource(base, [NativeCountryStateSource(base), static])
    context = static.context()
    write(args.output / "static-context.json", context)
    assert context["status"] == "ready" and context["complete"] is True, context
    query = {"topic": "T01", "object": {"type": "trade_node", "node_id": "english_channel"},
             "fields": ["node_id", "provinces", "upstream", "downstream", "routes"], "parameters": {}}
    node = static.read(query)
    assert node["complete"] is True and node["fields"]["provinces"]["value"], node
    province = node["fields"]["provinces"]["value"][0]
    queries = [query,
               {"topic": "G04", "object": {"type": "province", "province_id": province}, "fields": ["trade_node"]},
               {"topic": "C01", "object": {"type": "session"}, "fields": ["game_day"]}]
    request = {"tool": "information_query", "arguments": {"request_id": "static-installed-query", "queries": queries}}
    completed = subprocess.run([sys.executable, "tools/serve_information.py", "--jsonl", "--static-game-data",
                                "--database", str(args.output / "information.sqlite3")], cwd=ROOT,
                               input=json.dumps(request) + "\n", capture_output=True, text=True, encoding="utf-8", timeout=30)
    (args.output / "cli-stderr.txt").write_text(completed.stderr, encoding="utf-8")
    (args.output / "cli-stdout.jsonl").write_text(completed.stdout, encoding="utf-8")
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    write(args.output / "query-result.json", result)
    assert result["context"]["status"] == "unready" and result["context"]["session_id"] is None
    assert result["status"] == "partial"
    assert result["items"][0]["complete"] is True
    assert result["items"][1]["fields"]["trade_node"]["value"] == "english_channel"
    assert result["items"][2]["fields"]["game_day"]["status"] == "unavailable"
    coverage = coverage_report(source)
    coverage["configuration"] = {"native_country_state": True, "static_game_data": True,
                                  "static_definitions_sha256": context["definitions_sha256"],
                                  "implementation_coverage_is_not_live_acceptance": True}
    write(args.output / "coverage.json", coverage)
    summary = {"status": "passed", "scope": "configured_static_rules", "game_process_accessed": False,
               "definitions_sha256": context["definitions_sha256"],
               "configuration_sha256": context["configuration_sha256"],
               "checks": ["current_enabled_mod_stack", "cli_static_node_query", "province_to_node", "unready_game_item_preserved"],
               "coverage": {"topics": coverage["topic_count"], "fields": coverage["field_count"],
                            "routable_topics": len(coverage["available_topics"]),
                            "field_states": dict(Counter(field["coverage"] for topic in coverage["topics"] for field in topic["fields"].values()))}}
    write(args.output / "report.json", summary)
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
