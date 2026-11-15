"""Refresh T04 source metadata without promoting its partial coverage."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.composite import CompositeSource
from bridge.information.sources import DiplomacySource
from bridge.information.trade_power import NativeTradePowerSource
from bridge.information.trade_details import NativeTradeDetailsSource

STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"


def counts(topics):
    counter = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    return {"topic_count": len(topics), "field_count": sum(counter.values()),
            "available_topic_count": sum(t["status"] == "available" for t in topics),
            "callable_topic_count": sum(t["status"] == "available" for t in topics),
            "field_counts": {key: counter[key] for key in ("available", "partial", "planned")}}


def main():
    target = ROOT / "docs/信息字段覆盖.json"
    old_bytes = (STAGE / "coverage-matrix-before-001.json").read_bytes()
    assert target.read_bytes() == old_bytes
    live = json.loads((STAGE / "live-acceptance-001/report.json").read_bytes())
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    matrix = json.loads(old_bytes)
    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeTradePowerSource(primary), NativeTradeDetailsSource(primary)])
    topic = next(t for t in source.catalog() if t["topic_id"] == "T04")
    index = next(i for i, t in enumerate(matrix["topics"]) if t["topic_id"] == "T04")
    old_counts = counts(matrix["topics"])
    assert all(matrix["topics"][index]["fields"][key]["coverage"] == topic["fields"][key]["coverage"] == "partial"
               for key in ("country_power", "total_power", "shares", "sources"))
    matrix["topics"][index] = topic
    matrix["T04"] = {"fields": topic["fields"], "context_scope": topic["context_scope"],
                     "source": topic["source"], "adapter_sources": topic["adapter_sources"]}
    matrix["counts"] = matrix["expected_counts"] = counts(matrix["topics"])
    assert old_counts == matrix["counts"] and old_counts["field_count"] == 397 and old_counts["topic_count"] == 74
    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    discovery = json.loads((STAGE / "live-acceptance-001/discovery.json").read_bytes())
    update = {"schema": "information_trade_extended_sources_metadata_update.v1", "goal_complete": False,
              "before_sha256": hashlib.sha256(old_bytes).hexdigest(), "after_sha256": hashlib.sha256(raw).hexdigest(),
              "counts": matrix["counts"], "actual_live_counts": counts(discovery["topics"]),
              "actual_configuration": live["configuration"], "coverage_changes": [],
              "metadata_changes": {"topic": "T04", "field": "sources", "unit": topic["fields"]["sources"].get("unit"),
                                   "gaps": topic["fields"]["sources"].get("gaps")},
              "note": "Additional native source details do not establish complete coverage, cache freshness or competitor scope."}
    assert not (STAGE / "coverage-update-001.json").exists()
    target.write_bytes(raw)
    with (STAGE / "coverage-update-001.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(update, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(update, ensure_ascii=False))


if __name__ == "__main__":
    main()
