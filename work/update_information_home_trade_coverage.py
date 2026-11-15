"""Update T02 from the actual native/static field composition after acceptance."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.composite import CompositeSource
from bridge.information.sources import DiplomacySource
from bridge.information.static_data import StaticTradeSource
from bridge.information.trade_home import NativeTradeHomeSource

STAGE = ROOT/"work/runtime/information-trade-state-20261027-001"


def counts(topics):
    counter = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    return {"topic_count": len(topics), "field_count": sum(counter.values()),
            "available_topic_count": sum(t["status"] == "available" for t in topics),
            "callable_topic_count": sum(t["status"] == "available" for t in topics),
            "field_counts": {key: counter[key] for key in ("available", "partial", "planned")}}


def main():
    target = ROOT/"docs/信息字段覆盖.json"
    old_raw = (STAGE/"coverage-matrix-before-001.json").read_bytes()
    assert target.read_bytes() == old_raw
    live = json.loads((STAGE/"live-acceptance-001/report-004.json").read_bytes())
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    matrix = json.loads(old_raw)
    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeTradeHomeSource(primary), StaticTradeSource(context_provider=primary.context)])
    new_topic = next(t for t in source.catalog() if t["topic_id"] == "T02")
    index = next(i for i,t in enumerate(matrix["topics"]) if t["topic_id"] == "T02")
    old_topic = matrix["topics"][index]
    assert old_topic["fields"]["home_node"]["coverage"] == "planned"
    changes = [field for field in old_topic["fields"] if old_topic["fields"][field]["coverage"] != new_topic["fields"][field]["coverage"]]
    assert changes == ["home_node"]
    matrix["topics"][index] = new_topic
    matrix["counts"] = matrix["expected_counts"] = counts(matrix["topics"])
    matrix["configuration"]["adapters"].append("NativeTradeHomeSource")
    matrix["T02"] = {"fields": new_topic["fields"], "context_scope": new_topic["context_scope"],
                     "source": new_topic["source"], "adapter_sources": new_topic["adapter_sources"]}
    raw = (json.dumps(matrix,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
    actual = json.loads((STAGE/"live-acceptance-001/discovery.json").read_bytes())
    update = {"schema": "information_home_trade_coverage_update.v1", "goal_complete": False,
              "before_sha256": hashlib.sha256(old_raw).hexdigest(), "after_sha256": hashlib.sha256(raw).hexdigest(),
              "counts": matrix["counts"], "actual_live_counts": counts(actual["topics"]),
              "actual_configuration": live["configuration"],
              "changes": [{"topic":"T02","field":"home_node","before":"planned","after":"partial"}],
              "note": "Existing optional static/mission configuration preserved. T02 was already callable through static fields, so configured callable count need not increase."}
    target.write_bytes(raw)
    with (STAGE/"coverage-update-001.json").open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(update,stream,ensure_ascii=False,indent=2)
        stream.write("\n")
    print(json.dumps(update,ensure_ascii=False))


if __name__ == "__main__":
    main()
