"""Update only T05 income in the existing configured matrix after live acceptance."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.trade_income import NativeTradeIncomeSource
from bridge.information.sources import DiplomacySource

STAGE = ROOT / "work/runtime/information-budget-collectors-20261027-001"


def main():
    target = ROOT / "docs/信息字段覆盖.json"
    old = (STAGE / "coverage-matrix-before-001.json").read_bytes()
    assert target.read_bytes() == old
    live = json.loads((STAGE / "live-acceptance-001/report.json").read_bytes())
    assert live["status"] == "passed"
    matrix = json.loads(old)
    item = NativeTradeIncomeSource(DiplomacySource(observer="FRA")).catalog()[0]
    topic = next(x for x in matrix["topics"] if x["topic_id"] == "T05")
    assert topic["fields"]["income"]["coverage"] == "planned"
    for key, value in item.items():
        if key == "fields":
            topic[key].update(value)
        else:
            topic[key] = value
    counter = Counter(field["coverage"] for t in matrix["topics"] for field in t["fields"].values())
    counts = {"topic_count": len(matrix["topics"]), "field_count": sum(counter.values()),
              "available_topic_count": sum(t["status"] == "available" for t in matrix["topics"]),
              "callable_topic_count": sum(t["status"] == "available" for t in matrix["topics"]),
              "field_counts": {key: counter[key] for key in ("available", "partial", "planned")}}
    assert (counts["topic_count"], counts["field_count"]) == (74, 397)
    matrix["counts"] = matrix["expected_counts"] = counts
    matrix["configuration"]["adapters"].append("NativeTradeIncomeSource")
    matrix["T05"] = {"fields": topic["fields"], "runtime_validation": topic["runtime_validation"], "observer_scope": topic["observer_scope"]}
    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    discovery = json.loads((STAGE / "live-acceptance-001/discovery.json").read_bytes())
    actual = Counter(field["coverage"] for t in discovery["topics"] for field in t["fields"].values())
    report = {"schema": "information_trade_income_coverage_update.v1", "goal_complete": False,
              "before_sha256": hashlib.sha256(old).hexdigest(), "after_sha256": hashlib.sha256(raw).hexdigest(),
              "counts": counts, "actual_live_counts": {"topic_count": len(discovery["topics"]), "field_count": sum(actual.values()),
              "callable_topic_count": sum(t["status"] == "available" for t in discovery["topics"]),
              "field_counts": {key: actual[key] for key in ("available", "partial", "planned")}},
              "changes": [{"topic": "T05", "field": "income", "before": "planned", "after": item["fields"]["income"]["coverage"]}],
              "configuration_note": "Existing optional static/mission configuration is preserved. Live acceptance enables neither static nor mission nor battle sources."}
    target.write_bytes(raw)
    with (STAGE / "coverage-update-001.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
