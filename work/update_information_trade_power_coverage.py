"""Publish only the two T04 fields verified by batch44 acceptance."""
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

STAGE = ROOT / "work/runtime/information-trade-power-20261027-001"


def counts(topics):
    fields = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    return {"topic_count": len(topics), "field_count": sum(fields.values()),
            "available_topic_count": sum(t["status"] == "available" for t in topics),
            "callable_topic_count": sum(t["status"] == "available" for t in topics),
            "field_counts": {key: fields[key] for key in ("available", "partial", "planned")}}


def main():
    target = ROOT / "docs/信息字段覆盖.json"
    old_raw = (STAGE / "coverage-matrix-before-001.json").read_bytes()
    assert target.read_bytes() == old_raw
    live = json.loads((STAGE / "live-acceptance-001/report.json").read_bytes())
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    matrix = json.loads(old_raw)
    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeTradePowerSource(primary)])
    new_topic = next(t for t in source.catalog() if t["topic_id"] == "T04")
    index = next(i for i, t in enumerate(matrix["topics"]) if t["topic_id"] == "T04")
    old_topic = matrix["topics"][index]
    assert all(old_topic["fields"][field]["coverage"] == "planned" for field in ("country_power", "total_power"))
    changes = [field for field in old_topic["fields"] if old_topic["fields"][field]["coverage"] != new_topic["fields"][field]["coverage"]]
    assert changes == ["country_power", "total_power"]
    matrix["topics"][index] = new_topic
    matrix["counts"] = matrix["expected_counts"] = counts(matrix["topics"])
    assert matrix["counts"]["topic_count"] == 74 and matrix["counts"]["field_count"] == 397
    matrix["configuration"]["adapters"].append("NativeTradePowerSource")
    matrix["T04"] = {"fields": new_topic["fields"], "context_scope": new_topic["context_scope"], "source": new_topic["source"]}
    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    actual = json.loads((STAGE / "live-acceptance-001/discovery.json").read_bytes())
    update = {"schema": "information_trade_power_coverage_update.v1", "goal_complete": False,
              "before_sha256": hashlib.sha256(old_raw).hexdigest(), "after_sha256": hashlib.sha256(raw).hexdigest(),
              "counts": matrix["counts"], "actual_live_counts": counts(actual["topics"]),
              "actual_configuration": live["configuration"],
              "changes": [{"topic": "T04", "field": field, "before": "planned", "after": "partial"} for field in changes],
              "note": "Preserves all other topic metadata and optional-source configuration. Shares, sources and competitors remain incomplete."}
    assert not (STAGE / "coverage-update-001.json").exists()
    target.write_bytes(raw)
    with (STAGE / "coverage-update-001.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(update, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(update, ensure_ascii=False))


if __name__ == "__main__":
    main()
