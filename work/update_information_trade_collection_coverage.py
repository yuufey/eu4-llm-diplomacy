"""Promote only T05.collection and refresh conditional T04 name metadata."""
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
from bridge.information.trade_income import NativeTradeIncomeSource
from work.archive_information_trade_collection import STAGE, write


def counts(topics):
    fields = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    return {"topic_count": len(topics), "field_count": sum(fields.values()),
            "available_topic_count": sum(topic["status"] == "available" for topic in topics),
            "callable_topic_count": sum(topic["status"] == "available" for topic in topics),
            "field_counts": {key: fields[key] for key in ("available", "partial", "planned")}}


def main(snapshot=False):
    target = ROOT / "docs/信息字段覆盖.json"
    baseline = STAGE / "coverage-matrix-before-001.json"
    if snapshot:
        with baseline.open("xb") as stream:
            stream.write(target.read_bytes())
        return
    old = baseline.read_bytes()
    assert target.read_bytes() == old
    live = json.loads((STAGE / "live-acceptance-001/report.json").read_bytes())
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    matrix = json.loads(old)
    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeTradeIncomeSource(primary), NativeTradePowerSource(primary), NativeTradeDetailsSource(primary)])
    catalog = source.catalog()
    old_counts = counts(matrix["topics"])
    changes = []
    for topic_id in ("T04", "T05"):
        topic = next(item for item in catalog if item["topic_id"] == topic_id)
        index = next(i for i, item in enumerate(matrix["topics"]) if item["topic_id"] == topic_id)
        for key, value in topic["fields"].items():
            before = matrix["topics"][index]["fields"][key]["coverage"]
            if before != value["coverage"]:
                changes.append({"topic": topic_id, "field": key, "before": before, "after": value["coverage"]})
        matrix["topics"][index] = topic
        matrix[topic_id] = {key: topic[key] for key in ("fields", "context_scope", "source")}
        if "adapter_sources" in topic:
            matrix[topic_id]["adapter_sources"] = topic["adapter_sources"]
    assert changes == [{"topic": "T05", "field": "collection", "before": "planned", "after": "partial"}], changes
    matrix["counts"] = matrix["expected_counts"] = counts(matrix["topics"])
    assert matrix["counts"]["topic_count"] == 74 and matrix["counts"]["field_count"] == 397
    assert old_counts["field_counts"] == {"available": 56, "partial": 117, "planned": 224}
    assert matrix["counts"]["field_counts"] == {"available": 56, "partial": 118, "planned": 223}
    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    discovery = json.loads((STAGE / "live-acceptance-001/discovery.json").read_bytes())
    update = {"schema": "information_trade_collection_coverage_update.v1", "goal_complete": False,
              "before_sha256": hashlib.sha256(old).hexdigest(), "after_sha256": hashlib.sha256(raw).hexdigest(),
              "counts": matrix["counts"], "actual_live_counts": counts(discovery["topics"]),
              "actual_configuration": live["configuration"], "coverage_changes": changes,
              "name_metadata": matrix["T04"]["fields"]["sources"].get("gaps"),
              "note": "Collection is the aggregate native predicate; it does not establish merchant presence/task or transfer relations. Dynamic name positives are offline only."}
    assert not (STAGE / "coverage-update-001.json").exists()
    target.write_bytes(raw)
    write("coverage-update-001.json", update)
    print(json.dumps(update, ensure_ascii=False))


if __name__ == "__main__":
    assert sys.argv[1:] in ([], ["--snapshot"])
    main(snapshot=sys.argv[1:] == ["--snapshot"])
