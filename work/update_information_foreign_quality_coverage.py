"""Publish the live-verified quality field without changing the full goal."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-foreign-military-quality-20261029-001"


def read(path):
    assert 0 < path.stat().st_size <= 16 * 1024 * 1024
    return json.loads(path.read_bytes())


def counts(topics):
    fields = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    statuses = Counter(topic["status"] for topic in topics)
    return {"topic_count": len(topics), "field_count": sum(fields.values()),
        "topic_status_counts": {key: statuses[key] for key in ("available", "partial", "planned")},
        "field_counts": {key: fields[key] for key in ("available", "partial", "planned")},
        "available_topic_count": statuses["available"], "callable_topic_count": statuses["available"]}


def main():
    path = ROOT / "docs/信息字段覆盖.json"
    raw = path.read_bytes()
    matrix = json.loads(raw)
    before = deepcopy(matrix)
    assert matrix["counts"]["field_counts"] == {"available": 62, "partial": 187, "planned": 148}
    receipt = read(STAGE / "mcp-live-001/receipt.json")
    discovery = read(STAGE / "mcp-live-001/discovery.json")
    assert receipt["status"] == "passed" and receipt["server_exit_code"] == 0
    assert receipt["source_pins_unchanged"] is True and receipt["cleanup_completed"] is True
    assert all(value is True for value in receipt["checks"].values())
    assert receipt["periodic_counts"]["2"] >= 2 and receipt["periodic_counts"]["5"] >= 2
    topic = next(row for row in discovery["topics"] if row["topic_id"] == "F02")
    index = next(i for i, row in enumerate(matrix["topics"]) if row["topic_id"] == "F02")
    old = matrix["topics"][index]
    assert set(old["fields"]) == set(topic["fields"])
    assert old["fields"]["military_quality"]["coverage"] == "planned"
    assert all(row["coverage"] == "partial" for row in topic["fields"].values())
    matrix["topics"][index] = deepcopy(topic)
    matrix["F02"] = {key: deepcopy(topic[key]) for key in
        ("fields", "context_scope", "source", "adapter_sources") if key in topic}
    matrix["counts"] = counts(matrix["topics"])
    matrix["expected_counts"] = deepcopy(matrix["counts"])
    assert matrix["counts"]["field_counts"] == {"available": 62, "partial": 188, "planned": 147}
    assert matrix["counts"]["topic_count"] == 74 and matrix["counts"]["field_count"] == 397
    assert matrix["goal_complete"] is False
    assert all(a == b for a, b in zip(before["topics"], matrix["topics"]) if a["topic_id"] != "F02")
    with (STAGE / "coverage-before-001.json").open("xb") as stream:
        stream.write(raw)
    updated = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    path.write_bytes(updated)
    result = {"status": "updated_partial", "goal_complete": False,
        "coverage_changes": {"F02.military_quality": ["planned", "partial"]},
        "before_sha256": hashlib.sha256(raw).hexdigest(), "after_sha256": hashlib.sha256(updated).hexdigest(),
        "configured_counts": matrix["counts"], "actual_live_counts": counts(discovery["topics"]),
        "scope": "12 native quality components; cache freshness, actual UI and unsupported branch conditions remain unclosed"}
    with (STAGE / "coverage-update-001.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
