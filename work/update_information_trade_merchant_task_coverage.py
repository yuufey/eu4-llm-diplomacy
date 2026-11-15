"""Promote only T05.merchant_task after batch48 live acceptance."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.composite import CompositeSource
from bridge.information.sources import DiplomacySource
from bridge.information.trade_details import NativeTradeDetailsSource
from bridge.information.trade_income import NativeTradeIncomeSource
from bridge.information.trade_power import NativeTradePowerSource
from work.archive_information_trade_merchant_task import STAGE, write


EXPECTED_STATIC_FIELD_COUNTS = {"available": 56, "partial": 119, "planned": 222}
EXPECTED_ACTUAL_FIELD_COUNTS = {"available": 56, "partial": 108, "planned": 233}


def counts(topics):
    fields = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    return {
        "topic_count": len(topics),
        "field_count": sum(fields.values()),
        "available_topic_count": sum(topic["status"] == "available" for topic in topics),
        "callable_topic_count": sum(topic["status"] == "available" for topic in topics),
        "field_counts": {key: fields[key] for key in ("available", "partial", "planned")},
    }


def main(snapshot=False):
    target = ROOT / "docs/信息字段覆盖.json"
    baseline = STAGE / "coverage-matrix-before-001.json"
    assert STAGE.is_dir()
    if snapshot:
        assert not baseline.exists()
        assert not (STAGE / "coverage-update-001.json").exists()
        with baseline.open("xb") as stream:
            stream.write(target.read_bytes())
        return

    old = baseline.read_bytes()
    assert target.read_bytes() == old
    live = json.loads((STAGE / "live-acceptance-001/report.json").read_bytes())
    assert live["status"] == "passed" and live["server_exit_code"] == 0
    assert all(live.get("checks", {}).values())

    matrix = json.loads(old)
    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(
        primary,
        [
            NativeTradeIncomeSource(primary),
            NativeTradePowerSource(primary),
            NativeTradeDetailsSource(primary),
        ],
    )
    catalog = source.catalog()
    topic = next(item for item in catalog if item["topic_id"] == "T05")
    index = next(i for i, item in enumerate(matrix["topics"]) if item["topic_id"] == "T05")
    before_topic = matrix["topics"][index]
    assert before_topic["fields"]["merchant_task"]["coverage"] == "planned"
    assert before_topic["fields"]["collection"]["coverage"] == "partial"
    assert before_topic["fields"]["transfer"]["coverage"] == "planned"
    assert before_topic["fields"]["steering_direction"]["coverage"] == "planned"
    assert topic["fields"]["merchant_task"]["coverage"] == "partial"

    changes = []
    for field in before_topic["fields"]:
        before_coverage = before_topic["fields"][field]["coverage"]
        after_coverage = topic["fields"].get(field, {}).get("coverage", before_coverage)
        if before_coverage != after_coverage:
            changes.append({"topic": "T05", "field": field, "before": before_coverage, "after": after_coverage})
    assert changes == [{"topic": "T05", "field": "merchant_task", "before": "planned", "after": "partial"}], changes

    # Merge the live merchant field while preserving the other T05 fields and
    # every T04 metadata value byte-for-byte in the logical JSON projection.
    merged_topic = json.loads(json.dumps(before_topic, ensure_ascii=False))
    merged_topic["fields"]["merchant_task"] = topic["fields"]["merchant_task"]
    matrix["topics"][index] = merged_topic
    matrix["T05"] = {
        key: merged_topic[key]
        for key in ("fields", "context_scope", "source")
        if key in merged_topic
    }
    if "adapter_sources" in merged_topic:
        matrix["T05"]["adapter_sources"] = merged_topic["adapter_sources"]

    matrix["counts"] = matrix["expected_counts"] = counts(matrix["topics"])
    assert matrix["counts"]["topic_count"] == 74
    assert matrix["counts"]["field_count"] == 397
    assert matrix["counts"]["callable_topic_count"] == 37
    assert matrix["counts"]["field_counts"] == EXPECTED_STATIC_FIELD_COUNTS

    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    discovery = json.loads((STAGE / "live-acceptance-001/discovery.json").read_bytes())
    actual = counts(discovery["topics"])
    assert actual["topic_count"] == 74 and actual["field_count"] == 397
    assert actual["callable_topic_count"] == 34
    assert actual["field_counts"] == EXPECTED_ACTUAL_FIELD_COUNTS

    update = {
        "schema": "information_trade_merchant_task_coverage_update.v1",
        "goal_complete": False,
        "before_sha256": hashlib.sha256(old).hexdigest(),
        "after_sha256": hashlib.sha256(raw).hexdigest(),
        "counts": matrix["counts"],
        "actual_live_counts": actual,
        "actual_configuration": live.get("configuration"),
        "coverage_changes": changes,
        "unchanged": {"T05.collection": "partial", "T04": "metadata preserved"},
        "merchant_task_contract": {
            "node_enum": ["none", "collect", "transfer"],
            "country_rows": "active rows only",
            "gaps": ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "TRANSIT_IDLE_TASK_LIFECYCLE_NOT_PROVEN"],
        },
        "note": "Only T05.merchant_task is promoted; collection remains partial and false is not a standalone transfer/no-merchant proof.",
    }
    assert not (STAGE / "coverage-update-001.json").exists()
    target.write_bytes(raw)
    write("coverage-update-001.json", update)
    print(json.dumps(update, ensure_ascii=False))


def refresh_collection_metadata():
    """Replace the obsolete enum gap, preserving the first coverage receipt."""
    target = ROOT / "docs/信息字段覆盖.json"
    old = target.read_bytes()
    first_path = STAGE / "coverage-update-001.json"
    first = json.loads(first_path.read_bytes())
    assert hashlib.sha256(old).hexdigest() == first["after_sha256"]
    matrix = json.loads(old)
    topic = next(item for item in matrix["topics"] if item["topic_id"] == "T05")
    old_gaps = topic["fields"]["collection"]["gaps"]
    assert old_gaps == ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "MERCHANT_TASK_ENUM_NOT_PROVEN"]
    actual = NativeTradeIncomeSource(DiplomacySource(observer="FRA")).catalog()[0]["fields"]["collection"]
    assert actual["coverage"] == topic["fields"]["collection"]["coverage"] == "partial"
    new_gaps = actual["gaps"]
    assert new_gaps == ["NATIVE_CACHE_FRESHNESS_NOT_PROVEN", "MERCHANT_TASK_LIFECYCLE_NOT_PROVEN"]
    topic["fields"]["collection"]["gaps"] = new_gaps
    matrix["T05"]["fields"]["collection"]["gaps"] = new_gaps
    assert counts(matrix["topics"]) == matrix["counts"]
    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    receipt = {**first, "after_sha256": hashlib.sha256(raw).hexdigest(),
               "intermediate_receipt": {"path": first_path.relative_to(ROOT).as_posix(),
                                        "sha256": hashlib.sha256(first_path.read_bytes()).hexdigest()},
               "intermediate_matrix_sha256": first["after_sha256"],
               "metadata_changes": [{"topic": "T05", "field": "collection", "property": "gaps",
                                     "before": old_gaps, "after": new_gaps}],
               "note": "Merchant-task coverage changes as in 001; collection stays partial but its obsolete enum gap is replaced by the still-unproven full lifecycle."}
    assert not (STAGE / "coverage-update-002.json").exists()
    target.write_bytes(raw)
    write("coverage-update-002.json", receipt)
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    assert sys.argv[1:] in ([], ["--snapshot"], ["--refresh-collection-gap"])
    if sys.argv[1:] == ["--refresh-collection-gap"]:
        refresh_collection_metadata()
    else:
        main(snapshot=sys.argv[1:] == ["--snapshot"])
