"""Promote the bounded N03 discipline and morale fields after live batch50 acceptance.

``--snapshot`` records the pre-change matrix and is the only operation that
may run before live acceptance.  The normal path derives both configured and
runtime discovery counts, and refuses to write a coverage update until the
matrix and source receipt still match the saved baseline.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.composite import CompositeSource
from bridge.information.military_quality import NativeMilitaryQualitySource
from bridge.information.sources import DiplomacySource
from work.archive_information_military_effective import STAGE, write


EXPECTED_STATIC_FIELD_COUNTS = {"available": 59, "partial": 120, "planned": 218}
EXPECTED_ACTUAL_FIELD_COUNTS = {"available": 59, "partial": 109, "planned": 229}
EXPECTED_CONFIGURED_CALLABLE_TOPICS = 38
EXPECTED_ACTUAL_CALLABLE_TOPICS = 35
PROMOTED_FIELDS = ("discipline", "morale")


def counts(topics):
    fields = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    return {
        "topic_count": len(topics),
        "field_count": sum(fields.values()),
        "available_topic_count": sum(topic.get("status") == "available" for topic in topics),
        "callable_topic_count": sum(topic.get("status") == "available" for topic in topics),
        "field_counts": {key: fields[key] for key in ("available", "partial", "planned")},
    }


def _read(path: Path):
    return json.loads(path.read_bytes())


def _catalog_topic():
    primary = DiplomacySource(observer="FRA")
    source = CompositeSource(primary, [NativeMilitaryQualitySource(primary)])
    return source, next(topic for topic in source.catalog() if topic["topic_id"] == "N03")


def _merge_topic(before, catalog_topic):
    merged = deepcopy(before)
    # The adapter owns the topic-level runtime contract.  Keep every other
    # N03 field from the saved matrix while replacing only the two promoted
    # fields.  This prevents a later catalog addition from changing coverage
    # for unrelated planned fields.
    for key in (
        "catalog_ids",
        "title",
        "topic_id",
        "object_types",
        "parameters",
        "source",
        "status",
        "supported_versions",
        "triggers",
        "visibility",
        "observer_roles",
        "observer_scope",
        "context_scope",
        "runtime_validation",
        "scope_note",
        "adapter_sources",
    ):
        if key in catalog_topic:
            merged[key] = deepcopy(catalog_topic[key])
    for field in PROMOTED_FIELDS:
        merged["fields"][field] = deepcopy(catalog_topic["fields"][field])
    return merged


def main(snapshot: bool = False):
    target = ROOT / "docs/信息字段覆盖.json"
    baseline = STAGE / "coverage-matrix-before-001.json"
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")

    if snapshot:
        if baseline.exists() or (STAGE / "coverage-update-001.json").exists():
            raise AssertionError("batch50 coverage snapshot/receipt already exists")
        with baseline.open("xb") as stream:
            stream.write(target.read_bytes())
        return

    old_raw = baseline.read_bytes()
    if target.read_bytes() != old_raw:
        raise AssertionError("coverage matrix changed after the batch50 snapshot")
    live = _read(STAGE / "live-acceptance-001/report.json")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise AssertionError("live acceptance did not pass")
    if not all(live.get("checks", {}).values()):
        raise AssertionError("live acceptance contains a failed check")

    matrix = _read(baseline)
    source, catalog_topic = _catalog_topic()
    index = next(i for i, topic in enumerate(matrix["topics"]) if topic["topic_id"] == "N03")
    before_topic = matrix["topics"][index]
    if any(before_topic["fields"][field]["coverage"] != "planned" for field in PROMOTED_FIELDS):
        raise AssertionError("N03 promotion is not based on planned fields")
    after_topic = _merge_topic(before_topic, catalog_topic)
    changes = [
        {
            "topic": "N03",
            "field": field,
            "before": before_topic["fields"][field]["coverage"],
            "after": after_topic["fields"][field]["coverage"],
        }
        for field in before_topic["fields"]
        if before_topic["fields"][field].get("coverage")
        != after_topic["fields"].get(field, before_topic["fields"][field]).get("coverage")
    ]
    expected_changes = [
        {"topic": "N03", "field": "discipline", "before": "planned", "after": "partial"},
        {"topic": "N03", "field": "morale", "before": "planned", "after": "available"},
    ]
    if sorted(changes, key=lambda row: row["field"]) != sorted(expected_changes, key=lambda row: row["field"]):
        raise AssertionError(f"unexpected coverage changes: {changes}")

    matrix["topics"][index] = after_topic
    matrix["counts"] = matrix["expected_counts"] = counts(matrix["topics"])
    if matrix["counts"]["field_counts"] != EXPECTED_STATIC_FIELD_COUNTS:
        raise AssertionError(matrix["counts"])
    if matrix["counts"]["topic_count"] != 74 or matrix["counts"]["field_count"] != 397:
        raise AssertionError(matrix["counts"])
    if matrix["counts"]["callable_topic_count"] != EXPECTED_CONFIGURED_CALLABLE_TOPICS:
        raise AssertionError(matrix["counts"])

    # Preserve the matrix's compact topic projection convention.  N04 is not
    # rewritten here; its final v4 dependency is pinned as a runtime source only.
    matrix["N03"] = {
        key: deepcopy(after_topic[key])
        for key in ("fields", "context_scope", "source", "adapter_sources")
        if key in after_topic
    }
    adapters = matrix.setdefault("configuration", {}).setdefault("adapters", [])
    if "NativeMilitaryQualitySource" not in adapters:
        adapters.append("NativeMilitaryQualitySource")

    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    discovery = _read(STAGE / "live-acceptance-001/discovery.json")
    actual = counts(discovery["topics"])
    if actual["field_counts"] != EXPECTED_ACTUAL_FIELD_COUNTS:
        raise AssertionError(actual)
    if actual["topic_count"] != 74 or actual["field_count"] != 397:
        raise AssertionError(actual)
    if actual["callable_topic_count"] != EXPECTED_ACTUAL_CALLABLE_TOPICS:
        raise AssertionError(actual)

    update = {
        "schema": "information_military_effective_coverage_update.v1",
        "goal_complete": False,
        "before_sha256": hashlib.sha256(old_raw).hexdigest(),
        "after_sha256": hashlib.sha256(raw).hexdigest(),
        "counts": matrix["counts"],
        "actual_live_counts": actual,
        "actual_configuration": live.get("configuration"),
        "coverage_changes": changes,
        "unchanged": {
            "N03": "discipline is promoted to partial and morale to available; technology and army_tradition remain available while professionalism/military_modifiers remain planned",
            "N04": "coverage and logical projection unchanged; domestic-pressure profile-v4 is pinned separately",
            "other_topics": True,
        },
        "source": {
            "adapter": "NativeMilitaryQualitySource",
            "basis": {
                "discipline": "native country discipline calculation from copied inputs",
                "morale": "native country morale caches",
            },
            "supported_scope": "FRA/1.37.4",
        },
        "note": "Configured and runtime counts are derived from the catalog and the live discovery receipt; no missionbattle entries are counted as callable.",
    }
    if (STAGE / "coverage-update-001.json").exists():
        raise AssertionError("coverage update receipt already exists")
    target.write_bytes(raw)
    write("coverage-update-001.json", update)
    print(json.dumps(update, ensure_ascii=False))


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--snapshot"]):
        raise SystemExit("usage: update_information_military_effective_coverage.py [--snapshot]")
    main(snapshot=sys.argv[1:] == ["--snapshot"])
