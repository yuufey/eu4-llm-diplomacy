"""Derive batch53 configured and live coverage from the real composite catalog.

The helper only writes the configured matrix and its receipt when explicitly
run.  ``--snapshot`` is the pre-acceptance operation.  It does not run MCP,
the game, RPM, REA, or pytest.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.composite import CompositeSource  # noqa: E402
from bridge.information.country_records import NativeCountryRecordsSource  # noqa: E402
from bridge.information.country_state import NativeCountryStateSource  # noqa: E402
from bridge.information.relation_state import NativeRelationSource  # noqa: E402
from bridge.information.sources import DiplomacySource  # noqa: E402
from work.archive_information_country_records_localization import (  # noqa: E402
    STAGE,
    write,
)


PROMOTED_FIELDS = {
    "N07": ("name", "description"),
    "R01": ("relation_type", "status", "grantor", "recipient"),
}
_MERGED_TOPICS = ("N01", "N07", "N08", "R01")

_MERGE_KEYS = (
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
)


def _read(path: Path):
    return json.loads(path.read_bytes())


def counts(topics: list[dict[str, Any]]) -> dict[str, Any]:
    field_counts = Counter()
    topic_status_counts = Counter()
    field_count = 0
    for topic in topics:
        if not isinstance(topic, dict):
            raise AssertionError("catalog topic is not an object")
        topic_status_counts[str(topic.get("status", "unknown"))] += 1
        fields = topic.get("fields", {})
        if not isinstance(fields, dict):
            raise AssertionError(f"catalog fields are not an object: {topic.get('topic_id')}")
        for descriptor in fields.values():
            if not isinstance(descriptor, dict):
                raise AssertionError(f"field descriptor is not an object: {topic.get('topic_id')}")
            field_counts[str(descriptor.get("coverage", "unknown"))] += 1
            field_count += 1
    return {
        "topic_count": len(topics),
        "field_count": field_count,
        "topic_status_counts": dict(sorted(topic_status_counts.items())),
        "available_topic_count": topic_status_counts.get("available", 0),
        "callable_topic_count": topic_status_counts.get("available", 0),
        "field_counts": dict(sorted(field_counts.items())),
    }


def _catalog_topics() -> tuple[CompositeSource, list[dict[str, Any]]]:
    primary = DiplomacySource(observer="FRA")
    state = NativeCountryStateSource(primary)
    records = NativeCountryRecordsSource(primary)
    relations = NativeRelationSource(primary)
    source = CompositeSource(primary, [state, records, relations])
    catalog = source.catalog()
    routes = getattr(source, "_routes", {})
    owner_names = {
        topic: [type(owner).__name__ for owner, _entry in route]
        for topic, route in routes.items()
        if topic in {"N01", "N07", "R01"}
    }
    if "N01" not in owner_names or "NativeCountryStateSource" not in owner_names["N01"]:
        raise AssertionError("N01 monthly/state owner is absent from the composite")
    if "NativeCountryRecordsSource" not in owner_names.get("N01", []):
        raise AssertionError("N01 loans owner is absent from the composite")
    if owner_names.get("N07") != ["NativeCountryRecordsSource"]:
        raise AssertionError(f"unexpected N07 owner routing: {owner_names.get('N07')}")
    if owner_names.get("R01") != ["NativeRelationSource"]:
        raise AssertionError(f"unexpected R01 owner routing: {owner_names.get('R01')}")
    return source, catalog


def _topics_from_discovery(document: dict[str, Any]) -> list[dict[str, Any]]:
    topics = document.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("live discovery topics are missing")
    return topics


def _merge_topic(before: dict[str, Any], catalog_topic: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(before)
    for key in _MERGE_KEYS:
        if key in catalog_topic:
            merged[key] = deepcopy(catalog_topic[key])
    for field, descriptor in catalog_topic.get("fields", {}).items():
        if field in merged.get("fields", {}):
            merged["fields"][field] = deepcopy(descriptor)
    return merged


def _coverage_changes(before_topics, after_topics):
    before = {
        (topic.get("topic_id"), field): descriptor.get("coverage")
        for topic in before_topics
        for field, descriptor in topic.get("fields", {}).items()
    }
    after = {
        (topic.get("topic_id"), field): descriptor.get("coverage")
        for topic in after_topics
        for field, descriptor in topic.get("fields", {}).items()
    }
    changes = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            changes.append({"topic": key[0], "field": key[1],
                            "before": before.get(key), "after": after.get(key)})
    return changes


def _target_descriptors(catalog_by_topic):
    result = {}
    for topic, fields in PROMOTED_FIELDS.items():
        entry = catalog_by_topic.get(topic)
        if not isinstance(entry, dict):
            raise AssertionError(f"adapter catalog topic missing: {topic}")
        result[topic] = {}
        for field in fields:
            descriptor = entry.get("fields", {}).get(field)
            if not isinstance(descriptor, dict):
                raise AssertionError(f"adapter catalog field missing: {topic}.{field}")
            if descriptor.get("coverage") in (None, "planned"):
                raise AssertionError(f"adapter catalog did not implement {topic}.{field}")
            result[topic][field] = deepcopy(descriptor)
    return result


def main(snapshot: bool = False) -> None:
    target = ROOT / "docs/信息字段覆盖.json"
    baseline = STAGE / "coverage-matrix-before-001.json"
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")
    if snapshot:
        if baseline.exists() or (STAGE / "coverage-update-001.json").exists():
            raise AssertionError("batch53 coverage snapshot/receipt already exists")
        with baseline.open("xb") as stream:
            stream.write(target.read_bytes())
        return

    old_raw = baseline.read_bytes()
    if target.read_bytes() != old_raw:
        raise AssertionError("coverage matrix changed after the batch53 snapshot")
    live = _read(STAGE / "live-acceptance-001/report.json")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise AssertionError("live acceptance did not pass")
    if isinstance(live.get("checks"), dict) and not all(live["checks"].values()):
        raise AssertionError("live acceptance contains a failed check")

    matrix = _read(baseline)
    source, catalog = _catalog_topics()
    catalog_by_topic = {topic.get("topic_id"): topic for topic in catalog}
    descriptors = _target_descriptors(catalog_by_topic)
    before_topics = matrix.get("topics")
    if not isinstance(before_topics, list):
        raise AssertionError("coverage matrix topics are missing")
    after_topics = deepcopy(before_topics)
    for index, topic in enumerate(before_topics):
        topic_id = topic.get("topic_id")
        if topic_id in _MERGED_TOPICS:
            if topic_id not in catalog_by_topic:
                raise AssertionError(f"adapter catalog topic missing during merge: {topic_id}")
            after_topics[index] = _merge_topic(topic, catalog_by_topic[topic_id])

    changes = _coverage_changes(before_topics, after_topics)
    expected_change_keys = {
        (topic, field)
        for topic, fields in PROMOTED_FIELDS.items()
        for field in fields
    }
    if {(item["topic"], item["field"]) for item in changes} != expected_change_keys:
        raise AssertionError(f"unexpected configured coverage changes: {changes}")
    if any(item["before"] != "planned" or item["after"] != "partial" for item in changes):
        raise AssertionError(f"localized fields did not promote planned->partial: {changes}")

    before_by_topic = {topic.get("topic_id"): topic for topic in before_topics}
    after_by_topic = {topic.get("topic_id"): topic for topic in after_topics}
    if (before_by_topic["N01"]["fields"]["loans"].get("coverage") != "partial"
            or after_by_topic["N01"]["fields"]["loans"].get("coverage") != "partial"):
        raise AssertionError("N01 loans coverage changed unexpectedly")

    after_counts = counts(after_topics)
    before_counts = counts(before_topics)
    if after_counts["field_count"] != before_counts["field_count"]:
        raise AssertionError("coverage promotion changed the catalog field count")
    matrix["topics"] = after_topics
    matrix["counts"] = matrix["expected_counts"] = after_counts
    for topic_id in PROMOTED_FIELDS:
        compact = next(topic for topic in after_topics if topic.get("topic_id") == topic_id)
        matrix[topic_id] = {
            key: deepcopy(compact[key])
            for key in ("fields", "context_scope", "source", "adapter_sources")
            if key in compact
        }
    routes = getattr(source, "_routes", {})
    adapter_names = matrix.setdefault("configuration", {}).setdefault("adapters", [])
    for owner in ("NativeCountryStateSource", "NativeCountryRecordsSource", "NativeRelationSource"):
        if owner not in adapter_names:
            adapter_names.append(owner)
    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    discovery = _read(STAGE / "live-acceptance-001/discovery.json")
    actual_topics = _topics_from_discovery(discovery)
    actual = counts(actual_topics)
    before_live = _read(
        ROOT / "work/runtime/information-country-records-20261027-001/"
        "live-acceptance-001/discovery.json"
    )
    actual_changes = _coverage_changes(_topics_from_discovery(before_live), actual_topics)
    if {(item["topic"], item["field"]) for item in actual_changes} != expected_change_keys:
        raise AssertionError(f"unexpected live coverage changes: {actual_changes}")
    if any(item["before"] != "planned" or item["after"] != "partial" for item in actual_changes):
        raise AssertionError(f"live localized fields did not promote planned->partial: {actual_changes}")

    update = {
        "schema": "information_country_records_localization_coverage_update.v1",
        "batch": 53,
        "goal_complete": False,
        "goal_status": "active",
        "before_sha256": hashlib.sha256(old_raw).hexdigest(),
        "after_sha256": hashlib.sha256(raw).hexdigest(),
        "counts": after_counts,
        "actual_live_counts": actual,
        "actual_configuration": live.get("configuration"),
        "coverage_changes": changes,
        "actual_live_coverage_changes": actual_changes,
        "loan_coverage_unchanged": True,
        "catalog_topics": {
            topic: {
                "status": catalog_by_topic[topic].get("status"),
                "fields": descriptors[topic],
            }
            for topic in PROMOTED_FIELDS
        },
        "owner_routes": {
            topic: [type(owner).__name__ for owner, _entry in routes.get(topic, [])]
            for topic in ("N01", "N07", "R01")
        },
        "source": {
            "adapter": "CompositeSource",
            "owners": [
                "NativeCountryStateSource",
                "NativeCountryRecordsSource",
                "NativeRelationSource",
            ],
            "catalog_origin": "production_composite_catalog",
            "discovery_origin": "live-acceptance-001/discovery.json",
            "supported_scope": "FRA/1.37.4",
        },
        "unchanged": {
            "N01.loans": "coverage remains partial; only localized metadata and R01 are promoted in this batch",
            "other_topics": True,
        },
        "note": (
            "Configured and runtime counts are derived independently from the production CompositeSource catalog and the live discovery receipt; no totals are hardcoded."
        ),
    }
    if (STAGE / "coverage-update-001.json").exists():
        raise AssertionError("coverage update receipt already exists")
    target.write_bytes(raw)
    write("coverage-update-001.json", update)
    print(json.dumps(update, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", action="store_true")
    args = parser.parse_args()
    main(snapshot=args.snapshot)
