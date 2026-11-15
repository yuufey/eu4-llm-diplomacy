"""Promote batch52 country-record fields from the real adapter catalog.

The snapshot path is the only pre-acceptance operation.  The normal path
reads the saved matrix, builds the production country-record adapter catalog,
and uses the live discovery receipt for the second count.  Counts are
calculated from those documents; no topic or field totals are embedded here.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.composite import CompositeSource
from bridge.information.sources import DiplomacySource
from work.archive_information_country_records import STAGE, BASELINE, write


PROMOTED_FIELDS = {
    "N01": ("loans",),
    "N07": ("modifier_id", "target", "effects"),
    "N08": (
        "modifier_start_date",
        "modifier_end_date",
        "remaining_days",
        "duration_type",
    ),
}
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


def counts(topics):
    """Return counts derived from the supplied catalog or discovery topics."""
    field_counts = Counter()
    topic_status_counts = Counter()
    field_count = 0
    for topic in topics:
        if not isinstance(topic, dict):
            raise AssertionError("catalog topic is not an object")
        topic_status_counts[str(topic.get("status", "unknown"))] += 1
        fields = topic.get("fields", {})
        if not isinstance(fields, dict):
            raise AssertionError(
                f"catalog fields are not an object: {topic.get('topic_id')}"
            )
        for descriptor in fields.values():
            if not isinstance(descriptor, dict):
                raise AssertionError(
                    f"field descriptor is not an object: {topic.get('topic_id')}"
                )
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


def _construct_records_adapter(primary: Any):
    """Load the root-owned adapter without importing it before it exists."""
    module = importlib.import_module("bridge.information.country_records")
    factories = [
        getattr(module, name, None)
        for name in ("build_source", "build_adapter", "create_source")
    ]
    for factory in factories:
        if callable(factory):
            for args, kwargs in (
                ((primary,), {}),
                ((), {"base_source": primary}),
                ((), {"source": primary}),
            ):
                try:
                    return factory(*args, **kwargs)
                except TypeError:
                    continue
    names = (
        "NativeCountryRecordsSource",
        "NativeCountryRecordSource",
        "NativeCountryRecordsAdapter",
        "NativeCountryRecordAdapter",
        "CountryRecordsSource",
        "CountryRecordsAdapter",
    )
    classes = [
        getattr(module, name, None)
        for name in names
    ]
    classes = [item for item in classes if isinstance(item, type)]
    if not classes:
        classes = [
            item
            for name, item in vars(module).items()
            if isinstance(item, type)
            and "record" in name.lower()
            and callable(getattr(item, "catalog", None))
        ]
    if not classes:
        raise AssertionError(
            "country_records.py exports no supported adapter/factory name"
        )
    attempts = (
        ((primary,), {}),
        ((primary,), {"capture": None}),
        ((), {"base_source": primary}),
        ((), {"source": primary}),
        ((), {}),
    )
    errors = []
    for cls in classes:
        for args, kwargs in attempts:
            try:
                return cls(*args, **kwargs)
            except TypeError as exc:
                errors.append(f"{cls.__name__}:{exc}")
    raise AssertionError(
        "country-record adapter constructor mismatch: " + "; ".join(errors)
    )


def _catalog_topics():
    from bridge.information.country_state import NativeCountryStateSource
    primary = DiplomacySource(observer="FRA")
    adapter = _construct_records_adapter(primary)
    # N01 has two field owners.  Include the established owner so the
    # primary catalog's planned placeholders cannot replace its live fields.
    source = CompositeSource(primary, [NativeCountryStateSource(primary), adapter])
    return source, source.catalog()


def _topics_from_discovery(document):
    topics = document.get("topics")
    if not isinstance(topics, list):
        raise AssertionError("live discovery topics are missing")
    return topics


def _merge_topic(before, catalog_topic):
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
            changes.append(
                {
                    "topic": key[0],
                    "field": key[1],
                    "before": before.get(key),
                    "after": after.get(key),
                }
            )
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
                raise AssertionError(
                    f"adapter catalog did not implement {topic}.{field}"
                )
            result[topic][field] = deepcopy(descriptor)
    return result


def main(snapshot: bool = False):
    target = ROOT / "docs/信息字段覆盖.json"
    baseline = STAGE / "coverage-matrix-before-001.json"
    if not STAGE.is_dir():
        raise AssertionError(f"stage missing: {STAGE}")
    if snapshot:
        if baseline.exists() or (STAGE / "coverage-update-001.json").exists():
            raise AssertionError("batch52 coverage snapshot/receipt already exists")
        with baseline.open("xb") as stream:
            stream.write(target.read_bytes())
        return

    old_raw = baseline.read_bytes()
    if target.read_bytes() != old_raw:
        raise AssertionError("coverage matrix changed after the batch52 snapshot")
    live = _read(STAGE / "live-acceptance-001/report.json")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise AssertionError("live acceptance did not pass")
    if not all(live.get("checks", {}).values()):
        raise AssertionError("live acceptance contains a failed check")

    matrix = _read(baseline)
    source, catalog = _catalog_topics()
    catalog_by_topic = {
        topic.get("topic_id"): topic
        for topic in catalog
    }
    descriptors = _target_descriptors(catalog_by_topic)
    before_topics = matrix.get("topics")
    if not isinstance(before_topics, list):
        raise AssertionError("coverage matrix topics are missing")
    after_topics = deepcopy(before_topics)
    for index, topic in enumerate(before_topics):
        topic_id = topic.get("topic_id")
        if topic_id in descriptors:
            after_topics[index] = _merge_topic(topic, catalog_by_topic[topic_id])

    changes = _coverage_changes(before_topics, after_topics)
    expected_change_keys = {
        (topic, field)
        for topic, fields in PROMOTED_FIELDS.items()
        for field in fields
    }
    if {(item["topic"], item["field"]) for item in changes} != expected_change_keys:
        raise AssertionError(
            f"unexpected configured coverage changes: {changes}"
        )
    if any(item["before"] != "planned" for item in changes):
        raise AssertionError(
            f"promotion did not start from planned fields: {changes}"
        )

    after_counts = counts(after_topics)
    before_counts = counts(before_topics)
    if after_counts["field_count"] != before_counts["field_count"]:
        raise AssertionError("coverage promotion changed the catalog field count")
    matrix["topics"] = after_topics
    matrix["counts"] = matrix["expected_counts"] = after_counts
    for topic_id in PROMOTED_FIELDS:
        compact = next(
            topic for topic in after_topics
            if topic.get("topic_id") == topic_id
        )
        matrix[topic_id] = {
            key: deepcopy(compact[key])
            for key in ("fields", "context_scope", "source", "adapter_sources")
            if key in compact
        }
    routes = getattr(source, "_routes", {})
    adapter_name = "NativeCountryRecordsSource"
    if "N01" in routes and routes["N01"]:
        adapter_name = next(type(owner).__name__ for owner, entry in routes["N01"]
                            if "loans" in entry["fields"])
    adapter_names = matrix.setdefault("configuration", {}).setdefault(
        "adapters", []
    )
    if adapter_name not in adapter_names:
        adapter_names.append(adapter_name)
    raw = (json.dumps(matrix, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    discovery = _read(STAGE / "live-acceptance-001/discovery.json")
    actual_topics = _topics_from_discovery(discovery)
    actual = counts(actual_topics)
    before_live = _read(BASELINE / "live-acceptance-001/discovery.json")
    actual_changes = _coverage_changes(_topics_from_discovery(before_live), actual_topics)
    if {
        (item["topic"], item["field"])
        for item in actual_changes
    } != expected_change_keys:
        raise AssertionError(
            f"unexpected live coverage changes: {actual_changes}"
        )
    if any(item["before"] != "planned" for item in actual_changes):
        raise AssertionError(
            f"live promotion did not start from planned fields: {actual_changes}"
        )

    update = {
        "schema": "information_country_records_coverage_update.v1",
        "goal_complete": False,
        "goal_status": "active",
        "before_sha256": hashlib.sha256(old_raw).hexdigest(),
        "after_sha256": hashlib.sha256(raw).hexdigest(),
        "counts": after_counts,
        "actual_live_counts": actual,
        "actual_configuration": live.get("configuration"),
        "coverage_changes": changes,
        "actual_live_coverage_changes": actual_changes,
        "catalog_topics": {
            topic: {
                "status": catalog_by_topic[topic].get("status"),
                "fields": descriptors[topic],
            }
            for topic in PROMOTED_FIELDS
        },
        "unchanged": {
            "N01": "monthly ledger and treasury fields remain unchanged; war_income remains planned",
            "N07": "name, description and source remain planned",
            "N08": "only modifier_start_date, modifier_end_date, remaining_days and duration_type are promoted; removal_conditions remains planned",
            "other_topics": True,
        },
        "source": {
            "adapter": adapter_name,
            "catalog_origin": "production_adapter_catalog",
            "discovery_origin": "live-acceptance-001/discovery.json",
            "supported_scope": "FRA/1.37.4",
        },
        "note": (
            "Configured and runtime counts and every promotion are derived "
            "from the real adapter catalog and live discovery receipt; no "
            "catalog totals are hardcoded."
        ),
    }
    if (STAGE / "coverage-update-001.json").exists():
        raise AssertionError("coverage update receipt already exists")
    target.write_bytes(raw)
    write("coverage-update-001.json", update)
    print(json.dumps(update, ensure_ascii=False))


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--snapshot"]):
        raise SystemExit(
            "usage: update_information_country_records_coverage.py [--snapshot]"
        )
    main(snapshot=sys.argv[1:] == ["--snapshot"])
