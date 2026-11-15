"""Export the current offline catalog after guarded N04 live acceptance.

This inventories declarations only. It does not open a game session or turn
catalog availability into evidence of lossless events or whole-plan completion.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.composite import CompositeSource
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.domestic_pressure import NativeDomesticPressureSource
from bridge.information.mission_definitions import MissionDefinitionIndex
from bridge.information.missions import MissionInformationSource, NativeMissionReader
from bridge.information.sources import DiplomacySource
from bridge.information.static_data import StaticTradeSource
from bridge.information.subject_relations import NativeSubjectRelationSource


def build() -> dict:
    primary = DiplomacySource(observer="FRA")
    adapters = [NativeCountryStateSource(primary), NativeDomesticPressureSource(primary),
                NativeSubjectRelationSource(primary), StaticTradeSource(context_provider=primary.context),
                MissionInformationSource(primary, MissionDefinitionIndex(), NativeMissionReader(primary))]
    topics = CompositeSource(primary, adapters).catalog()
    counter = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    counts = {"topic_count": len(topics), "field_count": sum(counter.values()),
              "available_topic_count": sum(topic["status"] == "available" for topic in topics),
              "callable_topic_count": sum(topic["status"] == "available" for topic in topics),
              "field_counts": {key: counter[key] for key in ("available", "partial", "planned")}}
    expected = {"topic_count": 74, "field_count": 397, "available_topic_count": 35,
                "callable_topic_count": 35,
                "field_counts": {"available": 54, "partial": 107, "planned": 236}}
    if counts != expected:
        raise ValueError(f"current_catalog_count_mismatch:{counts}")
    n04 = next(topic for topic in topics if topic["topic_id"] == "N04")
    for field in ("stability", "war_exhaustion", "corruption"):
        item = n04["fields"][field]
        if not (item["coverage"] == "available" and item["runtime_validation"] == "validated"
                and item["supported_countries"] == ["FRA"] and item["scale"] == 1000):
            raise ValueError(f"N04_scope_mismatch:{field}")
    for field in ("religious_unity", "overextension", "unrest"):
        if n04["fields"][field]["coverage"] != "planned":
            raise ValueError(f"N04_unimplemented_field_promoted:{field}")
    if any(field["coverage"] != "planned" for topic in topics
           if topic["topic_id"] in {"B01", "B02", "B03", "B04"}
           for field in topic["fields"].values()):
        raise ValueError("battle_field_promoted_without_capture")
    return {"schema": "information-recovery-coverage-v1", "status": "passed", "goal_complete": False,
            "counts": counts, "expected_counts": expected, "topics": topics,
            "N04": {"fields": n04["fields"], "runtime_validation": n04["runtime_validation"],
                    "observer_scope": n04["observer_scope"]},
            "configuration": {"observer": "FRA", "live_session_opened": False,
                              "catalog_is_not_live_acceptance": True,
                              "adapters": [type(adapter).__name__ for adapter in adapters]}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sync-docs", action="store_true")
    args = parser.parse_args()
    report = build()
    raw = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as stream:
        stream.write(raw)
    if args.sync_docs:
        (ROOT / "docs/信息字段覆盖.json").write_bytes(raw)
    print(json.dumps({"path": str(args.output), "sha256": hashlib.sha256(raw).hexdigest(),
                      "counts": report["counts"], "docs_synced": args.sync_docs}, ensure_ascii=False))


if __name__ == "__main__":
    main()
