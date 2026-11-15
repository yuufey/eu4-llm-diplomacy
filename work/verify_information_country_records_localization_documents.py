"""Verify batch53 documentation and write its archive receipt.

This verifier reads only receipts, documents, local files and production
validators.  It never starts tests, MCP, a game, RPM, REA, or a native read.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
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
    pin,
)
from work.document_information_country_records_localization import (  # noqa: E402
    COVERAGE,
    DOCS,
    PUBLIC_DOC,
    _EXPECTED_COVERAGE,
    collect_ready_inputs,
)


RECEIPT = STAGE / "document-verification-001.json"


class DocumentInvalid(RuntimeError):
    pass


def _json_blocks(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\n(.*?)\n```", text, re.DOTALL)
    for block in blocks:
        json.loads(block)
    return len(blocks)


def _check_links(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    checked = 0
    for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text):
        target = match.group(1).strip().strip("<>").split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        checked += 1
        if not (path.parent / target).resolve().is_file():
            raise DocumentInvalid(f"broken local link in {path.name}: {target}")
    return checked


def _check_api_shape() -> dict[str, Any]:
    primary = DiplomacySource(observer="FRA")
    state = NativeCountryStateSource(primary)
    records = NativeCountryRecordsSource(primary)
    relation = NativeRelationSource(primary)
    composite = CompositeSource(primary, [state, records, relation])
    relation_query = {
        "topic": "R01",
        "object": {"type": "country_pair", "actor": "FRA", "recipient": "ORL"},
        "fields": ["relation_type", "status", "grantor", "recipient"],
        "parameters": {},
    }
    modifier_query = {
        "topic": "N07",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["name", "description"],
        "parameters": {},
    }
    normalized_relation = composite.validate_query(relation_query)
    normalized_modifier = composite.validate_query(modifier_query)
    if normalized_relation["topic"] != "R01" or normalized_modifier["topic"] != "N07":
        raise DocumentInvalid("production query normalization returned the wrong topic")
    catalog = {item["topic_id"]: item for item in composite.catalog()}
    if not {"relation_type", "status", "grantor", "recipient"} <= set(catalog["R01"]["fields"]):
        raise DocumentInvalid("R01 catalog shape is incomplete")
    if not {"name", "description"} <= set(catalog["N07"]["fields"]):
        raise DocumentInvalid("N07 localization catalog shape is incomplete")
    return {
        "topics": {topic: sorted(catalog[topic]["fields"]) for topic in ("N07", "R01")},
        "normalized_queries": [normalized_relation, normalized_modifier],
        "route_owner_topics": {
            topic: [type(owner).__name__ for owner, _entry in composite._routes.get(topic, [])]
            for topic in ("N01", "N07", "R01")
        },
    }


def main() -> int:
    try:
        data = collect_ready_inputs()
        if RECEIPT.exists():
            raise DocumentInvalid("document verification receipt already exists")
        for path in (*DOCS, PUBLIC_DOC):
            if not path.is_file():
                raise DocumentInvalid(f"document is missing: {path}")
        if _IN_PROGRESS_MARKER in DOCS[0].read_text(encoding="utf-8"):
            raise DocumentInvalid("HANDOFF still contains the batch53 in-progress marker")
        if _IN_PROGRESS_MARKER in DOCS[1].read_text(encoding="utf-8"):
            raise DocumentInvalid("README still contains the batch53 in-progress marker")
        for path in DOCS[2:]:
            if "第五十三批" not in "\n".join(path.read_text(encoding="utf-8").splitlines()[:12]):
                raise DocumentInvalid(f"{path.name} lacks the batch53 top summary")
        json_count = _json_blocks(PUBLIC_DOC)
        links = _check_links(PUBLIC_DOC)
        api_shape = _check_api_shape()
        coverage = data["coverage"]
        comparison = data["comparison"]
        required_artifacts = {
            **data["artifacts"],
            "documents": {
                path.relative_to(ROOT).as_posix(): pin(path)
                for path in (*DOCS, PUBLIC_DOC)
            },
        }
        result = {
            "schema": "information_country_records_localization_document_verification.v1",
            "status": "passed",
            "batch": 53,
            "stage": STAGE.relative_to(ROOT).as_posix(),
            "documents": [path.relative_to(ROOT).as_posix() for path in (*DOCS, PUBLIC_DOC)],
            "json_schema": {"public_doc_json_blocks": json_count, "parsed": True},
            "api_shape": api_shape,
            "local_links": {"public_doc_checked": links, "passed": True},
            "artifact_pins": required_artifacts,
            "coverage": {
                "changes": sorted(
                    {f"{topic}.{field}" for topic, field in _EXPECTED_COVERAGE}
                ),
                "configured_counts": coverage["counts"],
                "actual_live_counts": coverage["actual_live_counts"],
                "goal_complete": coverage["goal_complete"],
                "goal_status": coverage["goal_status"],
            },
            "formal_regression": comparison["full"],
            "new_game_queries_or_pytest_runs": 0,
            "document_update_only": True,
        }
        RECEIPT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(json.dumps({"status": result["status"], "path": RECEIPT.relative_to(ROOT).as_posix()}, ensure_ascii=False))
        return 0
    except (DocumentInvalid, RuntimeError, KeyError, ValueError) as exc:
        print(json.dumps({"status": "not_ready", "reason": str(exc)}, ensure_ascii=False))
        return 2


_IN_PROGRESS_MARKER = "第五十三批关系状态与修正文本（进行中）"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    raise SystemExit(main())
