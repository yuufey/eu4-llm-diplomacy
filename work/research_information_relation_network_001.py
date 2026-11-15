"""Bounded offline review for the planned R01 relation-network topic.

This script only reviews source windows and already archived JSON reports.  It
does not import a live session, call REA/RPM, start the game, write a save, or
submit a diplomatic action.  The source-window reader deliberately stops at a
small byte budget so this remains useful when ``bridge/diplomacy.py`` grows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "work/runtime/information-relations-20261027-001/relation-source-001.json"
MAX_WINDOW_BYTES = 64 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_window(path: Path, start: int, end: int,
                    markers: tuple[str, ...]) -> dict[str, Any]:
    """Read only one line window and cap the retained source bytes."""

    used = 0
    lines_read = 0
    present = {marker: False for marker in markers}
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            if number > end:
                break
            if number < start:
                continue
            encoded = line.encode("utf-8", errors="replace")
            if used + len(encoded) > MAX_WINDOW_BYTES:
                break
            used += len(encoded)
            lines_read += 1
            for marker in markers:
                present[marker] |= marker in line
    return {
        "line_range": [start, end],
        "bytes_examined": used,
        "lines_examined": lines_read,
        "markers_present": present,
    }


def _source_ref(relative: str, windows: list[tuple[int, int, tuple[str, ...]]]) -> dict[str, Any]:
    path = ROOT / relative
    result: dict[str, Any] = {
        "path": relative,
        "exists": path.is_file(),
    }
    if not path.is_file():
        return result
    result["bytes"] = path.stat().st_size
    result["sha256"] = _sha256(path)
    result["bounded_windows"] = [
        _bounded_window(path, start, end, markers)
        for start, end, markers in windows
    ]
    return result


def _pointer(value: Any, pointer: str) -> Any:
    current = value
    if pointer in ("", "/"):
        return current
    for raw in pointer.lstrip("/").split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(key)]
        else:
            current = current[key]
    return current


def _pick(value: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"value_type": type(value).__name__}
    selected: dict[str, Any] = {
        "available_requested_keys": [key for key in keys if key in value],
    }
    for key in keys:
        if key in value:
            item = value[key]
            if key in {"acceptance", "legality", "visibility", "relationship_state"}:
                # These objects can contain long localized reason/item arrays.
                # Keep the state-bearing scalars while avoiding an archive copy.
                if isinstance(item, dict):
                    item = {
                        subkey: subvalue
                        for subkey, subvalue in item.items()
                        if subkey not in {"items", "reasons", "native_diagnostic"}
                    }
            selected[key] = item
    return selected


def _artifact(relative: str, pointer: str, keys: tuple[str, ...], note: str) -> dict[str, Any]:
    path = ROOT / relative
    result: dict[str, Any] = {
        "path": relative,
        "json_pointer": pointer,
        "note": note,
        "exists": path.is_file(),
    }
    if not path.is_file():
        return result
    result["bytes"] = path.stat().st_size
    result["sha256"] = _sha256(path)
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
        selected = _pointer(value, pointer)
        result["observed"] = _pick(selected, keys)
        if isinstance(selected, dict):
            result["relation_state_present"] = "relationship_state" in selected
    except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        result["read_error"] = type(exc).__name__
    return result


def build_report() -> dict[str, Any]:
    source_refs = [
        _source_ref(
            "docs/信息字段覆盖.json",
            [(1476, 1518, ("R01", "relation_type", '"source": "not_implemented"'))],
        ),
        _source_ref(
            "bridge/information/catalog.py",
            [(132, 141, ('("R01"', 'relation_type', 'not_implemented'))],
        ),
        _source_ref(
            "bridge/information/subject_relations.py",
            [
                (24, 128, ("_ACTION_ID", "_FIELDS", "DiplomacyTools.inspect_diplomatic_action")),
                (136, 210, ("class NativeSubjectRelationSource",)),
                (262, 378, ("_public_guard", "_derive_fields", "inspect_diplomatic_action")),
            ],
        ),
        _source_ref(
            "bridge/diplomacy.py",
            [
                (880, 1030, ("_public_native_inbound_offer", "read_native_alliance_inbound_offers")),
                (15208, 15243, ("def alliance_objects", "QUEUE_LIFECYCLE_NOT_RECOVERED")),
                (15244, 15305, ("def inspect_alliance",)),
                (15895, 16090, ("inspect_royal_marriage", "inspect_guarantee", "inspect_vassalization")),
                (8620, 8813, ("relationship_state", "guarantee_active", "vassal_active")),
                (11460, 11571, ("def _valid_native_inspection", "vassal_state_verified")),
                (21785, 21815, ("def inspect_diplomatic_action",)),
            ],
        ),
        _source_ref(
            "bridge/information/sources.py",
            [(430, 500, ("def _read_inspection", "def _read_inbound", "read_native_alliance_inbound_offers"))],
        ),
        _source_ref(
            "bridge/diplomacy_api.py",
            [(240, 330, ("def capabilities", "def preview"))],
        ),
    ]

    archived_examples = [
        _artifact(
            "work/runtime/diplomacy-query-20261016-r35-vassal-a/vassalization-queries-08b4e54e917040af8bddeaa95f6513f1/report.json",
            "/queries/ORL/offer_vassalization",
            ("action_id", "family", "actor", "recipient", "phase", "relationship_state",
             "vassal_active", "actor_is_overlord", "actor_is_subject", "subject_type", "visibility"),
            "read-only native vassal query; actor FRA is verified overlord and ORL is the subject",
        ),
        _artifact(
            "work/runtime/diplomacy-query-20261015-r30-guarantee-a/guarantee-queries-7cacb0e7cd4349218a6e6815a0dd8292/report.json",
            "/queries/SAV/proclaim_guarantee",
            ("action_id", "family", "actor", "recipient", "phase", "relationship_state", "visibility"),
            "read-only native guarantee query; active=false is a verified relation-state result",
        ),
        _artifact(
            "work/runtime/diplomacy-query-20261015-r31-support-a/support-independence-queries-9bf1deccef644b96a056d65c8c6c257a/report.json",
            "/queries/SWE/support_independence",
            ("action_id", "family", "actor", "recipient", "phase", "relationship_state", "visibility"),
            "read-only native support-independence query; selected-pair direction is actor FRA to recipient SWE",
        ),
        _artifact(
            "work/runtime/diplomacy-query-20261015-r32-military-access-a/military-access-queries-7a97bc04b2ee4d5f89fc5cbac7ef3fab/report.json",
            "/queries/ARA/ask_military_access",
            ("action_id", "family", "actor", "recipient", "phase", "relationship_state", "visibility"),
            "read-only native military-access query; relation direction is not renamed grantor/recipient without a role proof",
        ),
        _artifact(
            "work/runtime/diplomacy-query-20261015-r25-royal-d/royal-marriage-queries-7011638465244738b2c9582292e54651/report.json",
            "/queries/offer_royal_marriage:LAN",
            ("action_id", "actor", "recipient", "phase", "visibility", "legality", "acceptance"),
            "read-only royal-marriage inspection; no relationship_state key, so legality/acceptance is not current relation status",
        ),
        _artifact(
            "work/runtime/alliance-observer-20261013-r3/alliance-inspection-1791873501775372000.json",
            "/countries/2/actions/0",
            ("action_id", "actor_field", "recipient_field", "state_raw", "date_field_28", "date_field_2c", "complete"),
            "legacy read-only native queue item; lifecycle is incomplete and this is not an established relation snapshot",
        ),
        _artifact(
            "bridge/tests/fixtures/information_country_relations_live_1374.json",
            "/report/captures/ORL/public",
            ("action_id", "family", "actor", "recipient", "relationship_state", "vassal_active",
             "actor_is_overlord", "actor_is_subject", "subject_type", "visibility"),
            "recorded projection used by the information tests; its provenance identifies the original native query archive",
        ),
    ]

    return {
        "schema": "information_relation_network_source.v1",
        "stage": "information-relations-20261027-001",
        "status": "partial_existing_selected_pair_sources_only",
        "topic": "R01",
        "title": "外交关系网",
        "review_scope": {
            "kind": "offline_source_and_archive_review",
            "new_game_query": False,
            "rea_or_rpm": False,
            "business_action": False,
            "save_or_date_change": False,
            "full_binary_disassembly": False,
        },
        "catalog_contract": {
            "fields": ["relation_type", "grantor", "recipient", "status", "expires_at"],
            "object_types": ["country_pair"],
            "parameters": {},
            "visibility": "visible_scope",
            "triggers": ["query"],
            "coverage_before_this_review": "planned",
            "source_before_this_review": "not_implemented",
        },
        "source_refs": source_refs,
        "reusable_sources": [
            {
                "source_id": "native_subject_relation_selected_pair",
                "function": "NativeSubjectRelationSource.read",
                "source": "bridge/information/subject_relations.py",
                "reader_call": "DiplomacyTools.inspect_diplomatic_action('offer_vassalization', actor, recipient, 'initiate', {})",
                "input_scope": "country_pair with actor=FRA and a distinct three-letter recipient",
                "output_keys": ["actor", "recipient", "family", "vassal_active", "vassal_state_verified", "actor_is_overlord", "actor_is_subject", "subject_type", "relationship_state"],
                "r01_mapping": {
                    "relation_type": "known=vassalization when family and state verification pass; subject_type is a subtype",
                    "status": "known=active/inactive from vassal_active; inactive is selected-pair not_applicable in the existing R02 adapter",
                    "grantor": "known only with exclusive role flags: actor when actor_is_overlord, otherwise recipient",
                    "recipient": "known only with the same role proof: the opposite selected-pair endpoint",
                    "expires_at": "unknown; no relation expiry key",
                },
                "visible_scope": "selected pair and FRA observer only; the adapter does not enumerate all subjects or relation types",
            },
            {
                "source_id": "native_family_relation_inspections",
                "functions": [
                    "ObserverSession.inspect_guarantee",
                    "ObserverSession.inspect_support_independence",
                    "ObserverSession.inspect_military_access",
                    "ObserverSession.inspect_vassalization",
                    "DiplomacyTools.inspect_diplomatic_action",
                ],
                "source": "bridge/diplomacy.py",
                "reader_call": "inspect_diplomatic_action(action_id, actor, recipient, 'initiate', {})",
                "known_relation_state_keys": {
                    "guarantee": "relationship_state.guarantee_active",
                    "support_independence": "relationship_state.support_independence_active",
                    "military_access": "relationship_state.military_access_active",
                    "vassalization": "relationship_state.vassal_active plus role flags and subject_type",
                    "rival": "relationship_state.rival_active in the dedicated R34 path, when requested",
                },
                "mapping_boundary": "family plus a verified boolean can produce relation_type/status for this selected pair; actor/recipient remain query endpoints unless the family contract proves a grantor role",
                "visible_scope": "exact capability ACK, ready live session, FRA actor scope, selected recipient; preserve inspected.visibility.status separately",
                "not_covered": "no list/network enumeration and no relation expiry",
            },
            {
                "source_id": "native_inbound_offer_observation",
                "function": "ObserverSession.read_native_alliance_inbound_offers",
                "source": "bridge/diplomacy.py",
                "output_keys": ["proposal_id", "action_id", "family", "actor", "recipient", "decision_country", "phase", "observer_status", "currently_pending", "legality_status"],
                "r01_mapping": "pending proposal metadata only; it is not an established relation row and has no expires_at",
                "catalog_owner": "A04 外来提议, not R01",
            },
            {
                "source_id": "native_alliance_queue_observation",
                "function": "ObserverSession.alliance_objects",
                "source": "bridge/diplomacy.py",
                "output_keys": ["object_id", "action_id", "actor", "recipient", "lifecycle_stage", "decision_country", "source", "complete", "date_raw", "reason_code"],
                "r01_mapping": "pending queue objects only; lifecycle_stage remains unknown and no relation status/expiry is proven",
                "catalog_owner": "legacy queue evidence, not a public R01 reader",
            },
        ],
        "field_contract": {
            "relation_type": {
                "coverage": "partial_selected_pair",
                "known": ["vassalization", "guarantee", "support_independence", "military_access", "rival when dedicated path is requested"],
                "unknown": ["alliance current state", "royal_marriage current state", "port access", "trade league and other relation families"],
                "guard": "use family/relationship_state only; do not use action_id alone",
            },
            "status": {
                "coverage": "partial_selected_pair",
                "known": "active/inactive only when the family-specific relationship_state boolean and state_verified guard pass",
                "unknown": "legality.status, acceptance.predicted_response, native_would_accept and action visibility do not establish current relation status",
            },
            "grantor": {
                "coverage": "partial_directional",
                "known": "vassalization role flags identify the overlord endpoint; other family queries expose actor/recipient but no generic grantor role",
                "unknown": "military access grantor and any relation not carrying a role proof",
            },
            "recipient": {
                "coverage": "partial_directional",
                "known": "vassalization opposite endpoint after role proof; otherwise retain the selected query recipient without relabeling it as grantor/beneficiary",
                "unknown": "generic direction for families without role flags",
            },
            "expires_at": {
                "coverage": "unsupported",
                "reason": "no current relation expiry key in the selected-pair projections, inbound offers, or queue objects; inspect_alliance expiry is a short-lived query-wire deadline, not relation expiry",
            },
        },
        "minimal_implementation_contract": {
            "object": {"type": "country_pair", "actor": "FRA", "recipient": "TAG"},
            "parameters": {},
            "row_shape": {
                "relation_type": "family-specific verified label",
                "status": "active|inactive|unknown",
                "grantor": "role-derived tag or unknown",
                "recipient": "role-derived tag or selected endpoint",
                "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
                "visibility": "preserve inspected.visibility.status as source metadata",
            },
            "read_plan": [
                "Call only the family-specific query adapter for a selected pair; never infer a relation from legality or native_would_accept.",
                "Require family, endpoint, relationship_state and the family state_verified guard before publishing a known row.",
                "For vassalization, map grantor/recipient from exclusive actor_is_overlord/actor_is_subject; keep other directions unresolved until their role contract is proven.",
                "Keep alliance/royal-marriage rows unknown until a current relation-state reader exists; do not use offer or break-action legality.",
                "Leave expires_at unknown; do not expose the observer query deadline as a relation expiry.",
            ],
            "coverage": "partial; selected pair only, not a complete relation network",
        },
        "archived_example_pins": archived_examples,
        "conclusion": {
            "directly_reusable": "selected-pair family-specific relationship_state queries and the existing R02 subject adapter",
            "not_yet_reusable_for_full_R01": "complete relation enumeration, alliance/royal current-state rows, generic grantor/recipient roles, and expires_at",
            "next_smallest_gap": "add a read-only selected-pair relation-state adapter per remaining relation family, then prove a bounded visible relation enumerator before changing R01 coverage",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output),
        "bytes": args.output.stat().st_size,
        "status": report["status"],
        "archived_example_count": len(report["archived_example_pins"]),
        "source_ref_count": len(report["source_refs"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
