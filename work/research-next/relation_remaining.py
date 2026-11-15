"""Bounded source/evidence review for the remaining R01 relation families.

This review is deliberately source-only.  It inventories the existing
fleet-basing and trade-league action candidates, then checks whether the
current relation readers have a producer for an established relationship.
Action legality, pending offers, and acceptance/mode predicates are retained
as context but are never promoted to current-state evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-relation-remaining-20261027-001/"
    "relation-remaining-source-001.json"
)
TARGET_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
TARGET_VERSION = "1.37.4"
MAX_WINDOW_BYTES = 64 * 1024


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bounded_window(
    path: Path,
    start: int,
    end: int,
    markers: Iterable[str],
) -> dict[str, Any]:
    """Read only the requested line window and record marker presence."""
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
            for marker in present:
                present[marker] |= marker in line
    return {
        "line_range_inclusive": [start, end],
        "bytes_examined": used,
        "lines_examined": lines_read,
        "markers_present": present,
    }


def source_ref(
    relative: str,
    windows: list[tuple[int, int, tuple[str, ...]]],
    role: str,
) -> dict[str, Any]:
    path = ROOT / relative
    result: dict[str, Any] = {
        "path": relative,
        "exists": path.is_file(),
        "role": role,
    }
    if not path.is_file():
        return result
    result["bytes"] = path.stat().st_size
    result["sha256"] = file_sha(path)
    result["bounded_windows"] = [
        bounded_window(path, start, end, markers)
        for start, end, markers in windows
    ]
    return result


def read_json(relative: str) -> tuple[Path, dict[str, Any]]:
    path = ROOT / relative
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"expected object JSON: {relative}")
    return path, value


def _catalog_actions(value: Any, wanted: set[str], found: dict[str, dict[str, Any]]) -> None:
    if isinstance(value, dict):
        action_id = value.get("action_id")
        if isinstance(action_id, str) and action_id in wanted and action_id not in found:
            mapping = value.get("native_mapping")
            variants: list[dict[str, Any]] = []
            if isinstance(mapping, dict):
                raw_variants = mapping.get("variants")
                if isinstance(raw_variants, list):
                    for item in raw_variants:
                        if not isinstance(item, dict):
                            continue
                        variants.append({
                            key: item.get(key)
                            for key in (
                                "name", "accessor_rva", "vtable_rva",
                                "token_slot_offset", "factory_rva",
                                "mode_constraints", "value",
                            )
                            if key in item
                        })
            found[action_id] = {
                "action_id": action_id,
                "game_key": value.get("game_key"),
                "execution_status": (value.get("execution") or {}).get("status"),
                "execution_reason": (value.get("execution") or {}).get("reason"),
                "native_mapping": {
                    "exe_sha256": (mapping or {}).get("exe_sha256")
                    if isinstance(mapping, dict) else None,
                    "evidence_level": (mapping or {}).get("evidence_level")
                    if isinstance(mapping, dict) else None,
                    "runtime_verified": (mapping or {}).get("runtime_verified")
                    if isinstance(mapping, dict) else None,
                    "variants": variants,
                },
            }
        for child in value.values():
            _catalog_actions(child, wanted, found)
    elif isinstance(value, list):
        for child in value:
            _catalog_actions(child, wanted, found)


def catalog_action_snapshot() -> dict[str, dict[str, Any]]:
    _, catalog = read_json("bridge/diplomacy_catalog.json")
    wanted = {
        "ask_fleet_basing_rights",
        "cancel_fleet_basing_rights",
        "offer_fleet_basing_rights",
        "revoke_fleet_basing_rights",
        "invite_to_trade_league",
        "request_to_join_trade_league",
        "kick_from_trade_league",
        "leave_trade_league",
    }
    found: dict[str, dict[str, Any]] = {}
    _catalog_actions(catalog, wanted, found)
    missing = sorted(wanted - set(found))
    if missing:
        raise ValueError(f"catalog action records missing: {missing}")
    return {key: found[key] for key in sorted(found)}


def _current_source_guard() -> dict[str, Any]:
    path, contract = read_json(
        "work/runtime/information-relation-current-20261027-001/"
        "relation-current-contract-003.json"
    )
    target = contract.get("target_binary")
    if not isinstance(target, dict):
        raise ValueError("relation current contract has no target_binary")
    if str(target.get("sha256", "")).lower() != TARGET_SHA256:
        raise ValueError("relation current contract target SHA does not match this batch")
    if str(target.get("version", "")) != TARGET_VERSION:
        raise ValueError("relation current contract target version does not match")
    return {
        "path": str(path.relative_to(ROOT)).replace("\\", "/"),
        "sha256": file_sha(path),
        "target_binary": target,
        "unresolved": contract.get("unresolved", []),
    }


def _source_refs() -> list[dict[str, Any]]:
    return [
        source_ref(
            "bridge/information/relation_state.py",
            [(15, 27, (
                "SUPPORTED_FAMILIES", "_MEMORY_FAMILIES",
                "FLEET_BASING_NOT_IMPLEMENTED", "TRADE_LEAGUE_NOT_IMPLEMENTED",
                "RELATION_FAMILIES_NOT_EXHAUSTIVE",
            )), (53, 70, ("relation_types_by_object",))],
            "current adapter family set and explicit remaining gaps",
        ),
        source_ref(
            "bridge/information/relation_records.py",
            [(24, 49, (
                "SUPPORTED_FAMILIES", "ACTION_MAPPING", "military_access",
            )), (179, 182, ("RELATION_ROLE_DIRECTION_UNPROVEN",)),
             (226, 230, ("RELATION_EXPIRY_UNREAD",)),
             (259, 270, ("expires_at", "RELATION_EXPIRY_UNREAD"))],
            "current projection guard: action IDs alone are not current state",
        ),
        source_ref(
            "bridge/diplomacy_catalog.json",
            [(1528, 1590, (
                "ask_fleet_basing_rights", "fleet_access", "static_only",
                "No verified constructor",
            )), (8869, 8938, (
                "invite_to_trade_league", "runtime_verified", "0x1c7bd08",
                "No verified constructor",
            )), (9445, 9524, (
                "kick_from_trade_league", "same league pointer", "first member",
            )), (9936, 10016, (
                "leave_trade_league", "same league pointer", "first member",
            )), (10572, 10630, (
                "offer_fleet_basing_rights", "offer_fleet_access",
            )), (12578, 12645, (
                "request_to_join_trade_league", "request_to_join_trade_league",
            ))],
            "1.37.5 static action candidates; not a 1.37.4 current-state reader",
        ),
        source_ref(
            "docs/native-pair-extension-v10-1375.md",
            [(15, 23, (
                "fleet_access", "offer_fleet_access", "请求/持有停泊权",
                "港口国", "使用停泊权",
            ))],
            "action-direction wording only; no established-relation producer",
        ),
        source_ref(
            "docs/native-diplomacy-modes-1375.md",
            [(33, 61, (
                "cancel_fleet_basing_rights", "kick_from_trade_league",
                "leave_trade_league", "revoke_fleet_basing_rights",
            ))],
            "mode labels and action aliases only",
        ),
        source_ref(
            "docs/diplomacy-gaps.md",
            [(48, 53, (
                "贸易联盟", "invite_to_trade_league", "mode_constraints",
            )), (97, 102, (
                "fleet_access", "当前关系身份", "P1-2",
            ))],
            "explicit unresolved direction/current-state boundary",
        ),
        source_ref(
            "work/research-next/relation_network_scope_002.py",
            [(112, 146, (
                "relation-current-source-002.json", "ask_fleet_basing_rights",
                "invite_to_trade_league", "same league pointer",
            )), (191, 210, (
                "no current relation-state reader", "current member-vector reader",
                "country+0x1948",
            )), (313, 361, (
                "fleet_basing/trade_league remain unknown",
                "remaining_target_gaps", "RELATION_EXPIRY_UNREAD",
            ))],
            "prior bounded scope review retaining the same missing-source boundary",
        ),
        source_ref(
            "work/runtime/information-relation-current-20261027-001/"
            "relation-current-source-002.json",
            [(67, 94, (
                "owner_vector_layout", "alliance", "royal_marriage",
                "expiry_date",
            )), (315, 317, (
                "A68BC0", "A68A10", "public_relation_dates",
            ))],
            "bounded current producer evidence for alliance/royal only",
        ),
        source_ref(
            "docs/联盟与联姻关系网接口.md",
            [(122, 127, (
                "fleet_basing", "trade_league", "action 名称",
                "legality", "pending",
            ))],
            "public boundary and explicit non-substitutes",
        ),
        source_ref(
            "docs/信息字段覆盖.json",
            [(6125, 6133, ("trade_league", "planned"))],
            "directory coverage remains planned",
        ),
    ]


def _fleet_finding(actions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "r01_target": True,
        "current_state": {
            "status": "unknown",
            "producer": None,
            "producer_status": "not_found_in_scoped_current_readers",
            "relationship_state_helper_rva": None,
            "container_or_serializer": None,
            "build": TARGET_VERSION,
            "reason": (
                "The current relation adapter registers no fleet_basing family, "
                "and the scoped static evidence only describes action objects."
            ),
        },
        "action_only_candidates": [
            {
                "actions": ["ask_fleet_basing_rights", "cancel_fleet_basing_rights"],
                "native_family": "fleet_access",
                "catalog": actions["ask_fleet_basing_rights"],
                "static_direction": (
                    "requesting/holding side -> port country (action actor/target wording)"
                ),
                "current_relation_direction": {
                    "status": "unknown",
                    "grantor": "unknown",
                    "recipient": "unknown",
                },
            },
            {
                "actions": ["offer_fleet_basing_rights", "revoke_fleet_basing_rights"],
                "native_family": "offer_fleet_access",
                "catalog": actions["offer_fleet_basing_rights"],
                "static_direction": (
                    "port country -> fleet user (action actor/target wording)"
                ),
                "current_relation_direction": {
                    "status": "unknown",
                    "grantor": "unknown",
                    "recipient": "unknown",
                },
            },
        ],
        "candidate_container_or_helper": {
            "status": "action_only_static_candidate",
            "candidate_source_build": {
                "version": "1.37.5 static catalog evidence",
                "exe_sha256": "9ad3efe1af169f40ee577f9da5edebbc87af6fb8b5450fb345ebf110dc4d771a",
                "runtime_verified": False,
                "usable_as_1374_current_proof": False,
            },
            "rvas": ["0x530280", "0x534660", "0x35d210"],
            "names": ["fleet_access", "offer_fleet_access", "pair factory"],
            "not_proven": [
                "established active relation storage",
                "grantor/recipient field binding",
                "expiry/date field or serializer",
                "1.37.4 address equivalence",
            ],
        },
        "excluded_as_current_state": [
            "legality predicates",
            "AI acceptance or refusal",
            "pending request/offer state",
            "cancel/revoke action mode",
            "historical action outcome annotations",
        ],
        "minimum_next_source": [
            "A 1.37.4 current fleet-access relation producer or serializer.",
            "A bounded active-record/container read with both fullref endpoints.",
            "A native role proof for grantor/recipient and an expiry field if owned by the relation.",
        ],
    }


def _trade_finding(actions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "r01_target": True,
        "current_state": {
            "status": "unknown",
            "producer": None,
            "producer_status": "not_found_in_scoped_current_readers",
            "relationship_state_helper_rva": None,
            "container_or_serializer": None,
            "build": TARGET_VERSION,
            "reason": (
                "The current relation adapter has no trade_league family and "
                "the known action-mode branch is not a member-vector reader."
            ),
        },
        "action_only_candidates": [
            {
                "actions": ["invite_to_trade_league"],
                "native_family": "invite_to_trade_league",
                "catalog": actions["invite_to_trade_league"],
                "static_direction": "invite/request action; not a current membership direction",
                "current_relation_direction": {
                    "status": "unresolved_membership_or_leader_semantics",
                    "grantor": "not_applicable_until_native role is proven",
                    "recipient": "not_applicable_until native role is proven",
                },
            },
            {
                "actions": ["request_to_join_trade_league"],
                "native_family": "request_to_join_trade_league",
                "catalog": actions["request_to_join_trade_league"],
                "static_direction": "join request action; not a current membership direction",
                "current_relation_direction": {
                    "status": "unresolved_membership_or_leader_semantics",
                    "grantor": "unknown",
                    "recipient": "unknown",
                },
            },
            {
                "actions": ["kick_from_trade_league", "leave_trade_league"],
                "native_family": "invite_to_trade_league",
                "catalog": {
                    "kick": actions["kick_from_trade_league"],
                    "leave": actions["leave_trade_league"],
                },
                "static_direction": (
                    "same-league and first-member predicates distinguish action modes; "
                    "they do not serialize current membership"
                ),
                "current_relation_direction": {
                    "status": "unresolved_membership_or_leader_semantics",
                    "grantor": "unknown",
                    "recipient": "unknown",
                },
            },
        ],
        "candidate_container_or_helper": {
            "status": "action_mode_candidate_only",
            "candidate_source_build": {
                "version": "1.37.5 static catalog evidence",
                "exe_sha256": "9ad3efe1af169f40ee577f9da5edebbc87af6fb8b5450fb345ebf110dc4d771a",
                "runtime_verified": False,
                "usable_as_1374_current_proof": False,
            },
            "rvas": ["0x593520", "0x591350", "0x35d210"],
            "names": ["invite_to_trade_league", "request_to_join_trade_league", "pair factory"],
            "candidate_layout": {
                "country_offset": "0x1948",
                "meaning": "same league pointer in the action-mode predicate",
                "member_hint": "first member slot at league+0x20..+0x28",
            },
            "not_proven": [
                "league manager/member vector producer",
                "member fullref enumeration and leader identity",
                "current status serializer",
                "expiry/date semantics",
                "1.37.4 address equivalence",
            ],
        },
        "excluded_as_current_state": [
            "invite/request legality",
            "kick/leave action predicates",
            "AI acceptance or refusal",
            "pending invitations",
            "first-member action branch alone",
        ],
        "minimum_next_source": [
            "A 1.37.4 trade-league manager or country membership producer.",
            "A bounded member-vector read with country fullrefs and leader/role binding.",
            "A current-state status/expiry serializer if the relation owns dates.",
        ],
    }


def build_report() -> dict[str, Any]:
    current_guard = _current_source_guard()
    actions = catalog_action_snapshot()
    return {
        "schema": "information_relation_remaining_source.v1",
        "stage": "information-relation-remaining-20261027-001",
        "report_id": "relation-remaining-source-001",
        "review_scope": {
            "purpose": "R01 fleet_basing/trade_league current-state source inventory",
            "target_binary": {
                "version": TARGET_VERSION,
                "sha256": TARGET_SHA256,
                "image_base": "0x140000000",
            },
            "source_only": True,
            "ordinary_pe_decode": False,
            "rea": False,
            "rpm": False,
            "game_query": False,
            "mcp": False,
            "production_changes": False,
            "historical_or_action_projections_not_promoted": True,
        },
        "current_relation_guard": current_guard,
        "source_refs": _source_refs(),
        "family_findings": {
            "fleet_basing": _fleet_finding(actions),
            "trade_league": _trade_finding(actions),
        },
        "reusable_boundary": {
            "current_producers": {
                "alliance": {
                    "source": "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
                    "leaf_rva": "0xa68bc0",
                    "status": "closed_for_selected_pair_only",
                },
                "royal_marriage": {
                    "source": "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
                    "leaf_rva": "0xa68a10",
                    "status": "closed_for_selected_pair_only",
                },
                "fleet_basing": None,
                "trade_league": None,
            },
            "no_cross_family_substitution": (
                "Alliance/royal owner vectors and their predicates cannot stand in for "
                "fleet-basing rights or trade-league membership."
            ),
        },
        "next_minimum_source_gap": {
            "fleet_basing": "current 1.37.4 record/container plus grantor-recipient and optional expiry proof",
            "trade_league": "current 1.37.4 member-vector/manager plus fullref and leader/role proof",
            "shared_requirements": [
                "static guard tied to the 1.37.4 target SHA",
                "bounded two-pass current read with identity/session/date checks",
                "unknown on missing or ambiguous role/date data; no inactive inference from absence",
            ],
        },
        "conclusion": {
            "status": "no_mature_current_state_source_found",
            "fleet_basing": "remain unknown/planned",
            "trade_league": "remain unknown/planned",
            "direction_rule": "Action actor/target text is not a grantor/recipient proof for an established relation.",
            "expiry_rule": "Do not derive expires_at from pending, legality, action date, or a start date.",
        },
        "generated_by": {
            "script": "work/research-next/relation_remaining.py",
            "script_sha256": file_sha(Path(__file__).resolve()),
        },
    }


def write_report(output: Path) -> None:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing report: {output}")
    payload = json.dumps(build_report(), ensure_ascii=False, indent=2) + "\n"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
    print(json.dumps({
        "path": str(output),
        "bytes": output.stat().st_size,
        "sha256": file_sha(output),
    }, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    write_report(args.output if args.output.is_absolute() else ROOT / args.output)


if __name__ == "__main__":
    main()
