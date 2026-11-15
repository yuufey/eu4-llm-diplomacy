"""Corrected R01 relation-family and country-network scope review.

This report keeps the original scope-001 artifact unchanged.  It reconciles
the six R01 families stated in the LLM export directory with the current
five-family selected-pair catalog and records a bounded country-object read
contract.  It is source/archive-only: no game, RPM, REA, native call, or test
is started.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-relation-network-scope-20261027-001/"
    "relation-network-scope-002.json"
)
TARGET_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
MAX_WINDOW_BYTES = 64 * 1024


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bounded_window(path: Path, start: int, end: int,
                   markers: Iterable[str]) -> dict[str, Any]:
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


def source_ref(relative: str,
               windows: list[tuple[int, int, tuple[str, ...]]],
               role: str) -> dict[str, Any]:
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


def build_report() -> dict[str, Any]:
    previous_path, previous = read_json(
        "work/runtime/information-relation-network-scope-20261027-001/"
        "relation-network-scope-001.json"
    )
    previous_sha = file_sha(previous_path)

    source_refs = [
        source_ref(
            "docs/LLM导出信息目录.md",
            [(76, 86, ("### 外交关系与承诺", "R01", "联盟、王室联姻、保障独立、军事通行、驻港权及贸易联盟关系"))],
            "authoritative six-family R01 scope",
        ),
        source_ref(
            "docs/信息字段覆盖.json",
            [(1804, 1895, ("R01", "expires_at", "SELECTED_COUNTRY_PAIR_ONLY", "RELATION_FAMILIES_NOT_EXHAUSTIVE"))],
            "current public catalog boundary",
        ),
        source_ref(
            "bridge/information/relation_state.py",
            [(15, 57, ("SUPPORTED_FAMILIES", "SELECTED_COUNTRY_PAIR_ONLY", "country_pair")),
             (59, 88, ("relation_types", "actor must be the verified FRA observer"))],
            "current five-family selected-pair adapter",
        ),
        source_ref(
            "bridge/information/relation_records.py",
            [(15, 39, ("SUPPORTED_FAMILIES", "ACTION_MAPPING", "rival")),
             (141, 190, ("RELATION_ROLE_DIRECTION_UNPROVEN", "actor_is_overlord", "actor_is_subject")),
             (259, 270, ("expires_at", "RELATION_EXPIRY_UNREAD"))],
            "current projection direction and expiry boundary",
        ),
        source_ref(
            "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
            [(1, 4, ("information_relation_current_native_source.v1",)),
             (67, 94, ("owner_vector_layout", "offer_false_current_read", "expiry_date"))],
            "bounded alliance/royal membership leaf evidence",
        ),
        source_ref(
            "bridge/diplomacy_catalog.json",
            [(1528, 1590, ("ask_fleet_basing_rights", "fleet_access", "runtime_verified", "unimplemented")),
             (8867, 8938, ("invite_to_trade_league", "runtime_verified", "native_mapping")),
             (9508, 9524, ("same league pointer", "first member"))],
            "static action/container candidates; version and runtime caveat retained",
        ),
        source_ref(
            "docs/diplomacy-gaps.md",
            [(48, 53, ("贸易联盟", "invite_to_trade_league", "mode_constraints")),
             (97, 102, ("舰队通行", "fleet_access", "当前关系身份"))],
            "existing gap notes for fleet basing and trade-league direction",
        ),
        source_ref(
            "docs/diplomacy-lab-http-v10.md",
            [(20, 31, ("请求驻港权", "ask_fleet_basing_rights", "给予驻港权"))],
            "documented fleet-basing action names, not a current relation reader",
        ),
    ]

    six_families = [
        {
            "relation_type": "alliance",
            "r01_target": True,
            "current_catalog": False,
            "current_source_status": "static_membership_leaf_closed_selected_pair_only",
            "direction": "symmetric",
            "grantor_recipient": "not_applicable; do not invent an initiator role",
            "collection_status": "country enumeration seam not runtime-verified",
            "source": "relation-current-source-002: owner+0x80, leaf RVA 0xA68BC0",
        },
        {
            "relation_type": "royal_marriage",
            "r01_target": True,
            "current_catalog": False,
            "current_source_status": "static_membership_leaf_closed_selected_pair_only",
            "direction": "symmetric",
            "grantor_recipient": "not_applicable; marriage initiation is not current relation direction",
            "collection_status": "country enumeration seam not runtime-verified",
            "source": "relation-current-source-002: owner+0x68, leaf RVA 0xA68A10",
        },
        {
            "relation_type": "guarantee",
            "r01_target": True,
            "current_catalog": True,
            "current_source_status": "selected_pair_relationship_state_reusable",
            "direction": "directed; grantor/recipient role still unproven",
            "grantor_recipient": "preserve selected actor/recipient until native role proof",
            "collection_status": "no country-wide enumerator",
            "source": "relationship_state.guarantee_active",
        },
        {
            "relation_type": "military_access",
            "r01_target": True,
            "current_catalog": True,
            "current_source_status": "selected_pair_relationship_state_reusable",
            "direction": "directed; which side grants access is unproven",
            "grantor_recipient": "preserve selected actor/recipient until native role proof",
            "collection_status": "no country-wide enumerator",
            "source": "relationship_state.military_access_active",
        },
        {
            "relation_type": "fleet_basing",
            "r01_target": True,
            "current_catalog": False,
            "current_source_status": "no current relation-state reader",
            "direction": "directed; grantor/recipient required by R01 but unresolved",
            "grantor_recipient": "unknown until fleet-basing current container and role are proven",
            "collection_status": "unsupported; action names/static mode do not establish current relation",
            "source": "fleet_access action/static mode references only; no current membership state",
        },
        {
            "relation_type": "trade_league",
            "r01_target": True,
            "current_catalog": False,
            "current_source_status": "static same-league-pointer candidate only",
            "direction": "membership/leader semantics unresolved",
            "grantor_recipient": "do not fabricate grantor/recipient from invite or leave action",
            "collection_status": "unsupported; no current member-vector reader",
            "source": "invite_to_trade_league mode notes same league pointer at country+0x1948",
        },
    ]

    current_extras = [
        {
            "relation_type": "vassalization",
            "status": "selected-pair reusable; extra relative to original R01 list",
            "ownership": "R02 subject relation; keep role proof from exclusive vassal flags",
        },
        {
            "relation_type": "support_independence",
            "status": "selected-pair reusable; extra relative to original R01 list",
            "ownership": "action relation source; not a substitute for R01 guarantee",
        },
        {
            "relation_type": "rival",
            "status": "selected-pair reusable; extra relative to original R01 list",
            "ownership": "R03 rival family; one-sided and no grantor/recipient",
        },
    ]

    return {
        "schema": "information_relation_network_scope.v2",
        "stage": "information-relation-network-scope-20261027-001",
        "report_id": "relation-network-scope-002",
        "status": "corrected_six_family_scope_static_country_contract_no_runtime_network_capture",
        "supersedes_scope_interpretation": {
            "previous_report": {
                "path": str(previous_path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": previous_sha,
                "status": previous.get("status"),
                "preserved": True,
            },
            "correction": "The original R01 source directory names six families; the current five-family catalog is an implementation subset plus three cross-topic extras.",
        },
        "review_scope": {
            "kind": "offline_bounded_source_and_archived_contract_review",
            "new_game_query": False,
            "rpm_or_rea": False,
            "native_call": False,
            "production_changes": False,
            "tests_run": False,
            "full_binary_disassembly": False,
        },
        "target_binary": {
            "version": "1.37.4",
            "sha256": TARGET_SHA256,
            "image_base": "0x140000000",
            "address_note": "RVA is image-relative; no version-mismatched 1.37.5 static token is treated as a 1.37.4 runtime proof.",
        },
        "r01_authoritative_scope": {
            "source_path": "docs/LLM导出信息目录.md",
            "source_line": 80,
            "relation_types": [
                "alliance", "royal_marriage", "guarantee",
                "military_access", "fleet_basing", "trade_league",
            ],
            "direction_rule": "All directed relations retain grantor and recipient; symmetric or membership relations do not receive an invented initiator role.",
            "purpose": "country relation network and support/constraint/access conditions",
        },
        "family_mapping": {
            "r01_target_six": six_families,
            "current_catalog_extra_families": current_extras,
            "current_catalog_relation_types": [
                "vassalization", "guarantee", "support_independence",
                "military_access", "rival",
            ],
            "interpretation": "The five current enum values must not be presented as the complete R01 six-family target or as every relation in the world.",
            "missing_target_families": ["fleet_basing", "trade_league"],
            "static_but_unwired_target_families": ["alliance", "royal_marriage"],
        },
        "country_fra_collection_contract": {
            "object": {"type": "country", "country": "FRA"},
            "parameters": {
                "relation_types": {
                    "type": "array",
                    "uniqueItems": True,
                    "nonempty": True,
                    "enum": [
                        "alliance", "royal_marriage", "guarantee",
                        "military_access", "fleet_basing", "trade_league",
                    ],
                },
                "direction": {
                    "enum": ["outgoing", "incoming", "both"],
                    "meaning": "filter only directed families; symmetric alliance/marriage use the same partner set",
                },
                "partner_tags": {
                    "type": "array",
                    "optional": True,
                    "meaning": "identity filter; omission requests all valid country-table slots",
                },
                "include_inactive": {
                    "type": "boolean",
                    "default": False,
                    "meaning": "default output is active partners only after a complete read; false rows are not inferred from missing rows",
                },
            },
            "one_capture_read_sequence": [
                "Validate FRA session, game date, database global, country count, and FRA fullref before reading relation rows.",
                "Scan valid country-array slots once; for each non-null country require country+0x20 fullref high-word identity and retain the candidate slot/tag.",
                "Read FRA+0x1510 row at candidate_slot*0x48; require row+0x10 to equal that candidate fullref and retain row+0 owner address even when it differs from FRA.",
                "Cache owner-vector reads by (owner_address, relation_family), so repeated rows reuse one copied vector instead of rereading it for each candidate; this is a read optimization, not an owner identity claim.",
                "For alliance use owner+0x80/+0x8c and leaf 0xA68BC0; for royal_marriage use owner+0x68/+0x74 and leaf 0xA68A10. Validate count/begin and all 0x10-byte elements before deciding active/inactive.",
                "For the five-family reusable sources, only publish a known row after its family-specific relationship_state guard; fleet_basing/trade_league remain unknown until their current containers are closed.",
            ],
            "raw_fields_to_retain": {
                "country": ["country_slot", "country_fullref_raw_hex", "country_tag"],
                "row": ["relation_row_address", "row_owner_address", "row_recipient_fullref_raw_hex"],
                "owner_vector": ["family", "vector_begin_address", "count_i32", "matching_entry_slot_or_null", "vector_read_complete"],
                "provenance": ["static_guard_sha256", "runtime_identity", "game_date_raw", "read_budget_bytes"],
            },
            "deduplication": {
                "key": "(row_owner_address, relation_family)",
                "reason": "same owner can be referenced by many bilateral rows; avoid one vector copy per row",
                "not_a_claim": "deduplication does not prove the owner is FRA or that a vector is a global relation list",
            },
            "budget_and_completeness": {
                "hard_slot_bound": 4096,
                "hard_vector_count_bound": 4096,
                "row_bytes_per_candidate": "0x48",
                "vector_element_bytes": "0x10",
                "read_budget": "adapter-configured bounded byte budget; never silently raise it to claim completeness",
                "on_budget_exhaustion": "stop before unverified rows, retain rows already copied, mark remaining rows unknown and complete=false",
                "on_invalid_or_missing_row": "unknown with reason; do not convert to inactive",
                "full_set_claim": "complete=true only when all country slots within the verified country_count and all requested-family owner vectors were read and identity/context checks passed; no such runtime capture exists in this report",
            },
            "default_output": {
                "active_only": True,
                "unknown_rows": "retained in diagnostics/provenance even when inactive rows are filtered",
                "order": "native country-table slot order, then requested relation_types order",
                "dedupe": "one (partner_fullref, relation_type) row",
            },
        },
        "direction_and_expiry_semantics": {
            "alliance": {"direction": "symmetric", "grantor": "not_applicable", "recipient": "not_applicable"},
            "royal_marriage": {"direction": "symmetric", "grantor": "not_applicable", "recipient": "not_applicable"},
            "guarantee": {"direction": "directed", "grantor": "unknown_without_role_proof", "recipient": "unknown_without_role_proof"},
            "military_access": {"direction": "directed", "grantor": "unknown_without_role_proof", "recipient": "unknown_without_role_proof"},
            "fleet_basing": {"direction": "directed", "grantor": "unread", "recipient": "unread"},
            "trade_league": {"direction": "membership_or_leader_unresolved", "grantor": "unread", "recipient": "unread"},
            "expires_at": {
                "status": "unknown",
                "reason": "RELATION_EXPIRY_UNREAD",
                "required_semantics": "established relation expiry game date, if the native relation owns one",
                "not_substitutes": ["query deadline", "pending offer date", "legality/acceptance prediction", "start date without expiry proof"],
            },
        },
        "source_refs": source_refs,
        "conclusion": {
            "corrected_scope": "R01 has six documented target families; current five-family selected-pair enum is an implementation subset with vassalization/support_independence/rival extra reuse.",
            "country_collection": "A country/FRA object can be implemented as a bounded all-valid-slot scan using row+0x10 identity and owner+family vector caching, but the result must remain partial until a two-pass runtime capture completes every requested row/vector.",
            "remaining_target_gaps": ["fleet_basing current state", "trade_league member/current state", "full runtime country enumeration", "directed role proofs for guarantee/military_access", "relation expiry semantics"],
            "safety_boundary": "Do not call the six-family list complete-world coverage, and do not infer inactive from an unvisited or budget-truncated row.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--overwrite", action="store_true",
                        help="replace this task's own previously generated report")
    args = parser.parse_args()
    if args.output.exists() and not args.overwrite:
        raise SystemExit(f"refusing to overwrite existing report: {args.output}")
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output),
        "bytes": args.output.stat().st_size,
        "sha256": file_sha(args.output),
        "status": report["status"],
        "r01_target_family_count": len(report["r01_authoritative_scope"]["relation_types"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
