"""Bounded offline scope audit for the R01 relation-network extension.

The current public R01 adapter is a selected-country-pair reader.  This
report separates that contract from the later static evidence for the
alliance and royal-marriage membership leaves.  It does not attach to a game,
invoke REA/RPM, call a native function, submit an action, or run tests.
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
    "relation-network-scope-001.json"
)
TARGET_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = "0x140000000"
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


def artifact_summary(relative: str, role: str) -> dict[str, Any]:
    path = ROOT / relative
    result: dict[str, Any] = {
        "path": relative,
        "exists": path.is_file(),
        "role": role,
    }
    if not path.is_file():
        return result
    result.update({"bytes": path.stat().st_size, "sha256": file_sha(path)})
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError) as exc:
        result["read_error"] = type(exc).__name__
        return result
    if relative.endswith("native-alliance-ui-inputs.json"):
        pairs = value.get("pairs", []) if isinstance(value, dict) else []
        result["observed"] = {
            "game_sha256": value.get("game_sha256"),
            "read_only": value.get("read_only"),
            "native_methods_invoked": value.get("native_methods_invoked"),
            "date_raw": value.get("date_raw"),
            "pair_count": len(pairs),
            "pairs": [
                {
                    key: pair.get(key)
                    for key in (
                        "actor", "recipient", "row_owner_matches_actor_country",
                        "row_recipient_matches_full_handle", "membership_count",
                        "native_selector_return", "complete",
                    )
                    if key in pair
                }
                for pair in pairs
            ],
        }
    return result


def _relation_direction_rows() -> list[dict[str, Any]]:
    return [
        {
            "relation_type": "vassalization",
            "catalog_status": "supported_selected_pair",
            "network_status": "reusable_after_enumeration_seam",
            "direction": "directed_when_exclusive_role_flags_pass",
            "known_role_rule": (
                "actor_is_overlord=true and actor_is_subject=false maps actor to "
                "grantor/overlord; the opposite exclusive flags reverse endpoints"
            ),
            "collection_source": "NativeSubjectRelationSource.read, selected pair only",
        },
        {
            "relation_type": "guarantee",
            "catalog_status": "supported_selected_pair",
            "network_status": "reusable_after_enumeration_seam",
            "direction": "selected_endpoints_only",
            "known_role_rule": "generic grantor/recipient is unproven",
            "collection_source": "relationship_state.guarantee_active",
        },
        {
            "relation_type": "support_independence",
            "catalog_status": "supported_selected_pair",
            "network_status": "reusable_after_enumeration_seam",
            "direction": "selected_endpoints_only",
            "known_role_rule": "generic supporter/beneficiary is unproven",
            "collection_source": "relationship_state.support_independence_active",
        },
        {
            "relation_type": "military_access",
            "catalog_status": "supported_selected_pair",
            "network_status": "reusable_after_enumeration_seam",
            "direction": "selected_endpoints_only",
            "known_role_rule": "which endpoint grants access is unproven",
            "collection_source": "relationship_state.military_access_active",
        },
        {
            "relation_type": "rival",
            "catalog_status": "supported_selected_pair",
            "network_status": "reusable_after_enumeration_seam",
            "direction": "one_sided_from_observer",
            "known_role_rule": "grantor/recipient not_applicable",
            "collection_source": "relationship_state.rival_active in dedicated R34 path",
        },
        {
            "relation_type": "alliance",
            "catalog_status": "not_in_current_R01_enum",
            "network_status": "static_membership_leaf_closed; no public network reader",
            "direction": "symmetric",
            "known_role_rule": "grantor/recipient not_applicable",
            "collection_source": "owner+0x80 vector and RVA 0xA68BC0 leaf",
        },
        {
            "relation_type": "royal_marriage",
            "catalog_status": "not_in_current_R01_enum",
            "network_status": "static_membership_leaf_closed; no public network reader",
            "direction": "symmetric",
            "known_role_rule": "grantor/recipient not_applicable",
            "collection_source": "owner+0x68 vector and RVA 0xA68A10 leaf",
        },
    ]


def build_report() -> dict[str, Any]:
    source_refs = [
        source_ref(
            "docs/信息字段覆盖.json",
            [(1804, 1895, ("R01", "expires_at", "SELECTED_COUNTRY_PAIR_ONLY", "RELATION_FAMILIES_NOT_EXHAUSTIVE"))],
            "current catalog R01 fields, object, and gaps",
        ),
        source_ref(
            "bridge/information/catalog.py",
            [(132, 141, ('("R01"', 'relation_type grantor recipient status expires_at', 'country_pair'))],
            "legacy catalog topic definition",
        ),
        source_ref(
            "bridge/information/relation_state.py",
            [(15, 57, ("SUPPORTED_FAMILIES", "SELECTED_COUNTRY_PAIR_ONLY", "country_pair")),
             (59, 88, ("actor must be the verified FRA observer", "relation_types"))],
            "current selected-pair public adapter boundary",
        ),
        source_ref(
            "bridge/information/relation_records.py",
            [(15, 39, ("SUPPORTED_FAMILIES", "ACTION_MAPPING", "rival")),
             (141, 190, ("RELATION_ROLE_DIRECTION_UNPROVEN", "actor_is_overlord", "actor_is_subject")),
             (259, 270, ("expires_at", "RELATION_EXPIRY_UNREAD"))],
            "pure projection role and expiry rules",
        ),
        source_ref(
            "docs/信息导出与订阅开发计划.md",
            [(254, 262, ("R01–R07", "关系网", "双边方向与集合完整性明确", "期限及缺项可辨"))],
            "planned R01-R07 completeness criterion",
        ),
        source_ref(
            "work/native/alliance-query.inc",
            [(44, 89, ("relation=table+recipient_slot*72", "owner+(marriage?0x68:0x80)", "offer?1:0", "country_count"))],
            "bounded native selector and identity/vector guards",
        ),
        source_ref(
            "work/native/alliance-execution.inc",
            [(1279, 1333, ("execution_read_after", "alliance_query_visibility", "false,alliance_after", "royal_marriage"))],
            "existing read-after producer using current membership predicate",
        ),
        source_ref(
            "work/research-next/relation_current.py",
            [(1, 120, ("Offline bounded review", "alliance_query_visibility")),
             (220, 260, ("owner_vector", "relation_row_stride", "minimum_read_only_interface")),
             (260, 300, ("relation_network", "selected-pair only", "expires_at"))],
            "previous bounded source review contract",
        ),
        source_ref(
            "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
            [(1, 4, ("information_relation_current_native_source.v1",))],
            "pinned bounded leaf decode and source SHA",
        ),
        source_ref(
            "work/probe_alliance_relations.py",
            [(1, 55, ("relation_table", "recipient_slot * 72", "owner + 0x80", "membership_slots", "not_called"))],
            "archived raw-pointer probe design; not a network proof",
        ),
        source_ref(
            "work/probe_diplomacy_relations_1375.py",
            [(24, 35, ("RELATIONS", "royal_marriage", "vassalaction")),
             (136, 145, ("+ 0x1510", "* 0x48", "counterpart"))],
            "selected-pair index containers; not an all-partner reader",
        ),
    ]

    return {
        "schema": "information_relation_network_scope.v1",
        "stage": "information-relation-network-scope-20261027-001",
        "report_id": "relation-network-scope-001",
        "status": "static_network_contract_partial_no_runtime_enumeration",
        "review_scope": {
            "kind": "offline_bounded_source_and_archived_evidence_review",
            "new_game_query": False,
            "rea_or_rpm": False,
            "native_call": False,
            "business_action": False,
            "production_changes": False,
            "tests_run": False,
            "full_binary_disassembly": False,
        },
        "target_binary": {
            "version": "1.37.4",
            "sha256": TARGET_SHA256,
            "image_base": IMAGE_BASE,
            "address_note": "RVA values are image-relative; VA is image_base + RVA.",
        },
        "catalog_and_plan": {
            "current_catalog": {
                "topic": "R01",
                "title": "选定国家对的当前关系（部分类型）",
                "object_types": ["country_pair"],
                "fields": ["relation_type", "grantor", "recipient", "status", "expires_at"],
                "relation_types": [
                    "vassalization", "guarantee", "support_independence",
                    "military_access", "rival",
                ],
                "direction": "selected_country_pair",
                "coverage": "partial; complete=false",
                "gaps": ["SELECTED_COUNTRY_PAIR_ONLY", "RELATION_FAMILIES_NOT_EXHAUSTIVE"],
            },
            "plan_target": {
                "source": "R01-R07",
                "criterion": "双边方向与集合完整性明确，期限及缺项可辨",
                "interpretation": (
                    "This is a completeness goal, not proof that every native family belongs "
                    "in the current R01 enum. R02/R03/R07 keep their own field ownership."
                ),
            },
            "family_scope": {
                "current_catalog_families": [
                    "vassalization", "guarantee", "support_independence",
                    "military_access", "rival",
                ],
                "static_current_membership_additions": ["alliance", "royal_marriage"],
                "unenumerated_until_family_source_exists": [
                    "other native relation families; do not expand the enum from action names or queue records"
                ],
                "boundary": "covered-family set is not the set of all relations in the world",
            },
        },
        "relation_families": _relation_direction_rows(),
        "country_1510_audit": {
            "answer": "bounded static enumeration is implementable, but not runtime-verified as a full network",
            "country_identity": {
                "database_global_rva": "0x233d8b0",
                "country_array_offset": "0x118",
                "country_count_offset": "0x124",
                "fullref_offset": "0x20",
                "count_guard": "1 <= country_count <= 4096; slot must be < country_count",
            },
            "relation_table": {
                "country_offset": "0x1510",
                "row_stride": "0x48",
                "owner_offset": "0x00",
                "recipient_fullref_offset": "0x10",
                "identity_guard": "row+0x10 must equal the candidate fullref",
            },
            "owner_and_vectors": {
                "owner_semantics": (
                    "row+0 is the object passed to the membership leaves; it is not proven to "
                    "equal the actor country pointer"
                ),
                "alliance": {
                    "begin": "owner+0x80",
                    "count": "signed i32 owner+0x8c",
                    "element_stride": "0x10",
                    "leaf_rva": "0xA68BC0",
                    "leaf_result": "true iff element[0] matches sign-extended recipient slot",
                },
                "royal_marriage": {
                    "begin": "owner+0x68",
                    "count": "signed i32 owner+0x74",
                    "element_stride": "0x10",
                    "leaf_rva": "0xA68A10",
                    "leaf_result": "true iff element[0] matches sign-extended recipient slot",
                },
                "vector_guard": "0 <= count <= 4096; count>0 requires nonzero begin; validate each 0x10-byte element before leaf",
            },
            "enumeration_plan": [
                "Resolve the verified FRA country pointer and its +0x1510 table.",
                "Walk country-array slots 0..country_count-1, retaining only non-null pointers whose +0x20 fullref high word equals the slot.",
                "For each candidate and each requested family, read row=table+slot*0x48, reject null owner or fullref mismatch, validate the family-specific owner vector bounds, then use the offer=false membership leaf.",
                "Use the native table order, deduplicate by fullref and family, and publish only identity-verified rows; a failed row is unknown rather than inactive.",
            ],
            "why_not_already_full_network": [
                "The archived native-alliance-ui-inputs artifact read only five selected rows and recorded native_selector_return=not_called.",
                "That artifact recorded row_owner_matches_actor_country=false for all five pairs; owner must therefore not be assumed to be the actor country object.",
                "No archived capture enumerated all valid country slots or ran both leaves for the full FRA partner set.",
            ],
            "runtime_vs_static": "The loops and leaves are static bounded evidence; no new RPM or live full-network observation was made.",
        },
        "network_contract_recommendation": {
            "current_pair_contract": "retain R01 country_pair and its five-family behavior unchanged",
            "future_object": {
                "type": "country",
                "country": "FRA",
                "meaning": "observer country whose verified country table is enumerated",
            },
            "future_parameters": {
                "relation_types": {
                    "type": "array",
                    "uniqueItems": True,
                    "nonempty": True,
                    "enum_after_source_closure": [
                        "vassalization", "guarantee", "support_independence",
                        "military_access", "rival", "alliance", "royal_marriage",
                    ],
                },
                "direction": {
                    "enum": ["outgoing", "incoming", "both"],
                    "meaning": "filter directed families; symmetric families accept either endpoint",
                },
                "partner_tags": {
                    "type": "array",
                    "optional": True,
                    "meaning": "bounded identity filter; omit it to enumerate all verified country slots",
                },
                "include_inactive": {
                    "type": "boolean",
                    "default": False,
                    "meaning": "publish verified false leaf results only when explicitly requested",
                },
            },
            "row_shape": {
                "partner": "verified fullref/tag",
                "relation_type": "family-specific native family",
                "status": "active|inactive|unknown",
                "grantor": "role-derived tag, not_applicable for symmetric/rival, or unknown",
                "recipient": "role-derived tag, not_applicable for symmetric/rival, or unknown",
                "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
            },
            "publish_guards": [
                "Keep actor/partner fullref identity and session/date checks around the whole two-pass read.",
                "Do not convert absent/mismatched rows, legality, acceptance, pending offers, or queue objects into inactive current relations.",
                "Do not treat owner==actor as a guard; the archived five-row sample disproves that assumption.",
                "Keep alliance and royal-marriage grantor/recipient not_applicable because both leaves are symmetric.",
                "Keep expires_at unknown until a relation date field is read and its semantics are independently proven.",
            ],
            "implementation_status": "contract proposal only; no production or public catalog change in this stage",
        },
        "expires_at_semantics": {
            "current_status": "planned in catalog; unsupported by current sources",
            "required_value": "actual established-relation expiry game date, if the native family has one",
            "not_a_substitute": [
                "observer query deadline",
                "offer/acceptance pending queue date",
                "action legality or predicted response",
                "start date copied without an expiry semantic",
            ],
            "output_until_closed": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
        },
        "reusable_sources": {
            "five_current_families": [
                {
                    "family": "vassalization",
                    "source": "bridge/information/subject_relations.py::NativeSubjectRelationSource.read",
                    "container": "family-specific relationship_state plus exclusive role flags",
                },
                {
                    "family": "guarantee",
                    "source": "bridge/diplomacy.py family inspection",
                    "container": "relationship_state.guarantee_active",
                },
                {
                    "family": "support_independence",
                    "source": "bridge/diplomacy.py family inspection",
                    "container": "relationship_state.support_independence_active",
                },
                {
                    "family": "military_access",
                    "source": "bridge/diplomacy.py family inspection",
                    "container": "relationship_state.military_access_active",
                },
                {
                    "family": "rival",
                    "source": "dedicated R34 relation-state path",
                    "container": "relationship_state.rival_active",
                },
            ],
            "alliance_and_royal": {
                "source": "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
                "membership_leafs": {"alliance": "0xA68BC0", "royal_marriage": "0xA68A10"},
                "status": "static leaf closed; public adapter seam and runtime full enumeration remain pending",
            },
        },
        "archived_runtime_pointer_audit": artifact_summary(
            "work/runtime/alliance-query-20261013-r11/native-alliance-ui-inputs.json",
            "read-only selected-five pointer sample",
        ),
        "source_refs": source_refs,
        "evidence_pins": {
            "prior_relation_network_review": {
                "path": "work/runtime/information-relations-20261027-001/relation-source-001.json",
                "sha256": file_sha(ROOT / "work/runtime/information-relations-20261027-001/relation-source-001.json"),
                "meaning": "selected-pair five-family baseline; unchanged",
            },
            "relation_direction_review": {
                "path": "work/runtime/information-country-records-localization-20261027-001/relation-direction-source-001.json",
                "sha256": file_sha(ROOT / "work/runtime/information-country-records-localization-20261027-001/relation-direction-source-001.json"),
                "meaning": "role/direction boundaries; unchanged",
            },
            "native_membership_review": {
                "path": "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
                "sha256": file_sha(ROOT / "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json"),
                "meaning": "bounded A68BC0/A68A10 leaf evidence; no new runtime",
            },
        },
        "conclusion": {
            "country_scope": "A country-object enumeration is statically implementable for verified slots, with FRA as the current observer scope.",
            "owner_vector_answer": "The row owner supplies family-specific vectors to the leaves; it must not be equated with the actor country. The existing five-row archive is not a full-network observation.",
            "coverage_answer": "The five catalog families are reusable selected-pair sources; alliance and royal-marriage membership leaves are additionally closed statically, but neither a public network adapter nor full runtime enumeration is closed here.",
            "remaining_minimum_gap": "Implement one query-only country enumerator with two-pass identity/context guards, then capture an independent full FRA set before promoting R01 scope.",
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
        "source_ref_count": len(report["source_refs"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
