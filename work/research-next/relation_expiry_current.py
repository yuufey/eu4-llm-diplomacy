"""Offline, bounded source review for R01 relation expiry semantics.

This report deliberately separates a current-state membership predicate from a
relation's lifecycle.  It consumes already archived 1.37.4 source contracts,
profiles, and accepted evidence; it never opens a process, calls REA, invokes a
native function, or imports a production reader.

The default command is inert.  Use ``--write`` to create the new, exclusive
``source-001.json`` artifact for this review stage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
STAGE = "information-relation-expiry-current-20261027-001"
DEFAULT_OUTPUT = ROOT / "work" / "runtime" / STAGE / "source-001.json"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
HASH_CHUNK = 1024 * 1024

TARGET_BINARY = {
    "version": "1.37.4",
    "sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
    "image_base": "0x140000000",
}

FAMILIES = (
    "alliance",
    "royal_marriage",
    "guarantee",
    "military_access",
    "fleet_basing",
    "trade_league",
)

# These are all small source or evidence artifacts.  Large runtime raw captures
# are intentionally not opened or copied into this stage.
SOURCE_SPECS: tuple[tuple[str, str], ...] = (
    (
        "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json",
        "1.37.4 bounded alliance/royal selector and leaf review",
    ),
    (
        "work/runtime/information-relation-current-20261027-001/relation-current-source-001.json",
        "retained alliance/royal before-after and public expiry boundary review",
    ),
    (
        "work/runtime/information-relation-current-20261027-001/relation-current-contract-003.json",
        "accepted current-build alliance/royal leaf corroboration",
    ),
    (
        "bridge/information/profiles/relation-memory-1374.json",
        "current relation-memory layout and explicit expiry-unknown contract",
    ),
    (
        "bridge/information/relation_records.py",
        "selected-pair projection and RELATION_EXPIRY_UNREAD guard",
    ),
    (
        "bridge/information/relation_memory.py",
        "alliance/royal direct read and expiry-unknown field construction",
    ),
    (
        "bridge/information/relation_state.py",
        "current public family set and R01 expiry/catalog gap",
    ),
    (
        "bridge/tests/fixtures/information_relation_state_live_1374.json",
        "recorded 1.37.4 inspector shape for guarantee/military_access; no new runtime observation",
    ),
    (
        "work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json",
        "accepted current-build military-access membership leaf evidence",
    ),
    (
        "work/runtime/military-access-integration-20261015-001/findings.json",
        "bounded mapping of a68e60/a68e20 to military-access relation storage",
    ),
    (
        "work/runtime/diplomacy-query-20261015-r30-guarantee-a/alliance-execution.inc",
        "historical action/pending date fields; explicitly excluded from current relation expiry",
    ),
    (
        "work/runtime/diplomacy-query-20261015-r32-military-access-a/alliance-execution.inc",
        "historical action/pending date fields; explicitly excluded from current relation expiry",
    ),
    (
        "work/runtime/information-relation-remaining-20261027-001/fleet-basing-current-source-002.json",
        "current-build fleet-basing predicate and unread-tail boundary",
    ),
    (
        "bridge/information/profiles/fleet-basing-memory-1374.json",
        "fleet-basing partial/expiry-unknown contract",
    ),
    (
        "work/runtime/information-relation-remaining-20261027-001/relation-remaining-contract-005.json",
        "current-build fleet/trade relation contract",
    ),
    (
        "work/runtime/information-relation-remaining-20261027-001/relation-remaining-source-001.json",
        "retained legacy action-only candidates; 1.37.5/9ad addresses excluded",
    ),
    (
        "work/runtime/information-trade-league-current-20261027-001/trade-league-current-source-003.json",
        "current-build trade-league member-vector source",
    ),
    (
        "bridge/information/profiles/trade-league-memory-1374.json",
        "trade-league membership and role/expiry-unknown contract",
    ),
    (
        "work/runtime/information-relation-remaining-20261027-001/code-source004.json",
        "current-build trade-league predicate leaf and vtable source",
    ),
    (
        "work/runtime/information-relation-remaining-20261027-001/expected-trade-league-current-001.json",
        "independent current-identity/runtime membership projection reference",
    ),
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(HASH_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _read_text(path: Path, *, max_bytes: int = MAX_SOURCE_BYTES) -> str:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"source_too_large:{path}:{size}")
    return path.read_text(encoding="utf-8")


def _load_json(relpath: str, *, max_bytes: int = MAX_SOURCE_BYTES) -> Any:
    return json.loads(_read_text(ROOT / relpath, max_bytes=max_bytes))


def _pin(relpath: str, role: str) -> dict[str, Any]:
    path = ROOT / relpath
    if not path.is_file():
        raise FileNotFoundError(relpath)
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"source_too_large:{relpath}:{size}")
    return {
        "path": relpath,
        "bytes": size,
        "sha256": _sha256_file(path),
        "role": role,
        "bounded_read": True,
    }


def _unknown_expiry(reason: str, *, evidence: Iterable[str]) -> dict[str, Any]:
    return {
        "status": "unknown",
        "public_value": {
            "status": "unknown",
            "reason": "RELATION_EXPIRY_UNREAD",
        },
        "fixed_calendar_date": {
            "status": "not_observed",
            "reason": reason,
        },
        "no_fixed_expiry": {
            "status": "not_proven",
            "reason": "absence_of_a_date_read_does_not_prove_nonexpiring",
        },
        "revocation_condition": {
            "status": "unknown",
            "reason": "current_revocation_or_lifecycle_consumer_not_closed",
        },
        "reason": reason,
        "evidence": list(evidence),
        "emit_rule": "do_not_emit_expires_at_value",
    }


def _membership_producer(
    *,
    status: str,
    reader: str,
    read_fields: list[str],
    date_read: bool,
    evidence: list[str],
    rva: str | None = None,
    va: str | None = None,
    body_range: list[str] | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": status,
        "reader": reader,
        "read_fields": list(read_fields),
        "date_or_expiry_read": date_read,
        "evidence": list(evidence),
    }
    if rva is not None:
        result["rva"] = rva
    if va is not None:
        result["va"] = va
    if body_range is not None:
        result["body_rva_range"] = list(body_range)
    if note is not None:
        result["note"] = note
    return result


def _family_findings() -> dict[str, dict[str, Any]]:
    current_relation = (
        "work/runtime/information-relation-current-20261027-001/"
        "relation-current-source-002.json"
    )
    records = "bridge/information/relation_records.py"
    relation_memory = "bridge/information/relation_memory.py"
    fleet_source = (
        "work/runtime/information-relation-remaining-20261027-001/"
        "fleet-basing-current-source-002.json"
    )
    fleet_profile = "bridge/information/profiles/fleet-basing-memory-1374.json"
    trade_source = (
        "work/runtime/information-trade-league-current-20261027-001/"
        "trade-league-current-source-003.json"
    )
    trade_profile = "bridge/information/profiles/trade-league-memory-1374.json"

    return {
        "alliance": {
            "current_state": _membership_producer(
                status="closed_selected_pair_only",
                reader="alliance_query_visibility(offer=false)",
                rva="0xA68BC0",
                va="0x140A68BC0",
                body_range=["0xA68BC0", "0xA68BFC"],
                read_fields=[
                    "relation_row.owner(+0x0)",
                    "relation_row.recipient_fullref(+0x10)",
                    "owner_vector_begin(+0x80)",
                    "owner_vector_count(+0x8C)",
                    "owner_vector.element.first_dword",
                ],
                date_read=False,
                evidence=[current_relation, "work/runtime/information-relation-current-20261027-001/relation-current-contract-003.json"],
                note="The direct leaf only compares a selected partner slot in the owner vector.",
            ),
            "expiry": _unknown_expiry(
                "alliance leaf and selector windows read membership vector fields only; no date serializer is reached",
                evidence=[current_relation, relation_memory, "bridge/information/profiles/relation-memory-1374.json"],
            ),
            "revocation_candidates": [
                {
                    "candidate": "dissolve_alliance",
                    "status": "before_after_membership_only",
                    "meaning": "archived business result changed alliance_before true to alliance_after false; no relation expiry/date was emitted",
                    "current_proof": False,
                    "evidence": "work/runtime/information-relation-current-20261027-001/relation-current-source-001.json",
                }
            ],
            "minimum_next_source": "A current-build relation serializer or lifecycle consumer; do not infer a date from the 0x10 vector element width or from dissolve action results.",
        },
        "royal_marriage": {
            "current_state": _membership_producer(
                status="closed_selected_pair_only",
                reader="alliance_query_visibility(offer=false)",
                rva="0xA68A10",
                va="0x140A68A10",
                body_range=["0xA68A10", "0xA68A46"],
                read_fields=[
                    "relation_row.owner(+0x0)",
                    "relation_row.recipient_fullref(+0x10)",
                    "owner_vector_begin(+0x68)",
                    "owner_vector_count(+0x74)",
                    "owner_vector.element.first_dword",
                ],
                date_read=False,
                evidence=[current_relation, "work/runtime/information-relation-current-20261027-001/relation-current-contract-003.json"],
                note="The direct leaf is symmetric membership; no grantor/recipient or lifecycle date is established.",
            ),
            "expiry": _unknown_expiry(
                "royal-marriage leaf and selector windows read membership vector fields only; no date serializer is reached",
                evidence=[current_relation, relation_memory, "bridge/information/profiles/relation-memory-1374.json"],
            ),
            "revocation_candidates": [
                {
                    "candidate": "royal_marriage_before_after",
                    "status": "before_after_membership_only",
                    "meaning": "archived inspection/response recorded a before/after boolean; it does not identify an expiry or revocation consumer",
                    "current_proof": False,
                    "evidence": "work/runtime/information-relation-current-20261027-001/relation-current-source-001.json",
                }
            ],
            "minimum_next_source": "A current-build relation serializer or lifecycle consumer; preserve symmetric endpoint semantics and leave date unknown until that source is closed.",
        },
        "guarantee": {
            "current_state": _membership_producer(
                status="selected_pair_inspection_only",
                reader="inspect_diplomatic_action('proclaim_guarantee') -> relationship_state.guarantee_active",
                read_fields=["relationship_state.guarantee_active", "inspection.session.date_raw (query context only)"],
                date_read=False,
                evidence=[records, "bridge/tests/fixtures/information_relation_state_live_1374.json"],
                note="The inspector can verify a selected-pair active boolean when its relationship_state is complete; it is not a relation-date serializer.",
            ),
            "expiry": _unknown_expiry(
                "the public projection always adds RELATION_EXPIRY_UNREAD and the inspector's date_raw is session/query context",
                evidence=[records, relation_memory, "bridge/information/relation_state.py"],
            ),
            "revocation_candidates": [
                {
                    "candidate": "proclaim_guarantee / revoke_guarantee",
                    "status": "action_mapping_only",
                    "meaning": "action IDs identify initiation/cancellation modes, not an established relation's end date or automatic revocation condition",
                    "current_proof": False,
                    "evidence": records,
                }
            ],
            "pending_date_boundary": {
                "status": "excluded_from_current_expiry",
                "fields": ["pending/action.date28", "pending/action.date2c"],
                "reason": "existing action construction/transport source dates pending action objects; they are not proof of guarantee relation expiry",
                "evidence": "work/runtime/diplomacy-query-20261015-r30-guarantee-a/alliance-execution.inc",
            },
            "minimum_next_source": "A 1.37.4 established-guarantee relation producer/serializer, separate from legality, pending action construction, and action-ID mapping.",
        },
        "military_access": {
            "current_state": _membership_producer(
                status="closed_selected_pair_predicate_plus_inspection_projection",
                reader="RVA 0xA68E60 row-local membership predicate; public selected-pair inspector projects relationship_state.military_access_active",
                rva="0xA68E60",
                va="0x140A68E60",
                body_range=["0xA68E60", "0xA68E9B"],
                read_fields=[
                    "relation_row.owner(+0x0)",
                    "relation_row.fullref(+0x10) high-word slot",
                    "owner_object.vector_begin(+0xB0)",
                    "owner_object.vector_count(+0xBC)",
                    "vector.element.first_dword",
                ],
                date_read=False,
                evidence=[
                    "work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json",
                    "work/runtime/military-access-integration-20261015-001/findings.json",
                    records,
                ],
                note="The accepted current-build leaf only checks vector membership. RVA/VA are kept separate; no date field is read.",
            ),
            "expiry": _unknown_expiry(
                "A68E60/A68E20 use the row-local owner vector and key; the accepted body contains no date/expiry read",
                evidence=[
                    "work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json",
                    relation_memory,
                    records,
                ],
            ),
            "revocation_candidates": [
                {
                    "candidate": "ask_military_access / cancel_military_access",
                    "status": "action_mapping_only",
                    "meaning": "ask/cancel and the a68e20 lookup/cleanup path identify direction and removal handling, not a fixed expiration date",
                    "current_proof": False,
                    "evidence": [records, "work/runtime/military-access-integration-20261015-001/findings.json"],
                }
            ],
            "pending_date_boundary": {
                "status": "excluded_from_current_expiry",
                "fields": ["pending/action.date28", "pending/action.date2c"],
                "reason": "action lifecycle dates are request/transport context; they are not established relation expiry",
                "evidence": "work/runtime/diplomacy-query-20261015-r32-military-access-a/alliance-execution.inc",
            },
            "minimum_next_source": "A current-build serializer/consumer that owns an established military-access end condition; do not substitute action validity or pending dates.",
        },
        "fleet_basing": {
            "current_state": _membership_producer(
                status="partial_current_predicate",
                reader="fleet_basing_memory received/granted predicates",
                read_fields=[
                    "owner_vectors(+0xE0/+0xEC and +0xF8/+0x104)",
                    "element.first_dword slot",
                    "received matching element(+0x8) pointer",
                    "received agreement(+0x18) fullref slot",
                ],
                date_read=False,
                evidence=[fleet_source, fleet_profile, "work/runtime/information-relation-remaining-20261027-001/relation-remaining-contract-005.json"],
                note="Role and active predicate are bounded, but the current contract retains the remaining element bytes uninterpreted and has no positive runtime sample in the profile.",
            ),
            "expiry": _unknown_expiry(
                "fleet predicates read only the matching slot/record pointer; the remaining 12 bytes of each 16-byte element and any serializer are unresolved",
                evidence=[fleet_source, fleet_profile],
            ),
            "unread_boundary": {
                "element_stride": "0x10",
                "unread_bytes": "+0x4..+0xf",
                "meaning": "unknown; do not label any unread bytes as date or expiry",
            },
            "revocation_candidates": [
                {
                    "candidate": "cancel/revoke fleet-basing action modes",
                    "status": "legacy_action_candidate_excluded",
                    "meaning": "1.37.5/9ad static action candidates are not 1.37.4 current relation proof",
                    "current_proof": False,
                    "evidence": "work/runtime/information-relation-remaining-20261027-001/relation-remaining-source-001.json",
                }
            ],
            "minimum_next_source": "A 1.37.4 expiry serializer/consumer or bounded record read that proves whether the unread element tail carries a date; absence of a positive row does not prove non-expiring.",
        },
        "trade_league": {
            "current_state": _membership_producer(
                status="closed_current_membership_predicate_and_member_vector",
                reader="trade_league_memory country+0x1948 object predicate and +0x20..+0x28 member vector",
                read_fields=[
                    "country+0x1948 object pointer",
                    "active virtual slot+0x40 predicate",
                    "member_vector_begin(+0x20)",
                    "member_vector_end(+0x28)",
                    "member fullref stride 0x8",
                ],
                date_read=False,
                evidence=[trade_source, trade_profile, "work/runtime/information-relation-remaining-20261027-001/relation-remaining-contract-005.json"],
                note="The current reader proves group membership and preserves first-member leader metadata; it does not infer role or lifecycle dates.",
            ),
            "expiry": _unknown_expiry(
                "the active predicate and member vector contain no accepted expiry/date serializer; member identity is not an expiry field",
                evidence=[trade_source, trade_profile],
            ),
            "unread_boundary": {
                "object_prefix": "0x40",
                "member_identity": "full eight-byte country reference",
                "meaning": "membership/leader evidence only; no expiry semantics inferred from prefix or vector width",
            },
            "revocation_candidates": [
                {
                    "candidate": "leave/kick/invite/request action modes",
                    "status": "action_mode_only",
                    "meaning": "membership changes may be action-driven, but the current reader does not establish a fixed date or automatic revocation rule",
                    "current_proof": False,
                    "evidence": "work/runtime/information-relation-remaining-20261027-001/relation-remaining-source-001.json",
                }
            ],
            "minimum_next_source": "A current-build trade-league expiry/lifecycle serializer if the relation owns one; otherwise an explicit native no-fixed-expiry proof. Keep current member rows and expiry independent.",
        },
    }


def _runtime_identity_reference() -> dict[str, Any]:
    # This is an existing independent reference, not a new runtime read.  Keep
    # it only as the identity/date context for the current-build evidence.
    data = _load_json(
        "work/runtime/information-relation-remaining-20261027-001/expected-trade-league-current-001.json",
        max_bytes=8 * 1024 * 1024,
    )
    identity = data.get("identity") if isinstance(data, Mapping) else None
    if not isinstance(identity, Mapping):
        raise ValueError("current_identity_reference_missing")
    return {
        "observer": identity.get("observer"),
        "session_id": identity.get("session_id"),
        "pid": identity.get("pid"),
        "game_date": identity.get("game_date"),
        "creation_filetime": identity.get("creation_filetime"),
        "source": "work/runtime/information-relation-remaining-20261027-001/expected-trade-league-current-001.json",
        "new_runtime_observation": False,
    }


def build_report() -> dict[str, Any]:
    source_refs = [_pin(path, role) for path, role in SOURCE_SPECS]
    relation_source = _load_json(
        "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json"
    )
    relation_profile = _load_json("bridge/information/profiles/relation-memory-1374.json")
    fleet_profile = _load_json("bridge/information/profiles/fleet-basing-memory-1374.json")
    trade_profile = _load_json("bridge/information/profiles/trade-league-memory-1374.json")
    a68e60 = _load_json(
        "work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json"
    )
    records_text = _read_text(ROOT / "bridge/information/relation_records.py")
    relation_memory_text = _read_text(ROOT / "bridge/information/relation_memory.py")
    relation_state_text = _read_text(ROOT / "bridge/information/relation_state.py")

    checks = {
        "target_binary_current": relation_source.get("target_binary", {}).get("sha256", "").lower() == TARGET_BINARY["sha256"],
        "target_version_current": relation_source.get("target_binary", {}).get("version") == TARGET_BINARY["version"],
        "relation_profile_current": relation_profile.get("executable", {}).get("sha256", "").lower() == TARGET_BINARY["sha256"],
        "fleet_profile_current": fleet_profile.get("executable", {}).get("sha256", "").lower() == TARGET_BINARY["sha256"],
        "trade_profile_current": trade_profile.get("executable", {}).get("sha256", "").lower() == TARGET_BINARY["sha256"],
        "relation_source_expiry_unknown": relation_source.get("date_and_serializer", {}).get("expiry_date", {}).get("status") == "unknown",
        "relation_profile_expiry_unknown": relation_profile.get("semantics", {}).get("expiry_semantics") == "unknown_native_expiry_unread",
        "relation_records_guard_present": "RELATION_EXPIRY_UNREAD" in records_text and '"expires_at"' in records_text,
        "relation_memory_guard_present": "RELATION_EXPIRY_UNREAD" in relation_memory_text and '"expires_at"' in relation_memory_text,
        "relation_state_catalog_gap_present": "RELATION_EXPIRY_NOT_IMPLEMENTED" in relation_state_text,
        "fleet_profile_expiry_unknown": fleet_profile.get("semantics", {}).get("expiry_semantics") == "unknown_native_expiry_unread",
        "trade_profile_expiry_not_inferred": "expiry are not inferred" in json.dumps(trade_profile, ensure_ascii=False),
        "accepted_a68e60_current": a68e60.get("subject", {}).get("digest", {}).get("sha256", "").lower() == TARGET_BINARY["sha256"] and a68e60.get("parameters", {}).get("procedure") == "0x140a68e60",
    }
    failed = [name for name, value in checks.items() if value is not True]
    if failed:
        raise ValueError("source_contract_checks_failed:" + ",".join(failed))

    return {
        "schema": "information_relation_expiry_source.v1",
        "stage": STAGE,
        "report_id": "relation-expiry-current-source-001",
        "review_scope": {
            "kind": "offline_current_build_source_review",
            "source_only": True,
            "target_binary": dict(TARGET_BINARY),
            "new_rea": False,
            "new_rpm": False,
            "new_mcp": False,
            "new_game_query": False,
            "native_function_invoked": False,
            "production_changes": False,
            "pytest": False,
            "address_rule": "RVA and VA are recorded separately; no 1.37.5/9ad address is promoted to current proof.",
            "large_capture_rule": "large raw captures were not opened or copied; only bounded source/evidence artifacts are pinned",
        },
        "current_identity_reference": _runtime_identity_reference(),
        "semantic_classes": {
            "fixed_calendar_date": "A date field/serializer owned by the established relation is required; a query/session date or pending action date is insufficient.",
            "no_fixed_expiry": "Requires an explicit native or serializer proof; a missing read is not enough.",
            "revocation_condition": "A current lifecycle/removal consumer may establish a condition without a fixed date; action names, legality, pending state, and before/after booleans are candidates only.",
            "unknown": "Use status unknown and RELATION_EXPIRY_UNREAD when neither a date nor a no-fixed-expiry proof is closed.",
        },
        "family_order": list(FAMILIES),
        "family_findings": _family_findings(),
        "cross_family_rules": {
            "public_expires_at": {family: {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"} for family in FAMILIES},
            "not_fixed_date": "No family is promoted to no_fixed_expiry by this source-only review.",
            "current_date_is_not_expiry": "game_date/session.date_raw is context for a snapshot or action request, not an established relation end date.",
            "pending_date_is_not_expiry": "date28/date2c in action lifecycle/pending objects are excluded from current relation expiry until a current relation serializer binds them.",
            "action_is_not_current_state": "legality, acceptance, pending offers, cancel/revoke action IDs, and historical before/after results cannot replace a current relation expiry producer.",
            "legacy_build_exclusion": {
                "excluded_sha256": "9ad3efe1af169f40ee577f9da5edebbc87af6fb8b5450fb345ebf110dc4d771a",
                "reason": "1.37.5 static/action candidates are retained only as historical context and are not current 1.37.4 evidence.",
            },
        },
        "checks": checks,
        "source_refs": source_refs,
        "script": {
            "path": "work/research-next/relation_expiry_current.py",
            "sha256": _sha256_file(Path(__file__).resolve()),
            "mode": "offline_bounded_source_review",
        },
        "conclusion": {
            "status": "no_current_expiry_serializer_closed",
            "strongest_result": "All six current-build family outputs remain expires_at unknown; membership/current booleans and lifecycle candidates are retained separately.",
            "real_date_families": [],
            "explicit_no_fixed_expiry_families": [],
            "revocation_only_candidates": ["alliance", "royal_marriage", "guarantee", "military_access", "fleet_basing", "trade_league"],
            "next_root_entry": "Root may coordinate bounded current-build analysis of each family's established relation serializer/lifecycle consumer. Do not reuse 1.37.5/9ad action addresses, and do not call a missing date proof a no-expiry proof.",
        },
    }


def _write_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the new source-001 report")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="exclusive output path")
    args = parser.parse_args(argv)
    if not args.write:
        parser.print_help()
        return 0
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise FileExistsError(f"refusing_to_overwrite:{output}")
    _write_exclusive(output, build_report())
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
