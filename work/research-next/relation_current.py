"""Offline bounded review of the existing alliance/royal-marriage reader.

This script does not attach to a game, call REA/RPM, load a DLL, or infer a
relation from a legality/pending object.  It records the already implemented
native producer path that supplies ``alliance_before/after`` and
``royal_marriage_before/after`` in business-result wires.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "work" / "runtime" / "information-relation-current-20261027-001"
TARGET_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000


def file_sha(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bounded_lines(path: Path, start: int, end: int) -> list[str]:
    """Read only the requested one-based inclusive line window."""
    if start < 1 or end < start:
        raise ValueError("invalid bounded source window")
    lines: list[str] = []
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if number < start:
                continue
            if number > end:
                break
            lines.append(line.rstrip("\n"))
    return lines


def require_markers(path: Path, start: int, end: int, markers: Iterable[str]) -> None:
    text = "\n".join(bounded_lines(path, start, end))
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise AssertionError(f"missing markers in {path}:{start}-{end}: {missing}")


def ref(path_text: str, start: int, end: int, markers: Iterable[str]) -> dict[str, Any]:
    path = ROOT / path_text
    require_markers(path, start, end, markers)
    return {
        "path": path_text,
        "sha256": file_sha(path),
        "line_range": [start, end],
        "bytes_examined": sum(len(line.encode("utf-8")) + 1
                               for line in bounded_lines(path, start, end)),
        "markers": list(markers),
    }


def _first_result(path_text: str, wanted: tuple[str, ...]) -> dict[str, Any]:
    """Extract the first bounded archive result carrying the wanted keys."""
    path = ROOT / path_text
    data = json.loads(path.read_text(encoding="utf-8"))

    def walk(value: Any, pointer: str = "") -> tuple[str, dict[str, Any]] | None:
        if isinstance(value, dict):
            if all(key in value for key in wanted):
                return pointer or "/", value
            for key, child in value.items():
                found = walk(child, f"{pointer}/{key}")
                if found is not None:
                    return found
        elif isinstance(value, list):
            for index, child in enumerate(value):
                found = walk(child, f"{pointer}/{index}")
                if found is not None:
                    return found
        return None

    found = walk(data)
    if found is None:
        raise AssertionError(f"archive has no result with keys {wanted}: {path_text}")
    pointer, result = found
    return {
        "path": path_text,
        "sha256": file_sha(path),
        "bytes": path.stat().st_size,
        "json_pointer": pointer,
        "values": {key: result[key] for key in wanted},
    }


def build_report() -> dict[str, Any]:
    execution = ROOT / "work/native/alliance-execution.inc"
    query = ROOT / "work/native/alliance-query.inc"
    inbound = ROOT / "work/native/alliance-inbound-inspection-event.h"
    relation_state = ROOT / "bridge/information/relation_state.py"
    relation_records = ROOT / "bridge/information/relation_records.py"
    prior_report = ROOT / "work/runtime/information-relations-20261027-001/relation-source-001.json"

    source_refs = [
        ref("work/native/alliance-execution.inc", 1279, 1333, (
            "static bool execution_read_after",
            "return alliance_query_visibility(payload.actor10,payload.recipient20,false",
            "payload.family==ActionFamily::royal_marriage?0x28df:0x293d",
        )),
        ref("work/native/alliance-query.inc", 44, 89, (
            "static bool alliance_query_visibility",
            "const uintptr_t case_rva=marriage?0x35ac11:0x35a9e3",
            "relation=table+recipient_slot*72",
            "owner+(marriage?0x68:0x80)",
            "owner+(marriage?0x74:0x8c)",
            "using Selector=bool (*)(void*,int32_t,uint64_t,void*,unsigned char,void*)",
        )),
        ref("work/native/alliance-inbound-inspection-event.h", 159, 209, (
            "royal_marriage_before",
            "native_current_royal_marriage",
            "native_current_alliance",
            "native_current_alliance_readable",
        )),
        ref("bridge/information/relation_state.py", 15, 25, (
            "_ACTIONS = dict(zip(SUPPORTED_FAMILIES",
            '"relation_type", "status", "grantor", "recipient"',
        )),
        ref("bridge/information/relation_records.py", 15, 39, (
            "SUPPORTED_FAMILIES =",
            '"vassalization",',
            '"rival",',
            "ACTION_MAPPING =",
        )),
    ]

    alliance_archive = _first_result(
        "work/runtime/alliance-query-20261015-r24-dissolve-a/"
        "dissolve-execution-5db2994d34db45f69b8b6a808378a1ac/report.json",
        ("event", "action_id", "actor", "recipient", "alliance_before", "alliance_after"),
    )
    royal_report_path = (
        "work/runtime/diplomacy-query-20261015-r27-royal-inbound-f-accept/"
        "inbound-response-bc5ad1cad77943f28ee4435398b88845/report.json"
    )
    royal_before_archive = _first_result(
        royal_report_path,
        ("event", "action_id", "family", "actor", "recipient",
         "royal_marriage_before"),
    )
    royal_after_archive = _first_result(
        royal_report_path,
        ("event", "action_id", "family", "actor", "recipient",
         "royal_marriage_after"),
    )

    return {
        "schema": "information_relation_current_source.v1",
        "stage": "information-relation-current-20261027-001",
        "review_scope": {
            "kind": "offline_source_and_archived_result_review",
            "new_game_query": False,
            "rea_or_rpm": False,
            "dll_or_native_call": False,
            "business_action": False,
            "production_changes": False,
            "bounded_source_windows_only": True,
        },
        "target_binary": {
            "version": "1.37.4",
            "sha256": TARGET_EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_note": "RVA values below are image-relative; no VA is substituted for an RVA.",
        },
        "producer_contract": {
            "entrypoint": {
                "source": "work/native/alliance-execution.inc",
                "function": "execution_read_after",
                "rva": None,
                "line_range": [1279, 1333],
                "role": "business-result before/after reader; source file has no PE boundary claim",
            },
            "family_dispatch": [
                {
                    "family": "alliance",
                    "selector": "0x293d",
                    "offer_argument": 0,
                    "output": "alliance_after / alliance_before through the same bool reference",
                },
                {
                    "family": "royal_marriage",
                    "selector": "0x28df",
                    "offer_argument": 0,
                    "output": "royal_marriage_after / royal_marriage_before through the same bool reference",
                },
            ],
            "native_membership_helper": {
                "name": "alliance_query_visibility",
                "call_target_rva": "0x35a920",
                "call_target_va": "0x14135a920",
                "abi": "(country, selector, recipient_fullref, relation_row, offer_byte, nullptr) -> bool",
                "read_mode": "offer=false is used by execution_read_after; it reads current membership predicate",
                "selector_guard": {
                    "entry_bytes": "48895c2408",
                    "switch_rva": "0x35bebc",
                    "switch_table_rva": "0x35be80",
                    "alliance_case_rva": "0x35a9e3",
                    "royal_case_rva": "0x35ac11",
                    "alliance_switch_index": 3,
                    "royal_switch_index": 0,
                },
            },
            "actor_recipient_direction": {
                "actor": "database country slot selected from actor fullref high word; country+0x20 must equal actor fullref",
                "recipient": "recipient slot selected from recipient fullref high word; relation row +0x10 must equal recipient fullref",
                "relation_row": "actor_country+0x1510 + recipient_slot*0x48",
                "role_boundary": "actor/recipient are selected endpoints; alliance and royal marriage are symmetric, so do not relabel either as grantor/beneficiary",
            },
        },
        "container_layout": {
            "country_database_global_rva": "0x233d8b0",
            "country_array_offset": "0x118",
            "country_count_offset": "0x124",
            "country_fullref_offset": "0x20",
            "relation_table_offset": "0x1510",
            "relation_row_stride": 0x48,
            "relation_row_owner_offset": "0x0",
            "relation_row_recipient_fullref_offset": "0x10",
            "owner_vector": {
                "alliance": {"begin_offset": "0x80", "count_offset": "0x8c"},
                "royal_marriage": {"begin_offset": "0x68", "count_offset": "0x74"},
                "element_stride": 0x10,
                "count_guard": "0 <= count <= 4096; nonzero count requires nonzero begin",
                "read_guard": "the existing helper validates every 16-byte element before calling the native selector",
            },
        },
        "minimum_read_only_interface": {
            "object": "country_pair",
            "parameters": {"relation_types": ["alliance", "royal_marriage"]},
            "read_sequence": [
                "Validate observer/session and both country fullrefs against the country table.",
                "Resolve actor country relation table and recipient row at +0x48 stride.",
                "Select selector 0x293d or 0x28df and verify the existing entry/case/switch guards.",
                "Validate the selected owner vector range with its family-specific begin/count offsets and 0x10 stride.",
                "Call the existing native membership helper with offer=false, or expose this same call through a read-only bridge method.",
                "Publish relation_type and status only after the helper returns a bool; preserve actor/recipient as endpoints.",
            ],
            "row_shape": {
                "relation_type": "alliance | royal_marriage",
                "status": "active | inactive from the verified native bool",
                "actor": "selected actor endpoint",
                "recipient": "selected recipient endpoint",
                "grantor": {"status": "not_applicable", "reason": "SYMMETRIC_RELATION_NO_GRANTOR_ROLE"},
                "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
            },
            "safe_reuse": "reuse the existing native selector and guards; do not submit an offer/dissolve/break action",
        },
        "public_bridge_gap": {
            "native_relation_source_current_families": [
                "vassalization", "guarantee", "support_independence", "military_access", "rival"
            ],
            "missing_current_families": ["alliance", "royal_marriage"],
            "reason": "NativeRelationSource and relation_records only map the five existing selected-pair inspectors. inspect_diplomatic_action for offer_alliance/offer_royal_marriage exposes legality/visibility/acceptance projections, not a current membership field.",
            "pending_boundary": "alliance_objects and inbound inspection are pending/proposal or lifecycle observations; they cannot be used as a general current relation snapshot.",
            "expiry_boundary": "the current membership helper reads no expiry/date field; expires_at remains unknown.",
        },
        "archived_business_result_evidence": {
            "alliance": alliance_archive,
            "royal_marriage": {
                "before": royal_before_archive,
                "after": royal_after_archive,
            },
            "interpretation": "These archives prove the producer emitted bound before/after business-result values. They are corroboration for the helper path, not a replacement for a fresh read-only current snapshot.",
        },
        "source_refs": source_refs,
        "prior_relation_review": {
            "path": "work/runtime/information-relations-20261027-001/relation-source-001.json",
            "sha256": file_sha(prior_report),
            "role": "prior offline review; retained unchanged and not treated as a new runtime observation",
        },
        "conclusion": {
            "status_reader_closed": True,
            "status_reader": "execution_read_after -> alliance_query_visibility(offer=false)",
            "alliance_and_royal_current_export": "small read-only bridge seam is implementable by exposing this existing native call with the exact guards above",
            "relation_network": "not closed; this is selected-pair only",
            "roles_and_expiry": "not closed; symmetric endpoint roles and expiry remain unknown/not_applicable",
            "next_entry_if_needed": "add a query-only seam around alliance_query_visibility; do not route through legality, pending proposals, or action submission",
        },
    }


def main() -> int:
    report_path = STAGE / "relation-current-source-001.json"
    if report_path.exists():
        raise SystemExit(f"refusing to overwrite existing report: {report_path}")
    STAGE.mkdir(parents=True, exist_ok=True)
    report = build_report()
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(report_path)
    print(file_sha(report_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
