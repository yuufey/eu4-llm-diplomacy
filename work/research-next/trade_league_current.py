"""Build a bounded, source-only trade-league current-state evidence report.

The report records facts already supplied by the fixed 1.37.4 PE review and
the accepted read-only REA dossier.  It does not launch REA, open a game,
perform RPM, call a native function, or modify a production reader.  The
bounded source windows are kept separate from REA and runtime evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-trade-league-current-20261027-001/"
    "trade-league-current-source-002.json"
)
TARGET_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
TARGET_EXE_BYTES = 38_463_016
IMAGE_BASE = 0x140000000
REA_EVIDENCE = ROOT / (
    "work/runtime/information-relation-remaining-20261027-001/"
    "rea-trade-league-validity-001/evidence.json"
)
REA_RUN = ROOT / (
    "work/runtime/information-relation-remaining-20261027-001/"
    "rea-trade-league-validity-001/run.json"
)
PRIOR_SOURCE = ROOT / (
    "work/runtime/information-trade-league-current-20261027-001/"
    "trade-league-current-source-001.json"
)


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": file_sha(path),
    }


def rva(value: int) -> str:
    return f"0x{value:x}"


def va(value: int) -> str:
    return f"0x{IMAGE_BASE + value:x}"


def bounded_source_window(
    relative: str,
    start_line: int,
    end_line: int,
    markers: Iterable[str],
) -> dict[str, Any]:
    """Read only a line window and report marker presence."""

    path = ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(relative)
    marker_state = {marker: False for marker in markers}
    used = 0
    lines = 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            if number > end_line:
                break
            if number < start_line:
                continue
            used += len(line.encode("utf-8"))
            lines += 1
            for marker in marker_state:
                marker_state[marker] |= marker in line
    return {
        "line_range_inclusive": [start_line, end_line],
        "bytes_examined": used,
        "lines_examined": lines,
        "markers_present": marker_state,
    }


def static_source_refs() -> list[dict[str, Any]]:
    catalog = ROOT / "bridge/diplomacy_catalog.json"
    return [
        {
            "path": "bridge/diplomacy_catalog.json",
            "sha256": file_sha(catalog),
            "role": "existing action/literal catalog; labels are not current-state proof",
            "bounded_windows": [
                bounded_source_window(
                    "bridge/diplomacy_catalog.json",
                    8867,
                    8940,
                    ("invite_to_trade_league", "0x1c7bd08"),
                ),
                bounded_source_window(
                    "bridge/diplomacy_catalog.json",
                    12578,
                    12648,
                    ("request_to_join_trade_league",),
                ),
            ],
        },
    ]


def rea_summary() -> dict[str, Any]:
    if not REA_EVIDENCE.is_file() or not REA_RUN.is_file():
        raise FileNotFoundError("accepted trade-league REA evidence/run is missing")
    evidence = json.loads(REA_EVIDENCE.read_bytes())
    run = json.loads(REA_RUN.read_bytes())
    raw_value = evidence.get("raw_result", {}).get("value", {})
    procedure = raw_value.get("procedure", {}) if isinstance(raw_value, dict) else {}
    body = procedure.get("body", {}) if isinstance(procedure, dict) else {}
    ranges = body.get("ranges", []) if isinstance(body, dict) else []
    return {
        "evidence": pin(REA_EVIDENCE),
        "run": pin(REA_RUN),
        "evidence_id": evidence.get("evidence_id"),
        "authority": "REA shipped-artifact read-only analysis",
        "provider": evidence.get("provider"),
        "target_sha256": evidence.get("subject", {}).get("digest", {}).get("sha256"),
        "procedure": procedure.get("address"),
        "body": {
            "ranges": ranges,
            "total_bytes": body.get("total_bytes"),
            "span_bytes": body.get("span_bytes"),
            "range_semantics": "preserve REA reported endpoint semantics; do not normalize here",
        },
        "run_status": run.get("status"),
        "provider_exit_code": run.get("provider_exit_code"),
        "postread": run.get("postread"),
        "cleanup": run.get("cleanup"),
        "database": run.get("database"),
        "process_memory_limit_bytes": run.get("process_memory_limit_bytes"),
        "query_reanalysis": run.get("query_reanalysis"),
    }


def build_report() -> dict[str, Any]:
    request_start, request_end = 0x58FD60, 0x5909DE
    invite_start, invite_end = 0x5917A0, 0x592BDF
    leaf_start, leaf_end = 0x593550, 0x593556
    report = {
        "schema": "information_trade_league_current_source.v2",
        "batch": 55,
        "status": "static_and_accepted_rea_source_only",
        "scope": {
            "current_state_reader": "not implemented",
            "objective": "bound the trade-league object/predicate and active virtual entrypoints without publishing legality as current state",
            "new_rea_or_rpm": False,
            "game_or_native_calls": False,
            "production_changes": False,
        },
        "target_binary": {
            "version": "1.37.4",
            "sha256": TARGET_EXE_SHA256,
            "bytes": TARGET_EXE_BYTES,
            "image_base": hex(IMAGE_BASE),
            "address_note": "all RVA values are image-relative; VA is derived only as image_base + RVA",
        },
        "prior_candidate": {
            "path": PRIOR_SOURCE.relative_to(ROOT).as_posix(),
            "exists_at_generation": PRIOR_SOURCE.is_file(),
            "role": "historical source-001 candidate; preserved and not overwritten",
            "relation_to_this_report": "source-002 corrects the current-vtable and bounded-body facts",
        },
        "literal_and_xref_anchors": [
            {
                "literal": "CRequestToJoinTradeLeague, %s, %s",
                "literal_rva": rva(0x1C8A4D8),
                "literal_va": va(0x1C8A4D8),
                "xref_rva": rva(0x59011A),
                "xref_va": va(0x59011A),
                "bounded_function_window": {
                    "start_rva": rva(request_start),
                    "end_rva": rva(request_end),
                    "end_semantics": "reported bounded endpoint; exclusive byte arithmetic only",
                    "bytes_if_exclusive": request_end - request_start,
                },
            },
            {
                "literal": "TradeLeagueInvite, %s, %s",
                "literal_rva": rva(0x1C8A628),
                "literal_va": va(0x1C8A628),
                "xref_rva": rva(0x591D5A),
                "xref_va": va(0x591D5A),
                "bounded_function_window": {
                    "start_rva": rva(invite_start),
                    "end_rva": rva(invite_end),
                    "end_semantics": "reported bounded endpoint; exclusive byte arithmetic only",
                    "bytes_if_exclusive": invite_end - invite_start,
                },
            },
        ],
        "rdata_and_vtable": {
            "unique_qword_exec_targets_rva": [rva(0x1C7BAF0), rva(0x1C7BD50)],
            "unique_qword_exec_targets_va": [va(0x1C7BAF0), va(0x1C7BD50)],
            "invite_vtable_rva": rva(0x1C7BD08),
            "invite_vtable_va": va(0x1C7BD08),
            "slots": [
                {
                    "slot_offset": rva(0x80),
                    "target_rva": rva(0x592CD0),
                    "target_va": va(0x592CD0),
                    "implementation": "REA-analyzed function; body range is retained in rea_summary",
                },
                {
                    "slot_offset": rva(0x88),
                    "target_rva": rva(0x5932F0),
                    "target_va": va(0x5932F0),
                    "implementation": "entry target observed; body not followed in this bounded source report",
                },
                {
                    "slot_offset": rva(0x98),
                    "target_rva": rva(0x593550),
                    "target_va": va(0x593550),
                    "instruction_window": {
                        "start_rva": rva(leaf_start),
                        "end_rva": rva(leaf_end),
                        "bytes_hex": "b81d330000c3",
                        "assembly": "mov eax, 0x331d; ret",
                        "bytes": leaf_end - leaf_start,
                    },
                    "meaning": "returns constant 0x331d; business role unresolved",
                },
            ],
            "old_accessor": {
                "rva": rva(0x593520),
                "status": "not_current_invite_vtable_entry",
                "note": "older 1.37.5-oriented accessor; do not substitute for 1.37.4 slot +0x98",
            },
        },
        "bounded_window_budget": {
            "max_single_bytes": 8192,
            "max_total_bytes": 16384,
            "windows": [
                {"name": "request_xref_body", "bytes_if_exclusive": request_end - request_start},
                {"name": "invite_xref_body", "bytes_if_exclusive": invite_end - invite_start},
                {"name": "constant_leaf", "bytes_if_exclusive": leaf_end - leaf_start},
            ],
            "total_bytes_if_exclusive": (request_end - request_start)
            + (invite_end - invite_start)
            + (leaf_end - leaf_start),
            "note": "No new PE decode was run; windows record the already supplied bounded facts.",
        },
        "rea_contract": {
            "rea_summary": rea_summary(),
            "function_role": "validity/eligibility path, not a public current-state getter",
            "observed_country_member_shape": {
                "country_object_offset": rva(0x1948),
                "object_storage": "QWORD pointer/object at country+0x1948",
                "predicate_vtable_slot": rva(0x40),
                "predicate_return": "AL boolean",
                "member_vector_begin_offset": rva(0x20),
                "member_vector_end_offset": rva(0x28),
                "member_width_bytes": 8,
                "member_payload": "8-byte fullref values",
                "first_member_use": "input to LEADER display text in the analyzed path",
            },
            "semantic_boundary": "the AL result and action legality path must not be published as current trade-league membership",
        },
        "current_state_contract": {
            "closed": [
                "literal and bounded xref anchors for request/join and invite labels",
                "invite vtable RVA and +0x80/+0x88/+0x98 entry targets",
                "+0x98 constant leaf bytes and constant return value",
                "country+0x1948 object shape, +0x40 AL predicate seam, and +0x20/+0x28 fullref vector shape",
            ],
            "unknown": [
                "concrete C++/RTTI object type",
                "complete meaning of each active virtual method",
                "which country is leader and the complete member role mapping",
                "whether any value represents current membership versus action eligibility",
                "expiry/start-date storage and semantics",
                "production-safe current-state reader and country-wide enumeration",
            ],
            "not_substitutes": [
                "request/invite action labels",
                "legality or pending results",
                "the 0x331d constant alone",
                "the older 0x593520 accessor",
            ],
        },
        "source_layering": {
            "ordinary_static": static_source_refs(),
            "rea": "rea_contract.rea_summary; accepted read-only shipped-artifact evidence",
            "runtime": "none",
            "business_or_game_effect": "none",
        },
        "unresolved_conditions": [
            "No runtime current trade-league sample was collected in this source-only task.",
            "The analyzed validity function's boolean is not promoted to current relation state.",
            "A future reader must separately prove object identity, member ordering, role direction, and expiry before publishing fields.",
        ],
    }
    return report


def write_report(output: Path = DEFAULT_OUTPUT) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report()
    report["producer_script"] = {
        "path": Path(__file__).resolve().relative_to(ROOT).as_posix(),
        "sha256": file_sha(Path(__file__).resolve()),
        "generation": "offline bounded source packaging; no REA/RPM/game/test run",
    }
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the bounded source-002 report")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if not args.write:
        parser.print_help()
        return 0
    output = args.output if args.output.is_absolute() else ROOT / args.output
    print(write_report(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
