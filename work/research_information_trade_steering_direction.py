"""Batch-48 bounded native steering-direction source research.

This report follows two already bounded UI paths on the pinned EU4 1.37.4
binary.  The first builds the ``STEERING_TRADE_TO_LIST`` and
``TRADE_STEERED_FROM_LIST`` relation strings; its list elements go through the
previously closed packed-country resolver, so it is kept separate from the
trade-node definition key contract.  The second is a small merchant-route
boolean predicate and is recorded only as an unresolved candidate because its
return value is not a direction enum or a node key.  No B59550 caller or
STEER_NO_TRADER path is decoded here.

The script performs ordinary bounded PE decoding only.  It does not open the
game, use RPM/REA, execute a native function, or change production files.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-merchant-task-20261027-001"
OUTPUT = STAGE / "steering-direction-source-001.json"
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_SINGLE_DECODE = 4 * 1024
MAX_TOTAL_DECODE = 24 * 1024

# The first two windows are the relation-list selector/builder.  The last two
# are the small merchant-route predicate and its callsite.  Every range starts
# on an instruction boundary known from the same pinned PE, but is intentionally
# a partial window when the .pdata function is larger than the bounded slice.
CODE_RANGES = (
    (0x10CCEE7, 0x10CDEE7, "relation_vector_selector_and_element_loop"),
    (0x10CE2F6, 0x10CF2F6, "relation_to_from_ui_builder"),
    (0x352100, 0x3521A9, "merchant_route_boolean_predicate"),
    (0x353F81, 0x354381, "merchant_route_predicate_callsite"),
)

SELECTED = {
    "relation_vector_selector_and_element_loop": (
        0x10CCEE7, 0x10CCEEB, 0x10CCEF0, 0x10CCF00, 0x10CCF03,
        0x10CCF07, 0x10CCF0D, 0x10CCF18, 0x10CCF1C, 0x10CCF27,
        0x10CCF36, 0x10CCF40, 0x10CD330, 0x10CD335, 0x10CD339,
        0x10CD34C, 0x10CD369, 0x10CD36E, 0x10CD372, 0x10CD379,
        0x10CD37C, 0x10CD383, 0x10CD3A4,
    ),
    "relation_to_from_ui_builder": (
        0x10CE347, 0x10CE34B, 0x10CE352, 0x10CE35D, 0x10CE39F,
        0x10CE3A6, 0x10CE3AD, 0x10CE3F0, 0x10CE3FC, 0x10CE4AB,
        0x10CE4AF, 0x10CE4B6, 0x10CE4C1, 0x10CE503, 0x10CE50A,
        0x10CE511, 0x10CE554, 0x10CE560,
    ),
    "merchant_route_boolean_predicate": (
        0x35210F, 0x352119, 0x352126, 0x35212D, 0x352134,
        0x352139, 0x35213F, 0x352144, 0x352152, 0x352160,
        0x352178, 0x35217C, 0x352181, 0x352185, 0x352197,
    ),
    "merchant_route_predicate_callsite": (
        0x353F8F, 0x353F99, 0x353FA0, 0x353FA3, 0x353FA6,
        0x353FAB, 0x353FAD, 0x35422E, 0x354266, 0x354270,
        0x3542C9, 0x3542D3, 0x3542E4,
    ),
}

LITERALS = {
    0x1C44D1C: "LIST",
    0x1C5D658: "STEERING_TRADE_TO_LIST",
    0x1C5D670: "TRADE_STEERED_FROM_LIST",
}


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _with_va(row: dict) -> dict:
    result = dict(row)
    result["va"] = hex(IMAGE_BASE + int(row["rva"], 16))
    return result


def _select(rows: list[dict], addresses: tuple[int, ...]) -> list[dict]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = [hex(address) for address in addresses if address not in by_rva]
    if missing:
        raise AssertionError(f"decoder did not return selected instructions: {missing}")
    return [_with_va(by_rva[address]) for address in addresses]


def _range_record(pe: PE, rows: list[dict], begin: int, end: int, label: str) -> dict:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise AssertionError(f"range is not fully PE-backed: {begin:#x}:{end:#x}")
    pdata = pe.function(begin)
    return {
        "label": label,
        "rva_exclusive": [hex(begin), hex(end)],
        "va_exclusive": [hex(IMAGE_BASE + begin), hex(IMAGE_BASE + end)],
        "byte_length": len(raw),
        "raw_range_sha256": _sha256_bytes(raw),
        "pdata_function_boundary": (
            [hex(pdata[0]), hex(pdata[1])] if pdata else None
        ),
        "coverage": (
            "exact_pdata_function"
            if pdata and pdata[0] == begin and pdata[1] == end
            else "partial_or_explicit_window"
        ),
        "decoded_instruction_count": len(rows),
        "address_semantics": "RVA; VA=image_base_va+RVA; end is exclusive",
    }


def _literal(pe: PE, rva: int, expected: str) -> dict:
    wanted = expected.encode("ascii") + b"\0"
    raw = pe.bytes_at(rva, len(wanted))
    if raw != wanted:
        raise AssertionError(f"literal changed at {rva:#x}: {raw!r}")
    return {
        "rva": hex(rva),
        "va": hex(IMAGE_BASE + rva),
        "text": expected,
        "bytes_hex": raw.hex(),
        "bytes_sha256": _sha256_bytes(raw),
    }


def _prior(path: Path, role: str) -> dict:
    return {
        "path": _relative(path),
        "sha256": _sha256_path(path),
        "role": role,
        "evidence_kind": "prior_ordinary_static_or_static_runtime_corroboration",
    }


def build_report() -> dict:
    exe = Path(game_exe())
    pe = PE(exe)
    exe_sha = _sha256_bytes(pe.data)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {exe_sha}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded: dict[str, list[dict]] = {}
    ranges = []
    total = 0
    for begin, end, label in CODE_RANGES:
        size = end - begin
        if size <= 0 or size > MAX_SINGLE_DECODE:
            raise AssertionError(f"single decode limit failure: {label}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"non-executable range: {label}")
        total += size
        if total > MAX_TOTAL_DECODE:
            raise AssertionError("total decode limit failure")
        rows = _decode_range(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    selected = {
        label: _select(decoded[label], addresses)
        for label, addresses in SELECTED.items()
    }

    prior_trade_state = ROOT / "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json"
    prior_key = ROOT / "work/runtime/information-budget-collectors-20261027-001/trade-node-key-source-001.json"
    prior_corrob = ROOT / "work/runtime/information-budget-collectors-20261027-001/trade-node-key-corroboration-001.json"
    prior_modifiers = ROOT / "work/runtime/information-trade-source-details-20261027-001/source-modifiers-002.json"
    prior_direction_tail = ROOT / "work/runtime/information-trade-source-details-20261027-001/trade-details-source-index-003.json"
    for path in (prior_trade_state, prior_key, prior_corrob, prior_modifiers, prior_direction_tail):
        if not path.exists():
            raise FileNotFoundError(path)

    localization_paths = [
        Path(r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV\localisation\tradenodes_l_english.yml"),
        Path(r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV\localisation\rule_britannia_l_english.yml"),
    ]
    localization_evidence = []
    for path in localization_paths:
        item = {"path": str(path), "exists": path.exists()}
        if path.exists():
            item["sha256"] = _sha256_path(path)
            item["evidence_kind"] = "pinned_disk_localisation_read_only"
        localization_evidence.append(item)

    report = {
        "schema": "information.trade_state.steering_direction_source.v1",
        "report_id": "information-trade-steering-direction-source-001",
        "batch": 48,
        "stage": "information-trade-merchant-task-20261027-001",
        "generated_on": "2026-10-27",
        "status": "partial_native_ui_relation_path; trade_node_direction_unresolved",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "scope": {
            "topic_id": "T05",
            "field": "steering_direction",
            "question": "Find the native UI source that chooses a steering/outgoing direction and bind any selected item to the stable trade definition node_id.",
            "scope_boundary": "Relation-list UI and one small merchant-route predicate only; B59550 callers and STEER_NO_TRADER path are reused, not decoded.",
            "no_game": True,
            "no_rpm": True,
            "no_rea": True,
            "no_native_function_execution": True,
            "no_production_changes": True,
        },
        "target": {
            "game_version": "1.37.4",
            "exe_path": str(exe),
            "exe_sha256": exe_sha,
            "image_base_va": hex(IMAGE_BASE),
            "address_rule": "RVA and VA are separate; VA=image_base_va+RVA; ranges are half-open",
        },
        "decoder": {
            "name": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -d -w -Mintel",
            "decoded_bytes": total,
            "decoded_instruction_count": sum(len(rows) for rows in decoded.values()),
            "single_decode_limit_bytes": MAX_SINGLE_DECODE,
            "total_decode_limit_bytes": MAX_TOTAL_DECODE,
        },
        "decoded_code_ranges": ranges,
        "selected_instructions": selected,
        "native_literals": {
            name: _literal(pe, rva, name) for rva, name in LITERALS.items()
        },
        "prior_evidence": [
            _prior(prior_trade_state, "Batch-43 merchant-state labels and unresolved steering status contract"),
            _prior(prior_modifiers, "Batch-46 packed country/fullref resolver 0x2892D0 and TO/FROM detail contract"),
            _prior(prior_key, "stable trade definition ASCII node_id at definition+0x10"),
            _prior(prior_corrob, "runtime/static one-to-one corroboration of the 80 trade node keys and locations"),
            _prior(prior_direction_tail, "Batch-46 native TO/FROM source-index; reused as separate evidence"),
        ],
        "localization_evidence": localization_evidence,
        "findings": {
            "relation_list_ui": {
                "status": "closed_as_country_relation_list_source; not_trade_node_direction",
                "function": {
                    "rva_exclusive": ["0x10cc1c0", "0x10cf793"],
                    "va_exclusive": ["0x1410cc1c0", "0x1410cf793"],
                    "pdata_boundary": "the selected windows are partial slices of this larger function",
                },
                "labels": {
                    "to": {
                        "label_rva": "0x1c5d658",
                        "label": "STEERING_TRADE_TO_LIST",
                        "callsite_rva": "0x10ce352",
                        "meaning_from_literal": "native relation label with a $LIST$ substitution; no node-id claim",
                    },
                    "from": {
                        "label_rva": "0x1c5d670",
                        "label": "TRADE_STEERED_FROM_LIST",
                        "callsite_rva": "0x10ce4b6",
                        "meaning_from_literal": "native relation label with a $LIST$ substitution; no node-id claim",
                    },
                    "list_placeholder": {
                        "rva": "0x1c44d1c",
                        "text": "LIST",
                        "callsite_rvas": ["0x10ce34b", "0x10ce4af"],
                    },
                },
                "vector_selection": {
                    "initial_vector": "QWORD [r15+0x48] is treated as a begin/end pointer-vector object",
                    "scan": "begin=[r15+0x48], end=[r15+0x50], stride=8; each packed QWORD has its high 16 bits compared with RDI>>32",
                    "alternate_vector": "on a high16 match, R12 is changed to &r15+0x78; otherwise the +0x48 vector remains selected",
                    "rvas": ["0x10ccee7", "0x10cceeb", "0x10ccef0", "0x10ccf00", "0x10ccf07", "0x10ccf18"],
                    "selection_semantics": "static list selection is closed; the meaning of the packed selector is not renamed as a direction enum",
                },
                "element_to_text": {
                    "vector_iteration": "R12 is replaced by begin=[R12]; end is read before the loop and count is (end-begin)/8",
                    "element_rva": "0x10cd34c loads QWORD [R12] and 0x10cd3a4 advances R12 by 8",
                    "resolver_call": {
                        "callsite_rva": "0x10cd369",
                        "target_rva": "0x2892d0",
                        "arguments": "RCX=&local packed QWORD; RDX=R8=R9=0",
                        "result_use": "the caller reads the returned string-like object at +0x10/+0x18 and appends its bytes",
                    },
                    "identity_boundary": "Prior bounded 0x2892D0 evidence reads high16(element) as a signed country-table slot and resolves a country object/string path. It does not read trade definition+0x10.",
                    "safe_conclusion": "The two relation labels enumerate packed country/fullref-derived display items. They are not sufficient to expose a selected outgoing trade-node node_id.",
                },
                "ui_sink": {
                    "to_callsite_rva": "0x10ce3fc",
                    "from_callsite_rva": "0x10ce560",
                    "effect": "both paths pass the built string to an indirect UI sink at [vtable+0x260]",
                    "direction_value": "no scalar direction, selected definition pointer, or definition+0x10 key is returned by this path",
                },
            },
            "merchant_route_predicate_candidate": {
                "status": "candidate_boolean_only; not_closed_as_steering_direction",
                "function": {
                    "rva_exclusive": ["0x352100", "0x3521a9"],
                    "va_exclusive": ["0x140352100", "0x1403521a9"],
                    "pdata_exact": True,
                },
                "abi_from_callsite": {
                    "callsite_rva": "0x353fa6",
                    "rcx": "R15",
                    "rdx": "R13",
                    "r8": "&[RBP+0xa8], initialized to 1000 at 0x353f8f",
                    "return": "AL is tested at 0x353fab; true branches to 0x35422e, false continues the alternate UI path",
                },
                "predicate": {
                    "direct_true": "[R15+0x14b0]+0xe8 == [R13+0xe8] returns AL=1",
                    "fallback": "otherwise reads a signed cache value through 0x350400, scales it with the output DWORD, calls 0x3526e0, and compares the returned DWORD with the normalized quotient",
                    "true_condition": "[result_from_0x3526e0] <= normalized quotient returns AL=1; otherwise AL=0",
                    "unknown_callees": ["0x350400", "0x3526e0"],
                },
                "safe_conclusion": "This is a boolean merchant-route/UI predicate with an amount scratch output. It has no direction enum, no outgoing-node key, and no visible definition+0x10 edge; do not map AL to to/from or to a node_id.",
            },
        },
        "stable_node_id_contract": {
            "prior_static_source": "definition+0x10 std::string-like ASCII key; bounded getter 0x9a920",
            "prior_runtime_static_correspondence": "80 true-predicate runtime node keys and centers match the 80 resolved static trade definitions; Null/0x8f450 is excluded",
            "current_path_edge": "not_found: relation list goes through packed country/fullref resolver 0x2892d0, not a trade-definition key getter",
            "public_mapping": None,
        },
        "unresolved_conditions": [
            "The actual T05 steering choice (direction enum or selected outgoing trade-node edge) is not closed in these bounded windows.",
            "The relation list's packed country/fullref elements are not interchangeable with trade-node definition keys; no conversion from country relation item to node_id is proven.",
            "The 0x352100 boolean depends on 0x350400 and 0x3526e0; their cache semantics, direction meaning, and selected-node identity remain unknown.",
            "TRADEMAP_OUTGOING/OUTGOING_* strings have no direct code xref in the bounded scan, so no GUI outgoing formatter is claimed.",
            "No runtime value, freshness, GUI pointer identity, native call, save/restart, or game action is claimed.",
        ],
        "recommended_next_entry": {
            "condition": "Only if T05 must expose the actual selected outgoing node rather than the already available static outgoing edges",
            "bounded_target": "Find a caller that writes/reads the trade-node route list or selected edge and passes a trade definition pointer (definition+0x10) into a formatter; avoid country relation vectors +0x48/+0x78.",
            "do_not_repeat": ["B59550 caller set", "STEER_NO_TRADER path", "0x2892D0 full body already in source-modifiers-002"],
        },
        "verification": {
            "script": _relative(Path(__file__)),
            "json_written_exclusively": True,
            "game_access": False,
            "rpm_used": False,
            "rea_access": False,
            "native_function_execution": False,
            "production_files_changed": False,
            "old_reports_overwritten": False,
            "active_shells": 0,
            "resource_limits": {
                "single_decode_bytes": MAX_SINGLE_DECODE,
                "total_decode_bytes": total,
                "process_memory": "ordinary bounded PE helper; no whole-image disassembly",
            },
        },
    }
    return report


def main() -> int:
    if OUTPUT.exists():
        raise SystemExit("refusing_to_overwrite_output")
    report = build_report()
    STAGE.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "output": _relative(OUTPUT),
        "sha256": _sha256_path(OUTPUT),
        "output_bytes": OUTPUT.stat().st_size,
        "decoded_bytes": report["decoder"]["decoded_bytes"],
        "decoded_instructions": report["decoder"]["decoded_instruction_count"],
        "active_shells": 0,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
