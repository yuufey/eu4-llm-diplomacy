"""Close the static source contract for ``TRADE_POWER_CAPITAL``.

This Batch-46 report reuses the bounded Batch-45 source and formatter
evidence, and decodes only the capital-row caller context in the already
identified B57700 function.  It does not start the game, use RPM/REA, or
change production code.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-source-details-20261027-001"
OUTPUT = STAGE / "capital-source-001.json"
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
MAX_SINGLE_RANGE = 8 * 1024
MAX_TOTAL_DECODE = 16 * 1024

# The range starts at an instruction boundary in the same pdata function and
# includes enough preceding context to make the capital chain and its only
# branch observable.  The capital-specific selected instructions begin at
# B579A3.
CAPITAL_CONTEXT_WINDOW = (0xB57960, 0xB57A1D)
CAPITAL_CHAIN_START = 0xB579A3
CAPITAL_CHAIN_END = 0xB57A1D
CAPITAL_SELECTED_RVAS = (
    0xB579A3,
    0xB579AA,
    0xB579B2,
    0xB579B9,
    0xB579C0,
    0xB579C4,
    0xB579CB,
    0xB579D2,
    0xB579D8,
    0xB579DE,
    0xB579E4,
    0xB579E9,
    0xB579EC,
    0xB579F2,
    0xB579F9,
    0xB579FD,
    0xB57A03,
    0xB57A06,
    0xB57A0D,
    0xB57A14,
    0xB57A18,
)

LOCALIZATION_LINES = (10, 11, 26, 37, 78, 79, 110, 117)


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


def _display_path(path: Path) -> str:
    try:
        return _relative(path)
    except ValueError:
        return str(path)


def _localization_evidence(path: Path) -> dict:
    lines: dict[str, dict] = {}
    wanted = set(LOCALIZATION_LINES)
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for number, line in enumerate(stream, 1):
            if number not in wanted:
                continue
            text = line.rstrip("\r\n")
            encoded = text.encode("utf-8")
            lines[str(number)] = {
                "line": number,
                "text": text,
                "bytes_hex": encoded.hex(),
                "sha256": _sha256_bytes(encoded),
            }
    missing = sorted(wanted - {int(k) for k in lines})
    if missing:
        raise AssertionError(f"missing localization lines: {missing}")
    return {
        "path": _display_path(path),
        "sha256": _sha256_path(path),
        "encoding": "utf-8-sig text; line hashes cover exact text without the line ending",
        "lines": lines,
    }


def _range_record(pe: PE, rows: list[dict], begin: int, end: int) -> dict:
    raw = pe.bytes_at(begin, end - begin)
    pdata = pe.function(begin)
    if pdata is None or pe.function(end - 1) is None:
        raise AssertionError(f"capital window must be covered by pdata: {pdata}")
    return {
        "name": "capital_row_caller_context",
        "rva_exclusive": [hex(begin), hex(end)],
        "va_exclusive": [hex(IMAGE_BASE + begin), hex(IMAGE_BASE + end)],
        "byte_length": len(raw),
        "raw_range_sha256": _sha256_bytes(raw),
        "pdata_function_boundary": [hex(pdata[0]), hex(pdata[1])],
        "pdata_unwind_rva": hex(pdata[2]),
        "decoded_instruction_count": len(rows),
        "address_semantics": "RVA; VA=image_base_va+RVA; end is exclusive",
    }


def _selected(rows: list[dict], addresses: tuple[int, ...]) -> list[dict]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = [hex(address) for address in addresses if address not in by_rva]
    if missing:
        raise AssertionError(f"decoder did not return capital instructions: {missing}")
    return [by_rva[address] for address in addresses]


def build_report() -> dict:
    exe = Path(game_exe())
    pe = PE(exe)
    exe_sha = _sha256_bytes(pe.data)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {exe_sha}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    begin, end = CAPITAL_CONTEXT_WINDOW
    if end <= begin or end - begin > MAX_SINGLE_RANGE:
        raise AssertionError("capital window exceeds single-window bound")
    if not pe.executable(begin) or not pe.executable(end - 1):
        raise AssertionError("capital window is not executable")
    pdata = pe.function(begin)
    if pdata is None or pe.function(end - 1) is None:
        raise AssertionError(f"capital window lacks pdata: {pdata}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    rows = _decode_range(pe, md, begin, end)
    decoded_bytes = end - begin
    if decoded_bytes > MAX_TOTAL_DECODE:
        raise AssertionError(f"total decode limit exceeded: {decoded_bytes}")
    selected = _selected(rows, CAPITAL_SELECTED_RVAS)

    localization_path = exe.parent / "localisation" / "tradenodes_l_english.yml"
    localization = _localization_evidence(localization_path)
    prior_source_001 = ROOT / "work" / "runtime" / "information-trade-share-20261027-001" / "power-sources-source-001.json"
    prior_source_002 = ROOT / "work" / "runtime" / "information-trade-share-20261027-001" / "power-sources-source-002.json"
    if not prior_source_001.is_file() or not prior_source_002.is_file():
        raise AssertionError("Batch-45 source reports are required as input evidence")

    report = {
        "schema": "information.trade_power.capital_source_static.v1",
        "report_id": "information-trade-capital-source-001",
        "batch": 46,
        "stage": "information-trade-source-details-20261027-001",
        "generated_on": "2026-10-27",
        "status": "static_capital_row_contract_closed_runtime_partial",
        "scope": {
            "topic_id": "T04",
            "fields": ["sources", "TRADE_POWER_CAPITAL"],
            "object": "trade_node",
            "question": "Close the TRADE_POWER_CAPITAL selector, identity guard, formatter path, localization semantics, and bounded reader contract.",
            "mode": "ordinary bounded PE plus disk localization and prior bounded formatter evidence",
            "no_game": True,
            "no_runtime_access": True,
            "no_rpm": True,
            "no_rea": True,
            "no_production_changes": True,
            "single_decode_limit_bytes": MAX_SINGLE_RANGE,
            "total_decode_limit_bytes": MAX_TOTAL_DECODE,
        },
        "target": {
            "game_version": "1.37.4",
            "exe_path": str(exe),
            "exe_sha256": exe_sha,
            "image_base_va": hex(IMAGE_BASE),
            "address_rule": "RVA and VA are separate; VA=image_base_va+RVA; ranges are half-open",
        },
        "input_evidence": [
            {
                "path": _relative(prior_source_001),
                "sha256": _sha256_path(prior_source_001),
                "role": "Batch-45 bounded B577 source/ABI report; supplies incoming RCX/R8/fullref context and existing capital-chain observations",
                "evidence_kind": "prior_ordinary_static_report",
            },
            {
                "path": _relative(prior_source_002),
                "sha256": _sha256_path(prior_source_002),
                "role": "Batch-45 bounded formatter proof; supplies signed DWORD and fixed-point 1000 semantics without re-decoding the helper",
                "evidence_kind": "prior_ordinary_static_report",
            },
            {
                "path": localization["path"],
                "sha256": localization["sha256"],
                "role": "English disk localization for the capital row and main-trade-city semantics",
                "evidence_kind": "disk_localization",
                "selected_lines": list(LOCALIZATION_LINES),
            },
        ],
        "decoded_code_ranges": [_range_record(pe, rows, begin, end)],
        "decoder": {
            "name": "capstone " + capstone.__version__ if capstone is not None else "bounded objdump -d -w -Mintel",
            "decoded_bytes": decoded_bytes,
            "decoded_instruction_count": len(rows),
            "selected_instruction_groups": ["capital_selector_and_row_call"],
        },
        "localization": localization,
        "selected_instructions": {
            "capital_selector_and_row_call": selected,
            "capital_chain_rva_exclusive": [hex(CAPITAL_CHAIN_START), hex(CAPITAL_CHAIN_END)],
            "branch_observation": {
                "identity_mismatch_rva": "0xb579d2",
                "identity_mismatch_target_va": hex(IMAGE_BASE + 0xB57ADE),
                "capital_chain_null_tests": [],
                "note": "Within B579A3..B57A18 there is no test/je for the root, vector element, +0x14c8 pointer, or +0xe8 pointer; the only capital-chain conditional is the identity jne.",
            },
        },
        "findings": {
            "incoming_selector_and_identity": {
                "prior_rcx": "B57724 copies incoming RCX to R12; the same R12 is compared at B579CB against QWORD [[selected_country+0x14c8]+0xe8].",
                "prior_r8": "B57721 copies incoming R8 to RBX; B57750..B57758 form slot_i16=sign_extend_i16((R8>>32)&0xffff) for the entry table, and the prior report binds the capital vector index to this same signed slot path.",
                "bounded_direct_caller": "At RVA 0x101ede0..0x101edf0, R8=QWORD [RDI+0x58] then R8=QWORD [R8+0x20], RCX=QWORD [RDI+0x60], and the call enters B57700. This is the observed fullref/node wrapper path; it does not by itself prove the wrapper object is identical to the selected vector country.",
                "fullref_low32": "opaque in the bounded evidence; preserve it and do not infer country identity from the low 32 bits.",
                "entry_context": "The pre-existing node entry table is [incoming_RCX+0x18]+slot_i16*0xc0; this capital caller then performs a separate slot-indexed country-vector lookup.",
            },
            "capital_vector_chain": {
                "database_global_rva": "0x233d8b0",
                "database_global_va": hex(IMAGE_BASE + 0x233D8B0),
                "root_load": "root = QWORD [module+0x233d8b0] (B579A3)",
                "country_table_offset": "0x118",
                "country_table_load": "vector_base = QWORD [root+0x118] (B579B9)",
                "slot_scale": "RSI = RSI*8 (B579AA); prior B577 ABI evidence supplies the signed high-16 slot, while this bounded window proves the scale-8 index operation.",
                "selected_country_load": "selected_country = QWORD [vector_base + slot*8] (B579C0)",
                "country_14c8_load": "identity_object = QWORD [selected_country+0x14c8] (B579C4)",
                "node_identity_load": "native_node = QWORD [identity_object+0xe8] (read by B579CB cmp)",
                "identity_condition": "include the capital row only when native_node == incoming_RCX/R12; JNE B579D2 -> B57ADE skips the row on mismatch.",
                "province_runtime_semantics": "No province-base/runtime fields are loaded in this capital window. The +0x14c8/+0xe8 object chain is proven only as an identity path; its C++ type and province/runtime meaning remain unresolved.",
            },
            "capital_scalar_and_formatter": {
                "scalar_rva": "0x233f2f0",
                "scalar_va": hex(IMAGE_BASE + 0x233F2F0),
                "raw_load": "raw_i32 = DWORD [module+0x233f2f0] loaded into EAX at B579D8, then copied unchanged to [RBP+0xc0].",
                "helper_rva": "0x14bc950",
                "helper_call_arguments": {
                    "rcx": "&[RBP-0x48] destination string object",
                    "rdx": "&[RBP+0xc0] temporary raw DWORD",
                    "r8d": 1,
                    "r9b": 1,
                },
                "formatter_evidence": "Batch-45 source-002 proves helper 0x14bc950 dereferences a signed DWORD and formats the fixed-point value raw/1000; it does not prove the BSS scalar producer or freshness.",
                "unit": "trade_power points",
                "scale": 1000,
                "display_formula": "display_value = signed_i32(raw) / 1000.0",
                "runtime_value": "not observed; module+0x233f2f0 is a runtime scalar and has no file-backed numeric sample in this report",
            },
            "row_builder": {
                "label_key_rva": "0x1ce8b38",
                "label_key_va": hex(IMAGE_BASE + 0x1CE8B38),
                "label_key": "TRADE_POWER_CAPITAL",
                "builder_rva": "0x8ecd0",
                "builder_call": "B57A03..B57A18 passes formatter return in R9, a literal/context pointer in R8, label pointer 0x141ce8b38 in RDX, and destination [RBP-0x28] in RCX to the row builder.",
            },
        },
        "localization_semantics": {
            "row_label": {
                "line": 37,
                "text": localization["lines"]["37"]["text"],
                "meaning": "The disk label calls the row 'Main Trade City in area', so the UI concept is a country's main trade city/trade-collection anchor; it is not evidence that the value is the province capital name.",
            },
            "main_trade_city_context": [
                {
                    "line": 78,
                    "text": localization["lines"]["78"]["text"],
                    "implication": "A node where the country has power but which is not its Main Trade City is a transit node.",
                },
                {
                    "line": 79,
                    "text": localization["lines"]["79"]["text"],
                    "implication": "The game distinguishes collecting in the Main Trade City from collecting elsewhere.",
                },
                {
                    "line": 110,
                    "text": localization["lines"]["110"]["text"],
                    "implication": "The main collection behavior is described separately from the country's capital wording.",
                },
                {
                    "line": 117,
                    "text": localization["lines"]["117"]["text"],
                    "implication": "A home node is permanently collecting and cannot transfer trade power; this is a distinct home-node rule, not proof that the capital row is a province-capital getter.",
                },
            ],
            "related_trade_port_text": {
                "line": 26,
                "text": localization["lines"]["26"]["text"],
                "implication": "The locale uses 'Port' for a separate trade-value source row; this capital key itself says Main Trade City, so do not relabel it as a generic port or province-capital field.",
            },
        },
        "implemented_reader_contract": {
            "topic": "T04.sources",
            "native_key": "TRADE_POWER_CAPITAL",
            "source_kind": "native_trade_node_capital_trade_power_scalar",
            "inputs": [
                "validated trade-node record and its incoming node pointer",
                "validated country/fullref binding from the existing trade reader; the observed B577 caller obtains fullref from [RDI+0x58]+0x20 and node from [RDI+0x60]; fullref low32 remains opaque",
                "module_base",
            ],
            "selector": {
                "slot": "sign_extend_i16((fullref >> 32) & 0xffff), as established by the prior B577 entry-selection evidence",
                "vector_index": "slot * 8",
                "database_global_rva": "0x233d8b0",
                "country_table_offset": "0x118",
            },
            "reads": [
                {"address": "module_base+0x233d8b0", "type": "u64", "role": "database root pointer"},
                {"address": "database_root+0x118", "type": "u64", "role": "country/vector base pointer"},
                {"address": "vector_base+slot*8", "type": "u64", "role": "selected country pointer"},
                {"address": "selected_country+0x14c8", "type": "u64", "role": "identity/province-runtime candidate pointer"},
                {"address": "identity_object+0xe8", "type": "u64", "role": "native trade-node identity"},
                {"address": "module_base+0x233f2f0", "type": "i32", "role": "capital raw scalar"},
            ],
            "guards": [
                "Reject missing or invalid existing country/fullref/node identity before any new read.",
                "Reject slot outside the reader's signed-selector safety range before slot*8 arithmetic.",
                "Reject zero/noncanonical database root, vector base, selected-country, identity-object, and identity-node pointers. The native caller has no explicit null branch in B579A3..B57A18, so a reader must fail closed rather than dereference a null.",
                "Require identity_object+0xe8 == the supplied trade-node pointer; mismatch means omit the row, matching JNE B579D2.",
                "Do not silently equate the B577 direct-call wrapper/fullref holder with the vector-selected country; require an independently validated country identity or report the binding as unknown.",
                "Keep selected-country pointer, fullref, slot, all pointer raw values, scalar raw, and raw_hex bound to the same capture; do not substitute a same-valued pointer from another country.",
            ],
            "row": {
                "key": "TRADE_POWER_CAPITAL",
                "raw": "signed_i32(DWORD [module_base+0x233f2f0])",
                "raw_hex": "two's-complement 32-bit encoding",
                "value": "signed_i32(raw) / 1000.0",
                "unit": "trade_power",
                "scale": 1000,
                "period": "current/native cache period; refresh timing is unknown",
                "condition": "identity_object+0xe8 == supplied trade-node pointer",
                "localization": "Main Trade City in area: $VAL$",
                "value_origin": "native runtime global scalar, copied into the native formatter slot",
            },
            "new_rpm_offset_identity_checklist": [
                "existing country+0x20 fullref binding and signed high-16 slot (reuse existing trade reader; do not hard-code a slot)",
                "module+0x233d8b0 -> root+0x118 -> vector_base+slot*8 selected-country",
                "selected-country+0x14c8 -> identity-object+0xe8 node identity",
                "module+0x233f2f0 signed DWORD raw scalar",
                "code/profile guard for the B579A3..B57A18 selector and formatter caller if this is promoted to production",
            ],
        },
        "unknowns": [
            "The vector's capacity/count, native C++ element type, ownership, and producer are not closed by this caller window.",
            "The +0x14c8 target's exact province/runtime type and update path are unresolved; the static evidence proves only the +0xe8 identity comparison.",
            "The runtime value, refresh timing, and sign distribution of global RVA 0x233f2f0 are not observed here; the formatter proves signed fixed-point display semantics only.",
            "The low 32 bits of the fullref and the incoming R9 caller meaning remain opaque; no country identity may be inferred from either.",
            "The literal/context pointer passed in R8 to the row builder is not decoded; it is not needed to establish raw value, label, condition, or scale.",
            "Localization establishes Main Trade City/trade-collection semantics, but does not prove a one-to-one mapping to a province capital or a separate 'main trade port' getter.",
        ],
        "verification": {
            "script": _relative(Path(__file__)),
            "all_shell_work_completed": True,
            "game_access": False,
            "rpm_used": False,
            "rea_access": False,
            "production_written": False,
            "old_stage_files_untouched": True,
            "resource_limits": {
                "capital_context_window_bytes": decoded_bytes,
                "single_window_limit_bytes": MAX_SINGLE_RANGE,
                "total_decode_bytes": decoded_bytes,
                "total_decode_limit_bytes": MAX_TOTAL_DECODE,
                "process_memory_policy": "bounded decoder only; no whole-image disassembly",
            },
        },
    }
    return report


def main() -> int:
    report = build_report()
    STAGE.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": _relative(OUTPUT),
        "sha256": _sha256_path(OUTPUT),
        "decoded_bytes": report["decoder"]["decoded_bytes"],
        "decoded_instruction_count": report["decoder"]["decoded_instruction_count"],
        "decoder": report["decoder"]["name"],
        "capital_scalar_rva": report["findings"]["capital_scalar_and_formatter"]["scalar_rva"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
