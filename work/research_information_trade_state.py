"""Produce the bounded stage-43 native trade-state contract.

This is an ordinary PE-only study.  It decodes only the explicit RVA windows
below and never opens the game, calls RPM/REA, or writes a production profile.
The live FRA artifact is listed as a separate runtime-corroboration source; it
is not used as static evidence and is not read from a process by this script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXPECTED_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_RANGE_BYTES = 8 * 1024
MAX_TOTAL_DECODE_BYTES = 32 * 1024

# These are all bounded, explicit windows.  The larger windows are complete
# pdata functions only where they are needed to follow the label/status uses.
CODE_RANGES = (
    (0xB58A80, 0xB58B30, "entry_gate_b58a80"),
    (0xB58B30, 0xB58C40, "entry_field_filter_b58b30"),
    (0xB58C40, 0xB58C61, "ad_getter_b58c40"),
    (0xB58C70, 0xB58CD0, "eligibility_predicate_b58c70"),
    (0xB58CD0, 0xB58CFA, "income_copy_b58cd0"),
    (0xB5B100, 0xB5B318, "steering_status_b5b100"),
    (0xB5BE80, 0xB5C2EC, "steering_status_b5be80"),
    (0xB59260, 0xB59546, "status_caller_b59260"),
    (0x13D40F0, 0x13D4190, "transit_label_caller"),
    (0xEB96F1, 0xEB97A7, "budget_income_caller"),
)

CALLSITE_GUARDS = {
    0xB5B119: "e852dbffff",  # B5B100 -> B58C70
    0xB5BEA7: "e8c4cdffff",  # B5BE80 -> B58C70
    0xB5941C: "e84ff8ffff",  # B59260 -> B58C70
    0x13D4143: "e8f84a78ff",  # transit label caller -> B58C40
    0xEB971B: "e850f5c9ff",  # budget trade list -> B58C70
    0xEB979B: "e830f5c9ff",  # budget trade list -> B58CD0
}

TARGET_BYTES = {
    0xB58C70: (
        "488b4918488bc248c1e820480fbfc048c1ea204c8d04400fbfc249c1e006"
        "4903c83b05214c7e0175054885c9752c32d23891ae00000074100fb681ac"
        "00000084c00f95c284c074124885c9741080b9ad00000000740784d27503b0"
        "01c332c0c3"
    ),
    0xB58CD0: (
        "49c1e820490fbfc04c8d044049c1e0064c034118740a418b40348902488bc2"
        "c3c70200000000488bc2c3"
    ),
}

STRING_RANGES = {
    0x1CE8ED0: "STEER_NO_POWER",
    0x1CE8EE0: "STEER_LATER",
    0x1CE8F30: "STEER_HOME",
    0x1CE8F40: "STEER_NO_TRADER",
    0x1D4FC78: "TRADE_TRANSIT_NODE",
    0x1D4FD10: "TRADE_TRANSIT_NODE_CAPITAL",
}


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _va(rva: int) -> str:
    return hex(IMAGE_BASE + rva)


def _instruction_map(rows):
    return {int(row["rva"], 16): row for row in rows}


def _cstring(pe: PE, rva: int, expected: str):
    raw = bytearray()
    for offset in range(512):
        byte = pe.bytes_at(rva + offset, 1)
        if not byte:
            break
        raw.extend(byte)
        if byte == b"\0":
            break
    if bytes(raw) != expected.encode("ascii") + b"\0":
        raise AssertionError(
            f"literal mismatch at {rva:#x}: {bytes(raw)!r} != {expected!r}"
        )
    return {
        "rva": hex(rva),
        "va": _va(rva),
        "string": expected,
        "bytes_hex": bytes(raw).hex(),
        "bytes_sha256": _sha_bytes(bytes(raw)),
    }


def _range_record(pe: PE, rows, begin: int, end: int, label: str):
    raw = pe.bytes_at(begin, end - begin)
    function = pe.function(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": _va(begin),
        "end_va_exclusive": _va(end),
        "byte_length": len(raw),
        "bytes_sha256": _sha_bytes(raw),
        "pdata_function_boundary":
            [hex(function[0]), hex(function[1])] if function else None,
        "decoded_instruction_count": len(rows),
    }


def build_report():
    pe = PE(game_exe())
    binary_sha256 = _sha_bytes(pe.data)
    if binary_sha256 != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {binary_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded = {}
    ranges = []
    total = 0
    for begin, end, label in CODE_RANGES:
        if end <= begin or end - begin > MAX_RANGE_BYTES:
            raise AssertionError(f"range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total decode limit failure")
        rows = _decode_range(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    for rva, expected in TARGET_BYTES.items():
        actual = pe.bytes_at(rva, len(expected) // 2).hex()
        if actual != expected:
            raise AssertionError(f"target bytes changed at {rva:#x}")
    for rva, expected in CALLSITE_GUARDS.items():
        actual = pe.bytes_at(rva, len(expected) // 2).hex()
        if actual != expected:
            raise AssertionError(f"callsite bytes changed at {rva:#x}")

    selected = []
    for rva, expected in TARGET_BYTES.items():
        selected.append({
            "role": "target_function",
            "rva": hex(rva),
            "va": _va(rva),
            "bytes_hex": expected,
            "bytes_sha256": _sha_bytes(bytes.fromhex(expected)),
        })
    for rva, expected in CALLSITE_GUARDS.items():
        selected.append({
            "role": "direct_callsite",
            "rva": hex(rva),
            "va": _va(rva),
            "bytes_hex": expected,
            "bytes_sha256": _sha_bytes(bytes.fromhex(expected)),
        })

    # Keep a compact disassembly excerpt at every flag read/callsite that is
    # used by the findings.  The full bounded byte digest above remains the
    # guard for the surrounding windows.
    excerpt_addresses = {
        "entry_gate_b58a80": (0xB58AA2, 0xB58AB4, 0xB58AC0),
        "entry_field_filter_b58b30": (0xB58B55, 0xB58B5E, 0xB58B67, 0xB58BB0),
        "ad_getter_b58c40": (0xB58C40, 0xB58C4B, 0xB58C58),
        "eligibility_predicate_b58c70": (0xB58C70, 0xB58C90, 0xB58CA4, 0xB58CB6),
        "income_copy_b58cd0": (0xB58CD0, 0xB58CEB, 0xB58CF0),
        "steering_status_b5b100": (0xB5B119, 0xB5B1F0, 0xB5B2A0),
        "steering_status_b5be80": (0xB5BEA7, 0xB5C0D7, 0xB5C1A0),
        "status_caller_b59260": (0xB5941C, 0xB59320),
        "transit_label_caller": (0x13D4143, 0x13D415E, 0x13D4165),
        "budget_income_caller": (0xEB971B, 0xEB979B, 0xEB97A3),
    }
    selected_instructions = {}
    for label, addresses in excerpt_addresses.items():
        mapping = _instruction_map(decoded[label])
        selected_instructions[label] = [
            mapping[address] for address in addresses if address in mapping
        ]

    literals = [_cstring(pe, rva, value) for rva, value in STRING_RANGES.items()]

    runtime_path = ROOT / "work/runtime/information-trade-state-20261027-001/native-trade-state-inputs-001.json"
    runtime = {
        "path": runtime_path.relative_to(ROOT).as_posix(),
        "sha256": _sha_file(runtime_path) if runtime_path.exists() else None,
        "evidence_kind": "independent_runtime_observation_not_static_evidence",
        "used_by_this_script": False,
        "identity_date_session": "fresh stage43 artifact supplied by root; FRA/PID31460/date56557728",
        "observed_examples": [
            {"node_id": "champagne", "flags_ac_ad_ae_hex": "000101", "income_raw": 3813},
            {"node_id": "rheinland", "flags_ac_ad_ae_hex": "010001", "income_raw": 0},
        ],
        "limitation": "The raw snapshot corroborates bytes/flag order only; it does not label AC/AD/AE or prove merchant_task values.",
    }

    report = {
        "schema": "information.trade_state.merchant_task_source.v1",
        "stage": "information-trade-state-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; ranges end exclusive",
        },
        "scope": {
            "question": "entry flags +0xAC/+0xAD/+0xAE and T05 merchant_task/collection/transfer",
            "runtime_entry_layout": "country+0x18 table; signed country slot * 0xC0; flags at entry+0xAC..+0xAE",
            "no_game_or_production_access": True,
        },
        "analysis": {
            "decoder": (
                "capstone " + capstone.__version__
                if capstone is not None else "bounded objdump -w -Mintel"
            ),
            "decoded_bytes": total,
            "limits": {
                "single_code_range_bytes": MAX_RANGE_BYTES,
                "total_code_decode_bytes": MAX_TOTAL_DECODE_BYTES,
                "runtime_process_opened": False,
                "rpm_used": False,
                "rea_used": False,
                "production_written": False,
            },
        },
        "ranges": ranges,
        "selected_instructions": selected_instructions,
        "target_and_callsite_guards": selected,
        "string_literals": literals,
        "runtime_corroboration": runtime,
        "findings": {
            "AC": {
                "status": "not_closed",
                "static_evidence": "B58C70 reads byte [entry+0xAC] as part of a boolean eligibility predicate; no bounded getter, enum conversion, or collect/transfer label consumes it directly.",
                "runtime_evidence": "The fresh snapshot reports the raw byte only; its value is not semantically labelled.",
                "public_mapping": None,
            },
            "AD": {
                "status": "partial",
                "static_evidence": "B58C40 returns byte [entry+0xAD]. Its only bounded caller chooses TRADE_TRANSIT_NODE versus TRADE_TRANSIT_NODE_CAPITAL. This supports a capital/home transit-node display discriminator, while the exact native field name and task domain remain unresolved.",
                "runtime_evidence": "Raw AC/AD/AE bytes are corroborated but not decoded as a task.",
                "public_mapping": None,
            },
            "AE": {
                "status": "partial",
                "static_evidence": "B58A80/B58B30 gate entry use on [entry+0xAE], and B5B100/B5BE80 status paths also test it. The bounded paths emit steering status strings, never a merchant-task enum.",
                "runtime_evidence": "Raw AE bytes are corroborated only.",
                "public_mapping": None,
            },
            "merchant_task": {
                "status": "unknown",
                "supported_values": ["collect", "transfer", "none"],
                "reason": "No direct enum/string or complete native getter for collect/transfer/none was found in the bounded B58Axx..B5C2xx and UI windows. B58C70 returns a bool used for eligibility/steering status, so it must not be exposed as a three-valued task.",
            },
            "collection": {
                "status": "not_proven",
                "reason": "No direct collection amount/state getter or label was closed; do not infer it from AC/AD/AE.",
            },
            "transfer": {
                "status": "not_proven",
                "reason": "No direct transfer relation/state getter was closed; catalog transfer must not be mapped to an AC/AD/AE boolean.",
            },
            "steering_direction": {
                "status": "partial",
                "labels": ["STEER_HOME", "STEER_NO_TRADER", "STEER_NO_POWER", "STEER_LATER"],
                "reason": "These are native trade-steering/status strings reached around B58C70, not a complete public direction contract.",
            },
            "income": {
                "status": "closed_for_existing_T05_component",
                "producer_rva": "0xb58cd0",
                "producer_va": _va(0xB58CD0),
                "semantics": "B58CD0 copies signed dword entry+0x34; EB7B20 applies B58C70 and adds the copied contribution to the existing trade-income view.",
                "not_a_merchant_task_proof": True,
            },
        },
        "unresolved_conditions": [
            "The bounded evidence does not identify AC/AD/AE C++ field names or prove that any one is collect, transfer, or none.",
            "The outer definition predicate and country-slot reader are separate from these flags; this report does not expand their previously archived contracts.",
            "Runtime observations are two-pass raw bytes and are not an atomic snapshot or a fresh cache refresh.",
            "A future task-specific producer/serializer must be found before exposing merchant_task, collection, or transfer.",
        ],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json",
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output = output.resolve()
    if output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    report = build_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "output": output.relative_to(ROOT).as_posix(),
        "sha256": _sha_file(output),
        "bytes": output.stat().st_size,
        "decoded_bytes": report["analysis"]["decoded_bytes"],
        "range_count": len(report["ranges"]),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
