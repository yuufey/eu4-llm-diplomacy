"""Pin the bounded static contract for T02.home_node.

Only the selected-country/fullref producer, the B58C40 leaf, its caller, and
the two transit-node localisation branches are read.  This is ordinary PE and
on-disk localisation evidence only: the script does not open the game, use
RPM/REA, or modify a bridge/profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe, game_root
from work.research_information_branch_inputs import _decode_range


EXPECTED_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_RANGE_BYTES = 8 * 1024
MAX_TOTAL_DECODE_BYTES = 8 * 1024

CODE_RANGES = (
    (0x763840, 0x763870, "selected_fullref_getter"),
    (0xB58C40, 0xB58C61, "ad_leaf"),
    (0x13D40CC, 0x13D4180, "selected_country_home_label_caller"),
)

BYTE_GUARDS = {
    0x763840: "80b9661e000007751780b96f1e000000740e488b81681e0000488902488bc2c3488b81601e0000488902488bc2c3",
    0xB58C40: "48c1ea20480fbfc2488d144048c1e2064803511874080fb682ad000000c332c0c3",
    0x13D40CC: "4c8b0585bdf600498bc8e865f738ff488b08488b05cb97f60048c1e920480fbfc9488b8018010000488b1cc8498b85f8000000488b88a8000000486381dc0000004869d0102e0000490390a81c0000c644242800c64424200141b1014c8d45a0488bcbe8bcf1f7fe84c0747e488b5320498b8df8000000e8f84a78ff4533c94533c0488d4c245884c0488d151cbb97007407488d15abbb9700e836f20d00488d542458488d4dc0e8b80dccfe488d4c2458e8de14",
}

CALLSITE_GUARDS = {
    0x13D40D6: "e865f738ff",  # selected fullref getter
    0x13D4143: "e8f84a78ff",  # B58C40
    0x13D415C: "7407",  # AD == 0 selects normal node label
    0x13D415E: "488d15abbb9700",  # AD != 0 selects capital/home label
}

LOCALISATION_KEYS = (
    "STEER_HOME",
    "TRADE_TRANSIT_NODE",
    "TRADE_TRANSIT_NODE_DESC",
    "TRADE_TRANSIT_NODE_CAPITAL",
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _va(rva: int) -> str:
    return hex(IMAGE_BASE + rva)


def _read_localisation(path: Path):
    if not path.exists():
        raise FileNotFoundError(path)
    hits = []
    wanted = set(LOCALISATION_KEYS)
    # Stream the text; do not load the whole installation localisation tree.
    with path.open("rb") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            text = raw_line.decode("utf-8", errors="strict").rstrip("\r\n")
            match = re.match(r"^\s*([A-Z0-9_]+):0\s+(.*)$", text)
            if match and match.group(1) in wanted:
                hits.append({
                    "key": match.group(1),
                    "line": line_number,
                    "raw_utf8": text,
                    "raw_line_hex": raw_line.hex(),
                })
    if {item["key"] for item in hits} != wanted:
        raise AssertionError("required trade-node localisation keys are incomplete")
    return {
        "path": str(path),
        "relative_to_game_root": path.relative_to(game_root()).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": _sha_file(path),
        "language": "l_english",
        "matched_entries": hits,
        "read_mode": "bounded_key_match_stream",
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
        "bytes_sha256": _sha(raw),
        "pdata_function_boundary":
            [hex(function[0]), hex(function[1])] if function else None,
        "decoded_instruction_count": len(rows),
    }


def _selected(rows, addresses):
    table = {int(row["rva"], 16): row for row in rows}
    return [table[address] for address in addresses if address in table]


def build_report():
    pe = PE(game_exe())
    binary_sha256 = _sha(pe.data)
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

    for rva, expected in BYTE_GUARDS.items():
        actual = pe.bytes_at(rva, len(expected) // 2).hex()
        if actual != expected:
            raise AssertionError(f"byte guard changed at {rva:#x}")
    for rva, expected in CALLSITE_GUARDS.items():
        actual = pe.bytes_at(rva, len(expected) // 2).hex()
        if actual != expected:
            raise AssertionError(f"callsite guard changed at {rva:#x}")

    selected_instructions = {
        "selected_fullref_getter": _selected(
            decoded["selected_fullref_getter"],
            (0x763840, 0x763849, 0x763852, 0x763860, 0x763867),
        ),
        "ad_leaf": _selected(
            decoded["ad_leaf"],
            (0xB58C40, 0xB58C44, 0xB58C50, 0xB58C56, 0xB58C5E),
        ),
        "selected_country_home_label_caller": _selected(
            decoded["selected_country_home_label_caller"],
            (0x13D40CC, 0x13D40D6, 0x13D40DB, 0x13D40DE,
             0x13D40F8, 0x13D4106, 0x13D4114, 0x13D4138,
             0x13D4143, 0x13D4153, 0x13D4155, 0x13D415C,
             0x13D415E, 0x13D4165),
        ),
    }

    localisation_path = game_root() / "localisation" / "tradenodes_l_english.yml"
    localisation = _read_localisation(localisation_path)

    report = {
        "schema": "information.trade_state.home_node_source.v1",
        "stage": "information-trade-state-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_plus_on_disk_localisation",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; ranges end exclusive",
        },
        "scope": {
            "field": "T02.home_node",
            "entry_flag": "entry+0xAD",
            "runtime_entry_layout": "selected country object +0x20 packed fullref; B58C40 uses signed high-16 slot and table +0x18 with stride 0xC0",
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
        "byte_guards": [
            {"rva": hex(rva), "va": _va(rva), "bytes_hex": value,
             "bytes_sha256": _sha(bytes.fromhex(value))}
            for rva, value in BYTE_GUARDS.items()
        ],
        "callsite_guards": [
            {"rva": hex(rva), "va": _va(rva), "bytes_hex": value,
             "bytes_sha256": _sha(bytes.fromhex(value))}
            for rva, value in CALLSITE_GUARDS.items()
        ],
        "selected_instructions": selected_instructions,
        "localisation": localisation,
        "findings": {
            "selected_country_fullref": {
                "status": "static_closed_for_input_chain",
                "getter_rva": "0x763840",
                "getter_va": _va(0x763840),
                "selection": [
                    "At caller 0x13D40CC, global 0x14233FE58 is passed to 0x763840.",
                    "0x763840 returns game+0x1E68 when byte +0x1E66 == 7 and byte +0x1E6F != 0; otherwise it returns game+0x1E60.",
                    "The returned packed fullref is loaded at 0x13D40DB; its signed high-16 slot indexes [module+0x233D8B0]+0x118 to obtain the selected object rbx.",
                    "That object’s +0x20 packed fullref is the rdx input at 0x13D4138 immediately before B58C40.",
                ],
                "cxx_names": "not claimed; the register/offset chain is the static contract",
            },
            "ad_leaf": {
                "status": "static_closed",
                "rva_range": ["0xb58c40", "0xb58c61"],
                "behavior": "rdx >>= 32; signed int16 slot; entry=[rcx+0x18]+slot*0xC0; return entry ? byte entry+0xAD : 0",
                "returned_domain": "boolean byte, no enum conversion",
            },
            "caller_branch": {
                "status": "static_closed",
                "caller_rva": "0x13d40cc",
                "b58c40_callsite_rva": "0x13d4143",
                "branch": "test AL; zero -> TRADE_TRANSIT_NODE; nonzero -> TRADE_TRANSIT_NODE_CAPITAL",
                "normal_key_rva": "0x1d4fc78",
                "capital_key_rva": "0x1d4fd10",
            },
            "home_node_semantics": {
                "status": "supported_with_runtime_uniqueness_guard",
                "localisation_evidence": {
                    "TRADE_TRANSIT_NODE": "Send Merchant to Transfer Trade Power.",
                    "TRADE_TRANSIT_NODE_CAPITAL": "Your home node is permanently Collecting from Trade, you can't Transfer Trade Power from it.",
                    "STEER_HOME": "You can't steer where you Collect from Trade.",
                },
                "meaning": "AD==1 is a static/native-supported home or capital trade-node display branch for the selected country object; AD==0 is the ordinary transit-node branch.",
                "reader_contract": "Scan all verified real definitions for the selected country and accept home_node only when exactly one entry has AD!=0. Zero or multiple true entries remain unknown/unavailable; never choose an arbitrary node.",
                "scope_limit": "The static caller proves the selected-country input and branch meaning, but does not prove runtime uniqueness for every save.",
            },
        },
        "unresolved_conditions": [
            "The native C++ field name for +0xAD is not claimed; only its leaf and localization branch are pinned.",
            "A runtime reader must independently verify the selected country identity, all real node definitions, static guards, and exactly-one AD!=0 before publishing home_node.",
            "The branch proves the home-node display distinction, not a complete merchant-task/collection/transfer API.",
        ],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work/runtime/information-trade-state-20261027-001/home-node-source-001.json",
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
