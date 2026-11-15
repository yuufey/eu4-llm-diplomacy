"""Retained static message-selection, formatting and entry-boundary ledger.

This consumes bounded selected evidence.  The 16-byte PE entry window is
ordinary file evidence.  No REA query, hook installation or game call occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
from pathlib import Path

from work.probe_information_message_vtable import (
    DEFAULT_EXE, EXPECTED_EXE_SHA256, IMAGE_BASE, _parse_pe,
    _rva_to_file_offset, _sha256_file, _pdata_rows,
)

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-fragments-20261025-001"
PREVIOUS = ROOT / "work/runtime/information-battle-message-20261025-001"
QUERIES = {
    "setting": ("rea-message-setting-001", 0x8C1BA0),
    "membership": ("rea-message-membership-001", 0x84C0B0),
    "format": ("rea-localized-format-001", 0x14B33A0),
}


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": _sha256_file(path)}


def excerpt(lines: list[str], needle: str, before: int, after: int) -> dict:
    indexes = [i for i, text in enumerate(lines) if needle in text]
    if len(indexes) != 1:
        raise ValueError(f"anchor {needle!r}: {len(indexes)}")
    index = indexes[0]
    start, end = max(0, index - before), min(len(lines), index + after + 1)
    return {"line_start": start + 1, "line_end": end,
            "anchor": needle, "lines": lines[start:end]}


def build() -> dict:
    sources, values = {}, {}
    for label, (directory, rva) in QUERIES.items():
        path = STAGE / directory / "selected-evidence-001.json"
        assert path.stat().st_size <= 2 * 1024 * 1024
        data = json.loads(path.read_text(encoding="utf-8"))
        value = data["raw_result_value"]
        procedure = value["procedure"]["value"]
        assert int(procedure["address"], 0) == IMAGE_BASE + rva
        body = procedure["body"]
        assert sum(int(row["end"], 0) - int(row["start"], 0) + 1
                   for row in body["ranges"]) == body["total_bytes"]
        values[label] = value
        sources[label] = {
            "selected": pin(path), "rva": hex(rva),
            "evidence_id": data["top_level"]["evidence_id"]["value"],
            "body_inclusive": body,
            "runtime_receipt_present": (path.parent / "run.json").is_file(),
        }
    entry_path = PREVIOUS / "rea-result-delivery-001/evidence.json"
    assert entry_path.stat().st_size <= 2 * 1024 * 1024
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    assert entry["subject"]["digest"]["sha256"] == EXPECTED_EXE_SHA256
    entry_value = entry["raw_result"]["value"]
    assert entry_value == entry["normalized_result"]
    sources["delivery_entry"] = {
        "raw": pin(entry_path), "rva": "0x244630",
        "evidence_id": entry["evidence_id"],
        "body_inclusive": entry_value["procedure"]["body"],
    }
    assert _sha256_file(DEFAULT_EXE) == EXPECTED_EXE_SHA256
    with DEFAULT_EXE.open("rb") as handle, mmap.mmap(
            handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        pe = _parse_pe(mapped)
        assert pe["image_base"] == IMAGE_BASE
        offset = _rva_to_file_offset(pe, 0x244630, 16)
        assert offset is not None
        window = bytes(mapped[offset:offset + 16])
        _section, rows = _pdata_rows(mapped, pe)
        matching = [row for row in rows
                    if row["start_rva"] <= 0x244630 < row["end_rva_exclusive"]]
    assert window.hex() == "4889542410534881ec00010000488bda"

    def pseudo(label: str) -> list[str]:
        return values[label]["pseudocode"]["value"].splitlines()

    def asm(label: str) -> list[str]:
        return values[label]["assembly"]["value"]

    claims = [
        {"id": "selection-not-visibility", "source": "setting",
         "evidence_kind": "static_rea_pseudocode_and_machine",
         "finding": "8C1BA0 selects a short reference slot from game+1E60, or +1E68 in its special mode; it compares slots32..47 with message+28/+30 and selects definition+88/+90. Otherwise it tests a lookup for both references and chooses +98 or +A0, falling back to a default settings object. These are settings branches, not a proven visibility or observer-country contract.",
         "proof": [excerpt(pseudo("setting"), "sVar4 = (short)((ulonglong)*(undefined8 *)(DAT_14233fe58 + 0x1e68)", 1, 5),
                   excerpt(pseudo("setting"), "param_2 + 0x28", 1, 21),
                   excerpt(asm("setting"), "0x1408c1c4d:", 3, 16)]},
        {"id": "lookup-low-byte-only", "source": "membership",
         "evidence_kind": "static_rea_pseudocode_and_machine",
         "finding": "84C0B0 searches a tree by the signed16-bit slot from input bits32..47. A matching node yields its byte+20; the no-match path clears AL only. The caller tests AL, so undefined upper return bits are not a true result. Tree membership/value has no independently proven allied/enemy/fog-of-war meaning.",
         "proof": [excerpt(asm("membership"), "0x14084c0b0:", 0, 8),
                   excerpt(asm("membership"), "0x14084c0f9:", 2, 3),
                   excerpt(asm("setting"), "0x1408c1c52:", 1, 6)]},
        {"id": "localized-template-lookup", "source": "format",
         "evidence_kind": "static_rea_pseudocode",
         "finding": "14B33A0 hashes the input key with the exact multiply-then-XOR recurrence, looks it up in the localization table, and copies the original key when missing. A returned string does not prove a localized full popup was obtained.",
         "proof": [excerpt(pseudo("format"), "uVar6 = 0x811c9dc5;", 0, 15)]},
        {"id": "format-expansion-boundary", "source": "format",
         "evidence_kind": "static_rea_pseudocode",
         "finding": "Found templates use a stack scratch buffer, find paired dollar delimiters and call14B2B40 for expansion with argument pointer/count. The wrapper tests destination-minus-scratch against0xFC00 after expansion. Its overflow branch resets the output object and copies from the current scratch input; this does not prove either a blank result or complete untruncated text. Encoding, expansion semantics and live lifetime remain unresolved.",
         "proof": [excerpt(pseudo("format"), "uStack_10048 = 0xa110ca7e;", 2, 40),
                   excerpt(pseudo("format"), "FUN_140095110(param_1,param_2);", 2, 2)]},
        {"id": "entry-argument-evidence", "source": "delivery_entry",
         "evidence_kind": "static_rea_machine_and_separate_ordinary_pe_bytes",
         "finding": "At244630 entry RDX is saved as the message object; RCX is retained in R10 as the manager, while R8/R9 select an optional pair. The first16bytes comprise four whole non-RIP-relative instructions and stop before MOV R10,RCX. This is a static candidate entry boundary, not an installed or validated hook ABI, unwind, thread, visibility or coverage contract.",
         "proof": [excerpt(entry_value["assembly"], "0x140244630:", 0, 10),
                   excerpt(entry_value["assembly"], "0x140244677:", 0, 5)]},
    ]
    return {
        "schema": "information_battle_capture_scope_text_ledger_v1",
        "target": {"build": "1.37.4", "executable_sha256": EXPECTED_EXE_SHA256,
                   "static_image_base": hex(IMAGE_BASE)},
        "scope": {"static_only": True, "game_access": False,
                  "native_functions_invoked": False, "hook_installed": False,
                  "dispatch_authorized": False, "B01_B04_available": False},
        "sources": sources, "claims": claims,
        "ordinary_PE_entry_window": {
            "kind": "ordinary_PE_bytes_not_REA_or_runtime", "executable": pin(DEFAULT_EXE),
            "rva_start": "0x244630", "rva_end_exclusive": "0x244640",
            "file_offset": hex(offset), "bytes": len(window), "hex": window.hex(),
            "sha256": hashlib.sha256(window).hexdigest(),
            "pdata_half_open_containing_rows": matching,
            "unwind_registration_proven": False,
        },
        "receipt_gap": {
            "query": "rea-localized-format-001", "shell_session": 52519,
            "shell_wrapper_exit_code": 1, "run_json_present": False,
            "provider_exit_code": None, "provider_peak_committed_bytes": None,
            "reason": "Historical runner threw its unchanged10MiB postread guard after producing32568212B; bounded selected recovery does not recover the absent runtime receipt.",
            "query_repeated": False,
        },
        "unresolved": [
            "Allied/enemy/nonparticipant eligibility before message submission and actual fog-of-war visibility.",
            "Physical selected/player reference versus configured information observer (historically POR versus FRA) must remain separate.",
            "A244630 hook would miss formatter-suppressed messages and cannot alone prove all relevant battle capture.",
            "An earlier router/result hook needs full ABI/unwind/thread/reentrancy, owned payload, stable battle/war identity, and observed live lifetime.",
            "Complete visible popup text needs independently mapped controls, localized expansions, encoding and semantic completeness; no real payload has been captured.",
            "The missing14B33A0 process receipt remains unknown despite later runner repair; old evidence/run state must not be rewritten.",
        ],
        "gate_survey": pin(STAGE / "capture-gate-survey-001.json"),
        "script": pin(Path(__file__).resolve()),
        "ordinary_PE_helper": pin(ROOT / "work/probe_information_message_vtable.py"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    output = STAGE / "capture-scope-text-ledger-001.json"
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert output.read_text(encoding="utf-8") == text
    else:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    print(json.dumps({"output": pin(output), "verified_existing": args.verify_existing},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
