"""Freeze retained-result scope and history-date evidence without a new query.

Only saved bounded REA members and three narrow ordinary PE windows are read.
This neither reads the running game nor installs/calls a native hook.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

from work.extract_information_battle_war_evidence import _compare_values
from work.probe_information_battle_capture_scope import excerpt
from work.probe_information_message_vtable import (
    DEFAULT_EXE, EXPECTED_EXE_SHA256, IMAGE_BASE, _parse_pe,
    _rva_to_file_offset, _sha256_file, _pdata_rows,
)

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-war-records-20261025-001"
QUERIES = {
    "retain": ("rea-war-result-retain-001", 0xD89A80),
    "score": ("rea-result-war-binding-001", 0x1DD3C0),
    "append": ("rea-war-history-append-001", 0xD8FF10),
    "date": ("rea-history-date-set-001", 0x7E7FB0),
}


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": _sha256_file(path)}


def load(path: Path, bound: int = 2 * 1024 * 1024) -> dict:
    assert path.stat().st_size <= bound, str(path)
    return json.loads(path.read_text(encoding="utf-8"))


def build() -> dict:
    sources, values = {}, {}
    for name, (directory, rva) in QUERIES.items():
        path = STAGE / directory / "selected-evidence-001.json"
        data = load(path)
        comparison = _compare_values(data)
        assert all(row["status"] == "equal" for row in comparison.values())
        value = {key: row["value"] for key, row in data["raw_result_value"].items()}
        assert int(value["procedure"]["address"], 0) == IMAGE_BASE + rva
        values[name] = value
        sources[name] = {"selected": pin(path), "rva": hex(rva),
                         "evidence_id": data["top_level"]["evidence_id"]["value"],
                         "raw_normalized_comparison": comparison,
                         "Ghidra_body_inclusive": value["procedure"]["body"]}
    callback_path = STAGE / "callback-entry-selected-001.json"
    callback = load(callback_path)
    comparison = _compare_values(callback)
    assert all(row["status"] == "equal" for row in comparison.values())
    values["callback"] = {key: row["value"] for key, row in callback["raw_result_value"].items()}
    assert int(values["callback"]["procedure"]["address"], 0) == IMAGE_BASE + 0x238620
    callback_raw = ROOT / "work/runtime/information-battles-20261025-001/rea-battle-result-effects-001/evidence.json"
    assert callback["source"]["sha256"] == _sha256_file(callback_raw)
    sources["callback"] = {"selected": pin(callback_path), "raw": pin(callback_raw),
                           "rva": "0x238620", "query_repeated": False,
                           "evidence_id": callback["top_level"]["evidence_id"]["value"],
                           "raw_normalized_comparison": comparison,
                           "Ghidra_body_inclusive": values["callback"]["procedure"]["body"]}
    router_path = ROOT / "work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json"
    router = load(router_path, 4 * 1024 * 1024)
    assert router["subject"]["digest"]["sha256"] == EXPECTED_EXE_SHA256
    assert router["raw_result"]["value"] == router["normalized_result"]
    values["router"] = router["raw_result"]["value"]
    sources["router"] = {"raw": pin(router_path), "rva": "0x23a020",
                         "evidence_id": router["evidence_id"], "query_repeated": False}

    def pseudo(name: str) -> list[str]:
        return values[name]["pseudocode"].splitlines()

    def asm(name: str) -> list[str]:
        return values[name]["assembly"]

    assert _sha256_file(DEFAULT_EXE) == EXPECTED_EXE_SHA256
    windows = []
    with DEFAULT_EXE.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        pe = _parse_pe(mapped)
        assert pe["image_base"] == IMAGE_BASE
        _, pdata = _pdata_rows(mapped, pe)
        for rva, size in ((0x1D20CB0 + 0x90, 32), (0x1D21400 + 0x90, 32), (0x238620, 36)):
            offset = _rva_to_file_offset(pe, rva, size)
            assert offset is not None
            raw = bytes(mapped[offset:offset + size])
            row = {"rva_start": hex(rva), "rva_end_exclusive": hex(rva + size),
                   "file_offset": hex(offset), "bytes": size, "hex": raw.hex(),
                   "sha256": hashlib.sha256(raw).hexdigest()}
            if size == 32:
                row["qword_target_rvas"] = [hex(x - IMAGE_BASE) for x in struct.unpack("<4Q", raw)]
                assert row["qword_target_rvas"] == ["0x8f450", "0x7e7cc0", "0x7e7d00", "0x8f440"]
            else:
                row["pdata_half_open_containing_rows"] = [x for x in pdata if x["start_rva"] <= rva < x["end_rva_exclusive"]]
                row["REA_entry_instructions"] = asm("callback")[:11]
                assert "0x140238644:" in asm("callback")[11]
            windows.append(row)
    assert _sha256_file(DEFAULT_EXE) == EXPECTED_EXE_SHA256
    claims = [
        {"id": "retained-subset", "source": "router",
         "finding": "Retention requires a nonzero context from A688B0 and signed raw summary+38 >200 or <-200 (floor(-199.5)=-200). The same boolean gates 1DD3C0/D89A80 and the later conditional result destructor. Units and semantic significance remain unknown; the F0 vector cannot prove all-battle capture.",
         "proof": [excerpt(pseudo("router"), "iVar3 = (int)uStack_50;", 3, 26),
                   excerpt(pseudo("router"), "if (cVar11 == '\\0')", 2, 3)]},
        {"id": "retained-result-and-history-reference", "source": "retain",
         "finding": "D89A80, when R8B !=0, appends the result pointer to context F0/F8/100 and allocates a48-byte history event with vtable1D20CB0, context+38 and result+40. It passes the current game+1DD0 raw date to D8FF10. This proves a static retained path, not unbounded lifetime.",
         "proof": [excerpt(asm("retain"), "0x140d89ace:", 0, 25),
                   {"lines": pseudo("retain")}]},
        {"id": "query-label-correction", "source": "score",
         "finding": "The directory named result-war-binding contains a calculation: result84/FC are cleared, then derived through context160 virtual rules, country modifier key500 and /1000 arithmetic. These are the side74 saved war_goal slots; this is not a war-ID binding function and must not be called as a getter.",
         "proof": [excerpt(pseudo("score"), "*(undefined4 *)(param_1 + 0x84) = 0;", 0, 13),
                   excerpt(pseudo("score"), "*(int *)(param_1 + 0x84) = local_res8[0] / 1000;", 0, 4)]},
        {"id": "history-date-join", "source": "append",
         "finding": "D8FF10 allocates a40-byte group with vtable1D21400 and owner38, assigns raw date10 and context118, appends the event then the group to context108. 7E7FB0 recursively visits child-list head20, node child0/next10 when virtual90 is false, and writes object10. Both sampled vtables use the same default90/98/A0 functions. Result8=165 is not this history date.",
         "proof": [{"lines": pseudo("append")}, {"lines": pseudo("date")}],
         "ordinary_PE_windows": [0, 1]},
        {"id": "earlier-natural-entry-candidate", "source": "router",
         "finding": "238620 is called for every nonnull built result on this router path, outside the history-retention gate, before land/naval message submission and conditional destruction. Win64 machine entry preserves RCX combat, receives RDX summary and R8 result. The first36 bytes are whole non-RIP-relative prologue instructions. This is only a static hook candidate; actual entry lifetime, thread, reentry, ABI/unwind registration and observer visibility are not validated. A15-byte copied partial prologue cannot blindly reuse the original unwind metadata.",
         "proof": [excerpt(pseudo("router"), "FUN_140238620(param_1,local_88,puVar6);", 5, 18),
                   {"lines": asm("callback")[:24]}], "ordinary_PE_windows": [2]},
    ]
    return {"schema": "information_battle_war_retention_ledger_v1",
            "target": {"build": "1.37.4", "executable_sha256": EXPECTED_EXE_SHA256,
                       "static_image_base": hex(IMAGE_BASE)},
            "sources": sources, "claims": claims,
            "ordinary_PE": {"evidence_kind": "ordinary_PE_bytes_not_REA_or_runtime",
                            "executable": pin(DEFAULT_EXE), "windows": windows},
            "scope": {"game_access": False, "new_REA_query": False, "hook_installed": False,
                      "native_function_invoked": False, "dispatch_authorized": False,
                      "source_scope": "native_retained_subset/query_only",
                      "battle_complete": False, "visibility_complete": False, "overall_complete": False},
            "unresolved": ["Stable native war/battle identity; addresses are private research context only.",
                           "History retention omits below-threshold results; source may not span ended wars.",
                           "Raw scales, battle kind, exact text encoding and observer eligibility need independent verification.",
                           "No natural hook or source-to-subscription battle payload has been installed or accepted."],
            "script": pin(Path(__file__).resolve()),
            "helpers": [pin(ROOT / x) for x in ("work/extract_information_battle_war_evidence.py",
                        "work/probe_information_battle_capture_scope.py", "work/probe_information_message_vtable.py")]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    output = STAGE / "war-result-retention-ledger-001.json"
    value = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert output.read_text(encoding="utf-8") == value
    else:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
    print(json.dumps({"output": pin(output), "verified_existing": args.verify_existing}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
