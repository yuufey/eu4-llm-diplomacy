"""Inspect the one known country writer for modifier-instance serialization.

Ordinary PE evidence only: no native execution, RPM, REA, or image-wide decode.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range

SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
START, END = 0x2DC6E0, 0x2E125B
STAGE = ROOT / "work/runtime/information-military-modifiers-20261027-001"


def main(selector_tokens=False):
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == SHA
    assert pe.function(START)[:2] == (START, END)
    assert END - START < 32 * 1024
    md, _ = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    raw = pe.bytes_at(START, END - START)
    rows = _decode_range(pe, md, START, END)
    tokens = []
    selected = []
    selector_map = {}
    if selector_tokens:
        for section in pe.sections:
            if section["flags"] & 0x20000000:
                continue
            begin, end = section["raw"], section["raw"] + section["size"]
            for match in re.finditer(rb"[a-z][a-z0-9_]{2,70}\x00", pe.data[begin:end]):
                offset = begin + match.start()
                if offset < 4 or pe.data[offset - 1] != 0:
                    continue
                key = int.from_bytes(pe.data[offset - 4:offset], "little")
                if not 0 < key < 65536:
                    continue
                record = dict(token_rva=hex(pe.to_rva(offset - 4)), key=hex(key),
                              text=match.group()[:-1].decode("ascii"),
                              raw_hex=pe.data[offset - 4:offset + len(match.group())].hex())
                selector_map.setdefault(key, []).append(record)
    for index, ins in enumerate(rows):
        if selector_tokens:
            operand = re.fullmatch(r"edx,0x([0-9a-f]+)", ins["operands"].lower())
            if ins["mnemonic"] == "mov" and operand:
                for candidate in selector_map.get(int(operand[1], 16), []):
                    record = dict(candidate, instruction_rva=ins["rva"])
                    tokens.append(record)
                    if "modif" in record["text"]:
                        selected.append(dict(token=record, instructions=rows[max(0,index-18):index+25]))
            continue
        if ins["mnemonic"] != "lea" or "rip" not in ins["operands"].lower():
            continue
        encoded = bytes.fromhex(ins["bytes"])
        if len(encoded) == 7 and encoded[1] == 0x8D and encoded[2] & 0xC7 == 0x05:
            target = int(ins["rva"], 16) + len(encoded) + int.from_bytes(encoded[-4:], "little", signed=True)
            data = pe.bytes_at(target, 100)
            if len(data) < 8:
                continue
            key = int.from_bytes(data[:4], "little")
            text_raw = data[4:].split(b"\0", 1)[0]
            if not 0 < key < 65536 or not 2 <= len(text_raw) <= 80:
                continue
            if any(c not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in text_raw):
                continue
            token = text_raw.decode("ascii")
            record = dict(instruction_rva=rows[index]["rva"], token_rva=hex(target),
                          token_static_va=hex(pe.base + target), key=hex(key), text=token,
                          raw_hex=data[:5 + len(text_raw)].hex())
            tokens.append(record)
            if "modif" in token:
                selected.append(dict(token=record, instructions=rows[max(0, index-12):index+23]))
    report = dict(schema="information_active_military_modifiers_country_writer.v1",
                  evidence_kind="ordinary_bounded_PE_not_REA", exe_sha256=SHA,
                  image_base=hex(pe.base), rva_rule="runtime VA = runtime module base + RVA",
                  decoded_range=dict(start_rva=hex(START), end_rva_exclusive=hex(END),
                                     bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()),
                  first_instructions=rows[:30], token_references=tokens,
                  selector_map_method="bounded PE data-section ASCII token candidates matched to immediate EDX selectors" if selector_tokens else "RIP-relative token pointers only",
                  modifier_token_windows=selected,
                  boundaries=["Token references and writer code are static observations only.",
                              "A token spelling alone does not identify a live instance collection.",
                              "No runtime active-list, visibility, or completeness claim is made."],
                  native_calls=0, new_REA=False, RPM=False,
                  peak_committed_bytes=check_memory_budget())
    STAGE.mkdir(parents=True, exist_ok=True)
    output = STAGE / ("active-military-modifiers-source-003.json" if selector_tokens else "active-military-modifiers-source-002.json")
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(dict(output=str(output), token_count=len(tokens),
                          modifier_tokens=[r["token"] for r in selected]), ensure_ascii=False))


if __name__ == "__main__":
    assert sys.argv[1:] in ([], ["--selector-tokens"])
    main(sys.argv[1:] == ["--selector-tokens"])
