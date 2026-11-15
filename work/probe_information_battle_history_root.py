"""Compare the observed embedded history root with narrow fixed-PE windows.

The saved runtime observation and ordinary PE bytes remain separate evidence.
No REA query, native call, game read or hook installation is performed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

from work.probe_information_message_vtable import (
    DEFAULT_EXE, EXPECTED_EXE_SHA256, IMAGE_BASE, _parse_pe,
    _rva_to_file_offset, _sha256_file,
)

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-war-records-20261025-001"


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": _sha256_file(path)}


def build() -> dict:
    observation_path = STAGE / "live-fra-bur-001/report.json"
    assert observation_path.stat().st_size < 2 * 1024 * 1024
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    assert observation["status"] == "observed"
    assert observation["identity_before"]["process_path_sha256"] == EXPECTED_EXE_SHA256
    assert observation["identity_before"] == observation["identity_after"]
    assert observation["doublepass"]["consistent"] is True
    assert observation["cleanup"]["handle_close"]["closed"] is True
    module_base = int(observation["module_base"]["va"], 0)
    history = observation["wars"][0]["history"]
    root_vtable = int(history["root_vtable"]["value"]["va"], 0)
    assert root_vtable - module_base == 0x1D20BE0
    live_targets = [int(history["root_vtable"]["slots"][hex(s)]["value"]["va"], 0) - module_base
                    for s in (0x90, 0x98, 0xA0)]
    assert live_targets == [0x8F440, 0x7E7CC0, 0x7E7D00]
    assert _sha256_file(DEFAULT_EXE) == EXPECTED_EXE_SHA256
    windows = []
    with DEFAULT_EXE.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        pe = _parse_pe(mapped)
        assert pe["image_base"] == IMAGE_BASE
        for rva, size in ((0x1D20C70, 32), (0x8F440, 16), (0x8F450, 16)):
            offset = _rva_to_file_offset(pe, rva, size)
            assert offset is not None
            raw = bytes(mapped[offset:offset + size])
            row = {"rva_start": hex(rva), "rva_end_exclusive": hex(rva + size),
                   "file_offset": hex(offset), "bytes": size, "hex": raw.hex(),
                   "sha256": hashlib.sha256(raw).hexdigest()}
            if size == 32:
                targets = [x - IMAGE_BASE for x in struct.unpack("<4Q", raw)]
                assert targets == [0x8F440, 0x7E7CC0, 0x7E7D00, 0x8F440]
                row["slot_offsets"] = ["0x90", "0x98", "0xa0", "0xa8"]
                row["target_rvas"] = [hex(x) for x in targets]
            elif rva == 0x8F440:
                assert raw == bytes.fromhex("b001c3" + "cc" * 13)
                row["ordinary_instruction_interpretation"] = "MOV AL,1; RET; followed by INT3 padding. Only AL is defined."
            else:
                assert raw == bytes.fromhex("32c0c3" + "cc" * 13)
                row["ordinary_instruction_interpretation"] = "XOR AL,AL; RET; followed by INT3 padding. Only AL is defined."
            windows.append(row)
    assert _sha256_file(DEFAULT_EXE) == EXPECTED_EXE_SHA256
    return {
        "schema": "information_battle_history_root_contract_v1",
        "target": {"build": "1.37.4", "exe_sha256": EXPECTED_EXE_SHA256,
                   "static_image_base": hex(IMAGE_BASE)},
        "saved_runtime_observation": {"report": pin(observation_path), "module_base_va": hex(module_base),
                                      "root": history["root"], "root_vtable_va": hex(root_vtable),
                                      "root_vtable_rva": "0x1d20be0", "target_rvas": [hex(x) for x in live_targets],
                                      "history_date_status": "unknown_in_original_observation"},
        "ordinary_PE": {"evidence_kind": "ordinary_PE_bytes_not_REA_or_runtime_execution",
                        "executable": pin(DEFAULT_EXE), "windows": windows},
        "reader_contract": {
            "root_storage": "embedded war+108; first qword is vtable, not another object pointer",
            "root_vtable_rva": "0x1d20be0",
            "root_slot_targets": {"0x90": "0x8f440", "0x98": "0x7e7cc0", "0xa0": "0x7e7d00"},
            "root_child_list_head_offset": "0x20", "node_child_offset": "0x0", "node_next_offset": "0x10",
            "basis": "D8FF10 appends a group through embedded root98; the known base child list/date layout comes from retained REA, not from a native call in this probe.",
            "critical_distinction": "Root90 returns true; known group/event90 returns false. Do not change either type or claim the date setter recursively walks the root when90 is true.",
            "date_join": "Traverse known list nodes as reads only; bind event40 to an observed retained result only when event38 equals the same war. Unknown child types, cycles, truncation and duplicate dates remain explicit.",
        },
        "retention_ledger": pin(STAGE / "war-result-retention-ledger-001.json"),
        "scope": {"new_game_access": False, "new_REA_query": False, "native_call": False,
                  "hook_installed": False, "overall_complete": False},
        "script": pin(Path(__file__).resolve()),
        "PE_helper": pin(ROOT / "work/probe_information_message_vtable.py"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    output = STAGE / "history-root-contract-001.json"
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert output.read_text(encoding="utf-8") == text
    else:
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    print(json.dumps({"output": pin(output), "verified_existing": args.verify_existing}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
