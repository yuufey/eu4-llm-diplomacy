"""Bound the country serializer/parser for the professionalism token."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range

STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"
RANGES = ((0x2DC6E0, 0x2DC71C), (0x2DFC0E, 0x2DFC46), (0x1707A50, 0x1707AB1), (0x955620, 0x955765))


def main(ui=False, writer=False):
    pe = PE(game_exe())
    digest = hashlib.sha256(pe.data).hexdigest()
    assert digest == "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
    md, cs = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    result = {"schema": "information_military_professionalism_static.v1", "kind": "ordinary_bounded_PE_not_REA",
              "exe_sha256": digest, "image_base": hex(pe.base), "runtime_or_RPM": False, "ranges": []}
    raw = pe.bytes_at(0x2231038, 4 + len(b"army_professionalism\0"))
    assert raw.startswith(bytes.fromhex("d6360000") + b"army_professionalism\0")
    result["token"] = {"id": "0x36d6", "rva": "0x2231038", "va": "0x142231038", "raw_hex": raw.hex()}
    ranges = ((0x6D2B80, 0x6D2F78),) if writer else ((0xFB4BA0, 0xFB88A0),) if ui else RANGES
    assert all(0 < end - start <= 0x4000 for start, end in ranges)
    assert sum(end - start for start, end in ranges) <= 0x8000
    for start, end in ranges:
        raw = pe.bytes_at(start, end - start)
        result["ranges"].append({"start_rva": hex(start), "end_rva_exclusive": hex(end),
                                 "start_va": hex(pe.base + start), "end_va_exclusive": hex(pe.base + end),
                                 "bytes_sha256": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw),
                                 "instructions": _decode_range(pe, md, start, end)})
    result["peak_committed_bytes"] = check_memory_budget()
    path = STAGE / ("professionalism-writer-001.json" if writer else "professionalism-ui-001.json" if ui else "professionalism-code-001.json")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ui", action="store_true")
    parser.add_argument("--writer", action="store_true")
    args = parser.parse_args()
    assert not (args.ui and args.writer)
    main(args.ui, args.writer)
