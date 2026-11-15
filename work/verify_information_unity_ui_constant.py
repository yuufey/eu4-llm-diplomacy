"""Verify four fixed PE bytes cited by the bounded REA unity UI callsite."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "work/runtime/ghidra-full/b23fa0e1f698d31b-20261014T054913Z-6dda97/input/eu4.exe"
STAGE = ROOT / "work/runtime/information-religious-unity-20261025-001"
EXPECTED = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def main():
    if EXE.stat().st_size != 38463016:
        raise ValueError("fixed executable size mismatch")
    digest = hashlib.sha256()
    with EXE.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != EXPECTED:
        raise ValueError("fixed executable SHA mismatch")
    rva = 0x1DC1860
    with EXE.open("rb") as stream:
        dos = stream.read(64)
        if dos[:2] != b"MZ":
            raise ValueError("not PE")
        pe_offset = struct.unpack_from("<I", dos, 60)[0]
        if pe_offset > 1024 * 1024:
            raise ValueError("PE header outside bounded window")
        stream.seek(pe_offset)
        header = stream.read(24)
        if header[:4] != b"PE\0\0":
            raise ValueError("PE signature mismatch")
        section_count = struct.unpack_from("<H", header, 6)[0]
        optional_size = struct.unpack_from("<H", header, 20)[0]
        if not 1 <= section_count <= 96 or optional_size > 4096:
            raise ValueError("unbounded PE headers")
        stream.seek(optional_size, 1)
        matches = []
        for _ in range(section_count):
            section = stream.read(40)
            virtual_size, start, raw_size, raw_offset = struct.unpack_from("<IIII", section, 8)
            if start <= rva and rva + 4 <= start + raw_size:
                matches.append((raw_offset + rva - start, section[:8].rstrip(b"\0").decode("ascii")))
        if len(matches) != 1:
            raise ValueError("RVA is not uniquely file-backed")
        offset, section_name = matches[0]
        stream.seek(offset)
        raw = stream.read(4)
    value = struct.unpack("<f", raw)[0]
    if value != 100.0:
        raise ValueError("UI percentage constant changed")
    source = STAGE / "rea-unity-ui-tooltip-001/evidence.json"
    report = {
        "schema": "information_unity_ui_float_constant_v1",
        "evidence_kind": "ordinary_bounded_PE_bytes_not_REA_or_runtime",
        "exe_sha256": EXPECTED,
        "exe_bytes": EXE.stat().st_size,
        "image_base": "0x140000000",
        "rva": hex(rva),
        "static_va": hex(0x140000000 + rva),
        "file_offset": offset,
        "section": section_name,
        "bytes": len(raw),
        "raw_hex": raw.hex(),
        "float32_little_endian": value,
        "referencing_REA_evidence_id": "ev_16619d154f61d8baeaca5e9373c1f022345206c16f7402e7987afc0d163745c1",
        "referencing_REA_file_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "callsite_rva": "0xfec804",
        "runtime_observation": False,
        "production_changed": False,
    }
    target = STAGE / "ui-float-constant-001.json"
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": "verified", "rva": hex(rva), "value": value}))


if __name__ == "__main__":
    main()
