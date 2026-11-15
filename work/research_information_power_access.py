"""Find bounded raw candidates for indexed native power-counter reads.

No instruction decoding or target execution is performed. Candidates must be
resolved by a focused disassembler before they support any layout conclusion.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget

SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def main():
    # Use the game's explicit local binding, never discover a different binary.
    from work.local_config import game_exe
    path = game_exe()
    assert path.stat().st_size < 64 * 1024 * 1024
    pe = PE(path)
    assert hashlib.sha256(pe.data).hexdigest() == SHA
    patterns = {
        "indexed_dword_260_scale4": rb"[\x40-\x4f]?\x8b[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x80-\xbf]\x60\x02\x00\x00",
        "indexed_address_260_scale4": rb"[\x40-\x4f]?\x8d[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc][\x80-\xbf]\x60\x02\x00\x00",
    }
    rows = []
    for label, pattern in patterns.items():
        for section in pe.sections:
            if not section["flags"] & 0x20000000:
                continue
            for match in re.finditer(pattern, pe.data[section["raw"]:section["raw"] + section["size"]]):
                offset = section["raw"] + match.start()
                rva = pe.to_rva(offset)
                function = pe.function(rva)
                rows.append({"pattern": label, "file_offset": hex(offset), "rva": hex(rva),
                             "static_va": hex(pe.base + rva), "candidate_bytes": match.group().hex(),
                             "function_range_rva": [hex(v) for v in function[:2]] if function else None,
                             "context_hex": pe.data[max(0, offset-16):offset+32].hex()})
                if len(rows) > 512:
                    raise ValueError("candidate count bound exceeded")
    check_memory_budget()
    result = {"evidence_kind": "ordinary_raw_byte_candidates_not_REA_no_disassembly",
              "executable_sha256": SHA, "image_base": hex(pe.base), "rows": rows,
              "limits": {"max_context_bytes": 48, "max_matches": 512},
              "unresolved": ["instruction boundaries", "object type", "enum semantics", "balance semantics"]}
    output = ROOT / "work/runtime/information-country-scalars-20261024-001/indexed-power-access-001.json"
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"count": len(rows), "rows": rows}, ensure_ascii=False))


if __name__ == "__main__":
    main()
