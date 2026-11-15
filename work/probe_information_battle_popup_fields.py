"""Build a bounded, reproducible static ledger for battle popup fields.

Only already-retained selected REA values and a 16-byte ordinary PE window
are read.  This does not run REA, game code, a hook, or a live process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
from pathlib import Path

from work.probe_information_message_vtable import (
    DEFAULT_EXE,
    EXPECTED_EXE_SHA256,
    IMAGE_BASE,
    _parse_pe,
    _rva_to_file_offset,
    _sha256_file,
)

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-popup-20261025-001"
QUERIES = {
    "message_copy": ("rea-popup-message-copy-001", 0x598DC0),
    "node_copy": ("rea-template-node-copy-001", 0x5B29C0),
    "land_fields": ("rea-land-popup-fields-001", 0x8C75D0),
    "naval_fields": ("rea-naval-popup-fields-001", 0x8CA460),
}
MAX_SELECTED_BYTES = 2 * 1024 * 1024


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": _sha256_file(path)}


def excerpt(text: str, anchor: str, before: int = 2, after: int = 8) -> dict:
    lines = text.splitlines()
    hits = [i for i, line in enumerate(lines) if anchor in line]
    if len(hits) != 1:
        raise ValueError(f"expected unique anchor {anchor!r}: {len(hits)}")
    index = hits[0]
    start, end = max(0, index - before), min(len(lines), index + after + 1)
    return {"anchor": anchor, "line_start": start + 1, "line_end": end,
            "text": "\n".join(lines[start:end])}


def build() -> dict:
    sources, values = {}, {}
    for label, (directory, rva) in QUERIES.items():
        path = STAGE / directory / "selected-evidence-001.json"
        if path.stat().st_size > MAX_SELECTED_BYTES:
            raise ValueError("selected read budget exceeded")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["status"] == "observed"
        assert data["identity_audit"]["status"] == "passed"
        assert data["provider_runtime"]["audit"]["status"] == "passed"
        assert data["request"]["all_fixed_checks_pass"]
        result = data["raw_result_value"]
        procedure = result["procedure"]["value"]
        assert int(procedure["address"], 0) == IMAGE_BASE + rva
        body = procedure["body"]
        ranges = [{"start_rva": hex(int(row["start"], 0) - IMAGE_BASE),
                   "end_rva_inclusive": hex(int(row["end"], 0) - IMAGE_BASE),
                   "end_rva_exclusive": hex(int(row["end"], 0) - IMAGE_BASE + 1)}
                  for row in body["ranges"]]
        assert sum(int(row["end"], 0) - int(row["start"], 0) + 1
                   for row in body["ranges"]) == body["total_bytes"]
        sources[label] = {"selected": pin(path), "rva": hex(rva),
                          "evidence_id": data["top_level"]["evidence_id"]["value"],
                          "ghidra_inclusive_body_ranges": ranges,
                          "body_total_bytes": body["total_bytes"],
                          "body_span_bytes": body["span_bytes"]}
        values[label] = result

    # This is ordinary file evidence, deliberately separate from REA.
    assert _sha256_file(DEFAULT_EXE) == EXPECTED_EXE_SHA256
    with DEFAULT_EXE.open("rb") as handle, mmap.mmap(
            handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        pe = _parse_pe(mapped)
        assert pe["image_base"] == IMAGE_BASE
        offset = _rva_to_file_offset(pe, 0x1CC08D0, 16)
        assert offset is not None
        window = bytes(mapped[offset:offset + 16])
    assert window.startswith(b"_1\0\0Line1\0")

    def pseudocode(label: str) -> str:
        return values[label]["pseudocode"]["value"]

    copy_asm = "\n".join(values["message_copy"]["assembly"]["value"])
    node_asm = "\n".join(values["node_copy"]["assembly"]["value"])
    claims = [
        {"id": "message-container-copy", "source": "message_copy",
         "evidence_kind": "static_rea_machine_and_pseudocode",
         "finding": "598DC0 initializes a new destination container, walks source +10 nodes via +60, and passes each current source node in RDX to 5B29C0. The decompiler omits this second helper argument.",
         "excerpts": [excerpt(copy_asm, "0x140598e0a:", 0, 9),
                      excerpt(pseudocode("message_copy"), "param_1[5] =", 0, 7)]},
        {"id": "node-key-value-copy", "source": "node_copy",
         "evidence_kind": "static_rea_machine_and_pseudocode",
         "finding": "5B29C0 allocates 0x70 bytes, constructs independent key/value strings at +0/+20 using NUL lengths and 095110, then links a new node. Source +40/+48/+50 metadata are copied as qwords; no transitive ownership or lifetime is established for these values.",
         "excerpts": [excerpt(node_asm, "0x1405b29da:", 1, 4),
                      excerpt(node_asm, "0x1405b2a29:", 1, 16),
                      excerpt(node_asm, "0x1405b2a67:", 0, 15)]},
        {"id": "message-string-and-context", "source": "message_copy",
         "evidence_kind": "static_rea_machine_and_pseudocode",
         "finding": "Message +60 is separately constructed from source bytes. Definition +8, context +28..+58, and +80 are copied as qwords; date +88 and flag bytes +8C/+8D are copied. This is not a fully deep, indefinitely owned message snapshot.",
         "excerpts": [excerpt(copy_asm, "0x140598e5f:", 0, 19)]},
        {"id": "land-control-values", "source": "land_fields",
         "evidence_kind": "static_rea_pseudocode",
         "finding": "Land walks popup+1D0 template nodes and sends value +20 to named controls, with definition+5C branches for compact losses versus detailed leader/unit controls. OUR/ENEMY are UI template labels, not proof of an observer-side identity.",
         "excerpts": [excerpt(pseudocode("land_fields"), 'lVar9,"WINORLOSE"', 1, 7),
                      excerpt(pseudocode("land_fields"), '"COMPACT_BATTLE_RESULT_LOSSES","NUMBER",lVar9 + 0x20', 6, 2)
                      if pseudocode("land_fields").count('"COMPACT_BATTLE_RESULT_LOSSES","NUMBER",lVar9 + 0x20') == 1
                      else excerpt(pseudocode("land_fields"), 'lVar9,"ENEMYLOST"', 1, 7)]},
        {"id": "land-line1-format", "source": "land_fields",
         "evidence_kind": "static_rea_pseudocode_plus_separate_pe_literal",
         "finding": "Land collects all key/value pairs for formatter 14B33A0 and formats definition-key + _1 into control Line1 via 152AD10. Button text uses separate _BTN1/_BTN2/_BTN3 paths. An assembled line alone is not the complete set of visible popup controls.",
         "excerpts": [excerpt(pseudocode("land_fields"), "local_ad0 = 0;", 0, 24),
                      excerpt(pseudocode("land_fields"), '"_BTN1"', 3, 4)]},
        {"id": "naval-control-values", "source": "naval_fields",
         "evidence_kind": "static_rea_pseudocode",
         "finding": "Naval separately fills named unit/leader/result controls from template strings, including CAPTURE. Land-like template names such as OURCAVSTART are reused in naval UI and do not establish ship-class semantics by spelling.",
         "excerpts": [excerpt(pseudocode("naval_fields"), 'strcmp(pcVar17,"OURCAVSTART")', 1, 7),
                      excerpt(pseudocode("naval_fields"), 'pcVar17[lVar13] != "CAPTURE"[lVar13]', 2, 7)]},
        {"id": "naval-line1-format", "source": "naval_fields",
         "evidence_kind": "static_rea_pseudocode_plus_separate_pe_literal",
         "finding": "Naval builds formatter arguments from the node key/value strings, appends _1 to the definition key, calls 14B33A0, then assigns Line1 through 152AD10. Flags still select separate button behavior.",
         "excerpts": [excerpt(pseudocode("naval_fields"), "local_c8 = 0;", 0, 32),
                      excerpt(pseudocode("naval_fields"), "local_40 = (longlong)(puVar21 + 4);", 0, 22)]},
    ]
    return {
        "schema": "information_battle_popup_field_ledger_v1",
        "scope": {"fixed_build": "1.37.4", "executable_sha256": EXPECTED_EXE_SHA256,
                  "static_image_base": hex(IMAGE_BASE), "game_access": False,
                  "native_invocation": False, "dispatch_authorized": False,
                  "B01_B04_available": False},
        "sources": sources,
        "ordinary_pe_literals": {"kind": "ordinary_static_PE_bytes_not_REA",
            "executable": pin(DEFAULT_EXE), "rva_start": "0x1cc08d0",
            "rva_end_exclusive": "0x1cc08e0", "file_offset": hex(offset),
            "bytes": len(window), "hex": window.hex(),
            "sha256": hashlib.sha256(window).hexdigest(),
            "literals": [{"rva": "0x1cc08d0", "ascii": "_1"},
                         {"rva": "0x1cc08d4", "ascii": "Line1"}]},
        "claims": claims,
        "unresolved": [
            "All retained claims are static; no execution, hook ABI/thread/reentrancy, live lifetime or observer visibility has been verified.",
            "095110 string-copy behavior is inferred from bounded machine arguments/construction patterns, not an independent runtime allocator/string contract.",
            "Definition/context/node metadata may contain borrowed references. A whole-message memcpy is not an owned export.",
            "UI construction remains gated and side-effecting; these functions must not be called as read-only queries or used as the sole complete event source.",
            "Complete B04 needs every displayed control plus formatted Line1, localization/encoding, identity, sequence and completeness; no collected complete battle payload exists.",
            "Stable battle/war identity, observer-side mapping, eligible allied/enemy nonparticipant battles and dynamic display field coverage remain unresolved.",
        ],
        "script": pin(Path(__file__).resolve()),
        "helper_dependency": pin(ROOT / "work/probe_information_message_vtable.py"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=STAGE / "popup-field-ledger-001.json")
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    value = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert args.output.read_text(encoding="utf-8") == value
    else:
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
    print(json.dumps({"output": str(args.output), "sha256": _sha256_file(args.output),
                      "verified_existing": args.verify_existing}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
