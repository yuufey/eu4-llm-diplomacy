"""Extend the retained custom-record probe to observe its weight fields.

Only selected option-header reads in this Python process expand from 72 to
208 bytes. The complete expanded bytes enter both snapshot comparisons.
The original probe and its first report remain unchanged.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work import probe_information_custom_localization as original


def main():
    if "--output" not in sys.argv:raise ValueError("Require --output")
    destination=Path(sys.argv[sys.argv.index("--output")+1])
    base=original.mm.BoundedRPM

    class ExtendedRPM(base):
        def read(self,address,size,label):
            if label=="customloc.option_header":
                if size!=0x48:raise ValueError("Unexpected option-header read size")
                size=0xD0
            return super().read(address,size,label)

    try:
        original.mm.BoundedRPM=ExtendedRPM
        original.main()
    finally:original.mm.BoundedRPM=base
    report=json.loads(destination.read_text(encoding="utf-8"))
    report["weight_extension"]={"script":str(Path(__file__).resolve()),"sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "original_probe_sha256":hashlib.sha256(Path(original.__file__).read_bytes()).hexdigest(),
        "expanded_label":"customloc.option_header","old_bytes":0x48,"new_bytes":0xD0,
        "weight_uint32_offset":"0xb8","modifier_begin_offset":"0xc0","modifier_end_offset":"0xc8",
        "evidence_scope":"raw compiled weight/modifier headers, not predicate evaluation or game invocation"}
    destination.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    methods=report.get("before",{}).get("missions",{}).get("custom_localization_probe",{}).get("methods",{})
    summary={}
    for name,method in methods.items():
        summary[name]=[]
        for option in method["options"]:
            raw=bytes.fromhex(option["header_hex"])
            summary[name].append({"text_key":option["text_key"].get("text"),
                "weight":int.from_bytes(raw[0xb8:0xbc],"little"),
                "modifier_begin":hex(int.from_bytes(raw[0xc0:0xc8],"little")),
                "modifier_end":hex(int.from_bytes(raw[0xc8:0xd0],"little"))})
    print(json.dumps(summary))


if __name__=="__main__":main()
