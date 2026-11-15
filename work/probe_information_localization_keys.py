"""Observe explicitly named native localization cache entries by pure RPM.

This research extension runs in the observer Python process. It does not
install a hook or call a game function. Keys are operator-supplied, not scanned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bridge.information import mission_memory as mm
from bridge.native_text import decode_native_text


def key_hash(key):
    result=0x811C9DC5
    for value in key.encode("ascii"):result=((result*0x1000193)^value)&0xFFFFFFFF
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation",type=Path,required=True)
    parser.add_argument("--key",action="append",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise FileExistsError(args.output)
    if (not 1<=len(args.key)<=8 or len(set(args.key))!=len(args.key)
            or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}",v) for v in args.key)):
        raise ValueError("Require 1..8 explicit bounded ASCII keys")
    original=mm._snapshot

    def extended(reader,module_base,country,include_completed,*rest):
        snapshot=original(reader,module_base,country,include_completed,*rest)
        if snapshot.get("status")!="observed":return snapshot
        observed={"status":"unknown","entries":[]}
        try:
            outer,_=reader.qword(module_base+0x2357B00,"localization.global")
            if not mm._valid_pointer(outer):raise ValueError("outer_invalid")
            raw=reader.read(outer,56,"localization.outer")
            inner=int.from_bytes(raw[:8],"little");pool=int.from_bytes(raw[32:40],"little")
            pool_end=int.from_bytes(raw[40:48],"little");pool_cap=int.from_bytes(raw[48:56],"little")
            if (not mm._valid_pointer(inner) or not mm._valid_pointer(pool)
                    or not pool<=pool_end<=pool_cap or pool_cap-pool>128*1024*1024):raise ValueError("pool_invalid")
            header=reader.read(inner,56,"localization.inner")
            language=mm._decode_string32(reader,inner,header[:32],"localization.language")
            begin=int.from_bytes(header[32:40],"little");end=int.from_bytes(header[40:48],"little")
            if not mm._valid_pointer(begin) or end<begin or (end-begin)%16 or not 0<(end-begin)//16<=1048576:
                raise ValueError("table_invalid")
            observed.update(outer_va=hex(outer),outer_hex=raw.hex(),inner_va=hex(inner),inner_hex=header.hex(),language=language,
                table_count=(end-begin)//16,pool_length=pool_end-pool)
            for key in args.key:
                target=key_hash(key);lo=0;hi=(end-begin)//16;steps=[]
                while lo<hi:
                    mid=(lo+hi)//2;entry=reader.read(begin+mid*16,16,"localization.search")
                    value=int.from_bytes(entry[:8],"little");steps.append({"index":mid,"hex":entry.hex()})
                    if value<target:lo=mid+1
                    else:hi=mid
                if lo>=(end-begin)//16:raise ValueError("key_not_found")
                entry=reader.read(begin+lo*16,16,"localization.match")
                if int.from_bytes(entry[:8],"little")!=target:raise ValueError("key_not_found")
                offset=int.from_bytes(entry[8:12],"little")
                if not offset<pool_end-pool:raise ValueError("value_offset_invalid")
                address=pool+offset;value=bytearray()
                while len(value)<8192:
                    length=min(64,8192-len(value),pool_end-address-len(value))
                    if not length:raise ValueError("unterminated_value_at_pool_end")
                    chunk=reader.read_code(address+len(value),length,"localization.value")
                    if b"\0" in chunk:
                        value.extend(chunk.split(b"\0",1)[0]);break
                    value.extend(chunk)
                else:raise ValueError("value_too_long")
                observed["entries"].append({"key":key,"hash":hex(target),"index":lo,"entry_hex":entry.hex(),"steps":steps,
                    "offset":offset,"value_hex":value.hex(),"decoded_eu4_escape":decode_native_text(value,"eu4_escape",max_bytes=8192),
                    "semantics":"native_cached_template_before_dollar_and_script_substitution"})
            observed["status"]="observed"
        except Exception as exc:observed["error"]=str(exc)
        snapshot["missions"]["localization_keys_probe"]=observed
        return snapshot

    try:
        mm._snapshot=extended
        report=mm.capture(args.installation,"FRA")
    finally:mm._snapshot=original
    report["research_extension"]={"script":str(Path(__file__).resolve()),"sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "kind":"process_local_Python_snapshot_extension_not_game_hook","keys":args.key}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"doublepass":report["doublepass"],"rpm_bytes":report["access"]["rpm_bytes_requested"],
        "localization":report.get("before",{}).get("missions",{}).get("localization_keys_probe")},ensure_ascii=False))


if __name__=="__main__":main()
