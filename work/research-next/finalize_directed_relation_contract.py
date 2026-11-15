"""Bind the directed relation network to the current PE and accepted evidence.

No process access, REA analysis or game calls. Published reports are exclusive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, make_disassembler
from work.research_information_branch_inputs import _decode_range

STAGE = ROOT / "work/runtime/information-relation-network-remaining-20261027-001"
EXE = Path(r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV\eu4.exe")
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EVIDENCE = {
    "military_access_predicate": "work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json",
    "military_access_validity": "work/runtime/military-access-identification-20261015-001/rea-525530/evidence.json",
    "guarantee_predicate": "work/runtime/guarantee-support-identification-20261015-001/guarantee-integration-20261015-001/rea-a69e00/evidence.json",
    "guarantee_validity": "work/runtime/guarantee-support-identification-20261015-001/rea-521b00/evidence.json",
}


def pin(path: Path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.relative_to(ROOT)).replace("\\", "/"), "bytes": path.stat().st_size, "sha256": digest}


def run(output: Path) -> int:
    with EXE.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == EXE_SHA
    pe = PE(EXE)
    md, _ = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    if md is None:
        raise RuntimeError("pinned local Capstone unavailable")
    evidence = {}
    for name, relative in EVIDENCE.items():
        path = ROOT / relative
        assert path.stat().st_size <= 8 * 1024 * 1024
        doc = json.loads(path.read_bytes())
        assert doc["subject"]["digest"]["sha256"] == EXE_SHA
        evidence[name] = dict(pin(path), evidence_id=doc["evidence_id"], subject_sha256=EXE_SHA)

    def guard(name, rva, size):
        raw = pe.bytes_at(rva, size)
        assert len(raw) == size
        return {"name": name, "kind": "bytes", "rva": hex(rva), "static_va": hex(pe.base+rva),
                "end_rva_exclusive": hex(rva+size), "hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()}

    guards = [guard("military_access_predicate", 0xA68E60, 60),
              guard("guarantee_predicate", 0xA69E00, 90)]
    actions = {}
    for name, vt, validity, token in (("military_access", 0x1C7FB70, 0x525530, 0x2943),
                                      ("guarantee", 0x1C7FE50, 0x521B00, 0x2941)):
        slot = int.from_bytes(pe.bytes_at(vt+0x80, 8), "little")
        assert slot == pe.base+validity
        leaf = int.from_bytes(pe.bytes_at(vt+0x98, 8), "little")-pe.base
        token_guard = guard(name+"_token", leaf, 6)
        assert token_guard["hex"] == "b8"+token.to_bytes(4,"little").hex()+"c3"
        slot_guard = guard(name+"_validity_slot", vt+0x80, 8)
        slot_guard.update(kind="pointer_slot", target_rva=hex(validity))
        guards.extend([slot_guard, token_guard])
        actions[name] = {"vtable_rva":hex(vt),"validity_rva":hex(validity),"token_leaf_rva":hex(leaf),"token":hex(token)}
    windows = [{"begin_rva":hex(begin),"end_rva_exclusive":hex(end),
                "instructions":_decode_range(pe,md,begin,end)}
               for begin,end in ((0xA68E60,0xA68E9C),(0xA69E00,0xA69E5A))]
    result = {
        "schema":"information_directed_relation_network_contract.v1", "status":"source_closed_runtime_pending",
        "binary":{"version":"1.37.4","sha256":EXE_SHA,"image_base":hex(pe.base)},
        "source":pin(STAGE/"source-002.json"), "accepted_REA":evidence,
        "ordinary_PE":{"code_guards":guards,"leaf_windows":windows,"decoded_bytes":150,"actions":actions},
        "common":{"country_table":"*(base+0x233d8b0)+0x118; signed count +0x124, 1..4096",
                  "fullref":"country+0x20; compare all 8 bytes and database slot",
                  "row":"*(country+0x1510)+target_slot*0x48; row+0 owner, row+0x10 exact target fullref",
                  "owner_equals_country":False,"known_null_country_fullref_hex":"2d2d2d0000000000",
                  "key":"sign_extend_i16(target_fullref.slot), compared to signed DWORD entry+0",
                  "stride":16,"native_return":"AL only; ignore upper RAX"},
        "families":{
            "military_access":{"begin_offset":"0xb0","count_offset":"0xbc","predicate_rva":"0xa68e60",
                               "native_predicate":"any matching key; no element payload dereference",
                               "direction_map":{"forward":"received","reverse":"granted"}},
            "guarantee":{"begin_offset":"0x1a0","count_offset":"0x1ac","predicate_rva":"0xa69e00",
                         "native_predicate":"FIRST matching key; entry+8 record pointer non-null; signed16 slot(record+0x18 QWORD)==target slot",
                         "null_record_is_false":True,"unreadable_record_is_unknown":True,
                         "direction_map":{"forward":"granted","reverse":"received"},
                         "pair_validity_difference":"521B00 mode0 checks key+non-null only; its result does not replace A69E00 record identity predicate"}},
        "operand_paths":{"forward":"actor-country row for partner fullref","reverse":"partner-country row for actor fullref"},
        "role_binding":{"evidence_layer":"static action endpoint and mode interpretation, not runtime action observation",
                        "guarantee":"proclaim/revoke 2941: action+10 guarantor, action+20 beneficiary; forward=actor grants partner",
                        "military_access":"ask/cancel 2943: action+10 requester/user, action+20 land grantor; forward=partner grants actor",
                        "received":{"grantor":"partner","recipient":"actor"},
                        "granted":{"grantor":"actor","recipient":"partner"}},
        "public_scope":{"change":"country network gains guarantee and military_access, six families total",
                        "selected_pair":"existing nine family / ten-row contract retained",
                        "expiry":"planned; other vector bytes/record fields and revocation conditions do not supply a date",
                        "coverage":"four R01 fields remain partial; complete=false",
                        "military_access_semantics":"explicit native relation cache; not effective army traversal permission from wars/subjects/conditional access"},
        "unknowns":["runtime country scan completeness and positive samples pending", "native expiry dates", "other entry/record bytes"],
        "read_only":True,"new_REA_calls":0,"new_RPM_calls":0,"native_game_calls":False,
        "full_goal_scope":{"topics":74,"fields":397,"phases":[2,3,4],"battle":"B01-B04 retained","status":"active"},
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(result,stream,ensure_ascii=False,indent=2);stream.write("\n")
    print(json.dumps(pin(output),ensure_ascii=False))
    return 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true")
    parser.add_argument("--output",type=Path,default=STAGE/"relation-network-contract-003.json")
    args=parser.parse_args()
    if not args.run:
        parser.print_help();return 0
    return run(args.output)


if __name__=="__main__":
    raise SystemExit(main())
