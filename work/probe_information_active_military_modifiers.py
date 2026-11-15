"""Copy bounded discovery inputs from the statically identified modifier list.

This is an independent source probe, not the public military_modifiers field.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe
from work.probe_information_current_overextension import probe
from work.probe_information_military_quality import (
    EXPECTED_DATE, EXPECTED_EXE_SHA256, EXPECTED_INSTALLATION,
    _installation_preflight, _valid_pointer,
)

def capture(definition_fields=False):
    preflight=_installation_preflight(EXPECTED_INSTALLATION)
    pe=PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest()==EXPECTED_EXE_SHA256
    guard_rva,guard_width=0x2E0076,0x63
    guard=pe.bytes_at(guard_rva,guard_width)
    def inputs(reader,module_base,country):
        used=0
        reads=[]
        def read(address,size,label):
            nonlocal used
            assert _valid_pointer(address) and 0<size<=512
            assert address+size<=0x7FFFFFFFFFFF and used+size<=32*1024
            used+=size
            raw=reader.read(address,size,'reference.modifier_instances.'+label)
            assert len(raw)==size
            reads.append(dict(label=label,va=hex(address),bytes=size,raw_hex=raw.hex()))
            return raw
        assert read(module_base+guard_rva,guard_width,'writer_guard')==guard
        header=read(country+0x1D8,0x38,'owner_header')
        node=int.from_bytes(header[0x18:0x20],'little')
        result=dict(module_base=hex(module_base),country_pointer=hex(country),
                    head=hex(node),owner_header_raw=header.hex(),nodes=[],
                    inputs_only_not_public_field=True)
        visited=set()
        while node and len(result['nodes'])<8:
            assert node not in visited
            visited.add(node)
            raw=read(node,0x18,f'node_{len(visited)}')
            item=int.from_bytes(raw[:8],'little')
            nxt=int.from_bytes(raw[0x10:0x18],'little')
            body=read(item,0x80,f'item_{len(visited)}')
            vtable=int.from_bytes(body[:8],'little')
            definition=int.from_bytes(body[0x30:0x38],'little')
            assert module_base<=vtable<module_base+0x4000000
            vt=read(vtable,0x30,f'item_vtable_{len(visited)}')
            definition_body=read(definition,0x180,f'definition_{len(visited)}')
            record=dict(node_va=hex(node),item_va=hex(item),next_va=hex(nxt),
                                        item_vtable_rva=hex(vtable-module_base),
                                        virtual_method_rvas=[hex(int.from_bytes(vt[i:i+8],'little')-module_base) for i in range(0,len(vt),8)],
                                        definition_va=hex(definition),item_raw_hex=body.hex(),
                                        definition_raw_hex=definition_body.hex())
            if definition_fields:
                length=int.from_bytes(definition_body[0x168:0x170],'little')
                capacity=int.from_bytes(definition_body[0x170:0x178],'little')
                assert 0<length<=255 and length<=capacity<=4096
                key_address=definition+0x158 if capacity<16 else int.from_bytes(definition_body[0x158:0x160],'little')
                key_raw=read(key_address,length+1,f'definition_key_{len(visited)}')
                assert key_raw[-1:]==b'\0'
                record['definition_key']=key_raw[:-1].decode('ascii')
                record['effect_count']=count=int.from_bytes(definition_body[0x64:0x68],'little',signed=True)
                assert 0<=count<=32
                pointer=int.from_bytes(definition_body[0x58:0x60],'little')
                manager=int.from_bytes(read(module_base+0x2358060,8,f'effect_manager_{len(visited)}'),'little')
                record['definition_effects']=[]
                for index in range(count):
                    pair=read(pointer+index*8,8,f'effect_pair_{len(visited)}_{index}')
                    identifier=int.from_bytes(pair[:4],'little')
                    assert identifier<8192
                    metadata=read(manager+identifier*0x60,0x60,f'effect_record_{len(visited)}_{index}')
                    record['definition_effects'].append(dict(index=identifier,raw=int.from_bytes(pair[4:],'little',signed=True),
                                                             raw_hex=pair[4:].hex(),pair_raw_hex=pair.hex(),
                                                             selector=int.from_bytes(metadata[0x50:0x54],'little'),
                                                             metadata_raw_hex=metadata.hex()))
            result['nodes'].append(record)
            node=nxt
        result.update(remaining_node=hex(node),bounded_prefix_only=bool(node),
                      child_budget=dict(bytes_requested=used,limit=32768),reads=reads)
        return dict(modifier_instances=result)
    report=probe(EXPECTED_INSTALLATION,field='modifier_instances',input_reader=inputs)
    report.update(schema='information_modifier_instances_independent_raw_inputs.v1',
                  preflight=preflight,binary_sha256=EXPECTED_EXE_SHA256,
                  game_functions_called=False,business_actions_submitted=0)
    dates=[r['date'].get('value') for r in report.get('modifier_instances_inputs',[])]
    if dates != [EXPECTED_DATE,EXPECTED_DATE]:
        report.update(status='error',completed=False)
        report['errors'].append(dict(stage='expected_date',observed=dates,expected=EXPECTED_DATE))
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--definition-fields',action='store_true')
    args=parser.parse_args()
    assert not args.output.exists()
    report=capture(args.definition_fields)
    with args.output.open('x',encoding='utf-8') as f:
        json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(status=report['status'],cleanup=report['cleanup'],
                         errors=report['errors'],inputs=[
                             dict(head=r['modifier_instances']['head'],bounded_prefix_only=r['modifier_instances']['bounded_prefix_only'],
                                  nodes=[{k:n.get(k) for k in ('item_va','definition_key','effect_count','definition_effects')} for n in r['modifier_instances']['nodes']])
                             for r in report.get('modifier_instances_inputs',[])]),ensure_ascii=False))
