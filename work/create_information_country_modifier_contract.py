"""Freeze the observed country modifier-instance storage contract."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe

OLD=ROOT/'work/runtime/information-military-modifiers-20261027-001'
STAGE=ROOT/'work/runtime/information-country-records-20261027-001'
SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'

def pin(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=h.hexdigest())

def main():
    pe=PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest()==SHA
    source_names=('active-military-modifiers-source-003.json',
                  'active-military-modifiers-source-005.json',
                  'active-military-modifiers-source-006.json')
    rea=[]
    for name in ('rea-modifier-instance-accessor-001','rea-modifier-instance-writer-001',
                 'rea-modifier-instance-serialize-fields-001'):
        run=json.loads((OLD/name/'run.json').read_text(encoding='utf-8'))
        assert run['status']=='completed' and run['exit_code']==0 and run['database_unchanged'] is True
        assert run['cleanup']['status']=='complete'
        ep=OLD/name/'evidence.json'
        assert ep.stat().st_size<10000000
        evidence=json.loads(ep.read_text(encoding='utf-8'))
        rea.append(dict(evidence_id=evidence['evidence_id'],evidence=pin(ep),run=pin(OLD/name/'run.json')))
    guards=[]
    for name,start,end in (('country_list_writer',0x2E0076,0x2E00D9),
                           ('list_iterator',0xC0170,0xC0181),
                           ('instance_fields_writer',0xB359E0,0xB35C1A),
                           ('definition_effects_writer',0x8E67C0,0x8E6855)):
        raw=pe.bytes_at(start,end-start)
        guards.append(dict(name=name,rva=hex(start),end_rva_exclusive=hex(end),
                           bytes=len(raw),raw_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest()))
    d=dict(schema='information_country_modifier_storage_contract.v1',
           evidence_kind='ordinary_PE_plus_accepted_REA_static_not_runtime',
           target=dict(version='1.37.4',exe_sha256=SHA,image_base=hex(pe.base)),
           layout=dict(country_list_head_offset='0x1f0',node_item_offset='0x0',
                       node_next_offset='0x10',node_width=24,instance_width=80,
                       instance_vtable_rva='0x1ce7f08',definition_pointer_offset='0x30',
                       definition_vtable_rva='0x1c42ae0',definition_key_offset='0x158',
                       sso_length_offset='0x10',sso_capacity_offset='0x18',sso_inline_capacity=15,
                       start_date_raw_offset='0x40',date_raw_offset='0x44',
                       default_date_raw='0x29c77f8',
                       flags={'ruler_modifier':'0x48','parliament_modifier':'0x49',
                              'permanent':'0x4a','hidden':'0x4b'},
                       effect_values_pointer_offset='0x58',effect_count_offset='0x64',
                       effect_pair_stride=8,effect_index_width=4,effect_raw_width=4,
                       effect_raw_signed=True,modifier_manager_global_rva='0x2358060',
                       modifier_record_stride='0x60',modifier_selector_offset='0x50'),
           semantics=dict(population='records present in the direct country modifier-instance list',
                          key='definition stable script identifier serialized under modifier token 0x2968',
                          order='native list order, including duplicate definition keys',
                          start_date='signed raw native date serialized under start_date token 0x28e4',
                          date='signed raw native date serialized under date token 0x284d; expiry consumer proof tracked separately',
                          default_date='constructor default omitted by serializer; do not call this a genuine start date',
                          effects='definition signed numeric entries and native selector IDs; not final effective country attributes'),
           guards=guards,ordinary_sources=[pin(OLD/n) for n in source_names],accepted_REA=rea,
           unresolved=['source-specific activation and removal conditions',
                       'all aggregate/idea/religion/province modifier populations',
                       'localized display names and descriptions',
                       'effect units by type and full military category selection',
                       'cache freshness and main-thread atomicity'],
           RPM=False,native_calls=0)
    STAGE.mkdir(exist_ok=True,parents=True)
    p=STAGE/'country-modifiers-source-contract-001.json'
    with p.open('x',encoding='utf-8') as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(pin(p),ensure_ascii=False))

if __name__=='__main__':main()
