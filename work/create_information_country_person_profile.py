"""Pin the B23 S04 sources and exact readonly code/data guard ranges."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_foreign_technology_profile import pin,sha,load,write
from work.discover_diplomacy import PE
from work.local_config import game_exe

STAGE=ROOT/'work/runtime/information-country-person-20261029-001'
OLD=ROOT/'work/runtime/information-foreign-visibility-20261029-001'
PREVIOUS=ROOT/'work/runtime/information-foreign-scalars-20261029-001'
EXE='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    assert sha(game_exe())==EXE
    pe=PE(game_exe());old=ROOT/'bridge/information/profiles/foreign-technology-memory-1374-v2.json'
    original=load(old)
    functions=(0xefd2c0,0xa4c160,0xa4b130,0xa4f050,0x3d7b40,
        0x40a700,0x7ac9e0,0x7ac4f0,0x7abf90,0x7b3980,0x45b710,
        0xa4e140,0xcfe10,0x14c8020,0xa52350)
    ranges=[]
    for address in functions:
        span=pe.function(address);assert span and span[0]==address and span[1]-address<65536
        ranges.append((f'function_{address:x}',address,span[1],'.pdata bounded range; semantics from retained REA/ordinary evidence'))
    ranges.extend((('constant_bool_true',0x8f440,0x8f443,'ordinary exact3B'),
        ('union_type_getter_window',0x3d7a20,0x3d7b40,'explicit288B window; no .pdata entry, next selected known start is upper limit'),
        ('constant_bool_false',0x8f450,0x8f453,'ordinary exact3B'),
        ('claim_getter',0xa559c0,0xa559cc,'ordinary exact12B, Ghidra has no procedure here'),
        ('date_year_leaf',0xcfd70,0xcfe04,'ordinary range ends at verified RET; no .pdata entry'),
        ('type_comparison',0x1a350ac,0x1a350d3,'ordinary comparison helper through RET'),
        ('calendar_month_lengths',0x1c3a5c8,0x1c3a5f8,'immutable 12xi32 data, not executable code')))
    reloc=[]
    for section in pe.sections:
        if section['name']!='.reloc':continue
        raw=pe.bytes_at(section['rva'],section['size']);assert len(raw)<1024*1024
        offset=0
        while offset+8<=len(raw):
            page,size=struct.unpack_from('<II',raw,offset)
            if page==size==0:break
            assert 8<=size<=len(raw)-offset and size%2==0
            for at in range(offset+8,offset+size,2):
                entry=struct.unpack_from('<H',raw,at)[0]
                if entry>>12:reloc.append(page+(entry&0xfff))
            offset+=size
    guards=deepcopy(original['code_guards'])
    for name,begin,end,classification in ranges:
        assert not any(begin<=item<end for item in reloc)
        raw=pe.bytes_at(begin,end-begin);assert len(raw)==end-begin
        guards.append({'name':name,'rva':hex(begin),'end_rva_exclusive':hex(end),
            'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
            'aslr_invariant':True,'relocation_sites':[],'range_basis':classification})
    evidence=[OLD/'rea-ui-efd2c0-001/evidence.json',OLD/'rea-ui-f0ed60-001/evidence.json',
        PREVIOUS/'rea-person-display-name-001/evidence.json',PREVIOUS/'rea-person-interregnum-001/evidence.json']
    for directory in ('rea-ruler-union-gate-001','rea-subject-type-gate-001','rea-country-government-001',
        'rea-property-value-pointer-001','rea-property-type-001','rea-person-date-value-001',
        'rea-character-skill-text-001','rea-ruler-tooltip-001'):
        path=STAGE/directory/'evidence.json';value=load(path)
        assert value['subject']['digest']['sha256']==EXE and value['operation']=='procedure_pseudo_code'
        assert load(STAGE/directory/'run.json')['database_unchanged'] is True
        evidence.append(path)
    evidence.extend(STAGE/name for name in ('person-small-helpers-ordinary-001.json',
        'person-constant-methods-ordinary-001.json','person-date-helpers-ordinary-001.json',
        'heir-claim-getter-ordinary-001.json','union-type-getter-ordinary-001.json',
        'owned-age-verified-001/receipt.json'))
    owned=load(STAGE/'owned-age-verified-001/receipt.json')
    assert owned['status']=='passed' and owned['matches']==owned['actual_return_count']==owned['case_count']==1049
    assert owned['exitcode']==0 and owned['VirtualFree'] is True and owned['game_access'] is False
    dependencies=[old]+[ROOT/'bridge/information'/name for name in (
        'country_reference_memory.py','country_view_admission_memory.py','foreign_country_memory.py',
        'foreign_technology_capture.py','country_faith_capture.py','country_person_memory.py',
        'country_ruler_union_memory.py','person_panel_conditions_memory.py','person_name_memory.py',
        'person_age_memory.py','person_claim_memory.py')]+[ROOT/'bridge/native_text.py']
    profile={'profile_id':'country-person-memory-1374','profile_version':1,'game_version':'1.37.4',
        'executable':original['executable'],'observer':'FRA','source_evidence':[pin(path) for path in evidence],
        'layout_dependencies':[pin(path) for path in dependencies],'code_guards':guards,
        'observer_role_layout':original['observer_role_layout'],'predicate_layout':original['predicate_layout'],
        'layout':{'country_ruler':'0x1280','country_heir':'0x1298','country_government_owner':'0x1420',
            'person_owner_country_fullref':'0x20','person_base_name_String32':'0x28',
            'ruler_skills_i32':['0x48','0x4c','0x50'],'person_dynasty':'0x68','person_birth_date_i32':'0x70',
            'person_regency':'0x78','person_claim_i32':'0x148','dynasty_name_String32':'0x8',
            'claim_weak_threshold_rva':'0x233e1c4','claim_strong_threshold_rva':'0x233f76c',
            'government_attribute_base':'0x38','heir_panel_property_slot':'0xb8',
            'heir_special_name_property_slot':'0xa8','monarchists_property_slot':'0x1f8'},
        'semantics':{'actual_UI_observed':False,'native_function_invoked':False,
            'physical_player_equals_observer_required':False,'country_view_basis':'projected_to_FRA',
            'heir_panel_true':'character/name/info branch; false hides this panel, not proof of no heir',
            'name':'normal regency-pointer-zero a4b130 name component; not full UI title/label',
            'age':'a4e140 projection independently checked against copied code in an owned process; ruler uses a4c160 minimum known-birth guard',
            'claim':'current getter cache and runtime thresholds, not predicted succession outcome',
            'personal_union':'only the selected country ruler-label branch; no complete list of subjects',
            'dynasty':'independent normal-name suffix components, not stable dynasty IDs',
            'complete':False,'limitations':['regency name rendering','special complete heir labels','full person tooltips',
                'global government fallback','unobserved TLS-positive path','succession disputes/opportunity predictions',
                'atomic main-thread snapshot and cache freshness']}}
    output=ROOT/'bridge/information/profiles/country-person-memory-1374.json'
    encoded=(json.dumps(profile,ensure_ascii=False,indent=2)+'\n').encode('utf-8');assert len(encoded)<=256*1024
    with output.open('xb') as stream:stream.write(encoded)
    assert sha(game_exe())==EXE
    receipt={'status':'created','profile':pin(output),'builder':pin(Path(__file__).resolve()),
        'guard_count':len(guards),'guard_bytes_per_boundary':sum(len(bytes.fromhex(x['bytes'])) for x in guards),
        'runtime_budget_bytes':512*1024,'game_access':False,'new_rea_query':False,
        'owned_age_receipt':pin(STAGE/'owned-age-verified-001/receipt.json')}
    write(STAGE/'person-profile-build-001.json',receipt);print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
