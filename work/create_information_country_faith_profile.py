"""Create the B23 primary-religion field contract from retained evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_foreign_technology_profile import sha,pin,load,write
from work.discover_diplomacy import PE
from work.local_config import game_exe

STAGE=ROOT/'work/runtime/information-foreign-scalars-20261029-001'
OLD=ROOT/'work/runtime/information-foreign-visibility-20261029-001'
EXE='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    executable=game_exe();assert sha(executable)==EXE
    pe=PE(executable)
    old_profile_path=ROOT/'bridge/information/profiles/foreign-technology-memory-1374-v2.json'
    old_profile=load(old_profile_path)
    writer_path=OLD/'rea-ui-efd2c0-001/evidence.json'
    tooltip_path=OLD/'rea-ui-f0ed60-001/evidence.json'
    copy_path=STAGE/'rea-definition-cstring-001/evidence.json'
    evidence=[load(path) for path in (writer_path,tooltip_path,copy_path)]
    for row in evidence:
        assert row['subject']['digest']['sha256']==EXE
        assert row['operation']=='procedure_pseudo_code'
    assert '"religion_icon"' in evidence[0]['raw_result']['value']
    assert '+ 0xf30)' in evidence[0]['raw_result']['value']
    assert '+ 0xb0' in evidence[1]['raw_result']['value']
    assert 'param_2[3]' in evidence[2]['raw_result']['value']
    ranges=[('primary_religion_icon_input',0xefd775,0xefd788),
            ('primary_religion_tooltip_key_input',0xf0f67d,0xf0f694),
            ('string32_c_string_copy',0x985f0,0x98610)]
    guards=deepcopy(old_profile['code_guards'])
    relocations=[]
    for section in pe.sections:
        if section['name']!='.reloc':continue
        raw=pe.bytes_at(section['rva'],section['size']);assert len(raw)<=1024*1024
        at=0
        while at+8<=len(raw):
            page,size=struct.unpack_from('<II',raw,at)
            if page==size==0:break
            assert 8<=size<=len(raw)-at and size%2==0
            for pos in range(at+8,at+size,2):
                entry=struct.unpack_from('<H',raw,pos)[0]
                if entry>>12:relocations.append(page+(entry&0xfff))
            at+=size
    for name,begin,end in ranges:
        raw=pe.bytes_at(begin,end-begin)
        assert not any(begin<=rva<end for rva in relocations)
        guards.append({'name':name,'rva':hex(begin),'end_rva_exclusive':hex(end),
            'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
            'aslr_invariant':True,'relocation_sites':[],
            'evidence_class':'ordinary PE bytes; semantic chain from retained REA'})
    contract={'schema':'information.country_faith.field_contract.v1','status':'bounded_static_contract',
        'binary_sha256':EXE,'image_base':'0x140000000',
        'evidence':[dict(pin(path),evidence_id=row['evidence_id'])
                    for path,row in zip((writer_path,tooltip_path,copy_path),evidence)],
        'selected_country':'view+0x138 fullref -> DB+0x118 country table; logical observer separately bound',
        'field_chain':'selected country+0xf30 -> primary religion definition; +0xb0 String32 key; +0x570 u32 icon request',
        'field_conditions':'primary religion icon is populated before the later own-country branch; no extra primary field gate in reviewed writer',
        'string_contract':'REA985f0 chooses inline/heap at capacity>=16 then copies through first NUL; bounded reader additionally validates stored length/capacity',
        'native_invocations':False,'actual_UI_observed':False,
        'admission':'retained SelectCountry compound projected to FRA; not the native current-client execution',
        'guard_ranges':[{'name':name,'rva':hex(begin),'end_rva_exclusive':hex(end)} for name,begin,end in ranges],
        'unresolved':['Full localized religion tooltip, bonuses and secondary faith are not exported',
                      'A numeric religion database ID is not inferred from the icon frame',
                      'Main-thread atomicity and native cache freshness are not proven',
                      'Person name rendering has additional regency/dynasty/personal-union conditions; it is not closed by this faith contract']}
    contract_path=STAGE/'faith-field-contract-001.json';write(contract_path,contract)
    profile={'profile_id':'country-faith-memory-1374','profile_version':1,'game_version':'1.37.4',
        'executable':deepcopy(old_profile['executable']),'observer':'FRA',
        'target_scope':'resolved_country_including_observer',
        'source_evidence':[pin(path) for path in (writer_path,tooltip_path,copy_path,contract_path)],
        'layout_dependencies':[pin(old_profile_path),pin(ROOT/'bridge/information/foreign_country_memory.py'),
            pin(ROOT/'bridge/information/country_faith_memory.py')],
        'code_guards':guards,'observer_role_layout':deepcopy(old_profile['observer_role_layout']),
        'predicate_layout':deepcopy(old_profile['predicate_layout']),
        'field_layout':{'field_id':'S02.faith','country_primary_religion':'0xf30',
            'definition_key':'0xb0','definition_icon_frame_request':'0x570',
            'string32':{'width':32,'length_offset':16,'capacity_offset':24,'inline_capacity_max':15},
            'max_key_bytes':128},
        'semantics':{'actual_UI_observed':False,'native_function_invoked':False,
            'physical_player_equals_observer_required':False,
            'visibility_basis':'native_country_view_predicate_projected_to_observer',
            'scope':'current primary religion key and icon frame request only; partial S02.faith'}}
    output=ROOT/'bridge/information/profiles/country-faith-memory-1374.json';write(output,profile)
    assert sha(executable)==EXE
    receipt={'status':'created','profile':pin(output),'contract':pin(contract_path),
        'builder':pin(Path(__file__).resolve()),'code_guard_bytes':sum(len(bytes.fromhex(x['bytes'])) for x in guards),
        'game_access':False,'rea_queries_repeated':False}
    write(STAGE/'faith-profile-build-001.json',receipt)
    print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
