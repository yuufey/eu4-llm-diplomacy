"""Bind the current country-war index, native side vectors and shared observer IDs."""
from copy import deepcopy
import hashlib
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_country_person_plugin_profile import guard,relocations
from work.discover_diplomacy import PE
from work.local_config import game_exe
from work.verify_information_foreign_technology import pin,read_json,write_new

STAGE=ROOT/'work/runtime/information-country-wars-20261029-001'
OLD=ROOT/'work/runtime/information-country-territory-wars-20261029-001'
EARLIER=ROOT/'work/runtime/information-foreign-scale-20261029-001'
SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    with game_exe().open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==SHA
    original=ROOT/'bridge/information/profiles/country-scale-memory-1374-v2.json'
    profile=deepcopy(read_json(original));assert profile['profile_version']==2
    pe=PE(game_exe());sites=relocations(pe);evidence=[]
    for source,rva,label in (
        (EARLIER/'rea-country-war-membership-001/evidence.json',0x3f7570,'country_opponent_war_index_consumer'),
        (EARLIER/'rea-war-association-handle-001/evidence.json',0xd942f0,'war_opposite_side_vectors'),
        (OLD/'rea-current-war-constructor-001/evidence.json',0xd85520,'current_war_constructor'),
    ):
        row=read_json(source);assert row['subject']['digest']['sha256']==SHA
        assert row['operation']=='procedure_pseudo_code'
        span=pe.function(rva);assert span and span[0]==rva
        evidence.append(dict(pin(source),evidence_id=row['evidence_id'],rva=hex(rva),
            preferred_va=hex(0x140000000+rva),end_rva_exclusive=hex(span[1])))
        profile['code_guards'].append(guard(pe,label,rva,span[1],sites,
            'ordinary PE bytes; separate REA semantic evidence, no runtime invocation'))
    symbols=read_json(STAGE/'registry-code-symbols-001/registry-code-symbols-001.json')
    dll_pin={key:symbols['inputs']['dll'][key] for key in ('path','bytes','sha256')}
    assert pin(ROOT/dll_pin['path'])==dll_pin
    dll=PE(ROOT/dll_pin['path']);header=bytes(dll.data[:1024])
    nt=struct.unpack_from('<I',header,0x3c)[0]
    descriptor={'module_file':dll_pin,'image_size':struct.unpack_from('<I',header,nt+0x50)[0],
        'header_raw_hex':header.hex(),'header_image_base_offset':nt+0x30,
        'preferred_image_base':hex(dll.base),'count_rva':0x731678,
        'entries_rva':0x731680,'creation_rva':0xcf2720,'code_guards':[]}
    for key in ('peace_query_register_war','peace_context_query_run'):
        matches=symbols['symbol_matches'][key];assert len(matches)==1
        row=matches[0];assert row['pdata_status']=='exact_start_match'
        assert row['base_relocation_sites']==[]
        extent=row['function_range'];code=row['code_bytes']
        begin=int(extent['begin_rva'],0);end=int(extent['end_rva_exclusive'],0)
        assert dll.bytes_at(begin,end-begin).hex()==code['raw_hex']
        descriptor['code_guards'].append({'rva':hex(begin),'end_rva_exclusive':hex(end),
            'bytes':code['raw_hex'],'sha256':code['sha256'],'relocation_offsets':[]})
    supporting=[STAGE/'registry-code-symbols-001/registry-code-symbols-001.json',
        STAGE/'registry-lifecycle-source-001/registry-lifecycle-source-001.json',
        STAGE/'private-war-registry-receipt-001.json',
        STAGE/'current-war-id-query-001.json',
        STAGE/'registry-after-query-001/private-war-registry-receipt-001.json']
    assert all(p.is_file() for p in supporting)
    contract={'schema':'information.country_wars.native_contract.v1',
        'status':'bounded_static_and_readonly_runtime_contract','binary_sha256':SHA,
        'preferred_image_base':'0x140000000','rea':evidence,
        'supporting_evidence':[pin(p) for p in supporting],
        'country_index':{'pointer_offset':'0x1548','count_offset':'0x1554',
            'stride':16,'other_country_slot_offset':0,'war_reference_offset':8,
            'at_war_flag_offset':'0x289b','at_war_flag_consumer':'a85fa0 CV_REBEL_PROGRESS_NONE_AT_WAR',
            'max_rows':256,'max_distinct_wars':32},
        'war_object':{'vtable_rva':'0x1d1f6f0','marker_offset':8,'marker':'0x165',
            'side_vector_header_offsets':['0x48','0x78'],'fullref_width':8,
            'native_function_invoked':False},
        'checks':['target and observer complete fullrefs revalidated against the country database',
            'both nonempty side vectors resolve exact country fullrefs and have unique members',
            'target belongs to exactly one side; its opponent index equals the opposite-side union',
            'opponent reverse index points to the same current war',
            'member names require the real full country scan and per-member FRA view admission',
            'shared ID requires the pinned loaded DLL, exact header/code/epoch and matching registry reference'],
        'registry':{'read_only':True,'registration_invoked_by_reader':False,
            'prior_QUERY1':'one read-only FRA/BUR query; not repeated',
            'serial7':'war_1c5b10c9b19ce405_00000007',
            'identity_scope':'observer_session','lifetime_verified':False,
            'pointer_reuse_guard':False,'missing_or_unregistered':'unknown ID while independently verified membership remains'},
        'public_scope':'current_country_opponent_index','complete':False,
        'global_membership_verified':False,'actual_UI_observed':False,
        'unresolved':['global war container and wars absent from this country cache',
            'object lifetime, pointer reuse, registry retirement and generation identity',
            'side roles and leaders, names, dates, goals, scores and full field-specific UI visibility',
            'cache writer/freshness and external two-pass non-atomicity']}
    target=STAGE/'native-country-wars-contract-001.json';write_new(target,contract)
    profile['profile_version']=3;profile['supersedes']=pin(original)
    profile['observer_registry']=descriptor
    profile['source_evidence'] += [pin(original),pin(target)]+[pin(ROOT/x['path']) for x in evidence]+[pin(p) for p in supporting]
    profile['layout_dependencies'] += [pin(ROOT/'bridge/information'/name) for name in (
        'country_wars_memory.py','observer_module_binding.py','observer_registry_memory.py')]
    profile['semantics']['supported_fields'].append('F01.wars')
    profile['semantics']['unimplemented_fields']=[]
    profile['semantics']['wars']='partial current-country opponent-index projection; neither global enumeration nor lifetime verification'
    output=ROOT/'bridge/information/profiles/country-scale-memory-1374-v3.json'
    write_new(output,profile)
    receipt={'status':'created','profile':pin(output),'contract':pin(target),
        'original_profile':pin(original),'builder':pin(Path(__file__).resolve()),
        'guards':len(profile['code_guards']),
        'guard_bytes':sum(len(bytes.fromhex(row['bytes'])) for row in profile['code_guards']),
        'observer_code_guard_bytes':sum(len(bytes.fromhex(row['bytes'])) for row in descriptor['code_guards']),
        'game_access':False,'native_queries_repeated':False}
    write_new(STAGE/'country-wars-profile-build-001.json',receipt);print(receipt)


if __name__=='__main__':main()
