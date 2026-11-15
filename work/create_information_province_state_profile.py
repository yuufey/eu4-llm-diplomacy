"""Pin the bounded G02 province-reference and actor-discovery implementation."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_country_person_plugin_profile import guard,relocations
from work.discover_diplomacy import PE
from work.local_config import game_exe
from work.verify_information_foreign_technology import pin,read_json,write_new,manifest_inputs,BUILD_MANIFEST

STAGE=ROOT/'work/runtime/information-next-sources-20261029-001'
EXE_SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    pe=PE(game_exe());assert hashlib.sha256(pe.data).hexdigest()==EXE_SHA
    old=ROOT/'bridge/information/profiles/foreign-technology-memory-1374-v2.json'
    base=read_json(old);assert base['executable']['sha256']==EXE_SHA
    guards=deepcopy(base['code_guards']);assert len(guards)==1
    assert guards[0]['name']=='diplomacy_country_selection'
    sites=relocations(pe)
    for rva,name in ((0xa0acf0,'province_undiscover_by_country_reference'),
            (0x1346f90,'province_view_owner_background'),(0x1347920,'province_view_selected_record')):
        span=pe.function(rva);assert span and span[0]==rva and span[1]-rva<=65536
        guards.append(guard(pe,name,rva,span[1],sites,'Bounded .pdata bytes; semantics from retained REA, not runtime invocation'))
    build=manifest_inputs(BUILD_MANIFEST)
    native_names=('peace-province-candidates.inc','peace-effect-state.inc','peace-context-query.inc')
    assert all(name in build['names'] for name in native_names)
    compiled=[ROOT/path for path in build['native']+build['copies'] if Path(path).name in native_names]
    assert len(compiled)==6
    modules=('province_reference_memory.py','province_state_memory.py','country_reference_memory.py',
        'country_view_admission_memory.py','foreign_country_memory.py','foreign_technology_capture.py')
    dependencies=[ROOT/'bridge/information'/name for name in modules]+compiled
    evidence=[old,BUILD_MANIFEST,STAGE/'province-binding-contract-001.json',
        STAGE/'province-reuse-inventory-001.json',STAGE/'native-province-findings-002.json',
        STAGE/'rea-province-bitset-a0acf0-001/evidence.json',
        STAGE/'rea-provinceview-method-48-001/evidence.json',
        STAGE/'rea-provinceview-selected-pointer-writer-001/evidence.json']
    for path in evidence[-3:]:
        value=read_json(path);assert value['subject']['digest']['sha256']==EXE_SHA
        assert read_json(path.parent/'run.json')['database_unchanged'] is True
    profile={'profile_id':'province-state-memory-1374','profile_version':1,'game_version':'1.37.4',
        'observer':'FRA','executable':base['executable'],'code_guards':guards,
        'source_evidence':[pin(path) for path in evidence],
        'layout_dependencies':[pin(path) for path in dependencies],
        'observer_role_layout':base['observer_role_layout'],'predicate_layout':base['predicate_layout'],
        'layout':{'world_global_rva':'0x233fe58','province_count_begin':'0x1c90',
            'province_count_end':'0x1c98','province_records_pointer':'0x1ca8','province_record_stride':'0x2e10',
            'province_id_i32':'0x20','province_discovery_u32_array_pointer':'0x5e0',
            'owner_country_fullref':'0x468','controller_country_fullref':'0x470',
            'country_database_global_rva':'0x233d8b0','country_table_pointer':'0x118',
            'country_table_count_i32':'0x124','country_fullref':'0x20'},
        'semantics':{'supported_fields':['G02.owner','G02.controller'],
            'observer_role':'Human count1 and FRA controller0, separately from physical UI ref',
            'owner_snapshot_country_anchor':'FRA is the observer identity; outer object and replay closure bind province ID',
            'positive_admission':'FRA self identity/admission and observer-slot province discovery bit is1 on both passes',
            'clear_bit':'unknown; no owner/controller read; not a claim of invisibility',
            'physical_UI_cached_flags_used_to_admit':False,'physical_player_equals_FRA_required':False,
            'value':'TAG from a supported full64 country ref, bounded DB slot and exact country+20 echo',
            'unit':'country_tag','scale':1,'atomic_snapshot':False,'actual_UI_observed':False,
            'native_function_invoked':False,'complete':False,
            'gaps':['complete province discovery/visibility rules','unowned and special references',
                'development/culture/religion/autonomy/resource/center of trade','cache freshness and atomic snapshot']},
        'limits':{'read_bytes':512*1024,'read_calls':32768,'single_read_bytes':65536,
            'province_count':65536,'province_id_min':1,'province_id_max':65535,'country_slots':4096}}
    output=ROOT/'bridge/information/profiles/province-state-memory-1374.json'
    raw=(json.dumps(profile,ensure_ascii=False,indent=2)+'\n').encode('utf-8');assert len(raw)<=256*1024
    with output.open('xb') as stream:stream.write(raw)
    write_new(STAGE/'province-profile-build-001.json',{'status':'created','profile':pin(output),
        'builder':pin(Path(__file__).resolve()),'guards':len(guards),
        'guard_bytes_per_boundary':sum(len(bytes.fromhex(x['bytes'])) for x in guards),
        'manifest':build['manifest'],'native_copy_source_count':125,
        'game_reads':False,'game_controls':False,'new_rea_query':False})
    print(json.dumps({'status':'created','profile':pin(output),'guard_count':len(guards)},ensure_ascii=False))


if __name__=='__main__':main()
