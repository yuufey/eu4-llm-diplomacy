"""Create immutable G02 profile v2 for three additional native panel fields."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_country_person_plugin_profile import guard,relocations
from work.discover_diplomacy import PE
from work.local_config import game_exe
from work.verify_information_foreign_technology import pin,read_json,write_new

STAGE=ROOT/'work/runtime/information-province-details-20261029-001'
EXE_SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    old=ROOT/'bridge/information/profiles/province-state-memory-1374.json'
    base=read_json(old);assert base['profile_version']==1
    pe=PE(game_exe());assert hashlib.sha256(pe.data).hexdigest()==EXE_SHA
    assert base['executable']['sha256']==EXE_SHA
    profile=deepcopy(base);profile['profile_version']=2
    guards=profile['code_guards'];assert len(guards)==4
    sites=relocations(pe)
    for rva,name in ((0x1373ea0,'province_panel_update'),
            (0x13762f0,'province_culture_religion_names'),(0x136efe0,'province_religion_icon')):
        span=pe.function(rva);assert span and span[0]==rva and span[1]-rva<=65536
        guards.append(guard(pe,name,rva,span[1],sites,'REA native panel path; pure RPM projection, no native invocation'))
    evidence=[old,STAGE/'native-province-details-findings-001.json',
        STAGE/'rea-province-panel-update-001/evidence.json',
        STAGE/'rea-province-panel-prepare-001/evidence.json',
        STAGE/'rea-province-panel-helper-efe0-001/evidence.json']
    for path in evidence[-3:]:
        assert read_json(path)['subject']['digest']['sha256']==EXE_SHA
        assert read_json(path.parent/'run.json')['database_unchanged'] is True
    profile['source_evidence'] += [pin(path) for path in evidence]
    profile['layout_dependencies']=[pin(ROOT/row['path']) for row in base['layout_dependencies']]
    profile['layout_dependencies'] += [pin(ROOT/'bridge/information'/name) for name in (
        'province_identity_memory.py','province_scalar_memory.py','province_detail_memory.py')]
    profile['layout'].update(culture_definition_pointer='0x440',culture_name_String32='0x68',
        religion_definition_pointer='0x448',religion_name_String32='0xb0',religion_icon_i32='0x570',
        autonomy_current_i32='0x428',autonomy_lower_i32='0x2df0',autonomy_upper_i32='0x2df4')
    profile['semantics']['supported_fields'] += ['G02.culture','G02.religion','G02.autonomy']
    profile['semantics'].update(clear_bit='unknown; none of the five fields read; not invisibility',
        name_semantics='copied EU4Escape name cache, without owner-acceptance color prefix or full tooltip',
        religion_icon='signed i32 setter argument, not an actual rendered frame',
        autonomy='max(0,min(max(current,lower),upper)); integer percent thousandths; native clamp order preserved',
        gaps=['complete province discovery/visibility rules','unowned and special country references',
            'development/resource/center of trade','full culture/religion labels and tooltips',
            'cache freshness and atomic snapshot'])
    output=ROOT/'bridge/information/profiles/province-state-memory-1374-v2.json'
    write_new(output,profile)
    write_new(STAGE/'province-profile-build-001.json',{'status':'created','profile':pin(output),
        'builder':pin(Path(__file__).resolve()),'guards':len(guards),
        'guard_bytes_per_boundary':sum(len(bytes.fromhex(row['bytes'])) for row in guards),
        'prior_profile':pin(old),'game_reads':False,'game_controls':False})
    print(pin(output))


if __name__=='__main__':main()
