"""Pin G02 development, resource identity, and center-of-trade native paths."""
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
STAGE=ROOT/'work/runtime/information-province-production-20261029-001'
SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    old=ROOT/'bridge/information/profiles/province-state-memory-1374-v2.json'
    profile=deepcopy(read_json(old));assert profile['profile_version']==2
    with game_exe().open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==SHA
    pe=PE(game_exe());sites=relocations(pe);profile['profile_version']=3
    assert len(profile['code_guards'])==7
    for rva,name in ((0xa0cff0,'province_development_total'),(0xa0d520,'province_effective_tax'),
            (0xa0de60,'province_effective_production'),(0xa0d9c0,'province_effective_manpower'),
            (0x1379450,'province_resource_tooltip'),(0x1f7890,'tradegoods_localization_key'),
            (0x1390750,'province_center_state_update'),(0x138db50,'province_center_control_binding'),
            (0x1386380,'province_center_sprite_key')):
        span=pe.function(rva);assert span and span[0]==rva and span[1]-rva<=65536,(hex(rva),span)
        profile['code_guards'].append(guard(pe,name,rva,span[1],sites,
            'Bounded pdata code; semantics retained as REA separately, not a native function call'))
    assert pe.bytes_at(0xa16960,8)==bytes.fromhex('488b8158040000c3')
    profile['code_guards'].append(guard(pe,'province_resource_definition_getter',0xa16960,0xa16968,sites,
        'Exact eight-byte leaf getter through RET; ordinary bytes, no fabricated pdata extent'))
    profile['source_evidence'] += [pin(old),pin(STAGE/'native-development-contract-001.json'),
        pin(STAGE/'native-resource-cot-contract-001.json')]
    profile['layout_dependencies']=[pin(ROOT/row['path']) for row in profile['layout_dependencies']]
    profile['layout_dependencies'] += [pin(ROOT/'bridge/information'/name) for name in (
        'province_development_memory.py','province_resource_memory.py','province_cot_memory.py')]
    profile['layout'].update(development_tax_i32='0x3e4',development_production_i32='0x3e8',
        development_manpower_i32='0x3e0',owner_tribal_pointer='0x9a78',owner_tribal_province_id='0x14b8',
        tribal_components_i32=['0x1c','0x20','0x24'],resource_definition_pointer='0x458',
        resource_localization_key_String32='0x18',resource_icon_index_i32='0x78',
        center_of_trade_pointer='0x960',center_definition_pointer='0x8',
        center_kind_i32='0x10',center_level_i32='0x14')
    profile['semantics']['supported_fields'] += ['G02.development','G02.resource','G02.center_of_trade']
    profile['semantics'].update(clear_bit='unknown; none of the eight fields read, not a claim of invisibility',
        development='effective component bases plus conditional owner tribal bonuses, truncation toward zero and signed-i32 wrap; total raw thousandths',
        resource='native localization key and icon index; no translated name or actual frame requested/rendered claim',
        center='NULL ->presentFalse/level0; otherwise positive level plus kind and derived sprite key, no rendering claim',
        gaps=['full province discovery/visibility','unowned/special owner references',
            'translated resource name and latent resources','complete labels/tooltips and center costs/permissions',
            'cache freshness and atomicity'])
    output=ROOT/'bridge/information/profiles/province-state-memory-1374-v3.json';write_new(output,profile)
    write_new(STAGE/'province-profile-build-001.json',{'status':'created','profile':pin(output),
        'builder':pin(Path(__file__).resolve()),'guards':len(profile['code_guards']),
        'guard_bytes_per_boundary':sum(len(bytes.fromhex(row['bytes'])) for row in profile['code_guards']),
        'prior_profile':pin(old),'game_reads':False,'game_controls':False})
    print(pin(output))


if __name__=='__main__':main()
