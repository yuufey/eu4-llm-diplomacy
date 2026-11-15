"""Pin the observed loaded PE ImageBase as an explicit ASLR condition."""
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_foreign_technology_profile import pin,sha,load,write

STAGE=ROOT/'work/runtime/information-country-person-20261029-001'


def main():
    old=ROOT/'bridge/information/profiles/country-person-memory-1374-v2.json'
    assert sha(old)=='9eda15cbfb46a13183c4d898960138c9facb5aa39ea9c0aff25248e8311f1072'
    comparison=load(STAGE/'plugin-header-rebase-comparison-001.json')
    assert comparison['status']=='passed_offline_classification' and len(comparison['rows'])==4
    assert all(row['other_1016_bytes_exactly_match'] for row in comparison['rows'])
    profile=deepcopy(load(old));assert profile['profile_version']==2
    profile['profile_version']=3;profile['supersedes']=pin(old)
    plugin=profile['name_runtime']['plugin'];header=bytes.fromhex(plugin['header_bytes'])
    pe=int.from_bytes(header[0x3c:0x40],'little');offset=pe+24+24
    assert pe==0x110 and offset==0x140 and len(header)==1024
    assert int.from_bytes(header[offset:offset+8],'little')==int(plugin['preferred_image_base'],0)==0x180000000
    plugin['header_image_base_offset']=hex(offset)
    profile['layout_dependencies']=[pin(ROOT/row['path']) for row in profile['layout_dependencies']]
    profile['source_evidence'].append(pin(STAGE/'plugin-header-rebase-comparison-001.json'))
    semantics=profile['semantics']['name_runtime']
    semantics['runtime_verified']='patch, exact header with ImageBase positively checked against jump-derived base, pinned code and return/callback slots on both data passes'
    semantics['header_rebase_condition']='observed ImageBase==jump-derived plugin base; every other header byte matches the pinned file; no blind mask'
    output=ROOT/'bridge/information/profiles/country-person-memory-1374-v3.json'
    raw=(json.dumps(profile,ensure_ascii=False,indent=2)+'\n').encode('utf-8');assert len(raw)<=256*1024
    with output.open('xb') as stream:stream.write(raw)
    receipt={'status':'created','profile':pin(output),'parent_profile':pin(old),
        'builder':pin(Path(__file__).resolve()),'header_image_base_offset':hex(offset),
        'loaded_image_base_must_match_jump_derived_base':True,'all_other_header_bytes_exact':True,
        'game_access':False,'new_rea_query':False}
    write(STAGE/'person-profile-build-003.json',receipt);print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
