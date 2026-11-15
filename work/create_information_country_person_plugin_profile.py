"""Pin the exact vanilla/plugin64 person-name alternatives without a blind mask."""
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
EXE_SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'
PLUGIN_SHA='a73a8b6c82e620fc7d577bdb64df731b779a72bb43c2363a11ed12be23a9d819'
# These windows cover the reviewed normal paths across chained pdata fragments.
# Allocation and exception callees are not claimed to have been closed.
PLUGIN_RANGES=(('name_hook',0x3dd84,0x3dd98),('name_callback',0x38410,0x38883),
    ('plugin_string_append_B7C0',0xb7c0,0xb8bb),
    ('plugin_string_append_A5C0',0xa5c0,0xa643),
    ('plugin_string_concat_caller_A650',0xa650,0xa7c8),
    ('plugin_string_concat_7E30',0x7e30,0x7f4e))


def relocations(pe):
    found=[]
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
                if entry>>12:found.append(page+(entry&0xfff))
            offset+=size
    return found


def guard(pe,name,begin,end,reloc,basis):
    sites=[r for r in reloc if begin<=r<end]
    assert not sites,(name,sites)
    raw=pe.bytes_at(begin,end-begin);assert len(raw)==end-begin
    return {'name':name,'rva':hex(begin),'end_rva_exclusive':hex(end),'bytes':raw.hex(),
        'sha256':hashlib.sha256(raw).hexdigest(),'aslr_invariant':True,'relocation_sites':[],
        'range_basis':basis}


def main():
    exe=game_exe();plugin=exe.parent/'plugins'/'plugin64.dll'
    assert sha(exe)==EXE_SHA and sha(plugin)==PLUGIN_SHA and plugin.stat().st_size==538112
    pe,dll=PE(exe),PE(plugin);assert pe.base==0x140000000 and dll.base==0x180000000
    original=ROOT/'bridge/information/profiles/country-person-memory-1374.json'
    profile=deepcopy(load(original));assert profile['profile_version']==1
    profile['profile_version']=2;profile['supersedes']=pin(original)
    old=next(x for x in profile['code_guards'] if x['name']=='function_a4b130')
    begin,end=int(old['rva'],0),int(old['end_rva_exclusive'],0)
    assert begin==0xa4b130 and begin<0xa4b2fc<0xa4b30a<end
    unchanged=[x for x in profile['code_guards'] if x['name']!='function_a4b130']
    reloc=relocations(pe)
    for name,start,stop in (('person_name_before_runtime_patch',begin,0xa4b2fc),
            ('person_name_after_runtime_patch',0xa4b30a,end)):
        unchanged.append(guard(pe,name,start,stop,reloc,'Unmodified side of the positively attested 14B runtime patch window'))
    assert sum(len(bytes.fromhex(x['bytes'])) for x in unchanged)==sum(
        len(bytes.fromhex(x['bytes'])) for x in profile['code_guards'])-14
    profile['code_guards']=unchanged
    assert len(PLUGIN_RANGES)>2,'normal string helper ranges must be reviewed first'
    dll_reloc=relocations(dll)
    guards=[guard(dll,name,start,stop,dll_reloc,
        'Bounded ordinary PE bytes; normal paths reviewed separately; not REA or observed execution')
        for name,start,stop in PLUGIN_RANGES]
    opt=dll.u32(0x3c)+24;image_size=dll.u32(opt+56)
    assert image_size==561152
    patch=pe.bytes_at(0xa4b2fc,14)
    assert patch.hex()=='488d55b848837dd010480f4355b8'
    profile['name_runtime']={'patch_rva':'0xa4b2fc','original_bytes':patch.hex(),
        'plugin':{'configured_relative_path':'plugins/plugin64.dll','file_bytes':538112,
            'sha256':PLUGIN_SHA,'preferred_image_base':hex(dll.base),'image_size':image_size,
            'hook_rva':'0x3dd84','callback_rva':'0x38410','return_rva':'0xa4b316',
            'slots_rva':'0x820a8','header_bytes':dll.data[:1024].hex(),'code_guards':guards}}
    profile['layout_dependencies']=[pin(ROOT/x['path']) for x in profile['layout_dependencies']]
    profile['layout_dependencies'].append(pin(ROOT/'bridge/information/person_name_runtime_memory.py'))
    additions=('plugin-name-hook-identity-001.json','plugin-name-hook-ordinary-001.json',
        'plugin-name-callback-ordinary-001.json','plugin64-helper-exceptions-001.json',
        'plugin64-helper-normal-paths-001/attempt-002/plugin-helper-normal-paths-001.json','probe_person_hook_inputs_002.json',
        'probe_person_hook_inputs_readback_004.json')
    profile['source_evidence'].extend(pin(STAGE/name) for name in additions)
    profile['semantics']['name_runtime']={
        'layouts':['vanilla','plugin64'],'runtime_image_full_hash_observed':False,
        'plugin_file_identity_required':True,'runtime_verified':'patch, pinned header/code ranges and return/callback slots, on both data passes',
        'right_operand':'ASCII space + dynasty cache bytes',
        'plugin_selected_branch':'len(right)>=3 and right[1]==0xbf => dynasty[1:]+base, no added space',
        'plugin_other_branch':'base+ASCII space+dynasty',
        'plugin_output_supported_bytes':254,'callback_invoked':False,
        'complete_UI_label':False,'unfollowed_helpers':'allocator/exception/CRT implementation details remain separate from normal byte-copy inference'}
    output=ROOT/'bridge/information/profiles/country-person-memory-1374-v2.json'
    raw=(json.dumps(profile,ensure_ascii=False,indent=2)+'\n').encode('utf-8');assert len(raw)<=256*1024
    with output.open('xb') as stream:stream.write(raw)
    assert sha(exe)==EXE_SHA and sha(plugin)==PLUGIN_SHA
    receipt={'status':'created','profile':pin(output),'builder':pin(Path(__file__).resolve()),
        'parent_profile':pin(original),'main_guard_count':len(unchanged),
        'main_guard_bytes_per_boundary':sum(len(bytes.fromhex(x['bytes'])) for x in unchanged),
        'plugin_guard_count':len(guards),'plugin_guard_bytes_per_pass':sum(len(bytes.fromhex(x['bytes'])) for x in guards),
        'positive_patch_validation':True,'game_access':False,'new_rea_query':False}
    write(STAGE/'person-profile-build-002.json',receipt);print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
