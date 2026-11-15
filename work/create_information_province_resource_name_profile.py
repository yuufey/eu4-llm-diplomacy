"""Pin cached resource-name lookup without claiming a rendered UI string."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.local_config import game_exe
from work.verify_information_foreign_technology import pin,read_json,write_new

STAGE=ROOT/'work/runtime/information-province-resource-localization-20261029-001'
PREVIOUS=ROOT/'work/runtime/information-province-production-20261029-001'
SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'


def main():
    with game_exe().open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==SHA
    old=ROOT/'bridge/information/profiles/province-state-memory-1374-v3.json'
    assert pin(old)['sha256']=='77e82815ad485835202dd52f708c04065b089c37791d16be4157e5b2d4d01010'
    profile=deepcopy(read_json(old));assert profile['profile_version']==3
    local_path=ROOT/'bridge/information/profiles/localization-memory-1374.json'
    local=read_json(local_path)
    assert pin(local_path)['sha256']=='8052f51329598bb3baea137dd7694baba53ace7ecef970773a06cfafe0aef6cb'
    assert local['executable']['sha256']==SHA and local['profile_version']==1
    existing={int(row['rva'],0) for row in profile['code_guards']}
    for row in local['code_guards']:
        assert int(row['rva'],0) not in existing
        copied=deepcopy(row);copied['name']='resource_name_'+copied['name']
        profile['code_guards'].append(copied)
    references=[pin(local_path)]
    for row in local['source_evidence'].values():
        evidence=pin(ROOT/row['path']);assert evidence['sha256']==row['sha256']
        references.append(evidence)
    tradegoods=PREVIOUS/'rea-tradegoods-name-001/evidence.json'
    evidence=read_json(tradegoods);assert evidence['subject']['digest']['sha256']==SHA
    contract={'schema':'information.province_resource_name.native_contract.v1',
        'status':'bounded_static_contract','binary_sha256':SHA,'preferred_image_base':'0x140000000',
        'static_resource_input':{'evidence':pin(tradegoods),'evidence_id':evidence['evidence_id'],
            'rva':'0x1f7890','preferred_va':'0x1401f7890','end_rva_exclusive':'0x1f78be',
            'source':'definition+0x18 String32; caller1379450 tradegoods_name branch',
            'calls_translator_rva':'0x14b33a0'},
        'lookup':{'references':references,'hash_body_rva':'0x14b33a0',
            'hash_body_end_rva_exclusive':'0x14b35ba','search_helper_rva':'0x16faf60',
            'search_helper_end_rva_exclusive':'0x16fafe3','lookup_semantics':'native_FNV1_hash_only',
            'global_cell_rva':'0x2357b00','table_entry_stride':16,
            'search':'bounded lower_bound with local ordering/duplicate-neighbor checks; no full-table scan',
            'pool':'outer+20/+28/+30 begin/end/capacity-end; low32 entry offset and bounded NUL value',
            'language':'observed inner String32, not a filename assumption',
            'literal_key_collision_excluded':False,'secondary_records_read':False},
        'capture':'resource admitted first; reuse localization_memory._snapshot through a pure bounded adapter in the held parent reader',
        'public_name':'nonempty literal decoded with explicit eu4_escape codec; dynamic templates remain unknown',
        'dependencies':'shared identity changes withdraw all; resource base changes withdraw resource; name-only changes keep stable base and withdraw name',
        'native_function_invoked':False,'actual_UI_observed':False,'complete':False,
        'unresolved':['final rendered string, formatting and field-specific UI visibility',
            'literal source-key collision exclusion and secondary records',
            'dynamic substitutions, latent resource, icon frame and prices',
            'cache freshness, global table ordering and non-atomic external reads']}
    contract_path=STAGE/'native-resource-name-contract-001.json';write_new(contract_path,contract)
    profile['profile_version']=4;profile['supersedes']=pin(old)
    profile['source_evidence'] += [pin(old),pin(contract_path),pin(tradegoods)]+references
    before=deepcopy(profile['layout_dependencies'])
    profile['layout_dependencies']=[pin(ROOT/row['path']) for row in before]
    changed=[row['path'] for row,new in zip(before,profile['layout_dependencies']) if row!=new]
    assert changed==['bridge/information/province_detail_memory.py'],changed
    profile['layout_dependencies'] += [pin(ROOT/'bridge/information'/name) for name in (
        'province_resource_localization_memory.py','localization_memory.py','mission_texts.py')]
    profile['layout_dependencies'].append(pin(local_path))
    profile['semantics']['resource']='native key/icon plus cached name bytes; public literal name is not a rendered string'
    profile['semantics']['resource_name_encoding']='explicit eu4_escape decoding; no codec inference or dynamic substitution'
    profile['semantics']['resource_name_lookup']='native_FNV1_hash_only; literal_key_collision_excluded=false'
    profile['semantics']['gaps']=['full province discovery/visibility','unowned/special owner references',
        'final rendered resource name, dynamic templates, latent resources and prices',
        'literal source-key collision exclusion and secondary records',
        'complete labels/tooltips and center costs/permissions','cache freshness and atomicity']
    output=ROOT/'bridge/information/profiles/province-state-memory-1374-v4.json';write_new(output,profile)
    receipt={'status':'created','profile':pin(output),'prior_profile':pin(old),
        'builder':pin(Path(__file__).resolve()),'contract':pin(contract_path),
        'guards':len(profile['code_guards']),
        'guard_bytes_per_boundary':sum(len(bytes.fromhex(row['bytes'])) for row in profile['code_guards']),
        'reviewed_dependency_changes':changed,'new_REA_queries':False,'game_reads':False,'game_controls':False}
    write_new(STAGE/'province-resource-name-profile-build-001.json',receipt);print(receipt)


if __name__=='__main__':main()
