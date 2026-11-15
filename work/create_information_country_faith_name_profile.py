"""Correct the unproven key interpretation using the retained first live read."""
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_foreign_technology_profile import pin,load,write

STAGE=ROOT/'work/runtime/information-foreign-scalars-20261029-001'


def main():
    original=ROOT/'bridge/information/profiles/country-faith-memory-1374.json'
    profile=deepcopy(load(original))
    first=STAGE/'private-live-eng-001.json';report=load(first)
    field=report['observation']['backend']['targets'][0]['fields']['S02.faith']
    assert report['status']=='observed' and field['status']=='unknown'
    assert field['reason']=='primary_religion_key_syntax_invalid'
    raw=field['raw_inputs']['string32_payload_raw_hex'];assert raw=='10295911494e10596500'
    from bridge.native_text import decode_native_text_hex
    decoded=decode_native_text_hex(raw[:-2],codec='eu4_escape',max_bytes=128)
    contract={'schema':'information.country_faith.name_contract.v2','status':'corrected_from_observed_input',
        'binary_sha256':profile['executable']['sha256'],'image_base':'0x140000000',
        'supersedes':'The v1 configuration-key interpretation of definition+0xb0 was not proven and was rejected by real input',
        'source_evidence':profile['source_evidence'][:3],
        'first_live_capture':pin(first),'first_live_field_status':'unknown',
        'actual_payload_raw_hex':raw,'actual_decoded_name':decoded,
        'layout':'resolved selected country+0xf30 -> primary religion; +0xb0 String32 name cache; +0x570 u32 icon request',
        'semantics':'copy primary religion cached name bytes and strictly decode eu4_escape; no configuration key or numeric religion ID is exported',
        'admission':'native compound projected to logical FRA; FRA controller separately verified non-player',
        'unknowns':['full tooltip/bonuses','religion key/ID and group','actual UI display','main-thread atomicity/cache refresh time']}
    contract_path=STAGE/'faith-name-contract-002.json';write(contract_path,contract)
    profile['profile_version']=2
    profile['source_evidence']=profile['source_evidence'][:3]+[pin(contract_path)]
    profile['layout_dependencies']=[pin(original),pin(ROOT/'bridge/information/foreign_country_memory.py'),
        pin(ROOT/'bridge/information/country_faith_memory.py'),pin(ROOT/'bridge/native_text.py')]
    profile['field_layout'].pop('definition_key')
    profile['field_layout']['definition_name_cache']='0xb0'
    profile['field_layout']['max_name_bytes']=profile['field_layout'].pop('max_key_bytes')
    profile['field_layout']['encoding']='eu4_escape'
    profile['semantics']['scope']='current primary religion cached name bytes, strict decoded text, and icon request only; partial S02.faith'
    output=ROOT/'bridge/information/profiles/country-faith-memory-1374-v2.json';write(output,profile)
    receipt={'status':'created_corrected_name_contract','profile':pin(output),'contract':pin(contract_path),
        'original_profile_preserved':pin(original),'builder':pin(Path(__file__).resolve()),
        'no_new_game_access':True,'new_rea_query':False}
    write(STAGE/'faith-name-profile-build-002.json',receipt)
    print(json.dumps(receipt,ensure_ascii=False))


if __name__=='__main__':main()
