"""Clarify instance/definition ownership and freeze native duration evidence."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from work.create_information_country_modifier_contract import STAGE,OLD,pin,SHA
from work.discover_diplomacy import PE
from work.local_config import game_exe

def main():
    d=json.loads((STAGE/'country-modifiers-source-contract-001.json').read_text(encoding='utf-8'))
    d['supersedes']=pin(STAGE/'country-modifiers-source-contract-001.json')
    d['layout']['object_bases']={
        'country':{'list_head_offset':'0x1f0'},
        'node':{'item_pointer_offset':'0x0','next_pointer_offset':'0x10'},
        'instance':{'definition_pointer_offset':'0x30','start_date_offset':'0x40','date_offset':'0x44',
                    'flag_offsets':{'ruler_modifier':'0x48','parliament_modifier':'0x49','permanent':'0x4a','hidden':'0x4b'}},
        'definition':{'key_sso_offset':'0x158','effects_pointer_offset':'0x58','effects_count_offset':'0x64'}}
    d['layout']['unproven_header_fields']=['list count','list tail','node previous-pointer semantic']
    d['semantics']['ownership_rule']='Read dates and flags from instance bytes, never the definition prefix. Only the null-terminated head/next traversal is statically established.'
    for name in ('rea-modifier-instance-constructor-001','rea-country-modifier-add-001'):
        run=json.loads((OLD/name/'run.json').read_text(encoding='utf-8'))
        assert run['status']=='completed' and run['database_unchanged'] is True and run['cleanup']['status']=='complete'
        ep=OLD/name/'evidence.json'
        assert ep.stat().st_size<10000000
        e=json.loads(ep.read_text(encoding='utf-8'))
        assert e['subject']['digest']['sha256']==SHA
        d['accepted_REA'].append(dict(evidence_id=e['evidence_id'],evidence=pin(ep),run=pin(OLD/name/'run.json')))
    pe=PE(game_exe())
    fallback=pe.bytes_at(0x1FD149C,4)
    assert int.from_bytes(fallback,'little',signed=True)==43800000
    d['duration_contract']={
        'creator':{'rva':'0x328ca0','static_va':'0x140328ca0','log_literal':'AddTemporaryModifier',
                   'day_count_argument':'signed param_3 / R8D',
                   'nonnegative_duration':'signed32(day_count*24 + game_date_raw at game+0x1dd0)',
                   'negative_duration_fallback':{'rva':'0x1fd149c','raw_hex':fallback.hex(),'raw':43800000},
                   'constructor':'0xb35620 receives the computed raw date as R8D and stores it to instance+0x44'},
        'raw_ticks_per_game_day':24,
        'default_omitted_date_raw':43808760,
        'negative_duration_date_raw':43800000,
        'remaining_days':'exact signed difference (instance.date_raw-current.game_date_raw)/24 for finite dates; do not clamp overdue records',
        'permanent_flag_boundary':'A serialized permanent flag is preserved independently; it does not replace the observed raw-duration branch.',
        'limits':'No timer execution, removal callback, conditional activation, or cache refresh behavior is observed.'}
    d['ordinary_sources'].append(pin(OLD/'modifier-effect-date-source-001.json'))
    d['effect_scalar_contract']={'storage':'signed i32','scale':1000,'unit':'native fixed point; individual business units remain unresolved',
                                 'consumer_rva':'0x246bf0','basis':'definition serializer at 0x8e67c0'}
    p=STAGE/'country-modifiers-source-contract-002.json'
    with p.open('x',encoding='utf-8') as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(pin(p),ensure_ascii=False))

if __name__=='__main__':main()
