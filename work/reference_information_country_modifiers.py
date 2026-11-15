"""Derive modifier query expectations from independent raw bytes, stdlib only."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'work/runtime/information-country-records-20261027-001'
RAW=ROOT/'work/runtime/information-military-modifiers-20261027-001/native-modifier-inputs-002.json'
CONTRACT=STAGE/'country-modifiers-source-contract-002.json'
SHA='b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77'

def pin(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=h.hexdigest())

def main():
    d=json.loads(RAW.read_text(encoding='utf-8'))
    c=json.loads(CONTRACT.read_text(encoding='utf-8'))
    assert d['status']=='observed' and d['completed'] is True
    assert d['binary_sha256']==c['target']['exe_sha256']==SHA
    assert d['cleanup']['handle_close']['closed'] is True and d['doublepass']['consistent'] is True
    passes=d['modifier_instances_inputs']
    assert len(passes)==2 and passes[0]==passes[1]
    before=passes[0]
    date=before['date']['value']
    match=before['country']['matches']
    assert len(match)==1 and match[0]['handle_raw_hex']=='465241007a000001'
    identity=d['identity']
    assert identity['binding_verified'] is True
    assert identity['installation_creation_filetime']==identity['process_creation_filetime']
    rawdata=before['modifier_instances']
    assert rawdata['bounded_prefix_only'] is False
    reads={r['label']:r for r in rawdata['reads']}
    records=[]
    for index,node in enumerate(rawdata['nodes'],1):
        body=bytes.fromhex(node['item_raw_hex'])
        definition=bytes.fromhex(node['definition_raw_hex'])
        assert int.from_bytes(body[0x30:0x38],'little')==int(node['definition_va'],0)
        key_raw=bytes.fromhex(reads[f'definition_key_{index}']['raw_hex'])
        assert key_raw[-1:]==b'\0'
        key=key_raw[:-1].decode('ascii')
        assert len(key_raw)-1==int.from_bytes(definition[0x168:0x170],'little')
        assert key==node['definition_key']
        start=int.from_bytes(body[0x40:0x44],'little',signed=True)
        end=int.from_bytes(body[0x44:0x48],'little',signed=True)
        effect_count=int.from_bytes(definition[0x64:0x68],'little',signed=True)
        assert effect_count==node['effect_count'] and 0<=effect_count<=32
        effects=[]
        for j in range(effect_count):
            pair=bytes.fromhex(reads[f'effect_pair_{index}_{j}']['raw_hex'])
            metadata=bytes.fromhex(reads[f'effect_record_{index}_{j}']['raw_hex'])
            assert len(pair)==8 and len(metadata)==0x60
            effects.append(dict(index=int.from_bytes(pair[:4],'little'),
                                selector=int.from_bytes(metadata[0x50:0x54],'little'),
                                raw=int.from_bytes(pair[4:],'little',signed=True),raw_hex=pair[4:].hex(),
                                scale=1000,unit='native_fixed_point',business_unit='unknown'))
        records.append(dict(key=key,start=start,end=end,effects=effects))
    def field(value,unit,scale=1):
        return dict(status='known',value=value,unit=unit,scale=scale,period='current',complete=False)
    n07={
        'modifier_id':field([r['key'] for r in records],'identifier_collection'),
        'target':field([dict(modifier_id=r['key'],type='country',country='FRA') for r in records],'object_collection'),
        'effects':field([dict(modifier_id=r['key'],effects=r['effects'],basis='native_modifier_definition_entries',
                              final_effective_value=False) for r in records],'modifier_effect_records')}
    starts=[];ends=[];remaining=[];duration=[]
    for r in records:
        key=r['key']
        if r['start']==43808760:
            starts.append(dict(modifier_id=key,status='unknown',reason='NATIVE_DATE_DEFAULT_OMITTED'))
        else:
            starts.append(dict(modifier_id=key,status='known',value=r['start'],raw=r['start'],
                               raw_hex=r['start'].to_bytes(4,'little',signed=True).hex(),unit='game_date_raw',scale=1))
        # This reference covers the observed finite records only; an unseen
        # sentinel requires a new reference contract, never a fabricated date.
        assert r['end'] not in (43800000,43808760) and r['end']>=0
        ends.append(dict(modifier_id=key,status='known',value=r['end'],raw=r['end'],
                         raw_hex=r['end'].to_bytes(4,'little',signed=True).hex(),unit='game_date_raw',scale=1))
        remaining.append(dict(modifier_id=key,status='known',value=r['end']-date,raw=r['end']-date,
                              unit='days',scale=24,basis='native_expiry_minus_current_game_date'))
        duration.append(dict(modifier_id=key,status='known',value='fixed_term'))
    n08={'modifier_start_date':field(starts,'game_date_raw'),
         'modifier_end_date':field(ends,'game_date_raw'),
         'remaining_days':field(remaining,'days',24),
         'duration_type':field(duration,'state_collection')}
    out=dict(schema='information_country_modifiers_independent_reference.v1',status='observed',
             header=dict(session_id=identity['installation_session_id'],
                         creation_filetime=identity['process_creation_filetime'],game_date=date,
                         exe_sha256=SHA,country='FRA',slot=122,fullref_raw_hex=match[0]['handle_raw_hex']),
             queries={'N07':n07,'N08':n08},raw_source=pin(RAW),contract=pin(CONTRACT),
             production_modules_imported=False,new_RPM=False,new_game_queries=0)
    p=STAGE/'expected-country-modifiers-001.json'
    with p.open('x',encoding='utf-8') as f:json.dump(out,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(pin=pin(p),keys=[r['key'] for r in records],remaining_days=[(r['end']-date)/24 for r in records]),ensure_ascii=False))

if __name__=='__main__':main()
