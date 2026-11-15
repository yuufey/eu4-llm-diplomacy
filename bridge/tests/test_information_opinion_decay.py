from copy import deepcopy
import struct
import pytest
from bridge.information import opinion_decay_memory as m
from bridge.information import opinion_decay_capture as capture
from bridge.information.opinion_decay import NativeOpinionDecaySource
from bridge.tests import test_information_opinion_modifiers_memory as fixture_memory
from bridge.tests.test_information_opinion_modifiers import Primary,CaptureHarness

@pytest.mark.parametrize('current,base,skip,factor,raw',[
    (-50000,2000,0,{'status':'known','country_modifier_raw':250,'pair_modifier_raw':0},2500),
    (-50000,2000,0,{'status':'known','country_modifier_raw':-2000,'pair_modifier_raw':0},0),
    (-50000,333,0,{'status':'known','country_modifier_raw':250,'pair_modifier_raw':0},416),
    (9000,1000,0,{'status':'not_required'},-1000),
    (9000,-1000,0,{'status':'not_required'},0),
    (-50000,1000,1,{'status':'unknown','reason':'OPINION_DECAY_PROCESSOR_UNRESOLVED'},0),
    (9000,2147483647,0,{'status':'not_required'},-2147483647),
    (500,1000,0,{'status':'not_required'},0),
])
def test_native_yearly_examples(current,base,skip,factor,raw):
    assert m.yearly_contribution(current,base,skip,factor)['raw']==raw

@pytest.mark.parametrize('current,base,skip,factor',[
    (-50000,1000,0,{'status':'unknown','reason':'OPINION_DECAY_PAIR_EFFECT_UNRESOLVED'}),
    (-50000,1000,0,{'status':'known','country_modifier_raw':2147483647,'pair_modifier_raw':0}),
    (True,1000,0,{'status':'not_required'}),
])
def test_missing_inputs_and_arithmetic_bounds_remain_unknown(current,base,skip,factor):
    assert m.yearly_contribution(current,base,skip,factor)['status']=='unknown'

def memory():
    r,holder,target=fixture_memory.fixture()
    definition=bytearray(r.segments[fixture_memory.DEFINITION]);definition.extend(b'\0'*(0x60-len(definition)))
    struct.pack_into('<i',definition,0x58,2000);r.segments[fixture_memory.DEFINITION]=definition
    r.patch(fixture_memory.OBJECT+0x25,b'\0')
    p=int(target['country_pointer'],0)
    r.put(p+0x28c8,struct.pack('<i',2))
    storage=bytearray(0x68);storage[0x10]=0
    struct.pack_into('<Q',storage,0x58,0x910000);struct.pack_into('<I',storage,0x64,1)
    r.put(p+0x28d0,storage);r.put(0x910000,struct.pack('<ii',0x94,250))
    r.put(fixture_memory.BASE+0x2358060,struct.pack('<Q',0x900000))
    r.put(0x900000+0x37c0,b'\0'*8)
    r.put(p+0x1480,struct.pack('<Q',0x920000));r.put(0x920008,struct.pack('<Q',0x930000))
    r.put(0x930020,b'\0'*16)
    return r,holder,target

def test_leaf_reuses_target_storage_and_preserves_modifier_identity():
    r,holder,target=memory()
    row=m._record(r,fixture_memory.BASE,fixture_memory.OBJECT,0,int(target['country_pointer'],0))
    assert row['modifier_id']=='insult'
    assert row['factor']=={'status':'known','country_modifier_raw':250,'pair_modifier_raw':0}
    assert row['yearly_change']['raw']==2500
    assert '_stability' not in row

def test_processor_and_eligible_pair_effect_do_not_become_zero():
    r,_,target=memory();p=int(target['country_pointer'],0)
    r.patch(0x900000+0x37c0,struct.pack('<Q',0xa00000))
    r.put(0xa00000,struct.pack('<Q',fixture_memory.BASE+0x123400))
    assert m._country_factor(r,fixture_memory.BASE,p)['reason']=='OPINION_DECAY_PROCESSOR_UNRESOLVED'
    r.patch(0x900000+0x37c0,b'\0'*8)
    r.patch(0x930020,struct.pack('<QQ',0x940000,0x940008));r.put(0x940000,struct.pack('<Q',0x950000))
    r.put(0x950018,b'\2');r.put(0x950010,struct.pack('<Q',0x960000))
    r.put(0x960038,struct.pack('<Q',0x970000));r.put(0x9700e8,struct.pack('<Q',0x980000))
    assert m._pair_factor(r,p)['reason']=='OPINION_DECAY_PAIR_EFFECT_UNRESOLVED'

def test_known_processor_zero_secondary_is_branch_independent():
    r,_,target=memory();p=int(target['country_pointer'],0)
    r.patch(0x900000+0x37c0,struct.pack('<Q',0xa00000))
    r.put(0xa00000,struct.pack('<Q',fixture_memory.BASE+0x1cc93a0))
    r.put(fixture_memory.BASE+0x1cc93a8,struct.pack('<Q',fixture_memory.BASE+0x8f9300))
    assert m._country_factor(r,fixture_memory.BASE,p)['country_modifier_raw']==250
    r.segments[0x910000]=bytearray(struct.pack('<iiii',0x94,250,0x1a9,1000))
    r.patch(p+0x28d0+0x64,struct.pack('<I',2))
    assert m._country_factor(r,fixture_memory.BASE,p)['reason']=='OPINION_DECAY_PROCESSOR_BRANCH_UNRESOLVED'

def test_inactive_pair_cache_makes_no_country_pair_contribution():
    r,_,target=memory();p=int(target['country_pointer'],0)
    r.patch(0x930020,struct.pack('<QQ',0x940000,0x940008));r.put(0x940000,struct.pack('<Q',0x950000))
    r.put(0x950018,b'\2');r.put(0x950010,struct.pack('<Q',0x960000))
    r.put(0x960038,struct.pack('<Q',0x970000));r.put(0x9700e8,struct.pack('<Q',0x980000))
    r.put(0x980018,struct.pack('<Q',0x990000));r.put(0x9900ae,b'\0')
    assert m._pair_factor(r,p,base=fixture_memory.BASE,target_slot=0,processor_manager=0x900000)=={'status':'known','raw':0}

def test_unknown_factor_public_projection_does_not_leak_extra_fields():
    result=m.yearly_contribution(-2000,1000,0,{'status':'unknown','address':'0xDEADBEEF'})
    assert result=={'status':'unknown','reason':'OPINION_DECAY_FACTOR_UNKNOWN'}

def report():
    row={'status':'known','modifier_id':'friendship','current_opinion_raw':9000,
         'base_yearly_raw':1000,'suppress_yearly_raw':0,'factor':{'status':'not_required'}}
    row['yearly_change']=m.yearly_contribution(9000,1000,0,row['factor'])
    fields={}
    for field,holder,target in [(m.FIELDS[0],'FRA','ENG'),(m.FIELDS[1],'ENG','FRA')]:
        fields[field]={'status':'known','value':{'holder':holder,'target':target,'records':[deepcopy(row)]},
                       'unit':m.UNIT,'scale':1000,'complete':False}
    return {'observation':{'backend':{'status':'observed','consistency':{'status':'stable'},
                                     'targets':[{'tag':'ENG','fields':fields}]}}}

def query(actor='FRA',recipient='ENG'):
    return {'topic':'R04','object':{'type':'country_pair','actor':actor,'recipient':recipient},
            'fields':['decay'],'parameters':{}}

def test_source_pair_order_public_units_and_capture_once(tmp_path):
    harness=CaptureHarness(report())
    source=NativeOpinionDecaySource(Primary(tmp_path),capture=harness.capture,validator=harness.validate)
    output=source.read(query('ENG','FRA'))
    value=output['fields']['decay']
    assert value['status']=='known' and value['complete'] is False
    assert [d['holder'] for d in value['value']]==['ENG','FRA']
    assert value['value'][0]['records'][0]['yearly_change_decimal']=='-1.000'
    assert len(harness.capture_calls)==1
    assert source.catalog()[0]['fields']['decay']['coverage']=='partial'
    assert 'opinion_modifiers' not in output['fields']

def test_tampered_derived_value_is_rejected_without_discarding_another_known_record():
    row=report()['observation']['backend']['targets'][0]['fields'][m.FIELDS[0]]['value']['records'][0]
    row['yearly_change']['raw']+=1
    with pytest.raises(ValueError):NativeOpinionDecaySource._project_record(row)

def test_capture_scope_schema_and_readonly_shared_owner(monkeypatch):
    monkeypatch.setattr(capture.owner,'_capture_common',lambda *a,**k:k)
    result=capture.capture('installation','ENG')
    assert result['schema']==capture.SCHEMA and result['observe'] is m._observe
    with pytest.raises(ValueError):capture.capture('installation','FRA')
    assert not capture.validate_capture({'schema':'wrong'},{},1,'ENG')

def test_current_profile_and_dependencies_are_valid():
    assert m._load_profile()['profile_id']==m.PROFILE_ID
