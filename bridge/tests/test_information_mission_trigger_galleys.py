"""Native group kind controls count versus strength for kind-five records."""
from copy import deepcopy

import pytest

from bridge.information import mission_trigger_galleys as galleys
from bridge.information.mission_condition_memory import _TrackingReader
from bridge.tests.test_information_mission_memory import FakeReader

def fixture(monkeypatch, *, true_code=b'\xb0\x01\xc3\xcc\xcc\xcc'):
    reader=FakeReader();base=reader.module_base
    groups=[{'group_object':hex(0x900000+i*0x1000)} for i in range(2)]
    for index,group in enumerate(groups):
        vtable=base+0x1d00000+index*0x100
        method=base+0x5000+index*0x100
        reader.qword_put(int(group['group_object'],0),vtable)
        reader.qword_put(vtable+0x88,method)
        reader.put(method,true_code if index==0 else b'\x32\xc0\xc3\xcc\xcc\xcc')
    snapshot={'status':'observed','groups':groups,'records':[
        {'group_index':0,'type_kind':5,'strength_raw':700},
        {'group_index':0,'type_kind':4,'strength_raw':1000},
        {'group_index':1,'type_kind':5,'strength_raw':450}]}
    monkeypatch.setattr(galleys.forces,'read_fields',lambda *args,**kwargs:deepcopy(snapshot))
    return _TrackingReader(reader),snapshot

def test_native_true_gate_counts_and_false_gate_adds_fixed_strength(monkeypatch):
    reader,_=fixture(monkeypatch)
    result=galleys.count_galleys(reader,reader.module_base,0x500000)
    assert result['raw_fixed_milli']==1450
    assert any(row['label'].endswith('kind_method_bytes') for row in reader.rawreads)

def test_no_matching_kind_is_zero_without_guessing_unknown_gate(monkeypatch):
    reader,snapshot=fixture(monkeypatch,true_code=b'\x90'*6)
    snapshot['records']=[row for row in snapshot['records'] if row['type_kind']!=5]
    assert galleys.count_galleys(reader,reader.module_base,0x500000)['raw_fixed_milli']==0
    assert reader.rawreads==[]

def test_unknown_gate_is_not_assumed_naval(monkeypatch):
    reader,_=fixture(monkeypatch,true_code=b'\x90'*6)
    with pytest.raises(ValueError,match='NOT_CONSTANT'):
        galleys.count_galleys(reader,reader.module_base,0x500000)

def test_signed_32_bit_accumulation_and_eax_const_gate(monkeypatch):
    reader,snapshot=fixture(monkeypatch,true_code=b'\xb8\x01\0\0\0\xc3')
    snapshot['records']=[{'group_index':1,'type_kind':5,'strength_raw':0x7fffffff},
                         {'group_index':1,'type_kind':5,'strength_raw':1}]
    assert galleys.count_galleys(reader,reader.module_base,0x500000)['raw_fixed_milli']==-0x80000000

def test_unavailable_force_records_stay_unknown(monkeypatch):
    reader,_=fixture(monkeypatch)
    monkeypatch.setattr(galleys.forces,'read_fields',lambda *args,**kwargs:{'status':'unknown','reason':'fixture_gap'})
    with pytest.raises(ValueError,match='FORCE_RECORDS_UNAVAILABLE'):
        galleys.count_galleys(reader,reader.module_base,0x500000)
