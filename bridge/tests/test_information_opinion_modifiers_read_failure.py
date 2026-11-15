from copy import deepcopy

from bridge.information import opinion_modifiers_memory as memory


class FailedReader:
    def read(self,*args):
        raise RuntimeError('private address / failed process read')


def pair():
    return {
        'FRA':{'tag':'FRA','slot':3,'country_pointer':'0x20000','fullref':'0x100000300415246'},
        'ENG':{'tag':'ENG','slot':5,'country_pointer':'0x30000','fullref':'0x100000500474e45'},
    }


def test_one_failed_read_is_unknown_without_exception_details():
    bindings=pair()
    assert memory._direction(FailedReader(),0x140000000,bindings['FRA'],bindings['ENG'])=={
        'status':'unknown','reason':'OPINION_MODIFIER_READ_FAILED'}


def test_failure_in_one_direction_preserves_the_other_in_both_passes(monkeypatch):
    bindings=pair()
    monkeypatch.setattr(memory.ref,'resolve_countries',lambda *args,**kwargs:{
        'status':'observed','requested':deepcopy(bindings)})
    monkeypatch.setattr(memory.opinion,'_admission',lambda *args:{
        'status':'known','admitted':True,'observer_nonplayer_role':{'verified':True}})
    original=memory._direction
    def selected(reader,base,holder,indexed):
        if holder['tag']=='FRA':
            return original(FailedReader(),base,holder,indexed)
        return {'status':'knownempty','records':[]}
    monkeypatch.setattr(memory,'_direction',selected)
    result=memory._backend_read(FailedReader(),0x140000000,'ENG')
    fields=result['targets'][0]['fields']
    assert fields[memory.FIELD_OUTGOING]=={'status':'unknown','reason':'OPINION_MODIFIER_READ_FAILED'}
    assert fields[memory.FIELD_INCOMING]['status']=='known'
    assert fields[memory.FIELD_INCOMING]['value']['records']==[]
